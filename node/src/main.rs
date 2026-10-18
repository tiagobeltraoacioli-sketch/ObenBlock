//! GnB node — GnB-SMH proof of work · Falcon‖ML-DSA · GhostDAG.
//!
//! Inherited from the Bloch node (fixes applied there):
//!   #1  Real ML-DSA-65 signatures
//!   #2  Full IBD: PeerTip → GetHeaders → Headers → GetBlock → NewBlock response
//!   #3  Block structural + TX signature validation before storing
//!   #4  Persistent P2P identity
//!   #5  Mempool with fee ordering
//!   #6  Peer memory (known_peers.json)
//!   #7  Difficulty retargeting every 2016 blocks (seconds, not ms)
//!   #8  Founder/miner address uses proper 20-byte pubkey hash
//!   #9  Intra-block double-spend prevention via spent-set tracking
//!   #10 Unified TX validation (single code path for block/mempool/RPC)
//!   #11 Removed duplicated mining loop

// The crypto/wallet/tx island moved to the `gnb-crypto` crate
// (crates/gnb-crypto). Re-export its modules under `crate::` so every
// `core::…` / `crate::crypto::…` path in this binary and its sibling node
// modules keeps resolving unchanged.
use gnb_crypto::{crypto, core, address};

mod consensus;
mod mining;
mod storage;
mod network;
mod rpc;
mod metrics;
mod pow;         // GnB-SMH PoW adapter
mod transport;
// The binary uses part of the mempool's library API (the rest serves RPC
// consumers, tools and tests through the `gnb` library crate).
#[allow(dead_code)]
mod mempool;
mod analytics;
mod reorg;
mod attestation;  // L3 attestation (referenced by rpc)
// The binary uses the pipeline subset of the shielded-pool API; the rest
// (in-memory journal, mempool, snapshots) serves the library and its tests.
#[allow(dead_code)]
mod coherence;    // Coherence C2 shielded pool
mod tip;
mod sync;         // Phase 2 — drop-in Kaspa sync-negotiation layer
mod ingress;      // audit fixes: block-ingress / orphan / IBD-latch policy
mod accept;       // Block acceptance pipeline (accept/connect split, DAG-1)
mod assumevalid;  // assumed-valid block (Core's -assumevalid), P5-G
mod template;     // Block templates for the miner + getblocktemplate (MEM-2, DAG-2)
mod anchoring;    // ObenBlock checkpoints anchored in Bloch: records + advisory --bloch-rpc check
mod blockval;     // this chain's tx rules on top of the audit set (locktime, policy, BIP30)
mod powit;        // PoW + PoWit: witness shares, attestations, finality (node side)
mod genesis_init; // first-boot genesis and the data-dir genesis check (both chains)
#[allow(dead_code)] // the CLI and tests use the rest of its API
mod powit_signer; // PoWit signer protection (vote record, locks, rollback guard)
#[allow(dead_code)]
mod stratum;      // built-in Stratum V1 server + the work feed shared with V2 (docs/STRATUM.md)
#[cfg(feature = "stratum-v2")]
#[allow(dead_code)]
mod stratum_v2;   // built-in Stratum V2 server (Noise NX, SRI messages)

// The acceptance pipeline lives in `accept.rs` (shared with the library so
// integration tests drive the real path); same names and signatures as the
// functions that used to be defined in this file.
#[allow(unused_imports)]
use accept::{
    accept_block, validate_tx_standalone, validate_tx_inputs, miner_template_total_fees,
    validate_tx_in_block, validate_tx_in_block_with_maturity, ARCHIVE_MODE,
};

use clap::Parser;
use log::{info, warn, error, debug};
use std::sync::Arc;
use std::collections::HashSet;
use std::path::PathBuf;
use parking_lot::RwLock;
use tokio::sync::{mpsc, broadcast};

#[derive(Parser)]
#[command(name = "gnb")]
#[command(about = "ObenBlock node (relaunch in progress; this build: GnB-SMH memory-hard PoW) · Falcon‖ML-DSA · GhostDAG")]
#[command(version)]
struct Cli {
    #[arg(long)]                                         mine: bool,
    /// Number of CPU threads the GnB-SMH miner uses. Each thread holds its own
    /// 64 MiB scratchpad and searches a disjoint nonce range. Defaults to all
    /// logical CPUs.
    #[arg(long)]                                         mine_threads: Option<usize>,
    /// Keep EVERY block body — never prune. An archival node is what lets a
    /// FRESH node bootstrap: the default pruning depth (10,000 blocks) deletes
    /// bodies from CF_BLOCKS while the header/DAG map keeps every entry, so a
    /// pruned node still ADVERTISES headers it can no longer serve. With no
    /// archival peer anywhere on the network, a new node asks for block 0, is
    /// promised 500 headers, receives no bodies, and loops forever at height 1.
    /// That is the observed failure on this fleet (2026-07-19): every node had
    /// pruned below ~394,913, so those bodies exist nowhere and cannot be
    /// recovered. Run at least one archival node, or new nodes cannot join.
    /// Costs disk: the full chain instead of the last 10,000 blocks.
    #[arg(long)]                                         archive: bool,
    /// Rebuild the address history index (what getaddresshistory serves),
    /// with the height and timestamp rows, from the applied selected chain,
    /// then continue normally. Rows are keyed by chain position, the same
    /// rebuild the start-up migration of an older data dir runs (audit DAG-8).
    /// Spends are resolved from each block's undo record (genesis-ledger
    /// outputs included), so no snapshot is needed. Fixes histories that lost
    /// their spends to reorgs on older releases.
    #[arg(long)]                                         reindex_addresses: bool,
    /// Path to the uncompressed Bloch Genesis-3 carryover snapshot
    /// (`gunzip -k genesis/bloch-g3-carryover.tsv.gz`). Required on first
    /// boot: the genesis ledger is that snapshot converted to 1,000,000 GNB.
    /// The file is verified against the consensus constants (SHA3-256, rows,
    /// totals) before anything is written; any mismatch refuses to start.
    #[arg(long)]                                         carryover_snapshot: Option<PathBuf>,
    /// Chain to run: `gnb` (default) or `obenblock` (docs/DESIGN-obenblock.md
    /// §2). Selects the chain id, the default ports, data dir, DNS seed and
    /// P2P protocol ids.
    #[arg(long, value_parser = core::chain::Chain::parse)] chain: Option<core::chain::Chain>,
    /// GnB's public testnet (refused with `--chain obenblock`).
    #[arg(long)]                                         testnet: bool,
    /// ObenBlock's local regtest (needs `--chain obenblock`).
    #[arg(long)]                                         regtest: bool,
    /// Do not dial the chain's built-in DNS seeds (ObenBlock mainnet:
    /// seed.obenblock.xyz) when no --dns-seed is given.
    #[arg(long)]                                         no_default_dns_seed: bool,
    /// PoW + PoWit activation height (GnB-SMH v3, witness shares, witness-set
    /// finality). TEST NETWORKS ONLY: refused without --testnet / --regtest.
    /// Mainnet activation is a consensus constant (core::POWIT_HEIGHT_MAINNET).
    #[arg(long)]                                         powit_height: Option<u64>,
    /// PoWit witness: a forward-secure KES key from `gnb-cli witnesskeygen`.
    /// The node mines witness shares credited to it and, once it is in the
    /// witness set, signs checkpoints with the leaf of each target's epoch.
    /// Needs --witness-password-file and --witness-payout.
    #[arg(long)]                                         witness_key: Option<PathBuf>,
    /// File whose first line is the witness key password (keep it 0600).
    #[arg(long)]                                         witness_password_file: Option<PathBuf>,
    /// Address that receives this witness's share rewards (may be a cold wallet).
    #[arg(long)]                                         witness_payout: Option<String>,
    /// Threads mining witness shares (GnB-SMH v3, 4 MiB each). Default 2 when
    /// a witness wallet is set.
    #[arg(long)]                                         share_threads: Option<usize>,
    /// Data directory. Default: the network's (`./gnb-data` for GnB,
    /// `./obenblock-data`, `./obenblock-regtest-data`).
    #[arg(long = "data-dir")]                            data_dir_arg: Option<String>,
    #[arg(skip)]                                         data_dir: String,
    /// RPC bind address. SECURITY: defaults to 127.0.0.1 (local only).
    /// Use --rpc-public to bind 0.0.0.0, which exposes RPC to the internet.
    #[arg(long, default_value = "127.0.0.1")]            rpc_bind: String,
    /// Override rpc_bind to 0.0.0.0. DANGEROUS when unauthenticated.
    #[arg(long)]                                         rpc_public: bool,
    /// RPC port. Default: the network's (GnB 17210, ObenBlock 18210,
    /// ObenBlock regtest 18211).
    #[arg(long = "rpc-port")]                            rpc_port_arg: Option<u16>,
    #[arg(skip)]                                         rpc_port: u16,

    // ── Sprint M: authentication ────────────────────────────────────
    /// Shared-secret API key required for authenticated endpoints.
    /// Takes precedence over --rpc-api-key-file. Passing via CLI leaks
    /// the key into `ps aux`; prefer --rpc-api-key-file in production.
    #[arg(long)]                                         rpc_api_key: Option<String>,
    /// File containing the API key (first line, trimmed). Safer than --rpc-api-key.
    /// Suggested permissions: 0600, owned by the node user.
    #[arg(long)]                                         rpc_api_key_file: Option<std::path::PathBuf>,
    /// When true, writes (sendrawtransaction) require X-API-Key.
    /// Requires --rpc-api-key or --rpc-api-key-file to be set.
    /// Reads remain public (explorers need them).
    #[arg(long)]                                         rpc_require_auth_for_writes: bool,

    // ── Sprint M: rate limiting ─────────────────────────────────────
    /// Per-IP read-method rate limit, requests per minute. Default 60.
    /// Localhost (127.0.0.1, ::1) is exempt.
    #[arg(long, default_value = "60")]                   rpc_rate_limit_reads: u32,
    /// Per-IP write-method rate limit, requests per minute. Default 5.
    #[arg(long, default_value = "5")]                    rpc_rate_limit_writes: u32,

    /// Sprint M-patch1: also trust RFC1918 (10/8, 172.16/12, 192.168/16) and
    /// IPv6 ULA (fc00::/7) as "loopback" for auth/rate-limit bypass.
    /// This is needed when running in Docker with default bridge networking,
    /// where the host's 127.0.0.1 traffic appears as 172.17.0.1 inside the
    /// container. SECURITY: only enable on trusted single-tenant hosts. On
    /// Kubernetes, shared VLANs, or any multi-tenant network, leave this off.
    #[arg(long)]                                         rpc_trust_private_ranges: bool,

    // ── R3-audit H-R3-5: browser gate + loopback-auth policy ────────
    /// Browser origin allowed to call the RPC (repeatable), as exact
    /// `scheme://host[:port]`. Default: none — no CORS grants are emitted and
    /// any request carrying an Origin header is refused. `*` allows any
    /// origin for READ methods only; write methods never honour the wildcard.
    #[arg(long = "rpc-allow-origin")]                    rpc_allow_origins: Vec<String>,
    /// Extra hostname accepted in the Host header (repeatable),
    /// anti-DNS-rebinding. IP literals and `localhost` always pass; list your
    /// reverse-proxy / tunnel hostname here. `*` disables the check.
    #[arg(long = "rpc-allow-host")]                      rpc_allow_hosts: Vec<String>,
    /// Restore the pre-R3 "loopback bypasses auth" behaviour. Off by
    /// default: 127.0.0.1/::1 keep their rate-limit exemption but must
    /// present the API key like everyone else (a browser on this machine
    /// connects from loopback — the blanket bypass let any web page write).
    #[arg(long)]                                         rpc_trust_loopback: bool,
    /// The forwarding header your reverse proxy / tunnel WRITES with the
    /// client's address (B2-T11): the client of a proxied request is read
    /// from this header only (for X-Forwarded-For and Forwarded, its last
    /// hop), and only when the proxy connects from loopback (or a trusted
    /// private range). Default x-forwarded-for (nginx
    /// $proxy_add_x_forwarded_for, HAProxy option forwardfor, Caddy,
    /// cloudflared); set x-real-ip, cf-connecting-ip, forwarded, ... if your
    /// proxy sets that one instead.
    #[arg(long, default_value = "x-forwarded-for")]      rpc_proxy_client_header: String,

    // ── Sprint D: Prometheus metrics ─────────────────────────────────
    /// Enable Prometheus metrics server. Off by default (opt-in).
    /// Convention follows Geth: endpoint at /debug/metrics/prometheus.
    #[arg(long)]                                         metrics: bool,
    /// Metrics bind address. Default 127.0.0.1 (localhost-only).
    #[arg(long, default_value = "127.0.0.1")]            metrics_addr: String,
    /// Metrics port. Default: the network's (GnB 17310, ObenBlock 18310,
    /// ObenBlock regtest 18311).
    #[arg(long = "metrics-port")]                        metrics_port_arg: Option<u16>,
    #[arg(skip)]                                         metrics_port: u16,
    /// Shortcut: binds metrics to 0.0.0.0 (publicly reachable).
    /// DANGER: reveals version, peer count, timing data. Use only if you
    /// accept that the node advertises its status publicly.
    #[arg(long)]                                         metrics_public: bool,
    /// P2P listen multiaddr. Default: `/ip4/0.0.0.0/tcp/<port>` with the
    /// network's port (GnB 17110, ObenBlock 18110, ObenBlock regtest 18111).
    #[arg(long = "listen")]                              listen_arg: Option<String>,
    #[arg(skip)]                                         listen: String,
    #[arg(long)]                                         peer: Vec<String>,
    #[arg(long)]                                         miner_address: Option<String>,
    /// Sprint P: allow RFC1918 / loopback addresses via PEX. Dev/test only.
    /// Production deployments should leave this off; it opens a scanning vector.
    #[arg(long)]                                         allow_private_peers: bool,
    /// Mesh fix: set when this node sits behind a TCP proxy / NAT that makes
    /// many peers share one source IP (fly.io edge, k8s ingress, CGNAT). The
    /// gossipsub ip-colocation penalty (-50 x excess^2 above 3 peers/IP) would
    /// otherwise graylist the whole mesh at ~6 peers and silently blackhole
    /// every tip announcement. Disables only that weight; all other peer
    /// scoring stays active. Non-consensus — purely an operator knob.
    #[arg(long)]                                         behind_proxy: bool,
    /// Enable mDNS zero-config LAN peer discovery (OFF by default). Public nodes
    /// bootstrap via --peer/--dns-seed and should leave this off — mDNS is useless
    /// off a LAN and exercises a DNS-record parser with known LAN-only DoS CVEs.
    #[arg(long)]                                         enable_mdns: bool,
    /// Maximum peer connections (inbound cap). Raise this on a well-provisioned
    /// bootstrap / hub node so newcomers aren't rejected once the cap fills;
    /// keep it modest on a leaf node. Non-consensus — purely an operator knob.
    #[arg(long, default_value_t = 50)]                   max_peers: usize,
    /// Optional DNS seed hostname(s): the node resolves each to its A/AAAA
    /// records and dials them as peers (default port 17110; pass host:port to
    /// override). Bitcoin-style cold-start convenience — NON-privileged and
    /// opt-in: the shipped DEFAULT_SEEDS stays empty, so nobody's seed is
    /// required and you can point at (or run) any seed you trust. Repeatable.
    #[arg(long = "dns-seed")]                            dns_seed: Vec<String>,
    /// Minimum chain work (hexadecimal blue work, as Bitcoin Core's
    /// `-minimumchainwork`): while the selected tip carries less, the node is
    /// in initial block download — it stores no block it did not ask for
    /// (unless that block's own chain reaches it), refuses `submitblock`
    /// blocks below it and does not mine. Default: the network's value
    /// (mainnet `ingress::MAINNET_MINIMUM_CHAIN_WORK` = 0x6acfc0, raised at
    /// each release; testnet 0; docs/RUNNING.md). `0` turns it off; a value
    /// below the default is logged as a warning. Non-consensus — a
    /// node-local anti-DoS knob.
    #[arg(long = "minimumchainwork")]                    minimum_chain_work: Option<String>,
    /// Assumed-valid block (Bitcoin Core's `-assumevalid`): the id (64 hex
    /// digits, as `getblockdag` prints it) of a block whose selected-chain
    /// ancestors buried two weeks below the best block are connected without
    /// checking their transaction signatures (every other rule still runs),
    /// once its header is in the DAG and the best block has the minimum
    /// chain work. Default: the network's release value
    /// (`assumevalid::MAINNET_ASSUME_VALID`, none until a release sets it);
    /// `0` checks every signature. Non-consensus — node-local (docs/RUNNING.md).
    #[arg(long = "assumevalid")]                         assume_valid: Option<String>,
    /// PoWit finality checkpoint (weak subjectivity, review MEDIUM 6):
    /// `HASH:HEIGHT`, a block of the real chain (its id in 64 hex digits and
    /// its DAG height, as `getblockdag` prints them, read from nodes you
    /// trust) that this node treats as final from the start, before it holds
    /// the block: a finalized checkpoint that conflicts with it never pins
    /// fork choice, and once the block arrives no chain forking below it is
    /// selectable. Replaces the release finality checkpoint for this run
    /// (`powit::MAINNET_FINALITY_CHECKPOINT`); `none` removes it. An
    /// operator setting made with `setfinalitycheckpoint` takes precedence.
    /// Until the block arrives no finalized checkpoint above its height
    /// counts; a node that had a pin holds it, and once its chain is above
    /// that height, or after 30 minutes out of initial block download, it
    /// alerts (`anchor_overdue`, error log, metric
    /// `gnb_finality_anchor_unknown`). Non-consensus, node-local
    /// (docs/RUNNING.md).
    #[arg(long = "finalitycheckpoint")]                  finality_checkpoint: Option<String>,
    /// JSON-RPC URL of the operator's own Bloch node serving the ObenBlock
    /// anchor registry (docs/OBB-ANCHOR.md): https://, or http:// to a
    /// loopback host only. Advisory (DESIGN-obenblock §8): the newest anchor
    /// Bloch has finalized is compared with the node's chain; agreement is
    /// reported as corroboration, a contradiction or an unknown block raises
    /// the conflict alert (`getblochanchor`, `getfinalityinfo`, metric
    /// `gnb_bloch_anchor_conflict`). It never pins or refuses a block: the
    /// operator decides. Non-consensus, node-local.
    #[arg(long = "bloch-rpc")]                           bloch_rpc: Option<String>,
    /// Seconds between two reads of the Bloch anchor registry.
    #[arg(long = "bloch-anchor-interval", default_value_t = 300)] bloch_anchor_interval: u64,

    // ── Built-in stratum servers (SHA-256d chains only, docs/STRATUM.md) ──
    /// Start the Stratum V1 server (solo mode). Miners connect to
    /// stratum+tcp://<host>:3333 with their obb1… address as the worker name.
    /// V1 is plaintext; prefer --stratum-v2 on untrusted networks. Refused on
    /// GnB-SMH chains.
    #[arg(long)]                                         stratum: bool,
    /// Bind address of the Stratum V1 server.
    #[arg(long, default_value = stratum::DEFAULT_STRATUM_ADDR)] stratum_addr: String,
    /// Maximum concurrent Stratum V1 sessions.
    #[arg(long, default_value_t = stratum::DEFAULT_MAX_SESSIONS)] stratum_max_sessions: usize,
    /// Stratum mode. Only `solo` exists: each block pays its finder's address.
    #[arg(long, default_value = "solo")]                 stratum_mode: String,
    /// Payout address for workers that authorize with a plain label (e.g.
    /// `rig1`) instead of an obb1… address. Default: --miner-address. Without
    /// either, the worker name must be an address.
    #[arg(long)]                                         stratum_payout: Option<String>,
    /// Start the Stratum V2 server (Noise NX encrypted, standard channels).
    /// Pool URL: stratum2+tcp://<host>:3334/<authority key> (logged at start).
    #[arg(long)]                                         stratum_v2: bool,
    /// Bind address of the Stratum V2 server.
    #[arg(long, default_value = "0.0.0.0:3334")]         stratum_v2_addr: String,
    /// Authority keypair file of the Stratum V2 server (created, mode 0600,
    /// on first start). Default: <data-dir>/stratum-v2-authority.json. Keep it:
    /// miners pin its public key.
    #[arg(long)]                                         stratum_v2_key: Option<PathBuf>,
    /// Maximum concurrent Stratum V2 sessions.
    #[arg(long, default_value_t = 500)]                  stratum_v2_max_sessions: usize,
}

// Bloch-SIS founder address}

impl Cli {
    /// Select the network from `--chain` / `--testnet` / `--regtest` and fill
    /// every network default the operator did not override (ports, listen
    /// address, data dir, DNS seeds).
    fn resolve_network(&mut self) -> Result<&'static core::chain::ChainParams, String> {
        let p = core::chain::select_flags(self.chain, self.testnet, self.regtest)?;
        self.data_dir = self.data_dir_arg.clone().unwrap_or_else(|| p.data_dir.to_string());
        self.rpc_port = self.rpc_port_arg.unwrap_or(p.rpc_port);
        self.metrics_port = self.metrics_port_arg.unwrap_or(p.metrics_port);
        self.listen = self.listen_arg.clone().unwrap_or_else(|| format!("/ip4/0.0.0.0/tcp/{}", p.p2p_port));
        if self.dns_seed.is_empty() && !self.no_default_dns_seed {
            self.dns_seed = p.dns_seeds.iter().map(|s| s.to_string()).collect();
        }
        Ok(p)
    }
}

#[cfg(test)]
mod resolve_network_tests {
    use super::*;

    fn resolve(args: &[&str]) -> Result<(Cli, &'static core::chain::ChainParams), String> {
        let mut cli = Cli::try_parse_from(std::iter::once("gnb").chain(args.iter().copied()))
            .map_err(|e| e.to_string())?;
        let p = cli.resolve_network()?;
        Ok((cli, p))
    }

    /// GnB keeps every default it shipped.
    #[test]
    fn gnb_defaults_are_unchanged() {
        for args in [&[][..], &["--chain", "gnb"][..]] {
            let (cli, p) = resolve(args).unwrap();
            assert_eq!(p.chain_id, core::ChainId::Mainnet);
            assert_eq!((cli.rpc_port, cli.metrics_port), (17210, 17310));
            assert_eq!(cli.listen, "/ip4/0.0.0.0/tcp/17110");
            assert_eq!(cli.data_dir, "./gnb-data");
            assert!(cli.dns_seed.is_empty());
        }
        let (cli, p) = resolve(&["--testnet"]).unwrap();
        assert_eq!(p.chain_id, core::ChainId::Testnet);
        assert_eq!((cli.rpc_port, cli.listen.as_str(), cli.data_dir.as_str()), (17210, "/ip4/0.0.0.0/tcp/17110", "./gnb-data"));
    }

    #[test]
    fn obenblock_networks_have_their_own_defaults() {
        let (cli, p) = resolve(&["--chain", "obenblock"]).unwrap();
        assert_eq!(p.chain_id, core::ChainId::ObenBlockMainnet);
        assert_eq!((cli.rpc_port, cli.metrics_port), (18210, 18310));
        assert_eq!(cli.listen, "/ip4/0.0.0.0/tcp/18110");
        assert_eq!(cli.dns_seed, vec!["seed.obenblock.xyz".to_string()]);
        let (cli, _) = resolve(&["--chain", "obenblock", "--no-default-dns-seed"]).unwrap();
        assert!(cli.dns_seed.is_empty());
        let (cli, _) = resolve(&["--chain", "obenblock", "--dns-seed", "seed.example"]).unwrap();
        assert_eq!(cli.dns_seed, vec!["seed.example".to_string()]);
        let (cli, p) = resolve(&["--chain", "obenblock", "--regtest", "--rpc-port", "1", "--listen", "/ip4/127.0.0.1/tcp/2",
                                 "--data-dir", "d"]).unwrap();
        assert_eq!(p.chain_id, core::ChainId::ObenBlockRegtest);
        assert_eq!((cli.rpc_port, cli.listen.as_str(), cli.data_dir.as_str()), (1, "/ip4/127.0.0.1/tcp/2", "d"));
        assert!(cli.dns_seed.is_empty());
    }

    #[test]
    fn contradictory_flags_are_refused() {
        assert!(resolve(&["--chain", "obenblock", "--testnet"]).err().unwrap().contains("no public testnet"));
        assert!(resolve(&["--regtest"]).err().unwrap().contains("no regtest"));
        assert!(resolve(&["--chain", "bloch"]).is_err());
    }
}

/// Parse a gnb1q/gnb1t address string
/// into its 20-byte pubkey-hash script_pubkey.
///
/// This used to byte-slice the input directly
/// (`&stripped[..40.min(stripped.len())]`) — a panic hazard on any string
/// whose byte 40 is not a UTF-8 char boundary, i.e. indexing untrusted input
/// — and, on ANY parse failure (bad hex, wrong length, bad checksum),
/// silently fell back to `addr.as_bytes().to_vec()`: the RAW STRING BYTES of
/// the address, used as-is as a script_pubkey. That is neither a valid
/// P2PKH hash nor an error signal — it is an unspendable script that would
/// silently swallow every coinbase reward a miner earns under a mistyped
/// `--miner-address`, with no warning ever surfaced. Routes through the real
/// address parser (`Address::parse`: prefix, hex, length, AND checksum, none
/// of which does any raw indexing) and fails closed — every caller below
/// exits loudly instead of constructing a block that pays a burned address.
///
/// CRY-7: the address checksum does not cover the gnb1q/gnb1t prefix, so the
/// network is compared explicitly against the node's chain (set from
/// `--testnet` before any caller runs): a testnet address on a mainnet node
/// (or the reverse) is refused instead of silently paying the same hash.
/// The validated stratum settings (`None` when neither server is enabled).
struct StratumSetup {
    params: core::pow_scheme::Sha256dParams,
    payout: Option<stratum::Payout>,
    v1_addr: Option<std::net::SocketAddr>,
    v1_max_sessions: usize,
    v2_addr: Option<std::net::SocketAddr>,
    v2_max_sessions: usize,
}

/// Check the stratum flags once the chain is known: a SHA-256d chain, solo
/// mode, valid bind addresses and session caps, and a payout address of this
/// chain and network (`--stratum-payout`, else `--miner-address`, optional).
fn stratum_startup_checks(cli: &Cli) -> Result<Option<StratumSetup>, String> {
    if !cli.stratum && !cli.stratum_v2 {
        return Ok(None);
    }
    let params = stratum::require_sha256d_chain()?;
    if !cli.stratum_mode.eq_ignore_ascii_case("solo") {
        return Err(format!("--stratum-mode {:?}: only `solo` is supported (each block pays its finder)", cli.stratum_mode));
    }
    let payout = match cli.stratum_payout.as_deref().or(cli.miner_address.as_deref()) {
        None => None,
        Some(a) => Some(stratum::payout::parse_payout_address(a)
            .map_err(|e| format!("stratum payout address (--stratum-payout / --miner-address): {e}"))?),
    };
    let addr = |flag: &str, v: &str| v.parse::<std::net::SocketAddr>().map_err(|e| format!("{flag} {v:?}: {e}"));
    let v1_addr = if cli.stratum { Some(addr("--stratum-addr", &cli.stratum_addr)?) } else { None };
    let v2_addr = if cli.stratum_v2 { Some(addr("--stratum-v2-addr", &cli.stratum_v2_addr)?) } else { None };
    if cli.stratum_v2 && !cfg!(feature = "stratum-v2") {
        return Err("--stratum-v2: this binary was built without the `stratum-v2` feature".into());
    }
    if let (Some(a), Some(b)) = (v1_addr, v2_addr) {
        if a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified()) {
            return Err(format!("--stratum-addr {a} and --stratum-v2-addr {b} use the same port"));
        }
    }
    let v1_max_sessions = stratum::check_max_sessions(cli.stratum_max_sessions)
        .map_err(|e| format!("--stratum-max-sessions: {e}"))?;
    let v2_max_sessions = stratum::check_max_sessions(cli.stratum_v2_max_sessions)
        .map_err(|e| format!("--stratum-v2-max-sessions: {e}"))?;
    Ok(Some(StratumSetup { params, payout, v1_addr, v1_max_sessions, v2_addr, v2_max_sessions }))
}

/// Start the Stratum V2 server (feature `stratum-v2`): load or create the
/// authority key, bind, log the pool URL, serve. Exits the process on a
/// configuration error, as the other servers do.
#[cfg(feature = "stratum-v2")]
async fn start_stratum_v2(addr: std::net::SocketAddr, key_path: PathBuf, setup: &StratumSetup,
                          accept: Arc<rpc::SubmitBlockFn>, work: stratum::work::WorkReceiver) {
    let authority = match stratum_v2::AuthorityKeypair::load_or_generate(&key_path) {
        Ok(k) => k,
        Err(e) => {
            error!("stratum_v2: authority key {}: {e}", key_path.display());
            std::process::exit(1);
        }
    };
    let config = match stratum_v2::Sv2Config::new(addr, setup.v2_max_sessions, key_path.clone(),
                                                   setup.payout.clone(), accept) {
        Ok(c) => c,
        Err(e) => {
            error!("stratum_v2: {e}");
            std::process::exit(2);
        }
    };
    let listener = match stratum_v2::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("stratum_v2: cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    info!("stratum_v2: pool URL {} (authority key file {})",
          stratum_v2::pool_url("<host>", addr.port(), &authority), key_path.display());
    let params = setup.params;
    tokio::spawn(async move {
        if let Err(e) = stratum_v2::serve(listener, config, authority, params, work).await {
            error!("stratum_v2: server stopped: {e}");
        }
    });
}

/// Without the `stratum-v2` feature `--stratum-v2` is refused at start-up
/// (`stratum_startup_checks`); this is never reached.
#[cfg(not(feature = "stratum-v2"))]
async fn start_stratum_v2(_addr: std::net::SocketAddr, _key_path: PathBuf, _setup: &StratumSetup,
                          _accept: Arc<rpc::SubmitBlockFn>, _work: stratum::work::WorkReceiver) {}

fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, address::AddressError> {
    let network = core::node_chain_id().network();
    Ok(address::Address::parse_for_network_in(addr, network, address::process_family())?.hash().to_vec())
}

#[cfg(test)]
mod address_to_script_pubkey_tests {
    use super::*;

    fn sample_address() -> String {
        address::Address::from_hash([7u8; 20], address::Network::Mainnet).to_string()
    }

    #[test]
    fn valid_address_parses() {
        let spk = address_to_script_pubkey(&sample_address()).expect("valid address");
        assert_eq!(spk, vec![7u8; 20]);
    }

    /// Legacy L-3 regression: a malformed address (bad checksum) must be
    /// REJECTED, not silently converted into some other byte string used as
    /// a script_pubkey. Reverting the fix (restoring the raw byte-slice +
    /// `unwrap_or_else(|_| addr.as_bytes().to_vec())` fallback) makes this
    /// test fail — it would return `Ok(_)` with the raw ASCII bytes of the
    /// (invalid) address instead of an `Err`.
    #[test]
    fn malformed_address_is_rejected_not_silently_converted() {
        // A valid address with the last checksum hex digit flipped.
        let mut bad = sample_address();
        let last = bad.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        bad.push(flipped);
        assert!(address_to_script_pubkey(&bad).is_err(),
            "a bad-checksum address must be rejected, never silently accepted");
    }

    /// A garbage string (not even address-shaped) must also be rejected,
    /// never panic (the old code indexed the input directly) and never
    /// silently accepted as a script_pubkey.
    #[test]
    fn garbage_input_is_rejected_not_panicking() {
        assert!(address_to_script_pubkey("not-an-address").is_err());
        assert!(address_to_script_pubkey("").is_err());
        // Shorter than the old code's hardcoded byte-40 slice point — this
        // used to panic ("byte index 40 is out of bounds"); it must now
        // return a clean Err instead.
        assert!(address_to_script_pubkey("gnb1q").is_err());
    }

    /// CRY-7 regression: an address of the other network (valid checksum,
    /// same 20-byte hash) is rejected. Unit tests run with the default
    /// (mainnet) node chain id.
    #[test]
    fn address_of_the_wrong_network_is_rejected() {
        assert_eq!(core::node_chain_id(), core::ChainId::Mainnet);
        let testnet = address::Address::from_hash([7u8; 20], address::Network::Testnet).to_string();
        assert!(matches!(
            address_to_script_pubkey(&testnet),
            Err(address::AddressError::WrongNetwork { .. })
        ));
        assert_eq!(address_to_script_pubkey(&sample_address()).unwrap(), vec![7u8; 20]);
    }
}

/// Start-up guard for builds with gnb-crypto's `test-pow-limit` (the node's
/// `--features test-pow-limit`, or the feature reached any other way, such as
/// a dev-dependency unified into the binary by `cargo test`): every expected
/// target is pinned to the pow limit, so such a node mines and accepts blocks
/// at about one GnB-SMH evaluation each. Keyed on gnb-crypto's constant, not
/// on a feature name, so no route to the feature escapes it:
///
/// - an optimised build (`debug_assertions` off: the release profile, every
///   artifact) with it refuses to run on any network;
/// - a debug build with it refuses mainnet (on mainnet it would fork the node
///   off the network with worthless blocks) and runs on `--testnet`, which is
///   what the functional tests (test/functional) need;
/// - a build without it passes everywhere.
fn test_pow_limit_guard(test_pow_limit: bool, testnet: bool, debug_assertions: bool) -> Result<(), &'static str> {
    if test_pow_limit && !debug_assertions {
        return Err("this binary is an optimised build with gnb-crypto's test-pow-limit feature \
                    (functional tests only: every target is the pow limit) and refuses to run; \
                    test builds are debug builds");
    }
    if test_pow_limit && !testnet {
        return Err("this binary was built with the test-pow-limit feature (functional tests \
                    only: every target is the pow limit) and refuses to run on mainnet; \
                    start it with --testnet");
    }
    Ok(())
}

// The node's `test-pow-limit` feature exists for debug functional-test builds;
// a release build with it does not compile. (gnb-crypto's feature reached any
// other way compiles, and `test_pow_limit_guard` refuses to run it.)
#[cfg(all(feature = "test-pow-limit", not(debug_assertions)))]
compile_error!("the test-pow-limit feature is for debug functional-test builds only; \
                never enable it in a release build");

#[cfg(test)]
mod test_pow_limit_guard_tests {
    use super::test_pow_limit_guard;

    /// A debug test build refuses mainnet and runs on testnet. Dropping the
    /// guard's condition, or inverting its network check, fails here.
    #[test]
    fn test_build_refuses_mainnet_and_runs_on_testnet() {
        let refusal = test_pow_limit_guard(true, false, true).expect_err("mainnet must be refused");
        assert!(refusal.contains("test-pow-limit") && refusal.contains("mainnet"), "{refusal}");
        assert_eq!(test_pow_limit_guard(true, true, true), Ok(()));
    }

    /// An optimised (release-profile) build with the feature refuses every
    /// network, testnet included: `cargo build --release --features
    /// gnb-crypto/test-pow-limit` and `cargo test --release` compile such a
    /// binary.
    #[test]
    fn optimised_test_build_refuses_every_network() {
        for testnet in [false, true] {
            let refusal = test_pow_limit_guard(true, testnet, false)
                .expect_err("an optimised test-pow-limit build must never run");
            assert!(refusal.contains("optimised build") && refusal.contains("test-pow-limit"), "{refusal}");
        }
    }

    /// docs/CONSENSUS.md describes the guard as it is. It said the node
    /// binary rejects the feature, which stopped being true when debug test
    /// builds began to run on testnet for the functional tests.
    #[test]
    fn the_consensus_spec_describes_the_guard() {
        let spec = include_str!("../../docs/CONSENSUS.md").split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!spec.contains("is rejected by the node binary"));
        for says in ["refuses mainnet", "refuses every network", "`test_pow_limit_guard`", "`--testnet`"] {
            assert!(spec.contains(says), "docs/CONSENSUS.md must say {says:?} about test-pow-limit");
        }
    }

    #[test]
    fn production_build_runs_on_both_networks_in_every_profile() {
        for debug_assertions in [false, true] {
            assert_eq!(test_pow_limit_guard(false, false, debug_assertions), Ok(()));
            assert_eq!(test_pow_limit_guard(false, true, debug_assertions), Ok(()));
        }
    }
}

// Floor the worker count at 4. The default is the core count, and the
// production nodes are 2-core boxes: with only two workers, any pair of tasks
// that blocks (a held `node_state`/`dag` lock, a synchronous RocksDB read)
// parks the entire runtime, including the RPC accept loop. The RPC dispatch
// itself now runs on the blocking pool (see rpc/mod.rs), which is the actual
// fix; this is headroom so the async side keeps making progress while blocking
// work is in flight. Extra workers on a 2-core box cost context switches, not
// correctness.
#[tokio::main(worker_threads = 4)]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let mut cli = Cli::parse();
    let net_params = match cli.resolve_network() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(2);
        }
    };
    let test_network = net_params.chain_id.is_test_network();

    if let Err(refusal) = test_pow_limit_guard(core::TEST_POW_LIMIT, test_network, cfg!(debug_assertions)) {
        eprintln!("❌ {refusal}");
        std::process::exit(2);
    }
    if core::TEST_POW_LIMIT {
        eprintln!("⚠  TEST BUILD (test-pow-limit): every expected target is the pow limit. \
                   For functional tests on a local testnet only.");
    }

    // Roadmap #8: wire the node-level chain-id ONCE at startup from the runtime
    // network selection, before any validation runs. The miner and every
    // validator read core::node_chain_id() (design §4.3 invariant 6); without
    // this call a testnet node would default to the Mainnet sighash domain and
    // reject every correctly-signed testnet transaction.
    core::set_node_chain_id(net_params.chain_id)
        .expect("node chain-id must be settable exactly once at startup");
    info!("chain {} {} (chain id {:#010x})", net_params.chain.name(), net_params.network_name,
          net_params.chain_id.to_u32());
    // docs/DESIGN-obenblock.md §3: the ObenBlock mainnet genesis is mined at
    // launch; until its constants are pasted the node refuses to start.
    if let Some(why) = core::genesis::launch_refusal(net_params.chain_id) {
        eprintln!("❌ {why}");
        std::process::exit(2);
    }
    if let Some(h) = cli.powit_height {
        if net_params.chain == core::chain::Chain::ObenBlock {
            eprintln!("--powit-height is refused on ObenBlock: PoWit applies from height 0 on both its networks");
            std::process::exit(2);
        }
        if !test_network {
            eprintln!("--powit-height is for test networks only; mainnet activation is a consensus constant");
            std::process::exit(2);
        }
        core::set_powit_height_override(h).expect("PoWit height must be settable once at startup");
    }
    info!("proof of work: {} (PoWit activation height {})",
          if core::pow_scheme::node_sha256d_params().is_some() { "sha256d" } else { core::pow_algo(0).name() },
          match core::powit_height() { u64::MAX => "off".to_string(), h => h.to_string() });

    // Stratum (docs/STRATUM.md): only for SHA-256d chains; the flags and the
    // payout address are checked before anything else starts.
    let stratum_setup = match stratum_startup_checks(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(2);
        }
    };

    // POW-3 (Phase 4): the minimum chain work (Bitcoin Core's
    // nMinimumChainWork), once, before any block is handled.
    {
        let net = net_params.chain_id;
        let setting = match ingress::MinimumChainWorkSetting::resolve(cli.minimum_chain_work.as_deref(), net.into()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ --minimumchainwork: {e}");
                std::process::exit(2);
            }
        };
        let _ = ingress::set_minimum_chain_work(setting.value);
        info!("minimum chain work: {:#x} ({}){}", setting.value, setting.value,
            if setting.overridden { " (--minimumchainwork)" } else { " (network default)" });
        if let Some(w) = setting.below_default_warning() {
            warn!("⚠ {w}");
        }
        // P5-G: the assumed-valid block (Bitcoin Core's -assumevalid), once,
        // before any block is connected.
        let av = match assumevalid::AssumeValidSetting::resolve(cli.assume_valid.as_deref(), net.into()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ --assumevalid: {e}");
                std::process::exit(2);
            }
        };
        let _ = assumevalid::set_assume_valid(av.block);
        info!("{}", av.describe());
        // Review MEDIUM 6: the weak-subjectivity finality checkpoint, before
        // the finality index is loaded (the block need not be held yet).
        if let Some(arg) = cli.finality_checkpoint.as_deref() {
            let cp = match powit::parse_finality_checkpoint(arg) {
                Ok(cp) => cp,
                Err(e) => {
                    eprintln!("❌ --finalitycheckpoint: {e}");
                    std::process::exit(2);
                }
            };
            if let Err(e) = powit::set_finality_checkpoint_flag(cp) {
                eprintln!("❌ --finalitycheckpoint: {e}");
                std::process::exit(2);
            }
            match cp {
                Some(c) => info!("PoWit finality checkpoint (--finalitycheckpoint): {} at DAG height {}",
                    hex::encode(c.hash), c.height),
                None => warn!("⚠ --finalitycheckpoint none: no release finality checkpoint"),
            }
        }
    }

    // FIX v0.5.1 BLK-3: apply --rpc-public escape hatch.
    let rpc_bind = if cli.rpc_public { "0.0.0.0".to_string() } else { cli.rpc_bind.clone() };

    // ── Sprint M: load API key (CLI takes precedence over file) ────
    let api_key: Option<String> = match (&cli.rpc_api_key, &cli.rpc_api_key_file) {
        (Some(k), _) => Some(k.trim().to_string()),
        (None, Some(path)) => {
            // NET-16: an operator who names a key file wants authentication.
            // A missing, unreadable, empty or over-permissive file is a fatal
            // configuration error (it used to fall back to NO key, i.e. auth
            // silently disabled).
            match rpc::auth::check_key_file_permissions(std::path::Path::new(path)) {
                Ok(None) => {}
                Ok(Some(warning)) => eprintln!("⚠  {warning}"),
                Err(refusal) => {
                    eprintln!("❌ {refusal}");
                    std::process::exit(2);
                }
            }
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let k = contents.lines().next().unwrap_or("").trim().to_string();
                    if k.is_empty() {
                        eprintln!("❌ --rpc-api-key-file {:?} is empty", path);
                        std::process::exit(2);
                    }
                    Some(k)
                }
                Err(e) => {
                    eprintln!("❌ failed to read --rpc-api-key-file {:?}: {}", path, e);
                    std::process::exit(2);
                }
            }
        }
        (None, None) => None,
    };

    // Guard: --rpc-require-auth-for-writes without a key is a config error
    if cli.rpc_require_auth_for_writes && api_key.is_none() {
        eprintln!("❌ --rpc-require-auth-for-writes requires --rpc-api-key or --rpc-api-key-file");
        std::process::exit(2);
    }

    // Warnings on public bind
    if cli.rpc_trust_private_ranges {
        eprintln!("⚠  --rpc-trust-private-ranges: RFC1918 and IPv6 ULA ranges");
        eprintln!("   will bypass auth and rate limits. Only safe on trusted");
        eprintln!("   single-tenant hosts. DO NOT use on Kubernetes or shared VLANs.");
    }
    if cli.rpc_trust_loopback {
        eprintln!("⚠  --rpc-trust-loopback: 127.0.0.1/::1 will bypass API-key auth.");
        eprintln!("   Any local process — including a web page in a browser on this");
        eprintln!("   machine — can then call write methods without the key.");
    }
    // B2-T11: an --rpc-allow-host name means the RPC is reached through a
    // reverse proxy or tunnel, which delivers every remote caller from
    // loopback (docs/RUNNING.md, "Remote RPC through a proxy or tunnel").
    if !cli.rpc_allow_hosts.is_empty() {
        if api_key.is_none() || !cli.rpc_require_auth_for_writes {
            eprintln!("⚠  --rpc-allow-host: a proxied or tunnelled RPC must require the API key");
            eprintln!("   for writes (--rpc-api-key-file <PATH> --rpc-require-auth-for-writes);");
            eprintln!("   without it any remote caller may submit blocks and transactions.");
        }
        if cli.rpc_trust_loopback {
            eprintln!("⚠  --rpc-trust-loopback with --rpc-allow-host: a proxy that adds no");
            eprintln!("   forwarding header makes every remote caller an administrator.");
            eprintln!("   Do not combine them (docs/RUNNING.md).");
        }
    }
    let rpc_proxy_client_header = match rpc::auth::validate_proxy_client_header(&cli.rpc_proxy_client_header) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("❌ {e}");
            std::process::exit(2);
        }
    };
    if cli.rpc_allow_origins.iter().any(|o| o == "*") {
        eprintln!("⚠  --rpc-allow-origin '*': any web page may issue READ calls.");
        eprintln!("   Write methods still refuse wildcard origins.");
    }

    // ── Sprint D: resolve metrics bind, print warnings ───────────────
    let metrics_bind = if cli.metrics_public {
        "0.0.0.0".to_string()
    } else {
        cli.metrics_addr.clone()
    };
    if cli.metrics && cli.metrics_public {
        eprintln!("⚠  --metrics-public: Prometheus endpoint on 0.0.0.0:{}", cli.metrics_port);
        eprintln!("   Reveals version, peer count, hashrate, timing data.");
        eprintln!("   For most operators, prefer localhost + SSH tunnel or Grafana Agent push.");
    }

    if cli.rpc_public {
        eprintln!("⚠  --rpc-public binds RPC to 0.0.0.0 (all interfaces).");
        if api_key.is_none() {
            eprintln!("⚠  No --rpc-api-key set. Writes are rate-limited but not authenticated.");
            eprintln!("⚠  Recommend: --rpc-api-key-file <PATH> --rpc-require-auth-for-writes");
        } else if !cli.rpc_require_auth_for_writes {
            eprintln!("ℹ  API key set but --rpc-require-auth-for-writes is off.");
            eprintln!("ℹ  Writes will still accept unauthenticated requests (rate-limited).");
        } else {
            eprintln!("✓  RPC public with auth required for writes.");
        }
    }

    println!();
    println!("  ╔══════════════════════════════════════════════════╗");
    println!("  ║             ◆  O b e n B l o c k  ◆              ║");
    println!("  ║  GnB-SMH memory-hard PoW · Falcon‖ML-DSA · DAG   ║");
    println!("  ║  Post-quantum. ObenBlock relaunch in progress.   ║");
    println!("  ╚══════════════════════════════════════════════════╝");
    println!();

    let data_path = PathBuf::from(&cli.data_dir);
    std::fs::create_dir_all(&data_path).expect("create data dir");

    // ── Storage ───────────────────────────────────────────────────────────────
    let store = match storage::Storage::open(&data_path.join("db")) {
        Ok(s)  => { info!("storage ready"); Arc::new(s) }
        Err(e) => { error!("storage: {}", e); std::process::exit(1); }
    };
    // Audit POW-9: mainnet and testnet share the genesis, so the genesis
    // check below cannot tell the other network's data dir apart; the data
    // dir records its chain id (docs/RUNNING.md).
    match store.check_chain_marker(core::node_chain_id().to_u32()) {
        Ok(true) => info!("data dir marked for chain id {:#010x}", core::node_chain_id().to_u32()),
        Ok(false) => {}
        Err(e) => {
            error!("{e}. Refusing to start: use a separate --data-dir for each network.");
            std::process::exit(1);
        }
    }


    // ── Consensus ─────────────────────────────────────────────────────────────
    // `with_default_k_env` == `with_default_k` (Legacy) unless the dev/test
    // override `GNB_GHOSTDAG_COLORING=fast` is set. The live gate
    // (CORRECTED_COLORING_ACTIVATION_HEIGHT) is unchanged; see ColoringMode docs.
    let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k_env()));

    // ── Genesis + DAG reload ─────────────────────────────────────────────────
    // Archival mode is process-wide and fixed; set it before any block is accepted.
    if cli.archive {
        ARCHIVE_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("--archive: pruning DISABLED, every block body retained. This node can \
               bootstrap fresh peers; a pruned node cannot.");
    }

    if store.get_meta("genesis_hash").ok().flatten().is_none() {
        // ── Genesis: verified Bloch Genesis-3 carryover, locked allocations
        // and the genesis block of the node's chain (genesis_init). Verify
        // fully, then write the ledger in one atomic batch, before block 0. A
        // crash between ingestion and genesis init re-runs both (same keys).
        let Some(snap_path) = cli.carryover_snapshot.as_ref() else {
            error!("first boot requires --carryover-snapshot <bloch-g3-carryover.tsv> \
                    (gunzip -k genesis/bloch-g3-carryover.tsv.gz). Refusing to start.");
            std::process::exit(1);
        };
        let bytes = std::fs::read(snap_path).unwrap_or_else(|e| {
            error!("cannot read {}: {e}", snap_path.display());
            std::process::exit(1);
        });
        info!("Initialising the genesis ledger and the canonical genesis ({} proof of work)...",
              core::pow_scheme::node_pow_scheme().name());
        if let Err(failures) = genesis_init::initialise(&store, &dag, &bytes) {
            for f in &failures { error!("{f}"); }
            error!("REFUSING TO START: the genesis could not be initialised.");
            std::process::exit(1);
        }
    } else {
        if let Err(e) = genesis_init::check_data_dir(&store) {
            error!("{e}. Refusing to start.");
            std::process::exit(1);
        }
        // Full DAG reconstruction from persisted data (accept::load_dag).
        //
        // Sprint Y (M-2): the integrity hash-chain over GhostdagData is
        // verified before anything is inserted; a data dir from before the
        // chain self-heals (the records are computed and written). Audit
        // DAG-11: a chain that does not verify (the footprint of a pre-fix
        // binary that lost a DAG write: a missing record, a zero-filled link)
        // is repaired — records consistent with their own integrity hash
        // relinked, missing or corrupted ones recomputed from the stored
        // headers, the rest dropped and fetched again — instead of exiting
        // with no remedy but a resync. Only a repair that would leave applied
        // UTXO effects without their block refuses to start.
        match accept::load_dag(&dag, &store) {
            Ok(r) if r.blocks_loaded > 0 => {
                if let Some(rep) = &r.repair {
                    warn!("DAG loaded from disk after a repair: {} blocks ({} relinked, {} recomputed, {} dropped)",
                          r.blocks_loaded, rep.relinked.len(), rep.recomputed.len(), rep.dropped.len());
                } else if r.self_healed {
                    warn!("CF_DAG_INTEGRITY was empty: {} integrity records computed and written \
                           (first boot after the integrity chain); later boots validate strictly.",
                          r.blocks_loaded);
                } else {
                    info!("DAG loaded from disk (integrity verified): {} blocks", r.blocks_loaded);
                }
            }
            Ok(_) => {
                // Fallback: at least load genesis
                let gh = store.get_meta("genesis_hash").unwrap().unwrap();
                let gh32: [u8;32] = gh.as_slice().try_into().unwrap_or([0u8;32]);
                if let Ok(Some(blk)) = store.get_block(&gh32) {
                    dag.write().add_genesis(blk.block_hash(), blk.header.timestamp);
                    info!("Genesis loaded (fallback): {}", hex::encode(&gh));
                }
            }
            Err(e) => {
                error!("cannot load the GhostDAG state: {e}");
                error!("Refusing to start.");
                std::process::exit(1);
            }
        }
    }

    // ── Phase 2: durable reachability index — load-or-rebuild on boot ─────────
    //
    // `load_persisted*` above inserts blocks straight into the in-memory DAG
    // WITHOUT feeding the reachability index (it bypasses `add_block`). So when
    // the index is maintained (Fast / armed activation) it is empty here and
    // must be initialized before it colors any block:
    //
    //   * Fast-path: if CF_REACHABILITY carries the matching schema version and
    //     covers every CF_DAG block, load it directly (no O(chain) recompute).
    //   * Migration: otherwise rebuild by replaying the SAME `reach.add_block`
    //     code path in topological order, then persist the fresh snapshot.
    //   * Guard: random-sample self-check against the brute-force oracle before
    //     trusting the index; a loaded index that fails is rebuilt once.
    //
    // This whole block is inert on the live Legacy path (the gate is disabled),
    // so it never runs on a mainnet node from this branch. No peer resync ever.
    if dag.read().maintains_reachability_index() && dag.read().block_count() > 0 {
        let want_ver = storage::Storage::REACHABILITY_SCHEMA_VERSION;
        let have_ver = store.get_reachability_version().ok().flatten();
        let block_count = dag.read().block_count();

        let mut loaded_ok = false;
        if have_ver == Some(want_ver) {
            match store.load_all_reachability() {
                Ok(records) if records.len() == block_count => {
                    let root = store.get_reachability_root().ok().flatten();
                    match dag.write().reach_load_records(&records, root) {
                        Ok(()) => {
                            loaded_ok = true;
                            info!("reachability index loaded from disk: {} records", records.len());
                        }
                        Err(e) => warn!("reachability load failed ({e}); will rebuild"),
                    }
                }
                Ok(records) => warn!(
                    "reachability CF covers {}/{} blocks (partial/torn); will rebuild",
                    records.len(), block_count
                ),
                Err(e) => warn!("reachability CF read failed ({e}); will rebuild"),
            }
        } else {
            info!(
                "reachability index absent/version-mismatch (have {:?}, want {}); \
                 rebuilding from CF_DAG (one-time)",
                have_ver, want_ver
            );
        }

        let persist_rebuilt = |dag: &Arc<RwLock<consensus::GhostDAG>>, store: &storage::Storage| {
            let snap = dag.read().reach_export_all();
            let root = dag.read().reach_root();
            let _ = dag.write().reach_take_delta(); // clear the rebuild's dirty flags
            if let Err(e) = store.store_reachability_snapshot(&snap, root) {
                warn!("failed to persist rebuilt reachability index: {e}");
            }
        };

        if !loaded_ok {
            match dag.write().rebuild_reachability_from_store() {
                Ok(n) => info!("reachability index rebuilt from CF_DAG: {} blocks", n),
                Err(e) => {
                    error!("reachability rebuild FAILED: {e}");
                    error!("Refusing to continue with an uninitialized Fast-coloring index.");
                    std::process::exit(1);
                }
            }
            persist_rebuilt(&dag, &store);
        }

        // Self-check the (loaded or rebuilt) index against the unbounded oracle.
        // Bind in a `let` so the read guard drops before the rebuild's
        // `dag.write()` below (non-reentrant RwLock — holding it across the write
        // would deadlock the very path that recovers from a bad index).
        let self_check = dag.read().reach_self_check_sample(2000, 0xB10C_5157);
        if let Err(e) = self_check {
            if loaded_ok {
                warn!("loaded reachability failed self-check ({e}); rebuilding from CF_DAG");
                match dag.write().rebuild_reachability_from_store() {
                    Ok(n) => info!("reachability rebuilt after failed self-check: {} blocks", n),
                    Err(e2) => { error!("rebuild after failed self-check errored: {e2}"); std::process::exit(1); }
                }
                persist_rebuilt(&dag, &store);
                if let Err(e2) = dag.read().reach_self_check_sample(2000, 0x5157_B10C) {
                    error!("reachability STILL fails self-check after rebuild: {e2}");
                    std::process::exit(1);
                }
                info!("reachability self-check OK after rebuild");
            } else {
                error!("rebuilt reachability failed self-check: {e}");
                std::process::exit(1);
            }
        } else {
            info!("reachability self-check OK (sampled pairs match brute-force oracle)");
        }
    }

    // (The start-up clamp of `finalized_height` is gone with the finality
    // checkpoint itself — audit DAG-6. The meta key, if present in an old
    // data dir, is no longer read.)

    // ── Mempool + Network ─────────────────────────────────────────────────────
    let mempool  = Arc::new(mempool::Mempool::new());
    let net_cfg  = network::NetworkConfig {
        listen_addr:     cli.listen.clone(),
        bootstrap_peers: cli.peer.clone(),
        dns_seeds:       cli.dns_seed.clone(),
        max_peers:       cli.max_peers,
        data_dir:        data_path.clone(),
        allow_private_peers: cli.allow_private_peers,
        behind_proxy:    cli.behind_proxy,
        enable_mdns:     cli.enable_mdns,
        archive:         cli.archive,
    };
    // Audit POW-9: the node speaks its own network's protocol identifiers.
    // POW-3: below the minimum chain work the node advertises no frontier or
    // headers to peers (initial block download; `serve::serve_sync_request`).
    let mut node = match network::NetworkNode::new(net_cfg)
        .map(|n| n.with_chain(core::node_chain_id()).with_minimum_chain_work(ingress::minimum_chain_work()))
    {
        Ok(n)  => { info!("P2P: {}", n.peer_id); n }
        Err(e) => { error!("network: {}", e); std::process::exit(1); }
    };

    let (our_score, our_count) = {
        let d = dag.read();
        (d.tip_blue_score(), d.block_count() as u64)
    };

    let node_state = Arc::new(RwLock::new(rpc::NodeState {
        tip_blue_score: our_score,
        block_count:    our_count,
        version:        env!("CARGO_PKG_VERSION").into(),
        // POW-3: in initial block download from the start when the stored
        // chain is below the minimum chain work (the latch keeps it so).
        is_syncing:     ingress::below_minimum_chain_work(&dag.read(), ingress::minimum_chain_work()),
        ..Default::default()
    }));

    // NET-2: inbound frames carry their origin; gossip block verdicts flow
    // back to the network loop, which relays only Accepted frames.
    let (block_tx, mut block_rx) = mpsc::channel::<network::Inbound>(1000);
    let (vtx2, validation_rx) = mpsc::channel::<network::GossipValidation>(4096);
    // MEM-5 / MEM-6: processor → network penalties (an invalid orphan whose
    // frame left gossipsub's cache) and network → processor disconnect
    // notices (the tx relay drops per-connection budgets and orphans).
    let (net_ctl_tx, net_ctl_rx) = mpsc::channel::<network::NetworkControl>(1024);
    let (peer_ev_tx, mut peer_ev_rx) = mpsc::channel::<network::PeerEvent>(1024);
    node.attach_control(net_ctl_rx);
    node.attach_peer_events(peer_ev_tx);
    // B1-T19: gossip transactions have their own channel and their own task
    // (the transaction relay below), so a transaction flood can neither fill
    // the block channel nor queue block work behind transaction work.
    let (tx_ingest_tx, mut tx_ingest_rx) = mpsc::channel::<network::Inbound>(1000);
    node.attach_tx_ingest(tx_ingest_tx);
    // The applied-chain moves of accepted blocks, block processor → tx relay
    // (its orphan-transaction bookkeeping, MEM-6).
    let (chain_move_tx, mut chain_move_rx) = mpsc::channel::<accept::ChainMove>(256);
    // NET-2 residual: peers' remote addresses (their network group keys the
    // proof-of-work budget).
    let peer_addrs = node.peer_addrs();
    let (outbound_tx, outbound_rx) = mpsc::channel::<network::NetworkMessage>(1000);

    // ── Sprint 2.c: Tip-change broadcast channel ─────────────────────────────
    //
    // Fired whenever the selected DAG tip moves (Extension or Reorg disposition
    // in accept_block, or successful add_block in the miner loop). Stratum
    // server subscribes and re-broadcasts mining.notify with clean_jobs=true.
    //
    // Capacity 64: generous for burst tolerance; a lagging subscriber
    // (Lagged error variant) triggers a warn-and-continue in the server loop.
    //
    // When no subscriber exists (stratum disabled), send() returns Err and
    // all senders `let _ = ...` it. Safe no-op.
    let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(64);

    // Coherence C2: the node's shielded pool, reloaded from RocksDB (audit
    // COH-2: persisted with the UTXO set in every connect batch).
    let shielded = match crate::coherence::ShieldedPool::load(&store) {
        Ok(pool) => Arc::new(RwLock::new(pool)),
        Err(e) => {
            error!("cannot load the persisted shielded-pool state: {}. Refusing to start.", e);
            std::process::exit(1);
        }
    };

    // DAG-1 / DAG-11: load the persisted invalid-block set and reconcile any
    // state a pre-fix non-atomic commit left behind, before any block is
    // accepted. Reconciliation runs its repairs first (step 2: blocks with
    // applied effects but no DAG record are rolled back onto the block the
    // UTXO set sits on) and only then the DAG-11 residual chain-state check
    // (`accept::check_chain_state`), so the check never misfires on a state
    // step 2 repairs.
    if let Err(e) = accept::reconcile_on_startup(&dag, &store, &shielded) {
        // Re-audit B2-T1: the hardening recheck of stored blocks must
        // complete before any block is accepted.
        if e.starts_with(accept::HARDENING_RECHECK_FAILED) {
            error!("{e}. Refusing to start.");
            std::process::exit(1);
        }
        // DAG-11 residual: the footprint of the pre-fix NON-atomic extension
        // commit (UTXO effects without an undo record), which reconciliation
        // cannot repair, makes it refuse; rebuild the chain state from the
        // block bodies. A node must not run on an inconsistent UTXO set: it
        // would disqualify valid blocks and leave the network, so without the
        // means to rebuild it refuses to start.
        let faults = match accept::check_chain_state(&dag, &store) {
            Ok(f) => f,
            Err(ce) => {
                error!("chain-state check failed: {ce}. Refusing to start.");
                std::process::exit(1);
            }
        };
        if faults.is_empty() {
            // Audit DAG-11: continuing would leave the best chain unconnected
            // with nothing to retry it but the next block; like Bitcoin Core
            // ("Failed to connect best block", an init error), refuse to start.
            error!("start-up chain-state reconciliation failed: {}", e);
            // Review of audit F1, finding 4: the start-up rebuild only runs
            // when `check_chain_state` finds faults, which it did not here,
            // so a restart with --carryover-snapshot would repair nothing.
            error!("Refusing to start: the best valid chain cannot be connected. Fix the cause above \
                    (disk space, permissions, storage errors) and restart; if it persists, the data \
                    directory is damaged: resynchronize into a fresh, empty --data-dir (or start from a \
                    copy of an archival node's data directory).");
            std::process::exit(1);
        } else {
            for f in &faults {
                error!("chain-state check: {}", f);
            }
            let Some(snap_path) = cli.carryover_snapshot.as_ref() else {
                error!("the chain state is inconsistent (interrupted pre-fix commit). Restart with \
                        --carryover-snapshot <bloch-g3-carryover.tsv> to rebuild it from the block \
                        bodies. Refusing to start.");
                std::process::exit(1);
            };
            let snap = match std::fs::read(snap_path).map_err(|e| vec![e.to_string()])
                .and_then(|b| core::carryover::verify_and_convert(&b))
            {
                Ok(s) => s,
                Err(failures) => {
                    for f in &failures { error!("carryover for the rebuild: {f}"); }
                    error!("cannot rebuild the chain state without a valid carryover snapshot. Refusing to start.");
                    std::process::exit(1);
                }
            };
            let locked = core::vesting::genesis_tranches().unwrap_or_else(|e| {
                error!("locked allocations unavailable for the rebuild: {e}. Refusing to start.");
                std::process::exit(1);
            });
            let genesis = core::genesis_block();
            let gh = genesis.block_hash();
            let seed = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
                st.stage_carryover(batch, &snap, &locked).map_err(|e| e.to_string())?;
                // Exactly what first boot writes for the genesis block.
                for tx in &genesis.transactions {
                    st.stage_tx_index(batch, &tx.txid(), &gh, 0).map_err(|e| e.to_string())?;
                }
                Ok(())
            };
            match accept::rebuild_chain_state(&dag, &store, &shielded, &seed) {
                Ok(r) => info!("chain state rebuilt: {} block(s) re-applied from genesis", r.connected_blocks),
                Err(e) => {
                    error!("chain-state rebuild failed: {e}. Refusing to start.");
                    std::process::exit(1);
                }
            }
            if let Err(e) = accept::reconcile_on_startup(&dag, &store, &shielded) {
                error!("start-up chain-state reconciliation failed after the rebuild: {}. Refusing to start.", e);
                std::process::exit(1);
            }
        }
    }
    // PoWit finality: pin fork choice to the node's own finalized checkpoint
    // (the one it pinned last, the applied chain's), advanced by those it
    // learns from any stored block (kept current by accept_block from here
    // on; `consensus::finality`).
    powit::update_finalized(&dag, &store);
    if let Some((h, height)) = dag.read().finalized() {
        info!("PoWit finalized checkpoint: {} (DAG height {})", hex::encode(&h[..8]), height);
    }
    // POW-3: say at start-up when the stored chain is below the minimum
    // chain work (a fresh node, or one whose chain stopped short of it):
    // the node is in initial block download until a chain with that much
    // work arrives (Bitcoin Core's IsInitialBlockDownload). The IBD latch
    // repeats it as a warning while it lasts (`maybe_release_ibd`).
    {
        let (tip_work, min) = (ingress::tip_blue_work(&dag.read()), ingress::minimum_chain_work());
        if tip_work < min {
            info!("initial block download: the selected tip's chain work {:#x} is below the minimum chain work {:#x} \
                   ({}%); the miner stays paused and unrequested blocks are refused until the node syncs a chain \
                   with at least that much work (--minimumchainwork lowers it)",
                  tip_work, min, tip_work.saturating_mul(100) / min);
        }
    }
    if cli.reindex_addresses {
        // One layout, one rebuild: the DAG-8 migration's (chain positions,
        // rows exactly as a connect writes them, pruned blocks' rows kept).
        info!("reindexing the address history and the selected-chain indexes over the applied chain…");
        match accept::reindex_chain_indexes(&dag, &store) {
            Ok(r) => info!("address history rebuilt: {} blocks, {} rows, {} unresolved inputs{}",
                r.blocks, r.rows, r.unresolved,
                if r.lost > 0 { format!(", {} row(s) of pruned blocks not recoverable", r.lost) } else { String::new() }),
            Err(e) => { error!("address reindex failed: {e}"); std::process::exit(1); }
        }
    }
    // The ONE next-block height of mempool admission, eviction, templates
    // and getdaginfo (wallets): the node's next template height. Kept
    // current by accept_block from here on (nothing else runs yet).
    {
        let next = accept::sync_mempool_next_height(&dag, &store, &mempool);
        info!("next block height (template height): {}", next);
    }

    // ── Message processor ─────────────────────────────────────────────────────
    let store2    = store.clone();
    let shielded2 = shielded.clone();
    let dag2    = dag.clone();
    let state2  = node_state.clone();
    let mem2    = mempool.clone();
    let otx2    = outbound_tx.clone();
    let tip_tx2 = tip_tx.clone();

    // ── Phase-2 Kaspa sync-negotiation shared state (drop-in, additive) ───────
    // `peer_state`: PeerId-keyed chain-state table, written by the network loop
    // (P4) where the real libp2p PeerId is in scope; read here by the processor
    // + nudge. `frontier`: in-flight tip-request tracker gating IBD release.
    // Lock order everywhere: dag → peer_state → frontier → node_state.
    let peer_state = Arc::new(sync::peer_state::PeerStateTable::new());
    let frontier   = Arc::new(parking_lot::Mutex::new(sync::frontier::FrontierState::new()));
    let peer_state2 = peer_state.clone();
    let frontier2   = frontier.clone();

    // ── Echo-storm fix: correlate Headers replies with OUR OWN requests ──────
    // The gossip GetHeaders server arm replies by BROADCASTING Headers to the
    // whole mesh (wire compat: a gossip requester can only be answered on
    // gossip), so every node also receives replies meant for someone else.
    // Since the Headers frame carries no requester id (adding one would change
    // the wire format for the deployed fleet), correlation is local: record a
    // monotonic ms timestamp every time WE send a GetHeaders; a Headers frame
    // is "solicited" only within HEADERS_SOLICITED_WINDOW_MS of that. Shared
    // between the processor task (send sites + Headers arm) and the 30s nudge
    // task (its own send site). u64::MAX = never sent.
    let proc_start = std::time::Instant::now();
    let getheaders_sent_ms = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let getheaders_sent2   = getheaders_sent_ms.clone();

    // DAG-6, pruned nodes: the bodies an operator override (`invalidateblock`
    // / `reconsiderblock`, RPC task) needs wait for one in the DAG
    // (`accept::request_bodies`, the same record the acceptance pipeline
    // uses); this wakes the processor to request them at once through its
    // missing-parent tracker — the one request path for wanted bodies (the
    // periodic sweep would pick them up within `SWEEP_PERIOD` anyway).
    let body_requests = Arc::new(tokio::sync::Notify::new());
    let body_requests2 = body_requests.clone();

    // ── Transaction relay task (B1-T19) ───────────────────────────────────────
    //
    // Gossip transactions are judged here, on their own task fed by their own
    // channel (`NetworkNode::attach_tx_ingest`), never on the block processor:
    // admission (signatures last, budgeted per connection and node-wide, in
    // signatures AND bytes hashed — `mempool::relay::signature_gate_cost`)
    // used to be awaited inline on the one loop that also handles NewBlock,
    // fed by one shared FIFO that drops frames when full, so a transaction
    // flood delayed — and could drop — blocks. The applied-chain moves of
    // accepted blocks arrive from the block processor (`chain_move_tx`).
    //
    // PoWit items (witness shares, attestations, equivocation proofs) travel
    // on the transaction topic and are judged here too, never on the block
    // processor: cheap checks first, then verification (a share's proof is a
    // GnB-SMH v3 evaluation, an attestation a KES signature check) on the
    // blocking pool through their own bounded, budgeted proof-of-work
    // scheduler (`ingress::PowitIngress`), with the block gate's rollout-
    // gated penalties; relayed only once admitted.
    {
        let (store_t, mem_t, dag_t, state_t, otx_t, vtx_t, ctl_t) = (
            store.clone(), mempool.clone(), dag.clone(), node_state.clone(),
            outbound_tx.clone(), vtx2.clone(), net_ctl_tx.clone(),
        );
        let peer_addrs_t = peer_addrs.clone();
        let activation_t = core::activation::hardening_activation_height();
        tokio::spawn(async move {
            use futures::future::FutureExt;
            let mut backoff = ingress::SupervisorBackoff::new(
                std::time::Duration::from_millis(100),
                std::time::Duration::from_secs(30),
            );
            loop {
                let run_started = std::time::Instant::now();
                let relay_task = async {
                    // MEM-5 / MEM-6: validated transaction relay — signature
                    // budgets and the bounded orphan-transaction pool. Shared
                    // with the blocking pool, where admission runs.
                    let tx_relay = Arc::new(parking_lot::Mutex::new(mempool::relay::TxRelay::new()));
                    // MEM-6: verdicts withheld for orphan frames, keyed by the
                    // frame's wtxid and timed from its arrival (settled from
                    // the relay's OrphanEvents: Accept / Reject / Ignore) and
                    // re-announcements.
                    let mut deferred: mempool::relay::DeferredVerdicts<network::InboundOrigin> =
                        mempool::relay::DeferredVerdicts::new();
                    let mut sweep = tokio::time::interval(sync::parent_fetch::SWEEP_PERIOD);
                    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    sweep.reset();
                    // PoWit gossip: the bounded verification queue and its
                    // results (from the blocking pool).
                    let mut powit_core = ingress::PowitIngress::default();
                    let (powit_done_tx, mut powit_done_rx) =
                        mpsc::unbounded_channel::<(ingress::PowitJob, Result<(), String>)>();
                    loop {
                        tokio::select! {
                            // A PoWit item verified off this task.
                            Some((job, result)) = powit_done_rx.recv() => {
                                if let Err(e) = &result {
                                    debug!("PoWit item {} refused: {}", hex::encode(&job.id[..8]), e);
                                }
                                let in_force = ingress::block_penalties_in_force(selected_tip_height(&dag_t), activation_t);
                                let v = powit_core.complete(job, &result, in_force, std::time::Instant::now());
                                report_powit_verdict(&vtx_t, &ctl_t, v);
                                dispatch_powit(&mut powit_core, &powit_done_tx, &dag_t, &store_t, &vtx_t);
                            }
                            m = tx_ingest_rx.recv() => {
                                let Some(network::Inbound { msg, origin }) = m else { break };
                                if let network::NetworkMessage::NewPowitItem { id, kind, data } = msg {
                                    let now = std::time::Instant::now();
                                    let source = pow::verifier::PowSource {
                                        peer:  origin.peer(),
                                        group: origin.peer().and_then(|p| peer_addrs_t.group(&p)),
                                    };
                                    let in_force = ingress::block_penalties_in_force(selected_tip_height(&dag_t), activation_t);
                                    if let Some(v) = powit_core.on_item(id, kind, data, origin, source, in_force, now) {
                                        report_powit_verdict(&vtx_t, &ctl_t, v);
                                    }
                                    dispatch_powit(&mut powit_core, &powit_done_tx, &dag_t, &store_t, &vtx_t);
                                    continue;
                                }
                                // Validated transaction relay (MEM-5 / NET-2 / NET-4).
                                //
                                // The network loop does not relay a gossiped
                                // transaction on decode: it waits for the verdict
                                // computed here. The shared admission function (same
                                // rules as sendrawtransaction and reorg re-injection —
                                // strict decode, size, standardness incl. dust, witness
                                // and version policy, known/recent-reject, inputs from
                                // the UTXO set or the pool, version rule and maturity at
                                // the NEXT block height — `pool_next_height` — fees,
                                // replacement and chain limits) runs cheapest first; the
                                // frame's decoding and the signature step are charged to
                                // the DELIVERING CONNECTION's and the node-wide budgets
                                // (never the self-chosen gossip author), refunded on
                                // admission. Accept → relayed; Reject (malformed or
                                // consensus-invalid, once the chain contains the
                                // hardening activation block: `penalties_in_force`) →
                                // not relayed and the delivering peer takes gossipsub's
                                // invalid-message penalty; before that block an older
                                // release that forwards every frame unvalidated may be
                                // the honest deliverer, so the same frame is answered
                                // Ignore; Ignore → dropped without penalty (policy,
                                // duplicates, recent rejects, budgets). MEM-6: an
                                // orphan's verdict is WITHHELD (keyed by the frame's
                                // wtxid, timed from its arrival) and settled from the
                                // relay's OrphanEvents. P0: admission runs on the
                                // blocking pool so PQ signature work cannot stall this
                                // task's reactor.
                                let network::NetworkMessage::NewTransaction { txid, tx_data } = msg else {
                                    report_verdict(&vtx_t, &origin, network::GossipVerdict::Ignore);
                                    continue;
                                };
                                // The connection that delivered the frame (gossip
                                // propagation_source): the key of the budget and of
                                // the orphan quotas. The signed gossip author is
                                // chosen by the sender and bounds nothing.
                                let peer = origin.peer();
                                // The signed gossip author: for logs only.
                                let author = match &origin {
                                    network::InboundOrigin::Gossip { author, .. } => *author,
                                    _ => None,
                                };
                                let received_at = origin.received_at().unwrap_or_else(std::time::Instant::now);
                                let next_height = mempool::admission::pool_next_height(&dag_t.read(), &store_t, &mem_t);
                                let (store_v, mem_v, relay_v) = (store_t.clone(), mem_t.clone(), tx_relay.clone());
                                let outcome = tokio::task::spawn_blocking(move || {
                                    relay_v.lock().on_gossip_tx(
                                        &store_v, &mem_v, next_height, &txid, &tx_data, peer,
                                        std::time::Instant::now(), unix_now_secs())
                                }).await;
                                match outcome {
                                    Ok(o) => {
                                        if o.invalid {
                                            warn!("tx {} from {:?} (author {:?}) INVALID ({:?}): {}",
                                                hex::encode(&txid[..8]), peer, author, o.verdict, o.detail);
                                        } else {
                                            debug!("tx {} verdict {:?}: {}", hex::encode(&txid[..8]), o.verdict, o.detail);
                                        }
                                        if o.orphaned {
                                            if let Some(back) = deferred.defer(o.wtxid, origin, received_at, std::time::Instant::now()) {
                                                report_verdict(&vtx_t, &back, network::GossipVerdict::Ignore);
                                            }
                                        } else {
                                            report_verdict(&vtx_t, &origin, o.verdict);
                                        }
                                        settle_orphan_events(&mut deferred, &vtx_t, &ctl_t, &o.orphans);
                                    }
                                    Err(e) => {
                                        warn!("tx verify task failed: {}", e);
                                        report_verdict(&vtx_t, &origin, network::GossipVerdict::Ignore);
                                    }
                                }
                                state_t.write().mempool_size = mem_t.size();
                            }
                            // MEM-5 / MEM-6: a connection closed — forget its
                            // signature budget and the orphans it delivered.
                            Some(ev) = peer_ev_rx.recv() => {
                                let network::PeerEvent::Disconnected(peer) = ev;
                                let events = tx_relay.lock().on_peer_disconnected(peer);
                                settle_orphan_events(&mut deferred, &vtx_t, &ctl_t, &events);
                            }
                            // MEM-6: what an accepted block (and the orphan blocks
                            // it unblocked) did to the APPLIED chain: orphan
                            // transactions it confirms or conflicts with are
                            // dropped; those waiting on a transaction it gained (or
                            // lost back to the pool) are re-tried (and announced).
                            // Nothing for a fork-loser or merge candidate. Judged at
                            // the pool's next height, as every admission.
                            Some(chain) = chain_move_rx.recv() => {
                                if chain.is_empty() {
                                    continue;
                                }
                                let next_height = mempool::admission::pool_next_height(&dag_t.read(), &store_t, &mem_t);
                                let (store_v, mem_v, relay_v) = (store_t.clone(), mem_t.clone(), tx_relay.clone());
                                if let Ok(events) = tokio::task::spawn_blocking(move || {
                                    // R4 (B1-T20): the move lists block hashes; the
                                    // bodies are read here, on the blocking pool,
                                    // within Core's 20 MB budget.
                                    let (connected_txs, disconnected_txs) =
                                        (chain.connected_txs(&store_v), chain.disconnected_txs(&store_v));
                                    relay_v.lock().on_chain_moved(
                                        &store_v, &mem_v, next_height, &connected_txs, &disconnected_txs,
                                        std::time::Instant::now(), unix_now_secs())
                                }).await {
                                    settle_orphan_events(&mut deferred, &vtx_t, &ctl_t, &events);
                                }
                            }
                            // MEM-6: expire orphan transactions and re-try those
                            // whose parents arrived through any path (miner, RPC)
                            // — a bounded, round-robin scan — at the pool's next
                            // height, as every admission.
                            _ = sweep.tick() => {
                                let next_height = mempool::admission::pool_next_height(&dag_t.read(), &store_t, &mem_t);
                                let (store_v, mem_v, relay_v) = (store_t.clone(), mem_t.clone(), tx_relay.clone());
                                if let Ok(events) = tokio::task::spawn_blocking(move || {
                                    relay_v.lock().retry_orphans(&store_v, &mem_v, next_height,
                                        std::time::Instant::now(), unix_now_secs())
                                }).await {
                                    settle_orphan_events(&mut deferred, &vtx_t, &ctl_t, &events);
                                }
                                let now = std::time::Instant::now();
                                let stale = {
                                    let relay = tx_relay.lock();
                                    deferred.prune(|w| relay.orphans().contains(w), now)
                                };
                                for origin in stale {
                                    report_verdict(&vtx_t, &origin, network::GossipVerdict::Ignore);
                                }
                                let due: Vec<core::Transaction> = deferred.due_reannouncements(now).iter()
                                    .filter_map(|t| mem_t.get_tx(t)).collect();
                                announce_txs(&otx_t, &due);
                                // PoWit: answer stale queued items, keep the
                                // budget maps bounded.
                                dispatch_powit(&mut powit_core, &powit_done_tx, &dag_t, &store_t, &vtx_t);
                                powit_core.gc_at(now);
                            }
                        }
                    }
                };
                match std::panic::AssertUnwindSafe(relay_task).catch_unwind().await {
                    Ok(()) => {
                        info!("transaction relay: input channel closed; task exiting cleanly");
                        break;
                    }
                    Err(panic) => {
                        crate::metrics::inc_task_panic("transaction_relay");
                        let detail = panic.downcast_ref::<&str>().map(|s| (*s).to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "<non-string panic payload>".to_string());
                        let wait = backoff.on_panic(run_started.elapsed());
                        error!("transaction relay PANICKED: {} — node stays up; restarting in {:?}", detail, wait);
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        use futures::future::FutureExt;
        // ── P0 supervision (roadmap §2.5, top reliability risk #1) ───────────
        // A panic that escapes the processing loop is caught, logged, metered
        // (`task_panics_total`) and the loop restarts without dropping the
        // node. POW-2 (audit): the restart back-off is now RESET after a
        // healthy run (`ingress::SupervisorBackoff`); it used to only grow, to
        // its 30 s cap, so one crafted frame every 30 s kept block processing
        // stopped network-wide. (The panic itself — `height + CHECKPOINT_DEPTH`
        // on a wire-supplied `u64::MAX` — is gone: every peer-supplied integer
        // below is compared with saturating arithmetic.)
        //
        // Orphan-pool state lives inside the restartable closure, so a panic
        // rebuilds it empty (peers resend). A clean channel close exits.
        let mut backoff = ingress::SupervisorBackoff::new(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(30),
        );
        // B1-T7: the activation whose block, once on the selected chain, puts
        // penalties for relayed block frames in force.
        let activation = core::activation::hardening_activation_height();
        loop {
          let run_started = std::time::Instant::now();
          let processor = async {
            // The block-ingress core (`ingress::BlockIngress`, shared with the
            // integration tests): the orphan pool (POW-4: bounded by entries
            // AND bytes, globally and per delivering peer, evicting by ARRIVAL
            // order; first copy of an id wins, POW-8; reverse index parent ->
            // waiting orphans; POW-3 announced work), the missing-parent
            // retry tracker (orphan-deadlock fix: the periodic sweep
            // re-requests lost parents with backoff and prunes hopeless ones),
            // the merge-backed insertion budget (DAG-7 / POW-3 / B1-T5), the
            // POW-3 anti-DoS work rule and the minimum chain work. Lives inside
            // the restartable closure: a panic rebuilds it empty (peers resend).
            let mut ingress_core = ingress::BlockIngress::with_limits(ingress::OrphanLimits::default());
            let mut orphan_sweep = tokio::time::interval(sync::parent_fetch::SWEEP_PERIOD);
            orphan_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Never fire immediately on (re)start — tick 0 is now.
            orphan_sweep.reset();
            // NET-6: tip claims only trigger (rate-limited) directed pulls and
            // reciprocal announcements; they never latch IBD.
            let mut claims = ingress::ClaimPolicy::new();
            // NET-2 residual (Phase 4): proof-of-work evaluations run OFF this
            // task, on the blocking pool, at most `PowLimits::workers` at a
            // time, from a queue bounded globally, per peer and per network
            // group, charged to the delivering peer's and its network group's
            // budgets (refunded for a valid proof). A block whose proof is
            // pending is held as its frame (`Inbound`) and resubmitted to the
            // ingress core when the result arrives; its gossip verdict is
            // reported then, or `Ignore` if it waited past gossipsub's cache.
            let mut pow_sched: pow::verifier::PowScheduler<network::Inbound> =
                pow::verifier::PowScheduler::new(pow::verifier::PowLimits::default());
            let ibd_pow_workers = pow::verifier::ibd_workers();
            let (pow_done_tx, mut pow_done_rx) = mpsc::unbounded_channel::<PowDone>();
            // B1-T5: the verdicts of buffered orphan frames are withheld until
            // the orphan connects (Accept), is refused, or leaves the pool.
            let mut deferred_blocks: ingress::DeferredBlockVerdicts<network::InboundOrigin> =
                ingress::DeferredBlockVerdicts::new();
            let ctx = ingress::AcceptCtx {
                dag: &dag2, store: &store2, mempool: &mem2, node_state: &state2,
                tip_tx: Some(&tip_tx2), shielded: &shielded2,
            };

            loop {
            // Orphan-deadlock fix: select between the inbound channel, the
            // proof-of-work results and the ~30s orphan sweep.
            let inbound = tokio::select! {
                m = block_rx.recv() => match m { Some(m) => m, None => break },
                // NET-2 residual: a proof evaluated off this task. The block's
                // frame is resubmitted below; the ingress core now knows its
                // proof (`KnownPow`).
                Some(done) = pow_done_rx.recv() => {
                    pow_sched.complete(done.outcome, std::time::Instant::now());
                    done.inbound
                }
                // DAG-6: an operator override made bodies wait for one.
                _ = body_requests2.notified() => {
                    request_awaited_bodies(&dag2, &mut ingress_core.parent_fetch, &otx2).await;
                    continue;
                }
                _ = orphan_sweep.tick() => {
                    let ready = sweep_orphan_parents(
                        &mut ingress_core.orphans, &mut ingress_core.parent_fetch, &dag2, &otx2,
                    ).await;
                    // Defensive liveness: a waited-on parent that is ALREADY in
                    // the DAG (its accept raced the waiting_for insert) would
                    // otherwise strand its orphans forever — drain them now.
                    for p in ready {
                        ingress_core.drain_orphans(p, &ctx);
                    }
                    // MEM-6: what the drained blocks did to the applied chain,
                    // for the transaction relay's orphan bookkeeping.
                    let chain = ingress_core.take_chain_move();
                    if !chain.is_empty() && chain_move_tx.try_send(chain).is_err() {
                        warn!("transaction relay busy: an applied-chain move was not passed on (its orphan sweep catches up)");
                    }
                    settle_block_verdicts(&mut ingress_core, &mut deferred_blocks, &vtx2, &net_ctl_tx, &dag2, activation);
                    frontier2.lock().set_orphan_evidence(ingress_core.orphans.max_evidence_height());
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                    pow_sched.gc_at(std::time::Instant::now());
                    continue;
                }
            };
            let network::Inbound { msg, origin } = inbound;
            match msg {

                // NET-6: a peer's tip claim. Clamped once, consistently; a claim
                // ahead of us triggers a rate-limited DIRECTED pull (headers +
                // frontier) — it no longer sets `is_syncing`. The IBD latch is
                // set only by work-backed evidence (NewBlock arm below) and
                // released by `maybe_release_ibd`.
                network::NetworkMessage::PeerTip { blue_score: peer_s, ref peer_id, .. } => {
                    let our_s = dag2.read().tip_blue_score();
                    let act = claims.evaluate(peer_s, our_s, std::time::Instant::now());
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        // RPC display hint only (clamped).
                        if act.clamped > s.best_seen_blue_score { s.best_seen_blue_score = act.clamped; }
                    }
                    if act.pull {
                        info!("Peer {} claims to be ahead ({} > {}), pulling headers + frontier",
                            network::truncate_utf8(peer_id, 64), act.clamped, our_s);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                        let _ = otx2.send(network::NetworkMessage::GetTips).await;
                    } else if act.reciprocal {
                        // Mesh fix (reciprocal tip): the announcing peer is BEHIND
                        // us; answer with a fresh-timestamp Version (unique bytes,
                        // never dedup-dropped) carrying our blue_score.
                        let height = dag2.read().block_count() as u64;
                        debug!("peer behind (score {} < {}), sending reciprocal tip", act.clamped, our_s);
                        let _ = otx2.send(network::NetworkMessage::Version {
                            version:    network::PROTOCOL_VERSION,
                            user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                            blue_score: our_s,
                            height,
                            timestamp:  std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        }).await;
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // NET-7 (audit): gossip PULLS are never served. Answering them
                // made every node broadcast a reply to the whole mesh (up to
                // 2,000 headers, a full block, a NotFound) for every request —
                // O(N²) amplification, and DAG-12's unclamped `limit`. Pulls are
                // served only over directed `/gnb/sync/1` (network/mod.rs,
                // `serve_sync_request`, limit clamped), one requester, one
                // answer. The network loop no longer even delivers these.
                network::NetworkMessage::GetTips
                | network::NetworkMessage::GetHeaders { .. }
                | network::NetworkMessage::GetBlock { .. } => {
                    debug!("gossip pull ignored (served only over directed /gnb/sync/1)");
                }

                // Frontier reconciliation: a peer's advertised frontier. NET-10:
                // only a SOLICITED frontier (the answer to our own directed
                // GetTips) drives fetches, at most MAX_NEW_TIPS_PER_RESPONSE new
                // tips per answer and MAX_FRONTIER_IN_FLIGHT overall. NET-6: a
                // frontier gap no longer latches IBD by itself — the fetched tips
                // do, if they arrive as full-difficulty orphans well ahead of us.
                network::NetworkMessage::Tips { tips, .. } => {
                    // B1-T2 / NET-10: the network loop delivers a directed
                    // Tips only as the answer to one of our GetTips
                    // (`sync_rr::check_response`).
                    let Some(peer) = origin.peer().filter(|_| origin.is_solicited()) else {
                        debug!("unsolicited Tips ignored");
                        continue;
                    };
                    let advertised: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                    let now = std::time::Instant::now();
                    // NET-10 residual: at most MAX_FRONTIER_IN_FLIGHT_PER_PEER
                    // tips in flight on behalf of one peer's answers.
                    let to_req = {
                        let d = dag2.read();
                        frontier2.lock().request_from(
                            peer,
                            &advertised,
                            |h| accept::is_known_block_in(&d, &store2, h) || ingress_core.orphans.contains(h),
                            now,
                            sync::frontier::MAX_NEW_TIPS_PER_RESPONSE,
                        )
                    };
                    if !to_req.is_empty() {
                        // Pulled from the peer that advertised them first,
                        // charged to its pull quota (B1-T2 / B1-T6).
                        let _ = net_ctl_tx.send(network::NetworkControl::Fetch { source: peer, hashes: to_req }).await;
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // IBD step 3: headers — request missing blocks. NET-10: only the
                // answer to our own directed GetHeaders is acted on (gossip
                // Headers are no longer delivered; an overheard stream must
                // never drive the pipeline).
                network::NetworkMessage::Headers { entries } => {
                    // B1-T2: the network loop delivers a directed Headers
                    // only as the answer to one of our GetHeaders, with at
                    // most the requested count, none below the requested
                    // blue score (`sync_rr::check_response`); a Headers
                    // answer to GetPeers / GetTips / GetBlock used to be
                    // acted on here (2,000 GetBlocks per frame).
                    let Some(peer) = origin.peer().filter(|_| origin.is_solicited()) else {
                        debug!("unsolicited Headers ignored ({} entries)", entries.len());
                        continue;
                    };
                    let mut missing: Vec<[u8; 32]> = {
                        let d = dag2.read();
                        entries.iter()
                            .filter(|e| !accept::is_known_block_in(&d, &store2, &e.hash) && !ingress_core.orphans.contains(&e.hash))
                            .map(|e| e.hash).collect()
                    };
                    if !missing.is_empty() {
                        info!("IBD: need {}/{} blocks", missing.len(), entries.len());
                        // One answer never asks for more than one batch, and
                        // its pulls go first to the peer that announced them,
                        // charged to that peer's quota of the shared pull
                        // queue (`network::pull::MAX_PENDING_PER_SOURCE`).
                        missing.truncate(MAX_FETCH_PER_ANSWER);
                        let _ = net_ctl_tx.send(network::NetworkControl::Fetch { source: peer, hashes: missing }).await;
                    }
                    let recent_request = {
                        let sent = getheaders_sent2.load(std::sync::atomic::Ordering::Relaxed);
                        sent != u64::MAX
                            && (proc_start.elapsed().as_millis() as u64).saturating_sub(sent)
                                <= HEADERS_SOLICITED_WINDOW_MS
                    };
                    if entries.is_empty() {
                        maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                    } else if entries.len() >= 500 && recent_request {
                        // Pipeline IBD: a full batch means the serving peer has
                        // more — request the next batch immediately.
                        let next_from = entries.iter().map(|e| e.blue_score).max().unwrap_or(0);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: next_from, limit: 500, nonce: getblock_nonce() }).await;
                    }
                }

                // A peer told us it cannot serve this body. NET-9: counted once
                // per DISTINCT answering peer toward abandoning a frontier tip, so
                // a single peer can no longer abandon a tip by itself.
                network::NetworkMessage::BlockNotFound { block_hash, .. } => {
                    let Some(peer) = origin.peer().filter(|_| origin.is_solicited()) else { continue };
                    warn!("peer {} cannot serve block {} (pruned or unknown) — an \
                           archival peer is needed to bootstrap from this height",
                          peer, hex::encode(&block_hash[..8]));
                    frontier2.lock().note_not_found_from(&block_hash, peer, std::time::Instant::now());
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // Full validation before storing — with orphan pool support.
                //
                // NET-2 (audit): checks run CHEAPEST FIRST and the 64 MiB PoW
                // only after every cheap check has passed — off this task
                // (NET-2 residual, Phase 4: the PoW scheduler); the gossip
                // frame is relayed only after the verdict computed here is
                // reported (`report_verdict`): Accept → forwarded, Reject → not
                // forwarded and the delivering peer takes gossipsub's P4
                // penalty, Ignore → dropped without penalty. B1-T7: who is
                // charged follows `ingress::block_penalty`.
                network::NetworkMessage::NewBlock { block_data, block_hash, height, blue_score } => {
                    let now = std::time::Instant::now();
                    let tip_h = selected_tip_height(&dag2);
                    // B1-T7: the delivering peer authored the frame (nobody
                    // relayed it), or sent it as the answer to our own pull.
                    let self_authored = origin.delivered_by_author();
                    let in_force = ingress::block_penalties_in_force(tip_h, activation);
                    let penalty = |base: network::GossipVerdict, fault: ingress::BlockFault| {
                        ingress::block_penalty(base, fault, self_authored, in_force)
                    };
                    let plain = |v: network::GossipVerdict| ingress::BlockPenalty { gossip: v, misbehaving: false };
                    let pow_source = pow::verifier::PowSource {
                        peer:  origin.peer(),
                        group: origin.peer().and_then(|p| peer_addrs.group(&p)),
                    };
                    let step: BlockStep = 'blk: {
                        // Known = buffered, or in the DAG — unless a body of
                        // it is wanted (`accept::awaits_body`: its body was
                        // rejected for a witness-dependent reason, or a
                        // connect / operator override needs its missing —
                        // e.g. pruned, DAG-6 — body) and this is the answer
                        // to one of our own directed pulls (how wanted bodies
                        // are requested). Any other copy of a DAG block, a
                        // pushed old body included, is ignored here before
                        // decoding.
                        let known_in_dag = dag2.read().has_block(&block_hash)
                            && (!origin.is_solicited() || accept::is_known_block(&dag2, &store2, &block_hash));
                        if known_in_dag || ingress_core.orphans.contains(&block_hash) {
                            break 'blk BlockStep::Verdict(plain(network::GossipVerdict::Ignore));
                        }
                        // POW-2: bound the peer-supplied height BEFORE any
                        // decoding or arithmetic (unsolicited frames only — an
                        // answer to our own pull may legitimately be far ahead).
                        if !origin.is_solicited() && ingress::unsolicited_height_too_far_ahead(height, tip_h) {
                            debug!("NewBlock {} claims h={} far above tip h={}; ignored (pull-based IBD fetches it)",
                                hex::encode(&block_hash[..8]), height, tip_h);
                            break 'blk BlockStep::Verdict(plain(network::GossipVerdict::Ignore));
                        }
                        // Sprint 1.c: Bitcoin-format wire. A widened varint
                        // (which releases before the minimal-varint rule
                        // accept and relay) is Ignored, not penalized; every
                        // other malformed body is Rejected
                        // (`ingress::verdict_for_block_decode_error`).
                        let block = match core::Block::from_wire_bytes(&block_data) {
                            Ok(b) => b,
                            Err(e) => {
                                let v = ingress::verdict_for_block_decode_error(&e);
                                if v == network::GossipVerdict::Ignore {
                                    debug!("block {} not in its minimal encoding ({}); dropped without penalty \
                                            (an older node may have relayed it; its canonical encoding is accepted)",
                                        hex::encode(&block_hash[..8]), e);
                                } else {
                                    warn!("block deserialise: {}", e);
                                }
                                break 'blk BlockStep::Verdict(penalty(v, ingress::BlockFault::ContextFree));
                            }
                        };
                        // SECURITY (audit H2): bind the wire-supplied block_hash /
                        // height to the actual block content before anything else.
                        let real_hash = block.block_hash();
                        if real_hash != block_hash {
                            warn!("block id mismatch: claimed {} but content hashes to {}; dropping",
                                hex::encode(&block_hash[..8]), hex::encode(&real_hash[..8]));
                            break 'blk BlockStep::Verdict(penalty(network::GossipVerdict::Reject, ingress::BlockFault::ContextFree));
                        }
                        if height != block.height {
                            warn!("block {} height mismatch: claimed {} vs content {}; dropping",
                                hex::encode(&block_hash[..8]), height, block.height);
                            break 'blk BlockStep::Verdict(penalty(network::GossipVerdict::Reject, ingress::BlockFault::ContextFree));
                        }

                        // Everything else is the ingress core (shared with the
                        // integration tests), cheapest checks first:
                        //  * the unrequested-block and minimum-chain-work rules
                        //    (POW-3, Phase 4: Bitcoin Core's AcceptBlock);
                        //  * structure without PoW;
                        //  * ORPHAN (a parent unknown): backfill-flood guard (an
                        //    unsolicited far-below-tip orphan is dropped — backfill
                        //    is pulled), the anti-DoS bits floor BEFORE the proof
                        //    (NET-2 / POW-4), the proof, then the bounded pool;
                        //  * parents known: the POW-3 anti-DoS WORK rule — the
                        //    block's chain must come within ANTI_DOS_WINDOW_BLOCKS
                        //    of our tip's work, or be backed by a proof-of-work-
                        //    verified orphan chain announced on top of it, or by a
                        //    contextually checked voucher (rationed, B1-T5) — and
                        //    the checks accept_block runs before its proof
                        //    (height, expected bits, timestamp), BEFORE the proof,
                        //    storage or DAG insertion; then POW-8 metadata
                        //    normalization, `accept_block` and the iterative orphan
                        //    drain, which applies the work rule to every drained
                        //    orphan (B1-T5).
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs()).unwrap_or(0);
                        let t_validate = std::time::Instant::now();
                        let gated = ingress_core.handle_block_gated(block, block_hash, block_data.len(), origin.peer(),
                            origin.is_solicited(), now, now_unix, &ctx, &mut KnownPow(&pow_sched));
                        let outcome = match gated {
                            ingress::Gated::Done(o) => o,
                            ingress::Gated::PowPending(_) => break 'blk BlockStep::Pow,
                        };
                        match outcome {
                            ingress::BlockOutcome::Known | ingress::BlockOutcome::PoolRefused => {
                                BlockStep::Verdict(plain(network::GossipVerdict::Ignore))
                            }
                            ingress::BlockOutcome::BodyRestored => {
                                info!("wanted body of block {} h={} stored (it waited for one: rejected \
                                       for a witness-dependent reason, or pruned and needed again)",
                                    hex::encode(&block_hash[..8]), height);
                                BlockStep::Verdict(plain(network::GossipVerdict::Ignore))
                            }
                            ingress::BlockOutcome::Dropped(ingress::DropReason::OrphanBelowFloor) => {
                                // NET-2 residual: no honest miner publishes an
                                // orphan 16 times easier than a block at our
                                // tip (`ingress::orphan_floor_penalty`: gossip
                                // is charged to the deliverer's proof-of-work
                                // budget, its author penalised if it delivered
                                // it itself; an answer to our own pull is only
                                // dropped).
                                let (p, charge) = ingress::orphan_floor_penalty(origin.is_solicited(), self_authored, in_force);
                                if charge {
                                    let _ = pow_sched.charge(&pow_source, now);
                                }
                                debug!("orphan {} h={} below the anti-DoS floor (tip h={})",
                                    hex::encode(&block_hash[..8]), height, tip_h);
                                BlockStep::Verdict(p)
                            }
                            ingress::BlockOutcome::Dropped(reason) => {
                                debug!("block {} h={} dropped before PoW: {:?} (tip h={})",
                                    hex::encode(&block_hash[..8]), height, reason, tip_h);
                                crate::metrics::inc_block_backfill_dropped();
                                BlockStep::Verdict(plain(network::GossipVerdict::Ignore))
                            }
                            ingress::BlockOutcome::Invalid(reason) => {
                                warn!("block {} rejected ({})", hex::encode(&block_hash[..8]), reason);
                                BlockStep::Verdict(penalty(network::GossipVerdict::Reject, ingress::BlockFault::ContextFree))
                            }
                            ingress::BlockOutcome::BodyRefused(reason) => {
                                // B1-T2 review: a Reject here sanctions the
                                // peer that served the body (an answer to our
                                // own pull: its author, `ingress::block_penalty`)
                                // only for what the block id commits to.
                                warn!("wanted body of block {} h={} not stored: {}",
                                    hex::encode(&block_hash[..8]), height, reason);
                                BlockStep::Verdict(penalty(ingress::verdict_for_accept_error(&reason),
                                    ingress::accept_error_fault(&reason)))
                            }
                            ingress::BlockOutcome::Buffered { request, evidence, evicted } => {
                                if evicted > 0 {
                                    debug!("orphan pool full: evicted {} oldest orphan(s)", evicted);
                                }
                                for mp in request {
                                    // Orphan-deadlock fix: the attempt was recorded
                                    // by the core so the sweep can re-request it.
                                    let _ = otx2.send(network::NetworkMessage::GetBlock {
                                        block_hash: mp, nonce: getblock_nonce(),
                                    }).await;
                                }
                                {
                                    let mut fr = frontier2.lock();
                                    fr.note_received(&block_hash);
                                    fr.set_orphan_evidence(ingress_core.orphans.max_evidence_height());
                                }
                                // NET-6: the IBD latch is set ONLY by work-backed
                                // evidence — a full-difficulty orphan claiming to be
                                // well ahead of our tip.
                                if evidence {
                                    let mut s = state2.write();
                                    if !s.is_syncing {
                                        info!("IBD latched: work-backed orphan claims h={} (tip h={})", height, tip_h);
                                    }
                                    s.is_syncing = true;
                                }
                                maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                                // B1-T5: not relayed before it connects.
                                BlockStep::DeferOrphan
                            }
                            ingress::BlockOutcome::Processed { admission, result, drained, missing_bodies } => {
                                crate::metrics::observe_block_validation(t_validate.elapsed().as_secs_f64());
                                // Bodies the chain needs that are missing (e.g.
                                // pruned, DAG-6) or were rejected for a
                                // witness-dependent reason wait for one; they
                                // are requested right after the verdict
                                // (`request_awaited_bodies`).
                                if !missing_bodies.is_empty() {
                                    warn!("{} block bod(ies) wanted to follow the chain through {}; requesting them",
                                        missing_bodies.len(), hex::encode(&block_hash[..8]));
                                }
                                match result {
                                    Err(e) => {
                                        crate::metrics::inc_block_rejected();
                                        warn!("block {} h={} REJECTED: {}", hex::encode(&block_hash[..8]), height, e);
                                        BlockStep::Verdict(penalty(ingress::verdict_for_accept_error(&e), ingress::accept_error_fault(&e)))
                                    }
                                    Ok(_) => {
                                        crate::metrics::inc_block_accepted();
                                        if admission != ingress::WorkAdmission::NearTip {
                                            info!("block {} h={} admitted as {:?} (POW-3 work rule); {} orphan(s) drained",
                                                hex::encode(&block_hash[..8]), height, admission, drained.len());
                                        }
                                        {
                                            let mut fr = frontier2.lock();
                                            fr.note_received(&block_hash);
                                            fr.set_orphan_evidence(ingress_core.orphans.max_evidence_height());
                                        }
                                        maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                                        BlockStep::Verdict(plain(network::GossipVerdict::Accept))
                                    }
                                }
                            }
                        }
                    };
                    match step {
                        BlockStep::Verdict(p) => {
                            report_verdict(&vtx2, &origin, p.gossip);
                            // NET-2 residual + B1-T2: the deliverer's sanction
                            // (`block_sanction`).
                            if let Some(c) = block_sanction(p, &origin) {
                                let _ = net_ctl_tx.try_send(c);
                            }
                        }
                        BlockStep::DeferOrphan => {
                            // Only a gossip frame owes a verdict.
                            if origin.pending_verdict().is_some() {
                                let received_at = origin.received_at().unwrap_or(now);
                                if let Some(back) = deferred_blocks.defer(block_hash, origin, received_at, now) {
                                    report_verdict(&vtx2, &back, network::GossipVerdict::Ignore);
                                }
                            }
                        }
                        BlockStep::Pow => {
                            // NET-2 residual: every cheap check passed; the proof
                            // is evaluated off this task, charged to the
                            // delivering peer and its network group.
                            let job = pow::verifier::PowJob {
                                id: block_hash,
                                height,
                                source: pow_source,
                                solicited: origin.is_solicited(),
                                received_at: origin.received_at().unwrap_or(now),
                                payload: network::Inbound {
                                    msg: network::NetworkMessage::NewBlock { block_hash, blue_score, height, block_data },
                                    origin,
                                },
                            };
                            if let Err((refusal, job)) = pow_sched.submit(job, now) {
                                debug!("block {} not evaluated: proof-of-work queue refused it ({:?})",
                                    hex::encode(&block_hash[..8]), refusal);
                                report_verdict(&vtx2, &job.payload.origin, network::GossipVerdict::Ignore);
                            }
                        }
                    }
                    // B1-T5: verdicts of orphans the drain connected, refused or
                    // dropped; and of frames whose orphan left the pool.
                    settle_block_verdicts(&mut ingress_core, &mut deferred_blocks, &vtx2, &net_ctl_tx, &dag2, activation);
                    // P5-G: while the IBD latch holds (the miner and the
                    // witness duties wait), proofs are verified on every CPU
                    // but one (`pow::verifier::ibd_workers`), else on half.
                    pow_sched.set_initial_block_download(state2.read().is_syncing.then_some(ibd_pow_workers));
                    dispatch_pow(&mut pow_sched, &pow_done_tx, &vtx2);
                    // A body rejected for a witness-dependent reason, or found
                    // missing (pruned, DAG-6) during this acceptance: ask peers
                    // for it now; the orphan sweep retries with backoff.
                    request_awaited_bodies(&dag2, &mut ingress_core.parent_fetch, &otx2).await;
                    // MEM-6: what this block (and the orphan blocks it
                    // unblocked) did to the APPLIED chain, for the
                    // orphan-transaction bookkeeping of the transaction relay
                    // task — never on the block's relay path.
                    let chain = ingress_core.take_chain_move();
                    if !chain.is_empty() && chain_move_tx.try_send(chain).is_err() {
                        warn!("transaction relay busy: an applied-chain move was not passed on (its orphan sweep catches up)");
                    }
                }

                // Local heartbeat only: a PeerCount from a peer would let it set
                // our RPC peer count / addresses (and the miner's no-peer gate).
                network::NetworkMessage::PeerCount { count, addresses } => {
                    if matches!(origin, network::InboundOrigin::Local) {
                        let mut s = state2.write();
                        s.peer_count = count as u32;
                        s.peer_addresses = addresses;
                    }
                }

                // B1-T19: gossip transactions are delivered to the transaction
                // relay task (`NetworkNode::attach_tx_ingest`), never here.
                network::NetworkMessage::NewTransaction { .. } => {
                    report_verdict(&vtx2, &origin, network::GossipVerdict::Ignore);
                }

                // PoWit items (shares, attestations, equivocation proofs) are
                // delivered to the transaction relay task with transactions
                // (`network::goes_to_tx_ingest`), which verifies them off this
                // loop under budgets (`ingress::PowitIngress`), never here: a
                // share's proof is a GnB-SMH v3 evaluation, and awaiting it
                // here stalled every block behind a flood of junk shares.
                network::NetworkMessage::NewPowitItem { .. } => {
                    report_verdict(&vtx2, &origin, network::GossipVerdict::Ignore);
                }

                // NET-6: same claim handling as PeerTip (rate-limited directed
                // pull; never latches IBD). Version frames carry a fresh
                // timestamp, so they are the dedup-proof tip announcement.
                network::NetworkMessage::Version { version, blue_score: peer_s, .. } => {
                    if version < network::MIN_PROTOCOL_VERSION { continue; }
                    let our_s = dag2.read().tip_blue_score();
                    let act = claims.evaluate(peer_s, our_s, std::time::Instant::now());
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        if act.clamped > s.best_seen_blue_score { s.best_seen_blue_score = act.clamped; }
                    }
                    if act.pull {
                        info!("Version peer claims to be ahead (score {} > {}), pulling headers + frontier", act.clamped, our_s);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                        let _ = otx2.send(network::NetworkMessage::GetTips).await;
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }
                network::NetworkMessage::VersionAck
                | network::NetworkMessage::PeerExchange { .. }
                | network::NetworkMessage::PeerRequest => {}
            }
            }
          };
          // Catch a panic that escapes the processing loop, meter + log it, and
          // restart with bounded exponential backoff (reset after a healthy
          // run). Ok(()) means the input channel closed cleanly → exit.
          match std::panic::AssertUnwindSafe(processor).catch_unwind().await {
              Ok(()) => {
                  info!("message-processor: input channel closed; task exiting cleanly");
                  break;
              }
              Err(panic) => {
                  crate::metrics::inc_task_panic("message_processor");
                  let detail = panic.downcast_ref::<&str>().map(|s| (*s).to_string())
                      .or_else(|| panic.downcast_ref::<String>().cloned())
                      .unwrap_or_else(|| "<non-string panic payload>".to_string());
                  let wait = backoff.on_panic(run_started.elapsed());
                  error!("message-processor PANICKED: {} — node stays up; restarting loop in {:?}",
                      detail, wait);
                  tokio::time::sleep(wait).await;
              }
          }
        }
    });

    // ── Mesh fix: proactive IBD nudge ─────────────────────────────────────────
    //
    // A fresh joiner can miss every inbound tip signal: the seed's on-connect
    // announce races our Subscribe, the 60s periodic PeerTip is dedup-fragile,
    // and colocation scoring can graylist proxied peers. Don't wait to be told
    // we're behind — while we have peers and either (a) we've never seen a
    // remote tip, or (b) we know we're behind (is_syncing latched, or the
    // best announced blue_score exceeds ours), publish GetHeaders every 30s.
    //
    // This also un-crawls multi-batch IBD: the Headers handler requests one
    // 500-block batch and never issues a follow-up GetHeaders, so a node
    // thousands of blocks behind previously advanced one batch per 60s tip
    // re-announce. With the nudge it re-requests from its ADVANCING blue_score
    // at least every 30s. At parity the nudge stops (and the serving side
    // suppresses empty Headers replies), so steady-state cost is zero.
    {
        let dag_n        = dag.clone();
        let state_n      = node_state.clone();
        let otx_n        = outbound_tx.clone();
        let peer_state_n = peer_state.clone();
        let frontier_n   = frontier.clone();
        let getheaders_sent_n = getheaders_sent_ms.clone();
        tokio::spawn(async move {
            let mut nudge = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                nudge.tick().await;
                let our_s = dag_n.read().tip_blue_score();
                let (peers, syncing, best_seen, seen_tip) = {
                    let s = state_n.read();
                    (s.peer_count, s.is_syncing, s.best_seen_blue_score, s.seen_first_tip)
                };
                if peers > 0 {
                    // Retained legacy fallback (gossip path): only when we have a
                    // reason to believe we're behind, exactly as before.
                    if syncing || !seen_tip || best_seen > our_s {
                        debug!("IBD nudge: GetHeaders from score {} (best_seen={} syncing={} seen_tip={})",
                            our_s, best_seen, syncing, seen_tip);
                        getheaders_sent_n.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx_n.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    }
                    // Phase-2 frontier reconciliation: every peer replies Tips.
                    let _ = otx_n.send(network::NetworkMessage::GetTips).await;
                    // Re-request timed-out tip GetBlocks.
                    let now = std::time::Instant::now();
                    let stale = frontier_n.lock().expired(sync::TIP_REQUEST_TIMEOUT, now);
                    for h in stale {
                        let _ = otx_n.send(network::NetworkMessage::GetBlock { block_hash: h, nonce: getblock_nonce() }).await;
                    }
                    // Re-test the blue_work-verified IBD latch so a node never
                    // wedges in is_syncing after it has actually caught up —
                    // the liveness backstop against a fabricated high announced
                    // score freezing the node.
                    maybe_release_ibd(&dag_n, &peer_state_n, &frontier_n, &state_n);
                } else {
                    // POW-3: a node with no peer cannot sync to the minimum
                    // chain work either; say so as the latch would.
                    let tip_work = ingress::tip_blue_work(&dag_n.read());
                    warn_if_long_below_minimum(&state_n, tip_work, ingress::minimum_chain_work(), std::time::Instant::now());
                }
            }
        });
    }

    // ── Ready ─────────────────────────────────────────────────────────────────
    let (score, count) = { let d = dag.read(); (d.tip_blue_score(), d.block_count()) };
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  P2P   {}", cli.listen);
    info!("  RPC   {}:{}", cli.rpc_bind, cli.rpc_port);
    info!("  Mine  {}", if cli.mine { "ON" } else { "OFF" });
    info!("  DAG   {} blocks, score={}", count, score);

    // ── UTXO Reindex DISABLED (needs topological ordering for DAG) ──
    /*
    {
        let bc = dag.read().block_count() as u64;
        if bc > 1 {
            info!("Reindexing UTXOs from {} blocks...", bc);
            let _ = store.clear_utxos();
            let mut all_blocks = store.iter_all_blocks();
            // Sort by height for correct topological processing
            all_blocks.sort_by_key(|(_, b)| b.height);
            let mut reindexed = 0u64;
            for (hash, block) in &all_blocks {
                for tx in &block.transactions {
                    let txid = tx.txid();
                    for (j, out) in tx.outputs.iter().enumerate() {
                        let _ = store.put_utxo(&txid, j as u32, out);
                    }
                    if !tx.is_coinbase() {
                        for inp in &tx.inputs {
                            let _ = store.delete_utxo(&inp.prev_txid, inp.prev_index);
                        }
                    }
                }
                reindexed += 1;
            }
            info!("UTXO reindex complete: {} blocks processed", reindexed);
        }
    }*/

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");


    // ── PoWit pool upkeep, on EVERY node (PoWit audit finding 7) ──────────
    // Each new tip: forget what it made stale (shares out of the window,
    // expired or superseded attestations, proofs against barred keys) and
    // refresh the pool's witness sets. Off the acceptance lock; the DAG read
    // lock is held only to read the tip. (Every pool admission also follows
    // the tip first, so a lagging task never leaves a stale pool in use.)
    {
        let (dag_p, store_p) = (dag.clone(), store.clone());
        let mut tip_rx_p = tip_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match tip_rx_p.recv().await {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
                let (dag_b, store_b) = (dag_p.clone(), store_p.clone());
                let _ = tokio::task::spawn_blocking(move || powit::pool().follow_selected_tip(&dag_b, &store_b)).await;
            }
        });
    }

    // ── PoWit witness: share mining + checkpoint attestations ──────────────
    if let Some(key) = cli.witness_key.clone() {
        let Some(pw) = cli.witness_password_file.clone() else {
            eprintln!("--witness-key needs --witness-password-file");
            std::process::exit(2);
        };
        let payout = match cli.witness_payout.as_deref().map(address_to_script_pubkey) {
            Some(Ok(spk)) => spk,
            Some(Err(e)) => { eprintln!("--witness-payout: {:?}", e); std::process::exit(2); }
            None => { eprintln!("--witness-key needs --witness-payout <address>"); std::process::exit(2); }
        };
        let duty = match powit::WitnessDuty::load(&key, &pw, payout, &data_path) {
            Ok(d) => Arc::new(d),
            Err(e) => { eprintln!("witness: {}", e); std::process::exit(2); }
        };
        info!("🛡  PoWit witness key {} (activation {}, signer instance {})", hex::encode(duty.key_id),
              match core::powit_height() { u64::MAX => "off".to_string(), h => h.to_string() },
              hex::encode(duty.guard().instance()));
        // Signer protection: the rollback guard at start (and again before
        // every vote). A halted signer keeps the node running and reports
        // the alert (log, gnb_powit_signer_halted, getpowitinfo.signers).
        if let Some(alert) = duty.scan_for_rollback(&dag.read(), &store) {
            error!("🛡  PoWit witness signing halted: {alert}");
        }

        // Duty loop: follow the tip, sign the newest checkpoint once, gossip
        // equivocation proofs.
        {
            let (dag_w, store_w, otx_w, duty_w) = (dag.clone(), store.clone(), outbound_tx.clone(), duty.clone());
            let mut tip_rx_w = tip_tx.subscribe();
            tokio::spawn(async move {
                let mut sent_evidence: HashSet<[u8; 20]> = HashSet::new();
                loop {
                    // Every new tip, or every 2 s.
                    tokio::select! {
                        _ = tip_rx_w.recv() => {}
                        _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                    }
                    let (dag_b, store_b, duty_b) = (dag_w.clone(), store_w.clone(), duty_w.clone());
                    let out = tokio::task::spawn_blocking(move || {
                        let d = dag_b.read();
                        powit::pool().prune(&d, &store_b);
                        // POW-3: no vote on a checkpoint of a selected chain
                        // below the minimum chain work (initial block
                        // download; it may be an eclipsing peer's cheap
                        // chain, and the persistent vote record would then
                        // bar this key's vote on the real one).
                        if ingress::below_minimum_chain_work(&d, ingress::minimum_chain_work()) {
                            return (None, powit::pool_evidence_items(), None);
                        }
                        let att = match duty_b.maybe_attest(&d, &store_b) {
                            Ok(Some(a)) => {
                                let _ = powit::pool().admit_attestation(a.clone(), &d, &store_b);
                                Some(a)
                            }
                            Ok(None) => None,
                            Err(e) => { warn!("witness: {}", e); None }
                        };
                        // PoCI (ObenBlock): pruned for absence, online again: rejoin.
                        let rejoin = match duty_b.maybe_rejoin(&d, &store_b) {
                            Ok(Some(r)) => powit::pool().admit_rejoin(r.clone(), &d, &store_b)
                                .map_err(|e| warn!("witness rejoin: {}", e)).ok().map(|_| r),
                            Ok(None) => None,
                            Err(e) => { warn!("witness rejoin: {}", e); None }
                        };
                        if let Some(r) = rejoin {
                            info!("🛡  witness key pruned for absence: rejoin for epoch {} published", r.epoch);
                            let (id, kind, data) = powit::rejoin_item(&r);
                            return (att, powit::pool_evidence_items(), Some((id, kind, data)));
                        }
                        (att, powit::pool_evidence_items(), None)
                    }).await;
                    let Ok((att, evidence, rejoin)) = out else { continue };
                    if let Some((id, kind, data)) = rejoin {
                        let _ = otx_w.try_send(network::NetworkMessage::NewPowitItem { id, kind, data });
                    }
                    if let Some(a) = att {
                        info!("🛡  attested checkpoint slot {} ({})", a.target.height, hex::encode(&a.target.hash[..8]));
                        let (id, kind, data) = powit::attestation_item(&a);
                        let _ = otx_w.try_send(network::NetworkMessage::NewPowitItem { id, kind, data });
                    }
                    for (key, (id, kind, data)) in evidence {
                        if sent_evidence.insert(key) {
                            warn!("🛡  equivocation by witness {} — proof gossiped", hex::encode(key));
                            let _ = otx_w.try_send(network::NetworkMessage::NewPowitItem { id, kind, data });
                        }
                    }
                }
            });
        }

        // Share miners: read the tip under a short lock, mine without it.
        let threads = cli.share_threads.unwrap_or(2);
        for t in 0..threads {
            let (dag_s, store_s, otx_s, payout, witness) =
                (dag.clone(), store.clone(), outbound_tx.clone(), duty.payout_script.clone(), duty.key_id);
            std::thread::Builder::new().name(format!("share-miner-{t}")).spawn(move || {
                let stop = std::sync::atomic::AtomicBool::new(false);
                loop {
                    // POW-3: no share on a selected tip below the minimum
                    // chain work (initial block download), as no block is
                    // mined there.
                    let tip = {
                        let d = dag_s.read();
                        if ingress::below_minimum_chain_work(&d, ingress::minimum_chain_work()) {
                            None
                        } else {
                            d.selected_tip().and_then(|h| d.get_block_data(&h).map(|bd| (h, bd.height)))
                        }
                    };
                    let Some((tip, tip_h)) = tip.filter(|(_, h)| core::powit_active(h + 1)) else {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        continue;
                    };
                    let Some(attested) = store_s.get_block(&tip).ok().flatten() else {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        continue;
                    };
                    if let Some(share) = powit::mine_share(&attested, tip, witness, &payout, rand::random(), 16, &stop) {
                        let admitted = {
                            let d = dag_s.read();
                            powit::pool().admit_share(share.clone(), &d, &store_s)
                        };
                        match admitted {
                            Ok(_) => {
                                debug!("share found on h={}", tip_h);
                                let (id, kind, data) = powit::share_item(&share);
                                let _ = otx_s.try_send(network::NetworkMessage::NewPowitItem { id, kind, data });
                            }
                            Err(e) => debug!("own share not admitted: {}", e),
                        }
                    }
                }
            }).expect("spawn share miner");
        }
        info!("🛡  {} share-miner thread(s)", threads);
    }

    // ── Continuous Mining Loop ────────────────────────────────────────────────
    if cli.mine {
        // Fresh-miner fork guard: if the operator configured a bootstrap peer
        // or DNS seed they intend to JOIN an existing network, so mining before
        // we have any peer would fork from genesis on the forgeable chain.
        // Nodes with no peer/seed configured (intentional solo / island) keep
        // mining immediately.
        let wants_to_join = !cli.peer.is_empty() || !cli.dns_seed.is_empty();
        let store_m  = store.clone();
        let dag_m    = dag.clone();
        let state_m  = node_state.clone();
        let mem_m    = mempool.clone();
        let otx_m    = outbound_tx.clone();
        let tip_tx_m = tip_tx.clone();  // Sprint 2.c: tip broadcast for stratum
        let shielded_m = shielded.clone(); // LEG1: accept_block needs the shielded pool
        let miner_addr = cli.miner_address.clone().unwrap_or_else(|| {
            eprintln!("❌ --mine requires --miner-address <gnb1q…>: there is no default payout address.");
            std::process::exit(2);
        });
        // FIX #8 / Legacy L-3: convert miner address to a proper 20-byte
        // script_pubkey, or exit loudly — never silently mine into an
        // unspendable script built from the raw --miner-address bytes.
        let miner_spk = address_to_script_pubkey(&miner_addr)
            .unwrap_or_else(|e| {
                eprintln!("❌ --miner-address {miner_addr:?} is not a valid GnB address: {e}. Refusing to mine into an address that cannot be parsed back — every coinbase reward would be unspendable.");
                std::process::exit(1);
            });

        // Capacity: grind the SIS search across all logical CPUs by default
        // (result-identical — see pow::mine_sis_pow_parallel). Override with
        // --mine-threads. Clamp to >=1.
        let mine_threads = cli.mine_threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .max(1);

        tokio::spawn(async move {
            info!("⛏  Miner started → {} ({} thread(s))", miner_addr, mine_threads);
            let mut mining_round: u64 = 0;
            // Sprint GG: warn once when we first see IBD active, log
            // transition back to ready so operators see the transition.
            let mut was_syncing_last_tick: bool = false;
            let mut warned_no_peers: bool = false;
            // Sync-stall release: is_syncing pauses mining during genuine IBD,
            // but must never latch forever. If the tip has not advanced for
            // SYNC_STALL_SECS while syncing — peers cannot deliver the announced
            // best_seen tip (e.g. the whole network is wedged behind the
            // reachability perf wall) — resume mining on the best local tip.
            // is_syncing STAYS true so the IBD nudge keeps pulling; PoW advances
            // the chain in the meantime and we reorg to any heavier chain the
            // instant its blocks arrive. This is what stops a network-wide
            // freeze from being permanent.
            const SYNC_STALL_SECS: u64 = 90;
            let mut last_seen_tip: u64 = dag_m.read().tip_blue_score();
            let mut last_tip_advance = std::time::Instant::now();
            let mut warned_stall_release: bool = false;
            loop {
                // Fresh-miner fork guard (see wants_to_join above): a node told
                // to join a network but with 0 peers so far must not mine — it
                // would build an isolated fork from genesis that the network
                // rejects on cumulative work. Pause until at least one peer.
                // Wait not just for a connection but for the first remote tip:
                // there is a window where peer_count>0 but no PeerTip has been
                // evaluated yet, during which a fresh joiner would mine a
                // genesis fork. seen_first_tip closes that race.
                let (has_no_peer, no_tip_yet) = {
                    let s = state_m.read();
                    (s.peer_count == 0, !s.seen_first_tip)
                };
                if wants_to_join && (has_no_peer || no_tip_yet) {
                    if !warned_no_peers {
                        info!("⛏  not ready to mine yet — waiting to connect and see the network tip (would otherwise fork from genesis); still trying to reach the configured peer/seed");
                        warned_no_peers = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if warned_no_peers {
                    info!("⛏  connected and tip evaluated — miner active");
                    warned_no_peers = false;
                }
                // Sprint GG fix (pre-IBD mining bug, 2026-04-22):
                // During IBD the DAG tip reflects the local view, which
                // lags the network by up to thousands of blocks. Mining
                // against a stale tip produces blocks at low height
                // which lose to the network chain on blue work (and were,
                // before audit DAG-6, refused by its finality rule). Pre-fix,
                // fresh miners would burn CPU for hours producing
                // orphan blocks that never paid out — an awful new-user
                // experience that looked like a protocol fault.
                //
                // This check pauses the miner loop while is_syncing is
                // true. The heartbeat logs the transition once in each
                // direction so operators can see when IBD started and
                // when mining resumed.
                let syncing_now = state_m.read().is_syncing;
                // Track tip progress for the sync-stall release.
                {
                    let cur_tip = dag_m.read().tip_blue_score();
                    if cur_tip > last_seen_tip {
                        last_seen_tip = cur_tip;
                        last_tip_advance = std::time::Instant::now();
                        warned_stall_release = false;
                    }
                }
                let sync_stalled = last_tip_advance.elapsed()
                    >= std::time::Duration::from_secs(SYNC_STALL_SECS);
                // (Mining through a stall can no longer self-finalize a solo
                // fork: there is no finality checkpoint and no reorg-depth
                // limit, audit DAG-6 — a strictly heavier chain reorgs us at
                // any depth once its blocks arrive. The old FINALITY_FROZEN
                // flag is gone.)
                // POW-3: never mine on a selected tip below the minimum chain
                // work, stalled or not (Bitcoin Core's miners get no template
                // in initial block download): it may be a cheap chain this
                // node's own pulls fetched from an eclipsing peer, and the
                // stall release below exists for an unreachable frontier,
                // not for a chain the release does not trust.
                let below_min_work = {
                    let d = dag_m.read();
                    ingress::ibd_template_refusal(&d, ingress::minimum_chain_work())
                };
                if let Some(why) = below_min_work {
                    if !was_syncing_last_tick {
                        info!("⛏  miner paused: {why}");
                        was_syncing_last_tick = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if syncing_now && !sync_stalled {
                    if !was_syncing_last_tick {
                        info!("⛏  IBD in progress — miner paused, will resume when sync completes");
                        was_syncing_last_tick = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if syncing_now && sync_stalled && !warned_stall_release {
                    warn!("⛏  sync stalled {}s at tip {} (announced best_seen unreachable) — resuming mining on best local tip; will reorg when heavier blocks arrive",
                        SYNC_STALL_SECS, last_seen_tip);
                    warned_stall_release = true;
                }
                if was_syncing_last_tick && !syncing_now {
                    info!("⛏  IBD complete — miner resumed at tip");
                    was_syncing_last_tick = false;
                }

                // Re-broadcast mempool TXs before mining
                {
                    let pending = mem_m.get_for_block(100);
                    for tx in &pending {
                        let txid = tx.txid();
                        // Sprint 1.d: Bitcoin-format tx wire.
                        let data = tx.to_wire_bytes(true);
                        let _ = otx_m.try_send(network::NetworkMessage::NewTransaction {
                            txid, tx_data: data,
                        });
                    }
                }
                // Re-broadcast mempool TXs every ~30s to ensure propagation
                if mining_round % 10 == 0 {
                    let pending = mem_m.get_for_block(100);
                    for tx in &pending {
                        let txid = tx.txid();
                        let data = tx.to_wire_bytes(true);
                        let _ = otx_m.try_send(network::NetworkMessage::NewTransaction {
                            txid, tx_data: data,
                        });
                    }
                }
                mining_round += 1;

                // ── Block template (audit MEM-2 / DAG-2 / MEM-1 / MEM-3) ──────
                // Shared with getblocktemplate (`template::build_block_template`):
                // at most MAX_PARENTS bodied, non-disqualified tips by blue work
                // (header-only tips are unmineable, see GhostDAG::bodied_tips);
                // expected ASERT bits for exactly those parents (fail closed if
                // underivable — never mine on a guessed target); transactions as
                // whole ancestor packages by package fee rate, parents before
                // children (MEM-6 CPFP), under a byte budget measured exactly
                // like the consensus size rule of the template's height, each
                // re-validated at that height against the UTXO set plus the
                // outputs of the transactions placed before it (offenders are
                // evicted from the mempool with their descendants); coinbase
                // fees recomputed (N-7 duplicate-outpoint safe).
                // Coinbase reserve: our own coinbase at its widest encoding,
                // including the 80-byte hardening commitment, in the larger
                // of the two size measures (valid on both sides of the
                // activation). `assemble_block` writes the commitment and the
                // tagged Merkle root when the template's height requires them.
                let cb_reserve = template::miner_coinbase_reserve(&miner_spk);
                let tmpl = match template::build_block_template(&dag_m, &store_m, &mem_m, cb_reserve) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("⛏  cannot build a block template: {} — skipping mining round \
                               (fail-closed, no guessed target)", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };
                // Below the PoWit activation 100% of subsidy + fees to the
                // miner; from it, the miner's part plus one output per
                // witness share of the template's PoWit section.
                let coinbase = tmpl.miner_coinbase(miner_spk.clone());
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs();
                // Never before a parent (validate_timestamp); the template
                // self-check runs every structural rule except the PoW.
                let mut block = match template::assemble_block(&tmpl, coinbase, now_ts) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("⛏  block template failed its self-check: {} — skipping round", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };

                // Proof-of-work search under the process's scheme
                // (`pow::mine_header_round`: GnB-SMH, or SHA-256d on ObenBlock).
                // Short rounds so the template — tips, mempool, timestamp — is
                // rebuilt often; a fresh random start nonce per round. Aborted
                // early when a new tip arrives.
                let header = block.header.clone();
                let block_height = block.height;
                let start_nonce: u64 = rand::random();
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let mut tip_rx = tip_tx_m.subscribe();
                let stop_on_tip = stop.clone();
                let tip_watch = tokio::spawn(async move {
                    if tip_rx.recv().await.is_ok() {
                        stop_on_tip.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
                let stop_m = stop.clone();
                let mined = tokio::task::spawn_blocking(move || {
                    pow::mine_header_round(&header, block_height, start_nonce,
                                           mine_threads, Some(&*stop_m))
                }).await;
                tip_watch.abort();

                match mined {
                    Ok(Some(nonce)) => {
                        block.header.nonce = nonce;
                        let hash = block.block_hash();
                        info!("⛏  Block found! h={} {}", block.height, hex::encode(&hash[..8]));

                        // ── Round-2 audit LEG1-selfmine-accept ──────────
                        // Route the self-mined block through the SAME
                        // accept_block pipeline every other ingress uses
                        // (network gossip, RPC submitblock, stratum submit).
                        // The old inline put_block/apply path here committed
                        // the block with NO consensus validation, so a miner
                        // bug the mempool can miss (coinbase over-claim, dust
                        // tx, wrong expected bits, below-finality height, ...)
                        // was persisted locally and only rejected by PEERS —
                        // silently forking the producer off its own network.
                        // accept_block handles the DAG insert, storage,
                        // UTXO/undo mutations (Sprint DD), retarget meta
                        // ("current_bits"), mempool cleanup and the stratum
                        // tip notification; commit_self_mined_block adds the
                        // structural gate + RPC-state refresh, mirroring the
                        // stratum/RPC submission callbacks exactly.
                        if let Err(e) = commit_self_mined_block(
                            &block,
                            &dag_m, &store_m, &mem_m, &state_m,
                            Some(&tip_tx_m), &shielded_m,
                        ) {
                            // A locally-mined block should never be rejected
                            // by our own acceptor — this indicates a miner
                            // bug, not a peer attack. Log loud, do NOT
                            // broadcast, and skip so the miner doesn't spin
                            // on (or propagate) an invalid block.
                            log::error!(
                                "mining: our own block {} was rejected by accept_block: {} — discarding (miner bug)",
                                hex::encode(hash), e,
                            );
                            // MEM-1/MEM-3: never retry with the same poisoned
                            // template — drop every pooled tx no longer minable.
                            let next_height = mempool::admission::pool_next_height(&dag_m.read(), &store_m, &mem_m);
                            let dropped = accept::revalidate_mempool(&store_m, &mem_m, next_height);
                            if dropped > 0 {
                                warn!("mining: evicted {} stale tx(s) after the rejected block", dropped);
                            }
                            continue;
                        }

                        // Sprint 1.c: Bitcoin-format wire (replaces bincode).
                        // Infallible — no Result to unwrap.
                        let data = block.to_wire_bytes();
                        let _ = otx_m.send(network::NetworkMessage::NewBlock {
                            block_hash: hash,
                            blue_score: block.blue_score,
                            height:     block.height,
                            block_data: data,
                        }).await;
                    }
                    _ => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    }
                }
            }
        });
    }

    // ── External block submission (RPC submitblock) ──────────────────────────
    let rpc_submit_block: Arc<rpc::SubmitBlockFn> = make_rpc_submit_block_cb(
        dag.clone(), store.clone(), mempool.clone(), node_state.clone(),
        shielded.clone(), outbound_tx.clone(), tip_tx.clone(), ingress::minimum_chain_work(),
    );
    // ── Built-in stratum servers (docs/STRATUM.md) ───────────────────────────
    // One work feed (templates from the getblocktemplate builder, rebuilt on
    // every tip change, every 60 s and at every stall-relief step) serves V1
    // and V2; found blocks take the submitblock hook above.
    if let Some(setup) = stratum_setup {
        let ctx = Arc::new(stratum::NodeContext {
            dag: dag.clone(), store: store.clone(), mempool: mempool.clone(),
            min_chain_work: ingress::minimum_chain_work(),
        });
        let work = stratum::work::spawn(ctx, tip_tx.subscribe());
        if let Some(addr) = setup.v1_addr {
            let listener = match stratum::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("stratum: cannot bind {addr}: {e}");
                    std::process::exit(1);
                }
            };
            if !addr.ip().is_loopback() {
                warn!("stratum: V1 on {addr} is plaintext and unauthenticated (anyone reaching the port can mine \
                       to their own address); firewall it or prefer --stratum-v2 (docs/STRATUM.md)");
            }
            let config = stratum::StratumConfig {
                bind_addr: addr, max_sessions: setup.v1_max_sessions,
                payout: setup.payout.clone(), accept_block: rpc_submit_block.clone(),
            };
            let (params, work) = (setup.params, work.clone());
            tokio::spawn(async move {
                if let Err(e) = stratum::serve(listener, config, params, work).await {
                    error!("stratum: V1 server stopped: {e}");
                }
            });
        }
        if let Some(addr) = setup.v2_addr {
            let key_path = cli.stratum_v2_key.clone()
                .unwrap_or_else(|| PathBuf::from(&cli.data_dir).join("stratum-v2-authority.json"));
            start_stratum_v2(addr, key_path, &setup, rpc_submit_block.clone(), work).await;
        }
    }

    // Audit DAG-6: operator recovery (invalidateblock / reconsiderblock).
    let rpc_chain_admin: Arc<rpc::ChainAdminFn> = make_chain_admin_cb(
        dag.clone(), store.clone(), mempool.clone(), node_state.clone(),
        shielded.clone(), tip_tx.clone(), body_requests.clone(),
    );
    // ObenBlock anchors in Bloch (docs/OBB-ANCHOR.md), advisory only
    // (DESIGN-obenblock §8): the registry is read periodically and compared
    // with the node's chain; nothing is pinned, refused or persisted.
    if let Some(url) = cli.bloch_rpc.as_deref() {
        let reader = match anchoring::BlochRpcReader::new(url, std::time::Duration::from_secs(15)) {
            Ok(r) => r,
            Err(e) => {
                error!("--bloch-rpc: {e}");
                std::process::exit(1);
            }
        };
        anchoring::restore(url.to_string());
        let every = std::time::Duration::from_secs(cli.bloch_anchor_interval.max(10));
        info!("bloch anchor: reading the registry at {url} every {}s (advisory)", every.as_secs());
        tokio::spawn(anchoring::run(Box::new(reader), every, dag.clone()));
    }

    let metrics_state = std::sync::Arc::new(
        crate::metrics::MetricsState::new(
            env!("CARGO_PKG_VERSION"),
            net_params.network_name,
        )
    );
    let metrics_config = crate::metrics::MetricsConfig {
        enabled:      cli.metrics,
        bind_address: metrics_bind,
        port:         cli.metrics_port,
    };
    // Install as process-wide singleton so instrumentation points in other
    // modules can increment counters via free functions without plumbing.
    if cli.metrics {
        crate::metrics::install(metrics_state.clone());
    }

    // Audit F1: Bitcoin Core's `AbortNode`. A block whose validation keeps
    // ending on a storage-engine failure (the node cannot read its chain
    // state) stops the node (`accept::NO_VERDICT_ABORT_AFTER`): acceptance
    // and templates refuse at once, and the process exits here with the
    // operator's message (`accept::no_verdict_abort_message`), under the
    // acceptance lock (no chain move in flight; every commit is one atomic
    // batch). A restart that meets the same failure refuses to start with
    // it. An inconsistent index never stops the node: the block is parked
    // and retried (review of audit F1, finding 1; `getdaginfo` no_verdict).
    let store_for_abort = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if let Some(reason) = store_for_abort.abort_reason() {
                let _guard = store_for_abort.acceptance_lock();
                error!("FATAL: stopping the node: {reason}");
                eprintln!("❌ gnb stopped: {reason}");
                std::process::exit(1);
            }
        }
    });

    // Periodic sync of gauges from NodeState to Prometheus.
    // Runs every 5s. Cheap — just atomic reads + atomic gauge sets.
    let state_for_metrics = node_state.clone();
    let mempool_for_metrics = mempool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let (height, peers) = {
                let s = state_for_metrics.read();
                (s.block_count as i64, s.peer_count as i64)
            };
            crate::metrics::set_block_count(height);
            crate::metrics::set_peer_count(peers);
            crate::metrics::set_mempool_size(mempool_for_metrics.size() as i64);
        }
    });

    // NET-14: validate the auxiliary servers' addresses before starting
    // them (a bad address is a configuration error, reported clearly), then
    // run them as independent tasks. A server that fails later (bind error,
    // runtime error) logs and stops ITSELF; only the network loop's exit
    // ends the node. Previously both sat in the top-level `select!`, so any
    // RPC/metrics failure (e.g. `--metrics-addr ::1`) stopped the node.
    if let Err(e) = rpc::resolve_bind_address(&rpc_bind, cli.rpc_port) {
        eprintln!("❌ invalid RPC address (--rpc-bind/--rpc-port): {e}");
        std::process::exit(2);
    }
    if metrics_config.enabled {
        if let Err(e) = rpc::resolve_bind_address(&metrics_config.bind_address, metrics_config.port) {
            eprintln!("❌ invalid metrics address (--metrics-addr/--metrics-port): {e}");
            std::process::exit(2);
        }
    }
    tokio::spawn(crate::metrics::start_metrics_server(
        metrics_config,
        metrics_state.clone(),
    ));
    tokio::spawn(rpc::start_rpc_server(
        rpc::RpcConfig {
            bind_address:              rpc_bind,
            port:                      cli.rpc_port,
            api_key,
            require_auth_for_writes:   cli.rpc_require_auth_for_writes,
            rate_limit_reads_per_min:  cli.rpc_rate_limit_reads,
            rate_limit_writes_per_min: cli.rpc_rate_limit_writes,
            trust_private_ranges:      cli.rpc_trust_private_ranges,
            allowed_origins:           cli.rpc_allow_origins.clone(),
            allowed_hosts:             cli.rpc_allow_hosts.clone(),
            trust_loopback:            cli.rpc_trust_loopback,
            proxy_client_header:       rpc_proxy_client_header.clone(),
        },
        node_state.clone(), store.clone(), mempool.clone(), dag.clone(), outbound_tx.clone(),
        // B5f pool seam: submitblock hook (see rpc::SubmitBlockFn).
        Some(rpc_submit_block.clone()),
        // Audit DAG-6: invalidateblock / reconsiderblock (see rpc::ChainAdminFn).
        Some(rpc_chain_admin.clone()),
    ));
    // Sprint EE (S3): `None` = no listen-addr report; production behavior
    // is byte-identical to before the harness affordance was added.
    match node.run_validated(block_tx, validation_rx, outbound_rx, dag.clone(), peer_state.clone(), store.clone(), None).await {
        Ok(_) => error!("Network exited"),
        Err(e) => error!("Network exited: {:?}", e),
    }
}

// ── External block submission callbacks (RPC submitblock) ──────────────────
//
// Both builders wrap the shared `accept_block` consensus pipeline. They are
// named functions (not inline closures in main()) so their gates can be
// unit-tested — see `external_submission_tests` at the bottom of this file.

/// Commit a block THIS node just mined (Round-2 audit LEG1-selfmine-accept).
///
/// Self-mined blocks MUST take the same acceptance pipeline as every other
/// ingress: structural gate first (same call + error shape as
/// `make_rpc_submit_block_cb` / `make_stratum_accept_block_cb`), then the
/// shared `accept_block` (consensus validation, DAG insert, storage,
/// UTXO/undo mutations, retarget meta, mempool cleanup, stratum
/// tip notification), then the RPC-visible state refresh. Broadcasting to
/// the network stays with the caller — the miner loop only gossips a block
/// its OWN acceptor has admitted.
///
/// Returns the block hash on acceptance; any rejection here means the miner
/// produced a block its own validator refuses (a miner bug), and the caller
/// must discard it WITHOUT broadcasting.
fn commit_self_mined_block(
    block:      &core::Block,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    shielded:   &Arc<RwLock<crate::coherence::ShieldedPool>>,
) -> Result<[u8; 32], String> {
    // Same structural gate as external submissions (audit H2): the producer
    // grants itself no bypass.
    block.validate_structure()
        .map_err(|e| format!("structural validation: {}", e))?;

    let block_hash = block.block_hash();
    accept_block(
        block, block_hash, block.height,
        dag, store, mempool, node_state,
        tip_tx, shielded,
    )?;

    // Refresh RPC-visible state (mirrors the stratum/RPC accept callbacks).
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }

    Ok(block_hash)
}

/// Build the RPC `submitblock` hook (B5f pool seam): `Block::block_hash()`
/// identity, dedup, `validate_structure_without_pow()`, then the shared
/// `accept_block` pipeline (known parents, height, bits, timestamp, then the
/// proof of work: B2-T11) + gossip. `min_chain_work`: the node's minimum
/// chain work (`ingress::minimum_chain_work`; a parameter so tests pass it).
#[allow(clippy::too_many_arguments)]
fn make_rpc_submit_block_cb(
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
    otx:        mpsc::Sender<network::NetworkMessage>,
    tip_tx:     broadcast::Sender<tip::TipChanged>,
    min_chain_work: u128,
) -> Arc<rpc::SubmitBlockFn> {
    Arc::new(move |mut block: core::Block| -> Result<String, String> {
        let block_hash = block.block_hash();
        // POW-8 / re-audit B1-T0: the submitter's `blue_score` is not
        // committed by the block id. Replace it with the value derived from
        // the parents, as `accept_block` does before storing the body, so the
        // bytes relayed below are the bytes this node stores and serves.
        ingress::normalize_wire_metadata(&mut block, &dag);
        // A block waiting for a body (witness-dependent failure of its
        // previous body) is not a duplicate: this copy is re-evaluated.
        if accept::is_known_block(&dag, &store, &block_hash) {
            // DAG-1: a disqualified block stays in the DAG; tell the
            // submitter it is invalid rather than merely a duplicate.
            if dag.read().is_invalid(&block_hash) {
                let reason = store.invalid_block_reason(&block_hash).ok().flatten()
                    .unwrap_or_else(|| "descends from an invalid block".to_string());
                return Err(format!("duplicate block (known invalid: {})", reason));
            }
            return Err("duplicate block".to_string());
        }
        // POW-3 (Phase 4): the minimum chain work applies to submitted blocks
        // too (`ingress::submitted_block_admission`, DAG lookups only, before
        // the proof of work); the tip-relative anti-DoS work rule does not,
        // so an operator can replay a heavier chain that forks deep below the
        // tip (Bitcoin Core's `submitblock`). B2-T11 (NET-2 on the RPC path):
        // then the cheap, context-free half of the structure check only.
        // `accept_block` then checks the known parents, the header height,
        // the expected bits and the timestamp, and only then evaluates the
        // proof of work (cached by block id) — the order gossip ingress uses.
        // `validate_structure()` ran the proof first, so any block on random
        // parents or with wrong bits cost a full GnB-SMH evaluation per call.
        ingress::submitted_block_admission(&dag.read(), &block, min_chain_work)?;
        block.validate_structure_without_pow()
            .map_err(|e| format!("structural validation: {}", e))?;

        accept_block(
            &block, block_hash, block.height,
            &dag, &store, &mempool, &node_state,
            Some(&tip_tx), &shielded,
        )?;

        // Refresh RPC-visible state (mirrors the miner loop).
        {
            let mut s = node_state.write();
            s.tip_blue_score = dag.read().tip_blue_score();
            s.block_count    = dag.read().block_count() as u64;
            s.mempool_size   = mempool.size();
        }

        // Broadcast to gossipsub — other peers learn about the block.
        let data = block.to_wire_bytes();
        let msg = network::NetworkMessage::NewBlock {
            block_hash,
            blue_score: block.blue_score,
            height:     block.height,
            block_data: data,
        };
        let otx_clone = otx.clone();
        tokio::spawn(async move { let _ = otx_clone.send(msg).await; });

        Ok(hex::encode(block_hash))
    })
}

/// Build the `invalidateblock` / `reconsiderblock` hook (audit DAG-6): both
/// run through the acceptance pipeline (`accept::invalidate_block` /
/// `accept::reconsider_block`) under the acceptance lock, persist their marks
/// atomically with the chain move, and refresh mempool, RPC state and the
/// stratum tip notification. Authorization is the RPC layer's
/// (`rpc::auth::ADMIN_METHODS`: never anonymous).
///
/// On a pruned node the chain to move to may need bodies it pruned: the call
/// then changes nothing, the next batch of missing bodies waits for a body in
/// the DAG (`accept::request_bodies`, done by the override) and the processor
/// is woken (`body_requests`) to request them through its tracker — the same
/// path that fetches every wanted body — and the operator is asked to retry;
/// each retry fetches the next batch until it succeeds.
#[allow(clippy::too_many_arguments)]
fn make_chain_admin_cb(
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
    tip_tx:     broadcast::Sender<tip::TipChanged>,
    body_requests: Arc<tokio::sync::Notify>,
) -> Arc<rpc::ChainAdminFn> {
    Arc::new(move |op: rpc::ChainAdminOp, hash: [u8; 32]| -> Result<serde_json::Value, String> {
        // PoWit audit findings 2 and 3: the finality settings.
        let finality_op = match op {
            rpc::ChainAdminOp::Invalidate | rpc::ChainAdminOp::Reconsider => None,
            rpc::ChainAdminOp::IgnoreFinalized => Some(powit::FinalityOp::Ignore(hash)),
            rpc::ChainAdminOp::ReconsiderFinalized => Some(powit::FinalityOp::Reconsider(hash)),
            rpc::ChainAdminOp::SetFinalityCheckpoint => Some(powit::FinalityOp::SetAnchor(hash)),
            rpc::ChainAdminOp::SetFinalityCheckpointAt(height) => Some(powit::FinalityOp::SetAnchorAt(hash, height)),
            rpc::ChainAdminOp::DisableFinalityCheckpoint => Some(powit::FinalityOp::DisableAnchor),
            rpc::ChainAdminOp::DefaultFinalityCheckpoint => Some(powit::FinalityOp::DefaultAnchor),
        };
        let res = match (op, finality_op) {
            (_, Some(f)) => accept::override_finality(
                f, &dag, &store, &mempool, &node_state, Some(&tip_tx), &shielded),
            (rpc::ChainAdminOp::Invalidate, None) => accept::invalidate_block(
                hash, &dag, &store, &mempool, &node_state, Some(&tip_tx), &shielded),
            (_, None) => accept::reconsider_block(
                hash, &dag, &store, &mempool, &node_state, Some(&tip_tx), &shielded),
        };
        let r = match res {
            Ok(r) => r,
            Err(accept::OverrideError::MissingBodies { missing, .. }) => {
                let n = missing.len();
                body_requests.notify_one();
                warn!("{:?} {}: the chain to move to needs {} pruned block bod(ies); re-fetching them",
                    op, hex::encode(&hash[..8]), n);
                return Err(format!(
                    "nothing changed: this pruned node needs {n} block bod(ies) it pruned to move to the \
                     best remaining chain; they are being re-fetched from peers. Retry the same call \
                     once they have arrived (each retry requests the next missing ones)"));
            }
            Err(e) => return Err(e.to_string()),
        };
        let mut out = serde_json::json!({
            "block":       hex::encode(hash),
            "affected":    r.affected,
            "rolled_back": r.rolled_back,
            "connected":   r.connected,
            "tip":         hex::encode(r.tip),
            "tip_height":  r.tip_height,
        });
        if finality_op.is_some() {
            out["finality"] = powit::finality_info_json(&dag.read(), 8);
        }
        Ok(out)
    })
}

// ── Block acceptance + Orphan processing ─────────────────────────────────────

/// A per-request nonce whose ONLY job is to make each GetBlock unique on the
/// wire, so gossipsub's duplicate cache cannot swallow a retry. Monotonic rather
/// than random: retries must differ from each other, and a counter guarantees
/// that without depending on an RNG or on the clock's resolution.
fn getblock_nonce() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Echo-storm fix: a broadcast Headers frame counts as a reply to OUR OWN
/// GetHeaders only within this window of us actually sending one. Generous vs
/// the ~seconds a real reply takes (each pipeline continuation refreshes the
/// stamp), and safely above the 30s IBD nudge period, so a syncing node can
/// never starve itself; a SYNCED node stops reacting to overheard streams.
const HEADERS_SOLICITED_WINDOW_MS: u64 = 60_000;

/// B1-T2: most block pulls one directed Headers answer may start: one batch
/// (the `limit` every GetHeaders of this node asks for).
const MAX_FETCH_PER_ANSWER: usize = 500;

// `ARCHIVE_MODE` and `accept_block` moved to `accept.rs` (audit
// DAG-1/DAG-10/DAG-11); imported at the top of this file. `FINALITY_FROZEN`
// was removed with the finality checkpoint (audit DAG-6).

/// Blue_work-VERIFIED / evidence-based IBD release — the ONLY path that clears
/// `is_syncing`.
///
/// NET-6 (audit): both the latch and its release are driven by work-backed
/// evidence only. The latch is set solely by a PoW-verified, full-difficulty
/// orphan that claims to be well ahead of us (NewBlock arm); announced
/// `blue_score` claims never set it and no longer gate its release either (a
/// single inflated `Version` frame used to keep every node in IBD). Release
/// fires on the FIRST of:
///  (A) VERIFIED: we hold every advertised tip of the connected peers'
///      (directed, responder-attributed) frontiers — or gave up on it — AND our
///      selected-tip `blue_work` is at least the greatest locally-verified
///      `blue_work` reachable from them (`servable_blue_work`). Tips we cannot
///      verify contribute 0. `!abandoned_gap` keeps a given-up frontier from
///      counting as "verified".
///  (B) CAUGHT UP: no buffered work-backed orphan claims a height more than
///      `IBD_EXIT_LAG` above our selected tip any more (the evidence that
///      latched us was accepted, or evicted / given up by the orphan sweep).
///
/// Announced scores are still recorded (author-attributed, latest-wins,
/// TTL-decayed) for the RPC `best_announced` / `behind_by` hint.
///
/// Lock order (must match every other call-site): dag → peer_state → frontier
/// → node_state. All read locks drop before node_state.write().
fn maybe_release_ibd(
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    peer_state: &Arc<sync::peer_state::PeerStateTable>,
    frontier:   &Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
) {
    maybe_release_ibd_with(dag, peer_state, frontier, node_state,
        ingress::minimum_chain_work(), std::time::Instant::now());
}

/// POW-3: the long-IBD warning alone (`ingress::MinimumWorkWatch`), for the
/// periodic nudge of a node with no peer, which does not run the latch.
fn warn_if_long_below_minimum(
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_work:   u128,
    min_chain_work: u128,
    now:        std::time::Instant,
) {
    let mut s = node_state.write();
    if let Some(w) = s.min_work_watch.observe(tip_work, min_chain_work, now) {
        warn!("⚠ {w} (this node has no peer)");
    }
}

/// [`maybe_release_ibd`] against an explicit minimum chain work and clock
/// (testable: the process-wide value is the network default in tests).
fn maybe_release_ibd_with(
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    peer_state: &Arc<sync::peer_state::PeerStateTable>,
    frontier:   &Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    min_chain_work: u128,
    now:        std::time::Instant,
) {
    let (our_work, our_score, our_height, servable, reconciled, have_frontier, abandoned_gap, evidence) = {
        let d = dag.read();
        let selected = d.selected_tip().and_then(|h| d.get_node(&h));
        let our_work = selected.as_ref().map(|n| n.blue_work).unwrap_or(0);
        let our_score = selected.as_ref().map(|n| n.blue_score).unwrap_or(0);
        let our_height = selected.as_ref().map(|n| n.height).unwrap_or(0);
        // Disqualified blocks (DAG-1) are never selectable, so a peer frontier
        // that only leads to them must not hold the IBD latch. A block parked
        // without a verdict (and its selected-chain descendants) is NOT
        // disqualified (review of PR #15, finding 2): this node could not
        // judge it (a local storage fault), so a peer serving that branch is
        // ahead of us and holds the latch like any servable tip; one
        // transient failure during sync must not release it (one-way) and
        // report the node synced on a stale tip. The internal miner still
        // resumes after a stall (`SYNC_STALL_SECS`) and the RPC warns
        // (`accept::no_verdict_branch_warning`); the node never exits for it.
        let servable = peer_state.servable_blue_work(|h| {
            if d.is_invalid(h) && !d.is_no_verdict_branch(h) { None } else { d.get_node(h).map(|n| n.blue_work) }
        });
        let advertised = peer_state.connected_advertised_tips();
        let have_frontier = !advertised.is_empty();
        let fr = frontier.lock();
        let outstanding = fr.outstanding();
        let reconciled = sync::frontier::reconciled(
            &advertised, |h| d.has_block(h), outstanding, |h| fr.is_abandoned(h),
        );
        let abandoned_gap = advertised.iter().any(|h| !d.has_block(h) && fr.is_abandoned(h));
        let evidence = fr.orphan_evidence_height();
        drop(fr);
        (our_work, our_score, our_height, servable, reconciled, have_frontier, abandoned_gap, evidence)
    };
    let best_announced = peer_state.best_announced_blue_score();
    let evidence_ahead = evidence.is_some_and(|h| h > our_height.saturating_add(sync::IBD_EXIT_LAG));
    let verified  = have_frontier && reconciled && !abandoned_gap && our_work >= servable;
    let caught_up = !evidence_ahead;
    // POW-3 (Phase 4): below the minimum chain work the node is in initial
    // block download whatever else it sees (Bitcoin Core's first
    // IsInitialBlockDownload criterion): the latch is held and the miner
    // stays paused. A node that stays there for long says so, with the way
    // out (`ingress::MinimumWorkWatch`).
    let below_minimum_work = our_work < min_chain_work;
    {
        let mut s = node_state.write();
        // RPC honesty hint (fresh, author-attributed claims only).
        s.best_announced_blue_score = best_announced;
        if let Some(w) = s.min_work_watch.observe(our_work, min_chain_work, now) {
            warn!("⚠ {w}{}", if s.peer_count == 0 { " (this node has no peer)" } else { "" });
        }
        if below_minimum_work {
            if !s.is_syncing {
                info!("IBD latched: selected-tip work {:#x} is below the minimum chain work {:#x}",
                    our_work, min_chain_work);
            }
            s.is_syncing = true;
        } else if (verified || caught_up) && s.is_syncing {
            s.is_syncing = false;
            info!("IBD complete (verified={} caught_up={}; score {} height {} best_announced {}; work {} servable {}; abandoned_gap={}; orphan_evidence={:?})",
                verified, caught_up, our_score, our_height, best_announced, our_work, servable, abandoned_gap, evidence);
        }
    }
}

/// Current Unix time in seconds.
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// MEM-6: settle the withheld gossip verdicts of orphans from what the relay
/// reported: Accept for the frames of admitted orphans (gossipsub relays the
/// original bytes; every admitted orphan is also scheduled for
/// re-announcement), Reject for consensus-invalid ones still in gossipsub's
/// cache (the delivering peer takes the P4 penalty) — else an
/// application-score penalty on the connection that delivered it — and
/// Ignore for dropped ones.
fn settle_orphan_events(
    deferred: &mut mempool::relay::DeferredVerdicts<network::InboundOrigin>,
    vtx: &mpsc::Sender<network::GossipValidation>,
    net_ctl: &mpsc::Sender<network::NetworkControl>,
    events: &mempool::relay::OrphanEvents,
) {
    if events.is_empty() {
        return;
    }
    let s = deferred.settle(events, std::time::Instant::now());
    for (origin, verdict) in s.verdicts {
        report_verdict(vtx, &origin, verdict);
    }
    for peer in s.penalize {
        let _ = net_ctl.try_send(network::NetworkControl::PenalizePeer(peer));
    }
}

/// MEM-6: announce transactions that entered the pool without their own
/// gossip frame being relayed (orphans admitted after that frame expired).
fn announce_txs(otx: &mpsc::Sender<network::NetworkMessage>, txs: &[core::Transaction]) {
    for tx in txs {
        let _ = otx.try_send(network::NetworkMessage::NewTransaction {
            txid: tx.txid(),
            tx_data: tx.to_wire_bytes(true),
        });
    }
}

/// B1-T2: the peer to penalize for a block judged `verdict`: the sender of
/// an invalid block (`Reject`, the same judgement as for a gossip copy) that
/// came as the ANSWER to one of our directed pulls. A gossip copy's sender is
/// penalized by gossipsub through the reported `Reject` (and the network
/// loop adds it to the shared misbehaviour score); a directed answer has no
/// gossip frame, so the processor asks the network loop to
/// (`NetworkControl::PenalizePeer`). It used to cost nothing, so a peer
/// could answer every pull with an invalid block and keep being asked.
fn directed_block_penalty(verdict: network::GossipVerdict, origin: &network::InboundOrigin) -> Option<libp2p::PeerId> {
    match (verdict, origin) {
        (network::GossipVerdict::Reject, network::InboundOrigin::Directed { peer }) => Some(*peer),
        _ => None,
    }
}

/// The one misbehaviour model, block frames (R2b's NET-2 residual with
/// R2a's B1-T2): what the network loop is asked to do about the peer that
/// delivered a block frame judged `p`. Data no honest node sends
/// (`p.misbehaving`, `ingress::block_penalty`: a context-free fault, or one
/// the deliverer authored, which every answer to our own pull is) gets
/// `Misbehaving`: disconnect, identity and address discouraged at once. An
/// invalid directed answer the penalty model would not sanction still costs
/// its sender one offence of the shared decaying score
/// ([`directed_block_penalty`], `PenalizePeer`; four within the decay
/// disconnect it), so answering pulls with invalid blocks is never free.
/// A relayed gossip frame is left to gossipsub's verdict.
fn block_sanction(p: ingress::BlockPenalty, origin: &network::InboundOrigin) -> Option<network::NetworkControl> {
    if p.misbehaving {
        return origin.peer().map(network::NetworkControl::Misbehaving);
    }
    directed_block_penalty(p.gossip, origin).map(network::NetworkControl::PenalizePeer)
}

/// What the processor does with one block frame after the ingress core.
enum BlockStep {
    /// Report this verdict (and the misbehaviour, if any) now.
    Verdict(ingress::BlockPenalty),
    /// Buffered as an orphan: withhold the verdict until it connects (B1-T5).
    DeferOrphan,
    /// Every cheap check passed: evaluate the proof off the processor
    /// (NET-2 residual).
    Pow,
}

/// A proof of work evaluated on the blocking pool, back to the processor.
struct PowDone {
    /// The block's frame, resubmitted to the ingress core.
    inbound: network::Inbound,
    outcome: pow::verifier::PowOutcome,
}

/// NET-2 residual: the processor's proof-of-work gate — the result of an
/// earlier evaluation on the PoW scheduler, else "deferred" (the processor
/// then queues the evaluation and resubmits the block when it is done).
struct KnownPow<'a>(&'a pow::verifier::PowScheduler<network::Inbound>);

impl ingress::PowGate for KnownPow<'_> {
    fn check(&mut self, block: &core::Block, hash: &[u8; 32]) -> ingress::PowCheck {
        match self.0.known(hash, block.height) {
            Some(true) => ingress::PowCheck::Valid,
            Some(false) => ingress::PowCheck::Invalid,
            None => ingress::PowCheck::Deferred,
        }
    }
}

/// NET-2 residual: start every queued proof-of-work evaluation a worker slot
/// is free for, on the blocking pool; the result comes back on `done`. A
/// gossip job that waited past gossipsub's cache is answered `Ignore`
/// unevaluated.
fn dispatch_pow(
    sched: &mut pow::verifier::PowScheduler<network::Inbound>,
    done:  &mpsc::UnboundedSender<PowDone>,
    vtx:   &mpsc::Sender<network::GossipValidation>,
) {
    let now = std::time::Instant::now();
    loop {
        match sched.start_next(now) {
            pow::verifier::StartNext::Idle => break,
            pow::verifier::StartNext::Expired(job) => {
                debug!("block {} not evaluated: its frame waited past the gossip cache in the PoW queue",
                    hex::encode(&job.id[..8]));
                report_verdict(vtx, &job.payload.origin, network::GossipVerdict::Ignore);
            }
            pow::verifier::StartNext::Start(job) => {
                let done = done.clone();
                tokio::task::spawn_blocking(move || {
                    // GnB-SMH v1 or v3, as the header height says.
                    let valid = match &job.payload.msg {
                        network::NetworkMessage::NewBlock { block_data, .. } => pow::verifier::evaluate_block_frame(block_data),
                        _ => false,
                    };
                    let outcome = job.outcome(valid);
                    let _ = done.send(PowDone { inbound: job.payload, outcome });
                });
            }
        }
    }
}

/// PoWit gossip: start every queued PoWit verification a worker slot is
/// free for (`powit::admit_item` on the blocking pool, under a DAG read
/// lock); the result comes back on `done`. A frame that waited past
/// gossipsub's cache is answered `Ignore` unverified.
fn dispatch_powit(
    core_p: &mut ingress::PowitIngress,
    done:   &mpsc::UnboundedSender<(ingress::PowitJob, Result<(), String>)>,
    dag:    &Arc<RwLock<consensus::GhostDAG>>,
    store:  &Arc<storage::Storage>,
    vtx:    &mpsc::Sender<network::GossipValidation>,
) {
    let now = std::time::Instant::now();
    loop {
        match core_p.start_next(now) {
            pow::verifier::StartNext::Idle => break,
            pow::verifier::StartNext::Expired(job) => {
                debug!("PoWit item {} not verified: its frame waited past the gossip cache",
                    hex::encode(&job.id[..8]));
                report_verdict(vtx, &job.payload.origin, network::GossipVerdict::Ignore);
            }
            pow::verifier::StartNext::Start(job) => {
                let (done, dag, store) = (done.clone(), dag.clone(), store.clone());
                tokio::task::spawn_blocking(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let d = dag.read();
                        powit::admit_item(job.payload.kind, &job.payload.data, &d, &store)
                    }))
                    .unwrap_or_else(|_| Err("storage: PoWit verification panicked".into()));
                    let _ = done.send((job, result));
                });
            }
        }
    }
}

/// Report a PoWit frame's verdict and, for a misbehaving deliverer (a
/// context-free fault it authored, or relayed once penalties are in force:
/// `ingress::block_penalty`), disconnect it and discourage its address.
fn report_powit_verdict(
    vtx:     &mpsc::Sender<network::GossipValidation>,
    net_ctl: &mpsc::Sender<network::NetworkControl>,
    v:       ingress::PowitVerdict,
) {
    report_verdict(vtx, &v.origin, v.penalty.gossip);
    if v.penalty.misbehaving {
        if let Some(peer) = v.origin.peer() {
            warn!("PoWit item from {} invalid regardless of chain state: peer misbehaved", peer);
            let _ = net_ctl.try_send(network::NetworkControl::Misbehaving(peer));
        }
    }
}

/// B1-T5: report the withheld verdicts of buffered orphan frames — Accept
/// for an orphan that connected, the (B1-T7-gated) penalty for one
/// `accept_block` refused, Ignore for one the work rule refused or that left
/// the pool, or whose frame expired.
fn settle_block_verdicts(
    core:       &mut ingress::BlockIngress,
    deferred:   &mut ingress::DeferredBlockVerdicts<network::InboundOrigin>,
    vtx:        &mpsc::Sender<network::GossipValidation>,
    net_ctl:    &mpsc::Sender<network::NetworkControl>,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    activation: u64,
) {
    let events = core.take_orphan_events();
    if deferred.is_empty() {
        return;
    }
    let in_force = ingress::block_penalties_in_force(selected_tip_height(dag), activation);
    for (origin, fate) in deferred.settle(&events) {
        let p = match fate {
            ingress::OrphanFate::Accepted => ingress::BlockPenalty { gossip: network::GossipVerdict::Accept, misbehaving: false },
            ingress::OrphanFate::Rejected(e) => ingress::block_penalty(
                ingress::verdict_for_accept_error(&e), ingress::accept_error_fault(&e), origin.delivered_by_author(), in_force),
            ingress::OrphanFate::Dropped => ingress::BlockPenalty { gossip: network::GossipVerdict::Ignore, misbehaving: false },
        };
        report_verdict(vtx, &origin, p.gossip);
        if let Some(c) = block_sanction(p, &origin) {
            let _ = net_ctl.try_send(c);
        }
    }
    for origin in deferred.prune(|h| core.orphans.contains(h), std::time::Instant::now()) {
        report_verdict(vtx, &origin, network::GossipVerdict::Ignore);
    }
}

/// NET-2: report the processor's verdict for a deferred gossip frame. No-op
/// for frames that owe none (directed answers, local frames, or gossip whose
/// verdict the network loop already reported).
fn report_verdict(
    vtx:     &mpsc::Sender<network::GossipValidation>,
    origin:  &network::InboundOrigin,
    verdict: network::GossipVerdict,
) {
    if let Some((message_id, propagation_source)) = origin.pending_verdict() {
        // A full channel only means this frame is not relayed (it expires
        // from gossipsub's cache); never block the processor on it.
        let _ = vtx.try_send(network::GossipValidation { message_id, propagation_source, verdict });
    }
}

/// Height of our selected tip (0 for an empty DAG).
fn selected_tip_height(dag: &Arc<RwLock<consensus::GhostDAG>>) -> u64 {
    let d = dag.read();
    d.selected_tip()
        .and_then(|t| d.get_block_data(&t).map(|bd| bd.height))
        .unwrap_or(0)
}

// `normalize_wire_metadata` (POW-8) and `process_orphans` (iterative orphan
// drain, POW-3 / POW-4) moved to the library's `ingress` module, where the
// processor core (`ingress::BlockIngress`) and the integration tests use them.

/// Orphan-deadlock fix: periodic (~30s) sweep over the missing-parent set.
///
/// Re-emits GetBlock for parents pending past their (exponential, capped)
/// backoff, gives up past an attempt/age ceiling (dropping the dependent
/// orphans so the pool stays bounded), and returns waited-on parents that are
/// ALREADY in the DAG so the caller can drain their orphans.
///
/// NOT consensus: only re-sends an existing wire message and prunes a local
/// buffer. Validation/acceptance paths untouched.
async fn sweep_orphan_parents(
    orphans:      &mut ingress::OrphanPool,
    parent_fetch: &mut sync::parent_fetch::ParentFetchTracker,
    dag:          &Arc<RwLock<consensus::GhostDAG>>,
    otx:          &tokio::sync::mpsc::Sender<network::NetworkMessage>,
) -> Vec<[u8; 32]> {
    let now = std::time::Instant::now();
    // Partition waited-on parents WITHOUT holding the DAG lock across awaits:
    //  ready — already in the DAG (drainable orphans);
    //  chased — not buffered, not in the DAG: these need (re-)fetching.
    let (ready, chased) = {
        let d = dag.read();
        let mut ready = Vec::new();
        let mut chased = Vec::new();
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for p in orphans.waiting_parents() {
            if d.has_block(&p) {
                ready.push(p);
            } else if !orphans.contains(&p) && seen.insert(p) {
                chased.push(p);
            }
        }
        // Blocks in the DAG waiting for a body (a witness-dependent failure
        // below the hardening activation dropped theirs, or a connect needs a
        // missing or pruned one, audit DAG-6): fetched like a missing parent
        // until a body arrives — at most `MAX_BODY_PULLS_IN_FLIGHT` at once
        // (the ones being fetched keep their retry schedule), however many
        // wait, so they never fill the directed-pull queue.
        for h in ingress::awaited_bodies_to_chase(&d, parent_fetch, ingress::MAX_BODY_PULLS_IN_FLIGHT) {
            if seen.insert(h) {
                chased.push(h);
            }
        }
        (ready, chased)
    };
    let (retry, give_up) = parent_fetch.sweep(&chased, now);
    for h in &retry {
        let _ = otx.send(network::NetworkMessage::GetBlock {
            block_hash: *h, nonce: getblock_nonce(),
        }).await;
    }
    if !retry.is_empty() {
        let (skeletons, paths) = orphans.remembered_len();
        info!("orphan sweep: re-requested {} missing parent(s) (orphans={} bytes={}, remembered evicted={} paths={})",
            retry.len(), orphans.len(), orphans.total_bytes(), skeletons, paths);
    }
    for (h, attempts) in give_up {
        let dropped = drop_orphan_subtree(h, orphans);
        warn!("orphan sweep: giving up on missing parent {} after {} attempts; \
               dropped {} dependent orphan(s) — peers will re-announce if the \
               branch is real", hex::encode(&h[..8]), attempts, dropped);
    }
    ready
}

/// Remove every orphan transitively waiting on `root_parent` (which we gave up
/// fetching), iteratively. Returns how many orphans were dropped. Dropped
/// orphans are NOT banned: if a peer re-announces the branch and its ancestry
/// becomes fetchable, it re-enters the pool.
fn drop_orphan_subtree(root_parent: [u8; 32], orphans: &mut ingress::OrphanPool) -> usize {
    orphans.drop_subtree(&root_parent)
}

/// Ask peers for the body of every block that waits for one (its stored body
/// failed a rule that depends on witness bytes the block id does not commit
/// to, or is missing — pruned and needed again by a connect or an operator
/// override, audit DAG-6 — `GhostDAG::mark_body_pending`) and is not already
/// being fetched (`ingress::awaited_bodies_to_request`: at most
/// `ingress::MAX_BODY_PULLS_IN_FLIGHT` bodies are being fetched at once, the
/// others are requested as these arrive). The one request path for wanted
/// bodies; it reuses the missing-parent machinery: the request is tracked by
/// `parent_fetch`, so the periodic sweep retries it with backoff (from another
/// peer, `PullPeerSelector`), and the answer — a directed pull — is what the
/// ingress core accepts as a body (`BlockIngress::handle_block`). NOT
/// consensus.
async fn request_awaited_bodies(
    dag:          &Arc<RwLock<consensus::GhostDAG>>,
    parent_fetch: &mut sync::parent_fetch::ParentFetchTracker,
    otx:          &tokio::sync::mpsc::Sender<network::NetworkMessage>,
) {
    let wanted = ingress::awaited_bodies_to_request(&dag.read(), parent_fetch, ingress::MAX_BODY_PULLS_IN_FLIGHT);
    if wanted.len() > 1 {
        info!("requesting the bodies of {} block(s) waiting for one", wanted.len());
    }
    let now = std::time::Instant::now();
    for h in wanted {
        debug!("requesting a body of block {} (its previous body was rejected or is missing)",
            hex::encode(&h[..8]));
        parent_fetch.note_requested(h, now);
        let _ = otx.send(network::NetworkMessage::GetBlock { block_hash: h, nonce: getblock_nonce() }).await;
    }
}

#[cfg(test)]
mod ingress_processor_tests {
    //! Regressions for the processor-side audit fixes that live in this
    //! binary: iterative orphan draining with derived metadata (POW-3/4/8)
    //! and the evidence-driven IBD latch release (NET-6).
    use super::*;
    use crate::ingress::{normalize_wire_metadata, process_orphans};

    /// B1-T2: an invalid block that answered one of our pulls costs its
    /// sender a penalty; a valid or ignored one does not, and a gossip copy
    /// is penalized through its reported Reject instead (not twice).
    #[test]
    fn invalid_block_answering_our_pull_is_penalized() {
        use network::{GossipVerdict, InboundOrigin};
        let peer = libp2p::PeerId::random();
        let directed = InboundOrigin::Directed { peer };
        assert_eq!(directed_block_penalty(GossipVerdict::Reject, &directed), Some(peer));
        assert_eq!(directed_block_penalty(GossipVerdict::Ignore, &directed), None);
        assert_eq!(directed_block_penalty(GossipVerdict::Accept, &directed), None);
        let gossip = InboundOrigin::Gossip {
            propagation_source: peer,
            author: None,
            pending: None,
            received_at: std::time::Instant::now(),
        };
        assert_eq!(directed_block_penalty(GossipVerdict::Reject, &gossip), None);
        assert_eq!(directed_block_penalty(GossipVerdict::Reject, &InboundOrigin::Local), None);
    }

    /// R2a (B1-T2) with R2b (NET-2 residual, B1-T7): one sanction per block
    /// frame. An invalid answer to our own pull is authored by the peer that
    /// sent it, so the penalty model calls it misbehaving: `Misbehaving`
    /// (disconnect, identity and address discouraged), never a second
    /// `PenalizePeer` on top. A directed `Reject` the penalty model does not
    /// sanction still costs one offence of the shared score; a relayed
    /// gossip frame before penalties are in force costs nothing here (its
    /// gossip verdict is `Ignore`), and an honest verdict nothing at all.
    #[test]
    fn block_frames_get_one_sanction_from_the_shared_model() {
        use crate::ingress::{block_penalty, BlockFault, BlockPenalty};
        use network::{GossipVerdict, InboundOrigin, NetworkControl};
        let peer = libp2p::PeerId::random();
        let directed = InboundOrigin::Directed { peer };
        let relay = InboundOrigin::Gossip {
            propagation_source: peer,
            author: Some(libp2p::PeerId::random()),
            pending: None,
            received_at: std::time::Instant::now(),
        };
        for in_force in [false, true] {
            for fault in [BlockFault::ContextFree, BlockFault::Context] {
                let p = block_penalty(GossipVerdict::Reject, fault, directed.delivered_by_author(), in_force);
                assert_eq!(block_sanction(p, &directed), Some(NetworkControl::Misbehaving(peer)),
                    "an invalid answer to our pull ({fault:?}, in force {in_force})");
            }
        }
        let relayed = block_penalty(GossipVerdict::Reject, BlockFault::Context, relay.delivered_by_author(), false);
        assert_eq!(block_sanction(relayed, &relay), None, "a relayed frame before penalties are in force");
        let unsanctioned = BlockPenalty { gossip: GossipVerdict::Reject, misbehaving: false };
        assert_eq!(block_sanction(unsanctioned, &directed), Some(NetworkControl::PenalizePeer(peer)));
        let honest = BlockPenalty { gossip: GossipVerdict::Accept, misbehaving: false };
        assert_eq!(block_sanction(honest, &directed), None);
        assert_eq!(block_sanction(honest, &InboundOrigin::Local), None);
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn coinbase(height: u64) -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: format!("ingress-test:{}", height).into_bytes(),
                sequence:   u32::MAX,
            }],
            outputs: vec![core::TxOutput {
                value: core::tokenomics::block_subsidy_sat(height),
                script_pubkey: vec![0xAB; 20],
            }],
            locktime: 0,
        }
    }

    /// A valid (mined) child of `parent` at `height`.
    fn child(parent: &core::Block, height: u64) -> core::Block {
        let txs = vec![coinbase(height)];
        let ts = parent.header.timestamp + 30;
        let bits = pow::expected_bits(parent.header.timestamp, height).expect("bits");
        let mut b = core::Block {
            header: core::BlockHeader {
                version: 1,
                parents: vec![parent.block_hash()],
                merkle_root: core::Transaction::merkle_root(&txs),
                timestamp: ts,
                bits,
                nonce: 0,
            },
            transactions: txs,
            blue_score: 0,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        let nonce = pow::mine_parallel(&b.header.pow_preimage(), bits, b.height, 0, 1 << 16, 2, None)
            .expect("solve");
        b.header.nonce = nonce;
        assert!(b.validate_structure().is_ok());
        b
    }

    struct Fixture {
        _tmp:       tempfile::TempDir,
        dag:        Arc<RwLock<consensus::GhostDAG>>,
        store:      Arc<storage::Storage>,
        mempool:    Arc<mempool::Mempool>,
        node_state: Arc<RwLock<rpc::NodeState>>,
        shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
        genesis:    core::Block,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));
        let genesis = core::Block {
            header: core::BlockHeader {
                version: 1,
                parents: vec![],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp: unix_now().saturating_sub(600),
                bits: core::GENESIS_BITS,
                nonce: 0,
            },
            transactions: vec![coinbase(0)],
            blue_score: 0,
            height: 0,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        store.put_block(&genesis).expect("store genesis");
        dag.write().add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Fixture {
            _tmp: tmp,
            dag,
            store,
            mempool: Arc::new(mempool::Mempool::new()),
            node_state: Arc::new(RwLock::new(rpc::NodeState::default())),
            shielded: Arc::new(RwLock::new(crate::coherence::ShieldedPool::new())),
            genesis,
        }
    }

    /// POW-3 / POW-4 / POW-8: orphans are drained iteratively once their
    /// ancestor arrives, and the stored blue_score is DERIVED from verified
    /// parents, never the (forged) wire value.
    #[test]
    fn orphan_chain_drains_iteratively_with_derived_metadata() {
        let f = fixture();
        let b1 = child(&f.genesis, 1);
        let b2 = child(&b1, 2);
        let b3 = child(&b2, 3);
        let mut pool = ingress::OrphanPool::default();
        for (b, missing) in [(&b3, b2.block_hash()), (&b2, b1.block_hash())] {
            let mut forged = b.clone();
            forged.blue_score = u64::MAX; // wire metadata, not committed by the id
            let id = forged.block_hash();
            assert!(matches!(
                pool.insert(id, forged, b.height, 1_000, None, false, &[missing]),
                ingress::OrphanInsert::Inserted { .. }
            ));
        }
        let mut b1n = b1.clone();
        normalize_wire_metadata(&mut b1n, &f.dag);
        let h1 = accept_block(&b1n, b1.block_hash(), 1, &f.dag, &f.store, &f.mempool, &f.node_state, None, &f.shielded)
            .expect("b1 accepted");
        let mut chain = accept::ChainMove::default();
        process_orphans(h1, &mut pool, &f.dag, &f.store, &f.mempool, &f.node_state, None, &f.shielded,
            &mut chain);
        assert!(pool.is_empty(), "the whole orphan chain was drained");
        // MEM-6 review finding: the drained blocks' move of the applied chain
        // is reported for the orphan-transaction bookkeeping.
        assert_eq!(chain.connected(),
            vec![b2.block_hash(), b3.block_hash()]);
        assert!(chain.disconnected().is_empty());
        assert!(f.dag.read().has_block(&b3.block_hash()));
        let stored = f.store.get_block(&b3.block_hash()).unwrap().unwrap();
        assert_eq!(stored.blue_score, 3, "derived from parents, not the forged u64::MAX");
    }

    fn release_fixture() -> (
        Arc<RwLock<consensus::GhostDAG>>,
        Arc<sync::peer_state::PeerStateTable>,
        Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
        Arc<RwLock<rpc::NodeState>>,
    ) {
        let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));
        dag.write().add_genesis([0xAA; 32], 1_000);
        (
            dag,
            Arc::new(sync::peer_state::PeerStateTable::new()),
            Arc::new(parking_lot::Mutex::new(sync::frontier::FrontierState::new())),
            Arc::new(RwLock::new(rpc::NodeState::default())),
        )
    }

    /// A block whose body was rejected for a witness-dependent reason (below
    /// the hardening activation) waits for another body: the processor asks
    /// peers for it at once through the missing-parent tracker (so the
    /// backfill guard admits the solicited answer), does not ask twice, and
    /// the periodic sweep chases it like a missing parent.
    #[tokio::test]
    async fn blocks_waiting_for_a_body_are_requested_and_swept() {
        let (dag, _, _, _) = release_fixture();
        let waiting = [0xB0u8; 32];
        dag.write().add_block(waiting, vec![[0xAA; 32]], 1_001, 1).expect("child of genesis");
        dag.write().mark_body_pending(waiting, Some([0x11; 32]));
        let (otx, mut orx) = tokio::sync::mpsc::channel::<network::NetworkMessage>(8);

        let mut tracker = sync::parent_fetch::ParentFetchTracker::new();
        request_awaited_bodies(&dag, &mut tracker, &otx).await;
        match orx.try_recv() {
            Ok(network::NetworkMessage::GetBlock { block_hash, .. }) => assert_eq!(block_hash, waiting),
            other => panic!("expected a GetBlock, got {:?}", other.map(|_| "another message")),
        }
        assert!(tracker.is_awaited(&waiting), "tracked: the backfill guard admits the answer");
        request_awaited_bodies(&dag, &mut tracker, &otx).await;
        assert!(orx.try_recv().is_err(), "already being fetched: no duplicate request");

        // The sweep (a fresh tracker, e.g. after the record was given up on)
        // re-requests it although no orphan waits for it.
        let mut fresh = sync::parent_fetch::ParentFetchTracker::new();
        let mut orphans = ingress::OrphanPool::default();
        sweep_orphan_parents(&mut orphans, &mut fresh, &dag, &otx).await;
        match orx.try_recv() {
            Ok(network::NetworkMessage::GetBlock { block_hash, .. }) => assert_eq!(block_hash, waiting),
            other => panic!("expected a GetBlock from the sweep, got {:?}", other.map(|_| "another message")),
        }

        // Once a body is accepted the block no longer waits: nothing to chase.
        dag.write().clear_body_pending(&waiting);
        let mut fresh = sync::parent_fetch::ParentFetchTracker::new();
        sweep_orphan_parents(&mut orphans, &mut fresh, &dag, &otx).await;
        request_awaited_bodies(&dag, &mut fresh, &otx).await;
        assert!(orx.try_recv().is_err());
    }

    /// Review of the P3 merge: a pruned node following a fork deeper than the
    /// pruning depth can wait for thousands of bodies at once. The periodic
    /// sweep used to re-send a GetBlock for every one of them each period
    /// (filling the 4,096-entry directed-pull queue, so orphan-parent and IBD
    /// pulls were dropped); now at most `MAX_BODY_PULLS_IN_FLIGHT` bodies are
    /// being fetched at once, through the sweep and the request path alike.
    #[tokio::test]
    async fn the_sweep_fetches_a_bounded_number_of_waiting_bodies() {
        let (dag, _, _, _) = release_fixture();
        let cap = ingress::MAX_BODY_PULLS_IN_FLIGHT;
        let n = cap + 100;
        {
            let mut d = dag.write();
            for i in 0..n as u64 {
                let mut h = [0xC0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                d.add_block(h, vec![[0xAA; 32]], 1_001, 1).expect("child of genesis");
                d.mark_body_pending(h, None);
            }
        }
        let (otx, mut orx) = tokio::sync::mpsc::channel::<network::NetworkMessage>(4 * n);
        let drain = |orx: &mut tokio::sync::mpsc::Receiver<network::NetworkMessage>| {
            let mut k = 0usize;
            while let Ok(m) = orx.try_recv() {
                assert!(matches!(m, network::NetworkMessage::GetBlock { .. }));
                k += 1;
            }
            k
        };
        let mut tracker = sync::parent_fetch::ParentFetchTracker::new();
        let mut orphans = ingress::OrphanPool::default();
        sweep_orphan_parents(&mut orphans, &mut tracker, &dag, &otx).await;
        assert_eq!(drain(&mut orx), cap, "one bounded burst, not one GetBlock per waiting block");
        assert_eq!(tracker.len(), cap);
        // The request path adds nothing while the bound is reached ...
        request_awaited_bodies(&dag, &mut tracker, &otx).await;
        assert_eq!(drain(&mut orx), 0);
        // ... and the next sweep within the backoff re-sends nothing and
        // keeps every tracked body.
        sweep_orphan_parents(&mut orphans, &mut tracker, &dag, &otx).await;
        assert_eq!(drain(&mut orx), 0);
        assert_eq!(tracker.len(), cap);
        // Bodies that arrive make room for the next ones. An arrived block
        // can become the selected tip, and only the bodies of blocks that
        // could beat it stay wanted (`GhostDAG::wanted_body_blocks`), so how
        // many fresh bodies are still wanted depends on the window the
        // sweep's random rotation tracked (a fixed 30 failed about one run
        // in ten). The request path fills exactly the room the in-flight
        // bodies leave, from what is still wanted and not tracked.
        let arrived: Vec<[u8; 32]> = dag.read().body_pending_blocks().into_iter()
            .filter(|h| tracker.is_awaited(h)).take(30).collect();
        for h in &arrived {
            dag.write().clear_body_pending(h);
        }
        let wanted = dag.read().wanted_body_blocks();
        let in_flight = wanted.iter().filter(|h| tracker.is_awaited(h)).count();
        let fresh = wanted.len() - in_flight;
        assert!(in_flight <= cap - arrived.len(), "the arrived bodies are no longer in flight");
        request_awaited_bodies(&dag, &mut tracker, &otx).await;
        assert_eq!(drain(&mut orx), fresh.min(cap - in_flight));
    }

    /// The latch with the minimum chain work off: the NET-6 rules below are
    /// tested on the fixture's genesis-only chain, which is below mainnet's
    /// minimum (that alone holds the latch, see
    /// `ibd_latch_holds_below_the_mainnet_minimum_chain_work`).
    fn release_without_minimum(
        dag: &Arc<RwLock<consensus::GhostDAG>>,
        ps:  &Arc<sync::peer_state::PeerStateTable>,
        fr:  &Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
        st:  &Arc<RwLock<rpc::NodeState>>,
    ) {
        maybe_release_ibd_with(dag, ps, fr, st, 0, std::time::Instant::now());
    }

    /// NET-6: an inflated tip claim (even u64::MAX from a connected peer) can
    /// no longer hold the IBD latch: without work-backed evidence it releases.
    #[test]
    fn inflated_claim_cannot_hold_ibd_latch() {
        let (dag, ps, fr, st) = release_fixture();
        let liar = libp2p::PeerId::random();
        ps.on_connect(liar, std::time::Instant::now());
        ps.observe_claim(liar, u64::MAX, u64::MAX, std::time::Instant::now());
        st.write().is_syncing = true;
        release_without_minimum(&dag, &ps, &fr, &st);
        assert!(!st.read().is_syncing, "a claim alone must not keep the node in IBD");
    }

    /// Review of PR #15, finding 2: a peer's tip on a branch parked without a
    /// verdict (this node could not judge a block of it: a local storage
    /// fault) is servable work, so it keeps the latch; pre-fix it counted as
    /// a disqualified branch and the first such failure during sync released
    /// the latch for good. A genuinely disqualified branch still does not.
    #[test]
    fn a_branch_parked_without_a_verdict_holds_the_ibd_latch() {
        let (dag, ps, fr, st) = release_fixture();
        {
            let mut d = dag.write();
            d.add_block([0xA1; 32], vec![[0xAA; 32]], 1_001, 10).expect("our chain");
            d.add_block([0xB1; 32], vec![[0xAA; 32]], 1_001, 10).expect("the peer's branch");
            d.add_block([0xB2; 32], vec![[0xB1; 32]], 1_002, 10).expect("the peer's tip");
            d.park_no_verdict([0xB1; 32]);
            assert_eq!(d.selected_tip(), Some([0xA1; 32]));
        }
        let peer = libp2p::PeerId::random();
        let now = std::time::Instant::now();
        ps.on_connect(peer, now);
        ps.observe(peer, 2, 2, &[[0xB2; 32]], now);
        // Evidence of a chain ahead: only "verified" can release the latch.
        fr.lock().set_orphan_evidence(Some(sync::IBD_EXIT_LAG + 100));
        st.write().is_syncing = true;
        release_without_minimum(&dag, &ps, &fr, &st);
        assert!(st.read().is_syncing, "the peer serves more work than our tip: still syncing");

        // The same branch disqualified (a verdict): not servable, released.
        dag.write().mark_invalid([0xB1; 32]);
        release_without_minimum(&dag, &ps, &fr, &st);
        assert!(!st.read().is_syncing);
    }

    /// NET-6: work-backed evidence (an orphan claiming to be well ahead) holds
    /// the latch until it is resolved.
    #[test]
    fn work_backed_evidence_holds_latch_until_resolved() {
        let (dag, ps, fr, st) = release_fixture();
        fr.lock().set_orphan_evidence(Some(sync::IBD_EXIT_LAG + 100));
        st.write().is_syncing = true;
        release_without_minimum(&dag, &ps, &fr, &st);
        assert!(st.read().is_syncing, "evidence of a chain far ahead keeps the latch");
        fr.lock().set_orphan_evidence(Some(sync::IBD_EXIT_LAG));
        release_without_minimum(&dag, &ps, &fr, &st);
        assert!(!st.read().is_syncing, "within IBD_EXIT_LAG counts as caught up");
    }

    /// POW-3 with mainnet's minimum chain work (the process-wide value in
    /// tests: no chain id, no `--minimumchainwork`): a chain below it holds
    /// the IBD latch whatever else the node sees (no peer, no evidence: it
    /// would be "caught up"); one that reaches it releases the latch. An
    /// override at or below the chain's work releases it too. A node that
    /// stays below warns once per `MIN_WORK_WARNING_INTERVAL` (the watch in
    /// `NodeState`).
    #[test]
    fn ibd_latch_holds_below_the_mainnet_minimum_chain_work() {
        let min = core::MIN_CHAIN_WORK;
        assert_eq!(ingress::minimum_chain_work(), min, "the mainnet default is in force");
        assert_eq!(min, 7_000_000);
        let (dag, ps, fr, st) = release_fixture();
        dag.write().add_block([0xB1; 32], vec![[0xAA; 32]], 1_030, min - 1).expect("child of genesis");
        assert_eq!(ingress::tip_blue_work(&dag.read()), min - 1);

        // The production entry point, with the process-wide minimum.
        maybe_release_ibd(&dag, &ps, &fr, &st);
        assert!(st.read().is_syncing, "one unit of work short of the minimum: in IBD");
        // The NET-6 rules alone would release it (no evidence: caught up).
        release_without_minimum(&dag, &ps, &fr, &st);
        assert!(!st.read().is_syncing);
        // `--minimumchainwork` at the chain's work releases it as well.
        st.write().is_syncing = true;
        let t0 = std::time::Instant::now();
        maybe_release_ibd_with(&dag, &ps, &fr, &st, min - 1, t0);
        assert!(!st.read().is_syncing, "an override the chain reaches");

        // Back below mainnet's value: latched; the warning is issued once the
        // tip has stayed below for the interval (the watch in NodeState
        // then has nothing more to report within that interval).
        let iv = ingress::MIN_WORK_WARNING_INTERVAL;
        maybe_release_ibd_with(&dag, &ps, &fr, &st, min, t0);
        assert!(st.read().is_syncing);
        let mut probe = st.read().min_work_watch.clone();
        assert!(probe.observe(min - 1, min, t0 + iv).is_some(), "not warned before the interval");
        maybe_release_ibd_with(&dag, &ps, &fr, &st, min, t0 + iv);
        let mut probe = st.read().min_work_watch.clone();
        assert!(probe.observe(min - 1, min, t0 + iv + iv / 2).is_none(), "the latch issued this interval's warning");
        assert!(st.read().is_syncing);

        // A node with no peer (the nudge does not run the latch) still warns,
        // on the same watch: nothing more is due within this interval.
        warn_if_long_below_minimum(&st, min - 1, min, t0 + iv + iv / 2);
        let mut probe = st.read().min_work_watch.clone();
        assert!(probe.observe(min - 1, min, t0 + 2 * iv).is_some(), "the next interval's warning is still due");
        warn_if_long_below_minimum(&st, min - 1, min, t0 + 2 * iv);
        let mut probe = st.read().min_work_watch.clone();
        assert!(probe.observe(min - 1, min, t0 + 2 * iv + iv / 2).is_none(), "issued by the peerless path");

        // One more block reaches the minimum: IBD complete, watch reset.
        dag.write().add_block([0xB2; 32], vec![[0xB1; 32]], 1_060, 1).expect("child");
        maybe_release_ibd_with(&dag, &ps, &fr, &st, min, t0 + 3 * iv);
        assert!(!st.read().is_syncing, "the tip reached the minimum chain work");
        let mut probe = st.read().min_work_watch.clone();
        assert!(probe.observe(min, min, t0 + 10 * iv).is_none());
    }
}

// ── Unified TX validation ────────────────────────────────────────────────────
// `validate_tx_inputs`, `miner_template_total_fees`, `validate_tx_in_block*`
// and `validate_tx_standalone` moved to `accept.rs`; imported at the top.

// v0.2.0 PoI
// v0.2.1 reconnect
// v0.2.2 ws+pex
// v0.2.2 ws+pex
// v0.2.3 block-debug
// v0.2.4 height-fix
// v0.2.5 tx-rebroadcast
// v0.2.6 peer-count
// v0.2.7 utxo-reindex
// v0.2.8 dag-reindex
// v0.2.9 topo-sort
// v0.3.0 getpeers
// v0.3.0 getpeers
// v0.3.1 utxo-fix
// v0.3.2 balance-fix
// v0.3.3 recentblocks

// ─────────────────────────────────────────────────────────────────────────────
// Audit H2 regression tests — external-submission structural gate.
//
// The vulnerability: the stratum accept_block_cb handed miner-submitted
// blocks straight to `accept_block`, which checks bits/height/timestamp/tx
// validity but NOT `Block::validate_structure()` (Module-SIS PoW witness,
// merkle binding, coinbase format). A block with no SIS witness therefore
// passed the stratum path while the gossipsub and RPC paths rejected it.
//
// These tests build the callbacks through the same builders `main()` uses,
// so they exercise the real submission closures, not a re-implementation.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod external_submission_tests {
    use super::*;
    use tempfile::TempDir;

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    struct TestNode {
        _tmp:       TempDir,
        dag:        Arc<RwLock<consensus::GhostDAG>>,
        store:      Arc<storage::Storage>,
        mempool:    Arc<mempool::Mempool>,
        node_state: Arc<RwLock<rpc::NodeState>>,
        shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
        otx:        mpsc::Sender<network::NetworkMessage>,
        // Keep the receiver alive so post-accept broadcasts don't error.
        _orx:       mpsc::Receiver<network::NetworkMessage>,
        tip_tx:     broadcast::Sender<tip::TipChanged>,
    }

    impl TestNode {
        /// The `submitblock` hook with no minimum chain work: these fixture
        /// chains (pow-limit blocks, work 1 each) sit far below mainnet's,
        /// which `rpc_cb_with` tests.
        fn rpc_cb(&self) -> Arc<rpc::SubmitBlockFn> {
            self.rpc_cb_with(0)
        }

        fn rpc_cb_with(&self, min_chain_work: u128) -> Arc<rpc::SubmitBlockFn> {
            make_rpc_submit_block_cb(
                self.dag.clone(), self.store.clone(), self.mempool.clone(),
                self.node_state.clone(), self.shielded.clone(),
                self.otx.clone(), self.tip_tx.clone(), min_chain_work,
            )
        }
    }

    fn mk_coinbase(height: u64, value: u64) -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: format!("height:{}", height).into_bytes(),
                sequence:   u32::MAX,
            }],
            outputs: vec![core::TxOutput {
                value,
                script_pubkey: vec![0xAB; 20],
            }],
            locktime: 0,
        }
    }

    /// Fixture genesis. Deliberately NOT structurally valid (no SIS witness) —
    /// `accept_block` never re-validates ancestors, it only needs the genesis
    /// present in the DAG (for height/parent checks) and in storage (for the
    /// height-0 timestamp that seeds ASERT). The timestamp is "now" so ASERT
    /// eases difficulty for block 1, keeping the mined-block test fast.
    fn mk_genesis(ts: u64) -> core::Block {
        core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp:   ts,
                bits:        core::GENESIS_BITS,
                nonce:       0,
            },
            transactions: vec![mk_coinbase(0, 0)],
            blue_score: 0,
            height: 0,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        }
    }

    fn node_with_genesis(genesis: &core::Block) -> TestNode {
        let tmp   = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        let dag   = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));

        let gh = genesis.block_hash();
        store.put_block(genesis).expect("store genesis");
        dag.write().add_genesis(gh, genesis.header.timestamp);

        let (otx, orx) = mpsc::channel::<network::NetworkMessage>(64);
        let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(8);

        TestNode {
            _tmp: tmp,
            dag,
            store,
            mempool:    Arc::new(mempool::Mempool::new()),
            node_state: Arc::new(RwLock::new(rpc::NodeState::default())),
            shielded:   Arc::new(RwLock::new(crate::coherence::ShieldedPool::new())),
            otx,
            _orx: orx,
            tip_tx,
        }
    }

    /// Build a height-1 child of the fixture genesis that satisfies every
    /// check `accept_block` performs (bits, height, timestamp,
    /// coinbase value). With `mine == false` the block carries NO Module-SIS
    /// witness and a stale merkle root, so it fails `validate_structure()`
    /// while still being acceptable to `accept_block` — exactly the H2 gap.
    /// With `mine == true` a real SIS witness is mined (k = 4 regime below
    /// the SF-1 activation height) and the merkle root is binding.
    fn mk_child(node: &TestNode, genesis: &core::Block, mine: bool) -> core::Block {
        let gh = genesis.block_hash();
        let parent_ts = node.store.get_timestamp_at_height(0)
            .expect("ts read").expect("genesis ts present");
        let bits = pow::expected_bits(parent_ts, 1).expect("expected bits");
        let subsidy = core::tokenomics::block_subsidy_sat(1);

        let all_txs = vec![mk_coinbase(1, subsidy)];
        let merkle  = core::Transaction::merkle_root(&all_txs);

        let mut block = core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![gh],
                merkle_root: if mine { merkle } else { core::MerkleRoot::ZERO },
                timestamp:   parent_ts + 30,
                bits,
                nonce:       0,
            },
            transactions: all_txs,
            blue_score: 1,
            height: 1,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
                };

        if mine {
            let preimage = block.header.pow_preimage();
            let nonce = pow::mine_parallel(&preimage, bits, 1, 0, 1 << 16, 4, None)
                .expect("GnB-SMH solve within attempt budget");
            block.header.nonce = nonce;
            assert!(
                block.validate_structure().is_ok(),
                "mined fixture block must be structurally valid",
            );
        } else {
            assert!(
                block.validate_structure().is_err(),
                "fixture block must fail validate_structure",
            );
        }
        block
    }

    /// H2 regression: a block with a non-binding merkle root must be
    /// rejected by the RPC submitblock callback before it reaches the
    /// DAG/storage, by the structural gate.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_rejects_structure_invalid_block() {
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let bad = mk_child(&node, &genesis, false);
        let err = (node.rpc_cb())(bad).unwrap_err();
        assert!(err.contains("structural validation"), "rpc: {}", err);
        assert_eq!(node.dag.read().block_count(), 1, "DAG must contain only genesis");
    }

    /// A height-1 block with a binding Merkle root on `parents`, at `bits`,
    /// whose nonce FAILS the proof of work (searched with `validate_pow`, so
    /// `bits` must be hard enough for most nonces to fail).
    fn unmined_child(node: &TestNode, parents: Vec<[u8; 32]>, bits: u32) -> core::Block {
        let parent_ts = node.store.get_timestamp_at_height(0).unwrap().unwrap();
        let txs = vec![mk_coinbase(1, core::tokenomics::block_subsidy_sat(1))];
        let mut block = core::Block {
            header: core::BlockHeader {
                version: 1, parents, merkle_root: core::Transaction::merkle_root(&txs),
                timestamp: parent_ts + 30, bits, nonce: 0,
            },
            transactions: txs, blue_score: 1, height: 1, shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        while block.validate_pow() {
            block.header.nonce += 1;
        }
        assert_eq!(block.validate_structure_without_pow(), Ok(()), "fixture is structurally valid");
        block
    }

    /// B2-T11 (NET-2 on the RPC path): `submitblock` runs the cheap checks —
    /// structure without the proof, then `accept_block`'s known parents,
    /// header height, expected bits and timestamp — BEFORE the 64 MiB
    /// GnB-SMH evaluation, in the order gossip ingress uses. It called
    /// `validate_structure()` (proof included) first, so a block on random
    /// parents, or with the wrong bits, cost a full evaluation each and was
    /// refused as "invalid PoW"; now it is refused for its cheap fault.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_runs_cheap_checks_before_the_proof_of_work() {
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let orphan = unmined_child(&node, vec![[0x5A; 32]], core::GENESIS_BITS);
        let err = (node.rpc_cb())(orphan).unwrap_err();
        assert!(err.contains("unknown parent"), "the unknown parent must be found before the proof: {err}");
        let wrong_bits = unmined_child(&node, vec![genesis.block_hash()], core::GENESIS_BITS);
        let err = (node.rpc_cb())(wrong_bits).unwrap_err();
        assert!(err.contains("invalid difficulty"), "the bits must be checked before the proof: {err}");
        assert_eq!(node.dag.read().block_count(), 1, "nothing stored");
    }

    /// POW-8 challenge (1) / re-audit B1-T0: `submitblock` decodes the
    /// submitter's wire `blue_score`, which the block id does not commit to.
    /// The node stores, serves and relays the value derived from the
    /// block's parents, never the submitted one.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_stores_and_relays_the_derived_blue_score() {
        let genesis = mk_genesis(unix_now());
        let mut node = node_with_genesis(&genesis);
        let mut forged = mk_child(&node, &genesis, true);
        let id = forged.block_hash();
        forged.blue_score = u64::MAX;
        assert_eq!(forged.block_hash(), id, "the id does not commit to blue_score");
        (node.rpc_cb())(forged).expect("accepted");
        let stored = node.store.get_block(&id).unwrap().expect("stored");
        assert_eq!(stored.blue_score, 1, "stored with the derived blue score");
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), node._orx.recv())
            .await.expect("relayed").expect("channel open");
        match msg {
            network::NetworkMessage::NewBlock { block_hash, blue_score, block_data, .. } => {
                assert_eq!(block_hash, id);
                assert_eq!(blue_score, 1, "announced with the derived blue score");
                let relayed = core::Block::from_wire_bytes(&block_data).expect("canonical");
                assert_eq!(relayed.blue_score, 1, "relayed bytes carry the derived blue score");
                assert_eq!(block_data, stored.to_wire_bytes(), "the relayed bytes are the stored bytes");
            }
            other => panic!("expected NewBlock, got {:?}", std::mem::discriminant(&other)),
        }
    }

    /// Positive control: a genuinely mined block (GnB-SMH proof, binding
    /// merkle) is accepted by the RPC submitblock callback.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_accepts_valid_block() {
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let good = mk_child(&node, &genesis, true);
        let res = (node.rpc_cb())(good);
        assert!(res.is_ok(), "rpc submitblock must accept a valid block: {:?}", res);
        assert_eq!(node.dag.read().block_count(), 2);
    }

    /// POW-3: the hook applies the node's minimum chain work. With mainnet's
    /// (the release constant, what `main` passes on a mainnet node without
    /// `--minimumchainwork`) the same valid block, whose chain is far below
    /// it, is refused before its proof or any storage; with the minimum the
    /// chain reaches (an override), it is accepted.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_applies_the_minimum_chain_work() {
        assert_eq!(ingress::minimum_chain_work(), core::MIN_CHAIN_WORK, "the mainnet default is in force");
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let good = mk_child(&node, &genesis, true);
        let err = (node.rpc_cb_with(core::MIN_CHAIN_WORK))(good.clone()).unwrap_err();
        assert!(err.contains("below the minimum chain work") && err.contains("initial block download"), "{err}");
        assert_eq!(node.dag.read().block_count(), 1, "nothing stored");
        let lb = ingress::block_work_lower_bound(&node.dag.read(), &good.header.parents, good.header.bits, good.height)
            .expect("parent known");
        (node.rpc_cb_with(lb))(good).expect("a minimum the block's chain reaches");
        assert_eq!(node.dag.read().block_count(), 2);
    }

    // ── LEG1-selfmine-accept regressions (Round-2 audit) ────────────────────
    //
    // Self-mined blocks must go through `commit_self_mined_block` →
    // `accept_block`, the SAME pipeline as network/RPC/stratum ingress. The
    // pre-fix miner loop committed its own block inline (put_block +
    // apply_block_utxo_mutations + dag.add_block) with NO consensus
    // validation, so a block violating an invariant the mempool cannot catch
    // (e.g. a coinbase over-claim) was persisted locally and only rejected by
    // peers — forking the producer off its own network. These tests FAIL if
    // that inline commit path is ever restored.

    /// Like `mk_child(mine = true)` but with an arbitrary coinbase value:
    /// real SIS witness + binding merkle root, so `validate_structure()`
    /// passes and only `accept_block`'s consensus checks can stop it.
    fn mk_mined_child_with_coinbase(
        node: &TestNode,
        genesis: &core::Block,
        cb_value: u64,
    ) -> core::Block {
        let gh = genesis.block_hash();
        let parent_ts = node.store.get_timestamp_at_height(0)
            .expect("ts read").expect("genesis ts present");
        let bits = pow::expected_bits(parent_ts, 1).expect("expected bits");
        let all_txs = vec![mk_coinbase(1, cb_value)];
        let merkle  = core::Transaction::merkle_root(&all_txs);
        let mut block = core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![gh],
                merkle_root: merkle,
                timestamp:   parent_ts + 30,
                bits,
                nonce:       0,
            },
            transactions: all_txs,
            blue_score: 1,
            height: 1,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        let preimage = block.header.pow_preimage();
        let nonce = pow::mine_parallel(&preimage, bits, 1, 0, 1 << 16, 4, None)
                .expect("GnB-SMH solve within attempt budget");
            block.header.nonce = nonce;
        assert!(
            block.validate_structure().is_ok(),
            "fixture must be structurally valid — the rejection under test \
             is consensus-level, which only accept_block performs",
        );
        block
    }

    fn commit_mined(node: &TestNode, block: &core::Block) -> Result<[u8; 32], String> {
        commit_self_mined_block(
            block,
            &node.dag, &node.store, &node.mempool, &node.node_state,
            Some(&node.tip_tx), &node.shielded,
        )
    }

    /// C-R3-1 core regression: a self-mined block violating a
    /// mempool-missable invariant (coinbase over-claims subsidy by 1 sat —
    /// the coinbase never passes through the mempool) must be rejected by
    /// the PRODUCER ITSELF and leave no trace in DAG or storage. On the
    /// pre-fix inline path this block was committed unconditionally.
    #[tokio::test(flavor = "multi_thread")]
    async fn self_mined_block_violating_consensus_is_rejected_by_producer() {
        let genesis = mk_genesis(unix_now());
        let node    = node_with_genesis(&genesis);
        let subsidy = core::tokenomics::block_subsidy_sat(1);
        let bad     = mk_mined_child_with_coinbase(&node, &genesis, subsidy + 1);
        let hash    = bad.block_hash();

        let res = commit_mined(&node, &bad);
        assert!(
            res.is_err(),
            "LEG1: producer must reject its own consensus-invalid block, \
             got acceptance: {:?}", res,
        );
        let msg = res.unwrap_err();
        assert!(
            msg.contains("coinbase"),
            "rejection must come from the coinbase-value consensus check, got: {}", msg,
        );
        // UPDATED for audit DAG-1 (accept/connect split). The pre-fix path
        // deleted a block that failed transaction validation. Transaction
        // validity is now a connect-time property of the block's own chain
        // context; a block failing it is recorded as CHAIN-DISQUALIFIED and
        // kept in the DAG (so a peer that merged it as a non-selected parent
        // stays acceptable — arrival-order independence), but it is never
        // selected, never applied and never broadcast. What this test guards —
        // the producer refuses its own invalid block and nothing of it reaches
        // the chain state — is unchanged:
        assert!(node.dag.read().is_invalid(&hash), "must be recorded as disqualified");
        assert!(
            node.store.invalid_block_reason(&hash).expect("meta read").is_some(),
            "the disqualification must be persisted",
        );
        assert_eq!(
            node.dag.read().selected_tip(), Some(genesis.block_hash()),
            "a rejected self-mined block must never become the selected tip",
        );
        assert!(
            node.store.get_utxo(&bad.transactions[0].txid(), 0).expect("utxo read").is_none(),
            "a rejected self-mined block must have no UTXO effect",
        );
        assert!(
            node.store.get_meta("tip_hash").expect("meta read").is_none(),
            "the applied tip pointer must not move",
        );
    }

    /// Structural gate parity: the self-miner gets no structural bypass
    /// either (same H2 gate as stratum/RPC submissions).
    #[tokio::test(flavor = "multi_thread")]
    async fn self_mined_structure_invalid_block_is_rejected_by_producer() {
        let genesis = mk_genesis(unix_now());
        let node    = node_with_genesis(&genesis);
        let bad     = mk_child(&node, &genesis, false);
        let hash    = bad.block_hash();

        let msg = commit_mined(&node, &bad)
            .expect_err("structure-invalid self-mined block must be rejected");
        assert!(
            msg.contains("structural validation"),
            "rejection must come from the structural gate, got: {}", msg,
        );
        assert!(node.store.get_block(&hash).expect("store read").is_none());
        assert_eq!(node.dag.read().block_count(), 1);
    }

    /// Positive control: a genuinely valid self-mined block flows through
    /// the shared pipeline, is committed, advances the selected tip and
    /// refreshes the RPC-visible state — the fix does not over-reject.
    #[tokio::test(flavor = "multi_thread")]
    async fn self_mined_valid_block_is_committed_through_accept_block() {
        let genesis = mk_genesis(unix_now());
        let node    = node_with_genesis(&genesis);
        let good    = mk_child(&node, &genesis, true);
        let hash    = good.block_hash();

        let res = commit_mined(&node, &good);
        assert_eq!(
            res.expect("valid self-mined block must be accepted"), hash,
        );
        assert_eq!(node.dag.read().block_count(), 2);
        assert_eq!(node.dag.read().selected_tip(), Some(hash));
        assert!(
            node.store.get_block(&hash).expect("store read").is_some(),
            "accepted self-mined block must be persisted",
        );
        assert_eq!(node.node_state.read().block_count, 2, "RPC state must be refreshed");
    }

    // ── Audit DAG-6: no reorg-depth limit ───────────────────────────────────
    //
    // Drive the REAL `accept_block` pipeline (add_block → resolve → atomic
    // connect) with a fork that out-weighs the live chain only once it is
    // deeper than the live chain itself. The old pipeline refused such a
    // reorg once it exceeded `MAX_REORG_DEPTH` (a node-local cap, so nodes
    // that saw the blocks in different orders split); it is now followed at
    // any depth. The >1,000-block audit scenario, with two nodes and UTXO
    // digests, is `node/tests/fix_chain_selection.rs`.

    /// Submit a block through the real `accept_block` pipeline. This is the
    /// exact function the stratum/RPC callbacks delegate to; those wrappers
    /// only add the H2 `validate_structure()` pre-gate, which is orthogonal
    /// to the consensus ordering under test and would force mining a real
    /// SIS witness for every fixture block.
    fn accept(node: &TestNode, block: &core::Block) -> Result<[u8; 32], String> {
        accept_block(
            block, block.block_hash(), block.height,
            &node.dag, &node.store, &node.mempool, &node.node_state,
            Some(&node.tip_tx), &node.shielded,
        )
    }

    /// Build an H2-fixture-style (structurally lax) child of `parent` at
    /// `height` that satisfies every check `accept_block` performs (bits,
    /// height, timestamp, coinbase value). The merkle root is
    /// ZERO for these fixtures, so `nonce` is what differentiates
    /// same-position blocks on competing chains (block_hash covers it).
    fn mk_block_at(
        node: &TestNode,
        parent: [u8; 32],
        height: u64,
        ts: u64,
        nonce: u64,
    ) -> core::Block {
        let parent_ts = node.store.get_timestamp_at_height(height - 1)
            .expect("ts read").expect("parent-height timestamp present");
        let bits = pow::expected_bits(parent_ts, height).expect("expected bits");
        let subsidy = core::tokenomics::block_subsidy_sat(height);
        core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![parent],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp:   ts,
                bits,
                nonce,
            },
            transactions: vec![mk_coinbase(height, subsidy)],
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        }
    }

    /// Audit DAG-6 (replaces `refused_deep_reorg_must_not_poison_dag_selected_tip`,
    /// which pinned the removed depth cap): a heavier fork that branches at
    /// genesis, deeper than the whole live chain, is adopted — selected AND
    /// applied — and a later extension of the old chain is an ordinary
    /// fork-loser. The DAG and the applied state never disagree.
    #[tokio::test(flavor = "multi_thread")]
    async fn heavier_fork_is_followed_at_any_depth() {
        const D: u64 = 6;
        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // (a) Real chain R: genesis → r1 … r_{D+1}, all through accept_block.
        let mut parent = gh;
        for i in 1..=(D + 1) {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            parent = b.block_hash();
        }
        let real_tip = parent;
        assert_eq!(node.dag.read().selected_tip(), Some(real_tip));

        // (b) Fork F from genesis: f1 … f_{D+2}. f_{D+1} ties R's tip on
        // blue_work and is ground to lose the hash tie-break; f_{D+2}
        // strictly out-weighs R and needs a reorg of all D+1 blocks of R.
        let mut fparent = gh;
        let mut fork_tip = gh;
        for i in 1..=(D + 2) {
            let mut nonce = 1_000_000 + i;
            let mut fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
            if i == D + 1 {
                while fb.block_hash() >= real_tip {
                    nonce += 1;
                    fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
                }
            }
            let res = accept(&node, &fb);
            assert!(res.is_ok(), "fork block f{} must be accepted, got: {:?}", i, res);
            if i <= D + 1 {
                assert_eq!(node.dag.read().selected_tip(), Some(real_tip),
                    "fork-loser f{} must not move the selected tip", i);
            }
            fparent = fb.block_hash();
            fork_tip = fparent;
        }

        // (1) The heavier fork is followed: selected tip and applied tip.
        assert_eq!(node.dag.read().selected_tip(), Some(fork_tip));
        let tip_meta = node.store.get_meta("tip_hash").expect("meta read").expect("tip_hash");
        assert_eq!(tip_meta.as_slice(), &fork_tip[..], "the applied state follows the fork");

        // (2) An extension of the old chain that only TIES the fork (and is
        // ground to lose the hash tie-break) is a fork-loser: accepted into
        // the DAG, applied tip unchanged.
        let mut nonce = 424_242;
        let mut r_next = mk_block_at(&node, real_tip, D + 2, g_ts + 30 * (D + 2), nonce);
        while r_next.block_hash() >= fork_tip {
            nonce += 1;
            r_next = mk_block_at(&node, real_tip, D + 2, g_ts + 30 * (D + 2), nonce);
        }
        assert!(accept(&node, &r_next).is_ok());
        assert_eq!(node.dag.read().selected_tip(), Some(fork_tip));
        let tip_meta = node.store.get_meta("tip_hash").expect("meta read").expect("tip_hash");
        assert_eq!(tip_meta.as_slice(), &fork_tip[..]);
    }

    /// Root-cause regression for the red/side-block body-retention starvation
    /// that froze tip-selection (selected tip stuck while blue_score climbed)
    /// and stalled IBD ("body unavailable — an archival peer is needed").
    ///
    /// A block at or below the finalized height that is a *fork-loser* must be
    /// ACCEPTED and RETAINED (body in CF_BLOCKS + entry in the DAG) so it can
    /// serve as a GhostDAG mergeset member — it must NOT be rejected by the
    /// finality checkpoint, and it must NOT move the selected tip. Pre-fix,
    /// accept_block rejected it outright ("finality: ... at or below finalized
    /// height"), so its body was never stored and no node could serve it.
    #[tokio::test(flavor = "multi_thread")]
    async fn below_finality_fork_loser_is_retained_not_rejected() {
        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // Real chain: genesis → r1 … r5, all through the real accept path.
        let mut parent = gh;
        let mut r1 = gh;
        for i in 1..=5u64 {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            if i == 1 { r1 = b.block_hash(); }
            parent = b.block_hash();
        }
        let real_tip = parent;

        // An old data dir may still carry a `finalized_height` meta key (here
        // 3). Since audit DAG-6 it is ignored: nothing below must change.
        node.store.put_meta("finalized_height", &3u64.to_le_bytes())
            .expect("set finalized_height");

        // A side block at height 2 (<= finalized 3): sibling of r2 (same parent
        // r1, distinct nonce → distinct hash). It is a fork-loser — the real
        // chain to r5 has far more blue work.
        let fork = mk_block_at(&node, r1, 2, g_ts + 30 * 2, 987_654);
        let fork_hash = fork.block_hash();
        assert_ne!(fork_hash, real_tip);

        let res = accept(&node, &fork);
        assert!(
            res.is_ok(),
            "a below-finality FORK-LOSER must be accepted (retained as a \
             mergeset member), not rejected by finality; got: {:?}", res,
        );

        // Retained: body servable + present in the DAG.
        assert!(
            node.store.get_block(&fork_hash).expect("body read").is_some(),
            "below-finality fork-loser body must be RETAINED in CF_BLOCKS \
             (else peers answer 'body unavailable')",
        );
        assert!(
            node.dag.read().get_block_data(&fork_hash).is_some(),
            "below-finality fork-loser must be present in the DAG",
        );

        // Inert: it must NOT move the selected tip (finality invariant intact).
        assert_eq!(
            node.dag.read().selected_tip(), Some(real_tip),
            "a below-finality fork-loser must NOT become the selected tip",
        );

        // And re-submitting it is a cheap dedup no-op rejection, not a re-run.
        let again = accept(&node, &fork);
        assert!(
            again.is_err() && again.unwrap_err().contains("already in DAG"),
            "a block already in the DAG must be rejected by the early dedup",
        );
    }

    /// GnB derives expected difficulty from the block's parents' DAG entries
    /// (latest parent timestamp), never from pruned body history, so the
    /// check is complete at every height and enforced below finality too.
    /// (Bloch skipped it below finality because its re-derivation read pruned
    /// history; that hole let below-finality blocks carry arbitrary bits.)
    #[tokio::test(flavor = "multi_thread")]
    async fn difficulty_is_checked_below_and_above_finality() {
        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // Real chain: genesis → r1 … r5.
        let mut parent = gh;
        let mut r1 = gh;
        let mut r3 = gh;
        for i in 1..=5u64 {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            if i == 1 { r1 = b.block_hash(); }
            if i == 3 { r3 = b.block_hash(); }
            parent = b.block_hash();
        }
        let real_tip = parent;

        // A stale `finalized_height` meta key (ignored since audit DAG-6).
        node.store.put_meta("finalized_height", &3u64.to_le_bytes())
            .expect("set finalized_height");

        // (1) BELOW finality (h=2 ≤ 3): fork-loser sibling of r2 with the WRONG
        // difficulty bits must be rejected.
        let mut below = mk_block_at(&node, r1, 2, g_ts + 30 * 2, 111_222);
        let good_bits = below.header.bits;
        below.header.bits = good_bits ^ 0x0000_0001; // != expected
        assert_ne!(below.header.bits, good_bits);
        let below_hash = below.block_hash();
        let res = accept(&node, &below);
        assert!(
            res.as_ref().is_err_and(|e| e.contains("invalid difficulty")),
            "below-finality block with wrong bits must be rejected; got: {:?}", res,
        );
        assert!(node.dag.read().get_block_data(&below_hash).is_none());
        assert_eq!(node.dag.read().selected_tip(), Some(real_tip));

        // With the right bits the same below-finality sibling is retained as
        // an inert fork-loser and does not move the selected tip.
        below.header.bits = good_bits;
        assert!(accept(&node, &below).is_ok());
        assert_eq!(node.dag.read().selected_tip(), Some(real_tip));

        // (2) ABOVE finality (h=4 > 3): sibling of r4 with WRONG bits.
        let mut above = mk_block_at(&node, r3, 4, g_ts + 30 * 4, 333_444);
        above.header.bits ^= 0x0000_0001; // != expected
        let res2 = accept(&node, &above);
        assert!(
            res2.is_err() && res2.as_ref().unwrap_err().contains("invalid difficulty"),
            "above-finality block with wrong bits must STILL be rejected for \
             difficulty; got: {:?}", res2,
        );
    }
}

#[cfg(test)]
mod intra_tx_dup_tests {
    use super::*;
    use tempfile::TempDir;

    fn mk_store() -> (TempDir, Arc<storage::Storage>) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        (tmp, store)
    }

    /// A tx spending the SAME confirmed 100_000-sat outpoint `n` times, every
    /// input carrying a VALID hybrid signature over its own sighash — so
    /// without the duplicate-outpoint check nothing else rejects it and the
    /// fee comes out inflated by the duplicated value.
    fn dup_input_tx(store: &Arc<storage::Storage>, n: usize, out_value: u64)
        -> core::Transaction
    {
        use sha3::{Digest as _, Sha3_256};
        let (pk, sk) = crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
        let prev_txid = [0x42u8; 32];
        store.put_utxo(&prev_txid, 0,
            &core::TxOutput { value: 100_000, script_pubkey: pk_hash })
            .expect("put_utxo");

        let mut tx = core::Transaction {
            version: 1,
            inputs: (0..n).map(|_| core::TxInput {
                prev_txid, prev_index: 0, script_sig: vec![], sequence: u32::MAX,
            }).collect(),
            outputs: vec![core::TxOutput { value: out_value, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        };
        for i in 0..n {
            let sighash = tx.sighash(i, core::node_chain_id());
            let sig = crypto::sign(&sk, &sighash).expect("sign");
            tx.inputs[i].script_sig = core::Transaction::build_script_sig(&sig, &pk);
        }
        tx
    }

    /// Gossip-relay admission (`validate_tx_standalone`, spent_set = None):
    /// a 2-duplicate-input tx spending a 100k outpoint but emitting 150k must
    /// be refused. Without the fix this was ADMITTED with fee = 50_000.
    #[test]
    fn gossip_path_refuses_intra_tx_duplicate_outpoint() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 2, 150_000);
        let err = validate_tx_standalone(&tx, &store, 0)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// The exact conditional the audit flagged, hit directly: the shared core
    /// with `spent_set = None` must still catch an N=3 duplication (value
    /// would otherwise triple: 300k in, 290k out, fee 10k).
    #[test]
    fn validate_tx_inputs_refuses_duplicates_without_spent_set() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 3, 290_000);
        let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
            store.get_utxo(txid, idx).map_err(|e| e.to_string())
        };
        let err = validate_tx_inputs(&tx, &lookup, None, 1)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// Control: the SAME signed shape with a single input and honest amounts
    /// is still admitted with the right fee — the fix rejects duplication,
    /// not the legacy path itself.
    #[test]
    fn single_input_control_still_admitted() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 1, 70_000);
        let fee = validate_tx_standalone(&tx, &store, 0)
            .expect("valid single-input spend must be admitted");
        assert_eq!(fee, 30_000);
    }

    /// Consensus minimum fee: a well-formed, correctly signed spend paying
    /// less than `tokenomics::min_tx_fee_sat(size)` is refused.
    #[test]
    fn below_minimum_fee_is_refused() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 1, 90_000); // fee 10_000 < ~17_000 minimum
        let err = validate_tx_standalone(&tx, &store, 0).unwrap_err();
        assert!(err.contains("below consensus minimum"), "{err}");
    }

    /// Legacy N-7 regression: the MINER's OWN block-template fee estimate
    /// (`miner_template_total_fees`) must not inflate a duplicate-outpoint
    /// transaction's fee contribution. A 2-duplicate-input tx spending a
    /// 100k outpoint and emitting 150k has NO legitimate fee at all (such a
    /// tx is rejected outright by real admission) — but before the fix,
    /// summing every input's resolved value unconditionally would have
    /// counted the 100k outpoint TWICE (200k in, 150k out => 50k "fee").
    /// Reverting the fix (dropping the insert-as-check) makes this test
    /// fail (asserting 0 would fail; it would instead read 50_000).
    #[test]
    fn miner_template_does_not_inflate_duplicate_outpoint_fee() {
        let (_tmp, store) = mk_store();
        let dup_tx = dup_input_tx(&store, 2, 150_000);
        let total = miner_template_total_fees(std::slice::from_ref(&dup_tx), &store);
        assert_eq!(total, 0, "a duplicate-outpoint tx must contribute zero fee to the template");
    }

    /// Control: an honest, non-duplicated single-input tx still contributes
    /// its real fee to the template estimate, and a mixed set (one honest,
    /// one duplicate-outpoint) counts only the honest one.
    #[test]
    fn miner_template_counts_honest_fees_normally() {
        let (_tmp, store) = mk_store();
        let honest_tx = dup_input_tx(&store, 1, 90_000);
        assert_eq!(
            miner_template_total_fees(std::slice::from_ref(&honest_tx), &store),
            10_000,
        );

        let (_tmp2, store2) = mk_store();
        let honest_tx2 = dup_input_tx(&store2, 1, 90_000);
        let dup_tx2 = dup_input_tx(&store2, 2, 150_000);
        assert_eq!(
            miner_template_total_fees(&[honest_tx2, dup_tx2], &store2),
            10_000,
            "the mixed batch's total must equal the honest tx's fee alone",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy C-2 — a transaction may spend an EARLIER same-block transaction's
// output, but never a LATER one. `reorg::apply_block_utxo_mutations` applies
// each transaction's outputs THEN its inputs, walking `block.transactions` IN
// ORDER, so a later transaction's output does not exist in storage yet when
// an earlier transaction is applied. Before the fix,
// `validate_tx_in_block_with_maturity` (and the `euvm`-feature
// `validate_tx_in_block_euvm`) built their in-block prevout map from ALL of
// `block.transactions` unconditionally, so an out-of-order spend validated —
// and would have minted supply on acceptance (the spent value credited to
// the earlier tx's fee accounting was never actually removed from the UTXO
// set, since the later tx's `put_utxo` for that same output ran AFTER the
// earlier tx's no-op `delete_utxo` on a not-yet-existent key).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod out_of_order_spend_tests {
    use super::*;
    use tempfile::TempDir;

    fn mk_store() -> (TempDir, Arc<storage::Storage>) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        (tmp, store)
    }

    fn coinbase() -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: [0u8; 32], prev_index: u32::MAX,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 1_000, script_pubkey: vec![0xABu8; 20] }],
            locktime: 0,
        }
    }

    /// Regression: block index 1 ("early") claims to spend block index 2's
    /// ("late") not-yet-applied output. Reverting the Legacy C-2 fix
    /// (restoring the unconditional `block.transactions.iter()` prevout map)
    /// makes this test fail — the spend would validate (and return a fee)
    /// instead of being rejected.
    #[test]
    fn cannot_spend_a_later_transactions_output_in_the_same_block() {
        use sha3::{Digest as _, Sha3_256};
        let (_tmp, store) = mk_store();
        let (pk, sk) = crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();

        // tx_late (block index 2): an ordinary spend of an already-confirmed
        // UTXO, producing a fresh output paying `pk_hash`. Its own inputs are
        // irrelevant to this test — only the attempted spend of ITS output
        // (by tx_early, below) is under test.
        let late_prev_txid = [0x77u8; 32];
        store.put_utxo(&late_prev_txid, 0,
            &core::TxOutput { value: 100_000, script_pubkey: vec![9u8; 20] })
            .expect("put_utxo");
        let tx_late = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: late_prev_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 90_000, script_pubkey: pk_hash }],
            locktime: 0,
        };
        let late_txid = tx_late.txid();

        // tx_early (block index 1): a VALIDLY-SIGNED spend of tx_late's
        // output 0 — which does not exist anywhere (not in the block-applied
        // prefix, not in storage) at the point tx_early is validated/applied.
        let mut tx_early = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: late_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 80_000, script_pubkey: vec![1u8; 20] }],
            locktime: 0,
        };
        let sighash = tx_early.sighash(0, core::node_chain_id());
        let sig = crypto::sign(&sk, &sighash).expect("sign");
        tx_early.inputs[0].script_sig = core::Transaction::build_script_sig(&sig, &pk);

        let block = core::Block {
            header: core::BlockHeader {
                version: 1, parents: vec![], merkle_root: core::MerkleRoot::ZERO,
                timestamp: 0, bits: core::GENESIS_BITS, nonce: 0,
            },
            transactions: vec![coinbase(), tx_early, tx_late],
            blue_score: 0, height: 1,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };

        let mut spent = HashSet::new();
        let err = validate_tx_in_block_with_maturity(
            &block, &block.transactions[1], &store, &mut spent, 0,
        ).expect_err("a transaction must never validate against a LATER transaction's output");
        assert!(err.contains("not found"), "expected a prevout-not-found error, got: {err}");
    }

    /// Control: the SAME shape, but tx_early spends tx_late's output when
    /// tx_late sits EARLIER in the block (index 1, before tx_early at index
    /// 2) — ordinary, legitimate same-block chaining, which must still
    /// validate (the fix must not over-reject legal same-block spends).
    #[test]
    fn can_spend_an_earlier_transactions_output_in_the_same_block() {
        use sha3::{Digest as _, Sha3_256};
        let (_tmp, store) = mk_store();
        let (pk, sk) = crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();

        let early_prev_txid = [0x88u8; 32];
        store.put_utxo(&early_prev_txid, 0,
            &core::TxOutput { value: 100_000, script_pubkey: vec![9u8; 20] })
            .expect("put_utxo");
        // This transaction now sits EARLIER in the block (index 1).
        let tx_funding = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: early_prev_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 90_000, script_pubkey: pk_hash }],
            locktime: 0,
        };
        let funding_txid = tx_funding.txid();

        // This transaction sits LATER (index 2) and spends the funding tx's
        // output — a legitimate same-block chained spend.
        let mut tx_spend = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: funding_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 60_000, script_pubkey: vec![1u8; 20] }],
            locktime: 0,
        };
        let sighash = tx_spend.sighash(0, core::node_chain_id());
        let sig = crypto::sign(&sk, &sighash).expect("sign");
        tx_spend.inputs[0].script_sig = core::Transaction::build_script_sig(&sig, &pk);

        let block = core::Block {
            header: core::BlockHeader {
                version: 1, parents: vec![], merkle_root: core::MerkleRoot::ZERO,
                timestamp: 0, bits: core::GENESIS_BITS, nonce: 0,
            },
            transactions: vec![coinbase(), tx_funding, tx_spend],
            blue_score: 0, height: 1,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };

        let mut spent = HashSet::new();
        let fee = validate_tx_in_block_with_maturity(
            &block, &block.transactions[2], &store, &mut spent, 0,
        ).expect("a transaction MAY spend an earlier same-block transaction's output");
        assert_eq!(fee, 30_000);
    }
}
