//! Bloch-SIS Protocol — JSON-RPC over HTTP (axum)
//!
//! Methods:
//!   getnetworkinfo, getblockcount, getmempoolinfo,
//!   getblockhash, getblock, getblockbyheight, getrecentblocks,
//!   gettransaction, getbalance, getutxos,
//!   sendrawtransaction,
//!   validateaddress, estimatefee, getrawmempool,
//!   decoderawtransaction, getdaginfo, listtransactions, getpeerinfo,
//!   invalidateblock, reconsiderblock (admin: audit DAG-6)
//!
//! Mempool policy (audit MEM-6, `docs/MEMPOOL.md`): `sendrawtransaction`
//! accepts children of unconfirmed transactions (≤ 25 ancestors and
//! descendants, ≤ 500,000-byte packages) and applies FULL-RBF — a
//! transaction double-spending pooled ones replaces them iff it adds no new
//! unconfirmed input, pays a higher fee rate than each direct conflict, an
//! absolute fee ≥ the fees of everything it evicts plus 1 sat/byte of its own
//! size, and evicts ≤ 100 transactions (BIP125 rules 2–6, no signalling).
//! `getmempoolinfo` reports these parameters under `policy`.

pub mod auth;
mod explorer;


use std::sync::Arc;
use parking_lot::RwLock;
use log::{info, error};
use axum::{routing::post, Router, extract::State, extract::DefaultBodyLimit, http::StatusCode, Json};
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower::limit::GlobalConcurrencyLimitLayer;

/// P0 RPC hardening (roadmap §1.6 / §4.3).
/// Max request body of every method but `submitblock`: JSON-RPC calls are
/// tiny; 1 MiB is generous and tighter than axum's 2 MiB default. Blocks
/// oversized-payload memory abuse.
const RPC_MAX_BODY_BYTES: usize = 1024 * 1024;
/// B1-T4: largest body of a `submitblock` request. The block travels as the
/// hex of its wire bytes, about twice their size, and a block built from a
/// full template is up to `MAX_BLOCK_SIZE` (1,000,000 bytes): 4 MiB is that
/// twice over plus the JSON envelope, with margin (the same 4 MiB as a gossip
/// or sync frame). Every other method keeps `RPC_MAX_BODY_BYTES`.
const RPC_MAX_SUBMITBLOCK_BODY_BYTES: usize = 4 * 1024 * 1024;
/// B1-T4: bodies above `RPC_MAX_BODY_BYTES` buffered at once (each holds a
/// permit from `AppState::large_bodies` until its request is answered), so a
/// flood of large bodies cannot pin `RPC_MAX_CONCURRENCY` × 4 MiB.
const RPC_LARGE_BODY_PERMITS: usize = 4;
/// B1-T4 (review): further large-body permits only the operator's callers
/// may take (a caller that presents the API key, or a direct loopback /
/// trusted-range caller that did not come through a proxy). The shared
/// permits are taken before the request is authorized (the method is in the
/// body), so four anonymous slow uploads could hold all of them for the 30 s
/// request timeout, again and again, and the operator's miner got 503 for
/// every full-block `submitblock`.
const RPC_LARGE_BODY_RESERVED_PERMITS: usize = 2;
/// B1-T11 (review): most index entries `listtransactions` counts for a
/// height range other than the whole history (the deepest page it serves,
/// `MAX_HISTORY_OFFSET` + its 1,000-entry limit, is countable exactly).
const LISTTX_COUNT_CAP: u64 = if cfg!(test) { 500 } else { crate::storage::indexer::MAX_HISTORY_OFFSET as u64 + 1_000 };
/// B1-T10: burst of the node-wide budget for transactions submitted by
/// untrusted callers (`sendrawtransaction`, wire bytes): five
/// maximum-size (400 KiB) transactions.
const ANON_TX_VERIFY_BURST_BYTES: u64 = 2_000_000;
/// B1-T10: refill of that budget, bytes per second (3 MB a minute, about 350
/// hybrid inputs a second). Admitted transactions are refunded, so it only
/// ever runs out under transactions the node refuses.
const ANON_TX_VERIFY_BYTES_PER_SEC: u64 = 50_000;
/// Global cap on concurrently in-flight RPC handlers, shared across all
/// connections (GlobalConcurrencyLimitLayer holds one Arc'd semaphore). Bounds
/// how many expensive storage-scanning methods can pile up at once. Value is a
/// conservative default — needs load-testing to tune (not yet done).
const RPC_MAX_CONCURRENCY: usize = 256;
/// Per-request wall-clock timeout (returns 408). Kills slow-loris / stuck
/// handlers so they can't hold a concurrency slot forever.
const RPC_REQUEST_TIMEOUT_SECS: u64 = 30;
/// L-9 (audit): the dispatch-level timeout `handle_rpc` races its
/// `spawn_blocking` `JoinHandle` against, strictly SHORTER than
/// `RPC_REQUEST_TIMEOUT_SECS` so this one fires first and gets the chance to
/// `abort()` the handle — the outer `TimeoutLayer` only ever dropped the
/// response future, which never cancelled the underlying blocking task. See
/// the long comment at the `tokio::select!` call site for what `.abort()`
/// can and cannot stop.
const DISPATCH_INNER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS - 5);
use serde_json::{json, Value};
use crate::storage::{Storage, StorageError};
use crate::mempool::Mempool;
use crate::consensus::GhostDAG;
use crate::core::{Transaction, PROTOCOL_VERSION, MAINNET_PREFIX, TESTNET_PREFIX};
use tokio::sync::mpsc;
use crate::network::NetworkMessage;

#[derive(Clone, Debug, Default)]
pub struct NodeState {
    pub tip_blue_score: u64,
    pub block_count:    u64,
    pub peer_count:     u32,
    pub mempool_size:   usize,
    pub is_syncing:     bool,
    /// Highest tip blue-score any peer has announced (via PeerTip). Used to
    /// release the IBD latch: is_syncing clears once tip_blue_score catches up
    /// to this. (The old code only cleared on an empty Headers message, which
    /// no peer ever sends, so is_syncing — and the miner pause — latched
    /// forever and joining miners synced but never mined.)
    pub best_seen_blue_score: u64,
    /// Set once the node has processed at least one remote PeerTip. The
    /// fresh-miner fork guard waits for this so a joining miner never mines a
    /// genesis fork in the window between "connected" and "evaluated a tip".
    pub seen_first_tip: bool,
    /// Honest-RPC fix: highest blue_score announced by a CONNECTED peer,
    /// refreshed by every maybe_release_ibd re-test (event-driven + 30s
    /// nudge). UNTRUSTED wire hint — never gates consensus or the IBD latch;
    /// it exists so `getnetworkinfo` can report `best_announced`/`behind_by`
    /// and a lagging node SAYS it is lagging instead of just `syncing:false`.
    /// Differs from `best_seen_blue_score` (lifetime max over any peer ever,
    /// including long-gone ones): this one tracks currently-connected peers.
    pub best_announced_blue_score: u64,
    pub peer_addresses: Vec<String>,
    pub version:        String,
    /// How long the selected tip has stayed below the minimum chain work
    /// (the IBD latch's long-sync warning, `maybe_release_ibd`).
    pub min_work_watch: crate::ingress::MinimumWorkWatch,
}

/// Block-submission hook — the B5f pool seam.
///
/// Stratum V1/V2 cannot carry the Module-SIS solution vector in their share
/// messages (see main.rs B5f), so external pools mine full SIS blocks and
/// hand them in over RPC instead. main.rs wires this with a closure that
/// mirrors the gossipsub NewBlock path: `Block::block_hash()` identity,
/// `validate_structure_without_pow()` (merkle, coinbase, size...), then the
/// same `accept_block` consensus pipeline — known parents, height, bits and
/// timestamp before the proof of work (B2-T11) — then network broadcast.
///
/// `None` (tests, or callers that don't wire it) makes `submitblock` return
/// a "not wired" error instead of silently accepting.
pub type SubmitBlockFn = dyn Fn(crate::core::Block) -> Result<String, String> + Send + Sync;

/// Operator chain overrides (audit DAG-6), Bitcoin Core's `invalidateblock`
/// and `reconsiderblock`, and the PoWit finality settings (PoWit audit
/// findings 2 and 3, `powit::FinalityOp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainAdminOp {
    /// Disqualify a block and its selected-chain descendants, persistently.
    Invalidate,
    /// Remove such disqualifications (the block, its selected-chain ancestors
    /// and descendants) and let the node re-evaluate them.
    Reconsider,
    /// `ignorefinalized`: never pin a finalized checkpoint at or above the
    /// block on its chain.
    IgnoreFinalized,
    /// `reconsiderfinalized`: undo `ignorefinalized` for the block.
    ReconsiderFinalized,
    /// `setfinalitycheckpoint <hash>`: the operator's weak-subjectivity anchor.
    SetFinalityCheckpoint,
    /// `setfinalitycheckpoint <hash> <height>`: the same by hash and DAG
    /// height, for a block the node may not hold yet (review MEDIUM 6).
    SetFinalityCheckpointAt(u64),
    /// `setfinalitycheckpoint none` (the hash is ignored).
    DisableFinalityCheckpoint,
    /// `setfinalitycheckpoint default`: back to the release checkpoint.
    DefaultFinalityCheckpoint,
}

/// Hook that performs a [`ChainAdminOp`] on a block through the acceptance
/// pipeline (`accept::invalidate_block` / `accept::reconsider_block`), wired by
/// main.rs. Returns a JSON summary. `None` makes the methods report "not wired".
pub type ChainAdminFn = dyn Fn(ChainAdminOp, [u8; 32]) -> Result<Value, String> + Send + Sync;

#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind_address:              String,
    pub port:                      u16,
    /// Sprint M: shared-secret API key. None = no auth layer.
    pub api_key:                   Option<String>,
    /// Sprint M: require X-API-Key for write methods (sendrawtransaction).
    pub require_auth_for_writes:   bool,
    /// Sprint M: per-IP read rate limit, requests/minute.
    pub rate_limit_reads_per_min:  u32,
    /// Sprint M: per-IP write rate limit, requests/minute.
    pub rate_limit_writes_per_min: u32,
    /// Sprint M-patch1: also trust RFC1918/ULA ranges as loopback.
    /// Needed when node runs in Docker with default bridge networking.
    /// SECURITY: only set true on trusted single-tenant hosts.
    pub trust_private_ranges:      bool,
    /// R3-audit H-R3-5: browser origins allowed to call this RPC (exact
    /// `scheme://host[:port]` values). Empty (default) = no browser origin is
    /// allowed: no CORS grants are emitted and any request carrying an
    /// `Origin` header is refused. `"*"` allows any origin for READ methods
    /// only — write methods never honour the wildcard.
    pub allowed_origins:           Vec<String>,
    /// R3-audit H-R3-5: extra hostnames accepted in the `Host` header
    /// (anti-DNS-rebinding). IP literals and `localhost` are always accepted;
    /// a reverse-proxy / tunnel hostname must be listed here. `"*"` disables
    /// the check.
    pub allowed_hosts:             Vec<String>,
    /// R3-audit H-R3-5: restore the historical "loopback bypasses auth"
    /// behaviour. Default false: loopback keeps its rate-limit exemption but
    /// must satisfy the same API-key policy as remote callers (a browser on
    /// the operator's machine connects from 127.0.0.1 — the blanket bypass
    /// made every local web page an authenticated operator).
    pub trust_loopback:            bool,
    /// B2-T11 (review): the one forwarding header the reverse proxy in front
    /// of this RPC writes, read for the client address of proxied requests
    /// (`--rpc-proxy-client-header`, lower case; default `x-forwarded-for`,
    /// its last hop). Any other forwarding header only marks the request as
    /// proxied.
    pub proxy_client_header:       String,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            bind_address:              "127.0.0.1".into(),
            port:                      17210,
            api_key:                   None,
            require_auth_for_writes:   false,
            rate_limit_reads_per_min:  60,
            rate_limit_writes_per_min: 5,
            trust_private_ranges:      false,
            allowed_origins:           Vec::new(),
            allowed_hosts:             Vec::new(),
            trust_loopback:            false,
            proxy_client_header:       auth::DEFAULT_PROXY_CLIENT_HEADER.into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    node_state:              Arc<RwLock<NodeState>>,
    store:                   Arc<Storage>,
    mempool:                 Arc<Mempool>,
    dag:                     Arc<RwLock<GhostDAG>>,
    outbound_tx:             mpsc::Sender<NetworkMessage>,
    // Sprint M additions:
    api_key:                 Option<String>,
    require_auth_for_writes: bool,
    // M-1 (audit): `--rpc-require-auth-for-reads` mode. This is a
    // `RpcConfig`/CLI-flag-shaped concern, but the flag parser lives in
    // `main.rs`, which is outside this change's ownership — read directly
    // from the environment instead (see `start_rpc_server` below), matching
    // the same env-var-not-main.rs-touching pattern used for M-6 in
    // `network/mod.rs`. `GNB_RPC_REQUIRE_AUTH_FOR_READS=1` (or `true`)
    // turns it on; unset/anything else leaves the historical
    // "reads are public" default untouched. A future change should promote
    // this to a proper `RpcConfig` field + `--rpc-require-auth-for-reads`
    // CLI flag wired in `main.rs`, mirroring `require_auth_for_writes`.
    require_auth_for_reads:  bool,
    rate_limiter:            Arc<auth::RateLimiterSet>,
    trust_private_ranges:    bool,
    // R3-audit H-R3-5: browser gate + loopback-auth policy + heavy-read bound.
    allowed_origins:         Arc<Vec<String>>,
    allowed_hosts:           Arc<Vec<String>>,
    trust_loopback:          bool,
    heavy_gate:              Arc<HeavyGate>,
    /// L-8: `getblocktemplate`'s own cache and build permit
    /// (`gated_dispatch`), so an analytics scan never answers a miner "busy".
    template_gate:           Arc<HeavyGate>,
    /// One public PQ-PSBT operation; the blocking worker owns its permit.
    pqpsbt_gate:             Arc<tokio::sync::Semaphore>,
    // B5f pool seam: submitblock hook (None = method returns "not wired").
    submit_block:            Option<Arc<SubmitBlockFn>>,
    // NET-12: cancellation flag of THIS request (a fresh flag per request,
    // set when the dispatch timeout fires); long loops check it.
    cancel:                  Arc<std::sync::atomic::AtomicBool>,
    // Audit DAG-6: invalidateblock / reconsiderblock hook.
    chain_admin:             Option<Arc<ChainAdminFn>>,
    /// B1-T4: permits for request bodies above `RPC_MAX_BODY_BYTES` (only
    /// `submitblock` may be that large), `RPC_LARGE_BODY_PERMITS` of them.
    large_bodies:            Arc<tokio::sync::Semaphore>,
    /// B1-T4 (review): `RPC_LARGE_BODY_RESERVED_PERMITS` more, for the
    /// operator's callers only (`read_rpc_body`).
    large_bodies_reserved:   Arc<tokio::sync::Semaphore>,
    /// B2-T11 (review): `RpcConfig::proxy_client_header`.
    proxy_client_header:     Arc<str>,
    /// B1-T10: node-wide verification budget (wire bytes) of transactions
    /// and PoWit items submitted by untrusted callers (`sendrawtransaction`,
    /// `submitpowititem`).
    tx_verify_budget:        Arc<auth::ByteBudget>,
    /// B1-T10: THIS request's caller presented the API key or is a fully
    /// trusted direct caller (set per request, like `cancel`); such callers
    /// are not charged to `tx_verify_budget`.
    caller_trusted:          bool,
    /// POW-3: the node's minimum chain work (`ingress::minimum_chain_work`
    /// at start-up). `getdaginfo` reports it; below it `getblocktemplate`
    /// refuses (initial block download, `ingress::ibd_template_refusal`).
    min_chain_work:          u128,
}

// ─── R3-audit H-R3-5 / L-8: bound the expensive analytics + template RPCs ───
//
// These methods did expensive per-call work. NET-12 (audit): the chain
// statistics, rich list, supply distribution and address count are now
// served from incremental aggregates (`storage::aggregates`) with bounded,
// cancellable work (`analytics::*_bounded`); they stay classed heavy (TTL
// cache + single flight) as defence in depth. Still genuinely heavy: the
// per-address history walk (`getaddressbalance_at_height`, streamed and
// cancellable), and `getblocktemplate` (L-8), which reads the
// DAG twice, walks parent ancestry to derive `bits`, and drains + serialises
// up to 2000 mempool transactions — on a port that, for the analytics
// methods, has no auth and, for loopback/private callers, no rate limit
// either, so a request loop stacks that cost without bound. The bound is
// structural: results are served from a short TTL cache, and at most ONE
// cache-missing computation runs at a time — a second concurrent caller gets
// an immediate "busy" error instead of stacking another full computation.
const HEAVY_READ_METHODS: &[&str] = &[
    "getsupplydistribution",
    "getrichlist",
    "getchainstats",
    "gethashrate",
    "getaddresscount",
    "getaddressbalance_at_height",
    // NET-12: chain-walking explorer reads. Both are now bounded walks of
    // the selected chain (see `explorer::get_difficulty_history` /
    // `explorer::get_block_time_percentiles`) instead of decoding every
    // block body, and additionally share the single-flight TTL cache.
    "getdifficultyhistory",
    "getblocktimepercentiles",
    // VAL-11: the UTXO-set supply audit scans the whole UTXO set and every
    // undo record (cancellable, like Core's gettxoutsetinfo).
    "gettxoutsetinfo",
    // L-8 (audit): `getblocktemplate` is bounded the same way (cache +
    // single flight) but through its OWN gate (`AppState::template_gate`,
    // `gated_dispatch`): sharing this one's single scan permit answered a
    // miner "busy" whenever a public analytics scan was in flight.
];

/// NET-13: every method name `dispatch` implements. Metrics label anything
/// else as `"unknown"`, so a caller cannot mint unbounded Prometheus label
/// values, and logs show at most [`MAX_LOGGED_METHOD_LEN`] bytes of it.
/// `known_methods_list_matches_dispatch` keeps this list in sync.
const KNOWN_RPC_METHODS: &[&str] = &[
    "getnetworkinfo", "getblockcount", "getmempoolinfo", "getblockhash", "getblock",
    "getblockbyheight", "getrecentblocks", "gettransaction", "getrawtransaction", "getbalance",
    "getaddresscount", "getutxos", "sendrawtransaction", "validateaddress", "estimatefee",
    "getrawmempool", "decoderawtransaction", "getblocktemplate", "submitblock", "getdaginfo",
    "submitpowititem", "getpowitinfo", "pqpsbt", "getdescriptorinfo", "deriveaddresses",
    "listtransactions", "getpeerinfo", "getpeers", "getsupplyinfo", "getchainstats",
    "getsupplydistribution", "getselectedchain", "getblockdag", "gettransactionfull",
    "getdagwindow", "getaddresshistory", "getrichlist", "gethashrate", "getdifficultyhistory",
    "getblocktimepercentiles", "gettxstatus", "getaddressinfo", "estimatefeeadvanced",
    "getmempoolstats", "validateaddressverbose", "gettxsbyblock", "getaddressbalance_at_height",
    "getattestation", "invalidateblock", "reconsiderblock", "gettxoutsetinfo",
    "getfinalityinfo", "ignorefinalized", "reconsiderfinalized", "setfinalitycheckpoint",
];

/// Longest method-name prefix written to a log line (NET-13).
const MAX_LOGGED_METHOD_LEN: usize = 48;

/// NET-16: pause before answering a request that failed authentication, so
/// key guessing is slow even from loopback (which skips the rate limiter).
const FAILED_AUTH_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Bounded metrics label for a method name (NET-13).
pub fn method_label(method: &str) -> &'static str {
    KNOWN_RPC_METHODS.iter().copied().find(|m| *m == method).unwrap_or("unknown")
}

/// Log-safe form of a caller-supplied method name: known names verbatim,
/// anything else truncated and debug-escaped (no control characters).
fn method_for_log(method: &str) -> String {
    match KNOWN_RPC_METHODS.iter().find(|m| **m == method) {
        Some(m) => (*m).to_string(),
        None => format!("{:?}", crate::network::truncate_utf8(method, MAX_LOGGED_METHOD_LEN)),
    }
}

/// NET-14: resolve a configured bind address (`127.0.0.1`, `0.0.0.0`,
/// `::1`, `[::1]`, `localhost`) and port into a socket address, with a
/// clear error instead of a failure deep inside the server task.
pub fn resolve_bind_address(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let bare = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    use std::net::ToSocketAddrs;
    (bare, port).to_socket_addrs()
        .map_err(|e| format!("cannot resolve bind address {host:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("bind address {host:?} resolves to nothing"))
}

/// TTL for cached heavy-read results. Analytics freshness of ~1 block is fine.
const HEAVY_READ_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// L-8: how long a `getblocktemplate` result is served while its parents and
/// height are unchanged. A new tip misses the cache at once (`template_cache_key`); a
/// mempool change shows in the template within this time, which bounds the
/// rebuilds a polling miner causes on a busy pool to one per this interval
/// (Bitcoin Core rebuilds on a new tip, and on a mempool change at most every
/// 5 s).
const TEMPLATE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
/// Cap on distinct cached keys (parameterised methods could otherwise grow
/// the map unboundedly — the exact DoS shape this gate exists to close).
const HEAVY_READ_CACHE_MAX_KEYS: usize = 64;
/// Cap on cached templates (`HeavyGate::for_templates`). The template key
/// changes with every new block, so all but the newest entries are dead:
/// with the analytics cap of 64, a node kept up to 63 expired templates of
/// up to about 2 MB each (as JSON) for good. Expired entries are also dropped
/// on every insert; the few left cover two miners asking with different
/// params, or a parent set an invalidation brings back within the TTL.
const TEMPLATE_CACHE_MAX_KEYS: usize = 4;
/// The answer of the analytics gate while its single scan is in flight.
const HEAVY_BUSY: &str = "busy: another heavy analytics scan is in flight; retry shortly";
/// The answer of the template gate while another template is being built.
const TEMPLATE_BUSY: &str = "busy: another getblocktemplate build is in flight; retry shortly";

pub struct HeavyGate {
    ttl:   std::time::Duration,
    /// Most entries kept; expired ones are dropped on every insert, and the
    /// oldest when the map is still full.
    max_keys: usize,
    /// The error text for a caller that finds the permit taken.
    busy:  &'static str,
    cache: parking_lot::Mutex<std::collections::HashMap<String, (std::time::Instant, Value)>>,
    /// Held for the duration of a scan; `try_lock` makes concurrency-1 a hard
    /// bound with no queueing (queueing would just move the pile-up).
    scan:  parking_lot::Mutex<()>,
}

impl HeavyGate {
    /// The analytics gate (`HEAVY_READ_METHODS`): `ttl`, at most
    /// `HEAVY_READ_CACHE_MAX_KEYS` results.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self::with_limits(ttl, HEAVY_READ_CACHE_MAX_KEYS, HEAVY_BUSY)
    }

    /// `getblocktemplate`'s own gate (L-8): `TEMPLATE_CACHE_TTL`, at most
    /// `TEMPLATE_CACHE_MAX_KEYS` templates, and a "busy" answer that names
    /// the template build, not an analytics scan.
    pub fn for_templates() -> Self {
        Self::with_limits(TEMPLATE_CACHE_TTL, TEMPLATE_CACHE_MAX_KEYS, TEMPLATE_BUSY)
    }

    fn with_limits(ttl: std::time::Duration, max_keys: usize, busy: &'static str) -> Self {
        Self {
            ttl,
            max_keys: max_keys.max(1),
            busy,
            cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            scan:  parking_lot::Mutex::new(()),
        }
    }

    pub fn is_heavy(method: &str) -> bool {
        HEAVY_READ_METHODS.contains(&method)
    }

    /// Serve `key` from cache when fresh; otherwise run `f` under the single
    /// scan permit. A caller that can neither hit the cache nor take the
    /// permit gets an error Value immediately (bounded, non-queueing).
    pub fn run<F: FnOnce() -> Value>(&self, key: String, f: F) -> Value {
        let store_key = key.clone();
        self.run_keyed(key, f, move |_| Some(store_key))
    }

    /// [`Self::run`], but a computed result is stored under
    /// `store_key(&result)` (`None`: not stored) instead of under `key`: the
    /// key of what the result was actually computed from, when that can
    /// differ from what `key` was read from (`getblocktemplate`: a block
    /// accepted between reading `key` and the build changes the parents the
    /// template is built on). A hit on a key then only ever returns a result
    /// computed from what the key names.
    pub fn run_keyed<F, K>(&self, key: String, f: F, store_key: K) -> Value
    where
        F: FnOnce() -> Value,
        K: FnOnce(&Value) -> Option<String>,
    {
        let now = std::time::Instant::now();
        if let Some((at, v)) = self.cache.lock().get(&key) {
            if now.duration_since(*at) < self.ttl {
                return v.clone();
            }
        }
        match self.scan.try_lock() {
            Some(_permit) => {
                let v = f();
                // NET-12: never cache a failure (a cancelled or not-ready
                // computation must not answer the next caller for 30 s).
                if v.get("error").is_some() {
                    return v;
                }
                let Some(store_key) = store_key(&v) else { return v };
                let now = std::time::Instant::now();
                let mut cache = self.cache.lock();
                // Expired entries are dead (never served again): drop them on
                // every insert, then the oldest while the map is still full.
                cache.retain(|_, (at, _)| now.duration_since(*at) < self.ttl);
                if !cache.contains_key(&store_key) {
                    while cache.len() >= self.max_keys {
                        let Some(oldest) = cache.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone())
                            else { break };
                        cache.remove(&oldest);
                    }
                }
                cache.insert(store_key, (now, v.clone()));
                v
            }
            None => json!({ "error": self.busy }),
        }
    }
}

/// R3-audit H-R3-5: the CORS layer this server actually mounts.
///
/// Replaces `CorsLayer::permissive()`, which reflected EVERY origin (with
/// methods and headers) and thereby let any web page preflight its way into
/// `sendrawtransaction`. Policy:
///   - empty allowlist (default): `CorsLayer::new()` — no CORS grants at all;
///   - `"*"`: any origin may make CORS requests, but the per-request Origin
///     gate in `handle_rpc` still refuses write methods (wildcard never
///     applies to writes);
///   - otherwise: exactly the listed origins.
/// Credentials are never allowed; the API key travels in explicit headers.
fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::{HeaderValue, Method, header};
    let base = CorsLayer::new()
        .allow_methods([Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::HeaderName::from_static("x-api-key"),
        ]);
    if allowed_origins.is_empty() {
        // No allow-origin is ever emitted; browsers refuse the response.
        CorsLayer::new()
    } else if allowed_origins.iter().any(|o| o == "*") {
        base.allow_origin(tower_http::cors::Any)
    } else {
        let origins: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o.trim_end_matches('/')).ok())
            .collect();
        base.allow_origin(tower_http::cors::AllowOrigin::list(origins))
    }
}

/// The RPC service: one route, the CORS layer, the body limit, the global
/// concurrency limit and the per-request timeout, around [`handle_rpc`].
///
/// P0 RPC hardening (roadmap §1.6 / §4.3): body-size cap, global concurrency
/// limit, and a per-request timeout on top of the existing per-IP
/// auth/rate-limit. R3-audit H-R3-5: the CORS layer is restrictive (see
/// build_cors_layer); Host/Origin are additionally checked per request in
/// handle_rpc.
///
/// B1-T4: `handle_rpc` reads its body itself (`read_rpc_body`), because the
/// limit depends on the method: `RPC_MAX_SUBMITBLOCK_BODY_BYTES` for
/// `submitblock`, `RPC_MAX_BODY_BYTES` for everything else. The
/// `DefaultBodyLimit` below is the outer bound for any body extractor.
fn build_router(app_state: AppState, allowed_origins: &[String]) -> Router {
    Router::new()
        .route("/", post(handle_rpc))
        .layer(build_cors_layer(allowed_origins))
        .layer(DefaultBodyLimit::max(RPC_MAX_SUBMITBLOCK_BODY_BYTES))
        .layer(GlobalConcurrencyLimitLayer::new(RPC_MAX_CONCURRENCY))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS)))
        .with_state(app_state)
}

#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    config:      RpcConfig,
    state:       Arc<RwLock<NodeState>>,
    store:       Arc<Storage>,
    mempool:     Arc<Mempool>,
    dag:         Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    // B5f pool seam — see `SubmitBlockFn`.
    submit_block: Option<Arc<SubmitBlockFn>>,
    // Audit DAG-6 — see `ChainAdminFn`.
    chain_admin: Option<Arc<ChainAdminFn>>,
) {
    // NET-14: `format!("{host}:{port}")` could not express IPv6 hosts such as
    // `::1`; resolve explicitly and report a bad address clearly. main.rs
    // validates the same way at start-up, before the node starts.
    let addr = match resolve_bind_address(&config.bind_address, config.port) {
        Ok(a) => a,
        Err(e) => {
            error!("RPC: {}; the RPC service is not running (the node keeps running)", e);
            return;
        }
    };

    // L-6 (audit): validate the configured key BEFORE it is ever compared
    // against anything, regardless of how the caller sourced it
    // (`--rpc-api-key` directly, or `--rpc-api-key-file` read by main.rs).
    // Nothing previously prevented `--rpc-api-key x` (a one-character
    // "secret" the constant-time comparison then faithfully protects) or a
    // key containing control characters (a header-injection primitive
    // wherever it is later interpolated into raw text — see `bin/gnb-cli.rs`'s
    // M-11 fix). Refuse to start the RPC service on an invalid key rather
    // than silently running with one that provides no real protection, or
    // silently treating it as "no key" (which would DISABLE auth instead).
    if let Some(k) = &config.api_key {
        if let Err(reason) = auth::validate_api_key(k) {
            error!("RPC: configured API key is invalid ({}); refusing to start the RPC service. \
                    Fix --rpc-api-key / --rpc-api-key-file and restart.", reason);
            return;
        }
    }

    let rate_limiter = Arc::new(auth::RateLimiterSet::new(
        config.rate_limit_reads_per_min,
        config.rate_limit_writes_per_min,
    ));

    // M-1: see the field doc on `AppState::require_auth_for_reads`.
    let require_auth_for_reads = std::env::var("GNB_RPC_REQUIRE_AUTH_FOR_READS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_auth_for_reads && config.api_key.is_none() {
        // Fail-safe, loudly: the auth layer itself refuses every
        // non-trusted read in this configuration (see
        // `auth::authorize_with_read_policy`'s fail-safe doc), but an
        // operator who set the flag almost certainly meant to configure a
        // key too — say so instead of silently locking the RPC surface.
        log::warn!(
            "GNB_RPC_REQUIRE_AUTH_FOR_READS is set but no --rpc-api-key is \
             configured: every non-trusted read will be refused (fail-safe, \
             not a bug) until a key is configured"
        );
    }

    let app_state = AppState {
        node_state: state,
        store,
        mempool,
        dag,
        outbound_tx,
        api_key:                 config.api_key.clone(),
        require_auth_for_writes: config.require_auth_for_writes,
        require_auth_for_reads,
        rate_limiter,
        trust_private_ranges:    config.trust_private_ranges,
        allowed_origins:         Arc::new(config.allowed_origins.clone()),
        allowed_hosts:           Arc::new(config.allowed_hosts.clone()),
        trust_loopback:          config.trust_loopback,
        heavy_gate:              Arc::new(HeavyGate::new(HEAVY_READ_CACHE_TTL)),
        template_gate:           Arc::new(HeavyGate::for_templates()),
            pqpsbt_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        submit_block,
        cancel:                  Arc::new(std::sync::atomic::AtomicBool::new(false)),
        chain_admin,
        large_bodies:            Arc::new(tokio::sync::Semaphore::new(RPC_LARGE_BODY_PERMITS)),
        large_bodies_reserved:   Arc::new(tokio::sync::Semaphore::new(RPC_LARGE_BODY_RESERVED_PERMITS)),
        proxy_client_header:     match auth::validate_proxy_client_header(&config.proxy_client_header) {
            Ok(h) => h.into(),
            Err(e) => {
                log::error!("{e}; using {}", auth::DEFAULT_PROXY_CLIENT_HEADER);
                auth::DEFAULT_PROXY_CLIENT_HEADER.into()
            }
        },
        tx_verify_budget:        Arc::new(auth::ByteBudget::new(ANON_TX_VERIFY_BURST_BYTES, ANON_TX_VERIFY_BYTES_PER_SEC)),
        caller_trusted:          false,
        min_chain_work:          crate::ingress::minimum_chain_work(),
    };

    let app = build_router(app_state, &config.allowed_origins);

    info!("RPC on {} (auth={}, require_auth_writes={}, trust_private={}, trust_loopback={}, origins={:?}, hosts={:?}, limits: {}r/min, {}w/min)",
        addr,
        config.api_key.is_some(),
        config.require_auth_for_writes,
        config.trust_private_ranges,
        config.trust_loopback,
        config.allowed_origins,
        config.allowed_hosts,
        config.rate_limit_reads_per_min,
        config.rate_limit_writes_per_min,
    );
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l)  => l,
        Err(e) => {
            error!("RPC bind {} failed: {}; the RPC service is not running (the node keeps running)", addr, e);
            return;
        }
    };
    // Sprint M: connect_info makes the client IP available to handlers.
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    ).await {
        error!("RPC error: {}", e);
    }
}

/// L-5 (audit): storage errors used to be returned to RPC callers verbatim
/// (`json!({ "error": e.to_string() })`) at every one of this file's ~13
/// `state.store.*` call sites. `StorageError::ReadFailed` / `OpenFailed` /
/// `WriteFailed` wrap the underlying RocksDB error message
/// (`storage/mod.rs`'s `From<rocksdb::Error>` / explicit `.map_err`s), which
/// can include filesystem paths and column-family/engine internals — none of
/// which an unauthenticated caller (see M-1: reads are public by default) has
/// any business receiving. INVARIANT (L-5): the detail is logged
/// server-side, at a level an operator will see; the caller gets a stable,
/// content-free error code and message, identical across every storage
/// failure mode so nothing about the underlying condition leaks through
/// message shape either.
/// L-10 (audit): max bytes an echoed JSON-RPC `id` string may occupy in the
/// response. JSON-RPC 2.0 ids are meant to be short correlation tokens, not
/// payload; nothing legitimate needs anywhere near this much.
const MAX_ECHOED_ID_LEN: usize = 256;

/// L-10: normalize the request's `id` to a shape and size safe to echo back
/// unconditionally. A string is truncated (UTF-8-safely — see
/// `network::truncate_utf8`) rather than rejected outright, so a client
/// using a slightly-too-long-but-otherwise-legitimate correlation id still
/// gets a response, just a truncated echo of what it sent (a client cannot
/// reasonably rely on more than JSON-RPC 2.0 itself promises, which is
/// "echo the id", not "echo it losslessly at any length"). A `bool`,
/// `array`, or `object` id is not spec-compliant at all and is replaced with
/// `null` rather than echoed.
/// L-11 (audit): the JSON-RPC 2.0 error body for an unsupported batch
/// (top-level JSON array) request. Extracted so the exact code/shape is
/// unit-testable without constructing axum extractors.
fn batch_not_supported_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id":      Value::Null,
        "error":   { "code": -32600, "message": "Invalid Request: batch requests are not supported" },
    })
}

fn cap_echoed_id(id: Value) -> Value {
    match id {
        Value::String(s) => {
            Value::String(crate::network::truncate_utf8(&s, MAX_ECHOED_ID_LEN).to_string())
        }
        v @ (Value::Number(_) | Value::Null) => v,
        _ => Value::Null,
    }
}

/// Current Unix time in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// MEM-6: the node's transaction relay policy, as reported by
/// `getmempoolinfo` (normative text: docs/MEMPOOL.md).
fn mempool_policy_json() -> Value {
    use crate::mempool as m;
    json!({
        "replacement": "full-rbf: a conflicting transaction replaces pooled ones iff it adds no new unconfirmed input, \
                        pays a higher fee rate than each direct conflict, an absolute fee >= the sum of every evicted \
                        transaction's fee plus the incremental relay fee on its own size, and evicts at most \
                        max_replacement_evictions transactions (BIP125 rules 2-6, no signalling)",
        "max_replacement_evictions": m::MAX_REPLACEMENT_EVICTIONS,
        "incremental_relay_fee_sat_per_byte": m::INCREMENTAL_RELAY_FEE_RATE,
        "min_relay_fee_sat_per_byte": m::MIN_RELAY_FEE_RATE,
        "unconfirmed_chains": true,
        "max_ancestors": m::MAX_ANCESTORS,
        "max_descendants": m::MAX_DESCENDANTS,
        "max_package_bytes": m::MAX_PACKAGE_BYTES,
        "block_template_selection": "ancestor-package fee rate (child pays for parent)",
        "orphan_pool": {
            "max_transactions": m::orphanage::MAX_ORPHAN_TXS,
            "max_bytes": m::orphanage::MAX_ORPHAN_BYTES,
            "max_per_peer": m::orphanage::MAX_ORPHANS_PER_PEER,
            "max_bytes_per_peer": m::orphanage::MAX_ORPHAN_BYTES_PER_PEER,
            "expiry_secs": m::orphanage::ORPHAN_EXPIRY_SECS,
            "max_inputs": m::orphanage::MAX_ORPHAN_INPUTS,
            "keyed_by": "wtxid; quotas per delivering connection",
        },
        "signature_budget": {
            "keyed_by": "delivering connection (gossip propagation_source)",
            "burst_input_signatures": m::relay::SIG_BUDGET_BURST,
            "refill_per_sec": m::relay::SIG_BUDGET_REFILL_PER_SEC,
            "refunded_on_admission": true,
        },
        "expiry_secs": m::MEMPOOL_EXPIRY_SECS,
        "max_tx_bytes": m::MAX_TX_SIZE,
    })
}

fn storage_err_response(e: &StorageError) -> Value {
    log::warn!("rpc: storage error (detail withheld from caller): {}", e);
    json!({ "error": "internal storage error", "code": "STORAGE_ERROR" })
}

/// The response for a failed explorer statistic: a storage failure gets the
/// sanitised L-5 response (its detail only reaches the log); cancellation,
/// not-ready and no-tip keep their plain message (HeavyGate never caches
/// any of them).
fn stats_err_response(e: &crate::analytics::StatsError) -> Value {
    match e {
        crate::analytics::StatsError::Storage(se) => storage_err_response(se),
        other => json!({ "error": other.to_string() }),
    }
}

/// `gettxoutsetinfo` (audit VAL-11): the supply audit as JSON; amounts are
/// decimal strings of base units (they can exceed 2^53).
fn utxo_audit_json(a: &crate::storage::utxo_audit::UtxoSetAudit) -> Value {
    json!({
        "height":               a.height,
        "bestblock":            a.best_block.map(hex::encode),
        "txouts":               a.txouts,
        "total_amount_sat":     a.total_sat.to_string(),
        "hash_serialized":      hex::encode(a.hash_serialized),
        "hash_type":            "sha3-256 over the UTXO rows in key order, domain gnb/utxo-set/v1",
        "undecodable_txouts":   a.undecodable,
        "applied_blocks":       a.applied_blocks,
        "undo_off_chain":       a.undo_off_chain,
        "chain_without_undo":   a.chain_without_undo,
        "chain_ok":             a.chain_ok(),
        "expected": {
            "carryover_sat":        a.genesis_ledger.carryover_sat.to_string(),
            "locked_sat":           a.genesis_ledger.locked_sat.to_string(),
            "subsidy_sat":          a.subsidy_sat.to_string(),
            "max_supply_sat":       a.max_supply_sat().to_string(),
            "schedule_issued_sat":  a.schedule_issued_sat.to_string(),
        },
        "unclaimed_sat":        a.unclaimed_sat().map(|u| u.to_string()),
        "supply_ok":            a.supply_ok(),
        "aggregates": {
            "scan_txouts":          a.holder_txouts,
            "scan_amount_sat":      a.holder_total_sat.to_string(),
            "maintained_txouts":    a.maintained.map(|m| m.0),
            "maintained_amount_sat": a.maintained.map(|m| m.1.to_string()),
            "ok":                   a.aggregates_ok(),
        },
        "ok":                   a.ok(),
        "note": "max_supply_sat = carryover + locked team and founder allocations + the subsidy of every applied block; unclaimed_sat = max_supply_sat - total_amount_sat is unspendable value (unclaimed rewards, unissued witness-share slots from the PoWit activation, the shielded pool), never negative unless the set holds value that was not issued; aggregates compares the scan with the maintained address aggregates. See docs/RUNNING.md",
    })
}

/// Height of the selected tip — the number a confirmation count is relative to.
///
/// # Why this exists as a function
///
/// Three call sites computed confirmations as `node_state.block_count - height`,
/// subtracting a block's **height** from the DAG's **block count**. In a chain
/// those two numbers are the same and the bug is invisible; in a BlockDAG they
/// are not, because parallel blocks are kept rather than orphaned. Measured on
/// mainnet 2026-08-13: chain height 39,837, DAG block count 50,606 — an offset
/// of 10,769.
///
/// The consequence was not a cosmetic off-by-N. `gettxstatus` calls anything
/// with 100+ confirmations `final`, so **every mined transaction reported
/// final immediately**, and an exchange gating deposits on that field would
/// have credited at depth 1 while believing it waited. The failure was silent
/// and in the direction that costs the integrator money.
///
/// One definition, called three times — not three call sites each free to pick
/// a plausible-looking counter.
fn selected_tip_height(state: &AppState) -> u64 {
    let dag = state.dag.read();
    dag.selected_tip()
        .and_then(|h| dag.get_block_data(&h).map(|d| d.height))
        .unwrap_or(0)
}

/// Cache key of a `getblocktemplate` call: its params, and the parents and
/// header height the template would be built on
/// (`template::template_parents_and_height`, the template builder's own
/// choice), so anything that changes them misses the cache at once: a new
/// block, an `invalidateblock` / `reconsiderblock` (DAG-6: the tip SET is
/// unchanged, only which tips are valid), a parent's body arriving (a
/// header-only tip is not an eligible parent). The template's bits, blue
/// score, subsidy and UTXO view are functions of the parents and height.
/// Keyed by params alone, a template was served for up to 30 s after a new
/// block: parents a block behind, so an external miner kept building forks of
/// the tip (test/functional/mining_getblocktemplate_submitblock.py). Mempool
/// changes are not in the key: they show in the template within
/// `TEMPLATE_CACHE_TTL` (a pool-digest key missed on every admission, so a
/// miner polling a busy pool rebuilt the template on every call, and
/// computing the digest copied every pool txid).
///
/// This is the LOOKUP key, read under `dag.read()` only, before the build.
/// The builder takes the acceptance lock and chooses the parents again, so a
/// block accepted in between gives a template on other parents. A template
/// is therefore stored under the key of the parents and height it carries
/// ([`template_result_key`]), which equals this one only when nothing
/// changed in between.
fn template_cache_key(params: Option<&Value>, state: &AppState) -> String {
    let (parents, height) = {
        let dag = state.dag.read();
        crate::template::template_parents_and_height(&dag, &state.store)
    };
    template_cache_key_for(params, parents.iter().map(|p| p.as_slice()), height)
}

/// The template cache key of `params` and a template on `parents` (in
/// template order) at header `height`.
fn template_cache_key_for<'a>(params: Option<&Value>, parents: impl IntoIterator<Item = &'a [u8]>, height: u64) -> String {
    use sha3::{Digest as _, Sha3_256};
    // Order kept: the first parent is the template's selected parent.
    let mut h = Sha3_256::new();
    for p in parents {
        h.update(p);
    }
    format!("getblocktemplate|{}|parents={}|height={}",
        params.map(|p| p.to_string()).unwrap_or_default(), hex::encode(h.finalize()), height)
}

/// The key a built template is stored under: the `parents` and `height` it
/// was built on (its own fields), so a cache hit on a key only ever returns
/// a template on the parents that key names. Keyed by the lookup key, a
/// template built on a block X accepted during the build was stored under
/// the key of the parents before X, and after an `invalidateblock X` brought
/// those parents back, the next call within `TEMPLATE_CACHE_TTL` was served
/// a template on the invalidated X. `None` (not stored) for anything that is
/// not a template.
fn template_result_key(params: Option<&Value>, template: &Value) -> Option<String> {
    let parents = template.get("parents")?.as_array()?.iter()
        .map(|p| p.as_str().and_then(|h| hex::decode(h).ok()))
        .collect::<Option<Vec<Vec<u8>>>>()?;
    let height = template.get("height")?.as_u64()?;
    Some(template_cache_key_for(params, parents.iter().map(Vec::as_slice), height))
}

/// Run one dispatch `f` behind the bound its method needs (L-8 / H-R3-5):
/// `getblocktemplate` through its own gate (looked up by `template_cache_key`,
/// stored by `template_result_key`, `TEMPLATE_CACHE_TTL`,
/// `TEMPLATE_CACHE_MAX_KEYS`), the heavy analytics reads through the HeavyGate
/// (method|params key, `HEAVY_READ_CACHE_TTL`), everything else directly.
/// Separate gates: a public analytics scan holding the HeavyGate's single
/// permit must not answer a miner's template request "busy".
fn gated_dispatch<F: FnOnce() -> Value>(method: &str, params: Option<&Value>, state: &AppState, f: F) -> Value {
    if method == "getblocktemplate" {
        state.template_gate.run_keyed(template_cache_key(params, state), f,
            |template| template_result_key(params, template))
    } else if method == "gettxoutsetinfo" {
        // VAL-11: the supply audit shares the heavy gate (single flight, TTL
        // cache) but is keyed by the applied tip it describes, looked up by
        // the tip now and stored by the result's `bestblock`: an answer is
        // never served after a block was connected or disconnected.
        let key = |tip: Option<&str>| format!("gettxoutsetinfo|{}", tip.unwrap_or("-"));
        let now = state.store.get_meta("tip_hash").ok().flatten().map(hex::encode);
        state.heavy_gate.run_keyed(key(now.as_deref()), f, move |v| Some(key(v["bestblock"].as_str())))
    } else if HeavyGate::is_heavy(method) {
        let key = format!("{}|{}", method, params.map(|p| p.to_string()).unwrap_or_default());
        state.heavy_gate.run(key, f)
    } else {
        f()
    }
}

/// A transport-level JSON-RPC error response.
fn rpc_transport_error(status: StatusCode, code: i64, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": code, "message": message } })))
}

/// Read and parse a request body under the B1-T4 limits. A body grows past
/// `RPC_MAX_BODY_BYTES` only under one of the `RPC_LARGE_BODY_PERMITS`
/// permits (taken up front when the declared length is larger, else when the
/// stream crosses the cap), and never past `RPC_MAX_SUBMITBLOCK_BODY_BYTES`;
/// once parsed, only `submitblock` may keep a body above
/// `RPC_MAX_BODY_BYTES`. Returns the request and the permit (held until the
/// request is answered). `operator` (the caller presented the API key, or is
/// a direct loopback / trusted-range caller, known from the headers alone)
/// may also take one of the `RPC_LARGE_BODY_RESERVED_PERMITS` when the
/// shared ones are all held, so anonymous slow uploads cannot lock the
/// operator's miner out of full-block `submitblock` (B1-T4 review).
async fn read_rpc_body(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    body: axum::body::Body,
    operator: bool,
) -> Result<(Value, Option<tokio::sync::OwnedSemaphorePermit>), (StatusCode, Json<Value>)> {
    // Same media-type rule as axum's `Json` extractor, which this replaces.
    let json_type = headers.get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|m| {
            let m = m.trim().to_ascii_lowercase();
            m == "application/json" || (m.starts_with("application/") && m.ends_with("+json"))
        })
        .unwrap_or(false);
    if !json_type {
        return Err(rpc_transport_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, -32600,
            "Invalid Request: expected `Content-Type: application/json`"));
    }
    let declared = headers.get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    let too_large = || rpc_transport_error(StatusCode::PAYLOAD_TOO_LARGE, -32600,
        "Invalid Request: body too large (submitblock: 4 MiB, other methods: 1 MiB)");
    if declared.is_some_and(|n| n > RPC_MAX_SUBMITBLOCK_BODY_BYTES as u64) {
        return Err(too_large());
    }
    let take_permit = || state.large_bodies.clone().try_acquire_owned()
        .or_else(|e| if operator { state.large_bodies_reserved.clone().try_acquire_owned() } else { Err(e) })
        .map_err(|_| rpc_transport_error(
            StatusCode::SERVICE_UNAVAILABLE, -32005, "busy: too many large requests in flight; retry shortly"));
    let mut permit = match declared {
        Some(n) if n > RPC_MAX_BODY_BYTES as u64 => Some(take_permit()?),
        _ => None,
    };
    let mut bytes: Vec<u8> = Vec::with_capacity(declared.unwrap_or(0).min(RPC_MAX_BODY_BYTES as u64) as usize);
    let mut stream = body.into_data_stream();
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
        let chunk = chunk.map_err(|_| rpc_transport_error(StatusCode::BAD_REQUEST, -32600,
            "Invalid Request: the body could not be read"))?;
        let len = bytes.len().saturating_add(chunk.len());
        if len > RPC_MAX_SUBMITBLOCK_BODY_BYTES {
            return Err(too_large());
        }
        if len > RPC_MAX_BODY_BYTES && permit.is_none() {
            permit = Some(take_permit()?);
        }
        bytes.extend_from_slice(&chunk);
    }
    let req: Value = serde_json::from_slice(&bytes).map_err(|_| rpc_transport_error(
        StatusCode::BAD_REQUEST, -32700, "Parse error: the body is not valid JSON"))?;
    if bytes.len() > RPC_MAX_BODY_BYTES && req.get("method").and_then(Value::as_str) != Some("submitblock") {
        return Err(too_large());
    }
    Ok((req, permit))
}

async fn handle_rpc(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> (StatusCode, Json<Value>) {
    let client_ip = addr.ip();
    let presented_key = auth::extract_api_key(&headers);
    // B2-T11: a request that came through a reverse proxy (forwarding
    // headers) is a remote request whatever its TCP peer: rate-limited per
    // the client the proxy names (when the peer is a proxy) and never fully
    // trusted.
    let forwarded = auth::forwarded_client(&headers, &state.proxy_client_header);
    // B1-R2-9: the method is in the untrusted body and operator status
    // requires hashing a key. Bound both before doing either operation.
    if !auth::admit_before_auth(client_ip, forwarded, state.trust_private_ranges, &state.rate_limiter) {
        crate::metrics::inc_rpc_request("unknown", "rate_limited");
        return rpc_transport_error(StatusCode::TOO_MANY_REQUESTS, -32002,
            "rate limit exceeded; retry after a minute");
    }
    // B1-T4: the body limit depends on the method (`read_rpc_body`); the
    // operator's callers (known from the headers) have reserved permits.
    let operator = matches!((presented_key, state.api_key.as_deref()), (Some(p), Some(c)) if auth::keys_match(p, c))
        || (forwarded.is_none() && auth::is_trusted_local_ip(client_ip, state.trust_private_ranges));
    let (req, _large_body_permit) = match read_rpc_body(&state, &headers, body, operator).await {
        Ok(r) => r,
        Err(refusal) => {
            crate::metrics::inc_rpc_request("unknown", "invalid_request");
            log::info!("rpc denied ip={} reason=body status={}", addr.ip(), refusal.0);
            return refusal;
        }
    };
    // L-11 (audit): a top-level JSON ARRAY (a JSON-RPC 2.0 batch request,
    // which this server does not implement) used to fall through silently:
    // `req["method"]` on a `Value::Array` indexes to `Null` (the `&str`
    // `Index` impl only matches objects), so `method` became the empty
    // string and dispatch's catch-all returned `"unknown method: "` with
    // HTTP 200 — a standards-conformant client sees a "success" response
    // that is actually nonsensical. Detect the shape explicitly and answer
    // with the JSON-RPC 2.0 code for it.
    if req.is_array() {
        crate::metrics::inc_rpc_request("batch", "invalid_request");
        log::info!("rpc denied ip={} reason=batch_request_unsupported", addr.ip());
        return (StatusCode::BAD_REQUEST, Json(batch_not_supported_response()));
    }

    let method = req["method"].as_str().unwrap_or("");
    // NET-13: bounded label for metrics/spans, truncated form for logs.
    let label = method_label(method);
    let method_log = method_for_log(method);
    // L-10 (audit): the `id` used to be echoed back completely unbounded —
    // a ~1 MiB `id` string in the request produced a ~1 MiB response, at
    // zero cost to the attacker and real memory pressure for the node.
    // JSON-RPC 2.0 itself expects `id` to be a string, number, or null;
    // `cap_echoed_id` enforces exactly that shape and bounds the string case.
    let id     = cap_echoed_id(req.get("id").cloned().unwrap_or(json!(null)));
    let params = req.get("params");

    // R3-audit H-R3-5: Host + Origin gate BEFORE auth/rate-limit. Refuses
    // DNS-rebinding (hostile hostname in Host) and browser-borne CSRF (an
    // Origin the operator did not allowlist; wildcard never covers writes).
    let host_hdr   = headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok());
    let origin_hdr = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok());
    if let Err(refusal) = auth::gate_browser_request(
        host_hdr,
        origin_hdr,
        method,
        &state.allowed_hosts,
        &state.allowed_origins,
    ) {
        crate::metrics::inc_rpc_request(label, "forbidden");
        log::info!("rpc denied ip={} method={} reason={:?} host={:?} origin={:?}",
            client_ip, method_log, refusal,
            host_hdr.map(|h| crate::network::truncate_utf8(h, 128)),
            origin_hdr.map(|o| crate::network::truncate_utf8(o, 128)));
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "jsonrpc": "2.0",
                "id":      id,
                "error":   { "code": -32003, "message": "forbidden: request refused by Host/Origin policy" },
            })),
        );
    }

    let decision = auth::authorize_admitted_request(
        client_ip,
        forwarded,
        method,
        presented_key,
        state.api_key.as_deref(),
        state.require_auth_for_writes,
        state.require_auth_for_reads || method == "pqpsbt",
        state.trust_private_ranges && method != "pqpsbt",
        state.trust_loopback && method != "pqpsbt",
        &state.rate_limiter,
    );

    match decision {
        auth::AuthDecision::Allow => {
            let start = std::time::Instant::now();
            // P1 (roadmap §2): per-request tracing span, correlated with the
            // existing `rpc_requests{method,status}` metric so a slow method is
            // traceable to a client. `.instrument()` (not an entered guard) is
            // the correct form across the `dispatch` await. Inert unless a
            // subscriber is installed (init lives in main.rs, not owned here).
            use tracing::Instrument;
            // The dispatch arms below do their work INLINE and BLOCKING:
            // parking_lot acquisitions on `node_state`/`dag` and synchronous
            // RocksDB reads, none of which yield. Running that directly on a
            // tokio worker means a writer holding `node_state` (main.rs:2303,
            // :2352, :2910, :3080) parks the worker for as long as it holds the
            // lock. With `#[tokio::main]` defaulting worker_threads to the core
            // count — 2 on the production box — two stalled requests park the
            // WHOLE runtime, so it stops accepting connections at all.
            //
            // Measured on the producer, 2026-08-09: getblockcount took 30.01s
            // and 20.42s back to back while createauxblock returned in 0.01s.
            // The pool proxy times out at 10s and retries ~1/s, so the accept
            // queue filled (129 pending against a backlog of 128) and the node
            // never recovered on its own — only a restart cleared it, which is
            // why a watchdog was papering over this.
            //
            // Hand the whole dispatch to the blocking pool so worker threads
            // stay free to accept and poll. `block_on` is legal here precisely
            // because a spawn_blocking thread is not a runtime worker.
            // NET-12: a cancellation flag per request; the inner timeout
            // below sets it, and every long loop of a heavy method checks
            // it, so a timed-out scan stops instead of running on.
            let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut d_state = state.clone();
            d_state.cancel = cancel.clone();
            d_state.caller_trusted = auth::caller_is_trusted(
                client_ip,
                forwarded,
                presented_key,
                state.api_key.as_deref(),
                state.trust_private_ranges,
                state.trust_loopback,
            );
            let d_method = method.to_string();
            let d_params = params.cloned();
            let d_handle = tokio::runtime::Handle::current();
            let join_handle = tokio::task::spawn_blocking(move || {
                // R3-audit H-R3-5 / L-8: heavy O(chain) analytics reads and
                // getblocktemplate go through their gates — TTL cache + at
                // most one computation in flight per gate.
                gated_dispatch(&d_method, d_params.as_ref(), &d_state, || {
                    d_handle.block_on(dispatch(&d_method, d_params.as_ref(), &d_state))
                })
            });
            // L-9 (audit): the outer `TimeoutLayer` (tower-http) previously
            // was the ONLY thing standing between a stuck dispatch and a
            // permanently-occupied blocking-pool slot — and it drops the
            // RESPONSE future, which drops the `JoinHandle` value inline
            // above without ever calling `.abort()`. Dropping a
            // `tokio::task::JoinHandle` does NOT cancel the task it points
            // to: for `spawn_blocking`, the closure keeps running on its
            // blocking thread to completion regardless, so a timed-out
            // `getsupplydistribution` (H-6) kept loading the chain while a
            // fresh request was admitted in its place — the exact
            // "watchdog is papering over an unbounded background cost"
            // shape this file's own comments elsewhere warn about.
            //
            // Fix: race the dispatch against an INNER timeout, strictly
            // shorter than the outer `RPC_REQUEST_TIMEOUT_SECS`, so this
            // arm — not the outer layer's unconditional drop — is what
            // decides the outcome and can act on it. `abort_handle()` is
            // taken before the handle is consumed by `.instrument()` below,
            // so it stays independently usable to cancel from the other
            // `select!` arm.
            //
            // HONESTY: `.abort()` on an ALREADY-RUNNING blocking closure
            // cannot preempt it mid-execution (the OS thread runs the
            // closure to completion regardless — this is a `spawn_blocking`
            // limitation, not a bug in this fix); the queued case is where
            // this has full effect: a task that has not yet started
            // executing on the blocking pool is guaranteed to never run at
            // all once aborted. Either way, THIS request's response path
            // returns immediately at the inner deadline instead of holding
            // the connection until the outer layer's drop.
            let abort_handle = join_handle.abort_handle();
            let result = tokio::select! {
                r = join_handle.instrument(tracing::info_span!(
                    "rpc_request",
                    method = label,
                    client_ip = %client_ip,
                    id = %id,
                )) => {
                    r.unwrap_or_else(|e| {
                        log::error!("rpc dispatch task failed: {}", e);
                        json!({ "error": "internal dispatch failure" })
                    })
                }
                _ = tokio::time::sleep(DISPATCH_INNER_TIMEOUT) => {
                    abort_handle.abort();
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    log::warn!(
                        "rpc dispatch timed out for method={} ip={} after {:?}; aborted \
                         (queued work is cancelled; already-running work finishes in the \
                         background but this response does not wait for it)",
                        method_log, client_ip, DISPATCH_INNER_TIMEOUT
                    );
                    json!({ "error": "internal dispatch timeout" })
                }
            };
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_millis();
            crate::metrics::observe_rpc_latency(label, elapsed.as_secs_f64());
            crate::metrics::inc_rpc_request(label, "ok");
            log::debug!("rpc ok ip={} method={} took={}ms", client_ip, method_log, elapsed_ms);
            (
                StatusCode::OK,
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
            )
        }
        auth::AuthDecision::Unauthorized => {
            crate::metrics::inc_rpc_request(label, "unauthorized");
            log::info!("rpc denied ip={} method={} reason=unauthorized", client_ip, method_log);
            // NET-16: slow down key guessing (async sleep: no worker blocked).
            tokio::time::sleep(FAILED_AUTH_DELAY).await;
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id":      id,
                    "error":   { "code": -32001, "message": "unauthorized: valid X-API-Key required" },
                })),
            )
        }
        auth::AuthDecision::RateLimited => {
            crate::metrics::inc_rpc_request(label, "rate_limited");
            log::info!("rpc denied ip={} method={} reason=rate_limited", client_ip, method_log);
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id":      id,
                    "error":   { "code": -32002, "message": "rate limit exceeded; retry after a minute" },
                })),
            )
        }
    }
}

/// `invalidateblock` / `reconsiderblock` / `ignorefinalized` /
/// `reconsiderfinalized` / `setfinalitycheckpoint`: params `[block_hash_hex]`
/// (`ignorefinalized` without one: the current finality pin;
/// `setfinalitycheckpoint` also takes `none` or `default`, or a second
/// parameter, the block's DAG height, for a block the node may not hold
/// yet: a weak-subjectivity checkpoint set before syncing).
fn chain_admin_call(op: ChainAdminOp, params: Option<&Value>, state: &AppState) -> Value {
    let hex_str = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
    let op = match (op, params.and_then(|p| p.get(1))) {
        (ChainAdminOp::SetFinalityCheckpoint, Some(h)) => {
            match h.as_u64().or_else(|| h.as_str().and_then(|s| s.trim().parse::<u64>().ok())) {
                Some(height) => ChainAdminOp::SetFinalityCheckpointAt(height),
                None => return json!({ "error": "the second parameter is the block's DAG height (a number)" }),
            }
        }
        (op, _) => op,
    };
    let (op, hex_str) = match (op, hex_str) {
        (ChainAdminOp::SetFinalityCheckpoint, "none") => (ChainAdminOp::DisableFinalityCheckpoint, None),
        (ChainAdminOp::SetFinalityCheckpoint, "default") => (ChainAdminOp::DefaultFinalityCheckpoint, None),
        (ChainAdminOp::IgnoreFinalized, "") => match state.dag.read().finalized() {
            Some((h, _)) => (op, Some(hex::encode(h))),
            None => return json!({ "error": "this node has no finality pin; name a block hash" }),
        },
        (op, s) => (op, Some(s.to_string())),
    };
    let hash: [u8; 32] = match hex_str {
        None => [0u8; 32],
        Some(s) => match hex::decode(&s).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
            Some(h) => h,
            None => return json!({ "error": "expected one parameter: a 64-hex-character block hash" }),
        },
    };
    match &state.chain_admin {
        None => json!({ "error": "invalidateblock/reconsiderblock not wired on this node" }),
        Some(hook) => match hook(op, hash) {
            Ok(v) => v,
            Err(e) => json!({ "error": e }),
        },
    }
}

/// Public PQ-PSBT work is limited independently of the core's offline limits.
/// Three verification passes in finalization yield at most 48 partial-signature
/// checks. The gate is held by the blocking worker until it actually finishes;
/// a response timeout does not admit replacement work while it keeps running.
const PQPSBT_RPC_MAX_INPUTS: usize = 4;
const PQPSBT_RPC_MAX_SIGNATURES: usize = 16;
const POLICY_SELECTED_INPUTS_MAX: usize = 64;

fn selected_policy_outpoints(params: Option<&Value>)
    -> Result<Option<std::collections::BTreeSet<([u8;32],u32)>>, String>
{
    let Some(value) = params.and_then(|p| p.get(2)) else { return Ok(None); };
    let rows = value.as_array().ok_or("selected outpoints must be an array")?;
    if rows.len() > POLICY_SELECTED_INPUTS_MAX { return Err("at most 64 selected outpoints are allowed".into()); }
    let mut selected = std::collections::BTreeSet::new();
    for row in rows {
        let object = row.as_object().ok_or("selected outpoint must be an object")?;
        if object.len() != 2 { return Err("selected outpoint needs exactly txid and index".into()); }
        let txid = row.get("txid").and_then(Value::as_str).filter(|s| s.len() == 64)
            .and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok())
            .ok_or("selected txid must be 32-byte hex")?;
        let index = row.get("index").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok())
            .ok_or("selected index must fit u32")?;
        if !selected.insert((txid,index)) { return Err("duplicate selected outpoint".into()); }
    }
    Ok(Some(selected))
}

/// A short reference read, never held during signature checks or row reads.
/// Admission's selected-depth helpers use the applied storage tip; require
/// that it agrees with the DAG tip reported by getdaginfo before exposing it.
fn policy_rpc_snapshot(state: &AppState) -> Result<(u64,[u8;32]), Value> {
    let dag = state.dag.read();
    let tip = dag.selected_tip().ok_or_else(|| json!({"error":"node has no selected tip"}))?;
    let applied = state.store.get_meta("tip_hash").map_err(|e| storage_err_response(&e))?
        .and_then(|b| <[u8;32]>::try_from(b).ok());
    if applied != Some(tip) { return Err(json!({"error":"node applied and selected tips differ; retry preflight"})); }
    Ok((crate::mempool::admission::pool_next_height(&dag,&state.store,&state.mempool),tip))
}

async fn dispatch(method: &str, params: Option<&Value>, state: &AppState) -> Value {
    match method {
        "getnetworkinfo" => {
            // Review of PR #15, finding 2 (lock order: dag before node_state).
            let warnings: Vec<String> =
                crate::accept::no_verdict_branch_warning(&state.dag.read(), &state.store).into_iter().collect();
            let s = state.node_state.read();
            let pruned_h = state.store.pruned_height();
            json!({
                // The chain this node runs (`--testnet`), as set once at
                // start-up. Was the literal "mainnet" on every node
                // (test/functional/feature_test_build_guard.py).
                "network":         match crate::core::node_chain_id() {
                    crate::core::ChainId::Testnet => "testnet",
                    crate::core::ChainId::Mainnet => "mainnet",
                },
                "version":         s.version,
                // The hardening activation height this binary enforces on its
                // chain (builds before 0.1.1 do not report the field), so an
                // operator can confirm the upgrade (docs/RUNNING.md).
                "hardening_activation_height": crate::core::activation::hardening_activation_height(),
                "protocol":        PROTOCOL_VERSION,
                "net_protocol":    crate::network::PROTOCOL_VERSION,
                "blue_score":      s.tip_blue_score,
                "blocks":          s.block_count,
                "peers":           s.peer_count,
                "mempool":         s.mempool_size,
                "syncing":         s.is_syncing,
                // Honest-lag fields: `best_announced` is the highest blue_score
                // any CONNECTED peer claims (untrusted hint); `behind_by` is how
                // far our selected tip trails it. A node that gave up on an
                // unreachable frontier used to report syncing:false and NOTHING
                // else — operators and the explorer could not see real lag.
                // behind_by > 0 with syncing:false means "released by the lag
                // tolerance or gave up", not "provably at the network tip".
                "best_announced":  s.best_announced_blue_score,
                "behind_by":       s.best_announced_blue_score.saturating_sub(s.tip_blue_score),
                "chain":           "gnb",
                "pruned_height":   pruned_h,
                "warnings":        warnings,
            })
        }
        "getblockcount"  => json!(state.node_state.read().block_count),
        // MEM-6: the size plus the relay policy in force (docs/MEMPOOL.md).
        "getmempoolinfo" => json!({
            "size":                 state.node_state.read().mempool_size,
            "bytes":                state.mempool.size_bytes(),
            "rolling_min_fee_rate_sat_per_byte": state.mempool.rolling_min_fee_rate(),
            "policy":               mempool_policy_json(),
        }),

        "getblockhash" => {
            let height = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            match state.store.get_block_hash_at_height(height) {
                Ok(Some(h)) => json!(hex::encode(h)),
                Ok(None)    => json!({ "error": "height not found" }),
                Err(e)      => storage_err_response(&e),
            }
        }

        // ── Block explorer: full block with transaction details ──────
        "getblock" => {
            let hash_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let verbose  = params.and_then(|p| p.get(1)).and_then(|v| v.as_bool()).unwrap_or(false);
            match hex::decode(hash_hex).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) {
                Some(hash) => match state.store.get_block(&hash) {
                    Ok(Some(b)) => {
                        let mut result = json!({
                            "hash":        hash_hex,
                            "height":      b.height,
                            "blue_score":  b.blue_score,
                            "tx_count":    b.transactions.len(),
                            "timestamp":   b.header.timestamp,
                            "bits":        format!("0x{:08x}", b.header.bits),
                            "nonce":       b.header.nonce,
                            "parents":     b.header.parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                            "merkle_root": hex::encode(b.header.merkle_root),
                            "size":        b.size_bytes(),
                            "pow":         crate::core::pow_algo(b.height).name(),
                        });
                        if crate::core::powit_active(b.height) {
                            result["powit"] = format_powit(&b.powit);
                        }
                        if verbose {
                            result["transactions"] = json!(b.transactions.iter().map(|tx| {
                                format_tx(tx)
                            }).collect::<Vec<_>>());
                        } else {
                            result["txids"] = json!(b.transactions.iter().map(|tx| {
                                hex::encode(tx.txid())
                            }).collect::<Vec<_>>());
                        }
                        result
                    },
                    Ok(None)  => json!({ "error": "not found" }),
                    Err(e)    => storage_err_response(&e),
                },
                None => json!({ "error": "invalid hash" }),
            }
        }

        // ── Block explorer: get block by height ──────────────────────
        "getblockbyheight" => {
            let height = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            let verbose = params.and_then(|p| p.get(1)).and_then(|v| v.as_bool()).unwrap_or(false);
            match state.store.get_block_hash_at_height(height) {
                Ok(Some(hash)) => match state.store.get_block(&hash) {
                    Ok(Some(b)) => {
                        let mut result = json!({
                            "hash":        hex::encode(hash),
                            "height":      b.height,
                            "blue_score":  b.blue_score,
                            "tx_count":    b.transactions.len(),
                            "timestamp":   b.header.timestamp,
                            "bits":        format!("0x{:08x}", b.header.bits),
                            "nonce":       b.header.nonce,
                            "parents":     b.header.parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                            "merkle_root": hex::encode(b.header.merkle_root),
                            "size":        b.size_bytes(),
                            "pow":         crate::core::pow_algo(b.height).name(),
                        });
                        if crate::core::powit_active(b.height) {
                            result["powit"] = format_powit(&b.powit);
                        }
                        if verbose {
                            result["transactions"] = json!(b.transactions.iter().map(|tx| {
                                format_tx(tx)
                            }).collect::<Vec<_>>());
                        } else {
                            result["txids"] = json!(b.transactions.iter().map(|tx| {
                                hex::encode(tx.txid())
                            }).collect::<Vec<_>>());
                        }
                        result
                    },
                    Ok(None)  => json!({ "error": "block data not found" }),
                    Err(e)    => storage_err_response(&e),
                },
                Ok(None) => json!({ "error": "height not found" }),
                Err(e)   => storage_err_response(&e),
            }
        }

        // ── Block explorer: recent blocks list ───────────────────────
        "getrecentblocks" => {
            let count = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(10)
                .min(50); // cap at 50
            // The DAG's block count is not a height: it counts parallel blocks
            // too, and on 2026-08-13 exceeded the chain height by 10,769. Using
            // it here made the scan start ~10k heights above anything that
            // exists and walk down through nothing.
            let tip_height = selected_tip_height(&state).saturating_add(1);
            let mut blocks = Vec::new();
            // Iterate ALL heights until we find enough blocks (DAG may have gaps)
            for h in (0..tip_height).rev() {
                if blocks.len() >= count as usize { break; }
                if let Ok(Some(hash)) = state.store.get_block_hash_at_height(h) {
                    if let Ok(Some(b)) = state.store.get_block(&hash) {
                        blocks.push(json!({
                            "hash":      hex::encode(hash),
                            "height":    b.height,
                            "tx_count":  b.transactions.len(),
                            "timestamp": b.header.timestamp,
                            "size":      b.size_bytes(),
                            "bits":      b.header.bits,
                        }));
                    }
                }
            }
            json!(blocks)
        }

        // ── Block explorer: transaction lookup (O(1) via TX index) ────
        "gettransaction" => {
            let txid_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let txid_bytes = match hex::decode(txid_hex).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) {
                Some(b) => b,
                None    => return json!({ "error": "invalid txid" }),
            };
            // O(1) lookup via CF_TX_INDEX
            match state.store.get_tx_location(&txid_bytes) {
                Ok(Some((block_hash, height))) => {
                    let tip = selected_tip_height(&state);
                    match state.store.get_block(&block_hash) {
                        Ok(Some(block)) => {
                            let tx = block.transactions.iter().find(|t| t.txid() == txid_bytes);
                            match tx {
                                Some(tx) => json!({
                                    "txid":          txid_hex,
                                    "block_hash":    hex::encode(block_hash),
                                    "block_height":  height,
                                    "timestamp":     block.header.timestamp,
                                    "confirmations": tip.saturating_sub(height),
                                    "transaction":   format_tx(tx),
                                }),
                                None => json!({ "error": "tx index stale" }),
                            }
                        },
                        Ok(None) => json!({ "error": "block not found" }),
                        Err(e)   => storage_err_response(&e),
                    }
                },
                Ok(None) => json!({ "error": "transaction not found" }),
                Err(e)   => storage_err_response(&e),
            }
        }

        // ── Wallet: raw transaction bytes (WAL-1) ────────────────────
        //
        // Read-only. Returns the wire bytes (`to_wire_bytes(true)`) of a
        // transaction so a wallet can hash them, compare the result with
        // the txid of a UTXO it is about to spend, and read the output's
        // value from a source it does not have to trust. Outputs of the
        // genesis carryover have no creating transaction, and pruned nodes
        // lose old bodies: both answer with an error and the wallet treats
        // the input as unverified.
        "getrawtransaction" => {
            let txid_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let Some(txid) = hex::decode(txid_hex).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                return json!({ "error": "invalid txid" });
            };
            if let Some(entry) = state.mempool.get_entry(&txid) {
                return json!({
                    "txid":       hex::encode(txid),
                    "hex":        hex::encode(entry.tx.to_wire_bytes(true)),
                    "in_mempool": true,
                });
            }
            match state.store.get_tx_location(&txid) {
                Ok(Some((block_hash, height))) => match state.store.get_block(&block_hash) {
                    Ok(Some(block)) => match block.transactions.iter().find(|t| t.txid() == txid) {
                        Some(tx) => json!({
                            "txid":         hex::encode(txid),
                            "hex":          hex::encode(tx.to_wire_bytes(true)),
                            "block_hash":   hex::encode(block_hash),
                            "block_height": height,
                            "in_mempool":   false,
                        }),
                        None => json!({ "error": "tx index stale" }),
                    },
                    Ok(None) => json!({ "error": "transaction body not available (block pruned)" }),
                    Err(e)   => storage_err_response(&e),
                },
                Ok(None) => json!({ "error": "transaction not found" }),
                Err(e)   => storage_err_response(&e),
            }
        }

        // ── Wallet: balance query ────────────────────────────────────
        "getbalance" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            // B1-T11: one read of the holder aggregate (was a walk of every
            // UTXO of the address, ~426,000 for the carryover address).
            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Ok(ab) => match state.store.address_balance(&ab, &state.cancel) {
                    // R3 (docs/specs/BLOCH-RPC-V4.md): satoshi amounts are
                    // decimal STRINGS on the wire — V4's supply exceeds both
                    // i64::MAX and JS Number.MAX_SAFE_INTEGER. Display-only
                    // `*_bloch` floats stay JSON numbers (documented lossy).
                    Ok((sats, utxo_count)) => json!({
                        "satoshis":   sats.to_string(),
                        "gnb":       sats as f64 / 1e8,
                        "utxo_count": utxo_count,
                        "address":    addr,
                    }),
                    Err(e) => storage_err_response(&e),
                },
                Err(error) => json!({ "error": error }),
            }
        }

        // ── Chain: distinct on-chain wallets (addresses with a balance) ──
        "getaddresscount" => {
            // NET-12: one read of the incremental aggregates (was a scan of
            // the whole address index on every call).
            match crate::analytics::address_count_bounded(&state.store) {
                Ok((addrs, utxos)) => json!({
                    "addresses_with_balance": addrs,
                    "utxo_entries":           utxos,
                    "note": "distinct 20-byte addresses currently holding >=1 UTXO (on-chain wallets with a non-zero balance) and their UTXOs; addresses that spent to zero or never held a UTXO are not counted",
                }),
                Err(e) => stats_err_response(&e),
            }
        }

        "getdescriptorinfo" => {
            match inspect_rpc_descriptor(params) {
                Ok(info) => info,
                Err(error) => json!({"error": error}),
            }
        }
        "deriveaddresses" => {
            match inspect_rpc_descriptor(params) {
                Ok(info) => json!([info["address"]]),
                Err(error) => json!({"error": error}),
            }
        }

        "pqpsbt" => {
            if state.cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return json!({"error":"request cancelled"});
            }
            let _permit = match state.pqpsbt_gate.try_acquire() {
                Ok(permit) => permit,
                Err(_) => return json!({"error":"PQ-PSBT worker busy; retry later"}),
            };
            match gnb_crypto::wallet::pqpsbt::public_request_with_limits(
                params.unwrap_or(&Value::Null), PQPSBT_RPC_MAX_INPUTS, PQPSBT_RPC_MAX_SIGNATURES) {
                Ok(result) => result,
                Err(error) => json!({"error":error}),
            }
        }

        // ── Wallet: list UTXOs for address (needed by wallet CLI) ────
        "getutxos" => {
            // Optional third parameter requests consensus/mempool metadata
            // for at most 64 selected inputs. Refuse malformed selections
            // before any storage work; the default endpoint is unchanged.
            let selected = match selected_policy_outpoints(params) {
                Ok(s) => s,
                Err(error) => return json!({"error":error}),
            };
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let spk = match parse_rpc_destination(addr) {
                Ok(script) => script,
                Err(error) => return json!({"error":error}),
            };
            let snapshot = if selected.is_some() {
                match policy_rpc_snapshot(state) {
                    Ok(s) => Some(s),
                    Err(error) => return error,
                }
            } else { None };
            // Optional 2nd param: max UTXOs to return. A wallet with hundreds of
            // thousands of UTXOs (e.g. the carry-over founder set) otherwise serializes
            // a multi-MB response that overflows clients; a spender only needs enough
            // UTXOs to cover the amount, so it can pass a small limit.
            //
            // NET-12: the limit is applied WHILE walking the address index
            // (the old code loaded every UTXO of the address first), and a
            // request without a limit is capped at GETUTXOS_MAX. When the
            // walk stops early `truncated` is true and `utxo_count` /
            // `satoshis` cover the returned UTXOs only; `getbalance` gives
            // the address totals.
            // The wallets' send flow widens a truncated window to this cap
            // (`gnb_crypto::wallet::send::GETUTXOS_MAX_ROWS`, the same value).
            const GETUTXOS_MAX: usize = gnb_crypto::wallet::send::GETUTXOS_MAX_ROWS as usize;
            let limit = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64())
                .map(|n| usize::try_from(n).unwrap_or(usize::MAX).min(GETUTXOS_MAX))
                .unwrap_or(GETUTXOS_MAX);
            // Single-key (gnb1q…, 20-byte script) or policy (gnb1m…, 33-byte
            // script) address. The address index is keyed by the FULL script,
            // so the lookup must use all of it (a 20-byte prefix never matches
            // a policy entry); results are still filtered on the full script.
            match state.store.get_utxos_for_address_limited(&spk, limit) {
                    Ok((utxos, truncated)) => {
                        let utxos: Vec<_> = utxos.into_iter()
                            .filter(|(_, _, o)| o.script_pubkey == spk)
                            .collect();
                        let total: u64 = utxos.iter().map(|(_, _, o)| o.value).fold(0u64, u64::saturating_add);
                        // R3: `value` is a satoshi amount → decimal string.
                        // An output of a coinbase also carries a
                        // `coinbase_height`: it is spendable in the next
                        // block (getdaginfo `next_block_height`) iff
                        // next_block_height - coinbase_height >=
                        // COINBASE_MATURITY, and a wallet that cannot tell
                        // selected immature coinbase outputs and built
                        // transactions the node refuses
                        // (test/functional/wallet_coinbase_maturity.py). From
                        // the activation the value encodes the selected-chain
                        // depth at the next block (re-audit B1-T14,
                        // `admission::coinbase_height_for_wallets`). A height
                        // that cannot be read fails the call (never "not a
                        // coinbase", re-audit B1-T12).
                        let next_block_height = snapshot.map(|s| s.0).unwrap_or_else(|| {
                            let dag = state.dag.read();
                            crate::mempool::admission::pool_next_height(&dag, &state.store, &state.mempool)
                        });
                        let rows: Result<Vec<Value>, crate::storage::StorageError> = utxos.iter().map(|(txid, idx, out)| {
                            let mut row = json!({
                                "txid": hex::encode(txid), "index": idx,
                                "value": out.value.to_string(), "script_pubkey": hex::encode(&out.script_pubkey),
                            });
                            if let Ok(t) = <[u8; 32]>::try_from(txid.as_slice()) {
                                let h = crate::mempool::admission::coinbase_height_for_wallets(
                                    &state.store, &t, next_block_height)?;
                                if let Some(h) = h {
                                    row["coinbase_height"] = json!(h);
                                }
                                if selected.as_ref().is_some_and(|s| s.contains(&(t,*idx))) {
                                    row["spent_in_mempool"] = json!(state.mempool.spends_outpoint(&(t,*idx)));
                                    let confirmations = crate::mempool::admission::confirmations_for_next_block(
                                        &state.store,&t,next_block_height)
                                        .map_err(|e| crate::storage::StorageError::ReadFailed(e.msg))?;
                                    row["confirmations_at_next_block"] = json!(confirmations);
                                }
                            }
                            Ok(row)
                        }).collect();
                        let list = match rows {
                            Ok(l) => l,
                            Err(e) => return storage_err_response(&e),
                        };
                        if let Some(initial) = snapshot {
                            match policy_rpc_snapshot(state) {
                                Ok(current) if current == initial => {},
                                Ok(_) => return json!({"error":"node snapshot changed during UTXO lookup; retry preflight"}),
                                Err(error) => return error,
                            }
                        }
                        let mut result = json!({
                            "address":    addr,
                            "utxo_count": list.len(),
                            "returned":   list.len(),
                            "truncated":  truncated,
                            "satoshis":   total.to_string(),
                            "gnb":       total as f64 / 1e8,
                            "utxos":      list,
                        });
                        if let Some((height,tip)) = snapshot {
                            result["next_block_height"] = json!(height);
                            result["tip"] = json!(hex::encode(tip));
                        }
                        result
                    },
                    Err(e) => storage_err_response(&e),
            }
        }

        "sendrawtransaction" => {
            let hex_tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex_tx) {
                Err(_)   => json!({ "error": "invalid hex" }),
                // Sprint 1.d: Bitcoin-format tx bytes (replaces bincode).
                // Wallet clients send stratum_bytes(include_script_sig=true).
                // MEM-5: strict decode — trailing bytes are refused.
                Ok(raw)  => match crate::mempool::admission::decode_tx_strict(&raw) {
                    Err(_)  => json!({ "error": "deserialise failed" }),
                    Ok(tx)  => {
                        if tx.is_coinbase() { return json!({ "error": "coinbase not accepted" }); }
                        // B1-T10: an untrusted caller's transaction is charged
                        // to the node-wide verification budget by its wire
                        // size BEFORE any signature is checked, and refunded
                        // once admitted, so only refused transactions use it
                        // up. The per-IP limiter cannot do this: behind the
                        // explorer API every caller arrives from loopback, and
                        // a forged-signature flood from many addresses would
                        // otherwise cost the node unbounded verification work
                        // (Bitcoin Core bounds the same work per peer through
                        // its misbehaviour handling; MEM-5 does it for gossip).
                        let charged = if state.caller_trusted { 0 } else { raw.len() };
                        if charged > 0 && !state.tx_verify_budget.take(charged) {
                            return json!({ "error": "busy: the node's transaction-verification budget for \
                                unauthenticated callers is exhausted (it refills within a minute); retry \
                                shortly, or authenticate with the API key" });
                        }
                        // MEM-1/4/5: the SAME admission function as gossip and
                        // reorg re-injection. Version and maturity are evaluated
                        // at the next block's height (the node's next template
                        // height, `pool_next_height`, also reported by
                        // getdaginfo) — never the DAG block COUNT, which on
                        // 2026-08-13 exceeded the chain height by 10,769 and
                        // made every coinbase look mature. P0: PQ signature
                        // verification is CPU-bound, so it runs on the blocking
                        // pool.
                        let next_height = crate::mempool::admission::pool_next_height(
                            &state.dag.read(), &state.store, &state.mempool);
                        let store_v = state.store.clone();
                        let mempool_v = state.mempool.clone();
                        let txid = tx.txid();
                        let admitted = tokio::task::spawn_blocking(move || {
                            let policy = crate::mempool::admission::AdmissionPolicy::relay(next_height);
                            crate::mempool::admission::admit(&store_v, &mempool_v, tx, &policy)
                        }).await;
                        match admitted {
                            // Not L-5: an admission verdict (double-spend, fee too
                            // low, dust, ...) the caller needs to fix their tx —
                            // not an internal/filesystem detail to withhold.
                            Err(e)      => json!({ "error": format!("verify task failed: {}", e) }),
                            Ok(Err(e))  => json!({ "error": e.to_string() }),
                            Ok(Ok(_))   => {
                                state.tx_verify_budget.refund(charged);
                                let _ = state.outbound_tx.try_send(NetworkMessage::NewTransaction {
                                    txid, tx_data: raw,
                                });
                                json!({ "txid": hex::encode(txid) })
                            }
                        }
                    }
                },
            }
        }

        // ── Phase 2: validateaddress ─────────────────────────────────
        "validateaddress" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            validate_rpc_address(addr, false)
        }

        // ── Phase 2: estimatefee ─────────────────────────────────────
        "estimatefee" => {
            // MEM-6: a fee RATE (sat per 1,000 wire bytes, the unit of the
            // consensus minimum), never below the consensus minimum rate or the
            // mempool's rolling minimum, plus the resulting fee of a typical
            // one-input / two-output transaction, never below the consensus
            // minimum fee. (Previously: the median ABSOLUTE fee, defaulting to
            // 1,000 sat while the consensus minimum is 10,000 sat.)
            let rate = state.mempool.estimate_fee_rate_per_kb();
            let typical_size = Transaction::estimate_size(1, 2);
            let typical_fee = crate::core::tokenomics::min_tx_fee_sat(typical_size)
                .max((typical_size as u64).saturating_mul(rate).div_ceil(1000));
            json!({
                // R3: satoshi amounts → decimal strings.
                "feerate_sat_per_kb": rate.to_string(),
                "min_fee_sat":        crate::core::tokenomics::MIN_TX_FEE_SAT.to_string(),
                "typical_tx_bytes":   typical_size,
                "typical_tx_fee_sat": typical_fee.to_string(),
                // Legacy key: now the recommended ABSOLUTE fee for a typical
                // transaction (>= the consensus minimum).
                "feerate_sats":       typical_fee.to_string(),
                "feerate_gnb":        typical_fee as f64 / 1e8,
                "mempool_size":       state.mempool.size(),
                "note":               "fee rate in sat/kB of wire bytes (>= consensus minimum); typical_tx_fee_sat for a 1-in/2-out tx",
            })
        }

        // ── Phase 2: getrawmempool ───────────────────────────────────
        "getrawmempool" => {
            let verbose = params.and_then(|p| p.get(0)).and_then(|v| v.as_bool()).unwrap_or(false);
            if verbose {
                let entries = state.mempool.entries();
                let list: Vec<serde_json::Value> = entries.iter().map(|(txid, fee, added)| {
                    json!({
                        "txid":     hex::encode(txid),
                        // R3: satoshi amount → decimal string.
                        "fee":      fee.to_string(),
                        "fee_gnb": *fee as f64 / 1e8,
                        "time":     added,
                    })
                }).collect();
                json!({ "size": list.len(), "transactions": list })
            } else {
                let txids: Vec<String> = state.mempool.txids().iter().map(|t| hex::encode(t)).collect();
                json!({ "size": txids.len(), "txids": txids })
            }
        }

        // ── Phase 2: decoderawtransaction ────────────────────────────
        "decoderawtransaction" => {
            let hex_tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex_tx) {
                Err(_)  => json!({ "error": "invalid hex" }),
                // Sprint 1.d: Bitcoin-format tx bytes.
                Ok(raw) => match Transaction::from_wire_bytes(&raw) {
                    Err(e)  => json!({ "error": format!("decode failed: {}", e) }),
                    Ok(tx)  => {
                        let mut result = format_tx(&tx);
                        result["size"] = json!(raw.len());
                        result
                    }
                },
            }
        }

        // ── Phase 2: getdaginfo ──────────────────────────────────────
        // ── B5f pool seam: getblocktemplate / submitblock ─────────────────
        //
        // Stratum V1/V2 shares cannot carry the Module-SIS solution vector
        // (main.rs refuses to start them), so pool software mines complete
        // SIS blocks and talks to the node over these two methods instead:
        //
        //   getblocktemplate  — everything needed to assemble a candidate
        //                       block: parents, height, blue_score, the
        //                       expected `bits` (computed EXACTLY like
        //                       accept_block: ASERT-Lattice from the genesis
        //                       anchor + parent timestamp), subsidy/vesting
        //                       amounts, and mempool transactions with fees.
        //   submitblock       — full block (Bitcoin wire format hex, i.e.
        //                       Block::to_wire_bytes) routed through the
        //                       same validation pipeline as gossiped blocks.
        //
        // The reference pool consuming this lives in pool/.
        "getblocktemplate" => {
            // Shared template builder (audit MEM-2 / DAG-2): parents = at most
            // MAX_PARENTS bodied, non-disqualified tips by blue work; height =
            // max parent height + 1 (accept_block's VULN-02 rule); expected
            // bits exactly as accept_block validates them; transactions as
            // whole ANCESTOR PACKAGES by package fee rate, parents before
            // children (MEM-6 child-pays-for-parent), under a byte budget
            // measured like the consensus size rule of the template's height,
            // reserving EXTERNAL_COINBASE_RESERVE bytes for the caller's
            // coinbase; every tx re-validated at the template's height against
            // the UTXO set plus the outputs of the transactions placed before
            // it (offenders evicted with their descendants). Fees are
            // recomputed. Each entry's `depends` lists its in-template parents
            // (BIP22: 1-based positions in `transactions`): a block built from
            // a subset of the entries must keep every dependency of every
            // entry it keeps.
            //
            // POW-3: no template while the selected tip is below the minimum
            // chain work (Bitcoin Core: "in initial sync and waiting for
            // blocks"): it may be a chain this node's own pulls fetched from
            // an eclipsing peer, not one to mine on.
            if let Some(e) = crate::ingress::ibd_template_refusal(&state.dag.read(), state.min_chain_work) {
                return json!({ "error": e });
            }
            let tmpl = match crate::template::build_block_template(
                &state.dag, &state.store, &state.mempool,
                crate::template::EXTERNAL_COINBASE_RESERVE,
            ) {
                Ok(t) => t,
                Err(e) => return json!({ "error": e }),
            };
            let tx_entries = template_tx_entries(&tmpl);
            // Review of PR #15, finding 2: a template on the chain the node
            // can judge while a heavier branch is parked without a verdict.
            let warnings: Vec<String> =
                crate::accept::no_verdict_branch_warning(&state.dag.read(), &state.store).into_iter().collect();

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs();
            // Hardening block rules (docs/CONSENSUS.md, "Block rules at the
            // hardening activation"): at/after the activation the coinbase
            // script_sig MUST start with `coinbase_script_sig_prefix` (80
            // bytes: tag, height, parents commitment, witness root of exactly
            // the listed transactions in this order), followed by at most
            // `max_coinbase_extra_bytes` miner bytes; the header Merkle root
            // uses the tagged tree; the size limit is measured on the wire
            // encoding. Below it, all three are as before.
            //
            // The WHOLE coinbase, measured with `size_rule`, must fit in
            // `coinbase_reserve`: the listed transactions may fill the rest of
            // the block. `max_coinbase_extra_bytes` already includes that
            // bound for a coinbase with one output whose script_pubkey is at
            // most `max_coinbase_script_pubkey_bytes` bytes (and the consensus
            // script_sig cap), so a miner that stays within both fields can
            // never produce a block over `max_block_size`.
            let commitment = tmpl.coinbase_commitment();
            let max_extra = crate::template::external_coinbase_max_extra(
                commitment.map(|c| c.len()).unwrap_or(0),
                tmpl.hardened,
                crate::template::EXTERNAL_COINBASE_RESERVE,
            );

            let witness_commitment = if crate::core::suffix_witness_commitment_required(tmpl.height) {
                let probe = crate::core::Block {
                    header: crate::core::BlockHeader { version: 1, parents: vec![],
                        merkle_root: crate::core::MerkleRoot::ZERO, timestamp: 0, bits: tmpl.bits, nonce: 0 },
                    transactions: std::iter::once(crate::core::Transaction {
                        version: 1, inputs: vec![], outputs: vec![], locktime: 0 })
                        .chain(tmpl.transactions.iter().map(|(t, _)| t.clone())).collect(),
                    blue_score: tmpl.blue_score, height: tmpl.height,
                    shielded_transactions: Vec::new(), powit: tmpl.powit.clone(),
                };
                hex::encode(probe.witness_commitment())
            } else {
                String::new()
            };
            let powit_hex = {
                let mut v = Vec::new();
                tmpl.powit.write_wire(&mut v);
                hex::encode(v)
            };
            let coinbase_outputs: Vec<Value> = tmpl.coinbase_outputs(Vec::new()).iter().map(|o| json!({
                "value": o.value.to_string(), "script_pubkey": hex::encode(&o.script_pubkey),
            })).collect();

            json!({
                "hardening_active":     tmpl.hardened,
                "hardening_activation_height": tmpl.activation_height,
                "merkle_rule":          if tmpl.hardened { "gnb-tagged-v1" } else { "sha256d-duplicate-last" },
                "size_rule":            if tmpl.hardened { "wire" } else { "bincode" },
                "coinbase_script_sig_prefix": commitment.map(hex::encode).unwrap_or_default(),
                "max_coinbase_extra_bytes": max_extra,
                "max_coinbase_script_pubkey_bytes": crate::template::EXTERNAL_COINBASE_MAX_SPK,
                // Siblings from the coinbase leaf to the header root (fold the
                // coinbase txid through them with the `merkle_rule`).
                "coinbase_merkle_branch": tmpl.coinbase_merkle_branch().iter().map(hex::encode).collect::<Vec<_>>(),
                "parents":              tmpl.parents.iter().map(hex::encode).collect::<Vec<_>>(),
                "height":               tmpl.height,
                "blue_score":           tmpl.blue_score,
                "bits":                 tmpl.bits,
                "cur_time":             now,
                "parent_time":          tmpl.parent_timestamp,
                // R3: satoshi amounts → decimal strings.
                "subsidy_sat":          tmpl.subsidy.to_string(),
                "total_fees":           tmpl.total_fees.to_string(),
                "transactions":         tx_entries,
                "warnings":             warnings,
                // The block's timestamp must be >= parent_time and at most
                // MAX_FUTURE_SECS ahead of the validator's clock.
                "min_time":             tmpl.parent_timestamp,
                // Size accounting: the whole block, measured as the consensus
                // rule measures it at this height (`chain_size_rule`: the wire
                // encoding `Block::to_wire_bytes` at every height on this
                // chain, `block_rules::legacy_block_size` below the
                // activation, whose fixed-width blue_score no copy of a block
                // id can change, re-audit B1-T0), must stay <= max_block_size;
                // the listed transactions leave coinbase_reserve bytes for the
                // WHOLE coinbase (in the same measure), which is what
                // max_coinbase_extra_bytes is derived from.
                "max_block_size":       crate::core::MAX_BLOCK_SIZE,
                "coinbase_reserve":     crate::template::EXTERNAL_COINBASE_RESERVE,
                "max_parents":          crate::core::MAX_PARENTS,
                // Proof of work: GnB-SMH v1 over the header preimage
                // (version u32le | n_parents u32le | parents | merkle_root |
                // timestamp u64le | bits u32le) and the u64 nonce; valid iff
                // the 32-byte output, big-endian, is < target(bits).
                // From powit_height the proof of work is GnB-SMH v3 (4 MiB);
                // "pow" names the function for THIS height.
                "pow":                  crate::core::pow_algo(tmpl.height).name(),
                "pow_log2_n":           match crate::core::pow_algo(tmpl.height) {
                    gnb_smh::Algo::V1 => gnb_smh::LOG2_N,
                    gnb_smh::Algo::V3 => gnb_smh::v3::LOG2_N,
                },
                "target":               hex::encode(crate::core::bits_to_target(tmpl.bits)),
                // This chain measures the block size on the wire encoding at
                // every height (`size_rule` above names the audit's regime).
                "chain_size_rule":      "wire",
                // From witness_commitment_height up to the hardening
                // activation the coinbase script_sig must END with these
                // bytes (tag ‖ Merkle root of the wtxids, the coinbase counted
                // as zero); see Block::commit_witnesses.
                "witness_commitment_height": crate::core::WITNESS_COMMITMENT_HEIGHT,
                "witness_commitment":   witness_commitment,
                // PoWit (from powit_height): the block must carry this section
                // (wire hex, `PowitBody::write_wire`) and its coinbase exactly
                // these outputs, the first paid to the miner's script (one per
                // witness share after it; the miner output is subsidy share +
                // fees, see `core::Block::coinbase_outputs`).
                "powit_height":         crate::core::powit_height().to_string(),
                "powit":                powit_hex,
                "coinbase_outputs":     coinbase_outputs,
            })
        }

        "submitblock" => {
            let block_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let bytes = match hex::decode(block_hex) {
                Ok(b)  => b,
                Err(_) => return json!({ "error": "invalid hex" }),
            };
            let block = match crate::core::Block::from_wire_bytes(&bytes) {
                Ok(b)  => b,
                Err(e) => return json!({ "error": format!("deserialise failed: {}", e) }),
            };
            match &state.submit_block {
                None => json!({ "error": "submitblock not wired on this node (started without a block-submission hook)" }),
                Some(hook) => match hook(block) {
                    Ok(hash_hex) => json!({ "accepted": true, "hash": hash_hex }),
                    Err(reason)  => json!({ "error": format!("rejected: {}", reason) }),
                },
            }
        }

        // Audit DAG-6: operator recovery (Bitcoin Core's invalidateblock /
        // reconsiderblock). Admin methods: never anonymous (auth::ADMIN_METHODS).
        "invalidateblock" => chain_admin_call(ChainAdminOp::Invalidate, params, state),
        "reconsiderblock" => chain_admin_call(ChainAdminOp::Reconsider, params, state),
        // PoWit audit findings 2 and 3: the finality pin's escape hatch.
        // Admin methods (auth::ADMIN_METHODS); docs/RUNNING.md.
        "ignorefinalized" => chain_admin_call(ChainAdminOp::IgnoreFinalized, params, state),
        "reconsiderfinalized" => chain_admin_call(ChainAdminOp::ReconsiderFinalized, params, state),
        "setfinalitycheckpoint" => chain_admin_call(ChainAdminOp::SetFinalityCheckpoint, params, state),
        // The finality pin, where it comes from, the anchor, the finalized
        // checkpoints it counts and any conflict (read; bounded output).
        "getfinalityinfo" => {
            let dag = state.dag.read();
            crate::powit::finality_info_json(&dag, 32)
        }

        // submitpowititem [kind, hex]: kind 1 = witness share, 2 = attestation,
        // 3 = equivocation proof. Validated like a gossiped item, then relayed.
        "submitpowititem" => {
            let kind = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            let data = match params.and_then(|p| p.get(1)).and_then(|v| v.as_str()).map(hex::decode) {
                Some(Ok(d)) => d,
                _ => return json!({ "error": "usage: submitpowititem [kind, hex]" }),
            };
            if !(1..=3).contains(&kind) || data.len() > crate::network::MAX_WIRE_POWIT_ITEM {
                return json!({ "error": "bad kind or item too large" });
            }
            let kind = kind as u8;
            // B1-T10: the same node-wide budget as `sendrawtransaction`. An
            // untrusted caller's item is charged by its size before its KES
            // signature is checked (under the DAG read lock), and refunded
            // once admitted: items the node refuses cannot buy unbounded
            // verification work from many addresses behind a proxy.
            let charged = if state.caller_trusted { 0 } else { data.len() };
            if charged > 0 && !state.tx_verify_budget.take(charged) {
                return json!({ "accepted": false, "error": "busy: the node's verification budget for \
                    unauthenticated callers is exhausted (it refills within a minute); retry shortly, \
                    or authenticate with the API key" });
            }
            let res = {
                let dag = state.dag.read();
                crate::powit::admit_item(kind, &data, &dag, &state.store)
            };
            match res {
                Ok(()) => {
                    state.tx_verify_budget.refund(charged);
                    let id = crate::powit::item_id(kind, &data);
                    let _ = state.outbound_tx.try_send(NetworkMessage::NewPowitItem { id, kind, data });
                    json!({ "accepted": true, "id": hex::encode(id) })
                }
                Err(e) => json!({ "accepted": false, "error": e }),
            }
        }

        "getpowitinfo" => {
            let dag = state.dag.read();
            crate::powit::info_json(&dag, &state.store)
        }

        "getdaginfo" => {
            let dag = state.dag.read();
            let tips = dag.tips();
            let tip = dag.selected_tip();
            let tip_data = tip.and_then(|h| dag.get_block_data(&h).cloned());
            // B2-T5: the selected chain is the selected-parent chain from the
            // selected tip to genesis, and a block's DAG height is its
            // selected parent's + 1 (genesis 0), so its length is the tip's
            // height + 1. It used to be counted by walking the whole chain
            // under the DAG read lock on every call.
            let chain_length = tip_data.as_ref().map_or(0, |d| d.height + 1);
            // The header height of the next block mempool admission targets
            // (the node's next template height): wallets sign for it (version
            // 3 / sighash v3 from the hardening activation). Not always
            // tip_height + 1: a template that merges a tip with a greater DAG
            // height sits higher (DAG-8).
            let next_block_height = crate::mempool::admission::pool_next_height(&dag, &state.store, &state.mempool);
            // The activation height in force (the one block validation and
            // the template builder read) and whether the hardening rules
            // apply at next_block_height, as getblocktemplate reports them
            // for its template's height.
            let activation_height = crate::core::activation::hardening_activation_height();
            // POW-3: the minimum chain work in force (default or
            // `--minimumchainwork`), in the unit and format of
            // `tip_blue_work`; below it the node is in initial block download.
            let min_chain_work = state.min_chain_work;
            let tip_work = tip_data.as_ref().map_or(0, |d| d.blue_work);
            // Audit F1 (review, finding 1): the blocks whose validation ended
            // without a verdict (`accept`'s no-verdict guard), like
            // getchaintips' per-branch status: parked (not selectable until
            // the retry), never marked invalid. `stopped`: why the node
            // stopped (repeated storage-engine failures), if it did.
            let now = std::time::Instant::now();
            let no_verdict: Vec<Value> = state.store.no_verdict_records().into_iter().map(|(h, r)| json!({
                "hash":          hex::encode(h),
                "status":        if dag.is_no_verdict_parked(&h) { "no-verdict-parked" } else { "no-verdict-retrying" },
                "class":         if r.last_io { "storage-engine" } else { "inconsistent-chain-state" },
                "attempts":      r.attempts,
                "storage_engine_failures_in_a_row": r.io_failures,
                "reason":        r.reason,
                "retry_in_secs": r.retry_at.saturating_duration_since(now).as_secs(),
            })).collect();
            // Review of PR #15, finding 2: a heavier branch parked without a
            // verdict (the node mines on the lighter chain it can judge).
            let warnings: Vec<String> =
                crate::accept::no_verdict_branch_warning(&dag, &state.store).into_iter().collect();
            json!({
                "no_verdict":     no_verdict,
                "stopped":        state.store.abort_reason(),
                "warnings":       warnings,
                "tip":            tip.map(|h| hex::encode(h)),
                "tip_blue_score": tip_data.as_ref().map(|d| d.blue_score).unwrap_or(0),
                "tip_blue_work":  tip_data.as_ref().map(|d| d.blue_work.to_string()).unwrap_or_default(),
                "minimum_chain_work": min_chain_work.to_string(),
                "below_minimum_chain_work": tip_work < min_chain_work,
                "tip_height":     tip_data.as_ref().map(|d| d.height).unwrap_or(0),
                "next_block_height": next_block_height,
                "hardening_activation_height": activation_height,
                "hardening_active": crate::core::block_rules::rules_active_at(next_block_height, activation_height),
                "block_count":    dag.block_count(),
                "tip_count":      tips.len(),
                "tips":           tips.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
                "chain_length":   chain_length,
                "k":              crate::core::GHOSTDAG_K,
            })
        }

                "listtransactions" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let limit = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(20).min(1000) as usize;
            let start_height = params.and_then(|p| p.get(2)).and_then(|v| v.as_u64()).unwrap_or(0);
            let end_height = params.and_then(|p| p.get(3)).and_then(|v| v.as_u64())
                .unwrap_or_else(|| state.node_state.read().block_count);
            // B1-T11: the skipped prefix is bounded like getaddresshistory's
            // (a larger offset is refused, never clamped to another page).
            let offset = params.and_then(|p| p.get(4)).and_then(|v| v.as_u64()).unwrap_or(0);
            if offset > crate::storage::indexer::MAX_HISTORY_OFFSET as u64 {
                return explorer::offset_too_large();
            }
            let offset = offset as usize;

            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Ok(addr_hash) => {
                    match state.store.query_address_history(&addr_hash, start_height, end_height, limit, offset) {
                        Ok(entries) => {
                            let tip = selected_tip_height(&state);
                            // B1-T11: the whole history is counted by the
                            // per-address counter (one read); a narrower range
                            // by a cancellable walk that stops at
                            // LISTTX_COUNT_CAP entries (review: it walked the
                            // whole range, ~426,000 rows for the carryover
                            // address, on every anonymous call). Above the cap
                            // `total_available` is null and `total_at_least`
                            // says how many there are at least.
                            let counter = if start_height == 0 && end_height >= tip {
                                state.store.address_history_count(&addr_hash).ok().flatten()
                            } else {
                                None
                            };
                            let total = match counter {
                                Some(n) => Some(n),
                                None => match state.store.count_address_history_capped(
                                    &addr_hash, start_height, end_height, LISTTX_COUNT_CAP, &state.cancel)
                                {
                                    Ok(n) if n >= LISTTX_COUNT_CAP => None,
                                    Ok(n) => Some(n),
                                    Err(_) if state.cancel.load(std::sync::atomic::Ordering::Relaxed) => return json!({ "error": "cancelled" }),
                                    Err(e) => return storage_err_response(&e),
                                },
                            };
                            let txs: Vec<serde_json::Value> = entries.iter().map(|e| {
                                let timestamp = state.store.get_block_timestamp_at_height(e.height).unwrap_or(None).unwrap_or(0);
                                json!({
                                    "txid":          hex::encode(&e.txid),
                                    "block_height":  e.height,
                                    "timestamp":     timestamp,
                                    "confirmations": tip.saturating_sub(e.height),
                                    "direction":     e.direction_str(),
                                    // R3: satoshi amount → decimal string.
                                    "amount_sats":   e.amount.to_string(),
                                    "amount_bloch":   e.amount as f64 / 1e8,
                                })
                            }).collect();
                            json!({
                                "address":         addr,
                                "count":           txs.len(),
                                "total_available": total,
                                "total_at_least":  total.unwrap_or(LISTTX_COUNT_CAP),
                                "start_height":    start_height,
                                "end_height":      end_height,
                                "limit":           limit,
                                "offset":          offset,
                                "transactions":    txs,
                            })
                        }
                        Err(e) => storage_err_response(&e),
                    }
                }
                Err(error) => json!({ "error": error }),
            }
        }

// ── INSERT: gettxsbyblock ──

        // ── Phase 2: getpeerinfo ─────────────────────────────────────
        "getpeerinfo" => {
            let s = state.node_state.read();
            json!({
                "peer_count": s.peer_count,
                "syncing":    s.is_syncing,
            })
        }

        "getpeers" => {
            let s = state.node_state.read();
            let peers: Vec<serde_json::Value> = s.peer_addresses.iter().map(|addr| {
                // Extract IP from multiaddr like /ip4/1.2.3.4/tcp/17110/p2p/12D3...
                let ip = addr.split('/').enumerate()
                    .find(|(i, seg)| *i > 0 && seg.parse::<std::net::Ipv4Addr>().is_ok())
                    .map(|(_, s)| s.to_string())
                    .unwrap_or_default();
                let peer_id = addr.split("/p2p/").last().unwrap_or("").to_string();
                json!({
                    "address": addr,
                    "ip": ip,
                    "peer_id": peer_id,
                })
            }).collect();
            json!({
                "peer_count": s.peer_count,
                "peers": peers,
            })
        }

        // ── Treasury (community dev fund) ───────────────────────────────
        // V2 (ADR-028): replaces V1 "gettreasury" with multi-pool report.
        // Returns subsidy split for the next block + per-pool address/balance,
        // gracefully reporting "pending_phase_6" for pools whose address
        // constants are still None.
        "getsupplyinfo" => {
            use crate::core::tokenomics as t;
            let current_height = selected_tip_height(&state);
            let next_height    = current_height.saturating_add(1);
            let subsidy        = t::block_subsidy_sat(next_height);
            let issued         = t::issued_through_sat(current_height);
            let next_halving   = (next_height / t::HALVING_INTERVAL + 1) * t::HALVING_INTERVAL;
            json!({
                "current_height":          current_height,
                "next_block_height":       next_height,
                // Amounts in base units as decimal strings (1 GNB = 10^8).
                "max_supply_sat":          t::MAX_SUPPLY_SAT.to_string(),
                "issued_sat":              issued.to_string(),
                "subsidy_per_block_sat":   subsidy.to_string(),
                "subsidy_per_block_gnb":   subsidy as f64 / 1e8,
                "halving_interval":        t::HALVING_INTERVAL,
                "next_halving_height":     next_halving,
                "last_subsidy_height":     t::LAST_SUBSIDY_HEIGHT_EXCLUSIVE - 1,
                "miner_share_bps":         10_000,
                "min_fee_rate_sat_per_kb": t::MIN_FEE_RATE_SAT_PER_KB.to_string(),
                "min_tx_fee_sat":          t::MIN_TX_FEE_SAT.to_string(),
            })
        }

        // VAL-11: Bitcoin Core's gettxoutsetinfo — the UTXO set (count,
        // total, hash) against the issuance, over one snapshot. Heavy class
        // (single flight + TTL cache) and cancellable at the deadline.
        "gettxoutsetinfo" => {
            match state.store.utxo_set_audit(crate::storage::utxo_audit::GenesisLedger::NETWORK, &state.cancel) {
                Ok(a) => utxo_audit_json(&a),
                Err(StorageError::ReadFailed(m)) if m == "cancelled" => json!({ "error": "cancelled" }),
                Err(e) => storage_err_response(&e),
            }
        }

        // ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//      in src/rpc/mod.rs (last arm of the match in dispatch())
//
// ═════════════════════════════════════════════════════════════════════════════

        // ── Sprint B: Chain analytics ──────────────────────────────────────

        // NET-12: bounded — incremental aggregates plus an in-memory walk of
        // at most `analytics::STATS_WINDOW_MAX_BLOCKS` selected-chain blocks
        // (cancellable); was a decode of every stored block body per call.
        "getchainstats" => {
            match crate::analytics::chain_stats_bounded(&state.store, &state.dag, unix_now(), &state.cancel) {
                Ok(s) => json!({
                    "total_blocks":         s.total_blocks,
                    "chain_blocks":         s.chain_blocks,
                    "total_txs":            s.total_txs,
                    "avg_txs_per_block":    s.avg_txs_per_block,
                    "blocks_last_24h":      s.blocks_last_24h,
                    "txs_last_24h":         s.txs_last_24h,
                    "window_capped":        s.window_capped,
                    "avg_block_time_secs":  s.avg_block_time,
                    "avg_dag_block_interval_secs": s.avg_dag_block_interval,
                    "current_difficulty":   s.current_difficulty,
                    "hashrate_hs":          s.hashrate_estimate,
                    "hashrate_human":       format_hashrate(s.hashrate_estimate),
                    "note": "total_blocks: blocks in the DAG; chain_blocks/total_txs/*_last_24h: the applied selected chain (the ledger); avg_block_time_secs: interval between selected-chain blocks; hashrate_hs: from the interval between ALL DAG blocks (chain blocks and the blue and red blocks they merged, avg_dag_block_interval_secs) over the last 50 chain blocks",
                }),
                Err(e) => stats_err_response(&e),
            }
        }

        "getsupplydistribution" => explorer::get_supply_distribution(state),
        "getselectedchain"      => explorer::get_selected_chain(params, state),
        "getblockdag"           => explorer::get_block_dag(params, state),
        "gettransactionfull"    => explorer::get_transaction_full(params, state),
        "getdagwindow"          => explorer::get_dag_window(params, state),
        "getaddresshistory"     => explorer::get_address_history(params, state),
        "getrichlist"           => explorer::get_rich_list(params, state),
        "gethashrate" => {
            match crate::analytics::chain_stats_bounded(&state.store, &state.dag, unix_now(), &state.cancel) {
                Ok(s) => json!({
                    "hashrate_hs":          s.hashrate_estimate,
                    "hashrate_human":       format_hashrate(s.hashrate_estimate),
                    "avg_block_time_secs":  s.avg_block_time,
                    "avg_dag_block_interval_secs": s.avg_dag_block_interval,
                    "current_difficulty":   s.current_difficulty,
                    "note": "hashrate_hs counts every DAG block (chain blocks and the blue and red blocks they merged): hashes per block / avg_dag_block_interval_secs over the last 50 chain blocks",
                }),
                Err(e) => stats_err_response(&e),
            }
        }

        // NET-12: bounded walks of the selected chain (were full scans that
        // decoded every stored block body), also behind the HeavyGate.
        "getdifficultyhistory"    => explorer::get_difficulty_history(params, state),
        "getblocktimepercentiles" => explorer::get_block_time_percentiles(params, state),

        "gettxstatus" => {
            let txid_hex = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let txid_bytes = match hex::decode(txid_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => return json!({ "error": "invalid txid" }),
            };
            let mut txid_arr = [0u8; 32];
            txid_arr.copy_from_slice(&txid_bytes);

            // Check mempool first
            if state.mempool.contains(&txid_arr) {
                return json!({
                    "status":        "pending",
                    "in_mempool":    true,
                    "confirmations": 0,
                    "txid":          txid_hex,
                });
            }

            // Check storage
            match state.store.get_tx_location(&txid_arr) {
                Ok(Some((_block_hash, height))) => {
                    let tip = selected_tip_height(&state);
                    let confirmations = tip.saturating_sub(height) + 1;
                    json!({
                        "status":        if confirmations >= 100 { "final" } else { "confirmed" },
                        "in_mempool":    false,
                        "confirmations": confirmations,
                        "block_height":  height,
                        "txid":          txid_hex,
                    })
                }
                _ => json!({
                    "status":        "unknown",
                    "in_mempool":    false,
                    "confirmations": 0,
                    "txid":          txid_hex,
                })
            }
        }

        "getaddressinfo" => {
            let addr_str = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let addr_hash = match parse_address(addr_str) {
                Ok(hash) => hash,
                Err(error) => return json!({ "error": error }),
            };

            match crate::analytics::address_info(&state.store, &state.mempool, addr_str, &addr_hash) {
                Ok(info) => json!({
                    "address":           info.address,
                    // R3: satoshi amounts → decimal strings.
                    "balance_sats":      info.balance_sats.to_string(),
                    "balance_gnb":      info.balance_gnb,
                    "utxo_count":        info.utxo_count,
                    "pending_incoming":  info.pending_incoming.to_string(),
                    "pending_outgoing":  info.pending_outgoing.to_string(),
                    "pool_role":         info.pool_role,
                }),
                Err(e) => json!({ "error": e }),
            }
        }

        // B1-T21 / MEM-6: `[n_inputs=1, n_outputs=2]`. Every field is the
        // ABSOLUTE fee of a transaction of that shape (`tx_bytes`), from fee
        // rates, never below `min_tx_fee_sat(tx_bytes)` or the rolling
        // minimum (`analytics::estimate_fee_advanced`).
        "estimatefeeadvanced" => {
            let count = |i: usize, default: u64| -> Result<usize, Value> {
                match params.and_then(|p| p.get(i)) {
                    None | Some(Value::Null) => Ok(default as usize),
                    Some(v) => match v.as_u64() {
                        Some(n) if n <= crate::analytics::FEE_ESTIMATE_MAX_IO => Ok(n as usize),
                        _ => Err(json!({ "error": format!(
                            "params: [n_inputs, n_outputs], integers in [0, {}]",
                            crate::analytics::FEE_ESTIMATE_MAX_IO) })),
                    },
                }
            };
            let (n_in, n_out) = match (count(0, 1), count(1, 2)) {
                (Ok(i), Ok(o)) => (i, o),
                (Err(e), _) | (_, Err(e)) => return e,
            };
            let fee = crate::analytics::estimate_fee_advanced(&state.mempool, Transaction::estimate_size(n_in, n_out));
            json!({
                // R3: satoshi amounts → decimal strings.
                "next_block_sats":  fee.next_block_sats.to_string(),
                "medium_priority":  fee.medium_priority.to_string(),
                "slow_priority":    fee.slow_priority.to_string(),
                "mempool_median":   fee.mempool_median.to_string(),
                "mempool_size":     fee.mempool_size,
                "recommended_gnb": format!("{:.8}", fee.medium_priority as f64 / 1e8),
                "tx_bytes":         fee.tx_bytes,
                "inputs":           n_in,
                "outputs":          n_out,
                "min_fee_sat":      crate::core::tokenomics::min_tx_fee_sat(fee.tx_bytes).to_string(),
                "feerate_sat_per_kb": {
                    "floor":      fee.floor_rate_per_kb.to_string(),
                    "medium":     fee.medium_rate_per_kb.to_string(),
                    "next_block": fee.next_block_rate_per_kb.to_string(),
                },
                "note": "absolute fees for a transaction of tx_bytes wire bytes (params [n_inputs, n_outputs], default [1, 2]); \
                         none below the consensus minimum for that size or the mempool's rolling minimum",
            })
        }

        "getmempoolstats" => {
            let stats = crate::analytics::mempool_stats(&state.mempool);
            let buckets: Vec<Value> = stats.buckets.iter().map(|b| json!({
                "range":    b.range,
                "tx_count": b.tx_count,
            })).collect();
            json!({
                "size":        stats.size,
                // R3: satoshi amounts → decimal strings (`avg_fee` is a
                // documented-lossy float, so it stays a JSON number).
                "total_fees":  stats.total_fees.to_string(),
                "min_fee":     stats.min_fee.to_string(),
                "max_fee":     stats.max_fee.to_string(),
                "median_fee":  stats.median_fee.to_string(),
                "avg_fee":     stats.avg_fee,
                "buckets":     buckets,
            })
        }

        "validateaddressverbose" => {
            let addr_str = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            validate_rpc_address(addr_str, true)
        }

        // ── End of Sprint B additions ──────────────────────────────────────

"gettxsbyblock" => {
            // Accept either hash (hex string, 64 chars) or height (number).
            let p0 = params.and_then(|p| p.get(0));
            let block_hash = match p0 {
                Some(v) if v.is_string() => {
                    let s = v.as_str().unwrap();
                    if s.len() == 64 {
                        hex::decode(s).ok().and_then(|b| {
                            let mut h = [0u8; 32];
                            if b.len() == 32 { h.copy_from_slice(&b); Some(h) } else { None }
                        })
                    } else {
                        // try parse as height-as-string
                        s.parse::<u64>().ok().and_then(|h| state.store.get_block_hash_at_height(h).ok().flatten())
                    }
                }
                Some(v) if v.is_u64() => {
                    let h = v.as_u64().unwrap();
                    state.store.get_block_hash_at_height(h).ok().flatten()
                }
                _ => None,
            };

            match block_hash {
                Some(bh) => {
                    match state.store.get_block(&bh) {
                        Ok(Some(block)) => {
                            let txs: Vec<serde_json::Value> = block.transactions.iter().map(|tx| {
                                let txid = tx.txid();
                                // Sprint 1.d: size is length of stratum (Bitcoin-format) bytes.
                                // include_script_sig=true matches what lives on the wire and on disk.
                                let size_bytes = tx.to_wire_bytes(true).len() as u32;
                                // Fee: sum(inputs_value) - sum(outputs_value). For coinbase, fee = 0 by convention.
                                let outputs_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
                                let fee_sats: u64 = if tx.is_coinbase() {
                                    0
                                } else {
                                    let inputs_total: u64 = tx.inputs.iter().map(|inp| {
                                        state.store.get_utxo_including_spent(&inp.prev_txid, inp.prev_index)
                                            .ok().flatten().map(|o| o.value).unwrap_or(0)
                                    }).sum();
                                    inputs_total.saturating_sub(outputs_total)
                                };
                                json!({
                                    "txid":           hex::encode(&txid),
                                    "size_bytes":     size_bytes,
                                    "inputs_count":   tx.inputs.len(),
                                    "outputs_count":  tx.outputs.len(),
                                    // R3: satoshi amount → decimal string.
                                    "fee_sats":       fee_sats.to_string(),
                                    "is_coinbase":    tx.is_coinbase(),
                                })
                            }).collect();
                            json!({
                                "block_hash":      hex::encode(&bh),
                                "block_height":    block.height,
                                "block_timestamp": block.header.timestamp,
                                "count":           txs.len(),
                                "txs":             txs,
                            })
                        }
                        Ok(None) => json!({ "error": "block not found" }),
                        Err(e) => storage_err_response(&e),
                    }
                }
                None => json!({ "error": "invalid block identifier (expected hex hash or height)" }),
            }
        }

// ── INSERT: getaddressbalance_at_height ──

"getaddressbalance_at_height" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let height = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(0);

            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Ok(addr_hash) => {
                    // NET-12: streamed and cancellable (heavy method).
                    match state.store.balance_at_height_cancellable(&addr_hash, height, &state.cancel) {
                        Ok((balance, _)) => {
                            let tx_count = match state.store.count_address_history_cancellable(&addr_hash, 0, height, &state.cancel) {
                                Ok(n) => n,
                                Err(_) => return json!({ "error": "cancelled" }),
                            };
                            json!({
                                "address":               addr,
                                "height":                height,
                                // R3: satoshi amount → decimal string.
                                "balance_sats":          balance.to_string(),
                                "balance_gnb":          balance as f64 / 1e8,
                                "tx_count_up_to_height": tx_count,
                            })
                        }
                        Err(e) => storage_err_response(&e),
                    }
                }
                Err(error) => json!({ "error": error }),
            }
        }

        // Bloch-SIS-Linux L3: attestation status (pluggable provider; reports
        // attested=false when no TEE is active).
        "getattestation" => {
            // Optional freshness nonce (params[0]) echoed into the report and,
            // for a real TEE, bound into the quote's report-data.
            let nonce = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).map(String::from);
            serde_json::to_value(crate::attestation::current_report(nonce))
                .unwrap_or_else(|e| json!({ "error": format!("attestation serialize: {}", e) }))
        }

        // NET-13: never echo an unbounded caller-supplied string.
        _ => json!({ "error": format!("unknown method: {}", method_for_log(method)) }),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Read-only static descriptor inspection; all syntax and script derivation
/// use the same codec as offline CLI and WASM. The caller cannot choose a
/// different network, import a pool, or mutate a wallet through these RPCs.
fn inspect_rpc_descriptor(params: Option<&Value>) -> Result<Value, String> {
    let args = params.and_then(Value::as_array).filter(|args| args.len() == 1)
        .ok_or("expected exactly one checksummed descriptor in an array")?;
    let descriptor = args[0].as_str().ok_or("descriptor must be a string")?;
    let network = match crate::core::node_chain_id() {
        crate::core::ChainId::Mainnet => "mainnet",
        crate::core::ChainId::Testnet => "testnet",
    };
    gnb_crypto::wallet::descriptor::public_request(&json!({
        "action": "inspect", "network": network, "descriptor": descriptor,
    }))
}

fn rpc_address_network() -> crate::address::Network {
    match crate::core::node_chain_id() {
        crate::core::ChainId::Mainnet => crate::address::Network::Mainnet,
        crate::core::ChainId::Testnet => crate::address::Network::Testnet,
    }
}

/// Local RPC policy, not a transaction or block rule. All address entry
/// points use the same check before querying this chain's indices.
/// Modeled on Bitcoin Core v30.0 DecodeDestination / IsValidDestinationString:
/// the decoder checks prefixes and HRPs against the selected chain parameters.
/// https://github.com/bitcoin/bitcoin/blob/v30.0/src/key_io.cpp#L76-L128
fn require_rpc_address_network(network: crate::address::Network) -> Result<(), crate::address::AddressError> {
    let expected = rpc_address_network();
    if network != expected {
        return Err(crate::address::AddressError::WrongNetwork { expected, got: network });
    }
    Ok(())
}

fn address_query_error(error: crate::address::AddressError) -> String {
    match error {
        crate::address::AddressError::WrongNetwork { .. } => error.to_string(),
        _ => "invalid address".into(),
    }
}

/// The legacy holder/history index is keyed by a single-key hash, never the
/// textual encoding. Policy scripts remain outside these 20-byte indices.
fn parse_address(addr: &str) -> Result<[u8; 20], String> {
    let address = crate::address::Address::parse(addr).map_err(address_query_error)?;
    require_rpc_address_network(address.network()).map_err(address_query_error)?;
    Ok(*address.hash())
}

/// UTXO indices use the full output script, including the policy tag/hash.
fn parse_rpc_destination(addr: &str) -> Result<Vec<u8>, String> {
    let (network, script) = crate::address::destination_script(addr).map_err(address_query_error)?;
    require_rpc_address_network(network).map_err(address_query_error)?;
    Ok(script)
}

/// `valid`/`isvalid` means usable on this node's network. `checksum` remains
/// syntactic: a well-formed address for the other network has checksum=true,
/// validity=false and a reason. Conversion fields are only emitted on success.
fn validate_rpc_address(addr: &str, verbose: bool) -> Value {
    use crate::address::{Address, Network, PolicyAddress};
    let field = if verbose { "valid" } else { "isvalid" };
    let mut result = json!({ "address": addr });
    result[field] = json!(false);
    let (network, script) = match crate::address::destination_script(addr) {
        Ok(parsed) => parsed,
        Err(error) => {
            result["reason"] = json!(error.to_string());
            if !verbose {
                // Preserve the legacy malformed-address network hint.
                result["network"] = json!(if addr.starts_with(MAINNET_PREFIX) { "mainnet" }
                    else if addr.starts_with(TESTNET_PREFIX) { "testnet" } else { "unknown" });
                result["checksum"] = json!(false);
            }
            return result;
        }
    };
    result["network"] = json!(match network { Network::Mainnet => "mainnet", Network::Testnet => "testnet" });
    if !verbose { result["checksum"] = json!(true); }
    if let Err(error) = require_rpc_address_network(network) {
        result["reason"] = json!(error.to_string());
        return result;
    }
    let (canonical, bech32m, hash, prefix) = if let Ok(hash) = <[u8; 20]>::try_from(script.as_slice()) {
        let address = Address::from_hash(hash, network);
        (address.to_string(), address.to_bech32m(), hex::encode(hash), network.prefix())
    } else if let Some(address) = PolicyAddress::from_script(&script, network) {
        (address.to_string(), address.to_bech32m(), hex::encode(&script[1..]),
            match network { Network::Mainnet => crate::address::POLICY_MAINNET_PREFIX,
                Network::Testnet => crate::address::POLICY_TESTNET_PREFIX })
    } else {
        result["reason"] = json!("unsupported address script");
        return result;
    };
    result[field] = json!(true);
    result["canonical_address"] = json!(canonical);
    result["bech32m"] = json!(bech32m);
    if verbose {
        result["hash_hex"] = json!(hash);
        result["prefix"] = json!(prefix);
    }
    result
}

/// Format a transaction for JSON output
/// The `transactions` entries of `getblocktemplate`: `txid`, `fee` (decimal
/// string, R3), `data` (wire hex) and `depends` — the 1-based positions of
/// the entry's in-template parents (`BlockTemplate::depends`, BIP22
/// semantics). A subset of the entries is mineable only if it is closed
/// under `depends` and keeps the listed order.
fn template_tx_entries(tmpl: &crate::template::BlockTemplate) -> Vec<Value> {
    tmpl.transactions.iter().zip(tmpl.depends()).map(|((tx, fee), depends)| {
        json!({
            "txid":    hex::encode(tx.txid()),
            // R3: satoshi amount → decimal string.
            "fee":     fee.to_string(),
            "data":    hex::encode(tx.to_wire_bytes(true)),
            "depends": depends,
        })
    }).collect()
}

/// A block's PoWit section for explorers: witness shares, KES-signed
/// attestations (with the epoch leaf each one used) and equivocation proofs.
fn format_powit(p: &crate::core::powit::PowitBody) -> Value {
    let cp = |c: &crate::core::powit::Checkpoint| json!({ "slot": c.height, "hash": hex::encode(c.hash) });
    let att = |a: &crate::core::powit::Attestation| json!({
        "witness":    hex::encode(a.key_id()),
        "source":     cp(&a.source),
        "target":     cp(&a.target),
        "kes_epoch":  a.sig.index,
        "kes_depth":  a.witness.depth,
        "kes_root":   hex::encode(a.witness.root),
        "sig_bytes":  a.sig.sig.len(),
    });
    json!({
        "shares": p.shares.iter().map(|s| json!({
            "id":       hex::encode(crate::core::witness_share::share_id(s)),
            "attested": hex::encode(s.attested),
            "witness":  hex::encode(s.witness),
            "payout":   hex::encode(&s.payout),
        })).collect::<Vec<_>>(),
        "attestations": p.attestations.iter().map(att).collect::<Vec<_>>(),
        "evidence": p.evidence.iter().map(|e| json!({
            "witness": hex::encode(e.a.key_id()), "a": att(&e.a), "b": att(&e.b),
        })).collect::<Vec<_>>(),
    })
}

fn format_tx(tx: &Transaction) -> Value {
    json!({
        "txid":     hex::encode(tx.txid()),
        "version":  tx.version,
        "coinbase": tx.is_coinbase(),
        "inputs":   tx.inputs.iter().map(|inp| json!({
            "prev_txid":  hex::encode(inp.prev_txid),
            "prev_index": inp.prev_index,
            "sequence":   inp.sequence,
        })).collect::<Vec<_>>(),
        "outputs":  tx.outputs.iter().enumerate().map(|(i, out)| json!({
            "index":         i,
            // R3 (docs/specs/BLOCH-RPC-V4.md): satoshi amount → decimal string.
            "value":         out.value.to_string(),
            "gnb":          out.value as f64 / 1e8,
            "script_pubkey": hex::encode(&out.script_pubkey),
        })).collect::<Vec<_>>(),
        "locktime": tx.locktime,
    })
}

/// Validate a transaction for mempool/broadcast acceptance (no pool context).
/// Returns the fee (total_in - total_out) on success.
///
/// Delegates to the shared admission rules (`mempool::admission`, audit
/// MEM-1/4/5): size, standardness (dust, zero-value, canonical limits,
/// MoneyRange), duplicate inputs, UTXO presence, coinbase maturity at
/// `next_block_height` (`0` skips it), consensus minimum fee and relay fee,
/// then the hybrid signatures. `sendrawtransaction` itself calls
/// `admission::admit`, which also runs the pool-relative checks.
#[allow(dead_code)]
fn validate_tx_for_mempool(tx: &Transaction, store: &Arc<Storage>, next_block_height: u64) -> Result<u64, String> {
    let policy = crate::mempool::admission::AdmissionPolicy {
        next_block_height,
        check_signatures: true,
        use_reject_filter: false,
    };
    crate::mempool::admission::check_transaction(store, None, tx, &policy).map_err(|e| e.to_string())
}


// ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//      look for the "parse_address" helper (around line 560+)
//
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// V4 rule R3 (docs/specs/BLOCH-RPC-V4.md): every satoshi-denominated field is a
// decimal STRING on the JSON-RPC wire. The V4 supply exceeds i64::MAX and is
// ~1000× JavaScript's Number.MAX_SAFE_INTEGER, so a JSON number silently
// corrupts large amounts in every browser client. Internally values stay u64.
// `format_tx` is the shared output formatter behind getblock / gettransaction /
// decoderawtransaction, so pinning it pins those three response shapes.
// ─────────────────────────────────────────────────────────────────────────────
// ── L-10 / L-11 regressions ─────────────────────────────────────────────────

#[cfg(test)]
mod l10_l11_id_and_batch_tests {
    use super::*;

    /// L-10 core regression: an oversized `id` string must be truncated,
    /// never echoed at full length.
    #[test]
    fn oversized_string_id_is_truncated() {
        let huge = "x".repeat(MAX_ECHOED_ID_LEN * 10);
        let capped = cap_echoed_id(Value::String(huge));
        match capped {
            Value::String(s) => assert!(
                s.len() <= MAX_ECHOED_ID_LEN,
                "capped id is {} bytes, expected <= {}", s.len(), MAX_ECHOED_ID_LEN
            ),
            other => panic!("expected a String, got {:?}", other),
        }
    }

    /// A short, legitimate id passes through unchanged.
    #[test]
    fn short_string_id_is_unchanged() {
        assert_eq!(cap_echoed_id(json!("req-42")), json!("req-42"));
    }

    /// Numbers and null are the spec-legitimate id shapes and pass through.
    #[test]
    fn number_and_null_ids_pass_through() {
        assert_eq!(cap_echoed_id(json!(42)), json!(42));
        assert_eq!(cap_echoed_id(json!(null)), json!(null));
    }

    /// A non-spec id shape (bool/array/object) is replaced with null rather
    /// than echoed — nothing legitimate sends these, and echoing an
    /// attacker-shaped structure back verbatim is unnecessary surface.
    #[test]
    fn non_scalar_ids_become_null() {
        assert_eq!(cap_echoed_id(json!(true)), json!(null));
        assert_eq!(cap_echoed_id(json!([1, 2, 3])), json!(null));
        assert_eq!(cap_echoed_id(json!({"a": 1})), json!(null));
    }

    /// Truncation must never split a multi-byte UTF-8 character — reusing
    /// `network::truncate_utf8` is what guarantees this; pin it here too so a
    /// future change to this call site cannot silently regress to a raw
    /// byte-index slice.
    #[test]
    fn truncation_is_utf8_safe() {
        // 300 copies of a 3-byte character comfortably straddles a naive
        // byte-256 cut point.
        let s: String = "€".repeat(300);
        let capped = cap_echoed_id(Value::String(s));
        match capped {
            Value::String(s) => {
                assert!(s.len() <= MAX_ECHOED_ID_LEN);
                assert!(std::str::from_utf8(s.as_bytes()).is_ok(), "must remain valid UTF-8");
            }
            other => panic!("expected a String, got {:?}", other),
        }
    }

    /// L-11 core regression: the batch-request response must be the
    /// JSON-RPC 2.0 Invalid Request code, not a 200 with a garbled method name.
    #[test]
    fn batch_response_is_invalid_request_code() {
        let v = batch_not_supported_response();
        assert_eq!(v["error"]["code"], json!(-32600));
        assert_eq!(v["jsonrpc"], json!("2.0"));
    }
}

// ── L-5 regression: storage errors never reach the caller verbatim ─────────

#[cfg(test)]
mod l5_storage_error_sanitization_tests {
    use super::*;

    /// The core L-5 property: whatever detail `StorageError` carries (here, a
    /// fabricated RocksDB-shaped message with a filesystem path, mirroring
    /// what `storage/mod.rs`'s real `.map_err(|e| StorageError::ReadFailed(e.to_string()))`
    /// sites would actually produce) must NOT appear anywhere in the JSON
    /// handed back to the RPC caller.
    #[test]
    fn caller_response_never_contains_the_storage_detail() {
        let sensitive = StorageError::ReadFailed(
            "IO error: /var/lib/bloch-data/CF_BLOCKS/000123.sst: No such file or directory".into(),
        );
        let resp = storage_err_response(&sensitive);
        let rendered = resp.to_string();
        assert!(
            !rendered.contains("/var/lib/bloch-data"),
            "filesystem path from the underlying storage error leaked into the RPC response: {}",
            rendered
        );
        assert!(
            !rendered.contains("CF_BLOCKS"),
            "column-family internal name leaked into the RPC response: {}",
            rendered
        );
    }

    /// Review finding (NET-12 regression of L-5): the explorer statistics
    /// (`getrichlist`, `getsupplydistribution`, `getaddresscount`,
    /// `getchainstats`, `gethashrate`) return a typed `StatsError`; a
    /// storage failure is answered with the sanitised response and its
    /// detail never reaches the caller. (`StatsError` is not `Serialize`
    /// and its `Display` of a storage failure carries no detail, so no
    /// handler can echo it.) Pre-fix they returned `e.to_string()` of the
    /// `StorageError` — e.g. a RocksDB message with the data-dir path.
    #[test]
    fn stats_storage_errors_are_sanitised() {
        use crate::analytics::StatsError;
        let sensitive = StatsError::Storage(StorageError::ReadFailed(
            "IO error: /var/lib/gnb/db/000123.sst: No such file or directory".into(),
        ));
        let r = stats_err_response(&sensitive);
        assert_eq!(r, json!({ "error": "internal storage error", "code": "STORAGE_ERROR" }));
        assert!(!r.to_string().contains("/var/lib"), "{r}");
        assert!(!sensitive.to_string().contains("/var/lib"), "Display carries no detail either");
        assert_eq!(stats_err_response(&StatsError::Cancelled), json!({ "error": "cancelled" }));
        assert!(stats_err_response(&StatsError::NotReady)["error"].as_str().unwrap().contains("not built"));
        assert!(stats_err_response(&StatsError::NoTip).get("code").is_none());
    }

    /// Every `StorageError` variant must produce the SAME stable response —
    /// nothing about which failure mode occurred (open/read/write/serialize)
    /// should be distinguishable from the response shape either.
    #[test]
    fn every_storage_error_variant_yields_the_identical_stable_response() {
        let variants = [
            StorageError::OpenFailed("detail a".into()),
            StorageError::CfNotFound("detail b".into()),
            StorageError::SerializeFailed("detail c".into()),
            StorageError::DeserializeFailed("detail d".into()),
            StorageError::WriteFailed("detail e".into()),
            StorageError::ReadFailed("detail f".into()),
        ];
        let responses: Vec<Value> = variants.iter().map(storage_err_response).collect();
        for r in &responses {
            assert_eq!(*r, responses[0], "every StorageError variant must map to the identical sanitized response");
        }
        assert_eq!(responses[0], json!({ "error": "internal storage error", "code": "STORAGE_ERROR" }));
    }
}

#[cfg(test)]
mod r3_amount_encoding_tests {
    use super::*;
    use crate::core::{TxInput, TxOutput};

    fn tx_with_output(value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [9u8; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        }
    }

    #[test]
    fn tx_output_value_serializes_as_a_decimal_string() {
        let v = format_tx(&tx_with_output(354_617_540_000_000_000));
        let out = &v["outputs"][0];
        assert!(out["value"].is_string(), "R3: `value` must be a JSON string, got {}", out["value"]);
        assert_eq!(out["value"].as_str().unwrap(), "354617540000000000");
        // The display-only float companion stays a JSON number (lossy by design).
        assert!(out["gnb"].is_number(), "`gnb` stays a float");
    }

    #[test]
    fn amounts_past_the_javascript_safe_integer_survive_the_wire() {
        // A value above 2^53 round-trips exactly through the string form; the
        // same value as a JSON number is what R3 exists to prevent.
        let big = u64::MAX;
        let v = format_tx(&tx_with_output(big));
        let s = v["outputs"][0]["value"].as_str().expect("string amount");
        assert_eq!(s.parse::<u64>().unwrap(), big);
        assert!(big > 9_007_199_254_740_991, "test value must exceed MAX_SAFE_INTEGER");
    }
}

/// Format a hashrate in H/s into human-readable units (H/s, KH/s, MH/s, GH/s, TH/s, PH/s, EH/s).
fn format_hashrate(hs: f64) -> String {
    const UNITS: &[(&str, f64)] = &[
        ("EH/s", 1e18),
        ("PH/s", 1e15),
        ("TH/s", 1e12),
        ("GH/s", 1e9),
        ("MH/s", 1e6),
        ("KH/s", 1e3),
    ];
    for (label, threshold) in UNITS {
        if hs >= *threshold {
            return format!("{:.2} {}", hs / threshold, label);
        }
    }
    format!("{:.2} H/s", hs)
}


// ─────────────────────────────────────────────────────────────────────────────
// C-R3-2 (Round-2 audit, LEG2-intra-dup) — intra-transaction double-spend on
// the RPC admission path. `validate_tx_for_mempool` (sendrawtransaction) had
// NO duplicate-outpoint check at all: a tx listing the SAME outpoint N times
// had its value counted N times and was admitted with an N×-inflated fee.
// The gossip-path twins live in main.rs `intra_tx_dup_tests`; the euvm path
// was already covered (`euvm_admission_tests::intra_tx_double_spend_rejected`).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod c_r3_2_intra_dup_tests {
    use super::*;
    use crate::core::{TxInput, TxOutput};
    use tempfile::TempDir;

    fn mk_store() -> (TempDir, Arc<Storage>) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("storage"));
        (tmp, store)
    }

    /// A tx spending the SAME confirmed 100_000-sat outpoint `n` times, every
    /// input carrying a VALID hybrid signature over its own sighash — without
    /// the duplicate check nothing else rejects it.
    fn dup_input_tx(store: &Arc<Storage>, n: usize, out_value: u64) -> Transaction {
        use sha3::{Digest as _, Sha3_256};
        let (pk, sk) = crate::crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
        let prev_txid = [0x42u8; 32];
        store.put_utxo(&prev_txid, 0,
            &TxOutput { value: 100_000, script_pubkey: pk_hash })
            .expect("put_utxo");

        let mut tx = Transaction {
            version: 1,
            inputs: (0..n).map(|_| TxInput {
                prev_txid, prev_index: 0, script_sig: vec![], sequence: u32::MAX,
            }).collect(),
            outputs: vec![TxOutput { value: out_value, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        };
        for i in 0..n {
            let sighash = tx.sighash(i, crate::core::node_chain_id());
            let sig = crate::crypto::sign(&sk, &sighash).expect("sign");
            tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &pk);
        }
        tx
    }

    /// sendrawtransaction admission: a 2-duplicate-input tx spending a 100k
    /// outpoint but emitting 150k must be refused. Without the fix it was
    /// ADMITTED with fee = 50_000 (the outpoint's value counted twice).
    #[test]
    fn rpc_path_refuses_intra_tx_duplicate_outpoint() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 2, 150_000);
        let err = validate_tx_for_mempool(&tx, &store, 0)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// N=3 duplication is refused too (the check is set-based, not pairwise).
    #[test]
    fn rpc_path_refuses_triple_duplicate() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 3, 290_000);
        let err = validate_tx_for_mempool(&tx, &store, 0)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// Control: the SAME signed shape with a single input and honest amounts
    /// is still admitted with the right fee.
    #[test]
    fn rpc_single_input_control_still_admitted() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 1, 70_000);
        let fee = validate_tx_for_mempool(&tx, &store, 0)
            .expect("valid single-input spend must be admitted");
        assert_eq!(fee, 30_000);
    }
}

// ── R3-audit H-R3-5 tests: CORS layer + heavy-read gate ─────────────────────
//
// The auth-layer refusal logic (Host/Origin/loopback/WRITE_METHODS) is
// unit-tested in `auth.rs`; these tests pin the two pieces that live here:
// the mounted CORS layer is NOT permissive, and the heavy-read gate bounds
// the O(chain) analytics methods.
#[cfg(test)]
mod h_r3_5_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, HeaderValue, Method, Request, StatusCode};
    use tower::util::ServiceExt; // oneshot

    fn router_with(origins: &[&str]) -> Router {
        let origins: Vec<String> = origins.iter().map(|s| s.to_string()).collect();
        Router::new()
            .route("/", axum::routing::post(|| async { "ok" }))
            .layer(build_cors_layer(&origins))
    }

    async fn preflight(router: Router, origin: &str) -> axum::http::Response<Body> {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .body(Body::empty())
            .unwrap();
        router.oneshot(req).await.unwrap()
    }

    /// The core regression: with the default (empty) origin allowlist, a
    /// hostile page's preflight gets NO Access-Control-Allow-Origin grant.
    /// `CorsLayer::permissive()` echoed the origin back — this test FAILS on
    /// the pre-fix wiring.
    #[tokio::test]
    async fn default_config_grants_no_cors_to_any_origin() {
        let resp = preflight(router_with(&[]), "https://evil.example").await;
        assert!(
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "no origin allowlisted, yet a CORS grant was emitted: {:?}",
            resp.headers()
        );
    }

    #[tokio::test]
    async fn allowlisted_origin_gets_cors_unlisted_does_not() {
        let router = router_with(&["https://wallet.posternlabs.com"]);
        let ok = preflight(router.clone(), "https://wallet.posternlabs.com").await;
        assert_eq!(
            ok.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://wallet.posternlabs.com")),
        );
        let bad = preflight(router, "https://evil.example").await;
        assert!(bad.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "unlisted origin must not receive a CORS grant");
    }

    /// Simple (non-preflighted) POST: the response must carry no grant for an
    /// unlisted origin, so a browser page cannot read it.
    #[tokio::test]
    async fn simple_post_response_carries_no_grant_for_unlisted_origin() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = router_with(&[]).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK); // handler ran (gate lives in handle_rpc)
        assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    // ── HeavyGate ───────────────────────────────────────────────────

    #[test]
    fn heavy_methods_are_exactly_the_five_scanners() {
        for m in ["getsupplydistribution", "getchainstats", "gethashrate",
                  "getaddresscount", "getaddressbalance_at_height"] {
            assert!(HeavyGate::is_heavy(m), "{m} must be gated");
        }
        assert!(!HeavyGate::is_heavy("getblockcount"));
        assert!(!HeavyGate::is_heavy("sendrawtransaction"));
    }

    #[test]
    fn heavy_gate_serves_cache_instead_of_rescanning() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let gate = HeavyGate::new(std::time::Duration::from_secs(60));
        let scans = AtomicU32::new(0);
        for _ in 0..10 {
            let v = gate.run("getsupplydistribution|".into(), || {
                scans.fetch_add(1, Ordering::SeqCst);
                json!({"tiers": []})
            });
            assert_eq!(v, json!({"tiers": []}));
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1,
            "10 identical heavy calls inside the TTL must run exactly 1 scan");
    }

    #[test]
    fn heavy_gate_refuses_concurrent_second_scan() {
        use std::sync::Arc as StdArc;
        let gate = StdArc::new(HeavyGate::new(std::time::Duration::from_secs(60)));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let g2 = gate.clone();
        let t = std::thread::spawn(move || {
            g2.run("getchainstats|".into(), || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap(); // hold the scan permit
                json!({"total_blocks": 1})
            })
        });
        started_rx.recv().unwrap(); // first scan is in flight
        // A different heavy key cannot start a second concurrent scan.
        let v = gate.run("getsupplydistribution|".into(), || json!({"should": "not run"}));
        assert!(v.get("error").is_some(),
            "second concurrent heavy scan must be refused, got {v}");
        release_tx.send(()).unwrap();
        assert_eq!(t.join().unwrap(), json!({"total_blocks": 1}));
    }

    #[test]
    fn heavy_gate_cache_is_bounded() {
        let gate = HeavyGate::new(std::time::Duration::from_secs(3600));
        // Parameterised heavy method: attacker varies params to grow the map.
        for i in 0..(HEAVY_READ_CACHE_MAX_KEYS * 4) {
            gate.run(format!("getaddressbalance_at_height|[\"addr{i}\",1]"), || json!(i));
        }
        assert!(gate.cache.lock().len() <= HEAVY_READ_CACHE_MAX_KEYS,
            "cache must stay bounded under key churn");
    }
}

// ── 2026-10 audit regressions: NET-12, NET-13, NET-14, NET-15, WAL-1 ───────
#[cfg(test)]
mod audit_2026_10_rpc_tests {
    include!("../../tests/support/pqpsbt_rpc_unit.rs");
    include!("../../tests/support/address_frontends_rpc.rs");
    include!("../../tests/support/descriptor_rpc.rs");
    use super::*;
    use crate::core::{Block, BlockHeader, MerkleRoot, TxInput, TxOutput};
    use tempfile::TempDir;

    /// An AppState over a fresh store and a linear DAG of `n` chain blocks
    /// spaced 30 s apart (the last 10 gaps are 60 s).
    fn state_with_chain(n: u8) -> (TempDir, AppState) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("storage"));
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis([0u8; 32], 1_000);
        let mut ts = 1_000u64;
        for i in 1..=n {
            ts += if i > n.saturating_sub(10) { 60 } else { 30 };
            dag.add_block([i; 32], vec![[i - 1; 32]], ts, 1).unwrap();
        }
        let (outbound_tx, _rx) = mpsc::channel(1);
        let state = AppState {
            node_state: Arc::new(RwLock::new(NodeState::default())),
            store,
            mempool: Arc::new(Mempool::new()),
            dag: Arc::new(RwLock::new(dag)),
            outbound_tx,
            api_key: None,
            require_auth_for_writes: false,
            require_auth_for_reads: false,
            rate_limiter: Arc::new(auth::RateLimiterSet::new(60, 5)),
            trust_private_ranges: false,
            allowed_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(Vec::new()),
            trust_loopback: false,
            heavy_gate: Arc::new(HeavyGate::new(HEAVY_READ_CACHE_TTL)),
            template_gate: Arc::new(HeavyGate::for_templates()),
            pqpsbt_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            submit_block: None,
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            chain_admin: None,
            large_bodies: Arc::new(tokio::sync::Semaphore::new(RPC_LARGE_BODY_PERMITS)),
            large_bodies_reserved: Arc::new(tokio::sync::Semaphore::new(RPC_LARGE_BODY_RESERVED_PERMITS)),
            proxy_client_header: auth::DEFAULT_PROXY_CLIENT_HEADER.into(),
            tx_verify_budget: Arc::new(auth::ByteBudget::new(ANON_TX_VERIFY_BURST_BYTES, ANON_TX_VERIFY_BYTES_PER_SEC)),
            caller_trusted: false,
            // These fixture chains (work 1 per block) are far below
            // mainnet's minimum chain work; the test of `getdaginfo`'s
            // `minimum_chain_work` sets it.
            min_chain_work: 0,
        };
        (tmp, state)
    }

    #[test]
    fn method_labels_are_bounded_and_logs_truncated() {
        assert_eq!(method_label("getblockcount"), "getblockcount");
        assert_eq!(method_label(&"x".repeat(1 << 20)), "unknown");
        assert_eq!(method_label("getBlockCount"), "unknown");
        let logged = method_for_log(&"\u{1b}[31m".repeat(10_000));
        assert!(logged.len() < 4 * MAX_LOGGED_METHOD_LEN, "{}", logged.len());
        assert!(!logged.contains('\u{1b}'), "control characters are escaped");
    }

    /// Every arm of `dispatch` is a known method (so it gets its own metrics
    /// label) and every known method has an arm.
    #[test]
    fn known_methods_list_matches_dispatch() {
        let src = include_str!("mod.rs");
        let start = src.find("async fn dispatch(").unwrap();
        let end = src[start..].find("// ── Helpers").unwrap() + start;
        let mut arms = std::collections::BTreeSet::new();
        for line in src[start..end].lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix('"') {
                if let Some(q) = rest.find('"') {
                    if rest[q + 1..].trim_start().starts_with("=>") {
                        arms.insert(rest[..q].to_string());
                    }
                }
            }
        }
        let known: std::collections::BTreeSet<String> = KNOWN_RPC_METHODS.iter().map(|s| s.to_string()).collect();
        assert_eq!(arms, known);
    }

    /// A cached `getblocktemplate` never outlives the chain it was built on:
    /// its key changes with a new block. A pool transaction does not change
    /// it (the template catches up within TEMPLATE_CACHE_TTL), so a miner
    /// polling a busy pool does not rebuild on every call. Functional
    /// counterpart: test/functional/mining_getblocktemplate_submitblock.py.
    /// (Invalidation and body arrival: the test below.)
    #[test]
    fn template_cache_key_follows_new_blocks_not_the_pool() {
        let (_tmp, state) = state_with_chain(3);
        let k0 = template_cache_key(None, &state);
        assert_eq!(k0, template_cache_key(None, &state), "stable while nothing changes");

        let tx = crate::core::Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [7; 32], prev_index: 0, script_sig: vec![1; 8], sequence: 0 }],
            outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![2; 20] }],
            locktime: 0,
        };
        state.mempool.add(tx, 1_000_000).expect("pool accepts the fixture");
        assert_eq!(template_cache_key(None, &state), k0, "a pool change alone keeps the key");

        state.dag.write().add_block([9; 32], vec![[3; 32]], 2_000, 1).unwrap();
        assert_ne!(template_cache_key(None, &state), k0, "a new tip must miss the cached template");
        assert_ne!(template_cache_key(Some(&json!([{"x": 1}])), &state), template_cache_key(None, &state));
    }

    /// What a template build returns, as far as the cache reads it: the
    /// parents and height `template_parents_and_height` gives on the DAG at
    /// build time (the fields the builder copies from the template it built),
    /// and `n` to tell builds apart.
    fn fake_template(state: &AppState, n: u32) -> Value {
        let (parents, height) = {
            let dag = state.dag.read();
            crate::template::template_parents_and_height(&dag, &state.store)
        };
        json!({"template": n, "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(), "height": height})
    }

    /// getblocktemplate has its own gate: while a public analytics scan
    /// holds the HeavyGate's permit, a template is still built (it used to
    /// be answered "busy"), and analytics are still refused; a second
    /// template call with the same tips is served from the template cache,
    /// a new tip rebuilds at once.
    #[test]
    fn template_requests_are_not_blocked_by_an_analytics_scan() {
        let (_tmp, state) = state_with_chain(3);
        let builds = std::cell::Cell::new(0u32);
        let build = || { builds.set(builds.get() + 1); fake_template(&state, builds.get()) };
        let scan = state.heavy_gate.scan.lock(); // an analytics scan in flight
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, build)["template"], 1);
        let refused = gated_dispatch("getrichlist", None, &state, || json!({"should": "not run"}));
        assert!(refused["error"].as_str().unwrap_or("").contains("busy"), "{refused}");
        drop(scan);
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, build)["template"], 1,
            "same tips: served from the template cache");
        state.dag.write().add_block([9; 32], vec![[3; 32]], 2_000, 1).unwrap();
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, build)["template"], 2,
            "a new tip rebuilds at once");
        assert_eq!(builds.get(), 2);
        assert_eq!(gated_dispatch("getblockcount", None, &state, || json!(7)), json!(7));
        assert!(TEMPLATE_CACHE_TTL <= std::time::Duration::from_secs(5));
    }

    /// A template call that finds another template build in flight is told
    /// so, not that "another heavy analytics scan" is (the template gate
    /// answered with the analytics gate's text); analytics keep theirs.
    #[test]
    fn a_busy_template_gate_names_the_template_build() {
        let (_tmp, state) = state_with_chain(3);
        let build = state.template_gate.scan.lock(); // a template build in flight
        let busy = gated_dispatch("getblocktemplate", None, &state, || json!({"should": "not run"}));
        let text = busy["error"].as_str().unwrap_or("");
        assert!(text.starts_with("busy:") && text.contains("getblocktemplate"), "{busy}");
        assert!(!text.contains("analytics"), "{busy}");
        drop(build);
        let scan = state.heavy_gate.scan.lock();
        let busy = gated_dispatch("getrichlist", None, &state, || json!({"should": "not run"}));
        assert!(busy["error"].as_str().unwrap_or("").contains("analytics scan"), "{busy}");
        drop(scan);
    }

    /// The template key changes with every block, so the template gate keeps
    /// only fresh templates, and few: an expired one is dropped when the next
    /// is stored, and at most TEMPLATE_CACHE_MAX_KEYS are kept, the newest.
    /// With the analytics gate's eviction (only once 64 keys were reached), a
    /// node kept up to 63 dead templates of up to about 2 MB each for good.
    #[test]
    fn the_template_gate_keeps_only_a_few_fresh_templates() {
        let gate = HeavyGate::with_limits(std::time::Duration::from_millis(30), TEMPLATE_CACHE_MAX_KEYS, TEMPLATE_BUSY);
        gate.run("parents=a".into(), || json!(1));
        std::thread::sleep(std::time::Duration::from_millis(60));
        gate.run("parents=b".into(), || json!(2));
        assert_eq!(gate.cache.lock().keys().cloned().collect::<Vec<_>>(), vec!["parents=b".to_string()],
            "the expired template must be dropped when the next one is stored");

        let gate = HeavyGate::for_templates();
        const { assert!(TEMPLATE_CACHE_MAX_KEYS < HEAVY_READ_CACHE_MAX_KEYS) };
        for i in 0..(HEAVY_READ_CACHE_MAX_KEYS * 2) {
            gate.run(format!("parents={i}"), || json!(i));
        }
        let last = HEAVY_READ_CACHE_MAX_KEYS * 2 - 1;
        {
            let cache = gate.cache.lock();
            assert_eq!(cache.len(), TEMPLATE_CACHE_MAX_KEYS);
            assert!(cache.contains_key(&format!("parents={last}")), "the newest template is kept");
        }
        // ... and served while fresh.
        assert_eq!(gate.run(format!("parents={last}"), || json!("rebuilt")), json!(last));
    }

    #[test]
    fn bind_addresses_resolve_ipv4_ipv6_and_names() {
        assert!(resolve_bind_address("127.0.0.1", 17210).unwrap().is_ipv4());
        assert!(resolve_bind_address("::1", 17210).unwrap().is_ipv6());
        assert!(resolve_bind_address("[::1]", 17210).unwrap().is_ipv6());
        assert!(resolve_bind_address("localhost", 17210).is_ok());
        assert!(resolve_bind_address("not a host name", 17210).is_err());
    }

    /// NET-14: an RPC server whose port is taken returns instead of taking
    /// the node down with it.
    #[tokio::test]
    async fn rpc_server_bind_failure_returns() {
        let (_tmp, state) = state_with_chain(1);
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = RpcConfig { port: busy.local_addr().unwrap().port(), ..RpcConfig::default() };
        tokio::time::timeout(std::time::Duration::from_secs(10), start_rpc_server(
            config, state.node_state.clone(), state.store.clone(), state.mempool.clone(),
            state.dag.clone(), state.outbound_tx.clone(), None, None,
        )).await.expect("a failed bind must end the RPC task");
    }

    /// Review finding (getblocktemplate x MEM-6 CPFP): every transaction
    /// entry carries `depends`, the 1-based positions of its in-template
    /// parents (BIP22), so an external miner that keeps a subset of the
    /// entries can keep it closed under dependencies.
    #[test]
    fn getblocktemplate_entries_list_in_template_dependencies() {
        let tx = |ins: &[([u8; 32], u32)], tag: u8| Transaction {
            version: 1,
            inputs: ins.iter().map(|(t, i)| TxInput { prev_txid: *t, prev_index: *i, script_sig: vec![tag; 8], sequence: u32::MAX }).collect(),
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![tag; 20] }, TxOutput { value: 1_000, script_pubkey: vec![tag; 20] }],
            locktime: 0,
        };
        let a = tx(&[([0xA0; 32], 0)], 1);
        let b = tx(&[(a.txid(), 0)], 2);
        let c = tx(&[([0xA1; 32], 0)], 3);
        let d = tx(&[(b.txid(), 1), (a.txid(), 1), (b.txid(), 0), ([0xA2; 32], 0)], 4);
        let tmpl = crate::template::BlockTemplate {
            parents: vec![[0; 32]], height: 1, blue_score: 1, bits: 0x2100_FFFF, parent_timestamp: 0,
            transactions: vec![(a.clone(), 10), (b.clone(), 20), (c.clone(), 30), (d.clone(), 40)],
            total_fees: 100, subsidy: 0, evicted: 0, tx_byte_budget: 0,
            activation_height: u64::MAX, hardened: false,
            powit: Default::default(),
        };
        let entries = template_tx_entries(&tmpl);
        let depends: Vec<Value> = entries.iter().map(|e| e["depends"].clone()).collect();
        assert_eq!(depends, vec![json!([]), json!([1]), json!([]), json!([1, 2])]);
        for (e, (t, fee)) in entries.iter().zip(&tmpl.transactions) {
            assert_eq!(e["txid"], hex::encode(t.txid()));
            assert_eq!(e["fee"], fee.to_string());
            assert_eq!(e["data"], hex::encode(t.to_wire_bytes(true)));
        }
    }

    /// Audit DAG-6: `invalidateblock` / `reconsiderblock` parse one block
    /// hash and reach the chain-admin hook with the right operation; a bad
    /// parameter never reaches it; an unwired node says so.
    #[tokio::test]
    async fn chain_admin_methods_reach_the_hook() {
        let (_tmp, mut state) = state_with_chain(1);
        let r = dispatch("invalidateblock", Some(&json!([hex::encode([7u8; 32])])), &state).await;
        assert!(r["error"].as_str().unwrap().contains("not wired"), "{r}");

        type Calls = parking_lot::Mutex<Vec<(ChainAdminOp, [u8; 32])>>;
        let calls: Arc<Calls> = Arc::default();
        let seen = calls.clone();
        state.chain_admin = Some(Arc::new(move |op, h| {
            seen.lock().push((op, h));
            Ok(json!({ "tip": hex::encode(h) }))
        }));
        let r = dispatch("invalidateblock", Some(&json!([hex::encode([7u8; 32])])), &state).await;
        assert_eq!(r["tip"], json!(hex::encode([7u8; 32])));
        let r = dispatch("reconsiderblock", Some(&json!([hex::encode([8u8; 32])])), &state).await;
        assert_eq!(r["tip"], json!(hex::encode([8u8; 32])));
        for bad in [json!([]), json!(["zz"]), json!([hex::encode([1u8; 31])])] {
            let r = dispatch("invalidateblock", Some(&bad), &state).await;
            assert!(r["error"].as_str().unwrap().contains("block hash"), "{r}");
        }
        assert_eq!(*calls.lock(), vec![
            (ChainAdminOp::Invalidate, [7u8; 32]),
            (ChainAdminOp::Reconsider, [8u8; 32]),
        ]);
    }

    /// PoWit audit findings 2 and 3: the finality settings reach the
    /// chain-admin hook with the right operation (`ignorefinalized` without a
    /// hash takes the current pin; `setfinalitycheckpoint` takes `none` and
    /// `default`, and a DAG height for a block the node may not hold yet,
    /// review MEDIUM 6), are admin methods, and `getfinalityinfo` reports the
    /// pin.
    #[tokio::test]
    async fn finality_admin_methods_reach_the_hook() {
        let (_tmp, mut state) = state_with_chain(3);
        type Calls = parking_lot::Mutex<Vec<(ChainAdminOp, [u8; 32])>>;
        let calls: Arc<Calls> = Arc::default();
        let seen = calls.clone();
        state.chain_admin = Some(Arc::new(move |op, h| {
            seen.lock().push((op, h));
            Ok(json!({ "ok": true }))
        }));
        let r = dispatch("ignorefinalized", Some(&json!([])), &state).await;
        assert!(r["error"].as_str().unwrap().contains("no finality pin"), "{r}");
        let pinned = state.dag.read().selected_tip().unwrap();
        state.dag.write().set_finalized(pinned, 2);
        let info = dispatch("getfinalityinfo", None, &state).await;
        assert_eq!(info["pin"]["hash"], json!(hex::encode(pinned)), "{info}");
        for (method, params) in [
            ("ignorefinalized", json!([])),
            ("ignorefinalized", json!([hex::encode([5u8; 32])])),
            ("reconsiderfinalized", json!([hex::encode([5u8; 32])])),
            ("setfinalitycheckpoint", json!([hex::encode([6u8; 32])])),
            ("setfinalitycheckpoint", json!([hex::encode([7u8; 32]), 20])),
            ("setfinalitycheckpoint", json!([hex::encode([7u8; 32]), "21"])),
            ("setfinalitycheckpoint", json!(["none"])),
            ("setfinalitycheckpoint", json!(["default"])),
        ] {
            let r = dispatch(method, Some(&params), &state).await;
            assert_eq!(r["ok"], json!(true), "{method} {params}: {r}");
        }
        let r = dispatch("setfinalitycheckpoint", Some(&json!(["zz"])), &state).await;
        assert!(r["error"].as_str().unwrap().contains("block hash"), "{r}");
        let r = dispatch("setfinalitycheckpoint", Some(&json!([hex::encode([7u8; 32]), "x"])), &state).await;
        assert!(r["error"].as_str().unwrap().contains("DAG height"), "{r}");
        assert_eq!(*calls.lock(), vec![
            (ChainAdminOp::IgnoreFinalized, pinned),
            (ChainAdminOp::IgnoreFinalized, [5u8; 32]),
            (ChainAdminOp::ReconsiderFinalized, [5u8; 32]),
            (ChainAdminOp::SetFinalityCheckpoint, [6u8; 32]),
            (ChainAdminOp::SetFinalityCheckpointAt(20), [7u8; 32]),
            (ChainAdminOp::SetFinalityCheckpointAt(21), [7u8; 32]),
            (ChainAdminOp::DisableFinalityCheckpoint, [0u8; 32]),
            (ChainAdminOp::DefaultFinalityCheckpoint, [0u8; 32]),
        ]);
        for m in ["ignorefinalized", "reconsiderfinalized", "setfinalitycheckpoint"] {
            assert!(auth::ADMIN_METHODS.contains(&m) && auth::WRITE_METHODS.contains(&m), "{m}");
        }
        assert!(!auth::WRITE_METHODS.contains(&"getfinalityinfo"));
    }

    /// WAL-1: `getrawtransaction` returns bytes that hash to the txid.
    #[tokio::test]
    async fn getrawtransaction_returns_bytes_that_hash_to_the_txid() {
        let (_tmp, state) = state_with_chain(1);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: b"height:1".to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 5, script_pubkey: vec![1; 20] }],
            locktime: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [7; 32], prev_index: 1, script_sig: vec![9; 40], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 123_456, script_pubkey: vec![2; 20] }],
            locktime: 0,
        };
        let mut block = Block {
            header: BlockHeader { version: 1, parents: vec![[0; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 1_030, bits: 0x2100_FFFF, nonce: 0 },
            transactions: vec![coinbase.clone(), spend.clone()],
            blue_score: 1, height: 1, shielded_transactions: vec![],
            powit: Default::default(),
        };
        block.header.merkle_root = block.body_merkle_root();
        state.store.put_block(&block).unwrap();
        for tx in [&coinbase, &spend] {
            state.store.put_tx_index(&tx.txid(), &block.block_hash(), 1).unwrap();
        }
        for tx in [&coinbase, &spend] {
            let r = dispatch("getrawtransaction", Some(&json!([hex::encode(tx.txid())])), &state).await;
            let raw = hex::decode(r["hex"].as_str().expect("hex")).unwrap();
            assert_eq!(Transaction::from_wire_bytes(&raw).unwrap().txid(), tx.txid());
            assert_eq!(r["block_height"], 1);
        }
        let r = dispatch("getrawtransaction", Some(&json!([hex::encode([3u8; 32])])), &state).await;
        assert!(r["error"].is_string());
        let r = dispatch("getrawtransaction", Some(&json!(["zz"])), &state).await;
        assert_eq!(r["error"], "invalid txid");
    }

    /// NET-12: `getutxos` stops at its limit while walking the index.
    #[tokio::test]
    async fn getutxos_applies_its_limit_while_iterating() {
        let (_tmp, state) = state_with_chain(1);
        let address = crate::address::Address::from_hash([4; 20], crate::address::Network::Mainnet);
        for i in 0..5u8 {
            state.store.put_utxo(&[i; 32], 0, &TxOutput { value: 1_000, script_pubkey: vec![4; 20] }).unwrap();
        }
        let (rows, more) = state.store.get_utxos_for_address_limited(&[4; 20], 2).unwrap();
        assert_eq!((rows.len(), more), (2, true));
        let (rows, more) = state.store.get_utxos_for_address_limited(&[4; 20], 5).unwrap();
        assert_eq!((rows.len(), more), (5, false));

        let r = dispatch("getutxos", Some(&json!([address.to_string(), 2])), &state).await;
        assert_eq!(r["returned"], 2);
        assert_eq!(r["truncated"], true);
        assert_eq!(r["satoshis"], "2000");
        let r = dispatch("getutxos", Some(&json!([address.to_string()])), &state).await;
        assert_eq!(r["returned"], 5);
        assert_eq!(r["truncated"], false);

        // An output of a coinbase carries its coinbase's height (wallets skip
        // immature ones); any other output carries no such field.
        state.store.put_coinbase_info(&[3; 32], 77).unwrap();
        let r = dispatch("getutxos", Some(&json!([address.to_string()])), &state).await;
        let rows = r["utxos"].as_array().unwrap();
        for row in rows {
            let expected = if row["txid"] == hex::encode([3u8; 32]) { json!(77) } else { Value::Null };
            assert_eq!(row["coinbase_height"], expected, "{row}");
        }
    }

    #[tokio::test]
    async fn pqpsbt_getutxos_selected_metadata_matches_the_node_snapshot() {
        let (_tmp, state) = state_with_chain(5);
        state.store.put_meta("tip_hash", &[5; 32]).unwrap();
        let address = crate::address::Address::from_hash([41; 20], crate::address::Network::Mainnet);
        state.store.put_utxo(&[42; 32], 0, &TxOutput { value: 1_000, script_pubkey: vec![41;20] }).unwrap();
        state.store.put_tx_index(&[42;32], &[2;32], 2).unwrap();
        // Independent positive control: the old endpoint really returns the
        // requested output, without the optional metadata contract.
        let plain = dispatch("getutxos",Some(&json!([address.to_string(),1])),&state).await;
        assert_eq!(plain["utxos"][0]["value"],"1000");
        assert!(plain.get("tip").is_none());
        let snapshot = dispatch("getdaginfo",None,&state).await;
        let selected = json!([{"txid":hex::encode([42;32]),"index":0}]);
        let before = state.store.storage_reads();
        let result = dispatch("getutxos",Some(&json!([address.to_string(),1,selected])),&state).await;
        let reads = state.store.storage_reads()-before;
        assert_eq!(result["utxos"][0]["spent_in_mempool"],false,
            "selected inputs need an explicit mempool-spend verdict, got {result}");
        assert_eq!(result["next_block_height"],snapshot["next_block_height"]);
        assert_eq!(result["tip"],snapshot["tip"]);
        assert_eq!(result["utxos"][0]["confirmations_at_next_block"],snapshot["next_block_height"].as_u64().unwrap()-2);
        assert!(reads <= 24,"one selected input performed {reads} storage reads");
    }

    #[tokio::test]
    async fn pqpsbt_getutxos_rejects_more_than_64_selected_inputs_before_storage() {
        let (_tmp, state) = state_with_chain(1);
        let address = crate::address::Address::from_hash([41;20],crate::address::Network::Mainnet);
        let selected: Vec<_> = (0..65u32).map(|i| json!({"txid":hex::encode([42;32]),"index":i})).collect();
        let before = state.store.storage_reads();
        let result = dispatch("getutxos",Some(&json!([address.to_string(),1,selected])),&state).await;
        assert!(result["error"].is_string(),"65 selected inputs must be refused: {result}");
        assert_eq!(state.store.storage_reads()-before,0,"refusal precedes storage work");
    }

    /// NET-12: the chain-walking statistics read only the requested window.
    #[tokio::test]
    async fn block_time_percentiles_walk_only_the_window() {
        let (_tmp, state) = state_with_chain(60);
        assert!(HeavyGate::is_heavy("getblocktimepercentiles"));
        assert!(HeavyGate::is_heavy("getdifficultyhistory"));
        let r = dispatch("getblocktimepercentiles", Some(&json!([10])), &state).await;
        assert_eq!(r["sample_size"], 10);
        assert_eq!(r["p50_secs"], 60);
        let r = dispatch("getblocktimepercentiles", Some(&json!([1000])), &state).await;
        assert_eq!(r["sample_size"], 60);
        assert_eq!(r["min_secs"], 30);
        // No stored bodies: the difficulty walk is bounded and empty.
        let r = dispatch("getdifficultyhistory", Some(&json!([500])), &state).await;
        assert_eq!(r["count"], 0);
    }

    /// NET-12: the explorer statistics read a bounded number of storage
    /// entries (counted by the store) whatever the number of holders; the
    /// answers match the UTXO set. Pre-fix `getrichlist` /
    /// `getsupplydistribution` / `getaddresscount` scanned the whole UTXO
    /// set and `getchainstats` / `gethashrate` decoded every block body.
    #[tokio::test]
    async fn net12_explorer_methods_read_bounded_entries() {
        let (_tmp, state) = state_with_chain(60);
        assert!(state.store.aggregates_ready());
        for i in 0..300u32 {
            let mut spk = vec![0u8; 20];
            spk[..4].copy_from_slice(&i.to_le_bytes());
            state.store.put_utxo(&[(i % 251) as u8; 32], i, &TxOutput { value: 1_000 + i as u64, script_pubkey: spk }).unwrap();
        }
        for (method, params, bound) in [
            ("getrichlist", json!([100, 0]), 102u64),
            ("getrichlist", json!([100, 200]), 302),
            ("getsupplydistribution", json!([]), 1),
            ("getaddresscount", json!([]), 1),
            ("getchainstats", json!([]), 5),
            ("gethashrate", json!([]), 5),
        ] {
            let r0 = state.store.storage_reads();
            let r = dispatch(method, Some(&params), &state).await;
            let reads = state.store.storage_reads() - r0;
            assert!(r.get("error").is_none(), "{method}: {r}");
            assert!(reads <= bound, "{method} {params}: {reads} reads > {bound}");
        }
        let r = dispatch("getrichlist", Some(&json!([100, 0])), &state).await;
        assert_eq!(r["holders"], 300);
        assert_eq!(r["items"].as_array().unwrap().len(), 100);
        assert_eq!(r["items"][0]["balance"], "1299");
        assert_eq!(r["items"][0]["rank"], 1);
        let r = dispatch("getrichlist", Some(&json!([10, 1_000_000_000u64])), &state).await;
        assert_eq!(r["offset"], crate::analytics::MAX_RICHLIST_OFFSET, "offset clamped");
        let r = dispatch("getaddresscount", None, &state).await;
        assert_eq!((r["addresses_with_balance"].as_u64(), r["utxo_entries"].as_u64()), (Some(300), Some(300)));
        let r = dispatch("getchainstats", None, &state).await;
        assert_eq!(r["total_blocks"], 61);
        // A cancelled request stops (and HeavyGate never caches the error).
        let mut cancelled = state.clone();
        cancelled.cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let r = dispatch("getchainstats", None, &cancelled).await;
        assert_eq!(r["error"], "cancelled");
        let gate = HeavyGate::new(HEAVY_READ_CACHE_TTL);
        assert_eq!(gate.run("k".into(), || json!({ "error": "cancelled" }))["error"], "cancelled");
        assert_eq!(gate.run("k".into(), || json!(7)), json!(7), "the failure was not cached");
    }

    /// B1-T11 + NET-12 challenge: `getaddresshistory` and `getbalance` on an
    /// address with a long history and many UTXOs (the carryover address
    /// holds about 426,000) read a bounded number of entries: the balance and
    /// UTXO count come from the holder aggregate, the total from the
    /// per-address history counter, and a page walks the index newest-first
    /// from its end (or from the opaque cursor the previous page returned)
    /// instead of counting every entry and skipping from the oldest one;
    /// the offset is capped and the walk is cancellable. Pre-fix, page 0
    /// alone cost about 2 × history + 2 × UTXOs reads.
    #[tokio::test]
    async fn b1_t11_address_endpoints_read_bounded_entries() {
        const N: u32 = 3_000;
        let (_tmp, state) = state_with_chain(5);
        let addr = [0x5Au8; 20];
        let testnet = crate::core::node_chain_id() == crate::core::ChainId::Testnet;
        let addr_s = crate::crypto::address_from_hash(&addr, testnet);
        // History: N rows over 30 heights (one 100-output transaction each).
        for h in 0..N / 100 {
            let tx = Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: format!("h{h}").into_bytes(), sequence: u32::MAX }],
                outputs: (0..100u64).map(|i| TxOutput { value: 1_000 + i, script_pubkey: addr.to_vec() }).collect(),
                locktime: 0,
            };
            state.store.index_tx_addresses(&tx, 10 + h as u64, 0).unwrap();
        }
        for i in 0..N {
            state.store.put_utxo(&[(i % 251) as u8; 32], i, &TxOutput { value: 7, script_pubkey: addr.to_vec() }).unwrap();
        }
        for (params, bound) in [(json!([addr_s, 25, 0]), 40u64), (json!([addr_s, 25, 1_000]), 1_040)] {
            let r0 = state.store.storage_reads();
            let r = dispatch("getaddresshistory", Some(&params), &state).await;
            let reads = state.store.storage_reads() - r0;
            assert!(r.get("error").is_none(), "{r}");
            assert_eq!(r["total"], N, "{params}");
            assert_eq!(r["items"].as_array().unwrap().len(), 25);
            assert_eq!((r["balance"].as_str(), r["utxo_count"].as_u64()), (Some(&*(7 * N as u64).to_string()), Some(N as u64)));
            assert!(reads <= bound, "getaddresshistory {params}: {reads} reads > {bound}");
        }
        let r0 = state.store.storage_reads();
        let r = dispatch("getbalance", Some(&json!([addr_s])), &state).await;
        let reads = state.store.storage_reads() - r0;
        assert_eq!((r["satoshis"].as_str(), r["utxo_count"].as_u64()), (Some(&*(7 * N as u64).to_string()), Some(N as u64)), "{r}");
        assert!(reads <= 2, "getbalance: {reads} reads");

        // Cursor paging visits every row exactly once, newest first, each
        // page at a bounded cost.
        let mut seen = std::collections::HashSet::new();
        let mut cursor: Option<String> = None;
        let mut last_height = u64::MAX;
        loop {
            let mut params = json!([addr_s, 100, 0]);
            if let Some(c) = &cursor {
                params.as_array_mut().unwrap().push(json!(c));
            }
            let r0 = state.store.storage_reads();
            let r = dispatch("getaddresshistory", Some(&params), &state).await;
            let reads = state.store.storage_reads() - r0;
            assert!(reads <= 110, "page {params}: {reads} reads");
            let items = r["items"].as_array().unwrap_or_else(|| panic!("{r}"));
            for it in items {
                let h = it["height"].as_u64().unwrap();
                assert!(h <= last_height, "newest first");
                last_height = h;
                assert!(seen.insert((it["txid"].as_str().unwrap().to_string(), it["amount"].as_str().unwrap().to_string())), "row seen twice");
            }
            match r["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
            assert!(seen.len() <= N as usize);
        }
        assert_eq!(seen.len(), N as usize, "every row exactly once");
        assert_eq!(last_height, 10, "ends at the oldest row");

        // Offsets are capped (the explorer API accepts exactly this range).
        // Review: a larger offset is refused with an error that names the
        // cursor; it was clamped, so offset paging (offset += limit until
        // `items` is empty) got the page at 10,000 forever.
        let max = crate::storage::indexer::MAX_HISTORY_OFFSET as u64;
        let r = dispatch("getaddresshistory", Some(&json!([addr_s, 25, max])), &state).await;
        assert_eq!((r["offset"].as_u64(), r["items"].as_array().map(|a| a.len())), (Some(max), Some(0)), "{r}");
        for method in ["getaddresshistory", "listtransactions"] {
            let params = if method == "listtransactions" { json!([addr_s, 25, 0, 100, max + 1]) } else { json!([addr_s, 25, max + 1]) };
            let r = dispatch(method, Some(&params), &state).await;
            assert!(r["error"].as_str().is_some_and(|e| e.contains("cursor")), "{method}: {r}");
            assert!(r.get("items").is_none() && r.get("transactions").is_none(), "{method}: no other page: {r}");
        }
        // Review: listtransactions over a height range other than the whole
        // history counted every entry in it (no counter), on every call. The
        // count now stops at LISTTX_COUNT_CAP.
        let r0 = state.store.storage_reads();
        let r = dispatch("listtransactions", Some(&json!([addr_s, 1, 10, 39])), &state).await;
        let reads = state.store.storage_reads() - r0;
        assert_eq!(r["count"], 1, "{r}");
        assert!(r["total_available"].is_null() && r["total_at_least"] == LISTTX_COUNT_CAP, "{r}");
        assert!(reads <= LISTTX_COUNT_CAP + 10, "ranged listtransactions: {reads} reads for {N} rows");
        let r = dispatch("listtransactions", Some(&json!([addr_s, 1, 10, 11])), &state).await;
        assert_eq!((r["total_available"].as_u64(), r["total_at_least"].as_u64()), (Some(200), Some(200)), "{r}");
        let r = dispatch("getaddresshistory", Some(&json!([addr_s, 25, 0, "zz"])), &state).await;
        assert_eq!(r["error"], "invalid cursor");
        // A cancelled request stops walking.
        let mut cancelled = state.clone();
        cancelled.cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let r = dispatch("getaddresshistory", Some(&json!([addr_s, 25, 2_000])), &cancelled).await;
        assert_eq!(r["error"], "cancelled", "{r}");
    }

    /// Review finding (chain_tail): a cancelled request is an ERROR for the
    /// two selected-chain walks, also when the flag was set while the
    /// request waited for the DAG lock, and HeavyGate never caches it — the
    /// next uncancelled call computes real values. Pre-fix `chain_tail`
    /// stopped silently and returned an empty tail: `{sample_size: 0,
    /// p50_secs: 0, ...}` and `{count: 0, points: []}` as successes, cached
    /// for 30 s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn net12_cancelled_chain_walks_are_errors_and_never_cached() {
        let (_tmp, state) = state_with_chain(60);
        let mut cancelled = state.clone();
        cancelled.cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        for m in ["getblocktimepercentiles", "getdifficultyhistory"] {
            let r = dispatch(m, Some(&json!([10])), &cancelled).await;
            assert_eq!(r["error"], "cancelled", "{m}: {r}");
        }
        // Exactly as the server runs a heavy method: HeavyGate around a
        // blocking dispatch, both states sharing one gate.
        let run = |st: AppState| {
            let h = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                st.heavy_gate.clone().run("getblocktimepercentiles|[10]".into(), || {
                    h.block_on(dispatch("getblocktimepercentiles", Some(&json!([10])), &st))
                })
            })
        };
        let r = run(cancelled).await.unwrap();
        assert_eq!(r["error"], "cancelled");
        let r = run(state).await.unwrap();
        assert!(r.get("error").is_none(), "{r}");
        assert_eq!(r["sample_size"], 10, "computed, not served from a cached failure: {r}");
        assert_eq!(r["p50_secs"], 60);
    }

    /// VAL-11: `gettxoutsetinfo` reports the UTXO set against the issuance:
    /// count, total, hash, the expected supply, and agreement with the
    /// maintained aggregates; a cancelled request is an error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn val11_gettxoutsetinfo_reports_the_supply_audit() {
        let (_tmp, state) = state_with_chain(3);
        state.store.ensure_aggregates().unwrap();
        state.store.put_utxo(&[7u8; 32], 0, &TxOutput { value: 1_000, script_pubkey: vec![1; 20] }).unwrap();
        let carry = crate::core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT;
        // The locked team and founder tranches are part of the genesis
        // ledger (core::vesting): they sum to exactly the two allocations.
        let locked: u64 = crate::core::vesting::genesis_tranches().unwrap().iter().map(|t| t.output.value).sum();
        assert_eq!(locked, crate::core::tokenomics::TEAM_ALLOCATION_SAT + crate::core::tokenomics::FOUNDER_ALLOCATION_SAT);
        let r = dispatch("gettxoutsetinfo", None, &state).await;
        assert!(r.get("error").is_none(), "{r}");
        assert_eq!(r["txouts"], 1);
        assert_eq!(r["total_amount_sat"], "1000");
        assert_eq!(r["expected"]["carryover_sat"], carry.to_string());
        assert_eq!(r["expected"]["locked_sat"], locked.to_string());
        assert_eq!(r["expected"]["max_supply_sat"], (carry + locked).to_string());
        assert_eq!(r["expected"]["subsidy_sat"], "0", "no undo record: no applied block");
        assert_eq!(r["unclaimed_sat"], (carry + locked - 1_000).to_string());
        assert_eq!(r["supply_ok"], true);
        assert_eq!(r["hash_serialized"], hex::encode(state.store.utxo_set_digest().unwrap()));
        assert_eq!(r["aggregates"]["ok"], true, "{r}");
        assert_eq!(r["ok"], true);
        // The same row rewritten outside the node (value 1000 -> 5000):
        // the aggregates no longer agree and the hash changes.
        let mut key = [7u8; 32].to_vec();
        key.extend_from_slice(&0u32.to_le_bytes());
        let forged = bincode::serde::encode_to_vec(
            TxOutput { value: 5_000, script_pubkey: vec![1; 20] }, bincode::config::standard()).unwrap();
        let cf = state.store.db().cf_handle("utxo").unwrap();
        state.store.db().put_cf(cf, &key, forged).unwrap();
        let r2 = dispatch("gettxoutsetinfo", None, &state).await;
        assert_eq!(r2["total_amount_sat"], "5000");
        assert_eq!(r2["aggregates"]["ok"], false, "{r2}");
        assert_eq!(r2["ok"], false);
        assert_ne!(r2["hash_serialized"], r["hash_serialized"]);
        let mut cancelled = state.clone();
        cancelled.cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        assert_eq!(dispatch("gettxoutsetinfo", None, &cancelled).await["error"], "cancelled");
        assert!(HeavyGate::is_heavy("gettxoutsetinfo"));
    }

    /// VAL-11: the heavy gate's cache never answers `gettxoutsetinfo` for a
    /// tip other than the applied one (a method|params key served the
    /// previous block's audit for 30 s after a block was connected).
    #[test]
    fn val11_gettxoutsetinfo_cache_follows_the_applied_tip() {
        let (_tmp, state) = state_with_chain(1);
        let run = |tip: [u8; 32], n: u32| gated_dispatch("gettxoutsetinfo", None, &state,
            || json!({ "bestblock": hex::encode(tip), "n": n }));
        state.store.put_meta("tip_hash", &[1u8; 32]).unwrap();
        assert_eq!(run([1; 32], 1)["n"], 1);
        assert_eq!(run([1; 32], 2)["n"], 1, "same tip: served from the cache");
        state.store.put_meta("tip_hash", &[2u8; 32]).unwrap();
        assert_eq!(run([2; 32], 3)["n"], 3, "a new tip is never answered from the cache");
        state.store.put_meta("tip_hash", &[1u8; 32]).unwrap();
        assert_eq!(run([1; 32], 4)["n"], 1, "back on the first tip (a reorg): its own answer");
    }

    // ── The real router (body limits, auth layer) through tower::oneshot ──

    /// One POST through the real router, from `peer`, with extra headers.
    /// Returns the status and the body (JSON when it parses, else a string).
    async fn post_raw(state: &AppState, peer: &str, headers: &[(&str, &str)], body: Vec<u8>) -> (StatusCode, Value) {
        post_body(state, peer, headers, axum::body::Body::from(body)).await
    }

    async fn post_body(state: &AppState, peer: &str, headers: &[(&str, &str)], body: axum::body::Body) -> (StatusCode, Value) {
        use axum::http::Request;
        use tower::util::ServiceExt;
        let peer: std::net::SocketAddr = peer.parse().unwrap();
        let router = build_router(state.clone(), &[])
            .layer(axum::extract::connect_info::MockConnectInfo(peer));
        let mut req = Request::builder().method("POST").uri("/")
            .header("host", "127.0.0.1:17210")
            .header("content-type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = router.oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, body)
    }

    fn rpc_body(method: &str, params: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})).unwrap()
    }

    #[tokio::test]
    async fn r7_rpc_rejects_key_flood_before_body_and_hash_work() {
        let (_tmp, mut state) = state_with_chain(1);
        state.api_key = Some("k".repeat(32));
        state.rate_limiter = Arc::new(auth::RateLimiterSet::new(2, 1));
        auth::KEY_HASH_BYTES.with(|n| n.set(0));
        let attack = "x".repeat(8192);
        let mut refused = 0;
        let body_polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for i in 0..100 {
            // Malformed JSON used to hash the key before rejecting the body,
            // never reaching authorize_request or consuming any token.
            let polls = body_polls.clone();
            let body = axum::body::Body::from_stream(futures::stream::once(async move {
                polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{"))
            }));
            let (status, _) = post_body(&state, "127.0.0.1:5000",
                &[("x-forwarded-for", "198.51.100.7"), ("x-api-key", &attack)], body).await;
            if i < 3 { assert_eq!(status, StatusCode::BAD_REQUEST, "admitted requests still reach the parser"); }
            if i >= 3 && status == StatusCode::TOO_MANY_REQUESTS { refused += 1; }
        }
        let hashed = auth::KEY_HASH_BYTES.with(|n| n.get());
        let polled = body_polls.load(std::sync::atomic::Ordering::Relaxed);
        eprintln!("r7 router cost: {hashed} key bytes hashed, {polled} body chunks polled");
        assert_eq!(polled, 3, "rate-limited requests must not poll their body");
        assert!(hashed <= 3 * (attack.len() + 32), "pre-auth budget exceeded: {hashed} hashed bytes");
        assert_eq!(refused, 97, "must refuse before parsing the body");
    }

    #[tokio::test]
    async fn r7_getaddressinfo_storage_work_is_independent_of_confirmed_utxos() {
        let (_tmp, state) = state_with_chain(1);
        state.store.ensure_aggregates().unwrap();
        let address = [7u8; 20];
        for i in 0..256 {
            state.store.put_utxo(&[1u8; 32], i, &TxOutput { value: 1000, script_pubkey: address.to_vec() }).unwrap();
        }
        let start = state.store.storage_reads();
        let response = dispatch("getaddressinfo", Some(&json!([crate::address::Address::from_hash(address, crate::address::Network::Mainnet).to_string()])), &state).await;
        let reads = state.store.storage_reads() - start;
        assert_eq!(response["balance_sats"], "256000", "{response}");
        assert_eq!(response["utxo_count"], 256);
        assert!(reads <= 1, "empty mempool must need at most one storage read, observed {reads}");
    }

    #[tokio::test]
    async fn r7_getaddressinfo_does_not_scan_during_aggregate_rebuild() {
        let (_tmp, state) = state_with_chain(1);
        let address = [7u8; 20];
        state.store.put_utxo(&[1u8; 32], 0, &TxOutput { value: 1000, script_pubkey: address.to_vec() }).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        state.store.stage_aggregates_incomplete(&mut batch).unwrap();
        state.store.write_batch(batch).unwrap();
        assert!(!state.store.aggregates_ready());
        let start = state.store.storage_reads();
        let response = dispatch("getaddressinfo", Some(&json!([crate::address::Address::from_hash(address, crate::address::Network::Mainnet).to_string()])), &state).await;
        let reads = state.store.storage_reads() - start;
        assert_eq!(reads, 0, "unavailable aggregates must not trigger a fallback UTXO scan");
        assert!(response["error"].as_str().unwrap_or("").contains("aggregates"), "{response}");
    }

    /// B1-T4: `submitblock` carries a block as hex, about twice its wire
    /// size, so a block built from a full template (about 1 MB) needs a body
    /// of about 2 MB. Every body was capped at 1 MiB, so the block and its
    /// proof of work were refused with HTTP 413 before dispatch. Bitcoin Core
    /// accepts RPC bodies up to 32 MiB.
    #[tokio::test]
    async fn submitblock_body_carries_a_full_block() {
        let (_tmp, state) = state_with_chain(1);
        // 1,000,000 bytes of "block" (MAX_BLOCK_SIZE) as hex: a ~2 MB body.
        let body = rpc_body("submitblock", json!(["00".repeat(crate::core::MAX_BLOCK_SIZE)]));
        assert!(body.len() > 2 * 1024 * 1024 - 100_000 && body.len() > RPC_MAX_BODY_BYTES);
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[], body).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        // It reached dispatch: the bytes are not a block.
        assert!(resp["result"]["error"].as_str().unwrap_or("").contains("deserialise failed"), "{resp}");
    }

    /// B1-T4: only `submitblock` gets the larger body; every other method
    /// keeps the 1 MiB cap, and nothing exceeds the submitblock cap.
    #[tokio::test]
    async fn other_methods_keep_the_small_body_cap() {
        let (_tmp, state) = state_with_chain(1);
        let padded = rpc_body("getblockcount", json!(["a".repeat(RPC_MAX_BODY_BYTES + 10)]));
        let (status, _) = post_raw(&state, "127.0.0.1:5000", &[], padded).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let huge = rpc_body("submitblock", json!(["00".repeat(RPC_MAX_SUBMITBLOCK_BODY_BYTES / 2 + 10)]));
        let (status, _) = post_raw(&state, "127.0.0.1:5000", &[], huge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[], rpc_body("getblockcount", json!([]))).await;
        assert_eq!((status, resp["result"].clone()), (StatusCode::OK, json!(0)));
    }

    /// B1-T4: at most RPC_LARGE_BODY_PERMITS bodies above the 1 MiB cap are
    /// buffered at once for anonymous callers, plus at most
    /// RPC_LARGE_BODY_RESERVED_PERMITS for the operator's (a flood of 4 MiB
    /// bodies cannot pin 256 × 4 MiB); small requests are unaffected.
    /// (Review: this test used a direct loopback caller for the refused
    /// request, which pinned the lock-out of the operator's miner.)
    #[tokio::test]
    async fn large_bodies_are_bounded_in_number() {
        let (_tmp, state) = state_with_chain(1);
        let anon = [("x-forwarded-for", "198.51.100.61")];
        let held: Vec<_> = (0..RPC_LARGE_BODY_PERMITS)
            .map(|_| state.large_bodies.clone().try_acquire_owned().unwrap()).collect();
        let body = rpc_body("submitblock", json!(["00".repeat(crate::core::MAX_BLOCK_SIZE)]));
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &anon, body.clone()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{resp}");
        let (status, _) = post_raw(&state, "127.0.0.1:5000", &anon, rpc_body("getblockcount", json!([]))).await;
        assert_eq!(status, StatusCode::OK);
        let reserved: Vec<_> = (0..RPC_LARGE_BODY_RESERVED_PERMITS)
            .map(|_| state.large_bodies_reserved.clone().try_acquire_owned().unwrap()).collect();
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[], body.clone()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "the operator's permits are bounded too: {resp}");
        drop((held, reserved));
        let (status, _) = post_raw(&state, "127.0.0.1:5000", &anon, body).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// B1-T4 (review): large-body permits are taken before the request is
    /// authorized (its method is in the body). Four anonymous uploads that
    /// declare `Content-Length: 4000000` and then stall held every permit
    /// until the 30 s request timeout (and again after reconnecting), and
    /// the operator's `submitblock` of a full block got 503 every time. The
    /// operator's callers (API key, or direct loopback) now have reserved
    /// permits; anonymous callers still cannot get a fifth.
    #[tokio::test]
    async fn anonymous_slow_bodies_cannot_lock_out_the_operators_submitblock() {
        use axum::http::Request;
        use tower::util::ServiceExt;
        let (_tmp, mut state) = state_with_chain(1);
        let key = "k".repeat(32);
        state.api_key = Some(key.clone());
        let stalled = |state: AppState, i: u8| tokio::spawn(async move {
            let router = build_router(state, &[])
                .layer(axum::extract::connect_info::MockConnectInfo("127.0.0.1:5000".parse::<std::net::SocketAddr>().unwrap()));
            let stream = futures::StreamExt::chain(
                futures::stream::once(async { Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{\"jsonrpc\"")) }),
                futures::stream::pending());
            let req = Request::builder().method("POST").uri("/")
                .header("host", "127.0.0.1:17210")
                .header("content-type", "application/json")
                .header("content-length", "4000000")
                .header("x-forwarded-for", format!("198.51.100.{i}"))
                .body(axum::body::Body::from_stream(stream)).unwrap();
            let _ = router.oneshot(req).await;
        });
        let tasks: Vec<_> = (0..RPC_LARGE_BODY_PERMITS as u8).map(|i| stalled(state.clone(), i)).collect();
        for _ in 0..200 {
            if state.large_bodies.available_permits() == 0 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(state.large_bodies.available_permits(), 0, "the stalled uploads hold every shared permit");
        let block = rpc_body("submitblock", json!(["00".repeat(crate::core::MAX_BLOCK_SIZE)]));
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[("x-forwarded-for", "203.0.113.70")], block.clone()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "an anonymous caller gets no fifth permit: {resp}");
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[], block.clone()).await;
        assert_eq!(status, StatusCode::OK, "direct loopback (the co-located miner): {resp}");
        let (status, resp) = post_raw(&state, "127.0.0.1:5000",
            &[("x-forwarded-for", "203.0.113.71"), ("x-api-key", &key)], block).await;
        assert_eq!(status, StatusCode::OK, "the keyed pool behind the proxy: {resp}");
        assert!(resp["result"]["error"].as_str().unwrap_or("").contains("deserialise failed"), "{resp}");
        for t in tasks { t.abort(); }
    }

    /// B2-T11: a request that reached a loopback RPC through a reverse proxy
    /// (forwarding headers) is a remote request: it is rate-limited (per the
    /// client the proxy names) and never fully trusted, also with
    /// `--rpc-trust-loopback`. Before, every proxied client shared the
    /// loopback exemption: unlimited anonymous `submitblock`, and with
    /// `--rpc-trust-loopback` anonymous `invalidateblock`.
    #[tokio::test]
    async fn proxied_requests_are_neither_exempt_nor_trusted() {
        let (_tmp, mut state) = state_with_chain(1);
        state.rate_limiter = Arc::new(auth::RateLimiterSet::new(60, 2));
        let proxied = [("x-forwarded-for", "198.51.100.23")];
        let submit = || rpc_body("submitblock", json!(["00"]));
        let mut statuses = Vec::new();
        for _ in 0..4 {
            statuses.push(post_raw(&state, "127.0.0.1:5000", &proxied, submit()).await.0);
        }
        assert_eq!(statuses, [StatusCode::OK, StatusCode::OK, StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS], "proxied writes are rate-limited");
        // Another client behind the same proxy has its own bucket.
        let (status, _) = post_raw(&state, "127.0.0.1:5000", &[("x-forwarded-for", "203.0.113.9")], submit()).await;
        assert_eq!(status, StatusCode::OK);
        // A direct loopback caller (the operator, the co-located pool) keeps
        // its exemption.
        for _ in 0..4 {
            assert_eq!(post_raw(&state, "127.0.0.1:5000", &[], submit()).await.0, StatusCode::OK);
        }
        // --rpc-trust-loopback does not extend to proxied requests.
        state.trust_loopback = true;
        state.rate_limiter = Arc::new(auth::RateLimiterSet::new(60, 60));
        let admin = rpc_body("invalidateblock", json!([hex::encode([7u8; 32])]));
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[("x-real-ip", "198.51.100.23")], admin.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{resp}");
        let (status, resp) = post_raw(&state, "127.0.0.1:5000", &[], admin).await;
        assert_eq!(status, StatusCode::OK, "direct loopback stays trusted: {resp}");
    }

    /// A one-input spend of a fresh 100,000-sat outpoint `tag`, with a valid
    /// hybrid signature, or one with a corrupted signature when `forge`.
    fn signed_spend(state: &AppState, tag: u8, forge: bool) -> Vec<u8> {
        use sha3::{Digest as _, Sha3_256};
        let (pk, sk) = crate::crypto::generate_keypair();
        let prev_txid = [tag; 32];
        state.store.put_utxo(&prev_txid, 0,
            &TxOutput { value: 100_000, script_pubkey: Sha3_256::digest(&pk)[..20].to_vec() }).unwrap();
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid, prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 70_000, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        };
        let mut sighash = tx.sighash(0, crate::core::node_chain_id());
        if forge {
            sighash[0] ^= 1;
        }
        let sig = crate::crypto::sign(&sk, &sighash).unwrap();
        tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &pk);
        tx.to_wire_bytes(true)
    }

    /// B1-T10: transactions from untrusted callers are charged, by wire
    /// size and before their signatures are verified, to ONE node-wide
    /// budget; admitted transactions are refunded. Before, the only bound
    /// was the per-IP write limiter, which the explorer API bypasses by
    /// design (every caller arrives from loopback): a flood of forged
    /// transactions from any number of addresses cost the node unbounded
    /// signature verification.
    #[tokio::test]
    async fn anonymous_transaction_verification_is_bounded_node_wide() {
        let (_tmp, mut state) = state_with_chain(1);
        state.rate_limiter = Arc::new(auth::RateLimiterSet::new(600, 600));
        state.api_key = Some("operator-key".into());
        let valid = signed_spend(&state, 0x51, false);
        let forged: Vec<Vec<u8>> = (0..3u8).map(|i| signed_spend(&state, 0x61 + i, true)).collect();
        // Room for two forged transactions and no refill.
        state.tx_verify_budget = Arc::new(auth::ByteBudget::new(2 * forged[0].len() as u64 + 16, 0));
        let send = |raw: &[u8]| rpc_body("sendrawtransaction", json!([hex::encode(raw)]));
        let from = |i: u8| format!("198.51.100.{i}");

        // A valid transaction is admitted and refunded.
        let (status, r) = post_raw(&state, "127.0.0.1:5000", &[("x-forwarded-for", &from(1))], send(&valid)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(r["result"]["txid"].is_string(), "{r}");
        // Two forged transactions, from two clients, are verified and refused...
        for (i, tx) in forged.iter().enumerate().take(2) {
            let (_, r) = post_raw(&state, "127.0.0.1:5000", &[("x-forwarded-for", &from(10 + i as u8))],
                send(tx)).await;
            let e = r["result"]["error"].as_str().unwrap_or_default();
            assert!(!e.is_empty() && !e.starts_with("busy"), "{r}");
        }
        // ...and the third is refused before verification, from any client,
        // also from a direct loopback caller (the explorer API itself).
        for (peer, hdrs) in [("127.0.0.1:5000", vec![("x-forwarded-for", from(12))]), ("127.0.0.1:5001", vec![])] {
            let hdrs: Vec<(&str, &str)> = hdrs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let (_, r) = post_raw(&state, peer, &hdrs, send(&forged[2])).await;
            assert!(r["result"]["error"].as_str().unwrap_or_default().starts_with("busy"), "{r}");
        }
        // The operator (API key) is not charged.
        let (_, r) = post_raw(&state, "127.0.0.1:5000", &[("x-api-key", "operator-key")], send(&forged[2])).await;
        let e = r["result"]["error"].as_str().unwrap_or_default();
        assert!(!e.is_empty() && !e.starts_with("busy"), "{r}");
    }

    /// B1-T10 on main's `submitpowititem` (a write method that checks a KES
    /// signature under the DAG read lock): an untrusted caller's item is
    /// charged to the same node-wide verification budget as a transaction,
    /// before it is decoded or verified; the operator is not charged.
    #[tokio::test]
    async fn anonymous_powit_items_share_the_verification_budget() {
        let (_tmp, mut state) = state_with_chain(1);
        state.rate_limiter = Arc::new(auth::RateLimiterSet::new(600, 600));
        state.api_key = Some("operator-key".into());
        let item = vec![0u8; 600];
        assert!(item.len() <= crate::network::MAX_WIRE_POWIT_ITEM);
        // Room for two items and no refill.
        state.tx_verify_budget = Arc::new(auth::ByteBudget::new(2 * item.len() as u64 + 16, 0));
        let submit = || rpc_body("submitpowititem", json!([2, hex::encode(&item)]));
        for i in 0..2u8 {
            let (status, r) = post_raw(&state, "127.0.0.1:5000",
                &[("x-forwarded-for", &format!("198.51.100.{}", 20 + i))], submit()).await;
            assert_eq!(status, StatusCode::OK, "{r}");
            let e = r["result"]["error"].as_str().unwrap_or_default();
            assert!(r["result"]["accepted"] == false && !e.is_empty() && !e.starts_with("busy"), "refused on its merits: {r}");
        }
        for (peer, hdrs) in [("127.0.0.1:5000", vec![("x-forwarded-for", "198.51.100.30")]), ("127.0.0.1:5001", vec![])] {
            let (_, r) = post_raw(&state, peer, &hdrs, submit()).await;
            assert!(r["result"]["error"].as_str().unwrap_or_default().starts_with("busy"), "{r}");
        }
        let (_, r) = post_raw(&state, "127.0.0.1:5000", &[("x-api-key", "operator-key")], submit()).await;
        let e = r["result"]["error"].as_str().unwrap_or_default();
        assert!(!e.is_empty() && !e.starts_with("busy"), "the operator is not charged: {r}");
    }

    /// B1-T21 / MEM-6: `estimatefeeadvanced` never recommends a fee the
    /// network refuses. On a quiet pool it answered 5,000 sat (medium,
    /// `recommended_gnb`) and 1,000 sat (slow) against the 10,000-sat
    /// consensus minimum, and it ignored the transaction size (a 47-input
    /// payment needs about 800,000 sat). Every field is now an absolute fee
    /// for the stated size, from the fee-rate estimate, floored at
    /// `min_tx_fee_sat(size)` and the rolling minimum.
    #[tokio::test]
    async fn estimatefeeadvanced_never_recommends_less_than_the_consensus_minimum() {
        use crate::core::tokenomics::{min_tx_fee_sat, MIN_TX_FEE_SAT};
        let (_tmp, state) = state_with_chain(1);
        let sat = |v: &Value, k: &str| -> u64 { v[k].as_str().unwrap_or_else(|| panic!("{k}: {v}")).parse().unwrap() };
        let fields = ["next_block_sats", "medium_priority", "slow_priority", "mempool_median"];
        let typical = Transaction::estimate_size(1, 2);
        let r = dispatch("estimatefeeadvanced", None, &state).await;
        for k in fields {
            assert!(sat(&r, k) >= min_tx_fee_sat(typical).max(MIN_TX_FEE_SAT), "{k}: {r}");
        }
        let recommended: f64 = r["recommended_gnb"].as_str().unwrap().parse().unwrap();
        assert!(recommended * 1e8 >= MIN_TX_FEE_SAT as f64 - 0.5, "{r}");
        // Size-aware: a 47-input, 2-output payment.
        let big = Transaction::estimate_size(47, 2);
        let r = dispatch("estimatefeeadvanced", Some(&json!([47, 2])), &state).await;
        assert_eq!(r["tx_bytes"], big);
        for k in fields {
            assert!(sat(&r, k) >= min_tx_fee_sat(big), "{k}: {r}");
        }
        assert!(sat(&r, "next_block_sats") >= sat(&r, "medium_priority"));
        assert!(sat(&r, "medium_priority") >= sat(&r, "slow_priority"));
        // Absurd sizes are refused, not overflowed.
        let r = dispatch("estimatefeeadvanced", Some(&json!([u64::MAX, 2])), &state).await;
        assert!(r["error"].is_string(), "{r}");

        // A busy pool paying 100 sat/byte: the tiers follow its rates.
        for i in 0..4u8 {
            let tx = Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0x60 + i; 32], prev_index: 0, script_sig: vec![1; 100], sequence: 0 }],
                outputs: vec![TxOutput { value: 50_000, script_pubkey: vec![2; 20] }],
                locktime: 0,
            };
            let fee = tx.to_wire_bytes(true).len() as u64 * 100;
            state.mempool.add(tx, fee).expect("pool accepts the fixture");
        }
        // Review: the rates come from the wire size cached at admission; the
        // estimate re-encoded every pooled transaction under the pool's read
        // lock on each call. (A cached size changed behind the pool's back is
        // what the estimate must report: it never re-encodes.)
        let txid = *state.mempool.txids().first().expect("pooled");
        let wire = state.mempool.get_entry(&txid).unwrap().wire_size;
        assert_eq!(wire, state.mempool.get_entry(&txid).unwrap().tx.to_wire_bytes(true).len());
        state.mempool.set_cached_wire_size(&txid, wire * 1000);
        let rates = state.mempool.fee_rates_per_kb();
        assert_eq!(rates.len(), 4);
        assert!(rates[0] < 1_000, "the cached size is used, not a fresh encoding: {rates:?}");
        state.mempool.set_cached_wire_size(&txid, wire);
        let r = dispatch("estimatefeeadvanced", None, &state).await;
        assert_eq!(r["mempool_size"], 4);
        let medium_rate: u64 = r["feerate_sat_per_kb"]["medium"].as_str().unwrap().parse().unwrap();
        assert!((99_000..=100_000).contains(&medium_rate), "{r}");
        assert!(sat(&r, "medium_priority") >= (typical as u64 * medium_rate).div_ceil(1000));
        assert_eq!(sat(&r, "slow_priority"), min_tx_fee_sat(typical), "slow pays the floor");
    }

    /// MEM-6: `getmempoolinfo` reports the relay policy in force.
    #[tokio::test]
    async fn mem6_getmempoolinfo_reports_the_policy() {
        let (_tmp, state) = state_with_chain(1);
        let r = dispatch("getmempoolinfo", None, &state).await;
        assert_eq!(r["policy"]["max_replacement_evictions"], crate::mempool::MAX_REPLACEMENT_EVICTIONS);
        assert_eq!(r["policy"]["max_ancestors"], crate::mempool::MAX_ANCESTORS);
        assert_eq!(r["policy"]["unconfirmed_chains"], true);
        assert!(r["policy"]["replacement"].as_str().unwrap().starts_with("full-rbf"));
    }

    /// NET-15: explorer reads still work with storage access moved out of
    /// the DAG lock (and do not deadlock against a concurrent writer).
    #[tokio::test]
    async fn explorer_reads_release_the_dag_lock_before_storage() {
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getselectedchain", Some(&json!([0, 3])), &state).await;
        assert_eq!(r["chain_length"], 6);
        assert_eq!(r["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(r["blocks"][0]["height"], 5);
        let r = dispatch("getblockdag", Some(&json!([hex::encode([3u8; 32])])), &state).await;
        assert_eq!(r["colour"], "chain");
        assert_eq!(r["body"], false);
        assert_eq!(r["next_chain_block"], hex::encode([4u8; 32]));
        let r = dispatch("getblockdag", Some(&json!([hex::encode([0xEEu8; 32])])), &state).await;
        assert_eq!(r["error"], "block not found");
        // A writer can take the lock right after a read returns.
        drop(state.dag.try_write().expect("DAG lock must be free after an explorer read"));
    }

    /// NET-15 (re-audit): no explorer method reads storage while it holds
    /// the DAG read lock. A probe runs on every instrumented storage read of
    /// this thread and records a read made with the DAG locked; moving any
    /// storage access back into a `with_chain` closure makes this fail.
    #[test]
    fn net15_no_storage_read_runs_under_the_dag_lock() {
        let (_tmp, state) = state_with_chain(30);
        // Review: a confirmed transaction in a stored chain block, so
        // gettransactionfull reaches its `with_chain` colour lookup (with an
        // unknown txid it returned before it).
        let block = crate::core::genesis_block();
        let (bh, txid) = (block.block_hash(), block.transactions[0].txid());
        state.store.put_block(&block).unwrap();
        state.store.put_tx_index(&txid, &bh, 31).unwrap();
        state.dag.write().add_block(bh, vec![[30u8; 32]], 1_000 + 31 * 60, 1).unwrap();
        let addr = crate::crypto::address_from_hash(&[0x11; 20], crate::core::node_chain_id() == crate::core::ChainId::Testnet);
        let under_lock = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let reads = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let (dag, u, r) = (state.dag.clone(), under_lock.clone(), reads.clone());
        crate::storage::READ_PROBE.with(|p| *p.borrow_mut() = Some(Box::new(move || {
            r.set(r.get() + 1);
            if dag.is_locked() { u.set(u.get() + 1); }
        })));
        let chain_block = hex::encode([7u8; 32]);
        for (name, v) in [
            ("getselectedchain", explorer::get_selected_chain(Some(&json!([0, 10])), &state)),
            ("getblockdag", explorer::get_block_dag(Some(&json!([chain_block])), &state)),
            ("gettransactionfull", {
                let r = explorer::get_transaction_full(Some(&json!([hex::encode(txid)])), &state);
                assert_eq!((r["status"].as_str(), r["block_colour"].as_str()), (Some("confirmed"), Some("chain")), "{r}");
                r
            }),
            ("getdagwindow", explorer::get_dag_window(Some(&json!([50])), &state)),
            ("getaddresshistory", explorer::get_address_history(Some(&json!([addr])), &state)),
            ("getdifficultyhistory", explorer::get_difficulty_history(Some(&json!([5])), &state)),
        ] {
            assert!(v.is_object(), "{name}");
        }
        crate::storage::READ_PROBE.with(|p| *p.borrow_mut() = None);
        assert!(reads.get() >= 10, "the probe saw the explorer's storage reads ({})", reads.get());
        assert_eq!(under_lock.get(), 0, "storage reads made under the DAG read lock");
    }

    /// NET-15 residual: the explorer's selected-chain cache follows a tip
    /// change incrementally (work proportional to the blocks that left and
    /// joined the chain) and its first build takes the DAG read lock for a
    /// bounded number of blocks at a time. Pre-fix every tip change cloned
    /// the cached chain and rebuilt its position map (O(chain) under the
    /// DAG read lock), and the first call walked the whole chain under it.
    #[test]
    fn net15_chain_cache_follows_the_tip_incrementally() {
        const LEN: u32 = 2_000;
        let (_tmp, state) = state_with_chain(1);
        let h = |i: u32, side: u8| { let mut b = [side; 32]; b[..4].copy_from_slice(&i.to_be_bytes()); b[4] = 0xC5; b };
        {
            let mut dag = state.dag.write();
            let mut parent = [1u8; 32];
            for i in 2..=LEN {
                dag.add_block(h(i, 0), vec![parent], 1_000 + 30 * i as u64, 1).unwrap();
                parent = h(i, 0);
            }
        }
        let fresh_chain = |state: &AppState| { let mut c = state.dag.read().selected_chain(); c.reverse(); c };
        let check = |state: &AppState, bound: usize, what: &str| {
            let r = explorer::get_selected_chain(Some(&json!([0, 3])), state);
            let expect = fresh_chain(state);
            assert_eq!(r["chain_length"], expect.len(), "{what}");
            assert_eq!(r["blocks"][0]["hash"], hex::encode(expect.last().unwrap()), "{what}");
            let (chain, work) = explorer::chain_cache_probe(state).expect("cache built");
            assert_eq!(chain, expect, "{what}: cache equals the selected chain");
            assert!(work <= bound, "{what}: {work} blocks handled under one DAG lock hold > {bound}");
        };
        // First build: chunked, never the whole chain under one lock hold.
        check(&state, explorer::CHAIN_BUILD_CHUNK + 2, "first build");
        // One new block: constant work.
        state.dag.write().add_block(h(LEN + 1, 0), vec![h(LEN, 0)], 1_000 + 30 * (LEN as u64 + 1), 1).unwrap();
        check(&state, 4, "one block");
        // Review: a long gap with no explorer request (the node synced many
        // blocks meanwhile) is caught up in chunks too, not under one hold.
        {
            let mut dag = state.dag.write();
            for i in LEN + 2..=LEN + 300 {
                dag.add_block(h(i, 0), vec![h(i - 1, 0)], 1_000 + 30 * i as u64, 1).unwrap();
            }
        }
        check(&state, explorer::CHAIN_BUILD_CHUNK + 2, "long gap");
        // A reorg of depth 6 replaced by 10 side blocks: work ~ 16.
        {
            let mut dag = state.dag.write();
            let mut parent = h(LEN + 295, 0);
            for i in LEN + 296..=LEN + 306 {
                dag.add_block(h(i, 0xAB), vec![parent], 1_000 + 30 * i as u64 + 1, 1).unwrap();
                parent = h(i, 0xAB);
            }
        }
        check(&state, 40, "reorg");
        let r = explorer::get_block_dag(Some(&json!([hex::encode(h(LEN + 300, 0))])), &state);
        assert_ne!(r["colour"], "chain", "a block that left the chain is no longer reported on it");
    }

    /// CRY-3 / WAL-1: `getdaginfo` reports the height of the next block the
    /// mempool targets (`next_block_height`: the node's next template height,
    /// cached in the pool), which wallets sign for. It is not tip_height + 1
    /// when a template merges a tip with a greater DAG height (DAG-8). With no
    /// cached value it is computed (here: no bodied tip, so the selected tip's
    /// DAG height + 1).
    #[tokio::test]
    async fn getdaginfo_reports_the_pools_next_block_height() {
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["tip_height"], 5);
        assert_eq!(r["next_block_height"], 6);
        state.mempool.set_next_height(9);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["tip_height"], 5);
        assert_eq!(r["next_block_height"], 9, "the pool's next height, not tip_height + 1");
    }

    /// `getdaginfo` and `getnetworkinfo` report the hardening activation
    /// height in force (with no chain id set, as in every test: the mainnet
    /// height), and `getdaginfo` whether it applies at `next_block_height`,
    /// so an operator can confirm the upgrade (builds before 0.1.1 do not
    /// report it; docs/RUNNING.md).
    #[tokio::test]
    async fn rpc_reports_the_hardening_activation_height() {
        use crate::core::activation::{self, MAINNET_HARDENING_ACTIVATION_HEIGHT as MAINNET};
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getnetworkinfo", None, &state).await;
        assert_eq!(r["hardening_activation_height"], MAINNET);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_activation_height"], MAINNET);
        assert_eq!(r["hardening_active"], false, "next height 6 is below the mainnet activation");
        state.mempool.set_next_height(MAINNET - 1);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_active"], false);
        state.mempool.set_next_height(MAINNET);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_active"], true, "the activation height itself is hardened");
        let _g = activation::scoped_override(0);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_activation_height"], 0);
    }

    /// Review of audit F1, finding 1: `getdaginfo` lists the blocks whose
    /// validation ended without a verdict (class, attempts, reason, parked)
    /// and why the node stopped, if it did.
    #[tokio::test]
    async fn getdaginfo_reports_blocks_without_a_verdict() {
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["no_verdict"], json!([]));
        assert_eq!(r["stopped"], Value::Null);
        let tip = state.dag.read().selected_tip().unwrap();
        state.store.note_no_verdict(&tip, false, "tx-index row missing", std::time::Instant::now());
        state.dag.write().park_no_verdict(tip);
        let r = dispatch("getdaginfo", None, &state).await;
        let e = &r["no_verdict"][0];
        assert_eq!(e["hash"], hex::encode(tip));
        assert_eq!(e["status"], "no-verdict-parked");
        assert_eq!(e["class"], "inconsistent-chain-state");
        assert_eq!(e["attempts"], 1);
        assert_eq!(e["reason"], "tx-index row missing");
        assert!(e["retry_in_secs"].as_u64().unwrap() > 0);
        state.store.abort_node("stopped for the test".into());
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["stopped"], "stopped for the test");
    }

    /// POW-3: `getdaginfo` reports the node's minimum chain work (here
    /// mainnet's release value, what `start_rpc_server` takes from
    /// `ingress::minimum_chain_work` on a mainnet node without
    /// `--minimumchainwork`), in `tip_blue_work`'s unit and decimal format,
    /// and whether the selected tip is below it (initial block download), so
    /// an operator sees why a node does not leave IBD and the release tool
    /// (tools/release/min_chain_work.py) prints the value a node runs.
    /// Below it `getblocktemplate` refuses, as Bitcoin Core's does in
    /// initial block download: the tip may be a cheap chain the node's own
    /// pulls fetched from an eclipsing peer.
    #[tokio::test]
    async fn getdaginfo_and_getblocktemplate_apply_the_minimum_chain_work() {
        let (_tmp, mut state) = state_with_chain(5);
        assert_eq!(crate::ingress::minimum_chain_work(), crate::core::MIN_CHAIN_WORK, "the process default");
        state.min_chain_work = crate::core::MIN_CHAIN_WORK;
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["minimum_chain_work"], "7000000");
        assert_eq!(r["below_minimum_chain_work"], true, "a 5-block test chain");
        let t = dispatch("getblocktemplate", None, &state).await;
        let e = t["error"].as_str().unwrap_or_default();
        assert!(e.contains("initial block download") && e.contains("0x6acfc0"), "{t}");
        let tip_work: u128 = r["tip_blue_work"].as_str().unwrap().parse().unwrap();
        state.dag.write().add_block([0xD7; 32], vec![[5u8; 32]], 20_000, crate::core::MIN_CHAIN_WORK - tip_work)
            .unwrap();
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["tip_blue_work"], "7000000");
        assert_eq!(r["below_minimum_chain_work"], false, "at the minimum: out of IBD");
        let t = dispatch("getblocktemplate", None, &state).await;
        let e = t["error"].as_str().unwrap_or_default();
        assert!(!e.contains("initial block download"), "{t}");
        // With no minimum (testnet, `--minimumchainwork 0`) nothing is gated.
        let (_tmp0, state0) = state_with_chain(5);
        let r = dispatch("getdaginfo", None, &state0).await;
        assert_eq!((r["minimum_chain_work"].as_str(), r["below_minimum_chain_work"].as_bool()), (Some("0"), Some(false)));
    }

    /// B2-T5: `getdaginfo` used to walk the whole selected chain (under the
    /// DAG read lock) for `chain_length` on every call. Its DAG work no
    /// longer grows with the chain, and `chain_length` is still the number
    /// of blocks on the selected chain, genesis included.
    #[tokio::test]
    async fn getdaginfo_work_does_not_grow_with_the_chain() {
        let mut work = Vec::new();
        for extra in [0u32, 2_000] {
            let (_tmp, state) = state_with_chain(5);
            {
                let mut d = state.dag.write();
                let mut prev = [5u8; 32];
                for i in 0..extra {
                    let mut h = [0xA0u8; 32];
                    h[..4].copy_from_slice(&i.to_be_bytes());
                    d.add_block(h, vec![prev], 10_000 + u64::from(i), 1).unwrap();
                    prev = h;
                }
            }
            let before = state.dag.read().query_visits();
            let r = dispatch("getdaginfo", None, &state).await;
            work.push(state.dag.read().query_visits() - before);
            assert_eq!(r["chain_length"], 6 + extra as u64, "genesis + 5 + {extra}");
            assert_eq!(r["tip_height"], 5 + extra as u64);
        }
        assert!(work[1] <= work[0] + 4, "getdaginfo work grew with the chain: {work:?}");
    }
}

// ── Hardening block rules: getblocktemplate gives external miners the coinbase
//    layout and the Merkle rule of the template's height (package P1) ────────
#[cfg(test)]
mod block_rules_template_tests {
    use super::*;
    use crate::core::{self, activation, block_rules, Block, BlockHeader, MerkleRoot, TxInput, TxOutput};
    use tempfile::TempDir;

    /// An AppState whose DAG holds one bodied genesis (built under the
    /// calling thread's activation height).
    fn state_with_genesis() -> (TempDir, AppState) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("storage"));
        let mut genesis = core::genesis_block();
        genesis.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 1_000;
        let gh = genesis.block_hash();
        store.put_block(&genesis).unwrap();
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(gh, genesis.header.timestamp);
        let (outbound_tx, _rx) = mpsc::channel(1);
        let state = AppState {
            node_state: Arc::new(RwLock::new(NodeState::default())),
            store,
            mempool: Arc::new(Mempool::new()),
            dag: Arc::new(RwLock::new(dag)),
            outbound_tx,
            api_key: None,
            require_auth_for_writes: false,
            require_auth_for_reads: false,
            rate_limiter: Arc::new(auth::RateLimiterSet::new(60, 5)),
            trust_private_ranges: false,
            allowed_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(Vec::new()),
            trust_loopback: false,
            heavy_gate: Arc::new(HeavyGate::new(HEAVY_READ_CACHE_TTL)),
            template_gate: Arc::new(HeavyGate::for_templates()),
            pqpsbt_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            submit_block: None,
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            chain_admin: None,
            large_bodies: Arc::new(tokio::sync::Semaphore::new(RPC_LARGE_BODY_PERMITS)),
            large_bodies_reserved: Arc::new(tokio::sync::Semaphore::new(RPC_LARGE_BODY_RESERVED_PERMITS)),
            proxy_client_header: auth::DEFAULT_PROXY_CLIENT_HEADER.into(),
            tx_verify_budget: Arc::new(auth::ByteBudget::new(ANON_TX_VERIFY_BURST_BYTES, ANON_TX_VERIFY_BYTES_PER_SEC)),
            caller_trusted: false,
            // These fixture chains (work 1 per block) are far below
            // mainnet's minimum chain work; the test of `getdaginfo`'s
            // `minimum_chain_work` sets it.
            min_chain_work: 0,
        };
        (tmp, state)
    }

    fn hashes(v: &Value) -> Vec<[u8; 32]> {
        v.as_array().unwrap().iter()
            .map(|h| hex::decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
            .collect()
    }

    /// Assemble a block the way an external miner does from the RPC fields
    /// alone: coinbase script_sig = prefix || own bytes, header root folded
    /// from the coinbase txid through `coinbase_merkle_branch`.
    fn external_block(t: &Value, extra: &[u8]) -> Block {
        let mut script_sig = hex::decode(t["coinbase_script_sig_prefix"].as_str().unwrap()).unwrap();
        script_sig.extend_from_slice(extra);
        let value: u64 = t["subsidy_sat"].as_str().unwrap().parse().unwrap();
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: vec![0x44; 20] }],
            locktime: 0,
        };
        let hardened = t["merkle_rule"] == "gnb-tagged-v1";
        let root = block_rules::merkle_root_from_coinbase_branch(
            &coinbase.txid(), &hashes(&t["coinbase_merkle_branch"]), hardened);
        Block {
            header: BlockHeader {
                version: 1, parents: hashes(&t["parents"]), merkle_root: root,
                timestamp: t["min_time"].as_u64().unwrap() + 1,
                bits: t["bits"].as_u64().unwrap() as u32, nonce: 0,
            },
            transactions: vec![coinbase],
            blue_score: t["blue_score"].as_u64().unwrap(),
            height: t["height"].as_u64().unwrap(),
            shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    /// The getblocktemplate cache key follows the template's PARENTS, not
    /// the DAG's tip set: `invalidateblock` / `reconsiderblock` (DAG-6) leave
    /// the tip set and block count unchanged but change which tips are
    /// parents, and a header-only tip becomes a parent only when its body
    /// arrives. Each of these misses the cache at once (keyed on the tips, a
    /// miner kept the invalidated parent for up to TEMPLATE_CACHE_TTL).
    /// A height-1 block on genesis `gh` (timestamp `gts`), told apart by `tag`.
    fn genesis_child(gh: [u8; 32], gts: u64, tag: u8) -> Block {
        Block {
            header: BlockHeader {
                version: 1, parents: vec![gh], merkle_root: MerkleRoot::default(),
                timestamp: gts + 60, bits: core::POW_LIMIT_BITS, nonce: tag as u64,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: vec![tag; 8], sequence: u32::MAX }],
                outputs: vec![TxOutput { value: 1, script_pubkey: vec![0x44; 20] }],
                locktime: 0,
            }],
            blue_score: 1,
            height: 1,
            shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    #[test]
    fn template_cache_key_follows_invalidation_and_body_arrival() {
        let (_tmp, state) = state_with_genesis();
        let gh = state.dag.read().tips()[0];
        let gts = state.dag.read().get_block_data(&gh).map(|d| d.timestamp).unwrap_or(0);
        let child = |tag: u8| genesis_child(gh, gts, tag);
        let (a, b) = (child(1), child(2));
        let (ah, bh) = (a.block_hash(), b.block_hash());
        let parents_of = |state: &AppState| {
            let dag = state.dag.read();
            crate::template::template_parents_and_height(&dag, &state.store).0
        };

        // A bodied, B header-only: B is no parent, so its header changes
        // nothing; its body arriving does.
        state.store.put_block(&a).unwrap();
        state.dag.write().add_block(ah, vec![gh], gts + 60, 1).unwrap();
        let k_a = template_cache_key(None, &state);
        state.dag.write().add_block(bh, vec![gh], gts + 60, 1).unwrap();
        assert_eq!(parents_of(&state), vec![ah]);
        assert_eq!(template_cache_key(None, &state), k_a, "a header-only tip is no parent");
        state.store.put_block(&b).unwrap();
        let both = parents_of(&state);
        assert_eq!(both.len(), 2);
        let k_ab = template_cache_key(None, &state);
        assert_ne!(k_ab, k_a, "a parent's body arriving must miss the cached template");

        // invalidateblock A: same tips, same block count, other parents.
        let tips_before = state.dag.read().tips();
        state.dag.write().mark_invalid(ah);
        assert_eq!(state.dag.read().tips(), tips_before);
        assert_eq!(parents_of(&state), vec![bh]);
        let k_inv = template_cache_key(None, &state);
        assert_ne!(k_inv, k_ab, "an invalidated parent must miss the cached template");
        // reconsiderblock A: back to the first key.
        state.dag.write().reset_invalid_sets(std::iter::empty(), std::iter::empty());
        assert_eq!(parents_of(&state), both);
        assert_eq!(template_cache_key(None, &state), k_ab);
    }

    /// A template is cached under the parents it was BUILT on, not under the
    /// key read before the build. The race: a miner's call reads the key on
    /// [A]; block B is accepted while the build waits for the acceptance
    /// lock, so the template is built on [A, B]. Stored under the [A] key, an
    /// `invalidateblock B` (parents [A] again) within TEMPLATE_CACHE_TTL had
    /// the next call served the template on the invalidated B, which the node
    /// itself refuses. Now that call misses and builds on [A], and the
    /// template on [A, B] is served again only once B is reconsidered.
    #[test]
    fn a_template_is_cached_under_the_parents_it_was_built_on() {
        let (_tmp, state) = state_with_genesis();
        let gh = state.dag.read().tips()[0];
        let gts = state.dag.read().get_block_data(&gh).map(|d| d.timestamp).unwrap_or(0);
        let (a, b) = (genesis_child(gh, gts, 1), genesis_child(gh, gts, 2));
        let (ah, bh) = (a.block_hash(), b.block_hash());
        state.store.put_block(&a).unwrap();
        state.dag.write().add_block(ah, vec![gh], gts + 60, 1).unwrap();

        // What the builder returns: the parents and height it chose under the
        // acceptance lock (`build_block_template_with`), here read the same way.
        let built_on_current_parents = |n: u32| {
            let (parents, height) = {
                let dag = state.dag.read();
                crate::template::template_parents_and_height(&dag, &state.store)
            };
            json!({"build": n, "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(), "height": height})
        };
        let parents_in = |t: &Value| hashes(&t["parents"]);

        let t1 = gated_dispatch("getblocktemplate", None, &state, || {
            // B is accepted between the key lookup and the build.
            state.store.put_block(&b).unwrap();
            state.dag.write().add_block(bh, vec![gh], gts + 60, 1).unwrap();
            built_on_current_parents(1)
        });
        assert_eq!(parents_in(&t1).len(), 2, "{t1}");
        assert!(parents_in(&t1).contains(&bh));

        // invalidateblock B: the parents are [A] again.
        state.dag.write().mark_invalid(bh);
        let t2 = gated_dispatch("getblocktemplate", None, &state, || built_on_current_parents(2));
        assert_eq!(t2["build"], 2, "the template on the invalidated B was served from [A]'s key: {t2}");
        assert_eq!(parents_in(&t2), vec![ah]);

        // reconsiderblock B: the template on [A, B] is that key's again.
        state.dag.write().reset_invalid_sets(std::iter::empty(), std::iter::empty());
        let t3 = gated_dispatch("getblocktemplate", None, &state, || built_on_current_parents(3));
        assert_eq!(t3["build"], 1, "{t3}");
        // And [A] again serves the template built on [A].
        state.dag.write().mark_invalid(bh);
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, || built_on_current_parents(4))["build"], 2);
    }

    #[tokio::test]
    async fn getblocktemplate_returns_the_coinbase_layout_of_the_templates_height() {
        // From the activation: the 80-byte prefix, tagged root, wire size.
        {
            let _guard = activation::scoped_override(1);
            let (_tmp, state) = state_with_genesis();
            let t = dispatch("getblocktemplate", None, &state).await;
            assert_eq!(t["height"], 1, "{t}");
            assert_eq!(t["hardening_active"], true);
            assert_eq!(t["merkle_rule"], "gnb-tagged-v1");
            assert_eq!(t["size_rule"], "wire");
            let prefix = hex::decode(t["coinbase_script_sig_prefix"].as_str().unwrap()).unwrap();
            assert_eq!(prefix.len(), block_rules::COINBASE_COMMITMENT_LEN);
            assert_eq!(&prefix[..8], b"GNB-CB01");
            // The whole coinbase must fit the reserve: far below the
            // script_sig cap (9,920), which a full template has no room for.
            let max_extra = t["max_coinbase_extra_bytes"].as_u64().unwrap() as usize;
            assert_eq!(max_extra, crate::template::external_coinbase_max_extra(80, true, 1_000));
            assert!(max_extra > 700 && max_extra < 1_000 - 80, "{max_extra}");
            assert_eq!(t["max_coinbase_script_pubkey_bytes"], crate::template::EXTERNAL_COINBASE_MAX_SPK);
            let block = external_block(&t, &vec![0xE5; max_extra]);
            assert!(block.transactions[0].wire_size(true) <= t["coinbase_reserve"].as_u64().unwrap() as usize);
            assert_eq!(block_rules::check_block_hardened_at(&block, 1), Ok(()));
            assert_eq!(block.validate_structure_without_pow_at(1), Ok(()));
            let block = external_block(&t, b"pool-extranonce");
            assert_eq!(block_rules::check_block_hardened_at(&block, 1), Ok(()));
            assert_eq!(block.validate_structure_without_pow_at(1), Ok(()));
            assert_eq!(block.body_merkle_root(), block.header.merkle_root);
        }
        // Below it: no prefix, the legacy root and bincode size, as before.
        {
            let _guard = activation::scoped_override(activation::NEVER);
            let (_tmp, state) = state_with_genesis();
            let t = dispatch("getblocktemplate", None, &state).await;
            assert_eq!(t["hardening_active"], false, "{t}");
            assert_eq!(t["merkle_rule"], "sha256d-duplicate-last");
            assert_eq!(t["size_rule"], "bincode");
            assert_eq!(t["coinbase_script_sig_prefix"], "");
            let max_extra = t["max_coinbase_extra_bytes"].as_u64().unwrap() as usize;
            assert_eq!(max_extra, crate::template::external_coinbase_max_extra(0, false, 1_000));
            assert!(max_extra > 800 && max_extra < 1_000, "{max_extra}");
            let block = external_block(&t, &vec![0xE5; max_extra]);
            assert!(block.transactions[0].actual_size() <= t["coinbase_reserve"].as_u64().unwrap() as usize);
            assert_eq!(block.validate_structure_without_pow_at(activation::NEVER), Ok(()));
            let block = external_block(&t, b"height:1 pool");
            assert_eq!(block.validate_structure_without_pow_at(activation::NEVER), Ok(()));
            assert_eq!(block.header.merkle_root, core::Transaction::merkle_root(&block.transactions));
            assert_ne!(block.header.merkle_root, MerkleRoot::ZERO);
        }
    }

    /// Review of PR #15, finding 2: while a branch parked without a verdict
    /// has more chain work than the applied tip (the node mines on the
    /// lighter chain it can judge), getblocktemplate, getdaginfo and
    /// getnetworkinfo say so in `warnings`; not otherwise.
    #[tokio::test]
    async fn a_heavier_branch_parked_without_a_verdict_is_warned_about() {
        let _guard = activation::scoped_override(1);
        let (_tmp, state) = state_with_genesis();
        let gh = state.dag.read().selected_tip().unwrap();
        let ts = state.dag.read().get_block_data(&gh).unwrap().timestamp;
        for m in ["getblocktemplate", "getdaginfo", "getnetworkinfo"] {
            let r = dispatch(m, None, &state).await;
            assert_eq!(r["warnings"], json!([]), "{m}: {r}");
        }
        {
            let mut d = state.dag.write();
            d.add_block([0xB1; 32], vec![gh], ts + 1, 10).unwrap();
            d.add_block([0xB2; 32], vec![[0xB1; 32]], ts + 2, 10).unwrap();
        }
        state.store.note_no_verdict(&[0xB1; 32], false, "tx-index row missing", std::time::Instant::now());
        state.dag.write().park_no_verdict([0xB1; 32]);
        assert_eq!(state.dag.read().selected_tip(), Some(gh));
        for m in ["getblocktemplate", "getdaginfo", "getnetworkinfo"] {
            let r = dispatch(m, None, &state).await;
            let w = r["warnings"][0].as_str().unwrap_or_default();
            assert!(w.contains("parked without a verdict") && w.contains(&hex::encode([0xB1u8; 8]))
                && w.contains("tx-index row missing") && w.contains(&hex::encode([0xB2u8; 8])), "{m}: {r}");
        }
        let t = dispatch("getblocktemplate", None, &state).await;
        assert_eq!(t["parents"], json!([hex::encode(gh)]), "the template is still built: {t}");
        // A heavier chain the node can judge: the parked branch is lighter.
        {
            let mut d = state.dag.write();
            d.add_block([0xC1; 32], vec![gh], ts + 1, 30).unwrap();
        }
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["warnings"], json!([]), "{r}");
    }
}
