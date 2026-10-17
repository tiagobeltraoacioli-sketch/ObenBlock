//! gnb-cli — Bloch-SIS Protocol RPC client (like bitcoin-cli)
//!
//! Usage:
//!   gnb-cli getnetworkinfo
//!   gnb-cli getbalance gnb1q...
//!   gnb-cli send &lt;wallet.json&gt; &lt;to_address&gt; &lt;amount_gnb&gt; [--fee 0.0005]
//!   gnb-cli --help

use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    // Parse --rpc-url flag (default: 127.0.0.1:17210)
    let mut rpc_host = "127.0.0.1".to_string();
    let mut rpc_port = 17210u16;
    // WAL-7: `--rpc-url https://node.example` (certificate-verified), with
    // `--rpc-ca <PEM/DER file>` for a private CA or self-signed certificate.
    let mut rpc_url: Option<String> = None;
    let mut rpc_ca: Option<String> = None;
    let mut allow_large_hd_wallet = false;
    // WAL-7: the network of a new wallet is an explicit choice recorded in
    // the file (keystore v3 authenticates it), never inferred from its name.
    let mut testnet = false;
    // CRY-7: `send` unlocks a v2 keystore only for an explicitly stated
    // network (--mainnet / --testnet), then rewrites it as v3.
    let mut mainnet = false;
    let mut cmd_args: Vec<&str> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc-host" => { i += 1; if i < args.len() { rpc_host = args[i].clone(); } }
            "--rpc-port" => { i += 1; if i < args.len() { rpc_port = args[i].parse().unwrap_or(17210); } }
            "--rpc-url" => { i += 1; if i < args.len() { rpc_url = Some(args[i].clone()); } }
            "--rpc-ca" => { i += 1; if i < args.len() { rpc_ca = Some(args[i].clone()); } }
            "--allow-large-hd-wallet" => { allow_large_hd_wallet = true; }
            "--testnet" => { testnet = true; }
            "--mainnet" => { mainnet = true; }
            _ => { cmd_args.push(&args[i]); }
        }
        i += 1;
    }
    if testnet && mainnet {
        die("--mainnet and --testnet are mutually exclusive");
    }
    let stated_network = match (testnet, mainnet) {
        (true, _) => Some(gnb::address::Network::Testnet),
        (false, true) => Some(gnb::address::Network::Mainnet),
        (false, false) => None,
    };
    let rpc_target = RpcTarget::new(rpc_url, &rpc_host, rpc_port, rpc_ca.as_deref());

    if cmd_args.is_empty() {
        print_usage();
        return;
    }

    let method = cmd_args[0];
    let params = &cmd_args[1..];

    let (rpc_method, rpc_params) = match method {

        // ── Network ────────────────────────────────────────────────
        "getnetworkinfo" | "info" => ("getnetworkinfo", serde_json::Value::Null),
        "getblockcount"  | "height" => ("getblockcount", serde_json::Value::Null),
        "getmempoolinfo" | "mempool" => ("getmempoolinfo", serde_json::Value::Null),

        // ── Blocks ─────────────────────────────────────────────────
        "getblockhash" => {
            require_params(params, 1, "getblockhash <height>");
            let h: u64 = params[0].parse().unwrap_or_else(|_| die("height must be a number"));
            ("getblockhash", serde_json::json!([h]))
        }

        "getblock" => {
            require_params(params, 1, "getblock <hash> [verbose]");
            let verbose = params.get(1).map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getblock", serde_json::json!([params[0], verbose]))
        }

        "getblockbyheight" | "block" => {
            require_params(params, 1, "getblockbyheight <height> [verbose]");
            let h: u64 = params[0].parse().unwrap_or_else(|_| die("height must be a number"));
            let verbose = params.get(1).map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getblockbyheight", serde_json::json!([h, verbose]))
        }

        "getrecentblocks" | "recent" => {
            let count: u64 = params.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            ("getrecentblocks", serde_json::json!([count]))
        }

        // ── Transactions ───────────────────────────────────────────
        "gettransaction" | "tx" => {
            require_params(params, 1, "gettransaction <txid>");
            ("gettransaction", serde_json::json!([params[0]]))
        }

        "sendrawtransaction" | "sendraw" => {
            require_params(params, 1, "sendrawtransaction <hex>");
            ("sendrawtransaction", serde_json::json!([params[0]]))
        }

        // ── Wallet ─────────────────────────────────────────────────
        "getbalance" | "balance" => {
            require_params(params, 1, "getbalance <address>");
            ("getbalance", serde_json::json!([params[0]]))
        }

        "getutxos" | "utxos" | "listunspent" => {
            require_params(params, 1, "getutxos <address>");
            ("getutxos", serde_json::json!([params[0]]))
        }

        // ── Phase 2: new commands ──────────────────────────────────
        "validateaddress" | "validate" => {
            require_params(params, 1, "validateaddress <address>");
            ("validateaddress", serde_json::json!([params[0]]))
        }

        "estimatefee" | "fee" => {
            ("estimatefee", serde_json::Value::Null)
        }

        "getrawmempool" | "rawmempool" => {
            let verbose = params.first().map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getrawmempool", serde_json::json!([verbose]))
        }

        "decoderawtransaction" | "decode" => {
            require_params(params, 1, "decoderawtransaction <hex>");
            ("decoderawtransaction", serde_json::json!([params[0]]))
        }

        "submitpowit" => {
            require_params(params, 2, "submitpowit <kind 1|2|3> <hex>");
            let kind: u64 = params[0].parse().unwrap_or(0);
            ("submitpowititem", serde_json::json!([kind, params[1]]))
        }
        // Create a forward-secure PoWit witness key (KES). Password from
        // GNB_WALLET_PASSWORD or a prompt; the seed never leaves the file
        // unencrypted.
        "witnesskeygen" => {
            require_params(params, 1, "witnesskeygen <out.json> [depth=12]");
            let depth: u8 = params.get(1).and_then(|d| d.parse().ok()).unwrap_or(gnb::core::kes::DEFAULT_DEPTH);
            // CRY-4: the password stays in wiping storage (it was copied
            // into a plain String).
            let pw = match std::env::var("GNB_WALLET_PASSWORD") {
                Ok(p) => zeroize::Zeroizing::new(p),
                Err(_) => {
                    let a = read_password("Set witness key password: ");
                    let b = read_password("Confirm: ");
                    if *a != *b { eprintln!("Passwords don't match."); process::exit(1); }
                    a
                }
            };
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            rand::fill(&mut seed[..]);
            let total = 1u64 << depth;
            eprintln!("Generating {} epoch keys (hybrid ML-DSA-65 + Falcon-1024)...", total);
            // CRY-4: the seed is borrowed, never copied out of its wiping
            // owner (passing the array by value, as clippy suggests for a
            // `Borrow` argument, would leave an unwiped copy).
            #[allow(clippy::needless_borrows_for_generic_args)]
            let signer = gnb::core::kes::KesSigner::generate(depth, &*seed, |i| {
                if i % 256 == 0 || i == total { eprint!("\r  {}/{}", i, total); }
            }).unwrap_or_else(|e| { eprintln!("{}", e); process::exit(1) });
            eprintln!();
            let file = gnb::core::kes::KesKeyFile::seal(&signer, &pw)
                .unwrap_or_else(|e| { eprintln!("{}", e); process::exit(1) });
            file.save(std::path::Path::new(params[0])).unwrap_or_else(|e| { eprintln!("{}", e); process::exit(1) });
            println!("Witness key saved: {}", params[0]);
            println!("Witness id:        {}", hex::encode(signer.public().witness_id()));
            println!("Epochs:            {} (depth {})", total, depth);
            println!("Back up ONLY this file. Older copies of it can sign past epochs.");
            return;
        }
        // Sign a PoWit link with a KES witness key and print the attestation
        // hex (kind 2). For operators and tests: unlike the node's witness duty
        // this does not consult a vote record, and it evolves the key file.
        "powitattest" => {
            require_params(params, 6,
                "powitattest <witness-key.json> <mainnet|testnet> <src_slot> <src_hash> <tgt_slot> <tgt_hash> [activation]");
            // CRY-4: wiping storage, as for witnesskeygen.
            let pw = match std::env::var("GNB_WALLET_PASSWORD") {
                Ok(p) => zeroize::Zeroizing::new(p),
                Err(_) => read_password("Witness key password: "),
            };
            let path = std::path::Path::new(params[0]);
            let file = gnb::core::kes::KesKeyFile::load(path).unwrap_or_else(|e| { eprintln!("{}", e); process::exit(1) });
            let mut signer = file.open(&pw).unwrap_or_else(|e| { eprintln!("{}", e); process::exit(1) });
            let chain = if params[1] == "testnet" { gnb::core::ChainId::Testnet } else { gnb::core::ChainId::Mainnet };
            let cp = |slot: &str, h: &str| -> gnb::core::powit::Checkpoint {
                let mut hash = [0u8; 32];
                let b = hex::decode(h).unwrap_or_default();
                if b.len() != 32 { eprintln!("hash must be 32 bytes hex"); process::exit(1); }
                hash.copy_from_slice(&b);
                gnb::core::powit::Checkpoint { height: slot.parse().unwrap_or(0), hash }
            };
            let (src, tgt) = (cp(params[2], params[3]), cp(params[4], params[5]));
            let act: u64 = params.get(6).and_then(|a| a.parse().ok()).unwrap_or(0);
            let p = gnb::core::powit::params_for(chain);
            if tgt.height < act { eprintln!("target below activation"); process::exit(1); }
            let e = p.epoch(act, tgt.height);
            if e > signer.epoch() {
                signer.evolve_to(e).unwrap_or_else(|er| { eprintln!("{}", er); process::exit(1) });
                gnb::core::kes::KesKeyFile::seal(&signer, &pw).and_then(|f| f.save(path))
                    .unwrap_or_else(|er| { eprintln!("{}", er); process::exit(1) });
            } else if e < signer.epoch() {
                eprintln!("epoch {} already erased (key is at {}): forward security", e, signer.epoch());
                process::exit(1);
            }
            // The message of the target's height on `chain`'s schedule: from
            // the second hardening activation it commits the witness key
            // (PoWit audit finding 1). A signer has no node chain id, so the
            // schedule comes from the chain named here.
            let h2 = gnb::core::activation::hardening2_activation_height_for_signer(chain);
            let att = gnb::core::powit::Attestation::sign_at(chain, h2, src, tgt, &signer)
                .unwrap_or_else(|er| { eprintln!("{}", er); process::exit(1) });
            println!("{}", hex::encode(att.to_wire_bytes()));
            return;
        }
        "getpowitinfo" | "powit" => {
            ("getpowitinfo", serde_json::Value::Null)
        }
        "getdaginfo" | "dag" => {
            ("getdaginfo", serde_json::Value::Null)
        }

        // ── Operator recovery (audit DAG-6) ────────────────────────
        "invalidateblock" => {
            require_params(params, 1, "invalidateblock <block_hash>");
            ("invalidateblock", serde_json::json!([params[0]]))
        }
        "reconsiderblock" => {
            require_params(params, 1, "reconsiderblock <block_hash>");
            ("reconsiderblock", serde_json::json!([params[0]]))
        }

        "listtransactions" | "txlist" => {
            require_params(params, 1, "listtransactions <address> [count]");
            let count: u64 = params.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            ("listtransactions", serde_json::json!([params[0], count]))
        }

        "getpeerinfo" | "peers" => {
            ("getpeerinfo", serde_json::Value::Null)
        }

        // ── Wallet: send (builds + signs + broadcasts) ─────────────
        "send" => {
            require_params(params, 3, "send <wallet.json> <to_address> <amount_gnb> [--fee auto|GNB] [--max-fee GNB] [--yes] [--allow-unverified-inputs]");
            do_send(params, &rpc_target, stated_network);
            return;
        }

        // ── Multisig / timelock policies (core::policy) ────────────
        "pubkey" => {
            require_params(params, 1, "pubkey <wallet.json>");
            let kp = load_keypair(params[0], stated_network);
            println!("{}", hex::encode(&kp.public_key));
            return;
        }
        "policyaddress" => {
            require_params(params, 2, POLICY_ADDRESS_USAGE);
            do_policy_address(params, stated_network);
            return;
        }
        "policyspend" => {
            require_params(params, 3, POLICY_SPEND_USAGE);
            do_policy_spend(params, stated_network);
            return;
        }
        "pqpsbt" => {
            do_pqpsbt(params);
            return;
        }
        "descriptor" => {
            do_descriptor(params, stated_network);
            return;
        }
        "policysign" => {
            require_params(params, 2, POLICY_SIGN_USAGE);
            do_policy_sign(params, &rpc_target, stated_network);
            return;
        }
        "policysend" => {
            require_params(params, 1, "policysend <spend.json>");
            do_policy_send(params, &rpc_target);
            return;
        }

        // ── Bloch bridge vault (docs/SIDECHAIN-BLOCH.md) ──────────────
        "vaultcreate" => {
            require_params(params, 1, VAULT_CREATE_USAGE);
            do_vault_create(params, stated_network);
            return;
        }
        "vaultlock" => {
            require_params(params, 4, "vaultlock <wallet.json> <vault.json> <amount GNB> <0xL2address> [--fee GNB]");
            do_vault_lock(params, &rpc_target, stated_network);
            return;
        }
        "vaultchecklock" => {
            require_params(params, 2, "vaultchecklock <vault.json> <txid> [--min-conf N] [--min-amount SATS] [--finalized]");
            do_vault_check_lock(params, &rpc_target);
            return;
        }
        "vaultrelease" => {
            require_params(params, 4, "vaultrelease <vault.json> <burn_id hex> <gnb1 recipient> <burn amount SATS> --utxo TXID:VOUT:SATS ... --out spend.json");
            do_vault_release(params, stated_network);
            return;
        }
        "vaultcheckrelease" => {
            require_params(params, 5, "vaultcheckrelease <vault.json> <spend.json> <burn_id hex> <gnb1 recipient> <burn amount SATS>");
            do_vault_check_release(params, &rpc_target, stated_network);
            return;
        }
        "vaultrecover" => {
            require_params(params, 3, "vaultrecover <vault.json> <gnb1 destination> <amount GNB> --utxo TXID:VOUT:SATS ... --out spend.json");
            do_vault_recover(params, stated_network);
            return;
        }
        "vaultutxos" => {
            require_params(params, 1, "vaultutxos <vault.json>");
            do_vault_utxos(params, &rpc_target);
            return;
        }

        // ── Diagnostic: key format (no secret leaked — lengths/suite only) ─────
        "keyinfo" => {
            require_params(params, 1, "keyinfo <wallet.json>");
            let pw = read_password("Wallet password: ");
            let path = std::path::Path::new(params[0]);
            // CRY-7: a v2 keystore opens only for the network stated with
            // --mainnet / --testnet (v3 authenticates its own).
            match open_keystore(path, &pw, stated_network) {
                Ok(kp) => {
                    let pk = &kp.public_key; let sk = &kp.private_key;
                    // B2-T2: encodings are told apart by exact length, never by
                    // the first bytes (a raw key starts with random bytes).
                    let suite = gnb::crypto::public_key_suite(pk);
                    let pk_form = match suite {
                        Some(_) if pk.len() == 3_745 => "RAW hybrid (pre-envelope)".to_string(),
                        Some(s) => format!("enveloped suite 0x{s:04x}"),
                        None => "UNKNOWN encoding".to_string(),
                    };
                    let sk_form = match suite {
                        Some(1) if sk.len() == 6_337 => "RAW hybrid (pre-envelope)",
                        Some(1) if sk.len() == 6_341 => "enveloped suite 0x0001",
                        Some(2) if sk.len() == 4_032 => "RAW ML-DSA-65",
                        Some(2) if sk.len() == 4_036 => "enveloped suite 0x0002",
                        _ => "does not match the public key's suite",
                    };
                    println!("address:      {}", kp.address);
                    println!("pubkey  len:  {}  ({})", pk.len(), pk_form);
                    println!("privkey len:  {}  ({})", sk.len(), sk_form);
                    println!("expected: hybrid pk=3745 raw / 3749 enveloped, sk=6337 raw / 6341 enveloped; \
                              mldsa-only pk=1956 sk=4036");
                }
                Err(e) => { eprintln!("load failed: {}", e); process::exit(1); }
            }
            return;
        }

        // ── Wallet: generate ───────────────────────────────────────
        "newwallet" | "createwallet" => {
            require_params(params, 1, "newwallet <output_path.json> [--random-key] [--testnet]");
            let random_key = params[1..].contains(&"--random-key");
            do_new_wallet(params[0], testnet, random_key);
            return;
        }

        "restorewallet" => {
            require_params(params, 1, "restorewallet <output_path.json> [--testnet]");
            do_restore_wallet(params[0], testnet);
            return;
        }

        // ── Phase 3: HD Wallet commands ────────────────────────────
        "newseed" => {
            require_params(params, 1, "newseed <output_path.json> [--testnet]");
            do_newseed(params[0], testnet);
            return;
        }

        "newaddress" => {
            require_params(params, 1, "newaddress <wallet-hd.json> [label]");
            let label = params.get(1).copied().unwrap_or("new");
            do_newaddress(params[0], label, allow_large_hd_wallet);
            return;
        }

        "addresses" => {
            require_params(params, 1, "addresses <wallet-hd.json>");
            do_list_addresses(params[0], allow_large_hd_wallet);
            return;
        }

        "importfounder" | "import-founder" => {
            require_params(params, 2, "importfounder <wallet-hd.json> <founder.json>");
            do_import_founder(params[0], params[1], allow_large_hd_wallet, stated_network);
            return;
        }

        // ── PoI: Proof-of-Improvement ──────────────────────────────
        "pools" | "getpools" | "treasury" | "gettreasury" => {
            // V2: aliases preserved for UX; routes to V2 multi-pool endpoint.
            ("getpools", serde_json::Value::Null)
        }

        "poiclaims" | "claims" => {
            ("getpoiclaims", serde_json::Value::Null)
        }

        "poiclaim" | "claim" => {
            require_params(params, 1, "poiclaim <claim_id_hex>");
            ("getpoiclaim", serde_json::json!([params[0]]))
        }

        "poisubmit" | "submitclaim" => {
            require_params(params, 4, "poisubmit <commit_hash> <category:0-3> <description> <address> [ci_attestation]");
            let ci = params.get(4).copied().unwrap_or("");
            ("submitpoiclaim", serde_json::json!([params[0], params[1].parse::<u64>().unwrap_or(3), params[2], params[3], ci]))
        }

        "poivote" | "vote" => {
            require_params(params, 3, "poivote <claim_id> <voter_address> <yes|no|abstain>");
            ("submitpoivote", serde_json::json!([params[0], params[1], params[2]]))
        }

        // ── eUTXO VM (node must run with --features euvm) ──────────
        // Thin passthroughs to the D5 euvm_* RPC methods; on a node built
        // without the feature they return "unknown method".
        "euvm_utxos" | "euvm_listutxos" => {
            // [validator_hash|null] [limit] [offset]
            let vh = params.get(0)
                .filter(|s| **s != "null" && !s.is_empty())
                .map(|s| serde_json::json!(s))
                .unwrap_or(serde_json::Value::Null);
            let limit: u64 = params.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            let offset: u64 = params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            ("euvm_listutxos", serde_json::json!([vh, limit, offset]))
        }

        "euvm_getutxo" => {
            require_params(params, 2, "euvm_getutxo <txid_hex> <index>");
            let idx: u64 = params[1].parse().unwrap_or_else(|_| die("index must be a number"));
            ("euvm_getutxo", serde_json::json!([params[0], idx]))
        }

        "euvm_buildtx" => {
            // Takes the full build-request object as ONE JSON argument:
            //   gnb-cli euvm_buildtx '{"inputs":[...],"outputs":[...]}'
            // (May carry secret keys — the node treats it as an auth-gated
            // write; set GNB_RPC_API_KEY if the node requires auth.)
            require_params(params, 1, "euvm_buildtx '<build-request-json>'");
            let obj: serde_json::Value = serde_json::from_str(params[0])
                .unwrap_or_else(|e| die(&format!("argument must be valid JSON: {}", e)));
            ("euvm_buildtx", serde_json::json!([obj]))
        }

        // ── Help ───────────────────────────────────────────────────
        "help" => { print_usage(); return; }

        _ => {
            eprintln!("Unknown command: {}", method);
            eprintln!("Run 'gnb-cli help' for usage.");
            process::exit(1);
        }
    };

    // Make RPC call
    match rpc_call(&rpc_target, rpc_method, &rpc_params) {
        Ok(result) => {
            let pretty = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
            println!("{}", pretty);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

// ── RPC client ──────────────────────────────────────────────────────────────

/// Where gnb-cli sends its RPCs (WAL-7).
struct RpcTarget {
    /// `host:port` (plain HTTP), `http://…` or `https://…`.
    endpoint: String,
    /// HTTPS trust anchors: the webpki roots, or `--rpc-ca`.
    trust: gnb::wallet::http_rpc::TlsTrust,
}

impl RpcTarget {
    fn new(rpc_url: Option<String>, host: &str, port: u16, ca: Option<&str>) -> RpcTarget {
        let endpoint = match rpc_url {
            Some(url) => url,
            None if host.contains("://") => host.to_string(),
            None if host.contains(':') && !host.starts_with('[') => format!("[{host}]:{port}"),
            None => format!("{host}:{port}"),
        };
        let trust = match ca {
            Some(path) => gnb::wallet::http_rpc::TlsTrust::from_cert_file(std::path::Path::new(path))
                .unwrap_or_else(|e| die(&e)),
            None => gnb::wallet::http_rpc::TlsTrust::WebPkiRoots,
        };
        RpcTarget { endpoint, trust }
    }
}

/// JSON-RPC over HTTP or HTTPS. WAL-7/NET-16: `GNB_RPC_API_KEY` is sent over
/// HTTPS (certificate-verified) to any host, over plain HTTP only to a
/// loopback address (remote nodes: https:// or an SSH tunnel).
fn rpc_call(target: &RpcTarget, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    let api_key = std::env::var("GNB_RPC_API_KEY").ok().map(zeroize::Zeroizing::new);
    gnb::wallet::http_rpc::call_with_trust(&target.endpoint, method, params,
        api_key.as_deref().map(String::as_str), &target.trust)
}

// ── Send command ────────────────────────────────────────────────────────────

fn do_send(params: &[&str], target: &RpcTarget, stated_network: Option<gnb::address::Network>) {
    let wallet_path = params[0];
    let to_address = params[1];
    let amount_str = params[2];

    // Fee: `auto` (default) = the consensus minimum for the signed
    // transaction's actual size; a GNB value is a floor raised to that
    // minimum. --max-fee replaces the default guard explicitly (WAL-1).
    let mut fee_arg = "auto";
    let mut max_fee_arg: Option<&str> = None;
    let mut yes = false;
    let mut allow_unverified = false;
    let mut i = 3;
    while i < params.len() {
        match params[i] {
            "--fee" if i + 1 < params.len() => { fee_arg = params[i + 1]; i += 2; }
            "--max-fee" if i + 1 < params.len() => { max_fee_arg = Some(params[i + 1]); i += 2; }
            "--yes" | "-y" => { yes = true; i += 1; }
            "--allow-unverified-inputs" => { allow_unverified = true; i += 1; }
            other => die(&format!("unknown send option {other:?}")),
        }
    }

    let amount_sats = bloch_to_sats(amount_str);
    let fee = gnb::wallet::send::parse_fee_arg(fee_arg).unwrap_or_else(|message| die(message));
    let fee_policy = gnb::wallet::send::parse_max_fee_arg(max_fee_arg).unwrap_or_else(|message| die(message));

    // Load wallet
    let password = read_password("Wallet password: ");
    let path = std::path::Path::new(wallet_path);
    // Keystore v3/v2 first (address field; bloch1q… accepted for v2), then
    // the v1 keyfile format (address derived from the public key).
    // CRY-7: a v2 keystore needs the network stated (--mainnet/--testnet);
    // it is checked against the stored address and rewritten as v3 — but only
    // once the send is confirmed, keeping the original as <file>.v2.bak.
    let (keypair, pending_migration) = match gnb::wallet::Keypair::unlock_for_spending(path, &password, stated_network) {
        Ok((kp, pending)) => {
            if pending.is_some() {
                eprintln!("Keystore {} is v2: it is rewritten as v3 (network and address authenticated) \
                           once the send is confirmed; the original is kept as a .v2.bak copy for Bloch \
                           wallets and GnB releases before v3, which read only version 2.", path.display());
            }
            (kp, pending)
        }
        Err(e2) if is_keystore_v2_or_v3(path) => die(&format!("Failed to load wallet: {e2}")),
        Err(e2) => match gnb::wallet::Wallet::load_encrypted(path, &password) {
            Ok(w) => {
                if stated_network.is_some_and(|n| n != w.network()) {
                    die("the wallet's network does not match --mainnet/--testnet");
                }
                (w.into_keypair(), None)
            }
            Err(e1) => {
                eprintln!("Failed to load wallet: {} (keystore v2/v3) / {} (keyfile v1)", e2, e1);
                process::exit(1);
            }
        },
    };
    drop(password);

    checked_destination(to_address, &keypair.address).unwrap_or_else(|message| die(message));
    let to = gnb::address::Address::parse(to_address).unwrap_or_else(|_| die("invalid destination address"));

    // Fetch UTXOs (bounded), verify the selected ones against their
    // transactions (WAL-1), build and sign under the fee guard.
    let rpc = |method: &str, p: &serde_json::Value| rpc_call(target, method, p);
    let request = gnb::wallet::send::SendRequest {
        keypair: &keypair,
        to: &to,
        amount: amount_sats,
        fee,
        fee_policy,
        // Non-interactive sends refuse unprovable inputs unless asked.
        require_verified_inputs: yes && !allow_unverified,
        utxo_limit: 50,
    };
    let prepared = gnb::wallet::send::prepare_send(&rpc, &request)
        .unwrap_or_else(|e| die(&format!("TX build failed: {e}")));

    // Show what will be signed — with the ACTUAL fee — and confirm (WAL-7).
    println!("UTXOs seen: {} ({} GNB)", prepared.utxos_seen, prepared.value_seen as f64 / 1e8);
    for (k, v) in prepared.summary(&keypair.address, to_address) {
        println!("{:<14} {}", format!("{k}:"), v);
    }
    if !yes && !gnb::wallet::send::confirm("Broadcast this transaction?") {
        die("not broadcast");
    }
    // CRY-7: the send passed every check and was confirmed.
    if let Some(pending) = pending_migration {
        match pending.commit() {
            Ok(backup) => eprintln!("Keystore {} rewritten as v3; the v2 original is kept at {} \
                                     (keep it for Bloch or older GnB releases).", path.display(), backup.display()),
            Err(e) => eprintln!("Keystore not migrated: {e}"),
        }
    }

    match gnb::wallet::send::broadcast(&rpc, &prepared) {
        Ok(txid) => println!("Broadcast OK: {txid}"),
        Err(e) => die(&format!("Broadcast failed: {e}")),
    }
}


// ── New wallet command ──────────────────────────────────────────────────────

// ── Phase 3: HD Wallet functions ────────────────────────────────────────────

/// Prompt for a new password twice (CRY-4: every copy is zeroizing).
fn read_new_password() -> zeroize::Zeroizing<String> {
    loop {
        let p1 = read_password("Set password (min 12 chars, 3 of: upper/lower/digit/special): ");
        if let Err(e) = gnb::wallet::validate_password(&p1) {
            eprintln!("Weak password: {}", e);
            continue;
        }
        let p2 = read_password("Confirm password: ");
        if *p1 != *p2 {
            eprintln!("Passwords don't match.");
            continue;
        }
        break p1;
    }
}

/// WAL-7: a file name containing "testnet" no longer selects the network.
fn warn_if_name_suggests_other_network(output_path: &str, testnet: bool) {
    if output_path.contains("testnet") && !testnet {
        eprintln!("Note: creating a MAINNET wallet; pass --testnet for a testnet wallet \
                   (the network is no longer inferred from the file name).");
    }
}

fn do_newseed(output_path: &str, testnet: bool) {
    println!("Generating HD wallet with 24-word mnemonic...");
    println!();
    warn_if_name_suggests_other_network(output_path, testnet);

    let password = read_new_password();

    let use_passphrase = read_password("Optional passphrase (press Enter to skip): ");
    let passphrase = if use_passphrase.is_empty() { None } else { Some(use_passphrase.as_str()) };

    // CRY-4: the wallet does not keep the phrase; `create` hands it over
    // once, it is printed from one wiping buffer and wiped when dropped.
    let (wallet, phrase) = match gnb::hd_wallet::HdWallet::create(&password, passphrase, testnet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to create wallet: {}", e); process::exit(1); }
    };

    let first_addr = wallet.addresses[0].1.address.clone();

    let path = std::path::Path::new(output_path);
    if let Err(e) = wallet.save(path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("  BACKUP YOUR MNEMONIC PHRASE (24 words)");
    println!("══════════════════════════════════════════════════════════════");
    println!();
    let words: Vec<&str> = phrase.words().collect();
    if let Err(e) = gnb::wallet::print_phrase_grid(&words, "  ") {
        die(&format!("cannot print the mnemonic: {e}"));
    }
    drop(words);
    drop(phrase);
    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!();
    println!("Write these 24 words on paper. Store offline.");
    println!("Without BOTH the mnemonic AND {}, the wallet is inaccessible.", output_path);
    if passphrase.is_some() {
        println!("Passphrase is ALSO required to unlock.");
    }
    println!();
    println!("First address: {}", first_addr);
    println!("Wallet file:   {}", output_path);
}

fn load_hd_wallet(
    path: &std::path::Path,
    mnemonic: &str,
    passphrase: Option<&str>,
    password: &str,
    allow_large: bool,
) -> Result<gnb::hd_wallet::HdWallet, String> {
    if allow_large {
        // Explicit recovery mode for a trusted historical backup. It retains
        // the parser's absolute byte ceiling but intentionally relaxes the
        // normal address and rederivation work budgets.
        gnb::hd_wallet::HdWallet::load_with_file_limit(
            path,
            mnemonic,
            passphrase,
            password,
            gnb::util::MAX_WALLET_FILE_LIMIT,
        )
    } else {
        gnb::hd_wallet::HdWallet::load_bounded(path, mnemonic, passphrase, password)
            .map_err(|error| {
                if error.contains("exceeds configured limit") || error.contains("wallet file exceeds configured") {
                    format!("{error}; for a trusted historical backup retry with --allow-large-hd-wallet")
                } else {
                    error
                }
            })
    }
}

fn do_newaddress(wallet_path: &str, label: &str, allow_large_hd_wallet: bool) {
    let password = read_password("Wallet password: ");
    let passphrase_input = read_password("Passphrase (Enter to skip): ");
    let passphrase = if passphrase_input.is_empty() { None } else { Some(passphrase_input.as_str()) };
    let mnemonic = read_password("Mnemonic (24 words): ");

    let path = std::path::Path::new(wallet_path);
    let mut wallet = match load_hd_wallet(path, &mnemonic, passphrase, &password, allow_large_hd_wallet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Load failed: {}", e); process::exit(1); }
    };

    let new_addr = match wallet.new_address(label) {
        Ok(kp) => kp.address.clone(),
        Err(e) => { eprintln!("Derivation failed: {}", e); process::exit(1); }
    };

    if let Err(e) = wallet.save(path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("New address: {}", new_addr);
    println!("Label:       {}", label);
}

fn read_public_hd_wallet(
    wallet_path: &str,
    allow_large_hd_wallet: bool,
) -> Result<gnb::hd_wallet::HdWalletFile, String> {
    let path = std::path::Path::new(wallet_path);
    if allow_large_hd_wallet {
        gnb::hd_wallet::HdWalletFile::read_public_with_limits(
            path,
            gnb::util::MAX_WALLET_FILE_LIMIT,
            usize::MAX,
        )
    } else {
        gnb::hd_wallet::HdWalletFile::read_public_bounded(path).map_err(|error| {
            if error.contains("exceeds configured limit")
                || error.contains("wallet file exceeds configured")
            {
                format!("{error}; for a trusted historical backup retry with --allow-large-hd-wallet")
            } else {
                error
            }
        })
    }
}

fn do_list_addresses(wallet_path: &str, allow_large_hd_wallet: bool) {
    // Public metadata needs no password, but remains attacker-controlled input.
    let wallet = match read_public_hd_wallet(wallet_path, allow_large_hd_wallet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Invalid wallet file: {}", e); process::exit(1); }
    };
    println!();
    println!("HD Wallet — {} ({})", wallet_path, wallet.network);
    println!("Created: {}", wallet.created_at);
    println!();
    println!("  {:<4} {:<56} {}", "idx", "address", "label");
    println!("  {}", "-".repeat(80));
    for addr in &wallet.addresses {
        println!("  {:<4} {:<56} {}", addr.index, addr.address, addr.label);
    }
    println!();
    println!("Total: {} address(es)", wallet.addresses.len());
}

fn do_import_founder(
    hd_wallet_path: &str,
    founder_path: &str,
    allow_large_hd_wallet: bool,
    stated_network: Option<gnb::address::Network>,
) {
    println!("Importing founder.json into HD wallet...");
    println!();

    let founder_password = read_password("founder.json password: ");
    let founder_path_p = std::path::Path::new(founder_path);
    // CRY-7: a v2 founder keystore authenticates no network: it opens only
    // for the network stated with --mainnet / --testnet; the HD wallet then
    // refuses a key of the other network (HdWallet::try_import_keypair).
    let founder_kp = match open_keystore(founder_path_p, &founder_password, stated_network) {
        Ok(kp) => kp,
        Err(e) => { eprintln!("Failed to load founder.json: {}", e); process::exit(1); }
    };

    println!("Founder address: {}", founder_kp.address);
    println!();

    let hd_password = read_password("HD wallet password: ");
    let hd_passphrase_input = read_password("HD wallet passphrase (Enter to skip): ");
    let hd_passphrase = if hd_passphrase_input.is_empty() { None } else { Some(hd_passphrase_input.as_str()) };
    let mnemonic = read_password("HD wallet mnemonic (24 words): ");

    let hd_path = std::path::Path::new(hd_wallet_path);
    let mut wallet = match load_hd_wallet(hd_path, &mnemonic, hd_passphrase, &hd_password, allow_large_hd_wallet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to load HD wallet: {}", e); process::exit(1); }
    };

    let addr = founder_kp.address.clone();
    if let Err(e) = wallet.try_import_keypair(founder_kp, "founder") {
        eprintln!("Import failed: {}", e);
        process::exit(1);
    }

    if let Err(e) = wallet.save(hd_path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("Imported: {}", addr);
    println!("Label:    founder");
}

// ── Original wallet function ────────────────────────────────────────────────

fn network_of(testnet: bool) -> gnb::address::Network {
    if testnet { gnb::address::Network::Testnet } else { gnb::address::Network::Mainnet }
}

/// WAL-7: by default the key is derived from a new 24-word recovery phrase
/// (shown once), so the encrypted file is not its only backup; the network
/// is the explicit `--testnet` choice and keystore v3 authenticates it.
fn do_new_wallet(output_path: &str, testnet: bool, random_key: bool) {
    println!("Generating hybrid ML-DSA-65 + Falcon-1024 keypair...");
    warn_if_name_suggests_other_network(output_path, testnet);

    let keypair = if random_key {
        gnb::wallet::generate_keypair(testnet)
    } else {
        let (keypair, phrase) = gnb::wallet::generate_mnemonic_keypair(network_of(testnet))
            .unwrap_or_else(|e| die(&format!("key generation failed: {e}")));
        println!();
        println!("RECOVERY PHRASE (24 words). Write them down offline; anyone with them controls the funds:");
        println!();
        // CRY-4: one wiping buffer, written straight to the terminal.
        if let Err(e) = gnb::wallet::print_phrase_grid(&phrase.words(), "  ") {
            die(&format!("cannot print the recovery phrase: {e}"));
        }
        drop(phrase);
        println!();
        if !gnb::wallet::send::confirm("I have written the 24 words down") {
            die("aborted: no wallet file was written");
        }
        keypair
    };

    let password = read_new_password();
    let path = std::path::Path::new(output_path);

    match keypair.save_encrypted(path, &password) {
        Ok(_) => {
            println!("Wallet saved: {}", output_path);
            println!("Address:      {}", keypair.address);
            println!("Network:      {}", if testnet { "testnet" } else { "mainnet" });
            println!();
            if random_key {
                println!("BACKUP THIS FILE. If lost, your GNB is gone forever.");
            } else {
                println!("The recovery phrase restores this key: gnb-cli restorewallet <path>.");
            }
        }
        Err(e) => {
            eprintln!("Failed to save wallet: {}", e);
            process::exit(1);
        }
    }
}

fn do_restore_wallet(output_path: &str, testnet: bool) {
    let phrase = read_password("Recovery phrase (24 words): ");
    let keypair = gnb::wallet::keypair_from_mnemonic(&phrase, network_of(testnet))
        .unwrap_or_else(|e| die(&format!("restore failed: {e}")));
    drop(phrase);
    println!("Address: {}", keypair.address);
    let password = read_new_password();
    match keypair.save_encrypted(std::path::Path::new(output_path), &password) {
        Ok(_) => println!("Wallet saved: {}", output_path),
        Err(e) => die(&format!("failed to save wallet: {e}")),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Open a keystore without spending it (CRY-7): v3 authenticates its own
/// network (which must be the stated one, if any); a v2 file opens only for a
/// stated network.
fn open_keystore(
    path: &std::path::Path,
    password: &str,
    network: Option<gnb::address::Network>,
) -> Result<gnb::wallet::Keypair, String> {
    match network {
        Some(n) => gnb::wallet::Keypair::load_encrypted_on(path, password, n),
        None => gnb::wallet::Keypair::load_encrypted(path, password)
            .map_err(|e| format!("{e} (pass --mainnet or --testnet for a v2 keystore)")),
    }
}

/// CRY-4: passwords and mnemonics are read into wiping storage.
fn read_password(prompt: &str) -> zeroize::Zeroizing<String> {
    eprint!("{}", prompt);
    zeroize::Zeroizing::new(rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        process::exit(1);
    }))
}

fn bloch_to_sats(s: &str) -> u64 {
    checked_payment_sats(s).unwrap_or_else(|message| die(message))
}

fn checked_payment_sats(value: &str) -> Result<u64, &'static str> {
    let satoshis = gnb::wallet::parse_bloch_satoshis(value)?;
    if satoshis == 0 { return Err("payment must contain at least one satoshi"); }
    Ok(satoshis)
}

fn checked_destination(destination: &str, source: &str) -> Result<String, &'static str> {
    let destination = gnb::address::Address::parse(destination).map_err(|_| "invalid destination address")?;
    let source = gnb::address::Address::parse(source).map_err(|_| "invalid wallet address")?;
    if destination.network() != source.network() { return Err("destination address network differs from wallet"); }
    Ok(hex::encode(destination.hash()))
}

/// Test view of the production UTXO-row parser `send` uses
/// (`gnb::wallet::send::parse_utxo_rows`: number or decimal-string values,
/// malformed rows refused, never filtered).
#[cfg(test)]
fn parse_send_utxos(rows: &[serde_json::Value]) -> Result<Vec<(Vec<u8>, u32, gnb::core::TxOutput)>, String> {
    Ok(gnb::wallet::send::parse_utxo_rows(&serde_json::json!({ "utxos": rows }))?
        .into_iter().map(|u| (u.txid.to_vec(), u.index, u.output)).collect())
}

const POLICY_ADDRESS_USAGE: &str =
    "policyaddress <m> <pubkey-hex|file>... [--after HEIGHT] [--older BLOCKS] [--testnet]";
const POLICY_SPEND_USAGE: &str =
    "policyspend <policy-hex|file> <to_address> <amount_gnb> --utxo TXID:VOUT:SATS [--utxo ...] \
     [--fee 0.0005] [--locktime HEIGHT] [--next-height N] [--testnet] --out spend.json";

/// Open a keystore to sign with (`pubkey`, `policysign`, `vaultlock`).
/// CRY-7: every open path authenticates the network. A keystore v3 proves
/// its own, which must be `network` when one is given; a v2 file (which
/// authenticates none) opens only for a stated network, checked against its
/// address; a keyfile v1 must record that network.
fn load_keypair(path: &str, network: Option<gnb::address::Network>) -> gnb::wallet::Keypair {
    let password = read_password("Wallet password: ");
    let p = std::path::Path::new(path);
    match open_keystore(p, &password, network) {
        Ok(kp) => kp,
        Err(e2) if is_keystore_v2_or_v3(p) => die(&format!("Failed to load wallet: {e2}")),
        Err(e2) => match gnb::wallet::Wallet::load_encrypted(p, &password) {
            Ok(w) => {
                if network.is_some_and(|n| n != w.network()) {
                    die("the wallet's network does not match the network required here");
                }
                w.into_keypair()
            }
            Err(e1) => die(&format!("Failed to load wallet: {} (keystore v2/v3) / {} (keyfile v1)", e2, e1)),
        },
    }
}

/// The network of a policy / vault command (CRY-7): `--testnet` or
/// `--mainnet` as parsed by `main` (the global parser consumes both flags,
/// so they never reach `params`), mainnet by default.
fn policy_network(stated: Option<gnb::address::Network>) -> gnb::address::Network {
    stated.unwrap_or(gnb::address::Network::Mainnet)
}

/// A destination of a policy or vault spend (`gnb1q`/`gnb1t` or
/// `gnb1m`/`gnb1n`) as its output script, refused unless it is an address of
/// `network` (CRY-7: every payment path requires the expected network; a
/// single-key address's checksum does not cover its prefix, so a mistyped
/// prefix would otherwise make the spend one of the other chain).
fn destination_on(address: &str, network: gnb::address::Network, what: &str) -> Result<Vec<u8>, String> {
    let (dest_net, script) = gnb::address::destination_script(address)
        .map_err(|_| format!("invalid {what}"))?;
    if dest_net != network {
        return Err(format!("the {what} is a {dest_net:?} address; this spend is on {network:?} \
                            (pass --testnet / --mainnet to state the network)"));
    }
    Ok(script)
}

/// A network the caller stated (`--testnet` / `--mainnet`) must be the one
/// the spend or vault file records.
fn require_stated(stated: Option<gnb::address::Network>, recorded: gnb::address::Network, file: &str) {
    if stated.is_some_and(|n| n != recorded) {
        die(&format!("{file} is for {recorded:?}, not the network stated on the command line"));
    }
}

/// A hex argument, or the trimmed contents of a file holding the hex.
fn hex_arg(arg: &str) -> Vec<u8> {
    let text = if std::path::Path::new(arg).is_file() {
        std::fs::read_to_string(arg).unwrap_or_else(|e| die(&format!("read {}: {}", arg, e)))
    } else {
        arg.to_string()
    };
    hex::decode(text.trim()).unwrap_or_else(|_| die(&format!("not hex (or a file of hex): {}", arg)))
}

fn flag_value<'a>(params: &[&'a str], flag: &str) -> Option<&'a str> {
    params.windows(2).find(|w| w[0] == flag).map(|w| w[1])
}

fn do_policy_address(params: &[&str], stated: Option<gnb::address::Network>) {
    let m: u8 = params[0].parse().unwrap_or_else(|_| die("m must be a number"));
    let mut keys = Vec::new();
    let mut i = 1;
    while i < params.len() {
        match params[i] {
            "--after" | "--older" => i += 2,
            "--testnet" => i += 1,
            k => { keys.push(hex_arg(k)); i += 1; }
        }
    }
    let after: u32 = flag_value(params, "--after").map(|v| v.parse().unwrap_or_else(|_| die("--after: height"))).unwrap_or(0);
    let older: u32 = flag_value(params, "--older").map(|v| v.parse().unwrap_or_else(|_| die("--older: blocks"))).unwrap_or(0);
    // CRY-7: `--testnet` reaches this function as `stated` (it was tested
    // in `params`, where it never is: a testnet policy got a mainnet address).
    let network = policy_network(stated);
    let policy = gnb::core::policy::SpendPolicy::new(m, keys, after, older)
        .unwrap_or_else(|e| die(&format!("invalid policy: {}", e)));
    println!("address: {}", gnb::address::PolicyAddress::from_policy(&policy, network));
    println!("policy:  {}", hex::encode(policy.encode()));
    println!("{}-of-{}{}{}", policy.threshold, policy.pubkeys.len(),
        if after > 0 { format!(", spendable from height {}", after) } else { String::new() },
        if older > 0 { format!(", each deposit spendable {} blocks after it confirms", older) } else { String::new() });
    println!("Keep the policy hex: it is needed to spend, and the address alone does not reveal it.");
}

fn do_policy_spend(params: &[&str], stated: Option<gnb::address::Network>) {
    let policy = gnb::core::policy::SpendPolicy::decode(&hex_arg(params[0]))
        .unwrap_or_else(|e| die(&format!("invalid policy: {}", e)));
    // CRY-7: the spend's network is the one stated (mainnet by default), not
    // whatever the destination's prefix says; a destination of the other
    // network is refused.
    let network = policy_network(stated);
    let to_script = destination_on(params[1], network, "destination address").unwrap_or_else(|e| die(&e));
    let amount = bloch_to_sats(params[2]);
    let fee = gnb::wallet::parse_bloch_satoshis(flag_value(params, "--fee").unwrap_or("0.0005"))
        .unwrap_or_else(|m| die(m));
    let locktime: u32 = flag_value(params, "--locktime")
        .map(|v| v.parse().unwrap_or_else(|_| die("--locktime: height"))).unwrap_or(policy.after);
    let out = flag_value(params, "--out").unwrap_or_else(|| die("--out spend.json is required"));
    let inputs: Vec<([u8; 32], u32, u64)> = params.windows(2).filter(|w| w[0] == "--utxo").map(|w| {
        let parts: Vec<&str> = w[1].split(':').collect();
        if parts.len() != 3 { die("--utxo must be TXID:VOUT:SATS"); }
        let txid: [u8; 32] = hex::decode(parts[0]).ok().and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| die("--utxo: TXID must be 32-byte hex"));
        (txid,
         parts[1].parse().unwrap_or_else(|_| die("--utxo: VOUT")),
         parts[2].parse().unwrap_or_else(|_| die("--utxo: SATS")))
    }).collect();
    let mut spend = gnb::wallet::policy_spend::PolicySpend::new(network, policy, &inputs, to_script, amount, fee, locktime)
        .unwrap_or_else(|e| die(&e));
    apply_next_height(&mut spend, params);
    std::fs::write(out, spend.to_json().unwrap_or_else(|e| die(&e)))
        .unwrap_or_else(|e| die(&format!("write {}: {}", out, e)));
    let input_total: u64 = inputs.iter().map(|i| i.2).sum();
    println!("Unsigned spend written to {}", out);
    println!("Pays {} GNB to {}; fee {} GNB; needs {} signature(s)",
        amount as f64 / 1e8, params[1], (input_total - spend.outputs_total()) as f64 / 1e8, spend.policy.threshold);
}

fn print_spend_summary(spend: &gnb::wallet::policy_spend::PolicySpend) {
    println!("Network:  {:?}", spend.network);
    for (i, o) in spend.tx.outputs.iter().enumerate() {
        let kind = if o.script_pubkey == spend.locking_script() { " (change, back to the policy)" } else { "" };
        println!("Output {}: {} GNB → script {}{}", i, o.value as f64 / 1e8, hex::encode(&o.script_pubkey), kind);
    }
    println!("Locktime: {}", spend.tx.locktime);
    println!("Signed by keys {:?} of {}-of-{}", spend.signers(), spend.policy.threshold, spend.policy.pubkeys.len());
}

const POLICY_SIGN_USAGE: &str = "policysign <spend-or-pqpsbt.json> <wallet.json> [--max-fee GNB] [--yes]";

fn read_public_document(path: &str, limit: usize) -> Result<String, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes).map_err(|e| format!("read {path}: {e}"))?;
    if bytes.len() > limit { return Err(format!("public document exceeds {limit} bytes")); }
    String::from_utf8(bytes).map_err(|_| "public document must be UTF-8".into())
}

fn do_pqpsbt(params: &[&str]) {
    if params.len() != 1 { die("pqpsbt <public-request.json>: exactly one request file is required"); }
    // Documents remain strings inside the request, so the core sees the
    // original text and can reject duplicate fields before they are lost.
    let text = read_public_document(params[0], 2 * gnb::wallet::pqpsbt::MAX_JSON_BYTES + 4096)
        .unwrap_or_else(|e| die(&e));
    let request = serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("public request: {e}")));
    let response = gnb::wallet::pqpsbt::public_request(&request).unwrap_or_else(|e| die(&e));
    println!("{}", serde_json::to_string_pretty(&response).unwrap());
}

const DESCRIPTOR_USAGE: &str = "descriptor create|inspect|import <input-file> --mainnet|--testnet; descriptor export|pool <input-file> <new-pool-file> --mainnet|--testnet";

fn do_descriptor(params: &[&str], stated_network: Option<gnb::address::Network>) {
    use gnb::wallet::descriptor::{public_request, MAX_DESCRIPTOR_BYTES, MAX_POOL_BYTES};
    use serde_json::json;
    use std::io::Write;

    let network = match stated_network {
        Some(gnb::address::Network::Mainnet) => "mainnet",
        Some(gnb::address::Network::Testnet) => "testnet",
        None => die("descriptor requires an explicit network: --mainnet or --testnet"),
    };
    let action = params.first().copied().unwrap_or_else(|| die(DESCRIPTOR_USAGE));
    let writes_pool = match action {
        "create" | "inspect" | "import" => false,
        "export" | "pool" => true,
        _ => die(DESCRIPTOR_USAGE),
    };
    if params.len() != if writes_pool { 3 } else { 2 } {
        die(DESCRIPTOR_USAGE);
    }
    let limit = if matches!(action, "create" | "inspect") { MAX_DESCRIPTOR_BYTES } else { MAX_POOL_BYTES };
    // Cap raw bytes before parsing; keep bundle JSON intact so the shared
    // codec can reject duplicate fields. Array inputs contain strings only.
    let text = read_public_document(params[1], limit).unwrap_or_else(|error| die(&error));
    let request = match action {
        "create" => json!({"action": action, "network": network, "body": text}),
        "inspect" => json!({"action": action, "network": network, "descriptor": text}),
        "import" => json!({"action": action, "network": network, "bundle": text}),
        _ => {
            let entries: Vec<String> = serde_json::from_str(&text)
                .unwrap_or_else(|error| die(&format!("public string array: {error}")));
            if action == "export" { json!({"action": action, "network": network, "descriptors": entries}) }
            else { json!({"action": action, "network": network, "public_keys": entries}) }
        }
    };
    let response = public_request(&request).unwrap_or_else(|error| die(&error));
    if writes_pool {
        let bundle = response.get("bundle").and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| die("descriptor response has no public bundle"));
        // Atomic create-new refuses existing files and symlinks, including a
        // key backup accidentally chosen as the public pool destination.
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(params[2])
            .unwrap_or_else(|error| die(&format!("create new public pool {}: {error}", params[2])));
        file.write_all(bundle.as_bytes()).and_then(|()| file.sync_all())
            .unwrap_or_else(|error| die(&format!("write public pool {}: {error}", params[2])));
    }
    println!("{}", serde_json::to_string_pretty(&response).unwrap_or_else(|error| die(&error.to_string())));
}

fn public_rpc_result(
    rpc: &dyn Fn(&str, &serde_json::Value) -> Result<serde_json::Value, String>,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let result = rpc(method, params).map_err(|e| format!("{method}: {e}"))?;
    if let Some(error) = result.get("error").filter(|e| !e.is_null()) {
        return Err(format!("{method}: {error}"));
    }
    Ok(result)
}

fn policy_snapshot(result: &serde_json::Value) -> Result<(u64, [u8;32]), String> {
    let height = gnb::wallet::send::next_block_height_from_daginfo(result)?;
    let tip = result.get("tip").and_then(serde_json::Value::as_str)
        .and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok())
        .ok_or("node did not report a 32-byte tip hash")?;
    Ok((height, tip))
}

/// PF-2: BIP174's signer checks bind previous outputs, payment and fee before
/// key access; BIP370's role separation never rewrites an already signed
/// transaction. GnB's PQ-PSBT format is distinct from Bitcoin PSBT.
/// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#signer
/// https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#roles
fn with_policy_preflight<F>(
    text: &str,
    stated: Option<gnb::address::Network>,
    max_fee: u64,
    rpc: &dyn Fn(&str, &serde_json::Value) -> Result<serde_json::Value, String>,
    signer: F,
) -> Result<(gnb::wallet::pqpsbt::PqPsbt, bool, u8), String>
where F: FnOnce(&mut gnb::wallet::pqpsbt::PqPsbt, &gnb::wallet::pqpsbt::SignContext,
                &gnb::wallet::pqpsbt::Review) -> Result<u8, String>,
{
    use gnb::wallet::pqpsbt::{PqPsbt, SignContext};
    use serde_json::{json, Value};
    let (mut document, legacy) = match PqPsbt::from_json(text) {
        Ok(p) => (p, false),
        Err(pq_error) => (PqPsbt::from_legacy_json(text)
            .map_err(|legacy_error| format!("{pq_error}; {legacy_error}"))?, true),
    };
    let network = document.spend.network;
    if stated.is_some_and(|n| n != network) { return Err("spend network differs from the command line".into()); }
    let info = public_rpc_result(rpc,"getnetworkinfo",&Value::Null)?;
    let node_network = gnb::wallet::pqpsbt::parse_network(info.get("network").and_then(Value::as_str)
        .ok_or("node did not report its network")?)?;
    if node_network != network { return Err("node network differs from the spend network".into()); }
    let activation = gnb::core::activation::hardening_activation_height_for_signer(document.spend.chain_id());
    if info.get("hardening_activation_height").and_then(Value::as_u64) != Some(activation) {
        return Err("node hardening activation differs from this signer's network rules".into());
    }
    let initial = policy_snapshot(&public_rpc_result(rpc,"getdaginfo",&Value::Null)?)?;
    let context = SignContext { network, next_height: initial.0, max_fee };
    gnb::core::sighash::check_tx_version_standard(document.spend.tx.version,initial.0,activation)?;
    if u64::from(document.spend.tx.locktime) > initial.0 { return Err("transaction locktime is not reached".into()); }
    let address = gnb::address::PolicyAddress::from_script(&document.spend.locking_script(),network)
        .ok_or("unsupported policy output")?;
    let selected: Vec<Value> = document.spend.tx.inputs.iter().map(|i|
        json!({"txid":hex::encode(i.prev_txid),"index":i.prev_index})).collect();
    let result = public_rpc_result(rpc,"getutxos",&json!([
        address.to_string(),gnb::wallet::send::GETUTXOS_MAX_ROWS,selected]))?;
    if policy_snapshot(&result)? != initial { return Err("node snapshot changed during UTXO lookup; retry preflight".into()); }
    let truncated = result.get("truncated").and_then(Value::as_bool).ok_or("getutxos did not report whether its window was truncated")?;
    let rows = result.get("utxos").and_then(Value::as_array).ok_or("getutxos missing UTXO array")?;
    if rows.len() > gnb::wallet::send::GETUTXOS_MAX_ROWS as usize { return Err("getutxos response exceeds its row limit".into()); }
    let utxos = gnb::wallet::send::parse_utxo_rows(&result)?;
    let mut by_outpoint = std::collections::BTreeMap::new();
    for (position, utxo) in utxos.iter().enumerate() {
        if by_outpoint.insert((utxo.txid,utxo.index),position).is_some() { return Err("duplicate outpoint in node UTXO response".into()); }
    }
    for i in 0..document.inputs.len() {
        let input = &document.spend.tx.inputs[i];
        let position = *by_outpoint.get(&(input.prev_txid,input.prev_index)).ok_or_else(||
            format!("input {i} cannot be confirmed unspent in the node's {}UTXO window",if truncated {"truncated "} else {""}))?;
        let actual = &utxos[position].output;
        let claimed = &document.inputs[i].prevout;
        if actual.value != claimed.value || actual.script_pubkey != claimed.script_pubkey {
            return Err(format!("input {i}: node value/script differs from the document"));
        }
        let row = &rows[position];
        match row.get("spent_in_mempool").and_then(Value::as_bool) {
            Some(false) => {},
            Some(true) => return Err(format!("input {i} is already spent by a pooled transaction")),
            None => return Err(format!("input {i}: node did not report mempool spend status")),
        }
        if !gnb::wallet::send::utxo_row_spendable_at(row,initial.0)? {
            return Err(format!("input {i}: immature coinbase output"));
        }
        if document.spend.policy.older != 0 {
            // This field comes from admission's confirmations_for_next_block:
            // selected-chain depth after activation, not header subtraction.
            let age = row.get("confirmations_at_next_block").and_then(Value::as_u64)
                .ok_or_else(|| format!("input {i}: relative timelock confirmations unknown"))?;
            if age < u64::from(document.spend.policy.older) { return Err(format!("input {i}: relative timelock is not satisfied")); }
        }
        if document.spend.tx.version == 1 {
            let raw = public_rpc_result(rpc,"getrawtransaction",&json!([hex::encode(input.prev_txid)]))?;
            let raw = raw.get("hex").and_then(Value::as_str).ok_or("getrawtransaction missing hex")?;
            if raw.len() > 2 * gnb::wallet::pqpsbt::MAX_TX_BYTES { return Err("previous transaction exceeds byte limit".into()); }
            let mut update = document.inputs[i].clone();
            update.previous_tx = Some(hex::decode(raw).map_err(|_| "previous transaction is not hex")?);
            // The core checks complete canonical bytes, txid, output index,
            // value and locking script before accepting this public metadata.
            document.update_input(i,update)?;
        }
    }
    let review = document.review_for_signing(&context)?;
    if policy_snapshot(&public_rpc_result(rpc,"getdaginfo",&Value::Null)?)? != initial {
        return Err("node tip or next height changed during preflight; retry".into());
    }
    let key = signer(&mut document,&context,&review)?;
    Ok((document,legacy,key))
}

fn format_base_units(value: u64) -> String {
    format!("{}.{:08} GNB ({} base units)",value / 100_000_000,value % 100_000_000,value)
}

fn policy_review_lines(document: &gnb::wallet::pqpsbt::PqPsbt,
    context: &gnb::wallet::pqpsbt::SignContext, review: &gnb::wallet::pqpsbt::Review) -> Vec<String>
{
    let mut lines = vec![format!("Network: {:?}; next block height: {}; transaction version: {}",
        context.network,context.next_height,document.spend.tx.version)];
    for (i,(input,data)) in document.spend.tx.inputs.iter().zip(&document.inputs).enumerate() {
        lines.push(format!("Input {i}: {}:{}; {}; script {}",hex::encode(input.prev_txid),input.prev_index,
            format_base_units(data.prevout.value),hex::encode(&data.prevout.script_pubkey)));
    }
    let locking_script = document.spend.locking_script();
    for (i,output) in document.spend.tx.outputs.iter().enumerate() {
        let change = if output.script_pubkey == locking_script {" (change: same policy script)"} else {""};
        lines.push(format!("Output {i}: {}; script {}{}",format_base_units(output.value),hex::encode(&output.script_pubkey),change));
    }
    lines.extend([
        format!("Input total: {}",format_base_units(review.total_inputs)),
        format!("Output total: {}",format_base_units(review.total_outputs)),
        format!("Fee: {}; maximum: {}",format_base_units(review.fee),format_base_units(context.max_fee)),
        format!("Change: {}",format_base_units(review.change)),
        format!("Full previous transactions verified: {} of {}",review.previous_transactions_verified,document.inputs.len()),
        "Unspentness, maturity and locks reflect the configured node's snapshot; they are not a reservation against a later spend or reorganization.".into(),
        "Derivation labels are metadata, not proof of ownership or change.".into(),
    ]);
    lines
}

fn do_policy_sign(params: &[&str], target: &RpcTarget, stated: Option<gnb::address::Network>) {
    let mut max_fee = gnb::wallet::payment::FeePolicy::DEFAULT_MAX_FEE_SAT;
    let mut yes = false;
    let mut i = 2;
    while i < params.len() {
        match params[i] {
            "--yes" | "-y" => { yes = true; i += 1; },
            "--max-fee" if i+1 < params.len() => {
                max_fee = gnb::wallet::parse_bloch_satoshis(params[i+1]).unwrap_or_else(|e| die(e)); i += 2;
            },
            other => die(&format!("unknown policysign option {other:?}; {POLICY_SIGN_USAGE}")),
        }
    }
    let text = read_public_document(params[0],gnb::wallet::pqpsbt::MAX_JSON_BYTES).unwrap_or_else(|e| die(&e));
    let (document,legacy,index) = with_policy_preflight(&text,stated,max_fee,&|m,p| rpc_call(target,m,p),|doc,ctx,review| {
        for line in policy_review_lines(doc,ctx,review) { println!("{line}"); }
        if !yes && !gnb::wallet::send::confirm("Sign this policy spend?") { return Err("not signed".into()); }
        let key = load_keypair(params[1],Some(ctx.network));
        doc.sign(ctx,&key.public_key,|digest,version| key.sign_tx_digest(digest,version))
    }).unwrap_or_else(|e| die(&e));
    let output = if legacy { document.spend.to_json() } else { document.to_json() }.unwrap_or_else(|e| die(&e));
    std::fs::write(params[0],output).unwrap_or_else(|e| die(&format!("write {}: {e}",params[0])));
    println!("Signed as key {}; {} of {} signatures present.",index,document.spend.signers().len(),document.spend.policy.threshold);
}

fn do_policy_send(params: &[&str], target: &RpcTarget) {
    let text = std::fs::read_to_string(params[0]).unwrap_or_else(|e| die(&format!("read {}: {}", params[0], e)));
    let spend = gnb::wallet::policy_spend::PolicySpend::from_json(&text).unwrap_or_else(|e| die(&e));
    print_spend_summary(&spend);
    let tx = spend.finalize().unwrap_or_else(|e| die(&e));
    let raw = hex::encode(tx.to_wire_bytes(true));
    println!("TXID: {}", hex::encode(tx.txid()));
    match rpc_call(target, "sendrawtransaction", &serde_json::json!([raw])) {
        Ok(result) => {
            if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
                die(&format!("Broadcast rejected: {}", err));
            }
            println!("Broadcast OK");
        }
        Err(e) => die(&format!("Broadcast failed: {}", e)),
    }
}

// ── Bloch bridge vault ──────────────────────────────────────────────────────

const VAULT_CREATE_USAGE: &str = "vaultcreate <out.json> --release K <signer keys...> --recovery R <cold keys...> --older BLOCKS [--testnet]";

fn load_vault(path: &str) -> gnb::bridge::Vault {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {}: {}", path, e)));
    let v: gnb::bridge::Vault = serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("vault file: {}", e)));
    v.tree().unwrap_or_else(|e| die(&e));
    v
}

fn utxo_args(params: &[&str]) -> Vec<([u8; 32], u32, u64)> {
    params.windows(2).filter(|w| w[0] == "--utxo").map(|w| {
        let parts: Vec<&str> = w[1].split(':').collect();
        if parts.len() != 3 { die("--utxo must be TXID:VOUT:SATS"); }
        let txid: [u8; 32] = hex::decode(parts[0]).ok().and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| die("--utxo: TXID must be 32-byte hex"));
        (txid, parts[1].parse().unwrap_or_else(|_| die("--utxo: VOUT")),
         parts[2].parse().unwrap_or_else(|_| die("--utxo: SATS")))
    }).collect()
}

fn do_vault_create(params: &[&str], stated: Option<gnb::address::Network>) {
    let out = params[0];
    // CRY-7: `--testnet` reaches this function as `stated` (see
    // do_policy_address).
    let network = policy_network(stated);
    let section = |flag: &str| -> (u8, Vec<Vec<u8>>) {
        let start = params.iter().position(|p| *p == flag).unwrap_or_else(|| die(VAULT_CREATE_USAGE));
        let t: u8 = params.get(start + 1).and_then(|v| v.parse().ok()).unwrap_or_else(|| die(VAULT_CREATE_USAGE));
        let keys = params[start + 2..].iter().take_while(|p| !p.starts_with("--")).map(|k| hex_arg(k)).collect();
        (t, keys)
    };
    let (k, signers) = section("--release");
    let (r, cold) = section("--recovery");
    let older: u32 = flag_value(params, "--older").and_then(|v| v.parse().ok()).unwrap_or_else(|| die(VAULT_CREATE_USAGE));
    let v = gnb::bridge::Vault::create(network, k, signers, r, cold, older).unwrap_or_else(|e| die(&e));
    std::fs::write(out, serde_json::to_string_pretty(&v).unwrap()).unwrap_or_else(|e| die(&format!("write {}: {}", out, e)));
    println!("Vault written to {}", out);
    println!("Address:  {}", v.address);
    println!("Release:  {}-of-{} signer keys, no timelock", v.release_threshold, v.signers);
    println!("Recovery: {}-of-{} cold keys, {} blocks after each deposit", v.recovery_threshold, v.recovery_keys, v.recovery_older);
    println!("Publish this file once; signers and users check the address against it.");
}

fn do_vault_lock(params: &[&str], target: &RpcTarget, stated: Option<gnb::address::Network>) {
    let vault = load_vault(params[1]);
    require_stated(stated, vault.network(), params[1]);
    let amount = bloch_to_sats(params[2]);
    let l2: [u8; 20] = hex::decode(params[3].trim_start_matches("0x")).ok().and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die("L2 address must be 0x + 40 hex digits"));
    let fee = gnb::wallet::parse_bloch_satoshis(flag_value(params, "--fee").unwrap_or("0.0005")).unwrap_or_else(|m| die(m));
    // CRY-7: the paying keystore is opened for the vault's network, so the
    // lock is signed for the chain the vault's signers watch.
    let keypair = load_keypair(params[0], Some(vault.network()));
    let utxos = rpc_call(target, "getutxos", &serde_json::json!([keypair.address, 50]))
        .unwrap_or_else(|e| die(&format!("RPC: {}", e)));
    // Only outputs spendable in the next block (mature coinbase outputs).
    let next_height = next_block_height(target);
    let available: Vec<(Vec<u8>, u32, gnb::core::TxOutput)> =
        gnb::wallet::send::spendable_utxo_rows(&utxos, next_height)
            .unwrap_or_else(|m| die(&m)).0
            .into_iter().map(|u| (u.txid.to_vec(), u.index, u.output)).collect();
    let outputs = gnb::bridge::lock_outputs(&vault.script().unwrap(), amount, l2);
    let mut fee = fee;
    let mut tx = None;
    for _ in 0..16 {
        let built = gnb::wallet::TxBuilder::build_outputs(&keypair, &available, outputs.clone(), fee, next_height)
            .unwrap_or_else(|e| die(&e));
        let min = gnb::core::tokenomics::min_tx_fee_sat(built.to_wire_bytes(true).len());
        if fee >= min { tx = Some(built); break; }
        fee = fee.max(min);
    }
    let tx = tx.unwrap_or_else(|| die("could not settle the fee"));
    // Self-check: the transaction parses back as a lock of this vault.
    let lock = gnb::bridge::parse_lock(&tx.outputs, &vault.script().unwrap(), 0).unwrap_or_else(|e| die(&e));
    let raw = hex::encode(tx.to_wire_bytes(true));
    let res = rpc_call(target, "sendrawtransaction", &serde_json::json!([raw]))
        .unwrap_or_else(|e| die(&format!("broadcast: {}", e)));
    if let Some(e) = res.get("error").and_then(|e| e.as_str()) { die(&format!("broadcast rejected: {}", e)); }
    println!("{}", serde_json::json!({
        "lock_txid": hex::encode(tx.txid()), "lock_vout": 0, "amount": lock.amount.to_string(),
        "l2_recipient": format!("0x{}", hex::encode(lock.l2_recipient)), "fee": fee.to_string(),
    }));
}

/// Read a transaction from the node: (outputs, block_height, confirmations).
fn fetch_tx(target: &RpcTarget, txid: &str) -> Result<(Vec<gnb::core::TxOutput>, u64, u64, String), String> {
    let r = rpc_call(target, "gettransaction", &serde_json::json!([txid]))?;
    if let Some(e) = r.get("error").and_then(|e| e.as_str()) { return Err(e.to_string()); }
    let outs = r["transaction"]["outputs"].as_array().ok_or("no outputs")?.iter().map(|o| {
        Ok(gnb::core::TxOutput {
            value: o["value"].as_str().ok_or("value")?.parse::<u64>().map_err(|e| e.to_string())?,
            script_pubkey: hex::decode(o["script_pubkey"].as_str().ok_or("script")?).map_err(|e| e.to_string())?,
        })
    }).collect::<Result<Vec<_>, String>>()?;
    Ok((outs, r["block_height"].as_u64().unwrap_or(0), r["confirmations"].as_u64().unwrap_or(0),
        r["block_hash"].as_str().unwrap_or("").to_string()))
}

fn do_vault_check_lock(params: &[&str], target: &RpcTarget) {
    let vault = load_vault(params[0]);
    let txid = params[1];
    let min_conf: u64 = flag_value(params, "--min-conf").and_then(|v| v.parse().ok()).unwrap_or(1000);
    let min_amount: u64 = flag_value(params, "--min-amount").and_then(|v| v.parse().ok()).unwrap_or(0);
    let want_final = params.contains(&"--finalized");
    let verdict = (|| -> Result<serde_json::Value, String> {
        let (outs, height, conf, block_hash) = fetch_tx(target, txid)?;
        let lock = gnb::bridge::parse_lock(&outs, &vault.script()?, min_amount)?;
        let deep = if want_final {
            let p = rpc_call(target, "getpowitinfo", &serde_json::Value::Null)?;
            let fh = p["finalized"]["block_height"].as_u64().ok_or("PoWit finality not available")?;
            height <= fh
        } else {
            conf >= min_conf
        };
        Ok(serde_json::json!({
            "ok": deep, "reason": if deep { "" } else { "not deep enough yet" },
            "lock_txid": txid, "lock_vout": 0, "amount": lock.amount.to_string(),
            "l2_recipient": format!("0x{}", hex::encode(lock.l2_recipient)),
            "block_hash": block_hash, "block_height": height, "confirmations": conf,
        }))
    })();
    match verdict {
        Ok(v) => println!("{}", v),
        Err(e) => println!("{}", serde_json::json!({ "ok": false, "reason": e, "lock_txid": txid })),
    }
}

fn burn_id_arg(s: &str) -> [u8; 32] {
    hex::decode(s.trim_start_matches("0x")).ok().and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die("burn id must be 32-byte hex"))
}

fn do_vault_release(params: &[&str], stated: Option<gnb::address::Network>) {
    let vault = load_vault(params[0]);
    require_stated(stated, vault.network(), params[0]);
    let burn = burn_id_arg(params[1]);
    // CRY-7: the release is on the vault's network; a recipient of the other
    // network is refused.
    let network = vault.network();
    let recipient = destination_on(params[2], network, "recipient").unwrap_or_else(|e| die(&e));
    let burn_amount: u64 = params[3].parse().unwrap_or_else(|_| die("burn amount in base units"));
    let out = flag_value(params, "--out").unwrap_or_else(|| die("--out spend.json is required"));
    let inputs = utxo_args(params);
    let tree = vault.tree().unwrap_or_else(|e| die(&e));
    // The vault pays exactly the burned amount: payout = burn - marker - fee.
    // Learn the fee with a probe, then build the real spend with it.
    let build = |payout: u64, fee: u64| gnb::wallet::policy_spend::PolicySpend::new_branch(
        network, tree.clone(), gnb::bridge::RELEASE_BRANCH, &inputs,
        gnb::bridge::release_outputs(&recipient, payout, &burn), fee, 0);
    let probe_payout = burn_amount.checked_sub(gnb::bridge::MARKER_VALUE + 1).unwrap_or_else(|| die("burn too small"));
    let probe = build(probe_payout, 0).unwrap_or_else(|e| die(&e));
    // The probe's change returns to the vault, so inputs − outputs is its fee.
    let in_total: u64 = inputs.iter().map(|i| i.2).sum();
    let fee = in_total.saturating_sub(probe.outputs_total());
    let payout = burn_amount.checked_sub(gnb::bridge::MARKER_VALUE + fee).unwrap_or_else(|| die("burn smaller than marker + fee"));
    let mut spend = build(payout, fee).unwrap_or_else(|e| die(&e));
    apply_next_height(&mut spend, params);
    let check = gnb::bridge::check_release(&spend.tx.outputs,
        &inputs.iter().map(|i| (i.2, vault.script().unwrap())).collect::<Vec<_>>(),
        &vault.script().unwrap(), &recipient, burn_amount, &burn);
    if let Err(e) = check { die(&format!("built release fails its own check: {}", e)); }
    std::fs::write(out, spend.to_json().unwrap_or_else(|e| die(&e))).unwrap_or_else(|e| die(&format!("write {}: {}", out, e)));
    println!("Unsigned release written to {} (payout {} sats, fee {} sats, needs {} signatures)",
        out, payout, fee, spend.policy.threshold);
}

fn do_vault_check_release(params: &[&str], target: &RpcTarget, stated: Option<gnb::address::Network>) {
    let vault = load_vault(params[0]);
    require_stated(stated, vault.network(), params[0]);
    let text = std::fs::read_to_string(params[1]).unwrap_or_else(|e| die(&format!("read {}: {}", params[1], e)));
    let spend = gnb::wallet::policy_spend::PolicySpend::from_json(&text).unwrap_or_else(|e| die(&e));
    let burn = burn_id_arg(params[2]);
    let verdict = (|| -> Result<serde_json::Value, String> {
        // CRY-7: the recipient must be an address of the vault's network, and
        // so must the spend.
        let recipient = destination_on(params[3], vault.network(), "recipient")?;
        if spend.network != vault.network() {
            return Err(format!("the spend is for {:?}, the vault for {:?}", spend.network, vault.network()));
        }
        let burn_amount: u64 = params[4].parse().map_err(|_| "burn amount")?;
        if spend.tree.as_ref().map(|(_, b)| *b) != Some(gnb::bridge::RELEASE_BRANCH)
            || spend.locking_script() != vault.script()? {
            return Err("not a release-branch spend of this vault".into());
        }
        // Inputs as the signer's own node sees them.
        let mut inputs = Vec::new();
        for inp in &spend.tx.inputs {
            let (outs, _, _, _) = fetch_tx(target, &hex::encode(inp.prev_txid))?;
            let o = outs.get(inp.prev_index as usize).ok_or("input index out of range")?;
            inputs.push((o.value, o.script_pubkey.clone()));
        }
        let fee = gnb::bridge::check_release(&spend.tx.outputs, &inputs, &vault.script()?, &recipient, burn_amount, &burn)?;
        // Anti-replay: no output with this burn's marker may already exist.
        let marker = gnb::bridge::release_marker(&burn);
        let marker_addr = gnb::crypto::address_from_hash(&marker, vault.network() == gnb::address::Network::Testnet);
        let seen = rpc_call(target, "getutxos", &serde_json::json!([marker_addr, 1]))?;
        if seen.get("utxos").and_then(|u| u.as_array()).is_some_and(|a| !a.is_empty()) {
            return Err("a release for this burn already exists on chain".into());
        }
        Ok(serde_json::json!({ "ok": true, "fee": fee.to_string(), "burn_marker": marker_addr }))
    })();
    match verdict {
        Ok(v) => println!("{}", v),
        Err(e) => println!("{}", serde_json::json!({ "ok": false, "reason": e })),
    }
}

fn do_vault_recover(params: &[&str], stated: Option<gnb::address::Network>) {
    let vault = load_vault(params[0]);
    require_stated(stated, vault.network(), params[0]);
    // CRY-7: the recovery is on the vault's network.
    let network = vault.network();
    let dest = destination_on(params[1], network, "destination").unwrap_or_else(|e| die(&e));
    let amount = bloch_to_sats(params[2]);
    let out = flag_value(params, "--out").unwrap_or_else(|| die("--out spend.json is required"));
    let spend = gnb::wallet::policy_spend::PolicySpend::new_branch(network, vault.tree().unwrap_or_else(|e| die(&e)),
        gnb::bridge::RECOVERY_BRANCH, &utxo_args(params),
        vec![gnb::core::TxOutput { value: amount, script_pubkey: dest }], 0, 0).unwrap_or_else(|e| die(&e));
    let mut spend = spend;
    apply_next_height(&mut spend, params);
    std::fs::write(out, spend.to_json().unwrap_or_else(|e| die(&e))).unwrap_or_else(|e| die(&format!("write {}: {}", out, e)));
    println!("Unsigned recovery written to {}: valid only {} blocks after each input confirmed; needs {} cold signature(s)",
        out, vault.recovery_older, spend.policy.threshold);
}

fn do_vault_utxos(params: &[&str], target: &RpcTarget) {
    let vault = load_vault(params[0]);
    let r = rpc_call(target, "getutxos", &serde_json::json!([vault.address, 500]))
        .unwrap_or_else(|e| die(&format!("RPC: {}", e)));
    println!("{}", r);
}

/// `--next-height N` (the node's getdaginfo `next_block_height`) gives an
/// offline spend the transaction version of that block: 3 / sighash v3
/// at/after the hardening activation, 1 / sighash v2 below it. Without the
/// flag the spend is version 1, valid only below the activation.
fn apply_next_height(spend: &mut gnb::wallet::policy_spend::PolicySpend, params: &[&str]) {
    if let Some(h) = flag_value(params, "--next-height") {
        let h: u64 = h.parse().unwrap_or_else(|_| die("--next-height: block height"));
        spend.target_height(h).unwrap_or_else(|e| die(&e));
    } else {
        eprintln!("note: no --next-height given; the spend is version 1 (sighash v2), valid only below \
                   the hardening activation height {}",
                  gnb::core::activation::hardening_activation_height_for_signer(spend.chain_id()));
    }
}

/// The node's next block height (getdaginfo `next_block_height`).
fn next_block_height(target: &RpcTarget) -> u64 {
    let info = rpc_call(target, "getdaginfo", &serde_json::Value::Null)
        .unwrap_or_else(|e| die(&format!("RPC: {}", e)));
    info.get("next_block_height").and_then(|v| v.as_u64())
        .unwrap_or_else(|| die("the node did not report next_block_height"))
}

fn require_params(params: &[&str], min: usize, usage: &str) {
    if params.len() < min {
        eprintln!("Usage: gnb-cli {}", usage);
        process::exit(1);
    }
}

fn die(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    process::exit(1);
}

/// True when `path` holds a keystore v2/v3 JSON (a top-level `"version"` of 2
/// or 3), so a failure to unlock it is reported as is instead of falling back
/// to the v1 keyfile parser.
fn is_keystore_v2_or_v3(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if meta.len() > gnb::util::DEFAULT_WALLET_FILE_LIMIT as u64 {
        return false;
    }
    std::fs::read(path).ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("version").and_then(serde_json::Value::as_u64))
        .is_some_and(|v| v == 2 || v == 3)
}

fn print_usage() {
    println!(r#"
  gnb-cli — Bloch-SIS Protocol RPC client

  NETWORK
    gnb-cli info                          Network info
    gnb-cli height                        Current block count
    gnb-cli mempool                       Mempool info and relay policy (getmempoolinfo)
    gnb-cli peers                         Peer info
    gnb-cli dag                           DAG info (tips, chain, scores)

  BLOCKS
    gnb-cli block <height> [verbose]      Get block by height
    gnb-cli getblock <hash> [verbose]     Get block by hash
    gnb-cli getblockhash <height>         Get block hash at height
    gnb-cli recent [count]                Recent blocks (default: 10)

  OPERATOR RECOVERY (need GNB_RPC_API_KEY or --rpc-trust-loopback on the node)
    gnb-cli invalidateblock <hash>        Leave the chain through <hash>: mark it and its
                                          selected-chain descendants invalid (persisted)
    gnb-cli reconsiderblock <hash>        Undo invalidateblock (and re-check the chain)

  TRANSACTIONS
    gnb-cli tx <txid>                     Get transaction
    gnb-cli sendraw <hex>                 Broadcast raw transaction. Mempool policy
                                          (docs/MEMPOOL.md): it may spend outputs of
                                          unconfirmed txs (max 25 ancestors/descendants);
                                          full-RBF — a tx double-spending pooled ones
                                          REPLACES them iff it adds no new unconfirmed
                                          input, pays a higher fee rate than each, and
                                          an absolute fee >= all evicted fees + 1 sat/B
                                          of its own size, evicting <= 100 txs
    gnb-cli decode <hex>                  Decode raw TX (without broadcast)
    gnb-cli rawmempool [verbose]          List mempool transactions
    gnb-cli fee                           Estimate fee

  WALLET (simple)
    gnb-cli balance <address>             Get balance
    gnb-cli utxos <address>               List unspent outputs
    gnb-cli txlist <address> [count]      Transaction history
    gnb-cli validate <address>            Validate address format
    gnb-cli newwallet <path.json> [--random-key]
                                          New 1-key wallet from a 24-word recovery
                                          phrase (shown once); keystore v3
    gnb-cli restorewallet <path.json>     Restore a 1-key wallet from its phrase
    gnb-cli send <wallet.json> <to> <amount> [--fee auto|GNB] [--max-fee GNB]
                 [--yes] [--allow-unverified-inputs]
                                          Shows the actual fee and asks before
                                          broadcasting; verifies UTXO values

  HD WALLET (BIP39, multi-address)
    gnb-cli newseed <wallet-hd.json>      Generate 24-word mnemonic + wallet
    gnb-cli newaddress <wallet-hd.json> [label]    Add new address
    gnb-cli addresses <wallet-hd.json>    List all addresses
    gnb-cli importfounder <wallet-hd.json> <founder.json>    Import simple wallet

  eUTXO VM (node built with --features euvm)
    gnb-cli euvm_utxos [validator_hash] [limit] [offset]   List eUTXO contract UTXOs
    gnb-cli euvm_getutxo <txid> <index>   Inspect one UTXO (legacy or eUTXO, decoded)
    gnb-cli euvm_buildtx '<json>'         Build (and pre-validate) an eUTXO raw tx
                                            from a JSON build-request; broadcast the
                                            returned raw_tx with 'sendraw'

  PROOF-OF-IMPROVEMENT (PoI)
    gnb-cli treasury                      Treasury balance and stats
    gnb-cli claims                        List all PoI claims
    gnb-cli claim <claim_id>              Get claim details + vote tally
    gnb-cli submitclaim <commit> <cat:0-3> <desc> <addr> [ci_hex]    Submit improvement
    gnb-cli vote <claim_id> <voter_addr> <yes|no|abstain>            Vote on claim

  POLICY SIGNING AND PUBLIC DOCUMENT ROLES
    gnb-cli pqpsbt <public-request.json>    Offline create/decode/update/combine/review/finalize/extract
    gnb-cli descriptor create|inspect|import <input-file> --mainnet|--testnet
    gnb-cli descriptor export|pool <input-file> <new-pool-file> --mainnet|--testnet
                                           Offline public identities only; no key or balance restore
    gnb-cli policysign <document.json> <wallet.json> [--max-fee GNB] [--yes]
                                           Verify the configured node before key access

  OPTIONS
    --rpc-host <host>                      RPC host (default: 127.0.0.1)
    --rpc-port <port>                      RPC port (default: 17210)
    --rpc-url <url>                        RPC endpoint URL instead of host/port:
                                           http://host:port or https://host[:port]
                                           (certificate and host name verified)
    --rpc-ca <file>                        PEM/DER trust anchor(s) for https (a
                                           private CA or self-signed certificate)
    --allow-large-hd-wallet                Trusted-backup recovery (up to 512 MiB)
    --testnet                              New wallets are testnet (newwallet,
                                           restorewallet, newseed); for send,
                                           keyinfo, importfounder, pubkey: the
                                           keystore must be a testnet key;
                                           policyaddress, policyspend and
                                           vaultcreate work on testnet
    --mainnet                              For send, keyinfo, importfounder,
                                           pubkey: the keystore must be a mainnet
                                           key. A v2 keystore (which authenticates
                                           no network) opens only with --mainnet
                                           or --testnet; send rewrites it as v3.
                                           policysign / vaultlock open the
                                           keystore for the spend's / vault's
                                           network (CRY-7)
    GNB_RPC_API_KEY=<key>                  Sent over https to any host; over plain
                                           http only to loopback (or SSH tunnel)
    --help                                 This message
"#);
}

#[cfg(test)]
mod audit_send_inputs {
    use super::*;

    fn public_wallet_fixture(addresses: usize) -> gnb::hd_wallet::HdWalletFile {
        let crypto = gnb::wallet::KeystoreCrypto {
            cipher: "fixture".into(),
            ciphertext: String::new(),
            nonce: String::new(),
            kdf: "fixture".into(),
            kdf_params: gnb::wallet::KdfParams {
                memory_cost: 1,
                time_cost: 1,
                parallelism: 1,
                salt: String::new(),
                output_len: 32,
            },
        };
        gnb::hd_wallet::HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto: crypto.clone(),
            addresses: (0..addresses).map(|index| gnb::hd_wallet::HdAddress {
                index: index as u32,
                address: format!("{}public-{index}", gnb::core::TESTNET_PREFIX),
                label: String::new(),
                keypair_crypto: crypto.clone(),
                derived: false,
            }).collect(),
            created_at: String::new(),
            description: String::new(),
        }
    }

    #[test]
    fn amounts_are_exact_and_refuse_sub_satoshi_or_exponent_notation() {
        for value in ["NaN", "inf", "-1", "1e30", "0.000000019", "0"] {
            assert!(checked_payment_sats(value).is_err());
        }
        assert_eq!(gnb::wallet::parse_bloch_satoshis("0"), Ok(0));
        assert_eq!(checked_payment_sats("1.25"), Ok(125_000_000));
        assert_eq!(checked_payment_sats("90071992.54740993"), Ok(9_007_199_254_740_993));
    }
    #[test]
    fn indices_and_networks_are_checked_before_information_is_discarded() {
        use gnb::address::{Address, Network};
        let main = Address::from_hash([1; 20], Network::Mainnet).to_string();
        let test = Address::from_hash([1; 20], Network::Testnet).to_string();
        assert!(checked_destination(&main, &test).is_err());
        assert!(checked_destination(&test, &main).is_err());
        assert_eq!(checked_destination(&main, &main).unwrap(), "01".repeat(20));
        let mut row = serde_json::json!({"txid": "ab".repeat(32), "index": u32::MAX,
            "value": "9007199254740993", "script_pubkey": "cd".repeat(20)});
        let parsed = parse_send_utxos(&[row.clone()]).unwrap();
        assert_eq!(parsed[0].1, u32::MAX);
        assert_eq!(parsed[0].2.value, 9_007_199_254_740_993);
        row["index"] = serde_json::json!(4294967296u64);
        assert!(parse_send_utxos(&[row]).is_err());
        assert!(parse_send_utxos(&[serde_json::json!({})]).is_err());
    }

    #[test]
    fn address_listing_is_bounded_unless_trusted_backup_override_is_explicit() {
        let path = std::env::temp_dir().join(format!(
            "gnb-cli-public-wallet-limit-{}.json",
            std::process::id()
        ));
        let fixture = public_wallet_fixture(
            gnb::hd_wallet::DEFAULT_HD_WALLET_LOAD_LIMITS.max_addresses + 1,
        );
        std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
        let path_str = path.to_str().unwrap();

        let rejected = read_public_hd_wallet(path_str, false).err().unwrap();
        assert!(rejected.contains("address count 1025 exceeds configured limit 1024"));
        assert!(rejected.contains("--allow-large-hd-wallet"));
        assert_eq!(read_public_hd_wallet(path_str, true).unwrap().addresses.len(), 1025);
        std::fs::remove_file(path).unwrap();
    }

    /// CRY-7 on main's policy and vault commands: their network is the one
    /// stated (`--testnet` / `--mainnet`, which `main`'s parser consumes, so
    /// a test of `params` never saw it and a testnet policy address or vault
    /// came out as mainnet), mainnet by default; a destination of the other
    /// network is refused. A single-key address's checksum does not cover
    /// its prefix, so `gnb1t…` with a mainnet hash parses: the network check
    /// is the only thing that stops a mistyped prefix.
    #[test]
    fn policy_and_vault_destinations_must_be_on_the_spends_network() {
        use gnb::address::{Address, Network, PolicyAddress};
        assert_eq!(policy_network(None), Network::Mainnet);
        assert_eq!(policy_network(Some(Network::Testnet)), Network::Testnet);
        let main = Address::from_hash([0x11; 20], Network::Mainnet).to_string();
        let test = Address::from_hash([0x11; 20], Network::Testnet).to_string();
        assert_eq!(destination_on(&main, Network::Mainnet, "recipient").unwrap(), vec![0x11; 20]);
        let err = destination_on(&test, Network::Mainnet, "recipient").unwrap_err();
        assert!(err.contains("Testnet") && err.contains("Mainnet"), "{err}");
        assert!(destination_on(&main, Network::Testnet, "recipient").is_err());
        let keys: Vec<Vec<u8>> = (0..2).map(|_| gnb::crypto::generate_keypair().0).collect();
        let policy = gnb::core::policy::SpendPolicy::new(1, keys, 0, 0).unwrap();
        let pm = PolicyAddress::from_policy(&policy, Network::Mainnet).to_string();
        let pt = PolicyAddress::from_policy(&policy, Network::Testnet).to_string();
        assert_eq!(destination_on(&pm, Network::Mainnet, "destination").unwrap(), policy.script_pubkey());
        assert!(destination_on(&pt, Network::Mainnet, "destination").is_err());
        assert_eq!(destination_on(&pt, Network::Testnet, "destination").unwrap(), policy.script_pubkey());
        assert!(destination_on("gnb1zz", Network::Mainnet, "destination").is_err());
    }
}

#[cfg(test)]
#[path = "../../tests/support/pqpsbt_cli_unit.rs"]
mod pqpsbt_cli_tests;

#[cfg(test)]
#[path = "../../tests/support/address_frontends_cli.rs"]
mod address_frontends_tests;
