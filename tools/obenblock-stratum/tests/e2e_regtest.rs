//! End to end on ObenBlock regtest: a real node (`gnb --chain obenblock
//! --regtest`, fresh data directory), this stratum server, and two kinds of
//! miners connected to it: `obenblock-cpu-miner`, then a stock-firmware-style
//! device written here from the Stratum V1 protocol alone (Bitcoin's
//! coinbase / Merkle / header math with the `sha2` crate, no code of this
//! crate; version rolling and a rolled `ntime`). Both find blocks through
//! stratum, the server submits them with their extranonce, and the node
//! accepts them: its tip height grows, every submitted block is accepted,
//! and the coinbase outputs pay the configured address.
//!
//! Needs the node binary, built from the repository root (not part of this
//! workspace):
//!
//! ```text
//! cargo build --release -p gnb --bin gnb
//! cargo test --release --manifest-path tools/obenblock-stratum/Cargo.toml -- --ignored
//! ```
//!
//! `OBB_NODE_BIN` overrides the binary path (default
//! `<repo>/target/release/gnb`).

use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use obenblock_stratum::rpc::RpcClient;
use obenblock_stratum::server::StratumServer;
use obenblock_stratum::types::{Network, Payout, StratumConfig};
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

const API_KEY: &str = "3f9c2a7e5b1d48c6a0e7f2b9d4c18e56";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repository root")
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A regtest (testnet-slot) single-key address for `hash`:
/// `obb1t ‖ hex(hash ‖ SHA3(SHA3(hash))[:4])`.
fn regtest_address(hash: [u8; 20]) -> String {
    let check = Sha3_256::digest(Sha3_256::digest(hash));
    format!("obb1t{}{}", hex::encode(hash), hex::encode(&check[..4]))
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn node_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("node.log")).unwrap_or_default()
        .lines().rev().take(40).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
}

async fn block_count(rpc: &RpcClient) -> Option<u64> {
    rpc.call("getblockcount", json!([])).await.ok().and_then(|v| v.as_u64())
}

async fn tip_height(rpc: &RpcClient) -> Option<u64> {
    rpc.call("getdaginfo", json!([])).await.ok().and_then(|v| v.get("tip_height").and_then(Value::as_u64))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the node binary: cargo build --release -p gnb --bin gnb (see the module docs)"]
async fn cpu_miner_mines_regtest_blocks_through_stratum() {
    let _ = env_logger::builder().is_test(true).filter_level(log::LevelFilter::Info).try_init();
    let root = repo_root();
    let node_bin = std::env::var("OBB_NODE_BIN").map(PathBuf::from).unwrap_or_else(|_| root.join("target/release/gnb"));
    assert!(node_bin.exists(), "node binary {} missing: cargo build --release -p gnb --bin gnb", node_bin.display());

    let tmp = tempfile::tempdir().unwrap();
    let snapshot = tmp.path().join("bloch-g3-carryover.tsv");
    let out = Command::new("gzip").arg("-dc").arg(root.join("genesis/bloch-g3-carryover.tsv.gz")).output().unwrap();
    assert!(out.status.success(), "gunzip the carry-over snapshot");
    std::fs::write(&snapshot, &out.stdout).unwrap();

    let (rpc_port, p2p_port) = (free_port(), free_port());
    let log = std::fs::File::create(tmp.path().join("node.log")).unwrap();
    let node = Command::new(&node_bin)
        .args(["--chain", "obenblock", "--regtest", "--no-default-dns-seed"])
        .arg("--data-dir").arg(tmp.path().join("data"))
        .arg("--carryover-snapshot").arg(&snapshot)
        .args(["--rpc-port", &rpc_port.to_string(), "--rpc-api-key", API_KEY])
        .args(["--listen", &format!("/ip4/127.0.0.1/tcp/{p2p_port}")])
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("start the node");
    let mut node = Killed(node);

    let rpc = RpcClient::new(format!("127.0.0.1:{rpc_port}"), Some(API_KEY.into()));
    let t0 = Instant::now();
    let start_height = loop {
        if let Some(h) = tip_height(&rpc).await {
            break h;
        }
        if node_log(tmp.path()).contains("refusing to start the RPC") {
            panic!("node RPC refused to start:\n{}", node_log(tmp.path()));
        }
        if let Ok(Some(status)) = node.0.try_wait() {
            panic!("node exited ({status}):\n{}", node_log(tmp.path()));
        }
        assert!(t0.elapsed() < Duration::from_secs(300), "node RPC not up:\n{}", node_log(tmp.path()));
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let start_count = block_count(&rpc).await.expect("getblockcount");
    let hash = [0x42u8; 20];
    let address = regtest_address(hash);
    let cfg = StratumConfig {
        listen_addr: "127.0.0.1:0".into(),
        metrics_addr: String::new(),
        rpc_addr: format!("127.0.0.1:{rpc_port}"),
        rpc_api_key: Some(API_KEY.into()),
        network: Network::Regtest,
        payout: Payout { address: address.clone(), script_pubkey: hash.to_vec() },
        poll_interval: Duration::from_millis(200),
        refresh_interval: Duration::from_secs(10),
        vardiff_initial: 1e-6,
        vardiff_min: 1e-12,
        ..StratumConfig::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stratum_addr = listener.local_addr().unwrap();
    let server = StratumServer::new(cfg);
    let metrics = server.metrics();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(server.run_on(listener, async { let _ = stop_rx.await; }));

    let miner = Command::new(env!("CARGO_BIN_EXE_obenblock-cpu-miner"))
        .args(["-o", &format!("stratum+tcp://{stratum_addr}"), "-u", &format!("{address}.e2e"), "-t", "4", "--once"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start the CPU miner");
    let _miner = Killed(miner);

    // Five blocks through stratum.
    let want = 5u64;
    let t1 = Instant::now();
    loop {
        let accepted = metrics.blocks_accepted.load(Ordering::Relaxed);
        if accepted >= want {
            break;
        }
        assert!(t1.elapsed() < Duration::from_secs(240),
                "only {accepted} blocks accepted (rejected {}, shares {}):\n{}",
                metrics.blocks_rejected.load(Ordering::Relaxed), metrics.shares_accepted.load(Ordering::Relaxed),
                node_log(tmp.path()));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(metrics.blocks_rejected.load(Ordering::Relaxed), 0, "the node refused a block:\n{}", node_log(tmp.path()));
    let s = metrics.snapshot();
    assert!(s.shares_accepted >= want);
    drop(_miner);

    // A stock Stratum V1 device: three more blocks, each accepted.
    let before = metrics.blocks_accepted.load(Ordering::Relaxed);
    let user = format!("{address}.stock");
    let addr = stratum_addr.to_string();
    let stock = tokio::task::spawn_blocking(move || stock_device(&addr, &user, 3, Duration::from_secs(120)));
    let submitted = stock.await.unwrap().unwrap_or_else(|e| panic!("stock device: {e}\n{}", node_log(tmp.path())));
    assert_eq!(submitted, 3);
    let t4 = Instant::now();
    while metrics.blocks_accepted.load(Ordering::Relaxed) < before + 3 {
        assert!(t4.elapsed() < Duration::from_secs(30), "stock device blocks not accepted (rejected {}):\n{}",
                metrics.blocks_rejected.load(Ordering::Relaxed), node_log(tmp.path()));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(metrics.blocks_rejected.load(Ordering::Relaxed), 0, "the node refused a block:\n{}", node_log(tmp.path()));
    let want = want + 3;

    // The node holds every one of them. (Blocks found on the same parents
    // by different CPU-miner threads are DAG siblings at one height, so the
    // block count, not the tip height, grows by `want`; the stock device's
    // blocks each build on the previous one.)
    let t2 = Instant::now();
    loop {
        let n = block_count(&rpc).await.unwrap_or(0);
        let h = tip_height(&rpc).await.unwrap_or(0);
        if n >= start_count + want && h >= start_height + 3 {
            break;
        }
        assert!(t2.elapsed() < Duration::from_secs(30),
                "block count {n} (started at {start_count}), tip height {h} (started at {start_height})");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Their coinbases pay the configured address (the node's view).
    let t3 = Instant::now();
    loop {
        let info = rpc.call("getaddressinfo", json!([address])).await.unwrap_or(Value::Null);
        let utxos = info.get("utxo_count").and_then(Value::as_u64).unwrap_or(0);
        if utxos >= 1 {
            break;
        }
        assert!(t3.elapsed() < Duration::from_secs(30), "no output to {address}: {info}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = stop_tx.send(());
    let _ = server_task.await;
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

/// A compact `nbits` as a 32-byte big-endian target (exponent >= 3).
fn compact_target(bits: u32) -> [u8; 32] {
    let (e, m) = ((bits >> 24) as usize, bits & 0x007f_ffff);
    let mut t = [0u8; 32];
    t[32 - e..32 - e + 3].copy_from_slice(&m.to_be_bytes()[1..]);
    t
}

/// A stock Stratum V1 device, as Bitcoin ASIC firmware behaves: it
/// negotiates BIP 310 version rolling, takes `extranonce1` /
/// `extranonce2_size` from `mining.subscribe`, and for every
/// `mining.notify` builds `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2`,
/// folds its SHA-256d txid up `merkle_branch`, swaps the `prevhash` words
/// back, rolls version bits and `ntime` (+1) and scans nonces. It submits
/// the first header that meets `nbits` (a block) per job, until `blocks`
/// such submissions were accepted. Returns how many were.
fn stock_device(addr: &str, user: &str, blocks: usize, limit: Duration) -> Result<usize, String> {
    use std::io::{BufRead, BufReader, Write};
    let deadline = Instant::now() + limit;
    let stream = std::net::TcpStream::connect(addr).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut wr = stream.try_clone().unwrap();
    let mut send = |v: Value| wr.write_all(format!("{v}\n").as_bytes()).map_err(|e| e.to_string());
    send(json!({"id": 1, "method": "mining.configure", "params": [["version-rolling"], {"version-rolling.mask": "ffffffff"}]}))?;
    send(json!({"id": 2, "method": "mining.subscribe", "params": ["cgminer/4.12.1"]}))?;
    send(json!({"id": 3, "method": "mining.authorize", "params": [user, "x"]}))?;
    let mut rd = BufReader::new(stream);
    let (mut mask, mut en1, mut en2_size) = (0u32, Vec::new(), 0usize);
    let (mut counter, mut pending, mut accepted) = (0u32, 0usize, 0usize);
    let (mut latest, mut mined): (Option<Value>, Value) = (None, Value::Null);
    let mut line = String::new();
    while accepted < blocks {
        if Instant::now() > deadline {
            return Err(format!("only {accepted} block shares accepted"));
        }
        line.clear();
        match rd.read_line(&mut line) {
            Ok(0) => return Err("server closed the connection".into()),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e.to_string()),
        }
        let v: Value = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
        match (v["id"].as_u64(), v["method"].as_str()) {
            (Some(1), None) => {
                mask = u32::from_str_radix(v["result"]["version-rolling.mask"].as_str().unwrap_or("0"), 16).unwrap();
            }
            (Some(2), None) => {
                en1 = hex::decode(v["result"][1].as_str().ok_or("subscribe result")?).unwrap();
                en2_size = v["result"][2].as_u64().ok_or("extranonce2_size")? as usize;
            }
            (Some(3), None) if v["result"] != json!(true) => return Err(format!("authorize: {v}")),
            (Some(id), None) if id >= 100 => {
                if v["result"] == json!(true) {
                    accepted += 1;
                } else {
                    return Err(format!("block share rejected: {v}"));
                }
                pending -= 1;
            }
            (_, Some("mining.notify")) => latest = Some(v["params"].clone()),
            _ => {}
        }
        // One block share in flight; then the newest job not mined yet.
        if pending == 0 && accepted < blocks && !en1.is_empty() {
            if let Some(p) = latest.as_ref().filter(|p| p[0] != mined) {
                mined = p[0].clone();
                let hx = |i: usize| hex::decode(p[i].as_str().unwrap()).unwrap();
                let be = |i: usize| u32::from_str_radix(p[i].as_str().unwrap(), 16).unwrap();
                counter += 1;
                let en2: Vec<u8> = counter.to_be_bytes()[4 - en2_size.min(4)..].to_vec();
                let mut cb = hx(2);
                cb.extend_from_slice(&en1);
                cb.extend_from_slice(&en2);
                cb.extend(hx(3));
                let mut root = sha256d(&cb);
                for b in p[4].as_array().unwrap() {
                    let mut pair = root.to_vec();
                    pair.extend(hex::decode(b.as_str().unwrap()).unwrap());
                    root = sha256d(&pair);
                }
                let prev = hx(1);
                let rolled = (counter << 13) & mask;
                let (version, nbits, ntime) = (be(5) & !mask | rolled, be(6), be(7) + 1);
                let target = compact_target(nbits);
                let mut header = Vec::with_capacity(80);
                header.extend_from_slice(&version.to_le_bytes());
                for w in prev.chunks(4) {
                    header.extend(w.iter().rev());
                }
                header.extend_from_slice(&root);
                header.extend_from_slice(&ntime.to_le_bytes());
                header.extend_from_slice(&nbits.to_le_bytes());
                header.extend_from_slice(&[0; 4]);
                let nonce = (0u32..).find(|n| {
                    header[76..80].copy_from_slice(&n.to_le_bytes());
                    let mut id = sha256d(&header);
                    id.reverse();
                    id <= target
                }).unwrap();
                pending += 1;
                send(json!({"id": 100 + counter, "method": "mining.submit", "params": [user, p[0], hex::encode(&en2),
                    format!("{ntime:08x}"), format!("{nonce:08x}"), format!("{rolled:08x}")]}))?;
            }
        }
    }
    Ok(accepted)
}
