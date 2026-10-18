//! End to end on ObenBlock regtest: a real node (`gnb --chain obenblock
//! --regtest`, fresh data directory), this stratum server, and
//! `obenblock-cpu-miner` connected to it. The miner finds blocks through
//! stratum, the server submits them, and the node accepts them: its tip
//! height grows, every submitted block is accepted, and the coinbase outputs
//! pay the configured address.
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
    assert_eq!(s.shares_bitcoin_root, 0);

    // The node's chain grew by them.
    let t2 = Instant::now();
    loop {
        let h = tip_height(&rpc).await.unwrap_or(0);
        if h >= start_height + want {
            break;
        }
        assert!(t2.elapsed() < Duration::from_secs(30), "tip height {h}, started at {start_height}");
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
