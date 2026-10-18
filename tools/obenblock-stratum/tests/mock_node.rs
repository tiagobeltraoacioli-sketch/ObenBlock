//! The whole stratum path against a mock node (no node binary needed): the
//! mock answers `getdaginfo` and `getblocktemplate` (a header job built from
//! the node's job vectors, at the current time) and records `submitblock`.
//! `obenblock-cpu-miner` connects to the real server; the test checks that a
//! submitted block's own bytes carry a header whose SHA-256d id meets its
//! bits (Bitcoin's Merkle root over the patched coinbase), and that
//! `submitblock`'s solution (version, time, nonce, extranonce) matches it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use obenblock_stratum::server::StratumServer;
use obenblock_stratum::types::{Network, Payout, StratumConfig};
use obenblock_stratum::validator::{bits_to_target, block_id, header80, meets_target};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type Calls = Arc<Mutex<Vec<Value>>>;

async fn serve_mock(listener: TcpListener, calls: Calls) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else { return };
        let calls = calls.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            let body = loop {
                let n = s.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                    .unwrap_or(0);
                if buf.len() >= end + 4 + len {
                    break buf[end + 4..end + 4 + len].to_vec();
                }
            };
            let req: Value = serde_json::from_slice(&body).unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
            let result = match req["method"].as_str().unwrap() {
                "getdaginfo" => json!({"tips": ["11"], "tip_height": 0}),
                "getblocktemplate" => {
                    assert_eq!(req["params"][0]["header_job"]["extranonce"], json!("0000000000000000"));
                    obenblock_stratum::fixtures::template_from_vector_at(0, Some(now))
                }
                "submitblock" => {
                    calls.lock().unwrap().push(req["params"].clone());
                    json!({"accepted": true, "hash": "00"})
                }
                other => json!({"error": format!("unknown {other}")}),
            };
            let out = json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string();
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                               out.len());
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        });
    }
}

/// The 80-byte header a block's own bytes carry.
fn header_of_block(b: &[u8]) -> [u8; 80] {
    let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
    let n = b[4] as usize;
    let parents: Vec<[u8; 32]> = b[5..5 + 32 * n].chunks(32).map(|c| c.try_into().unwrap()).collect();
    let at = 5 + 32 * n;
    let root: [u8; 32] = b[at..at + 32].try_into().unwrap();
    let time = u64::from_le_bytes(b[at + 32..at + 40].try_into().unwrap());
    let bits = u32::from_le_bytes(b[at + 40..at + 44].try_into().unwrap());
    let nonce = u64::from_le_bytes(b[at + 44..at + 52].try_into().unwrap());
    header80(version, &gnb_smh::sha256d::parents_commitment(&parents), &root, time as u32, bits, nonce as u32)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cpu_miner_blocks_reach_submitblock_with_valid_headers() {
    let rpc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_addr = rpc_listener.local_addr().unwrap();
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(serve_mock(rpc_listener, calls.clone()));

    let cfg = StratumConfig {
        listen_addr: "127.0.0.1:0".into(),
        metrics_addr: String::new(),
        rpc_addr: rpc_addr.to_string(),
        network: Network::Mainnet,
        payout: Payout { address: "obb1q0000000000000000000000000000000000000000335d2ee7".into(), script_pubkey: vec![0; 20] },
        poll_interval: Duration::from_millis(100),
        vardiff_initial: 1e-6,
        vardiff_min: 1e-12,
        ..StratumConfig::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = StratumServer::new(cfg);
    let metrics = server.metrics();
    tokio::spawn(server.run_on(listener, std::future::pending()));

    let mut miner = std::process::Command::new(env!("CARGO_BIN_EXE_obenblock-cpu-miner"))
        .args(["-o", &format!("stratum+tcp://{addr}"), "-u", "obb1q0000000000000000000000000000000000000000335d2ee7.t",
               "-t", "2", "--once"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let t0 = Instant::now();
    while calls.lock().unwrap().len() < 3 {
        assert!(t0.elapsed() < Duration::from_secs(60), "no blocks submitted; shares {:?}", metrics.snapshot());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = miner.kill();
    let _ = miner.wait();

    let submitted = calls.lock().unwrap().clone();
    for p in &submitted {
        let block = hex::decode(p[0].as_str().unwrap()).unwrap();
        let header = header_of_block(&block);
        let bits = u32::from_le_bytes(header[72..76].try_into().unwrap());
        assert!(meets_target(&block_id(&header), &bits_to_target(bits)), "the block's own header meets its bits");
        let sol = &p[1];
        assert_eq!(sol["version"].as_u64().unwrap() as u32, u32::from_le_bytes(header[0..4].try_into().unwrap()));
        assert_eq!(sol["time"].as_u64().unwrap() as u32, u32::from_le_bytes(header[68..72].try_into().unwrap()));
        assert_eq!(sol["nonce"].as_u64().unwrap() as u32, u32::from_le_bytes(header[76..80].try_into().unwrap()));
        // The share's extranonce travels too, and is the one in the block's coinbase.
        let en = sol["extranonce"].as_str().expect("submitblock carries the extranonce");
        assert_eq!(en.len(), 16);
        assert!(hex::encode(&block).contains(&format!("2f6f62622f{en}")), "coinbase script_sig ends /obb/ ‖ extranonce");
    }
    // Distinct blocks (extranonce lanes and nonces never repeat).
    let mut ids: Vec<_> = submitted.iter().map(|p| block_id(&header_of_block(&hex::decode(p[0].as_str().unwrap()).unwrap()))).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), submitted.len());
    let s = metrics.snapshot();
    assert!(s.blocks_found >= 3, "{s:?}");
}
