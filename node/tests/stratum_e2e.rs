//! The node's built-in stratum servers on ObenBlock regtest, end to end
//! (docs/STRATUM.md).
//!
//! * The 80-byte header a V1 miner builds from `mining.notify`, the header
//!   an SV2 standard channel builds from `NewMiningJob` + `SetNewPrevHash`,
//!   the RPC header job (`getblocktemplate [{"header_job": …}]`) and the
//!   header the node's own proof check hashes (`BlockHeader::sha256d_pow_bytes`)
//!   are byte-identical for one template, payout script, extranonce and time.
//! * A V1 test client (subscribe, configure version rolling and
//!   `obb-merkle-root`, authorize with an `obb1t…` address, compute the
//!   header root with ObenBlock's rule from the notify alone, roll the
//!   version, search the nonce, submit) finds a block the node accepts.
//! * An SV2 test client built from SRI's own types (noise_sv2 `Initiator`,
//!   codec_sv2 `NoiseEncoder` / `StandardNoiseDecoder`, common_messages_sv2
//!   and mining_sv2 messages) pins the authority key, opens a standard
//!   channel, mines the job and gets a block accepted; the next tip's job
//!   follows on the same channel.
//! * The job of a late block changes bits at every stall-relief step: a
//!   share whose time leaves the job's step is refused, and the work feed's
//!   step check fires.
//!
//! The chain id is process-wide (ObenBlock regtest): this file is its own
//! test process. The node starts from the real regtest genesis
//! (`genesis_init`, as main.rs does), so every rule of the chain applies from
//! height 0 (PoWit, liveness, the exits list in the body root).
#![cfg(feature = "stratum-v2")]

mod fix_common;
use fix_common::*;

use std::sync::Arc;
use std::time::Duration;

use gnb::address::{self, AddressFamily, Network};
use gnb::coherence::ShieldedPool;
use gnb::consensus::GhostDAG;
use gnb::core::{self, pow_scheme, ChainId};
use gnb::mempool::Mempool;
use gnb::rpc::NodeState;
use gnb::storage::Storage;
use gnb::stratum::{self, jobs::Job, payout, work, NodeContext};
use gnb::stratum_v2::{self, messages as v2msg, AuthorityKeypair};
use gnb::{genesis_init, ingress, template, tip};
use parking_lot::RwLock;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

// ── Node set-up ──────────────────────────────────────────────────────────────

fn snapshot() -> Vec<u8> {
    let gz = concat!(env!("CARGO_MANIFEST_DIR"), "/../genesis/bloch-g3-carryover.tsv.gz");
    let out = std::process::Command::new("gzip").args(["-dc", gz]).output().expect("gzip");
    assert!(out.status.success(), "gunzip the shipped snapshot");
    out.stdout
}

/// A fresh ObenBlock regtest node on its real genesis.
fn regtest_node() -> Node {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = core::set_node_chain_id(ChainId::ObenBlockRegtest);
    assert!(pow_scheme::node_sha256d_params().is_some(), "SHA-256d bound to the chain id");
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Arc::new(Storage::open(&tmp.path().join("db")).unwrap());
    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    genesis_init::initialise(&store, &dag, &snapshot()).expect("regtest genesis");
    let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(64);
    Node {
        path: tmp.path().join("db"),
        _tmp: tmp,
        dag,
        store,
        mempool: Arc::new(Mempool::new()),
        node_state: Arc::new(RwLock::new(NodeState::default())),
        shielded: Arc::new(RwLock::new(ShieldedPool::new())),
        tip_tx,
    }
}

fn params() -> pow_scheme::Sha256dParams {
    stratum::require_sha256d_chain().expect("ObenBlock regtest is a SHA-256d chain")
}

/// An ObenBlock regtest address (`obb1t…`) of a 20-byte key hash.
fn obb_address(fill: u8) -> String {
    address::Address::from_hash([fill; 20], Network::Testnet).to_string_in(AddressFamily::ObenBlock)
}

/// The acceptance hook of RPC `submitblock` (main.rs `make_rpc_submit_block_cb`
/// without the gossip): block-id dedup, minimum chain work, the cheap
/// structure check, `accept_block`.
fn accept_hook(n: &Node) -> Arc<stratum::AcceptBlockFn> {
    let (dag, store, mempool, node_state, shielded, tip_tx) =
        (n.dag.clone(), n.store.clone(), n.mempool.clone(), n.node_state.clone(), n.shielded.clone(), n.tip_tx.clone());
    Arc::new(move |mut block: core::Block| -> Result<String, String> {
        let hash = block.block_hash();
        ingress::normalize_wire_metadata(&mut block, &dag);
        if gnb::accept::is_known_block(&dag, &store, &hash) {
            return Err("duplicate block".into());
        }
        ingress::submitted_block_admission(&dag.read(), &block, ingress::minimum_chain_work())?;
        block.validate_structure_without_pow().map_err(|e| format!("structural validation: {e}"))?;
        gnb::accept::accept_block(&block, hash, block.height, &dag, &store, &mempool, &node_state, Some(&tip_tx), &shielded)?;
        Ok(hex::encode(hash))
    })
}

fn ctx(n: &Node) -> Arc<NodeContext> {
    Arc::new(NodeContext { dag: n.dag.clone(), store: n.store.clone(), mempool: n.mempool.clone(), min_chain_work: 0 })
}

// ── An independent client-side ObenBlock header root ─────────────────────────

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t: [u8; 32] = Sha256::digest(tag).into();
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn dsha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

/// docs/OBENBLOCK-MINING.md §3.3, written from the document, not the node.
fn client_header_root(coinb1: &[u8], extranonce: &[u8], coinb2: &[u8], branch: &[[u8; 32]],
                      shielded_root: &[u8; 32], powit_root: &[u8; 32]) -> [u8; 32] {
    let mut cb = coinb1.to_vec();
    cb.extend_from_slice(extranonce);
    cb.extend_from_slice(coinb2);
    let mut cur = tagged(b"GnB/merkle/leaf", &[&dsha(&cb)]);
    for s in branch {
        cur = tagged(b"GnB/merkle/node", &[&cur, s]);
    }
    let mut h = Sha3_256::new();
    h.update(b"gnb:block:body:v2");
    h.update(cur);
    h.update(shielded_root);
    h.update(powit_root);
    h.finalize().into()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn header(version: u32, prev: &[u8; 32], root: &[u8; 32], time: u32, bits: u32, nonce: u32) -> [u8; 80] {
    stratum::jobs::header_bytes(version, prev, root, time, bits, nonce)
}

/// The V1 notify as a client reads it: the header (nonce 0) for extranonce
/// `en1 ‖ en2`.
fn v1_client_header(notify: &Value, en1: &[u8], en2: &[u8], rolled_version: Option<u32>) -> ([u8; 80], u32) {
    let p = notify.as_array().unwrap();
    let swapped = hex32(&p[1]);
    let prev = stratum::session::stratum_prevhash(&swapped); // le32dec of each word
    let coinb1 = hex::decode(p[2].as_str().unwrap()).unwrap();
    let coinb2 = hex::decode(p[3].as_str().unwrap()).unwrap();
    let branch: Vec<[u8; 32]> = p[4].as_array().unwrap().iter().map(hex32).collect();
    let version = u32::from_str_radix(p[5].as_str().unwrap(), 16).unwrap();
    let bits = u32::from_str_radix(p[6].as_str().unwrap(), 16).unwrap();
    let ntime = u32::from_str_radix(p[7].as_str().unwrap(), 16).unwrap();
    let ext = &p[9];
    assert_eq!(ext["merkle_root_rule"], json!("gnb-body-v2"));
    let mut en = en1.to_vec();
    en.extend_from_slice(en2);
    let root = client_header_root(&coinb1, &en, &coinb2, &branch, &hex32(&ext["shielded_root"]), &hex32(&ext["powit_root"]));
    (header(rolled_version.unwrap_or(version), &prev, &root, ntime, bits, 0), bits)
}

/// The first nonce whose header meets `bits` (regtest: about two hashes).
fn solve(h: &[u8; 80], bits: u32) -> u32 {
    gnb::pow::mine_sha256d_parallel(h, bits, 0, 1 << 20, 1, None).expect("regtest target")
}

// ── 1. Byte identity ─────────────────────────────────────────────────────────

#[test]
fn v1_v2_rpc_and_node_headers_are_byte_identical() {
    let n = regtest_node();
    let params = params();
    let tmpl = Arc::new(template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap());
    assert!(core::liveness::liveness_active_at(tmpl.height), "the exits list is part of the root from height 0");
    let payout = payout::parse_payout_address(&obb_address(0x5A)).unwrap();
    assert_eq!(payout.script_pubkey, vec![0x5A; 20]);
    let en: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0x01, 0x02, 0x03, 0x04];
    let now = unix_now();

    // RPC: getblocktemplate's header job.
    let fields = gnb::mining::sha256d::template_fields(&tmpl, Some(&json!([{"header_job": {
        "coinbase_script_pubkey": hex::encode(&payout.script_pubkey), "extranonce": hex::encode(en),
    }}])), now).unwrap();
    let rpc_header: [u8; 80] = hex::decode(fields["header_job"]["header"].as_str().unwrap()).unwrap().try_into().unwrap();
    assert_eq!(fields["powit_root"].as_str().unwrap(), hex::encode(gnb::mining::sha256d::powit_root(&tmpl)));

    // V1: the job a session with extranonce1 = en[..4] builds, read back from
    // mining.notify by an ObenBlock-aware client that rolls en2 = en[4..].
    let mut en1_job = [0u8; 8];
    en1_job[..4].copy_from_slice(&en[..4]);
    let v1 = Job::build(tmpl.clone(), &params, &payout.script_pubkey, en1_job, now).unwrap();
    let notify = stratum::session::notify_params(&v1, "job-1", true, true);
    let (v1_header, _) = v1_client_header(&notify, &en[..4], &en[4..], None);
    assert_eq!(v1_header, rpc_header, "V1 header == getblocktemplate header job");
    assert_eq!(v1.share_header(&en, v1.version, v1.time, 0).unwrap(), rpc_header);

    // V2: a standard channel with extranonce prefix `en`, from SRI-decoded
    // NewMiningJob + SetNewPrevHash.
    let (v2, root) = stratum_v2::template_adapter::build_channel_job(tmpl.clone(), &params, &payout.script_pubkey, en, now).unwrap();
    let mut p = v2msg::new_mining_job(1, 7, None, v2.version, &root).unwrap().payload;
    let job: mining_sv2::NewMiningJob = binary_sv2::from_bytes(&mut p).unwrap();
    let mut p = v2msg::set_new_prev_hash(1, 7, &v2.parents_commitment, v2.time, v2.bits).unwrap().payload;
    let prev: mining_sv2::SetNewPrevHash = binary_sv2::from_bytes(&mut p).unwrap();
    let v2_header = header(job.version, prev.prev_hash.inner_as_ref().try_into().unwrap(),
                           job.merkle_root.inner_as_ref().try_into().unwrap(), prev.min_ntime, prev.nbits, 0);
    assert_eq!(v2_header, rpc_header, "V2 header == getblocktemplate header job");
    assert_eq!(v2.header, rpc_header);

    // The node: the block a share turns into serializes exactly that header,
    // its id is the SHA-256d of it, and its root is the block's body root.
    let solved = v1.solve(&en, v1.version, v1.time, 0).unwrap();
    assert_eq!(solved.block.header.sha256d_pow_bytes().unwrap(), rpc_header);
    assert_eq!(solved.id, solved.block.block_hash());
    assert_eq!(solved.block.header.merkle_root, solved.block.body_merkle_root());
    let solved2 = v2.solve(&en, v2.version, v2.time, 0).unwrap();
    assert_eq!(solved2.block.block_hash(), solved.block.block_hash());

    // A BIP 320 roll changes only the version bytes; a roll outside the mask
    // is refused.
    let rolled = v1.solve(&en, v1.version | 0x0000_6000, v1.time, 0).unwrap();
    assert_eq!(&rolled.header[4..], &rpc_header[4..]);
    assert!(v1.solve(&en, v1.version | 0x0000_0001, v1.time, 0).is_err());
}

// ── 2. V1 end to end ─────────────────────────────────────────────────────────

async fn send_line(w: &mut tokio::net::tcp::OwnedWriteHalf, v: Value) {
    w.write_all(format!("{v}\n").as_bytes()).await.unwrap();
}

async fn read_msg(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Value {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(120), r.read_line(&mut line)).await.expect("server answers").unwrap();
    assert!(n > 0, "server closed the connection");
    serde_json::from_str(&line).unwrap()
}

/// Read until the response with `id` (notifications before it are returned too).
async fn read_until_id(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>, id: i64) -> (Value, Vec<Value>) {
    let mut notes = Vec::new();
    loop {
        let m = read_msg(r).await;
        if m["id"] == json!(id) {
            return (m, notes);
        }
        notes.push(m);
    }
}

async fn read_until_notify(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Value {
    loop {
        let m = read_msg(r).await;
        if m["method"] == json!("mining.notify") {
            return m["params"].clone();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_client_mines_a_block_the_node_accepts() {
    let n = regtest_node();
    let params = params();
    let feed = work::spawn(ctx(&n), n.tip_tx.subscribe());
    let listener = stratum::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = stratum::StratumConfig { bind_addr: addr, max_sessions: 8, payout: None, accept_block: accept_hook(&n) };
    tokio::spawn(stratum::serve(listener, config, params, feed));

    let (rd, mut wr) = TcpStream::connect(addr).await.unwrap().into_split();
    let mut rd = BufReader::new(rd);
    send_line(&mut wr, json!({"id": 1, "method": "mining.subscribe", "params": ["obb-test-miner/1.0"]})).await;
    let sub = read_msg(&mut rd).await;
    let en1 = hex::decode(sub["result"][1].as_str().unwrap()).unwrap();
    assert_eq!(sub["result"][2], json!(4));
    send_line(&mut wr, json!({"id": 2, "method": "mining.configure",
        "params": [["version-rolling", "obb-merkle-root"], {"version-rolling.mask": "1fffe000"}]})).await;
    let conf = read_msg(&mut rd).await;
    assert_eq!(conf["result"]["version-rolling"], json!(true));
    assert_eq!(conf["result"]["obb-merkle-root"], json!(true));

    // A Bitcoin address is refused; the obb1t address is accepted.
    send_line(&mut wr, json!({"id": 3, "method": "mining.authorize", "params": ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "x"]})).await;
    assert_eq!(read_msg(&mut rd).await["error"][0], json!(24));
    let worker = format!("{}.rig1", obb_address(0x77));
    send_line(&mut wr, json!({"id": 4, "method": "mining.authorize", "params": [worker, "x"]})).await;
    let (auth, _) = read_until_id(&mut rd, 4).await;
    assert_eq!(auth["result"], json!(true), "{auth}");
    let notify = read_until_notify(&mut rd).await;
    let job_id = notify[0].as_str().unwrap().to_string();

    // Mine: en2, a rolled version, the nonce.
    let en2 = [0xEE, 0x00, 0x00, 0x01];
    let version_bits = 0x0000_2000u32;
    let base = u32::from_str_radix(notify[5].as_str().unwrap(), 16).unwrap();
    let (h, bits) = v1_client_header(&notify, &en1, &en2, Some(base | version_bits));
    let nonce = solve(&h, bits);
    let ntime = notify[7].as_str().unwrap().to_string();
    send_line(&mut wr, json!({"id": 5, "method": "mining.submit", "params": [
        worker, job_id, hex::encode(en2), ntime, format!("{nonce:08x}"), format!("{version_bits:08x}")]})).await;
    let (sub_resp, mut notes) = read_until_id(&mut rd, 5).await;
    assert_eq!(sub_resp["result"], json!(true), "the block is accepted: {sub_resp}");

    // The node's tip is the block: height 1, the rolled version, paying the
    // worker's address.
    let mut h1 = h;
    h1[76..80].copy_from_slice(&nonce.to_le_bytes());
    let id = gnb_smh::sha256d::block_id(&h1);
    assert_eq!(sel_tip(&n), Some(id));
    let b = n.store.get_block(&id).unwrap().expect("stored");
    assert_eq!((b.height, b.header.version), (1, base | version_bits));
    assert_eq!(b.transactions[0].outputs[0].script_pubkey, vec![0x77; 20]);

    // The same share again is a duplicate; the tip change brings a clean job
    // on the new tip.
    send_line(&mut wr, json!({"id": 6, "method": "mining.submit", "params": [
        "w", notify[0], hex::encode(en2), notify[7], format!("{nonce:08x}"), format!("{version_bits:08x}")]})).await;
    let (dup, more) = read_until_id(&mut rd, 6).await;
    assert!(dup["error"][0] == json!(22) || dup["error"][0] == json!(21), "{dup}");
    notes.extend(more);
    let next = match notes.into_iter().find(|m| m["method"] == json!("mining.notify")) {
        Some(m) => m["params"].clone(),
        None => read_until_notify(&mut rd).await,
    };
    assert_eq!(next[8], json!(true), "clean_jobs on a new tip");
    let prev = stratum::session::stratum_prevhash(&hex32(&next[1]));
    assert_eq!(prev, gnb_smh::sha256d::parents_commitment(&[id]));
}

// ── 3. SV2 end to end with SRI client types ─────────────────────────────────

struct Sv2Client {
    stream: TcpStream,
    state: codec_sv2::State,
    decoder: codec_sv2::StandardNoiseDecoder<mining_sv2::SubmitSharesStandard>,
}

impl Sv2Client {
    async fn connect(addr: std::net::SocketAddr, authority: [u8; 32]) -> Self {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut initiator = noise_sv2::Initiator::from_raw_k(authority).unwrap();
        stream.write_all(&initiator.step_0().unwrap()).await.unwrap();
        let mut act2 = [0u8; noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream.read_exact(&mut act2).await.unwrap();
        let codec = initiator.step_2(act2).expect("the server's certificate verifies against the pinned key");
        Self { stream, state: codec_sv2::State::with_transport_mode(codec), decoder: codec_sv2::StandardNoiseDecoder::new() }
    }

    async fn send<T: binary_sv2::Serialize + binary_sv2::GetSize>(&mut self, m: T, msg_type: u8, channel_msg: bool) {
        let frame = codec_sv2::StandardSv2Frame::<T>::from_message(m, msg_type, 0, channel_msg).unwrap();
        let mut enc = codec_sv2::NoiseEncoder::<T>::new();
        let bytes = enc.encode(frame.into(), &mut self.state).unwrap();
        self.stream.write_all(bytes.as_ref()).await.unwrap();
    }

    /// The next frame: (msg_type, channel_msg, payload).
    async fn recv(&mut self) -> (u8, bool, Vec<u8>) {
        loop {
            match self.decoder.next_frame(&mut self.state) {
                Ok(f) => {
                    let mut f: codec_sv2::StandardSv2Frame<mining_sv2::SubmitSharesStandard> = f.try_into().unwrap();
                    let h = f.get_header().unwrap();
                    return (h.msg_type(), h.channel_msg(), f.payload().to_vec());
                }
                Err(codec_sv2::Error::MissingBytes(_)) => {
                    let buf = self.decoder.writable();
                    tokio::time::timeout(Duration::from_secs(120), self.stream.read_exact(buf)).await
                        .expect("server answers").expect("read");
                }
                Err(e) => panic!("SRI decoder: {e:?}"),
            }
        }
    }

    async fn recv_type(&mut self, want: u8) -> Vec<u8> {
        loop {
            let (t, _, p) = self.recv().await;
            if t == want {
                return p;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sv2_sri_client_mines_a_block_the_node_accepts() {
    use common_messages_sv2::{Protocol, SetupConnection, SetupConnectionSuccess, MESSAGE_TYPE_SETUP_CONNECTION,
                              MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS};
    use mining_sv2::*;

    let n = regtest_node();
    let params = params();
    let feed = work::spawn(ctx(&n), n.tip_tx.subscribe());
    let dir = tempfile::TempDir::new().unwrap();
    let key_path = dir.path().join("authority.json");
    let authority = AuthorityKeypair::load_or_generate(&key_path).unwrap();
    let pinned = stratum_v2::keypair::parse_public_key_base58(&authority.public_base58()).unwrap();
    let listener = stratum_v2::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = stratum_v2::Sv2Config::new(addr, 8, key_path, None, accept_hook(&n)).unwrap();
    tokio::spawn(stratum_v2::serve(listener, config, authority, params, feed));

    let mut c = Sv2Client::connect(addr, pinned).await;
    c.send(SetupConnection {
        protocol: Protocol::MiningProtocol, min_version: 2, max_version: 2, flags: 0b101,
        endpoint_host: "127.0.0.1".to_string().try_into().unwrap(), endpoint_port: addr.port(),
        vendor: "obb-test".to_string().try_into().unwrap(),
        hardware_version: "cpu".to_string().try_into().unwrap(),
        firmware: "1.0".to_string().try_into().unwrap(),
        device_id: "dev1".to_string().try_into().unwrap(),
    }, MESSAGE_TYPE_SETUP_CONNECTION, false).await;
    let mut p = c.recv_type(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS).await;
    let ok: SetupConnectionSuccess = binary_sv2::from_bytes(&mut p).unwrap();
    assert_eq!(ok.used_version, 2);
    assert_eq!(ok.flags & 1, 0, "REQUIRES_FIXED_VERSION is not set: version rolling allowed");

    // A user that is not an address of this network is refused.
    c.send(OpenStandardMiningChannel {
        request_id: 1u32.into(), user_identity: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string().try_into().unwrap(),
        nominal_hash_rate: 1.0e6, max_target: binary_sv2::U256::from([0xff; 32]),
    }, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false).await;
    let mut p = c.recv_type(MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR).await;
    let e: OpenMiningChannelError = binary_sv2::from_bytes(&mut p).unwrap();
    assert_eq!(e.error_code.inner_as_ref(), b"unknown-user");

    c.send(OpenStandardMiningChannel {
        request_id: 2u32.into(), user_identity: format!("{}.sv2rig", obb_address(0x66)).try_into().unwrap(),
        nominal_hash_rate: 1.0e6, max_target: binary_sv2::U256::from([0xff; 32]),
    }, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false).await;
    let mut p = c.recv_type(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS).await;
    let open: OpenStandardMiningChannelSuccess = binary_sv2::from_bytes(&mut p).unwrap();
    assert_eq!(open.request_id.as_u32(), 2);
    let channel_id = open.channel_id;
    assert_eq!(open.extranonce_prefix.inner_as_ref().len(), 8);

    // A SetTarget may come first (a channel opened before the first template
    // gets the block target as soon as its first job is built).
    let (mut t, mut chan_bit, mut p) = c.recv().await;
    if t == MESSAGE_TYPE_SET_TARGET {
        assert!(chan_bit);
        (t, chan_bit, p) = c.recv().await;
    }
    assert_eq!((t, chan_bit), (MESSAGE_TYPE_NEW_MINING_JOB, true));
    let job: NewMiningJob = binary_sv2::from_bytes(&mut p).unwrap();
    assert!(job.min_ntime.clone().into_inner().is_none(), "a future job, activated by SetNewPrevHash");
    let mut p = c.recv_type(MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH).await;
    let prev: SetNewPrevHash = binary_sv2::from_bytes(&mut p).unwrap();
    assert_eq!((prev.channel_id, prev.job_id), (channel_id, job.job_id));

    // Mine the job as a standard-channel device: header-only, rolled version.
    let version = job.version | 0x0000_4000;
    let h = header(version, prev.prev_hash.inner_as_ref().try_into().unwrap(),
                   job.merkle_root.inner_as_ref().try_into().unwrap(), prev.min_ntime, prev.nbits, 0);
    let nonce = solve(&h, prev.nbits);
    c.send(SubmitSharesStandard { channel_id, sequence_number: 1, job_id: job.job_id, nonce, ntime: prev.min_ntime, version },
           MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true).await;
    let (t, _, mut p) = c.recv().await;
    if t == MESSAGE_TYPE_SUBMIT_SHARES_ERROR {
        let mut q = p.clone();
        let e: SubmitSharesError = binary_sv2::from_bytes(&mut q).unwrap();
        panic!("share refused: {}", String::from_utf8_lossy(e.error_code.inner_as_ref()));
    }
    assert_eq!(t, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, "share accepted");
    let s: SubmitSharesSuccess = binary_sv2::from_bytes(&mut p).unwrap();
    assert_eq!((s.channel_id, s.last_sequence_number), (channel_id, 1));

    let mut h1 = h;
    h1[76..80].copy_from_slice(&nonce.to_le_bytes());
    let id = gnb_smh::sha256d::block_id(&h1);
    assert_eq!(sel_tip(&n), Some(id), "the node accepted the SV2 block");
    let b = n.store.get_block(&id).unwrap().unwrap();
    assert_eq!((b.height, b.header.version), (1, version));
    assert_eq!(b.transactions[0].outputs[0].script_pubkey, vec![0x66; 20]);

    // The same share again: duplicate. Then the new tip's job arrives.
    c.send(SubmitSharesStandard { channel_id, sequence_number: 2, job_id: job.job_id, nonce, ntime: prev.min_ntime, version },
           MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true).await;
    let mut seen_error = false;
    let mut next_prev = None;
    for _ in 0..8 {
        let (t, _, mut p) = c.recv().await;
        if t == MESSAGE_TYPE_SUBMIT_SHARES_ERROR {
            let e: SubmitSharesError = binary_sv2::from_bytes(&mut p).unwrap();
            assert!(matches!(e.error_code.inner_as_ref(), b"duplicate-share" | b"invalid-job-id"), "{:?}", e.error_code);
            seen_error = true;
        } else if t == MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH {
            let s: SetNewPrevHash = binary_sv2::from_bytes(&mut p).unwrap();
            next_prev = Some(<[u8; 32]>::try_from(s.prev_hash.inner_as_ref()).unwrap());
        }
        if seen_error && next_prev.is_some() {
            break;
        }
    }
    assert!(seen_error, "the repeated share is refused");
    assert_eq!(next_prev, Some(gnb_smh::sha256d::parents_commitment(&[id])), "the next job builds on the new tip");

    // A wrong key pin: the handshake fails on the client side.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut wrong = noise_sv2::Initiator::from_raw_k(AuthorityKeypair::generate().public).unwrap();
    stream.write_all(&wrong.step_0().unwrap()).await.unwrap();
    let mut act2 = [0u8; noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
    stream.read_exact(&mut act2).await.unwrap();
    assert!(wrong.step_2(act2).is_err(), "a client that pinned another key refuses the server");
}

// ── 4. Stall relief: one job per 60-second step ──────────────────────────────

#[test]
fn stall_relief_steps_change_the_job_bits() {
    let n = regtest_node();
    let params = params();
    let now = unix_now();
    // A late template whose ASERT bits are far from the pow limit (so the
    // relief is visible, not clamped): parents 1,000 s old.
    let mut t = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    t.bits = 0x1c00_ffff;
    t.parent_timestamp = now - 1_000;
    let t = Arc::new(t);
    let b0 = stratum::jobs::bits_at(&t, now);
    let b1 = stratum::jobs::bits_at(&t, now + 60);
    assert_ne!(b0, b1, "the next 60-second step relaxes the bits");
    // late = time - parent - 180 s; a step is 60 s of lateness.
    let step_start = now - ((now - (t.parent_timestamp + 180)) % 60);
    assert_eq!(stratum::jobs::bits_at(&t, step_start), stratum::jobs::bits_at(&t, step_start + 59), "constant within a step");
    assert_eq!(stratum::jobs::bits_at(&t, step_start), b0);

    let spk = vec![0x42; 20];
    let job = Job::build(t.clone(), &params, &spk, [0; 8], now).unwrap();
    assert_eq!(job.bits, b0);
    // Same step: fine. The next step: refused (take the new job).
    assert!(job.solve(&[0; 8], job.version, step_start as u32, 0).is_ok());
    let e = job.solve(&[0; 8], job.version, (step_start + 60) as u32, 0).unwrap_err();
    assert!(matches!(e, stratum::jobs::SolveError::BitsChanged { .. }), "{e}");

    // The work feed's check: due exactly when the bits for "now" differ.
    let w = work::Work { seq: 1, template: t.clone(), clean: true, reason: work::WorkReason::Start, bits: b0 };
    assert_eq!(work::stall_step_due(&w, now), None);
    assert_eq!(work::stall_step_due(&w, now + 60), Some(b1));
}
