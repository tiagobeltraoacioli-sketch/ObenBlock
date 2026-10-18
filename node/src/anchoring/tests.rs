use super::*;
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn h(i: u64) -> Hash {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&i.to_le_bytes());
    x[31] = 1;
    x
}

/// A fork's block `i` (distinct from the main chain's).
fn f(i: u64) -> Hash {
    let mut x = h(i);
    x[30] = 0xF0;
    x
}

fn mk_store() -> (TempDir, Storage) {
    let tmp = TempDir::new().unwrap();
    let s = Storage::open(&tmp.path().join("db")).unwrap();
    (tmp, s)
}

/// The chain h(0) (genesis) .. h(n), DAG heights 0..=n.
fn chain(n: u64) -> GhostDAG {
    let mut dag = GhostDAG::with_k_and_activation(10, u64::MAX);
    dag.add_genesis(h(0), 0);
    for i in 1..=n {
        dag.add_block(h(i), vec![h(i - 1)], i, 1_000).unwrap();
    }
    dag
}

fn cp(slot: u64) -> Checkpoint {
    // On a chain without height gaps, slot c names the block at height c - 1.
    Checkpoint { height: slot, hash: h(slot - 1) }
}

const K1: [u8; 20] = [0x11; 20];
const K2: [u8; 20] = [0x22; 20];

/// Finalized slots (mainnet params: epochs of 720, checkpoints every 60),
/// each finalized 125 blocks after its slot by the vote for slot + 60.
/// Slot 720 is skipped (epoch 1 starts at 780) and epoch 2 finalizes
/// nothing.
fn finalized_slots() -> Vec<u64> {
    let mut v: Vec<u64> = (1..=11).map(|i| i * 60).collect();
    v.extend((13..=23).map(|i| i * 60));
    v.extend([2220, 2280]);
    v
}

/// The PoWit state stored for block height `b`: the latest checkpoint whose
/// finalization height is at most `b`.
fn state_at(b: u64) -> PowitState {
    let mut st = PowitState::genesis(0, h(0));
    let mut work = BTreeMap::new();
    work.insert(0u64, BTreeMap::from([(K1, 100u128), (K2, 50u128)]));
    st.epoch_work = work;
    st.epoch = b / 720;
    for s in finalized_slots() {
        if s + 125 <= b {
            st.finalized = cp(s);
            st.finalized_at = s + 125;
            st.justified = cp(s + 60);
        }
    }
    st
}

fn fixture(top: u64) -> (TempDir, Storage, GhostDAG) {
    let dag = chain(top);
    let (tmp, store) = mk_store();
    for b in 1..=top {
        crate::powit::save_state(&store, &h(b), &state_at(b)).unwrap();
    }
    (tmp, store, dag)
}

#[test]
fn anchors_are_the_first_finalized_checkpoint_of_each_epoch() {
    let (_t, store, mut dag) = fixture(2600);
    dag.set_finalized(h(2600), 2600);
    let scan = epoch_anchors(&dag, &store, 0, 32).unwrap();
    assert!(scan.complete);
    let slots: Vec<(u64, u64)> = scan.anchors.iter().map(|a| (a.epoch, a.record.slot)).collect();
    assert_eq!(slots, vec![(0, 60), (1, 780), (3, 2220)]);
    let a = &scan.anchors[2];
    assert_eq!(a.record.block_id, h(2219));
    assert_eq!(a.record.finalized_at, 2345);
    assert_eq!(a.finalizing_block, h(2345));
    assert_eq!(a.justified, cp(2280));
    assert_eq!(a.record.chain_id, gnb_crypto::core::node_chain_id().to_u32());
    // Epoch(2280) = 3: the window (epochs 0..=1) holds K1 and K2.
    assert_eq!(a.record.w_digest, obb_anchor::w_digest(&[(K1, 100), (K2, 50)]).unwrap());
    assert_eq!((a.w_size, a.w_total), (2, 150));
    // Epoch(120) = 0: an empty window.
    assert_eq!(scan.anchors[0].record.w_digest, obb_anchor::w_digest(&[]).unwrap());
    assert_eq!(scan.anchors[0].record.finalized_at, 185);
}

#[test]
fn anchors_honour_from_epoch_count_and_the_pin() {
    let (_t, store, mut dag) = fixture(2600);
    assert!(epoch_anchors(&dag, &store, 0, 8).unwrap().anchors.is_empty(), "no pin, no anchors");
    dag.set_finalized(h(2600), 2600);
    let scan = epoch_anchors(&dag, &store, 1, 8).unwrap();
    assert_eq!(scan.anchors.iter().map(|a| a.record.slot).collect::<Vec<_>>(), vec![780, 2220]);
    assert!(scan.complete);
    let scan = epoch_anchors(&dag, &store, 0, 1).unwrap();
    assert_eq!(scan.anchors.iter().map(|a| a.record.slot).collect::<Vec<_>>(), vec![2220]);
    assert!(!scan.complete, "older anchors exist");
    // Only what the pinned block's chain finalized: pinned at 2400, slot
    // 2220's finalization (2345) is in, 2280's (2405) is not.
    let (_t2, store2, mut dag2) = fixture(2600);
    dag2.set_finalized(h(2400), 2400);
    let scan = epoch_anchors(&dag2, &store2, 3, 8).unwrap();
    assert_eq!(scan.anchors.len(), 1);
    assert_eq!(scan.anchors[0].record.slot, 2220);
    // The records are the same whichever pin built them.
    let full = epoch_anchors(&dag, &store, 3, 8).unwrap();
    assert_eq!(full.anchors[0].record, scan.anchors[0].record);
}

#[test]
fn the_read_budget_bounds_a_scan() {
    let (_t, store, mut dag) = fixture(2600);
    dag.set_finalized(h(2600), 2600);
    // Top, 2405's parent, 2345's parent, the 2220 record: then out of reads.
    let scan = epoch_anchors_within(&dag, &store, 0, 32, 4).unwrap();
    assert!(!scan.complete);
    assert_eq!(scan.anchors.iter().map(|a| a.record.slot).collect::<Vec<_>>(), vec![2220]);
    assert!(epoch_anchors_within(&dag, &store, 0, 32, MAX_STATE_READS).unwrap().complete);
}

fn rec(slot: u64, block: Hash) -> AnchorRecord {
    AnchorRecord {
        chain_id: gnb_crypto::core::node_chain_id().to_u32(),
        slot,
        block_id: block,
        finalized_at: slot + 125,
        w_digest: [3; 32],
    }
}

/// The main chain to `n` and a heavier fork off `from` to height `to`.
fn forked(n: u64, from: u64, to: u64) -> GhostDAG {
    let mut dag = chain(n);
    let mut prev = h(from);
    for i in from + 1..=to {
        dag.add_block(f(i), vec![prev], 10_000 + i, 5_000).unwrap();
        prev = f(i);
    }
    dag
}

#[test]
fn an_anchor_below_own_finality_is_checked_not_applied() {
    let mut dag = chain(100);
    dag.set_finalized(h(90), 90);
    assert_eq!(decide(&dag, &rec(60, h(59))), (Verdict::Consistent, Action::None));
    let (v, a) = decide(&dag, &rec(60, h(58)));
    assert!(matches!(v, Verdict::Conflict(_)) && a == Action::None);
    let (v, _) = decide(&dag, &rec(60, f(59)));
    assert!(matches!(v, Verdict::Conflict(_)), "an unknown block where own finality names another");
}

#[test]
fn a_known_anchor_ahead_of_finality_is_pinned_unless_it_leaves_it() {
    let mut dag = forked(100, 30, 120);
    assert_eq!(dag.selected_tip(), Some(f(120)), "the fork is heavier");
    dag.set_finalized(h(20), 20);
    assert_eq!(decide(&dag, &rec(60, h(59))), (Verdict::Pinned, Action::Pin(h(59))));
    let (v, a) = decide(&dag, &rec(60, f(59)));
    assert_eq!((v, a), (Verdict::Pinned, Action::Pin(f(59))), "the fork descends from h(20) too");
    dag.set_finalized(h(40), 40);
    let (v, a) = decide(&dag, &rec(60, f(59)));
    assert!(matches!(v, Verdict::Conflict(_)) && a == Action::None, "it leaves the node's finality");
    let (v, _) = decide(&dag, &rec(50, h(59)));
    assert!(matches!(v, Verdict::Conflict(_)), "a block above its slot");
}

struct DagOps<'a> {
    dag: &'a RwLock<GhostDAG>,
    calls: Mutex<Vec<Action>>,
}

impl ChainOps for DagOps<'_> {
    fn pin(&self, hash: Hash) -> Result<(), String> {
        self.calls.lock().push(Action::Pin(hash));
        let height = self.dag.read().get_block_data(&hash).unwrap().height;
        self.dag.write().set_finalized(hash, height);
        Ok(())
    }
    fn refuse(&self, hash: Hash) -> Result<(), String> {
        self.calls.lock().push(Action::Refuse(hash));
        self.dag.write().mark_invalid(hash);
        Ok(())
    }
}

#[test]
fn pinning_moves_fork_choice_off_a_contradicting_chain() {
    let dag = RwLock::new(forked(100, 30, 120));
    let ops = DagOps { dag: &dag, calls: Mutex::new(Vec::new()) };
    assert_eq!(enforce(&dag, &ops, &rec(60, h(59))), Verdict::Pinned);
    assert_eq!(dag.read().selected_tip(), Some(h(100)));
    assert_eq!(enforce(&dag, &ops, &rec(60, h(59))), Verdict::Pinned, "idempotent");
    assert_eq!(ops.calls.lock().len(), 1);
}

#[test]
fn an_unknown_anchor_refuses_chains_that_passed_its_slot() {
    // Only the fork is known past height 30; the anchored block is not.
    let mut d = chain(30);
    let mut prev = h(30);
    for i in 31..=120 {
        d.add_block(f(i), vec![prev], i, 1_000).unwrap();
        prev = f(i);
    }
    let dag = RwLock::new(d);
    let ops = DagOps { dag: &dag, calls: Mutex::new(Vec::new()) };
    let anchor = rec(60, h(59));
    assert_eq!(enforce(&dag, &ops, &anchor), Verdict::Pending);
    assert_eq!(*ops.calls.lock(), vec![Action::Refuse(f(60))], "the fork's first block past the slot");
    assert_eq!(dag.read().selected_tip(), Some(f(59)));
    // A chain still below the slot is left alone.
    assert_eq!(decide(&dag.read(), &anchor), (Verdict::Pending, Action::None));
    // The honest block arrives: the next enforcement pins it.
    {
        let mut w = dag.write();
        let mut prev = h(30);
        for i in 31..=70 {
            w.add_block(h(i), vec![prev], i, 1_000).unwrap();
            prev = h(i);
        }
    }
    assert_eq!(enforce(&dag, &ops, &anchor), Verdict::Pinned);
    assert_eq!(dag.read().selected_tip(), Some(h(70)));
}

#[test]
fn fresh_anchors_only_move_forward() {
    let (_t, store) = mk_store();
    let a = rec(720, h(719));
    assert_eq!(accept_fresh(&store, None, a), (Some(a), None));
    assert_eq!(load_latest(&store), Some(a));
    let newer = rec(1440, h(1439));
    assert_eq!(accept_fresh(&store, Some(a), newer), (Some(newer), None));
    assert_eq!(load_latest(&store), Some(newer));
    let (kept, alarm) = accept_fresh(&store, Some(newer), a);
    assert_eq!(kept, Some(newer));
    assert!(alarm.unwrap().contains("older"));
    let (kept, alarm) = accept_fresh(&store, Some(newer), rec(1440, h(1438)));
    assert_eq!(kept, Some(newer));
    assert!(alarm.is_some(), "other bytes for the same slot");
    assert_eq!(load_latest(&store), Some(newer));
}

#[test]
fn registry_entries_are_parsed_strictly() {
    let cid = gnb_crypto::core::node_chain_id().to_u32();
    let r = rec(720, h(719));
    let mut good = record_json(&r);
    good["bloch"] = json!({ "height": 123, "tx": "ab", "finalized": true });
    assert_eq!(parse_registry_entry(&good, cid).unwrap(), Some(r));
    assert_eq!(parse_registry_entry(&Value::Null, cid).unwrap(), None);
    let minimal = json!({ "record": hex::encode(r.encode()), "bloch": { "finalized": true } });
    assert_eq!(parse_registry_entry(&minimal, cid).unwrap(), Some(r));
    assert!(parse_registry_entry(&good, cid ^ 1).is_err(), "another chain");
    let mut v = good.clone();
    v["bloch"]["finalized"] = false.into();
    assert!(parse_registry_entry(&v, cid).is_err(), "not final on Bloch");
    let mut v = good.clone();
    v["slot"] = 721.into();
    assert!(parse_registry_entry(&v, cid).is_err(), "fields disagree");
    let mut v = good.clone();
    v["record"] = hex::encode(&r.encode()[..83]).into();
    assert!(parse_registry_entry(&v, cid).is_err());
    let mut v = good;
    v["record"] = "zz".repeat(84).into();
    assert!(parse_registry_entry(&v, cid).is_err());
}

/// The reader against a one-shot HTTP server speaking the registry's
/// JSON-RPC interface.
#[tokio::test]
async fn the_bloch_reader_speaks_the_registry_interface() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let r = rec(720, h(719));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut entry = record_json(&r);
    entry["bloch"] = json!({ "finalized": true });
    let body = json!({ "jsonrpc": "2.0", "id": 1, "result": entry }).to_string();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = sock.read(&mut buf).await.unwrap();
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req);
            if let Some(end) = text.find("\r\n\r\n") {
                let len = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                if req.len() >= end + 4 + len {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                            connection: close\r\n\r\n{}", body.len(), body);
        sock.write_all(resp.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&req).to_string()
    });
    let reader = BlochRpcReader::new(&format!("http://{addr}/registry"), Duration::from_secs(5)).unwrap();
    assert_eq!(reader.latest(r.chain_id).await.unwrap(), Some(r));
    let req = server.await.unwrap();
    assert!(req.starts_with("POST /registry "));
    assert!(req.contains("\"method\":\"obbanchor_latest\""));
    assert!(req.contains(&format!("\"params\":[{}]", r.chain_id)));
    assert!(BlochRpcReader::new("ftp://x", Duration::from_secs(1)).is_err());
}

#[test]
fn a_poll_takes_persists_and_enforces_the_answer() {
    let (_t, store) = mk_store();
    let dag = Arc::new(RwLock::new(forked(100, 30, 120)));
    let ops = DagOps { dag: &dag, calls: Mutex::new(Vec::new()) };
    let r = rec(60, h(59));
    let mock = MockReader::new(Ok(Some(r)));
    let res = futures::executor::block_on(mock.latest(r.chain_id));
    take_answer(res, "mock", &dag, &store, &ops);
    assert_eq!(dag.read().selected_tip(), Some(h(100)));
    assert_eq!(load_latest(&store), Some(r));
    let s = status_json();
    assert_eq!(s["status"], "pinned");
    assert_eq!(s["anchor"]["slot"], 60);
    // Bloch unreachable: the held anchor stays in force.
    take_answer(Err("down".into()), "mock", &dag, &store, &ops);
    assert_eq!(status_json()["last_error"], "down");
    assert_eq!(load_latest(&store), Some(r));
}
