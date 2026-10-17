//! Phase-4 package R4 (B2-T0) on the PoWit line: a block's in-context PoWit
//! state (`powit::block_state`, computed before the block is stored) is
//! committed in the SAME batch as its DAG record — the first chunk of the
//! chain move the block triggers, or its fork-loser record — so a block is
//! never recorded without the state its children build on, a refused commit
//! leaves no state behind, and a chunked move interrupted by a crash resumes
//! on blocks whose states are all on disk.
//!
//! This binary activates PoWit at height 3 (`core::set_powit_height_override`,
//! once per process): every block from there on goes through the PoWit path
//! of the REAL acceptance pipeline (empty PoWit section, coinbase split by
//! `Block::coinbase_outputs`), with the proof of work marked verified
//! (`Block::test_only_assume_pow_valid`, dev-only `test-pow-limit`).

mod fix_common;
use fix_common::*;

use gnb::accept;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput};
use gnb::pow;
use gnb::powit;
use gnb::reorg;

const ACTIVATION: u64 = 3;

fn activate() {
    let _ = core::set_powit_height_override(ACTIVATION);
    assert_eq!(core::powit_height(), ACTIVATION, "one PoWit activation height per test binary");
}

struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    /// A chain of `n` empty blocks on `from`, PoWit-valid from the activation
    /// (empty section, the miner's part of the subsidy).
    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let pd = self.dag.get_block_data(&p).expect("parent built").clone();
            let height = pd.height + 1;
            let bits = pow::expected_bits(pd.timestamp, height).unwrap();
            let cb = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32], prev_index: u32::MAX,
                    script_sig: format!("{tag}{i}").into_bytes(), sequence: u32::MAX,
                }],
                outputs: Block::coinbase_outputs(height, vec![0xC0; 20], 0, &[]),
                locktime: 0,
            };
            let mut b = Block {
                header: BlockHeader {
                    version: 1, parents: vec![p], merkle_root: MerkleRoot::ZERO,
                    timestamp: pd.timestamp + 1, bits, nonce: 0,
                },
                transactions: vec![cb],
                blue_score: height,
                height,
                shielded_transactions: Vec::new(),
                powit: Default::default(),
            };
            commit_block(&mut b);
            b.test_only_assume_pow_valid();
            self.dag.add_block(b.block_hash(), vec![p], b.header.timestamp, pow::block_work(bits, height))
                .expect("builder DAG accepts the block");
            p = b.block_hash();
            out.push(b);
        }
        out
    }
}

fn has_state(n: &Node, h: &BlockHash) -> bool {
    powit::load_state(&n.store, h).is_some()
}

/// Every block at or above the activation is recorded with its PoWit state,
/// whether it extends the applied chain (the chunk that connects it) or is a
/// fork-loser (its own record); both survive a restart, and blocks below the
/// activation have none.
#[test]
fn powit_state_lands_with_the_dag_record() {
    activate();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let main = b.chain(gh, 8, "m");
    let side = b.chain(main[3].block_hash(), 2, "s");

    let mut n = node_with(&genesis, &[]);
    for blk in main.iter().chain(&side) {
        accept(&n, blk).unwrap_or_else(|e| panic!("block h={} refused: {e}", blk.height));
    }
    assert_eq!(applied_tip(&n), Some(main[7].block_hash()));
    restart(&mut n);
    for blk in main.iter().chain(&side) {
        let h = blk.block_hash();
        assert!(n.dag.read().has_block(&h));
        assert_eq!(has_state(&n, &h), blk.height >= ACTIVATION, "h={}", blk.height);
    }
}

/// A block whose first commit fails (here: a storage failure injected before
/// the chunk that connects it is written) is refused and leaves nothing
/// behind: no DAG record, no body, and — now that the state is staged in that
/// batch — no orphan PoWit state either. Delivered again it is recorded with
/// its state, and its child, whose own state builds on it, connects.
#[test]
fn a_refused_commit_leaves_no_powit_state_behind() {
    activate();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let chain = b.chain(gh, 6, "r");
    let n = node_with(&genesis, &[]);
    for blk in &chain[..4] {
        accept(&n, blk).expect("connects");
    }

    let h4 = chain[4].block_hash();
    reorg::fault_injection::fail_after_commits(Some(0));
    let refused = accept(&n, &chain[4]);
    reorg::fault_injection::fail_after_commits(None);
    assert!(refused.is_err(), "the commit failed");
    assert!(!n.dag.read().has_block(&h4));
    assert!(!n.store.has_block_body(&h4).unwrap());
    assert!(!has_state(&n, &h4), "no PoWit state outlives the refused commit");

    accept(&n, &chain[4]).expect("delivered again, it connects");
    assert!(has_state(&n, &h4));
    accept(&n, &chain[5]).expect("its child builds on its committed state");
    assert_eq!(applied_tip(&n), Some(chain[5].block_hash()));
}

/// A chunked reorg onto a PoWit branch interrupted by a crash after two
/// commits: every block of the new branch was recorded with its state (the
/// fork-losers with their own records, the block that triggered the move
/// with the move's first chunk), so start-up resumes the move and the node
/// keeps extending the branch: a new block's state is computed from its
/// selected parent's stored one.
#[test]
fn a_chunked_powit_reorg_resumes_after_a_crash() {
    activate();
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 20, "a");
    let fork = b.chain(gh, 24, "b");
    let more = b.chain(fork[23].block_hash(), 1, "c");

    let mut n = node_with(&genesis, &[]);
    for blk in &a {
        accept(&n, blk).expect("A connects");
    }
    let a_tip = a[19].block_hash();
    for blk in &fork[..19] {
        accept(&n, blk).expect("B's first blocks are fork-losers");
    }
    assert_eq!(applied_tip(&n), Some(a_tip));

    // Two commits: the rollback of A's 4 tip-most blocks, then the last 16
    // rollbacks together with B's first 16 blocks (one batch, review of PR
    // #15, finding 5: a reorg never commits its whole rollback alone); the
    // next apply chunk "crashes".
    reorg::fault_injection::fail_after_commits(Some(2));
    let mut trigger = None;
    for blk in &fork[19..] {
        if applied_tip(&n) != Some(a_tip) {
            break;
        }
        let _ = accept(&n, blk);
        trigger = Some(blk.block_hash());
    }
    reorg::fault_injection::fail_after_commits(None);
    let trigger = trigger.unwrap();
    assert_eq!(applied_tip(&n), Some(fork[15].block_hash()), "stopped after the first apply chunk");
    assert!(has_state(&n, &trigger), "the trigger's state was committed with the first chunk");

    restart(&mut n);
    let target = n.dag.read().selected_tip().unwrap();
    assert_eq!(applied_tip(&n), Some(target), "start-up resumed the move");
    for blk in fork.iter().filter(|x| n.dag.read().has_block(&x.block_hash())) {
        assert_eq!(has_state(&n, &blk.block_hash()), blk.height >= ACTIVATION, "h={}", blk.height);
    }
    for blk in fork.iter().chain(&more) {
        if !n.dag.read().has_block(&blk.block_hash()) {
            accept(&n, blk).expect("later blocks build on the stored states");
        }
    }
    assert_eq!(applied_tip(&n), Some(more[0].block_hash()));
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());
}
