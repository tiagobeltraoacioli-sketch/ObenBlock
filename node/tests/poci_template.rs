//! `getblocktemplate` on a PoCI chain (ObenBlock regtest; re-review
//! findings of 2026-10-18): the template's PoWit section in the block's own
//! wire format (`BodyFormat::at`: the PoCI evidence list and the tagged
//! membership list of exits and rejoins), the bytes a pool carries into its
//! block and the coinbase body commitment hashes; and the template's byte
//! budget measured in that same format.
//!
//! One chain built through the real acceptance pipeline: ten witnesses mine
//! (one share per key per epoch), keys 0..=8 vote every slot and key 9
//! never does, so the handoff to epoch 8 prunes it (§4.1). In epoch 9 the
//! node's PoWit pool holds an exit (key 8), a rejoin (key 9) and PoCI
//! evidence (key 7). The template carries all three; a header job and a
//! block a pool builds itself from the template's fields are both accepted.
//!
//! The chain id and the PoWit pool are process-wide: this binary runs one
//! test, on ObenBlock regtest only.

mod fix_common;
use fix_common::*;

use std::sync::atomic::AtomicBool;

use gnb::consensus::BlockHash;
use gnb::core::kes::KesSigner;
use gnb::core::pow_scheme::{self, OBB_BLOCK_VERSION};
use gnb::core::powit::poci::{PociEvidence, OBB_REGTEST_POCI as PP};
use gnb::core::powit::{Attestation, BodyFormat, ChainView, Checkpoint, KeyId, PowitBody, PowitState, WitnessExit,
                       WitnessRejoin};
use gnb::core::{self, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::mining::sha256d as job;
use gnb::pow;
use gnb::powit::{self, DagChainView};
use gnb::template;

const EL: u64 = PP.epoch_len;
const IV: u64 = PP.checkpoint_interval;
const N: usize = 10;
/// Key 9 never votes: pruned at the handoff to 8.
const QUIET: usize = 9;

struct Witness {
    signer: KesSigner,
    id: KeyId,
}

impl Witness {
    fn evolved(&mut self, epoch: u64) -> &KesSigner {
        if epoch > self.signer.epoch() {
            self.signer.evolve_to(epoch).unwrap();
        }
        &self.signer
    }

    fn vote(&mut self, config_id: &[u8; 32], source: Checkpoint, target: Checkpoint) -> Attestation {
        let s = self.evolved(PP.epoch_of(target.height));
        Attestation::sign_v3(PP.chain_id, config_id, source, target, s).unwrap()
    }
}

fn state(n: &Node, h: &BlockHash) -> PowitState {
    powit::load_state(&n.store, h).expect("PoWit state")
}

/// One block on `parent`: the share of the key whose turn it is, and the
/// votes of keys `0..QUIET` for the open slot.
fn build(n: &Node, parent: BlockHash, ws: &mut [Witness]) -> Block {
    let (height, pts) = {
        let d = n.dag.read();
        let pd = d.get_block_data(&parent).expect("parent known");
        (pd.height + 1, pd.timestamp)
    };
    let mut shares = Vec::new();
    if let Some(i) = (0..N).find(|&i| height % EL == 2 + i as u64) {
        let pb = n.store.get_block(&parent).unwrap().expect("parent body");
        let stop = AtomicBool::new(false);
        shares.push(powit::mine_share(&pb, parent, ws[i].id, &[0x51; 20], height << 16, 1 << 20, &stop)
            .expect("a share at the regtest target"));
    }
    let mut atts = Vec::new();
    let st = powit::load_state(&n.store, &parent).unwrap_or_else(|| PowitState::genesis(0, parent));
    if let Some(cfg) = st.poci_config() {
        let slot = height / IV * IV;
        if slot > st.justified.height {
            let hash = {
                let d = n.dag.read();
                DagChainView { dag: &d, start: Some(parent) }.selected_at(slot).expect("slot on chain")
            };
            let target = Checkpoint { height: slot, hash };
            let cid = cfg.id();
            for w in ws[..QUIET].iter_mut() {
                let voted = st.votes.get(&target).is_some_and(|v| v.contains_key(&w.id));
                if cfg.weight(&w.id).is_some() && !voted {
                    atts.push(w.vote(&cid, st.justified, target));
                }
            }
        }
    }
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: format!("t{height}").into_bytes(),
                               sequence: u32::MAX }],
        outputs: Block::coinbase_outputs(height, vec![0xC0; 20], 0, &shares),
        locktime: 0,
    };
    let bits = pow::expected_block_bits(pts, height, pts + 1).unwrap();
    let mut b = Block {
        header: BlockHeader { version: OBB_BLOCK_VERSION, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                              timestamp: pts + 1, bits, nonce: 0 },
        transactions: vec![cb],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: PowitBody { shares, attestations: atts, ..Default::default() },
    };
    commit_block(&mut b);
    seal(&mut b);
    b
}

fn seal(b: &mut Block) {
    while !b.validate_pow() {
        b.header.nonce += 1;
    }
}

/// Synthetic unsigned spends (the template is built without script
/// checks): more than one block of them.
fn fill_mempool(n: &Node, height: u64) {
    for i in 0..4_000u32 {
        let mut prev = [0u8; 32];
        prev[..4].copy_from_slice(&i.to_le_bytes());
        prev[31] = 0xBD;
        n.store.put_utxo(&prev, 0, &out(1_000_000, &[0x55; 20])).unwrap();
        let fee = 50_000 + i as u64;
        let tx = Transaction {
            version: core::sighash::tx_version_for_height(height, core::activation::hardening_activation_height()),
            inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![0xA6; 250 + (i % 7) as usize],
                                   sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 1_000_000 - fee, script_pubkey: vec![0x13; 20] }],
            locktime: 0,
        };
        n.mempool.add(tx, fee).unwrap();
    }
}

#[test]
fn templates_carry_poci_items_in_the_block_format() {
    let _ = core::set_node_chain_id(ChainId::ObenBlockRegtest);
    assert_eq!(core::node_chain_id(), ChainId::ObenBlockRegtest, "one chain id per test binary");
    let params = pow_scheme::node_sha256d_params().expect("ObenBlock mines SHA-256d");
    let mut ws: Vec<Witness> = (0..N).map(|i| {
        let signer = KesSigner::generate(5, [0x70 + i as u8; 32], |_| {}).unwrap();
        Witness { id: signer.public().witness_id(), signer }
    }).collect();
    let genesis = mk_genesis(unix_now() - 40_000);
    let n = node_with(&genesis, &[]);
    let mut tip = genesis.block_hash();
    let in_9 = |n: &Node, tip: &BlockHash| powit::load_state(&n.store, tip)
        .is_some_and(|s| s.poci_config().is_some_and(|c| c.epoch() >= 9));
    while !in_9(&n, &tip) {
        let b = build(&n, tip, &mut ws);
        tip = accept(&n, &b).unwrap_or_else(|e| panic!("h={}: {e}", b.height));
    }
    let st = state(&n, &tip);
    let height = n.dag.read().get_block_data(&tip).unwrap().height + 1;
    let epoch = PP.epoch_of(height);
    assert_eq!(epoch, 9);
    let ps = st.poci.as_ref().unwrap();
    assert_eq!(ps.pruned.get(&ws[QUIET].id).map(|p| p.start), Some(8), "the quiet key is pruned at 8");
    let cfg = ps.config().clone();

    // The pool: an exit (key 8), a rejoin (the pruned key 9) and PoCI
    // evidence (key 7: two votes for one slot under the configuration in
    // force), each admitted as the next block will check it.
    let exit = WitnessExit::sign(PP.chain_id, ws[8].evolved(epoch)).unwrap();
    let rejoin = WitnessRejoin::sign(PP.chain_id, ws[QUIET].evolved(epoch)).unwrap();
    let slot = st.justified.height + IV;
    let (ta, tb) = (Checkpoint { height: slot, hash: [0xE1; 32] }, Checkpoint { height: slot, hash: [0xE2; 32] });
    let ev = PociEvidence { config_id: cfg.id(), a: ws[7].vote(&cfg.id(), st.justified, ta),
                            b: ws[7].vote(&cfg.id(), st.justified, tb) };
    {
        let d = n.dag.read();
        powit::pool().admit_exit(exit.clone(), &d, &n.store).expect("exit admitted");
        powit::pool().admit_rejoin(rejoin.clone(), &d, &n.store).expect("rejoin admitted");
        powit::pool().admit_poci_evidence(ev.clone(), &d, &n.store).expect("evidence admitted");
    }
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE)
        .unwrap();
    assert_eq!(tmpl.height, height);
    assert_eq!((tmpl.powit.exits.as_slice(), tmpl.powit.rejoins.as_slice(), tmpl.powit.poci_evidence.as_slice()),
               (std::slice::from_ref(&exit), std::slice::from_ref(&rejoin), std::slice::from_ref(&ev)));

    // ── Finding 1: `powit` is the section in the block's format ──────────
    let wire = tmpl.powit_wire();
    let fmt = BodyFormat::at(height);
    assert!(fmt.poci && fmt.exits);
    let mut expect = Vec::new();
    tmpl.powit.write_wire_for(&mut expect, fmt);
    assert_eq!(wire, expect);
    let decoded = PowitBody::read_wire_for(&mut std::io::Cursor::new(&wire[..]), fmt).expect("decodes as the block's");
    assert_eq!(decoded, tmpl.powit, "round trip with the PoCI evidence, the exit and the rejoin");
    // The pre-fix encoding (`write_wire_with`) drops the PoCI evidence and the
    // rejoin and has no membership tags: what a pool rebuilt from it does
    // not carry the template's section.
    let mut old = Vec::new();
    tmpl.powit.write_wire_with(&mut old, true);
    assert_ne!(old, wire);
    match PowitBody::read_wire_for(&mut std::io::Cursor::new(&old[..]), fmt) {
        Ok(b) => assert_ne!(b.root_for(fmt), tmpl.powit.root_for(fmt)),
        Err(_) => {}
    }

    // ── Finding 2: the byte budget counts the section as the block has it ─
    // Built before the items are mined (they stay valid in the pool).
    fill_mempool(&n, height);
    let full = template::build_block_template_with(&n.dag, &n.store, &n.mempool, &template::TemplateOptions {
        coinbase_reserve: template::EXTERNAL_COINBASE_RESERVE, verify_scripts: false,
    }).unwrap();
    assert!(full.transactions.len() < 4_000, "the mempool holds more than one block");
    assert_eq!(full.powit.rejoins.len() + full.powit.exits.len() + full.powit.poci_evidence.len(), 3);
    let fb = template::assemble_block(&full, full.miner_coinbase(vec![0x5A; 20]), full.parent_timestamp + 1)
        .expect("a full template with PoCI items assembles within the size limit");
    let size = fb.to_wire_bytes().len();
    assert!(size <= core::MAX_BLOCK_SIZE);
    assert!(wire.len() > old.len(), "the PoCI items the pre-fix measure left out");
    // At the edge: the bytes left are fewer than the pre-fix measure left out,
    // so a budget from `write_wire_with` overfills the block and
    // `assemble_block` refuses it.
    assert!(core::MAX_BLOCK_SIZE - size < wire.len() - old.len(),
            "slack {} vs undercount {}", core::MAX_BLOCK_SIZE - size, wire.len() - old.len());

    // ── Header job: the node's own block from the template ───────────────
    let now = tmpl.parent_timestamp + 1;
    let hj = job::header_job(&tmpl, &params, &[0x5A; 20], [1, 2, 3, 4, 5, 6, 7, 8], now).expect("header job");
    let mut b1 = hj.block.clone();
    assert_eq!(b1.powit, tmpl.powit);
    seal(&mut b1);
    let h1 = accept(&n, &b1).expect("the header-job block is accepted");
    let s1 = state(&n, &h1);
    let p1 = s1.poci.as_ref().unwrap();
    assert!(s1.exited.contains_key(&ws[8].id));
    assert!(p1.rejoins.contains_key(&ws[QUIET].id));
    assert_eq!(p1.bans[&ws[7].id][0].start, None, "pending until a handoff");

    // ── A pool's own coinbase from the template's fields ─────────────────
    // `coinbase_script_sig_prefix ‖ miner bytes`, `coinbase_outputs` with the
    // pool's script first, the listed transactions (none), the `powit` hex
    // decoded as the block's section, the root from `coinbase_merkle_branch`.
    let prefix = tmpl.coinbase_commitment().expect("hardened");
    let mut script_sig = prefix.to_vec();
    script_sig.extend_from_slice(b"/pool/");
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
        outputs: tmpl.coinbase_outputs(vec![0x77; 20]),
        locktime: 0,
    };
    let powit = PowitBody::read_wire_for(&mut std::io::Cursor::new(&wire[..]), fmt).unwrap();
    let bits = core::liveness::relieve_at(tmpl.bits, tmpl.parent_timestamp, tmpl.height, now, tmpl.activation_height,
                                          core::liveness::liveness_activation_height());
    let mut b2 = Block {
        header: BlockHeader { version: params.block_version, parents: tmpl.parents.clone(),
                              merkle_root: job::header_merkle_root(&tmpl, &cb.txid()).unwrap(), timestamp: now, bits,
                              nonce: 0 },
        transactions: vec![cb],
        blue_score: tmpl.blue_score,
        height: tmpl.height,
        shielded_transactions: Vec::new(),
        powit,
    };
    seal(&mut b2);
    // The block's wire encoding carries the template's `powit` bytes as listed.
    let bytes = b2.to_wire_bytes();
    assert!(bytes.windows(wire.len()).any(|w| w == wire.as_slice()));
    let back = Block::from_wire_bytes(&bytes).unwrap();
    assert_eq!(back.powit, tmpl.powit);
    let h2 = accept(&n, &back).expect("the pool-built block is accepted");
    assert_ne!(h1, h2, "two siblings on the same parent");
    assert_eq!(state(&n, &h2).poci, s1.poci, "the same PoCI items on both");
}
