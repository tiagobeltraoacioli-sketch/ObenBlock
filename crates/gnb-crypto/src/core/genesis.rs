//! The genesis block of each chain, and the rules ObenBlock applies from it
//! (docs/DESIGN-obenblock.md §3).
//!
//! GnB keeps its genesis (`super::genesis_block`, the constants
//! `super::GENESIS_*`), shared by its mainnet and testnet. ObenBlock has one
//! genesis per network, built here ([`chain_genesis`]):
//!
//! * **Header**: SHA-256d proof of work over the 80-byte header
//!   (`super::pow_scheme`), version [`OBB_BLOCK_VERSION`] (BIP 320 bits may
//!   be rolled), no parents, a `u32` timestamp and nonce. The header `bits`
//!   are the network's pow limit ([`OBB_POW_LIMIT_BITS`], Bitcoin's
//!   difficulty 1; regtest [`OBB_REGTEST_POW_LIMIT_BITS`]), so the genesis is
//!   mined on a CPU in minutes. The ASERT anchor is the genesis block (its
//!   height and timestamp) with the launch bits [`OBB_LAUNCH_BITS`] (1 EH/s,
//!   §4.2 "start high"; regtest: the pow limit), so block 1 is already
//!   expected at the launch difficulty
//!   (`Sha256dParams::asert_anchor`).
//! * **Coinbase**: one input whose `script_sig` is the 80-byte coinbase
//!   commitment of height 0 (`block_rules::coinbase_commitment` with the
//!   ObenBlock body commitment, `pow_scheme::obb_body_commitment`, as every
//!   later ObenBlock coinbase starts) followed by the genesis text, which
//!   commits to the Bloch Genesis-3 snapshot (`carryover::CARRYOVER_SNAPSHOT_SHA3`),
//!   the conversion and the vesting keys (`vesting::VESTING_SPEC_SHA3`). One
//!   output of 0 to an unspendable all-zero script: the first mined subsidy
//!   is at height 1.
//! * **Header root**: Bitcoin's transaction root, as for every ObenBlock
//!   block (`pow_scheme::bitcoin_merkle_root`): with one transaction, the
//!   coinbase txid. The empty shielded and PoWit sections (with the exits
//!   list: liveness applies from height 0) are committed by the coinbase
//!   commitment's body commitment.
//! * **Ledger**: exactly GnB's genesis ledger (owner decision, §3): the same
//!   Bloch Genesis-3 snapshot, the same fixed conversion
//!   `floor(v × CARRYOVER_ALLOCATION_SAT / CARRYOVER_SOURCE_TOTAL_SAT)` to the
//!   same 20-byte key hashes (`carryover::verify_and_convert`), and the same
//!   locked team and founder tranches (`vesting::genesis_tranches`). The node
//!   writes it with the same code for both chains. The allocations are
//!   GnB's: 9.0M mined, 1.0M carry-over, 1.25M team, 1.25M founder
//!   (`tokenomics`). Nothing mined or moved on GnB exists on ObenBlock.
//!
//! The executable reference is `reference/obb_genesis.py`; it recomputes
//! every field from the constants, and `reference/obb_genesis_vectors.json`
//! pins them (`crates/gnb-crypto/tests/obb_genesis_vectors.rs`).
//!
//! # Mainnet launch (owner decision: mined at launch)
//!
//! Everything of the mainnet genesis is fixed except its timestamp, the BIP
//! 320 version bits the search rolls, and its nonce. Until the launch they are
//! the placeholders below ([`OBB_MAINNET_GENESIS_TIMESTAMP`] = 0) and a node
//! refuses to start ObenBlock mainnet ([`launch_refusal`]). At launch, run
//! [`OBB_MAINNET_GENESIS_MINE_COMMAND`] and follow
//! `docs/OBENBLOCK-GENESIS.md`.
//!
//! # Rules from height 0
//!
//! None of GnB's legacy regimes is reachable on ObenBlock:
//!
//! * both hardening activations at height 0 (`activation`; v3 transactions,
//!   sighash v3, canonical witnesses, PF-4, the conservative suite 0x0003,
//!   the H2 PoWit rules);
//! * PoWit from height 0 (`super::powit_height`, which ignores the test
//!   override on ObenBlock); the witness set is empty for the first two
//!   epochs;
//! * SHA-256d proof of work, bound to the chain id
//!   (`super::set_node_chain_id`, [`pow_scheme_for`]; a process that only
//!   selected the ObenBlock chain falls back to it too);
//! * every block's witnesses are committed (the coinbase commitment) from
//!   height 0 ([`witness_commitment_height`]);
//! * the subsidy ramps up over the first `SLOW_START_BLOCKS` blocks
//!   (`tokenomics::block_subsidy_sat`, §4.2 "slow start");
//! * minimum chain work 0 and no assumed-valid block at launch
//!   ([`OBB_MIN_CHAIN_WORK`]; the node's defaults).

use super::chain::Chain;
use super::pow_scheme::{PowScheme, Sha256dParams, OBB_BLOCK_VERSION, OBB_POW_LIMIT_BITS, OBB_REGTEST_POW_LIMIT_BITS};
#[allow(unused_imports)] // rustdoc links
use super::pow_scheme::OBB_LAUNCH_BITS;
use super::{block_rules, pow_scheme, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput};

// ── ObenBlock genesis constants ─────────────────────────────────────────────

/// Everything of the genesis text after the network name. Commits to the
/// carry-over snapshot (`carryover::CARRYOVER_SNAPSHOT_SHA3`), the
/// conversion, and the vesting keys (`vesting::VESTING_SPEC_SHA3`), exactly
/// as GnB's genesis text does (tests below).
macro_rules! obb_genesis_text {
    ($network:literal) => {
        concat!(
            "ObenBlock ", $network, " genesis: SHA-256d proof of work, PoWit finality, every rule from height 0, \
12.5M OBB cap. Carryover Bloch G3 terminal snapshot sha3 3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d \
3810744000 BLCH -> 1000000 OBB, the key hashes of GnB's genesis. \
Team 1250000 + founder 1250000 OBB locked, 1y cliff + 36 monthly, keys sha3 \
e24828c3cc6d56fe635581b8214af8733f4b060784d13bd92f2d558940d90d20."
        )
    };
}

/// Genesis text of ObenBlock mainnet (after the 80-byte coinbase commitment).
pub const OBB_MAINNET_GENESIS_TEXT: &str = obb_genesis_text!("mainnet");
/// Genesis text of ObenBlock regtest.
pub const OBB_REGTEST_GENESIS_TEXT: &str = obb_genesis_text!("regtest");

// LAUNCH PLACEHOLDER (owner decision, docs/DESIGN-obenblock.md §3: the
// mainnet genesis is mined at launch). The three values below and
// `OBB_MAINNET_GENESIS_HASH` are produced by
// `OBB_MAINNET_GENESIS_MINE_COMMAND` with the launch timestamp; until then
// the timestamp is 0 and a node refuses to start ObenBlock mainnet.
/// Unix time of the ObenBlock mainnet genesis (also the ASERT anchor time).
/// **0 = not launched (placeholder).**
pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = 0;
/// Header version of the mainnet genesis: [`OBB_BLOCK_VERSION`] plus the
/// BIP 320 bits the genesis search rolled. **Placeholder until launch.**
pub const OBB_MAINNET_GENESIS_VERSION: u32 = OBB_BLOCK_VERSION;
/// Nonce of the mainnet genesis. **Placeholder until launch.**
pub const OBB_MAINNET_GENESIS_NONCE: u64 = 0;
/// Block id of the mainnet genesis. **All zero = not launched (placeholder).**
pub const OBB_MAINNET_GENESIS_HASH: [u8; 32] = [0u8; 32];
/// Header bits of the mainnet genesis: the pow limit (difficulty 1).
pub const OBB_MAINNET_GENESIS_BITS: u32 = OBB_POW_LIMIT_BITS;

/// Unix time of the ObenBlock regtest genesis: 2026-10-18 00:00:00 UTC.
pub const OBB_REGTEST_GENESIS_TIMESTAMP: u64 = 1_792_281_600;
/// Header version of the regtest genesis.
pub const OBB_REGTEST_GENESIS_VERSION: u32 = OBB_BLOCK_VERSION;
/// Nonce of the regtest genesis (`gnb-mine-genesis --chain obenblock --regtest`).
pub const OBB_REGTEST_GENESIS_NONCE: u64 = 0;
/// Block id of the regtest genesis (raw SHA-256d digest;
/// 6918ae0c247b3c7475edd95f406b676e5fe42351c0df7c8488a51cfe0117163d in
/// Bitcoin's display order).
pub const OBB_REGTEST_GENESIS_HASH: [u8; 32] = [
    0x3d, 0x16, 0x17, 0x01, 0xfe, 0x1c, 0xa5, 0x88,
    0x84, 0x7c, 0xdf, 0xc0, 0x51, 0x23, 0xe4, 0x5f,
    0x6e, 0x67, 0x6b, 0x40, 0x5f, 0xd9, 0xed, 0x75,
    0x74, 0x3c, 0x7b, 0x24, 0x0c, 0xae, 0x18, 0x69,
];
/// Header bits of the regtest genesis: the regtest pow limit.
pub const OBB_REGTEST_GENESIS_BITS: u32 = OBB_REGTEST_POW_LIMIT_BITS;

/// The command that mines the mainnet genesis at launch (replace the
/// timestamp with the launch time, `date -u +%s`); it prints the constants
/// above to paste. `docs/OBENBLOCK-GENESIS.md` has the whole procedure.
pub const OBB_MAINNET_GENESIS_MINE_COMMAND: &str =
    "cargo run --release -p gnb --bin gnb-mine-genesis -- --chain obenblock --timestamp <launch unix time>";

/// Minimum chain work of ObenBlock mainnet at launch: 0, with no release
/// finality checkpoint and no assumed-valid block (§3). Each release sets
/// them from independent nodes (`tools/release/min_chain_work.py`); the node
/// default is `ingress::OBENBLOCK_MINIMUM_CHAIN_WORK`, which must equal it.
pub const OBB_MIN_CHAIN_WORK: u128 = 0;

// ── Per-chain genesis ───────────────────────────────────────────────────────

/// The constants that fix a chain's genesis block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainGenesis {
    pub chain_id: ChainId,
    /// Coinbase text (after the 80-byte commitment on ObenBlock).
    pub text: &'static str,
    pub version: u32,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    /// `block_hash()` of the genesis; all zero while it is a placeholder.
    pub expected_hash: [u8; 32],
}

/// The genesis constants of the network `id`. GnB mainnet and testnet share
/// one genesis (`super::genesis_block`).
pub const fn chain_genesis(id: ChainId) -> ChainGenesis {
    match id {
        ChainId::Mainnet | ChainId::Testnet => ChainGenesis {
            chain_id: id,
            text: super::GENESIS_COINBASE_TEXT,
            version: 1,
            timestamp: super::GENESIS_TIMESTAMP,
            bits: super::GENESIS_BITS,
            nonce: super::GENESIS_NONCE,
            expected_hash: super::GENESIS_EXPECTED_HASH,
        },
        ChainId::ObenBlockMainnet => ChainGenesis {
            chain_id: id,
            text: OBB_MAINNET_GENESIS_TEXT,
            version: OBB_MAINNET_GENESIS_VERSION,
            timestamp: OBB_MAINNET_GENESIS_TIMESTAMP,
            bits: OBB_MAINNET_GENESIS_BITS,
            nonce: OBB_MAINNET_GENESIS_NONCE,
            expected_hash: OBB_MAINNET_GENESIS_HASH,
        },
        ChainId::ObenBlockRegtest => ChainGenesis {
            chain_id: id,
            text: OBB_REGTEST_GENESIS_TEXT,
            version: OBB_REGTEST_GENESIS_VERSION,
            timestamp: OBB_REGTEST_GENESIS_TIMESTAMP,
            bits: OBB_REGTEST_GENESIS_BITS,
            nonce: OBB_REGTEST_GENESIS_NONCE,
            expected_hash: OBB_REGTEST_GENESIS_HASH,
        },
    }
}

impl ChainGenesis {
    /// Whether the constants are still the launch placeholder (ObenBlock
    /// mainnet before it is mined).
    pub const fn is_placeholder(&self) -> bool {
        self.timestamp == 0
    }

    /// The genesis block these constants describe.
    pub fn block(&self) -> Block {
        self.block_with(self.version, self.timestamp, self.nonce)
    }

    /// The genesis block with another version, timestamp and nonce (the
    /// mining tool's search space; the text and bits stay).
    pub fn block_with(&self, version: u32, timestamp: u64, nonce: u64) -> Block {
        match self.chain_id.chain() {
            Chain::Gnb => super::create_genesis_block_with(timestamp, self.bits, nonce),
            Chain::ObenBlock => obenblock_genesis_block(self.text, version, timestamp, self.bits, nonce),
        }
    }
}

/// The ObenBlock genesis coinbase for `text`: the 80-byte commitment of
/// height 0 (no parents; the body commitment of a coinbase-only block with
/// empty shielded and PoWit sections), then the text; one output of 0 to an
/// all-zero script.
pub fn obenblock_genesis_coinbase(text: &str) -> Transaction {
    let mut cb = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: Vec::new(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 0, script_pubkey: vec![0u8; 20] }],
        locktime: 0,
    };
    // The witness root counts the coinbase as all-zero, so it does not
    // depend on the script_sig it is written into.
    let commitment = block_rules::coinbase_commitment(0, &[], &obenblock_genesis_body_commitment(&cb));
    cb.inputs[0].script_sig = block_rules::coinbase_script_sig(&commitment, text.as_bytes());
    cb
}

// The genesis root includes the liveness exits section (height 0).
const _: () = assert!(super::liveness::OBENBLOCK_LIVENESS_ACTIVATION_HEIGHT == 0, "the genesis root assumes it");

/// The body commitment of an ObenBlock genesis with coinbase `cb`
/// (`pow_scheme::obb_body_commitment` of the genesis): its witness root, the
/// empty shielded section and the empty PoWit section in the ObenBlock body
/// format (exits list and PoCI on both ObenBlock networks from height 0; an
/// empty section is the same bytes in every format). Computed
/// without the process-wide heights so tools and other chains' processes
/// get it too; equal to the node's value in a process running ObenBlock
/// (`tests/obb_genesis_regtest.rs`).
pub fn obenblock_genesis_body_commitment(cb: &Transaction) -> MerkleRoot {
    let shell = genesis_shell(cb);
    pow_scheme::obb_body_commitment_parts(
        &block_rules::witness_root(&shell.transactions), &shell.shielded_root(),
        &shell.powit.root_for(super::powit::BodyFormat { exits: true, poci: true }))
}

/// The header Merkle root of an ObenBlock genesis with coinbase `cb`:
/// Bitcoin's root over the one txid, which is that txid.
pub fn obenblock_genesis_merkle_root(cb: &Transaction) -> MerkleRoot {
    pow_scheme::bitcoin_merkle_root(&[cb.txid()]).0
}

fn genesis_shell(cb: &Transaction) -> Block {
    Block {
        header: BlockHeader { version: 0, parents: vec![], merkle_root: MerkleRoot::ZERO, timestamp: 0, bits: 0, nonce: 0 },
        transactions: vec![cb.clone()],
        blue_score: 0,
        height: 0,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    }
}

/// An ObenBlock genesis block (see the module documentation).
pub fn obenblock_genesis_block(text: &str, version: u32, timestamp: u64, bits: u32, nonce: u64) -> Block {
    let cb = obenblock_genesis_coinbase(text);
    Block {
        header: BlockHeader {
            version,
            parents: vec![],
            merkle_root: obenblock_genesis_merkle_root(&cb),
            timestamp,
            bits,
            nonce,
        },
        transactions: vec![cb],
        blue_score: 0,
        height: 0,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    }
}

// ── Chain rules bound to the genesis ────────────────────────────────────────

/// The proof-of-work scheme of the network `id`: GnB-SMH for GnB, SHA-256d
/// anchored at the network's genesis for ObenBlock (ASERT anchor bits: the
/// launch bits on mainnet, the pow limit on regtest).
pub const fn pow_scheme_for(id: ChainId) -> PowScheme {
    match id {
        ChainId::Mainnet | ChainId::Testnet => PowScheme::GnbSmh,
        ChainId::ObenBlockMainnet => PowScheme::Sha256d(Sha256dParams::obenblock_mainnet(OBB_MAINNET_GENESIS_TIMESTAMP)),
        ChainId::ObenBlockRegtest => PowScheme::Sha256d(Sha256dParams::obenblock_regtest(OBB_REGTEST_GENESIS_TIMESTAMP)),
    }
}

/// Bind the proof-of-work scheme of an ObenBlock network to the process
/// (`super::set_node_chain_id`): `Err` when another scheme was set first.
/// GnB networks bind nothing (their scheme is the default).
pub(super) fn bind_pow_scheme(id: ChainId) -> Result<(), PowScheme> {
    match id.chain() {
        Chain::Gnb => Ok(()),
        Chain::ObenBlock => super::pow_scheme::set_node_pow_scheme(pow_scheme_for(id)),
    }
}

/// Why a node must not start on `id` with this binary's constants: the
/// ObenBlock mainnet genesis is still the launch placeholder. `None` for
/// every network whose genesis is fixed.
pub fn launch_refusal(id: ChainId) -> Option<String> {
    let g = chain_genesis(id);
    if !g.is_placeholder() && g.expected_hash != [0u8; 32] {
        return None;
    }
    Some(format!(
        "the {} genesis is not mined yet (launch placeholder in crates/gnb-crypto/src/core/genesis.rs). \
         Mine it at launch with `{}` and paste the printed constants (docs/OBENBLOCK-GENESIS.md); \
         use --regtest for local development",
        id.params().network_name, OBB_MAINNET_GENESIS_MINE_COMMAND,
    ))
}

/// First height whose blocks must commit to their witnesses
/// (`super::witnesses_committed`): GnB's `WITNESS_COMMITMENT_HEIGHT`, 0 on
/// ObenBlock, whose coinbase commitment (which covers the witness root)
/// applies from the first block.
pub fn witness_commitment_height() -> u64 {
    match super::node_chain_id().chain() {
        Chain::Gnb => super::WITNESS_COMMITMENT_HEIGHT,
        Chain::ObenBlock => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{carryover, pow_scheme, vesting};

    /// The lib test binary never selects a chain: GnB's genesis is unchanged
    /// and still the default.
    #[test]
    fn gnb_genesis_is_unchanged() {
        for id in [ChainId::Mainnet, ChainId::Testnet] {
            let g = chain_genesis(id);
            assert_eq!(g.block().to_wire_bytes(), crate::core::genesis_block().to_wire_bytes());
            assert_eq!(g.block().block_hash(), crate::core::GENESIS_EXPECTED_HASH);
            assert!(!g.is_placeholder());
            assert_eq!(pow_scheme_for(id), PowScheme::GnbSmh);
            assert_eq!(launch_refusal(id), None);
        }
        assert_eq!(witness_commitment_height(), crate::core::WITNESS_COMMITMENT_HEIGHT);
    }

    /// §3: the ObenBlock genesis text commits to the same snapshot, the same
    /// conversion and the same vesting keys as GnB's.
    #[test]
    fn genesis_texts_commit_to_the_gnb_ledger() {
        for (text, net) in [(OBB_MAINNET_GENESIS_TEXT, "mainnet"), (OBB_REGTEST_GENESIS_TEXT, "regtest")] {
            assert!(text.starts_with(&format!("ObenBlock {net} genesis: ")), "{text}");
            assert!(text.contains(&hex::encode(carryover::CARRYOVER_SNAPSHOT_SHA3)));
            assert!(text.contains(&hex::encode(vesting::VESTING_SPEC_SHA3)));
            assert!(text.contains("3810744000 BLCH -> 1000000 OBB"));
            assert!(crate::core::GENESIS_COINBASE_TEXT.contains(&hex::encode(carryover::CARRYOVER_SNAPSHOT_SHA3)));
            assert!(text.len() < 1_000, "far below the script_sig cap");
        }
        assert_ne!(OBB_MAINNET_GENESIS_TEXT, OBB_REGTEST_GENESIS_TEXT);
    }

    /// The coinbase carries the height-0 commitment, pays nothing, and the
    /// header root is Bitcoin's root, the coinbase txid.
    #[test]
    fn obenblock_genesis_structure() {
        for id in [ChainId::ObenBlockMainnet, ChainId::ObenBlockRegtest] {
            let g = chain_genesis(id);
            let b = g.block();
            assert_eq!((b.height, b.blue_score), (0, 0));
            assert!(b.header.parents.is_empty() && b.shielded_transactions.is_empty() && b.powit.is_empty());
            assert_eq!(b.header.bits, if id == ChainId::ObenBlockMainnet { OBB_POW_LIMIT_BITS } else { OBB_REGTEST_POW_LIMIT_BITS });
            assert!(b.validate_coinbase_format());
            assert_eq!(b.transactions.len(), 1);
            let cb = &b.transactions[0];
            assert_eq!(cb.outputs.len(), 1);
            assert_eq!((cb.outputs[0].value, cb.outputs[0].script_pubkey.as_slice()), (0, &[0u8; 20][..]));
            // This lib test process runs GnB-SMH, so the commitment is
            // checked against the ObenBlock body commitment directly.
            let want = block_rules::coinbase_commitment(0, &[], &obenblock_genesis_body_commitment(cb));
            assert_eq!(&cb.inputs[0].script_sig[..block_rules::COINBASE_COMMITMENT_LEN], &want[..]);
            assert_ne!(obenblock_genesis_body_commitment(cb), block_rules::witness_root(&b.transactions),
                       "the body commitment, not GnB's bare witness root");
            assert_eq!(&cb.inputs[0].script_sig[block_rules::COINBASE_COMMITMENT_LEN..], g.text.as_bytes());
            assert_eq!(b.header.merkle_root, obenblock_genesis_merkle_root(cb));
            assert_eq!(b.header.merkle_root.0, cb.txid(), "Bitcoin's root of one transaction is its txid");
            // The header fits the 80-byte layout and the BIP 320 version rule.
            assert!(b.header.sha256d_pow_bytes().is_ok() || g.is_placeholder());
            assert!(gnb_smh::sha256d::version_ok(b.header.version, OBB_BLOCK_VERSION));
            let PowScheme::Sha256d(p) = pow_scheme_for(id) else { panic!("ObenBlock is SHA-256d") };
            assert_eq!(p.genesis_timestamp, g.timestamp);
            assert_eq!(p.asert_anchor().height, 0);
        }
        // Mainnet anchors ASERT at the launch bits, above the genesis's own
        // (pow-limit) target; regtest at its pow limit.
        let PowScheme::Sha256d(m) = pow_scheme_for(ChainId::ObenBlockMainnet) else { unreachable!() };
        assert_eq!((m.genesis_bits, m.pow_limit_bits), (pow_scheme::OBB_LAUNCH_BITS, OBB_POW_LIMIT_BITS));
        let PowScheme::Sha256d(r) = pow_scheme_for(ChainId::ObenBlockRegtest) else { unreachable!() };
        assert_eq!((r.genesis_bits, r.pow_limit_bits), (OBB_REGTEST_POW_LIMIT_BITS, OBB_REGTEST_POW_LIMIT_BITS));
    }

    /// Until the launch the mainnet genesis is a placeholder and the node is
    /// told how to mine it; regtest is mined.
    #[test]
    fn mainnet_is_a_launch_placeholder_and_regtest_is_mined() {
        let m = chain_genesis(ChainId::ObenBlockMainnet);
        if m.is_placeholder() {
            let why = launch_refusal(ChainId::ObenBlockMainnet).expect("placeholder refused");
            assert!(why.contains(OBB_MAINNET_GENESIS_MINE_COMMAND) && why.contains("OBENBLOCK-GENESIS.md"), "{why}");
            assert_eq!(m.expected_hash, [0u8; 32]);
        } else {
            assert_ne!(m.expected_hash, [0u8; 32], "a launched genesis pins its hash");
            assert!(u32::try_from(m.timestamp).is_ok() && u32::try_from(m.nonce).is_ok());
        }
        let r = chain_genesis(ChainId::ObenBlockRegtest);
        assert!(!r.is_placeholder() && r.expected_hash != [0u8; 32]);
        assert_eq!(launch_refusal(ChainId::ObenBlockRegtest), None);
        // The regtest proof, under the regtest parameters (the scheme of
        // this process is GnB-SMH, so check the header directly).
        let PowScheme::Sha256d(p) = pow_scheme_for(ChainId::ObenBlockRegtest) else { unreachable!() };
        let b = r.block();
        assert_eq!(pow_scheme::check_sha256d_pow(&b.header, &p), Ok(()));
        assert_eq!(b.header.sha256d_block_id(), OBB_REGTEST_GENESIS_HASH);
    }

    #[test]
    fn min_chain_work_is_zero_at_launch() {
        assert_eq!(OBB_MIN_CHAIN_WORK, 0);
    }
}
