//! UTXO-set supply audit (audit VAL-11 residual): the node's counterpart of
//! Bitcoin Core's `gettxoutsetinfo`.
//!
//! One pass over a consistent RocksDB snapshot (Core iterates a snapshot
//! cursor of its coins database the same way) computes the number of
//! unspent outputs, their total value and a deterministic hash of the set,
//! and checks the total against what consensus allows to exist:
//!
//! ```text
//! max_supply = genesis ledger + Σ block_subsidy(B.height) over the applied chain
//! genesis ledger = carryover + locked team and founder allocations
//! unclaimed  = max_supply - total
//! ```
//!
//! The genesis ledger is the outputs no transaction creates ([`GenesisLedger`]):
//! the converted Bloch carryover and the 72 locked vesting tranches
//! (`core::vesting`, 2 × 100,000 OBB, policy outputs with an absolute
//! timelock; locked or not, they are in the set and in the total). The
//! applied chain is the set of blocks that hold an undo record (every
//! connected block keeps one, pruned or not; the genesis has none and pays
//! nothing), and `B.height` is the header height its undo record stores: the
//! height its subsidy was computed for. That set must be exactly the
//! selected chain of the applied tip, which the audit checks by walking it
//! (`chain_ok`). `unclaimed` is permanently unspendable value: rewards
//! miners did not claim (a coinbase below its allowance); from the PoWit
//! activation, the witness-pool slots of a block that carries fewer than 16
//! witness shares, and the rounding of the split
//! (`witness_share::split_subsidy`: empty slots are not issued, so mined
//! issuance only falls below the schedule; the witness-share coinbase
//! outputs that are paid are ordinary outputs, in the total); and value
//! moved into the shielded pool (none while the pool is inactive). No coin
//! is ever replaced by an output with the same outpoint: this chain enforces
//! BIP30 at every height (audit VAL-2). A total above `max_supply` is
//! inflation or corruption. Fees move value between outputs and are not
//! issuance (on ObenBlock the fee slots a block leaves empty are burned,
//! `witness_share::split_reward`, which only lowers the total), and the proof of work (GnB-SMH v1, v3 from the PoWit height)
//! does not enter the bound: the subsidy depends on the header height alone.
//!
//! Independently, the scan's totals over 20-byte (address) scripts are
//! compared with the holder aggregates the node maintains in the same write
//! batches as the UTXO set (audit NET-12): a UTXO row changed outside the
//! node (disk corruption, an edited data dir) shows as a mismatch even when
//! the total stays below `max_supply`. Policy outputs (multisig, timelocks,
//! the locked tranches) are in neither aggregate.

use std::sync::atomic::{AtomicBool, Ordering};

use rocksdb::IteratorMode;

use super::aggregates::{self, TierTotals};
use super::{decode, Storage, StorageError, CF_DAG, CF_META, CF_UNDO, CF_UTXO};
use crate::consensus::GhostdagData;
use crate::core::{tokenomics, TxOutput};

/// Rows between two checks of the cancellation flag.
const CANCEL_STRIDE: u64 = 4_096;

/// The genesis ledger: outputs that exist from the genesis without a
/// creating transaction, the start of the issuance bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisLedger {
    /// The converted Bloch carryover (`core::carryover`).
    pub carryover_sat: u64,
    /// The locked team and founder allocations (`core::vesting`).
    pub locked_sat: u64,
}

impl GenesisLedger {
    /// This chain's genesis ledger (mainnet and testnet share it):
    /// `CARRYOVER_CONVERTED_TOTAL_SAT` plus the team and founder
    /// allocations, which the vesting tranches sum to exactly
    /// (`tokenomics::vesting_tranche_value`).
    pub const NETWORK: GenesisLedger = GenesisLedger {
        carryover_sat: crate::core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT,
        locked_sat: tokenomics::TEAM_ALLOCATION_SAT + tokenomics::FOUNDER_ALLOCATION_SAT,
    };

    /// carryover + locked.
    pub fn total_sat(&self) -> u128 {
        self.carryover_sat as u128 + self.locked_sat as u128
    }
}

/// The result of [`Storage::utxo_set_audit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoSetAudit {
    /// The applied tip (meta `tip_hash`) at the snapshot, if any.
    pub best_block: Option<[u8; 32]>,
    /// Its selected-chain position (DAG height).
    pub height: u64,
    /// Unspent outputs.
    pub txouts: u64,
    /// Their total value (u128: a corrupted set cannot overflow the sum).
    pub total_sat: u128,
    /// SHA3-256 over every CF_UTXO row in key order, `u32 LE len(key) ‖ key
    /// ‖ u32 LE len(value) ‖ value`, domain `gnb/utxo-set/v1`: the digest
    /// `Storage::utxo_set_digest` computes (the chain-state rebuild compares
    /// it), a pure function of the set's contents.
    pub hash_serialized: [u8; 32],
    /// Rows whose value does not decode as an output (corruption).
    pub undecodable: u64,
    /// The genesis ledger the bound starts from (passed by the caller).
    pub genesis_ledger: GenesisLedger,
    /// Blocks of the applied chain (undo records).
    pub applied_blocks: u64,
    /// Undo records of blocks that are not on the selected chain of
    /// `best_block` (a stale record: its issuance is counted in
    /// `subsidy_sat` although the block is not applied).
    pub undo_off_chain: u64,
    /// Blocks of that chain (genesis excluded) without an undo record (their
    /// issuance is missing from `subsidy_sat`), counting a chain the walk
    /// could not finish (a DAG record missing below the tip) as one more.
    pub chain_without_undo: u64,
    /// Σ block_subsidy(header height) over the applied chain.
    pub subsidy_sat: u128,
    /// The issuance schedule through the tip's position,
    /// `issued_through_sat(height)`: an upper bound of `subsidy_sat` (a block
    /// at position p has a header height of at least p, and the subsidy does
    /// not grow with the height).
    pub schedule_issued_sat: u64,
    /// Outputs paying a 20-byte (address) script, and their value, from the
    /// scan.
    pub holder_txouts: u64,
    pub holder_total_sat: u128,
    /// The same two from the maintained aggregates (`None`: the aggregates
    /// are not complete yet).
    pub maintained: Option<(u64, u128)>,
}

impl UtxoSetAudit {
    /// genesis ledger (carryover + locked) + Σ subsidy over the applied
    /// chain.
    pub fn max_supply_sat(&self) -> u128 {
        self.genesis_ledger.total_sat() + self.subsidy_sat
    }

    /// The UTXO set holds no more than consensus allows to exist (and every
    /// row decodes).
    pub fn supply_ok(&self) -> bool {
        self.undecodable == 0 && self.total_sat <= self.max_supply_sat()
    }

    /// max_supply - total, when the supply is within it.
    pub fn unclaimed_sat(&self) -> Option<u128> {
        self.max_supply_sat().checked_sub(self.total_sat)
    }

    /// The scan agrees with the maintained aggregates (`None`: no aggregates).
    pub fn aggregates_ok(&self) -> Option<bool> {
        self.maintained.map(|m| m == (self.holder_txouts, self.holder_total_sat))
    }

    /// The undo records are exactly the blocks of the selected chain of the
    /// applied tip (genesis excluded): every record's block is on that chain
    /// and every chain block has one, so no block's issuance is missing from,
    /// or counted twice in, the bound (a membership check, not a count: a
    /// stale record and a missing one cancel out in the count).
    pub fn chain_ok(&self) -> bool {
        self.applied_blocks == self.height && self.undo_off_chain == 0 && self.chain_without_undo == 0
    }

    /// Every check that can run passed (the subsidy sum is also within the
    /// schedule).
    pub fn ok(&self) -> bool {
        self.supply_ok()
            && self.chain_ok()
            && self.aggregates_ok() != Some(false)
            && self.subsidy_sat <= self.schedule_issued_sat as u128
    }
}

impl Storage {
    /// Audit the UTXO set against the issuance (module documentation). One
    /// pass over the UTXO set and one over the undo records, both in ONE
    /// RocksDB snapshot, so a block connected meanwhile is either wholly in
    /// the result or not at all. `genesis_ledger` is the value of the
    /// genesis ledger ([`GenesisLedger::NETWORK`] on the network). Checks
    /// `cancel` every few thousand rows and returns the "cancelled" error
    /// when it is set (a heavy RPC whose deadline fired).
    pub fn utxo_set_audit(&self, genesis_ledger: GenesisLedger, cancel: &AtomicBool) -> Result<UtxoSetAudit, StorageError> {
        use sha3::{Digest, Sha3_256};
        let cf = |n: &str| self.db().cf_handle(n).ok_or_else(|| StorageError::CfNotFound(n.into()));
        let (cf_utxo, cf_undo, cf_meta, cf_dag) = (cf(CF_UTXO)?, cf(CF_UNDO)?, cf(CF_META)?, cf(CF_DAG)?);
        let snap = self.db().snapshot();
        let read = |e: rocksdb::Error| StorageError::ReadFailed(e.to_string());

        let best_block = snap.get_cf(cf_meta, b"tip_hash").map_err(read)?
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
        let height = match best_block {
            Some(t) => snap.get_cf(cf_dag, t).map_err(read)?
                .map(|v| decode::<GhostdagData>(&v).map(|d| d.height))
                .transpose()?
                .unwrap_or(0),
            None => 0,
        };

        let mut h = Sha3_256::new();
        h.update(b"gnb/utxo-set/v1");
        let (mut txouts, mut total, mut undecodable, mut holder_txouts, mut holder_total) = (0u64, 0u128, 0u64, 0u64, 0u128);
        for (i, item) in snap.iterator_cf(cf_utxo, IteratorMode::Start).enumerate() {
            if (i as u64).is_multiple_of(CANCEL_STRIDE) && cancel.load(Ordering::Relaxed) {
                return Err(aggregates::cancelled());
            }
            let (k, v) = item.map_err(read)?;
            h.update((k.len() as u32).to_le_bytes());
            h.update(&k);
            h.update((v.len() as u32).to_le_bytes());
            h.update(&v);
            txouts += 1;
            match decode::<TxOutput>(&v) {
                Ok(out) => {
                    total += out.value as u128;
                    if out.script_pubkey.len() == 20 {
                        holder_txouts += 1;
                        holder_total += out.value as u128;
                    }
                }
                Err(_) => undecodable += 1,
            }
        }

        let (mut applied_blocks, mut subsidy) = (0u64, 0u128);
        let mut undo_blocks: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for (i, item) in snap.iterator_cf(cf_undo, IteratorMode::Start).enumerate() {
            if (i as u64).is_multiple_of(CANCEL_STRIDE) && cancel.load(Ordering::Relaxed) {
                return Err(aggregates::cancelled());
            }
            let (k, v) = item.map_err(read)?;
            let Ok(block) = <[u8; 32]>::try_from(k.as_ref()) else {
                continue; // pruned-body records share the column family
            };
            let undo = crate::core::UndoData::from_bytes(&v).map_err(StorageError::DeserializeFailed)?;
            applied_blocks += 1;
            subsidy += tokenomics::block_subsidy_sat(undo.block_height) as u128;
            undo_blocks.insert(block);
        }

        // Membership: walk the selected chain of the applied tip (CF_DAG
        // selected parents, same snapshot) down to the genesis; every block
        // on it but the genesis must hold an undo record, and no record may
        // be left over.
        let mut chain_without_undo = 0u64;
        let mut on_chain = 0u64;
        let mut cur = best_block;
        let mut steps = 0u64;
        while let Some(h) = cur {
            if steps.is_multiple_of(CANCEL_STRIDE) && cancel.load(Ordering::Relaxed) {
                return Err(aggregates::cancelled());
            }
            steps += 1;
            if steps > height + 1 {
                // Longer than the tip's position: corrupted selected parents.
                chain_without_undo += 1;
                break;
            }
            let Some(raw) = snap.get_cf(cf_dag, h).map_err(read)? else {
                chain_without_undo += 1; // the walk cannot reach the genesis
                break;
            };
            let data = decode::<GhostdagData>(&raw)?;
            match data.selected_parent {
                None => break, // the genesis: pays nothing, holds no record
                Some(parent) => {
                    if undo_blocks.contains(&h) {
                        on_chain += 1;
                    } else {
                        chain_without_undo += 1;
                    }
                    cur = Some(parent);
                }
            }
        }
        let undo_off_chain = applied_blocks - on_chain;

        let ready = snap.get_cf(cf_meta, aggregates::K_VERSION).map_err(read)?
            .is_some_and(|v| v.as_slice() == aggregates::AGG_VERSION.to_le_bytes());
        let maintained = if ready {
            let tiers: Vec<TierTotals> = snap.get_cf(cf_meta, aggregates::K_TIERS).map_err(read)?
                .and_then(|v| aggregates::dec_tiers(&v))
                .unwrap_or_else(|| vec![TierTotals::default(); aggregates::TIERS.len()]);
            Some((tiers.iter().map(|t| t.utxos).sum(), tiers.iter().map(|t| t.sats as u128).sum()))
        } else {
            None
        };

        Ok(UtxoSetAudit {
            best_block,
            height,
            txouts,
            total_sat: total,
            hash_serialized: h.finalize().into(),
            undecodable,
            genesis_ledger,
            applied_blocks,
            undo_off_chain,
            chain_without_undo,
            subsidy_sat: subsidy,
            schedule_issued_sat: tokenomics::issued_through_sat(height),
            holder_txouts,
            holder_total_sat: holder_total,
            maintained,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::witness_share::{self, WitnessShare};
    use crate::core::{Block, UndoData};

    /// From the PoWit activation the coinbase pays the miner's part plus one
    /// output per witness share (`Block::coinbase_outputs`), and the slots of
    /// absent shares (and the split's rounding) are never issued. The bound
    /// (genesis ledger, locked tranches included, + Σ subsidy) holds, and with
    /// every block claiming its whole allowance the unclaimed value is
    /// exactly the unissued part of each split. Without the locked
    /// allocations in the ledger the same set reads as inflation.
    #[test]
    fn powit_era_coinbases_and_the_locked_allocations_fit_the_bound() {
        let tmp = tempfile::TempDir::new().unwrap();
        let s = Storage::open(&tmp.path().join("db")).unwrap();
        const LOCKED: u64 = 7_000_000_000; // larger than the unissued value below
        let ledger = GenesisLedger { carryover_sat: 5_000, locked_sat: LOCKED };
        // The genesis ledger: a carryover-like key-hash output and a locked
        // tranche (a 33-byte policy script, `core::policy`).
        s.put_utxo(&[0xA1; 32], 0, &TxOutput { value: 5_000, script_pubkey: vec![0x11; 20] }).unwrap();
        let mut policy = vec![0x02u8];
        policy.extend_from_slice(&[0x22; 32]);
        s.put_utxo(&[0xA2; 32], 0, &TxOutput { value: LOCKED, script_pubkey: policy }).unwrap();

        let first = crate::core::POWIT_HEIGHT_MAINNET;
        assert!(crate::core::powit_active(first), "the tests run with mainnet's PoWit height");
        let genesis = [0u8; 32];
        s.put_dag_with_integrity(&genesis, &GhostdagData::genesis()).unwrap();
        let (mut parent, mut subsidy, mut unissued) = (genesis, 0u128, 0u128);
        for (i, n_shares) in [0usize, 5, witness_share::MAX_SHARES_PER_BLOCK].into_iter().enumerate() {
            let header_height = first + i as u64;
            let shares: Vec<WitnessShare> = (0..n_shares)
                .map(|k| WitnessShare { attested: [0; 32], witness: [k as u8; 20], payout: vec![0x30 + k as u8; 20], bits: 0, nonce: 0, sha256d: None })
                .collect();
            let outs = Block::coinbase_outputs(header_height, vec![0xCC; 20], 0, &shares);
            assert_eq!(outs.len(), 1 + n_shares, "miner output + one per share");
            let split = witness_share::split_subsidy(header_height, n_shares);
            let paid: u64 = outs.iter().map(|o| o.value).sum();
            assert_eq!(paid + split.unissued, tokenomics::block_subsidy_sat(header_height));
            let cb = [0xB0 + i as u8; 32];
            for (j, o) in outs.iter().enumerate() {
                s.put_utxo(&cb, j as u32, o).unwrap();
            }
            let hash = [i as u8 + 1; 32];
            let mut d = GhostdagData::genesis();
            d.selected_parent = Some(parent);
            d.parents = vec![parent];
            d.height = i as u64 + 1;
            s.put_dag_with_integrity(&hash, &d).unwrap();
            s.put_undo_data(&hash, &UndoData::new(hash, header_height)).unwrap();
            subsidy += tokenomics::block_subsidy_sat(header_height) as u128;
            unissued += split.unissued as u128;
            parent = hash;
        }
        assert!(unissued > 0, "16 empty slots, 11 empty slots and rounding");
        s.put_meta("tip_hash", &parent).unwrap();

        let a = s.utxo_set_audit(ledger, &AtomicBool::new(false)).unwrap();
        assert_eq!(a.subsidy_sat, subsidy);
        assert_eq!(a.max_supply_sat(), 5_000 + LOCKED as u128 + subsidy);
        assert_eq!(a.unclaimed_sat(), Some(unissued), "exactly the unissued witness-pool value");
        assert!(a.chain_ok() && a.supply_ok() && a.ok(), "{a:?}");
        // The policy tranche is in the total, not in the address aggregates.
        assert_eq!(a.total_sat - a.holder_total_sat, LOCKED as u128);

        let without_locked = s.utxo_set_audit(GenesisLedger { locked_sat: 0, ..ledger }, &AtomicBool::new(false)).unwrap();
        assert!(!without_locked.supply_ok(), "the locked allocations are part of the genesis ledger");
        assert_eq!(without_locked.total_sat - without_locked.max_supply_sat(), LOCKED as u128 - unissued);
    }

    /// The network's genesis ledger is the converted carryover plus the
    /// locked tranches, which sum to exactly the two allocations.
    #[test]
    fn the_network_genesis_ledger_counts_the_locked_tranches() {
        let tranches = crate::core::vesting::genesis_tranches().unwrap();
        let locked: u64 = tranches.iter().map(|t| t.output.value).sum();
        assert_eq!(GenesisLedger::NETWORK.locked_sat, locked);
        assert_eq!(GenesisLedger::NETWORK.carryover_sat, crate::core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT);
        assert_eq!(GenesisLedger::NETWORK.total_sat(), (crate::core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT + locked) as u128);
    }
}
