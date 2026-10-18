//! Genesis of a data directory: the first boot writes the genesis ledger and
//! the genesis block of the node's chain; every later boot checks that the
//! data directory holds this binary's genesis.
//!
//! The chain is the process's (`core::node_chain_id`, set at start-up): GnB
//! (`core::genesis_block`, shared by mainnet and testnet) or ObenBlock
//! (`core::genesis`, one genesis per network, docs/DESIGN-obenblock.md §3).
//! Both chains open with the same ledger: the Bloch Genesis-3 carry-over
//! converted by `core::carryover` plus the locked team and founder tranches
//! of `core::vesting`, verified before anything is written.

use log::info;
use parking_lot::RwLock;

use crate::consensus::GhostDAG;
use crate::storage::{self, Storage};
use gnb_crypto::core::{self, Block};

/// The genesis block of the node's chain, checked against the binary's
/// constants: a valid proof of work under the process's scheme, the pinned
/// block id, and (ObenBlock) the body root under the chain's own rules.
pub fn verified_genesis() -> Result<Block, String> {
    let id = core::node_chain_id();
    if let Some(why) = core::genesis::launch_refusal(id) {
        return Err(why);
    }
    let constants = core::genesis::chain_genesis(id);
    let genesis = core::genesis_block();
    if !genesis.validate_pow() {
        return Err(format!(
            "genesis PoW invalid ({}): the genesis does not verify against this binary's constants",
            core::pow_scheme::node_pow_scheme().name()
        ));
    }
    if constants.expected_hash != [0u8; 32] && genesis.block_hash() != constants.expected_hash {
        return Err(format!(
            "genesis block hash {} != expected {}: a baked constant drifted",
            hex::encode(genesis.block_hash()),
            hex::encode(constants.expected_hash)
        ));
    }
    if id.chain() == core::chain::Chain::ObenBlock && !genesis.validate_merkle() {
        return Err("genesis body root does not match the ObenBlock rules of height 0".into());
    }
    Ok(genesis)
}

/// First boot: verify `snapshot` (the uncompressed Bloch Genesis-3
/// carry-over) and the locked allocations, write the genesis ledger in one
/// atomic batch, then the genesis block, its DAG record and the start-up
/// metadata. Returns the genesis block id. Nothing is written when a check
/// fails; a crash between the ledger and the block re-runs both on the next
/// boot (the ledger keys are fixed).
pub fn initialise(store: &Storage, dag: &RwLock<GhostDAG>, snapshot: &[u8]) -> Result<[u8; 32], Vec<String>> {
    // The genesis first: a binary whose constants do not verify writes nothing.
    let genesis = verified_genesis().map_err(|e| vec![e])?;

    // Locked team and founder allocations (core::vesting): the keys must be
    // configured and match the consensus hash before any ledger exists.
    let locked = core::vesting::genesis_tranches().map_err(|e| vec![format!("locked allocations unavailable: {e}")])?;
    info!("locked allocations: {} tranches (team {} + founder {} sat), first unlock h={}, last h={}",
          locked.len(), core::tokenomics::TEAM_ALLOCATION_SAT, core::tokenomics::FOUNDER_ALLOCATION_SAT,
          core::tokenomics::vesting_unlock_height(1),
          core::tokenomics::vesting_unlock_height(core::tokenomics::VESTING_TRANCHES));
    let snap = core::carryover::verify_and_convert(snapshot).map_err(|failures| {
        let mut v: Vec<String> = failures.into_iter().map(|f| format!("carryover verification FAILED: {f}")).collect();
        v.push("the snapshot is not this chain's carryover".into());
        v
    })?;
    info!("carryover VERIFIED: {} Bloch outputs ({} BLCH sat) -> {} UTXOs, {} base units \
           ({} zero-value dropped, {} vouts fixed)",
          snap.source_rows, snap.source_total_sat, snap.utxos.len(),
          snap.converted_total_sat, snap.dropped_zero, snap.fixed_vouts);
    let n = store.ingest_carryover(&snap, &locked)
        .map_err(|e| vec![format!("carryover ingestion failed: {e}. Nothing was written")])?;
    info!("genesis ledger ingested: {n} UTXOs (carryover + locked) written atomically");

    let fail = |what: &str, e: String| vec![format!("{what}: {e}")];
    let hash = genesis.block_hash();
    store.put_block(&genesis).map_err(|e| fail("store genesis", e.to_string()))?;
    store.put_meta("genesis_hash", &hash).map_err(|e| fail("meta genesis_hash", e.to_string()))?;
    store.put_meta("tip_hash", &hash).map_err(|e| fail("meta tip_hash", e.to_string()))?;
    // Audit DAG-8: a new data dir starts with the position-keyed chain
    // indexes (no migration at its first reconciliation).
    store.put_meta(storage::CHAIN_INDEX_VERSION_META, &storage::CHAIN_INDEX_VERSION.to_le_bytes())
        .map_err(|e| fail("meta chain_index_version", e.to_string()))?;
    store.put_meta("current_bits", &genesis.header.bits.to_le_bytes())
        .map_err(|e| fail("meta current_bits", e.to_string()))?;
    dag.write().add_genesis(hash, genesis.header.timestamp);
    // Bind in a `let` so the read guard drops before the `dag.write()` inside
    // (parking_lot RwLock is not reentrant — holding this read across the
    // write deadlocks once the reachability gate is armed).
    let gdata_opt = dag.read().get_block_data(&hash).cloned();
    if let Some(gdata) = gdata_opt {
        // Sprint Y (M-2): atomic put to CF_DAG + CF_DAG_INTEGRITY.
        // Genesis anchors the hash-chain with an all-zero parent
        // integrity; see `compute_integrity_hash` for the convention.
        store.put_dag_with_integrity(&hash, &gdata)
            .map_err(|e| fail("persist genesis dag + integrity", e.to_string()))?;
        // Phase 1: when the reachability index is maintained (Fast / armed),
        // persist the genesis reachability record + version tag + root.
        // (Live Legacy path leaves CF_REACHABILITY untouched.)
        if dag.read().maintains_reachability_index() {
            let _ = dag.write().reach_take_delta(); // start tracking clean
            store.store_reachability_snapshot(&dag.read().reach_export_all(), dag.read().reach_root())
                .map_err(|e| fail("persist genesis reachability index", e.to_string()))?;
        }
    }
    // The genesis coinbase is unspendable: index it, but create no UTXO.
    for tx in &genesis.transactions {
        store.put_tx_index(&tx.txid(), &hash, 0).map_err(|e| fail("tx_index", e.to_string()))?;
    }
    info!("Genesis ({} {}): {}", core::node_chain_id().params().chain.name(),
          core::node_chain_id().params().network_name, hex::encode(hash));
    info!("Supply: hard cap {} (carryover {} sat, locked team+founder {} sat), initial subsidy {} sat/block, halving every {} blocks",
          core::tokenomics::MAX_SUPPLY_SAT / core::tokenomics::SAT_PER_GNB,
          core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT,
          core::tokenomics::TEAM_ALLOCATION_SAT + core::tokenomics::FOUNDER_ALLOCATION_SAT,
          core::tokenomics::INITIAL_SUBSIDY_SAT,
          core::tokenomics::HALVING_INTERVAL);
    Ok(hash)
}

/// Later boots: a data dir from another chain (or another genesis, or
/// another genesis ledger) must never be reused. `Err` names the mismatch.
pub fn check_data_dir(store: &Storage) -> Result<(), String> {
    let canonical = core::genesis_block().block_hash();
    match store.get_meta("genesis_hash").ok().flatten() {
        Some(g) if g.as_slice() == canonical => {}
        other => {
            return Err(format!(
                "data-dir genesis {} != this binary's genesis {}; use a fresh --data-dir",
                other.map(hex::encode).unwrap_or_default(), hex::encode(canonical)
            ));
        }
    }
    match store.get_meta("carryover_sha3").ok().flatten() {
        Some(r) if r.as_slice() == core::carryover::CARRYOVER_SNAPSHOT_SHA3 => {}
        _ => return Err("data-dir has no (or a different) carryover marker; \
                         use a fresh --data-dir with --carryover-snapshot".into()),
    }
    match store.get_meta("vesting_sha3").ok().flatten() {
        Some(r) if r.as_slice() == core::vesting::VESTING_SPEC_SHA3 => {}
        _ => return Err("data-dir has no (or a different) locked-allocation marker; use a fresh --data-dir".into()),
    }
    Ok(())
}
