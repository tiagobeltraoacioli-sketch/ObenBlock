//! PoCI finality certificates on the node (ObenBlock,
//! docs/DESIGN-obenblock-poci.md §6): the Proof of Integrity of every
//! finalized checkpoint, kept and served by `getfinalitycertificate`.
//!
//! A checkpoint `F` is finalized by the block `B` whose state first carries
//! it: under the configuration `C` in force at `B`'s selected parent (whose
//! justified checkpoint is `F`), the votes `F -> t` (`t = F +
//! checkpoint_interval`, `B`'s justified checkpoint) included on `B`'s
//! selected chain reached the strict quorum. Those votes are what the node
//! already stores (block bodies), so the certificate is rebuilt from them:
//! every attestation `F -> t` by a key of `C` included in a block of `B`'s
//! selected chain at a height in `t.height ..= B.height` (a vote is
//! includable only there, and the duplicate rule keeps one per key). The
//! configuration cannot change in between: only a finalization changes it,
//! and that moves the justified checkpoint away from `F` first.
//!
//! Kept: when a block that finalizes a checkpoint is accepted
//! ([`keep`]), its certificate is built, verified once against `C`
//! (`poci::Certificate::verify`, every signature) and stored as
//! `powit/pocicert/<checkpoint hash>`; `C` itself is stored by id
//! (`powit/pocicfg/<id>`, the ledger rows). A checkpoint without a row (a
//! data directory from before this code) is rebuilt on request from the
//! selected chain ([`lookup`]) and stored then. The launch checkpoint of §9
//! (and the genesis slot) is final by definition and has no certificate.
//!
//! Cost: building reads at most `vote_ttl + 1` bodies and verifies one
//! signature per vote, once per finalized checkpoint; serving a kept
//! certificate reads one row and checks nothing again.

use std::collections::BTreeMap;
use std::sync::Arc;

use gnb_crypto::core::kes::{KesPublic, KesSignature};
use gnb_crypto::core::powit::poci::{Certificate, Configuration, Kes, PociParams};
use gnb_crypto::core::powit::{Checkpoint, KeyId, PowitState};
use gnb_crypto::core;

use super::{bincode_decode, load_state, poci_config_key, selected_chain_since, ChainView, DagChainView, Hash,
            PociConfigRow};
use crate::consensus::GhostDAG;
use crate::storage::Storage;

fn cert_key(checkpoint: &Hash) -> String {
    format!("powit/pocicert/{}", hex::encode(checkpoint))
}

/// A kept certificate row.
#[derive(serde::Serialize, serde::Deserialize)]
struct CertRow {
    /// The checkpoint's slot (the key holds its hash).
    slot: u64,
    /// The block that finalized it and its height.
    finalized_by: Hash,
    finalized_at: u64,
    /// The configuration it was finalized under (row `powit/pocicfg/<id>`).
    config_id: Hash,
    /// The configuration in force after it (a handoff), if it differs.
    next_config_id: Option<Hash>,
    /// `Certificate::encode` (§6 wire).
    certificate: Vec<u8>,
}

/// A finality certificate with what it was verified against.
pub struct KeptCertificate {
    pub certificate: Certificate<Kes>,
    pub config: Arc<Configuration>,
    pub finalized_by: Hash,
    pub finalized_at: u64,
    pub next_config_id: Option<Hash>,
    /// Encoded size (`certificate` wire).
    pub size: usize,
}

impl KeptCertificate {
    /// The weight of the configuration the certificate's votes carry.
    pub fn signed_weight(&self) -> u128 {
        self.certificate.votes.iter()
            .filter_map(|(k, _)| self.config.weight(&k.witness_id()))
            .fold(0u128, |a, w| a.saturating_add(w))
    }
}

fn params() -> Option<PociParams> {
    PociParams::for_chain(core::node_chain_id())
}

/// The configuration `id` from the ledger rows.
pub fn load_config(store: &Storage, id: &Hash) -> Option<Arc<Configuration>> {
    let row: PociConfigRow = bincode_decode(&store.get_meta(&poci_config_key(id)).ok()??)?;
    (row.config.id() == *id).then(|| Arc::new(row.config))
}

/// Whether `f` is final by definition (genesis slot, the §9 launch
/// checkpoint): no certificate exists for it.
pub fn final_by_definition(pp: &PociParams, f: &Checkpoint) -> bool {
    f.height == 0 || f.height == pp.opening(pp.bootstrap_epochs)
}

/// Build the certificate of the checkpoint `fin` (its PoWit state
/// `fin_state`) finalized: see the module docs. Verifies it.
pub fn build(dag: &GhostDAG, store: &Storage, fin: &Hash, fin_state: &PowitState) -> Result<KeptCertificate, String> {
    let pp = params().ok_or("PoCI: not an ObenBlock chain")?;
    let f = fin_state.finalized;
    if final_by_definition(&pp, &f) {
        return Err("checkpoint is final by definition (genesis or the PoCI launch checkpoint): no certificate".into());
    }
    let d = dag.get_block_data(fin).ok_or("finalizing block not in the DAG")?;
    let height = d.height;
    let parent = d.selected_parent.ok_or("finalizing block without a selected parent")?;
    let pst = load_state(store, &parent).ok_or("storage: missing PoWit state of the finalizing block's parent")?;
    if pst.finalized == f || pst.justified != f {
        return Err("block does not finalize this checkpoint (its parent's justified checkpoint is not it)".into());
    }
    let t = fin_state.justified;
    if t.height != f.height.saturating_add(pp.checkpoint_interval) {
        return Err("finalizing link is not source -> direct child".into());
    }
    let config = pst.poci_config().cloned().ok_or("no PoCI configuration in force at the finalizing block's parent")?;
    let mut votes: BTreeMap<KeyId, (KesPublic, KesSignature)> = BTreeMap::new();
    for (h, _) in selected_chain_since(dag, Some(*fin), t.height) {
        let b = store.get_block(&h).map_err(|e| format!("storage: {e}"))?
            .ok_or_else(|| format!("block body {} not stored (pruned?)", hex::encode(&h[..8])))?;
        for a in &b.powit.attestations {
            let k = a.key_id();
            if a.source == f && a.target == t && config.weight(&k).is_some() {
                votes.entry(k).or_insert_with(|| (a.witness, a.sig.clone()));
            }
        }
    }
    let cert = Certificate::<Kes>::new(pp.chain_id, config.id(), f, t, votes.into_values().collect());
    cert.verify(&pp, &config).map_err(|e| e.to_string())?;
    let next = fin_state.poci_config().map(|c| c.id()).filter(|id| *id != config.id());
    let size = cert.encode().len();
    Ok(KeptCertificate { certificate: cert, config, finalized_by: *fin, finalized_at: height, next_config_id: next, size })
}

fn store_row(store: &Storage, k: &KeptCertificate) -> Result<(), String> {
    let row = CertRow {
        slot: k.certificate.source.height,
        finalized_by: k.finalized_by,
        finalized_at: k.finalized_at,
        config_id: k.config.id(),
        next_config_id: k.next_config_id,
        certificate: k.certificate.encode(),
    };
    let bytes = bincode::serde::encode_to_vec(&row, bincode::config::standard())
        .map_err(|e| format!("poci certificate encode: {e}"))?;
    store.put_meta(&cert_key(&k.certificate.source.hash), &bytes).map_err(|e| format!("storage: {e}"))
}

/// The kept certificate of the checkpoint `hash`, if stored.
pub fn load(store: &Storage, hash: &Hash) -> Option<KeptCertificate> {
    let row: CertRow = bincode_decode(&store.get_meta(&cert_key(hash)).ok()??)?;
    let certificate = Certificate::<Kes>::decode(&row.certificate).ok()?;
    if certificate.source.hash != *hash || certificate.source.height != row.slot || certificate.config_id != row.config_id {
        return None;
    }
    let config = load_config(store, &row.config_id)?;
    Some(KeptCertificate { size: row.certificate.len(), certificate, config, finalized_by: row.finalized_by,
                           finalized_at: row.finalized_at, next_config_id: row.next_config_id })
}

/// Acceptance hook: `hash` (just stored, PoWit state `state`) finalized a
/// checkpoint without a kept certificate: build, verify and keep it. A
/// failure is logged, never a verdict on the block (the certificate is a
/// product of consensus, not part of it).
pub fn keep(dag: &parking_lot::RwLock<GhostDAG>, store: &Storage, hash: &Hash, state: Option<&PowitState>) {
    let (Some(pp), Some(st)) = (params(), state) else { return };
    if st.poci.is_none() || final_by_definition(&pp, &st.finalized) {
        return;
    }
    let height = match dag.read().get_block_data(hash) {
        Some(d) => d.height,
        None => return,
    };
    // Finalized by this block (`finalized_at` is the finalizing block's
    // height), not yet kept.
    if st.finalized_at != height || matches!(store.get_meta(&cert_key(&st.finalized.hash)), Ok(Some(_))) {
        return;
    }
    let built = build(&dag.read(), store, hash, st);
    match built.and_then(|k| store_row(store, &k)) {
        Ok(()) => {}
        Err(e) => log::warn!("PoCI: finality certificate of slot {} not kept: {e}", st.finalized.height),
    }
}

/// The certificate of the finalized checkpoint `f` on the selected chain
/// from `tip` (whose state `tip_state` finalized `f` or a later one): the
/// kept row, else rebuilt from the chain and kept.
pub fn lookup(dag: &GhostDAG, store: &Storage, tip: &Hash, tip_state: &PowitState, f: &Checkpoint)
    -> Result<KeptCertificate, String>
{
    let pp = params().ok_or("PoCI: not an ObenBlock chain")?;
    if final_by_definition(&pp, f) {
        return Err("checkpoint is final by definition (genesis or the PoCI launch checkpoint): no certificate".into());
    }
    if f.height > tip_state.finalized.height
        || (DagChainView { dag, start: Some(*tip) }).selected_at(f.height) != Some(f.hash)
    {
        return Err("checkpoint is not finalized on this node's selected chain".into());
    }
    if let Some(k) = load(store, &f.hash) {
        return Ok(k);
    }
    // The block that finalized it lies at most `vote_ttl` above its child
    // slot: the lowest one whose state carries `f`.
    let t = f.height + pp.checkpoint_interval;
    let tip_h = dag.get_block_data(tip).map(|d| d.height).ok_or("tip not in the DAG")?;
    if tip_h < t {
        return Err("checkpoint is not finalized on this node's selected chain".into());
    }
    let mut chain = selected_chain_since(dag, Some(*tip), t);
    chain.reverse();
    if chain.first().map(|(_, h)| *h) != Some(t) {
        return Err("checkpoint is too deep below the tip to rebuild its certificate".into());
    }
    for (h, height) in chain.into_iter().take_while(|(_, h)| *h <= t + pp.vote_ttl) {
        let Some(st) = load_state(store, &h) else { continue };
        if st.finalized == *f && st.finalized_at == height {
            let k = build(dag, store, &h, &st)?;
            store_row(store, &k)?;
            return Ok(k);
        }
    }
    Err("checkpoint is not finalized on this node's selected chain".into())
}

fn hex32(v: &serde_json::Value) -> Option<Hash> {
    hex::decode(v.as_str()?).ok()?.try_into().ok()
}

/// `getfinalitycertificate [checkpoint]`: the certificate of a finalized
/// checkpoint, named by its slot (number) or hash (hex); without one, the
/// latest finalized checkpoint of the selected tip. With the registry proof
/// (§6) a verifier that trusts `config_id` checks it without the entries.
pub fn rpc_json(dag: &GhostDAG, store: &Storage, which: Option<&serde_json::Value>) -> serde_json::Value {
    use serde_json::json;
    let Some(pp) = params() else { return json!({ "error": "getfinalitycertificate: PoCI runs on ObenBlock only" }) };
    let Some(tip) = dag.selected_tip() else { return json!({ "error": "no tip" }) };
    let tip_h = dag.get_block_data(&tip).map(|d| d.height).unwrap_or(0);
    let Some((tip, st)) = selected_chain_since(dag, Some(tip), tip_h.saturating_sub(16)).into_iter()
        .find_map(|(h, _)| load_state(store, &h).map(|s| (h, s)))
    else {
        return json!({ "error": "no PoWit state at the tip yet" });
    };
    let view = DagChainView { dag, start: Some(tip) };
    let f = match which.filter(|v| !v.is_null()) {
        None => st.finalized,
        Some(v) => {
            if let Some(slot) = v.as_u64() {
                if !pp.is_slot(slot) {
                    return json!({ "error": format!("{slot} is not a checkpoint slot (every {})", pp.checkpoint_interval) });
                }
                if final_by_definition(&pp, &Checkpoint { height: slot, hash: [0; 32] }) {
                    return json!({ "error": "checkpoint is final by definition (genesis or the PoCI launch \
                                             checkpoint): no certificate" });
                }
                match view.selected_at(slot) {
                    Some(hash) => Checkpoint { height: slot, hash },
                    None => return json!({ "error": "slot not on the selected chain" }),
                }
            } else if let Some(hash) = hex32(v) {
                // A checkpoint's hash is the highest selected-chain block
                // strictly below its slot: the next slot above its height.
                let Some(h) = dag.get_block_data(&hash).map(|d| d.height) else {
                    return json!({ "error": "unknown block" });
                };
                let slot = (h / pp.checkpoint_interval + 1) * pp.checkpoint_interval;
                if view.selected_at(slot) != Some(hash) {
                    return json!({ "error": "block is not a checkpoint of the selected chain" });
                }
                Checkpoint { height: slot, hash }
            } else {
                return json!({ "error": "usage: getfinalitycertificate [slot | checkpoint hash]" });
            }
        }
    };
    match lookup(dag, store, &tip, &st, &f) {
        Ok(k) => certificate_json(dag, &k, true),
        Err(e) => json!({ "error": e, "checkpoint": { "slot": f.height, "hash": hex::encode(f.hash) } }),
    }
}

/// JSON of a kept certificate (`full`: with the wire bytes and the registry
/// proof).
pub fn certificate_json(dag: &GhostDAG, k: &KeptCertificate, full: bool) -> serde_json::Value {
    use serde_json::json;
    let c = &k.certificate;
    let cp = |x: &Checkpoint| json!({
        "slot": x.height, "hash": hex::encode(x.hash),
        "block_height": dag.get_block_data(&x.hash).map(|d| d.height) });
    let mut out = json!({
        "version": c.version,
        "chain_id": c.chain_id,
        "checkpoint": cp(&c.source),
        "target": cp(&c.target),
        "config_id": hex::encode(c.config_id),
        "config_epoch": k.config.epoch(),
        // u128 as decimal strings (JSON numbers lose precision).
        "config_total": k.config.total().to_string(),
        "config_entries": k.config.len(),
        "votes": c.votes.len(),
        "signed_weight": k.signed_weight().to_string(),
        "finalized_by": hex::encode(k.finalized_by),
        "finalized_at": k.finalized_at,
        "hands_off_to": k.next_config_id.map(hex::encode),
        "size": k.size,
    });
    if full {
        let voters: Vec<KeyId> = c.votes.iter().map(|(p, _)| p.witness_id()).collect();
        out["certificate"] = json!(hex::encode(c.encode()));
        out["registry_proof"] = json!(k.config.registry_proof(&voters).map(|p| hex::encode(p.encode())));
    }
    out
}
