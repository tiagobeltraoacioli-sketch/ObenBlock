//! ObenBlock finalized checkpoints anchored in Bloch, node side (phase 1).
//!
//! See `docs/OBB-ANCHOR.md` and `docs/DESIGN-obenblock.md` §8. The record
//! format is `gnb_crypto::obb_anchor`. This module supplies what needs the
//! DAG and storage:
//!
//! - [`epoch_anchors`]: the anchor records of the node's own finalized
//!   chain, one per epoch (`getfinalityanchors`; the `obenblock-anchor`
//!   daemon publishes them).
//! - [`AnchorReader`]: where the node reads the anchors Bloch has finalized
//!   (`--bloch-rpc`): [`BlochRpcReader`] speaks the registry's JSON-RPC
//!   interface; tests use [`MockReader`].
//! - [`check`]: the newest anchor is **advisory only**
//!   (docs/DESIGN-obenblock.md §8, owner decision 2026-10-18). A record
//!   carries no proof that W finalized it, anyone with a Bloch account can
//!   publish first, and the answer comes from one unauthenticated JSON-RPC
//!   call; so an anchor never sets a checkpoint by itself. The node only
//!   compares it with its own chain: an anchor its finalized chain contains
//!   is reported as corroboration; one ahead of its finality on its selected
//!   chain as agreement; one that contradicts its finality or its selected
//!   chain, or whose block it does not have, raises the conflict alert
//!   (`getblochanchor`, the `bloch_anchor` field of `getfinalityinfo`, an
//!   error log line, the `gnb_bloch_anchor_conflict` metric) and the
//!   operator decides with `setfinalitycheckpoint` / `ignorefinalized`.
//!   Nothing here pins, invalidates or persists anything fork choice reads.
//!
//! Nothing here is a consensus rule: a node without `--bloch-rpc` behaves
//! exactly as before.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde_json::{json, Value};
use tracing::{error, info, warn};

use crate::consensus::GhostDAG;
use crate::storage::Storage;
use gnb_crypto::core::activation;
use gnb_crypto::core::powit::{self, Checkpoint, PowitState, Regime};
use gnb_crypto::obb_anchor::{self, AnchorRecord, RECORD_LEN};

type Hash = [u8; 32];

/// PoWit states one [`epoch_anchors`] call may read (each is one stored
/// state decode): about ten epochs of finalized checkpoints at the mainnet
/// cadence (12 checkpoints an epoch, one read each, plus one per anchor).
pub const MAX_STATE_READS: usize = 128;

/// Records one call returns at most.
pub const MAX_ANCHORS_PER_CALL: usize = 32;

/// Largest registry answer the reader accepts.
const MAX_REGISTRY_RESPONSE: usize = 64 * 1024;


// ── Records from the node's own finality ─────────────────────────────────────

/// One anchor with what was hashed into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltAnchor {
    pub record: AnchorRecord,
    pub epoch: u64,
    /// The block whose state first finalized the checkpoint (`finalized_at`).
    pub finalizing_block: Hash,
    /// The checkpoint that justification finalized it (its epoch's witness
    /// set is the digested one).
    pub justified: Checkpoint,
    pub w_size: usize,
    pub w_total: u128,
}

/// Result of [`epoch_anchors`].
#[derive(Clone, Debug, Default)]
pub struct AnchorScan {
    /// Ascending by slot.
    pub anchors: Vec<BuiltAnchor>,
    /// False when the read budget ran out before `from_epoch` (or the
    /// activation checkpoint) was reached: older anchors exist but were not
    /// built.
    pub complete: bool,
}

/// The selected-chain block of `start`'s chain (inclusive) at exactly DAG
/// height `height`, if there is one.
fn chain_block_at(dag: &GhostDAG, start: Hash, height: u64) -> Option<Hash> {
    let mut cur = Some(start);
    while let Some(h) = cur {
        let d = dag.get_block_data(&h)?;
        if d.height == height {
            return Some(h);
        }
        if d.height < height {
            return None;
        }
        cur = d.selected_parent;
    }
    None
}

/// The block slot `slot` names on `start`'s selected chain (inclusive): the
/// highest one with height below `slot` (`powit::ChainView`), and the chain
/// block right above it, if `start` is at or above the slot.
fn slot_block(dag: &GhostDAG, start: Hash, slot: u64) -> Option<(Hash, Option<Hash>)> {
    let mut above = None;
    let mut cur = Some(start);
    while let Some(h) = cur {
        let d = dag.get_block_data(&h)?;
        if d.height < slot {
            return Some((h, above));
        }
        above = Some(h);
        cur = d.selected_parent;
    }
    None
}

/// The anchor records of the node's finalized chain, for the epochs from
/// `from_epoch`, at most `count` (newest kept when there are more).
///
/// For epoch `e` the record is the first checkpoint with a slot in `e` that
/// the chain finalized (the epoch-boundary slot when finality reached it, the
/// next one otherwise; an epoch in which no checkpoint was finalized has no
/// record). `finalized_at` is the height of the block whose state first holds
/// it as finalized, and `w_digest` digests that state's witness set of the
/// epoch of its justified checkpoint (the vote that finalized it):
/// `witness_set_in(epoch(justified), Regime::at(finalized_at))`. That state
/// has just reset inactivity decay (finality advanced), so the weights are
/// the undecayed window weights of the unbarred keys.
///
/// Only blocks at or below the node's pinned finalized checkpoint are read,
/// so every record is fixed: the block that finalized it can no longer be
/// reorganized away, and every node on this chain builds the same bytes.
/// The walk goes back from the pinned block through `finalized_at` links,
/// reading one stored PoWit state per finalized checkpoint plus one per
/// record, at most [`MAX_STATE_READS`].
pub fn epoch_anchors(dag: &GhostDAG, store: &Storage, from_epoch: u64, count: usize) -> Result<AnchorScan, String> {
    epoch_anchors_within(dag, store, from_epoch, count, MAX_STATE_READS)
}

/// [`epoch_anchors`] with an explicit read budget.
fn epoch_anchors_within(dag: &GhostDAG, store: &Storage, from_epoch: u64, count: usize, budget: usize)
    -> Result<AnchorScan, String>
{
    let count = count.clamp(1, MAX_ANCHORS_PER_CALL);
    let Some((top, _)) = dag.finalized() else {
        return Ok(AnchorScan { anchors: Vec::new(), complete: true });
    };
    if !dag.has_block(&top) {
        return Err("the finalized checkpoint's block is not in the DAG".into());
    }
    let p = powit::params();
    let h2 = activation::hardening2_activation_height();
    let chain_id = gnb_crypto::core::node_chain_id().to_u32();
    let reads = std::cell::Cell::new(0usize);
    let read = |h: &Hash| -> Result<Option<PowitState>, String> {
        reads.set(reads.get() + 1);
        Ok(crate::powit::load_state(store, h))
    };
    let Some(mut st) = read(&top)? else {
        // Below activation, or a pin taken from a Bloch anchor whose state
        // this node has not computed: nothing to build from.
        return Ok(AnchorScan { anchors: Vec::new(), complete: true });
    };
    let mut cur = top;
    let mut out: Vec<BuiltAnchor> = Vec::new();
    let complete = loop {
        let act = st.activation;
        let c = st.finalized;
        if c.height <= act {
            break true; // the activation checkpoint: final by definition, never anchored
        }
        let epoch = p.epoch(act, c.height);
        if epoch < from_epoch {
            break true;
        }
        if reads.get() >= budget {
            break false;
        }
        let b = chain_block_at(dag, cur, st.finalized_at)
            .ok_or_else(|| format!("no selected-chain block at finalized_at {} below {}", st.finalized_at,
                                   hex::encode(&cur[..8])))?;
        let parent = dag.get_block_data(&b).and_then(|d| d.selected_parent)
            .ok_or("finalizing block without a selected parent")?;
        let parent_h = dag.get_block_data(&parent).map(|d| d.height).ok_or("unknown selected parent")?;
        // The finalized checkpoint before this one (the activation checkpoint
        // below activation).
        let older = if parent_h < act {
            None
        } else {
            let ps = read(&parent)?.ok_or_else(|| format!("missing PoWit state of {}", hex::encode(&parent[..8])))?;
            Some(ps)
        };
        let older_cp = older.as_ref().map(|s| s.finalized).unwrap_or(Checkpoint { height: act, hash: [0; 32] });
        let starts_epoch = older_cp.height <= act || p.epoch(act, older_cp.height) < epoch;
        if starts_epoch {
            let sb = if b == cur { st.clone() } else {
                read(&b)?.ok_or_else(|| format!("missing PoWit state of {}", hex::encode(&b[..8])))?
            };
            if sb.finalized != c || sb.finalized_at != st.finalized_at {
                return Err(format!("PoWit state of {} does not hold the checkpoint it finalized", hex::encode(&b[..8])));
            }
            let je = p.epoch(act, sb.justified.height);
            let w = sb.witness_set_in(&p, je, Regime::at(sb.finalized_at, h2));
            let w_total = w.iter().fold(0u128, |a, (_, x)| a.saturating_add(*x));
            let record = AnchorRecord {
                chain_id,
                slot: c.height,
                block_id: c.hash,
                finalized_at: sb.finalized_at,
                w_digest: obb_anchor::w_digest(&w)?,
            };
            record.check()?;
            out.push(BuiltAnchor { record, epoch, finalizing_block: b, justified: sb.justified, w_size: w.len(), w_total });
            if out.len() >= count {
                break older_cp.height <= act;
            }
        }
        match older {
            Some(s) => {
                st = s;
                cur = parent;
            }
            None => break true,
        }
    };
    out.reverse();
    Ok(AnchorScan { anchors: out, complete })
}

/// JSON form of a record (RPC, daemon, docs/OBB-ANCHOR.md).
pub fn record_json(r: &AnchorRecord) -> Value {
    json!({
        "chain_id": r.chain_id,
        "slot": r.slot,
        "block_id": hex::encode(r.block_id),
        "finalized_at": r.finalized_at,
        "w_digest": hex::encode(r.w_digest),
        "record": hex::encode(r.encode()),
        "record_id": hex::encode(r.record_id()),
    })
}

/// `getfinalityanchors [from_epoch, count]`.
pub fn anchors_json(dag: &GhostDAG, store: &Storage, from_epoch: u64, count: usize) -> Value {
    match epoch_anchors(dag, store, from_epoch, count) {
        Ok(scan) => json!({
            "chain_id": gnb_crypto::core::node_chain_id().to_u32(),
            "finalized": dag.finalized().map(|(h, height)| json!({ "hash": hex::encode(h), "height": height })),
            "complete": scan.complete,
            "anchors": scan.anchors.iter().map(|a| {
                let mut v = record_json(&a.record);
                v["epoch"] = a.epoch.into();
                v["finalizing_block"] = hex::encode(a.finalizing_block).into();
                v["justified"] = json!({ "slot": a.justified.height, "hash": hex::encode(a.justified.hash) });
                v["w_size"] = a.w_size.into();
                v["w_total"] = a.w_total.to_string().into();
                v
            }).collect::<Vec<_>>(),
        }),
        Err(e) => json!({ "error": e }),
    }
}

// ── Reading Bloch's anchors ──────────────────────────────────────────────────

pub type ReadFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<AnchorRecord>, String>> + Send + 'a>>;

/// A source of the anchors Bloch has finalized for a chain.
pub trait AnchorReader: Send + Sync {
    /// The newest finalized anchor for `chain_id` (highest slot), if any.
    fn latest(&self, chain_id: u32) -> ReadFuture<'_>;
    /// For logs and `getblochanchor`.
    fn describe(&self) -> String;
}

/// Parse a registry entry (`obbanchor_latest` / `obbanchor_get` result,
/// docs/OBB-ANCHOR.md): `null`, or an object whose `record` is the 84-byte
/// record in hex and whose `bloch.finalized` is `true`. The record is
/// authoritative; the convenience fields, when present, must agree with it.
pub fn parse_registry_entry(v: &Value, chain_id: u32) -> Result<Option<AnchorRecord>, String> {
    if v.is_null() {
        return Ok(None);
    }
    let raw = v.get("record").and_then(Value::as_str).ok_or("registry entry without a record")?;
    if raw.len() != RECORD_LEN * 2 {
        return Err("registry record: wrong length".into());
    }
    let bytes = hex::decode(raw).map_err(|_| "registry record: not hex")?;
    let r = AnchorRecord::decode(&bytes)?;
    if r.chain_id != chain_id {
        return Err(format!("registry record for chain {:#x}, expected {:#x}", r.chain_id, chain_id));
    }
    if v.get("bloch").and_then(|b| b.get("finalized")).and_then(Value::as_bool) != Some(true) {
        return Err("registry entry is not final on Bloch".into());
    }
    let agrees = |k: &str, want: Value| v.get(k).is_none_or(|x| *x == want);
    if !agrees("chain_id", r.chain_id.into()) || !agrees("slot", r.slot.into())
        || !agrees("block_id", hex::encode(r.block_id).into())
        || !agrees("finalized_at", r.finalized_at.into())
        || !agrees("w_digest", hex::encode(r.w_digest).into())
    {
        return Err("registry entry fields disagree with its record".into());
    }
    Ok(Some(r))
}

/// `--bloch-rpc` must be `https://`, or plain `http://` to a loopback host
/// (`localhost`, `127.0.0.0/8`, `::1`): the answer is unauthenticated, so
/// it may not cross a network in the clear.
pub fn check_bloch_rpc_url(u: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(u).map_err(|_| "--bloch-rpc must be an https:// URL".to_string())?;
    match url.scheme() {
        "https" if url.host().is_some() => Ok(()),
        "http" => {
            let host = url.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']');
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
            if loopback {
                Ok(())
            } else {
                Err("--bloch-rpc: plain http:// is allowed only to a loopback host; use https://".into())
            }
        }
        _ => Err("--bloch-rpc must be an https:// URL (or http:// to a loopback host)".into()),
    }
}

/// The registry's JSON-RPC 2.0 interface on the operator's own Bloch node.
pub struct BlochRpcReader {
    url: String,
    http: reqwest::Client,
}

impl BlochRpcReader {
    pub fn new(url: &str, timeout: Duration) -> Result<Self, String> {
        let u = url.trim();
        check_bloch_rpc_url(u)?;
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.without_url().to_string())?;
        Ok(BlochRpcReader { url: u.to_string(), http })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut resp = self.http.post(&self.url).json(&body).send().await
            .map_err(|e| format!("bloch rpc: {}", e.without_url()))?;
        if !resp.status().is_success() {
            return Err(format!("bloch rpc: HTTP {}", resp.status()));
        }
        if resp.content_length().is_some_and(|n| n > MAX_REGISTRY_RESPONSE as u64) {
            return Err("bloch rpc: response too large".into());
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("bloch rpc: {}", e.without_url()))? {
            if buf.len() + chunk.len() > MAX_REGISTRY_RESPONSE {
                return Err("bloch rpc: response too large".into());
            }
            buf.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&buf).map_err(|_| "bloch rpc: response is not JSON")?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            let msg = e.get("message").and_then(Value::as_str).unwrap_or("");
            return Err(format!("bloch rpc: error {}: {}", e.get("code").unwrap_or(&Value::Null),
                               crate::network::truncate_utf8(msg, 120)));
        }
        v.get("result").cloned().ok_or_else(|| "bloch rpc: response without result".into())
    }
}

impl AnchorReader for BlochRpcReader {
    fn latest(&self, chain_id: u32) -> ReadFuture<'_> {
        Box::pin(async move {
            let v = self.call("obbanchor_latest", json!([chain_id])).await?;
            parse_registry_entry(&v, chain_id)
        })
    }

    fn describe(&self) -> String {
        self.url.clone()
    }
}

/// A fixed answer, for tests (the binary itself never builds one).
#[allow(dead_code)]
pub struct MockReader {
    pub answer: Mutex<Result<Option<AnchorRecord>, String>>,
}

#[allow(dead_code)]
impl MockReader {
    pub fn new(answer: Result<Option<AnchorRecord>, String>) -> Self {
        MockReader { answer: Mutex::new(answer) }
    }
}

impl AnchorReader for MockReader {
    fn latest(&self, chain_id: u32) -> ReadFuture<'_> {
        let a = self.answer.lock().clone();
        Box::pin(async move {
            match a {
                Ok(Some(r)) if r.chain_id != chain_id => Err("mock: other chain".into()),
                other => other,
            }
        })
    }

    fn describe(&self) -> String {
        "mock".into()
    }
}

// ── The advisory anchor ──────────────────────────────────────────────────────

/// What the newest anchor says about the node's chain. Advisory only: no
/// verdict changes fork choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The node's own finalized chain names the anchor's block at its slot:
    /// Bloch corroborates the node's finality.
    Consistent,
    /// The slot is above the node's own finality and the anchor's block is
    /// on the node's selected chain: the anchor agrees with the chain the
    /// node follows, which its own PoWit finality has not reached yet.
    Ahead,
    /// The anchor contradicts the node's own finality or its selected chain
    /// (or is malformed for this DAG): conflict alert; nothing changed, the
    /// operator decides.
    Conflict(String),
    /// The anchor's block is not in the node's DAG: conflict alert (the node
    /// may be behind, or on another chain); nothing changed, the operator
    /// decides.
    Unknown(String),
}

impl Verdict {
    /// Whether this verdict raises the conflict alert.
    pub fn is_alert(&self) -> bool {
        matches!(self, Verdict::Conflict(_) | Verdict::Unknown(_))
    }

    fn label(&self) -> &'static str {
        match self {
            Verdict::Consistent => "consistent",
            Verdict::Ahead => "ahead",
            Verdict::Conflict(_) => "conflict",
            Verdict::Unknown(_) => "unknown",
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Verdict::Conflict(m) | Verdict::Unknown(m) => Some(m),
            _ => None,
        }
    }
}

/// Compare anchor `r` with `dag`; pure, under the caller's read lock, and
/// read-only: the anchor is advisory (module docs).
pub fn check(dag: &GhostDAG, r: &AnchorRecord) -> Verdict {
    let (a, s) = (r.block_id, r.slot);
    let fin = dag.finalized().filter(|(h, _)| dag.has_block(h));
    if let Some((fh, _)) = fin {
        let fheight = dag.get_block_data(&fh).map(|d| d.height).unwrap_or(0);
        if fheight >= s {
            return match slot_block(dag, fh, s) {
                Some((named, _)) if named == a => Verdict::Consistent,
                Some((named, _)) => Verdict::Conflict(format!(
                    "the node's finalized chain names {} at slot {s}, the Bloch anchor {}",
                    hex::encode(named), hex::encode(a))),
                None => Verdict::Conflict(format!("slot {s} is not on the node's finalized chain")),
            };
        }
    }
    let Some(ad) = dag.get_block_data(&a) else {
        return Verdict::Unknown(format!("the Bloch anchor's block {} at slot {s} is not in this node's DAG",
                                        hex::encode(a)));
    };
    if ad.height >= s {
        return Verdict::Conflict(format!(
            "the Bloch anchor's block {} has height {} and cannot be named by slot {s}", hex::encode(a), ad.height));
    }
    if let Some((fh, _)) = fin {
        if !dag.is_on_selected_chain_of(&fh, &a) {
            return Verdict::Conflict(format!(
                "the Bloch anchor {} at slot {s} does not descend from the node's finalized checkpoint {}",
                hex::encode(a), hex::encode(fh)));
        }
    }
    // The slot is above the node's finality: the anchor agrees iff the
    // selected chain names its block at the slot.
    match dag.selected_tip().and_then(|tip| slot_block(dag, tip, s)) {
        Some((named, _)) if named == a => Verdict::Ahead,
        Some((named, Some(_))) => Verdict::Conflict(format!(
            "the node's selected chain names {} at slot {s}, the Bloch anchor {}", hex::encode(named), hex::encode(a))),
        _ => Verdict::Conflict(format!(
            "the Bloch anchor {} at slot {s} is not the block the node's selected chain names there", hex::encode(a))),
    }
}

/// The node's anchor state, for `getblochanchor` and `getfinalityinfo`.
#[derive(Clone, Debug, Default)]
pub struct AnchorStatus {
    pub source: Option<String>,
    /// The newest registry answer taken this run (memory only: nothing about
    /// an anchor is persisted).
    pub anchor: Option<AnchorRecord>,
    pub verdict: Option<Verdict>,
    pub last_poll: Option<u64>,
    pub last_error: Option<String>,
    /// A registry answer for the anchored slot with other bytes, or an
    /// older slot than the anchor already held.
    pub registry_alarm: Option<String>,
    /// The highest slot the registry corroborated (`Consistent`).
    pub corroborated_slot: Option<u64>,
}

static STATUS: Mutex<Option<AnchorStatus>> = parking_lot::const_mutex(None);

fn with_status<R>(f: impl FnOnce(&mut AnchorStatus) -> R) -> R {
    let mut g = STATUS.lock();
    f(g.get_or_insert_with(AnchorStatus::default))
}

/// `getblochanchor`, and the `bloch_anchor` field of `getfinalityinfo`.
pub fn status_json() -> Value {
    let s = STATUS.lock().clone().unwrap_or_default();
    json!({
        "enabled": s.source.is_some(),
        "advisory": true,
        "source": s.source,
        "anchor": s.anchor.as_ref().map(record_json),
        "status": s.verdict.as_ref().map_or("none", Verdict::label),
        "alert": s.verdict.as_ref().is_some_and(Verdict::is_alert) || s.registry_alarm.is_some(),
        "detail": s.verdict.as_ref().and_then(Verdict::detail),
        "corroborated_slot": s.corroborated_slot,
        "last_poll": s.last_poll,
        "last_error": s.last_error,
        "registry_alarm": s.registry_alarm,
    })
}

/// Take `fresh` (from Bloch) against the anchor already held this run: a
/// newer slot replaces it; the same record is kept; an older slot or other
/// bytes for the same slot are refused and raise the registry alarm.
/// Returns the anchor to compare. Pure (nothing is persisted).
pub fn accept_fresh(held: Option<AnchorRecord>, fresh: AnchorRecord) -> (Option<AnchorRecord>, Option<String>) {
    match held {
        Some(h) if h == fresh => (Some(h), None),
        Some(h) if fresh.slot < h.slot => (Some(h), Some(format!(
            "the Bloch registry's newest anchor (slot {}) is older than the one held (slot {})", fresh.slot, h.slot))),
        Some(h) if fresh.conflicts_with(&h) => (Some(h), Some(format!(
            "the Bloch registry answered record {} for slot {}, the node holds {}",
            hex::encode(fresh.record_id()), h.slot, hex::encode(h.record_id())))),
        _ => (Some(fresh), None),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn note_verdict(r: &AnchorRecord, v: &Verdict) {
    let (changed, alarm) = with_status(|s| {
        let changed = s.anchor != Some(*r) || s.verdict.as_ref() != Some(v);
        s.anchor = Some(*r);
        s.verdict = Some(v.clone());
        if *v == Verdict::Consistent {
            s.corroborated_slot = Some(s.corroborated_slot.map_or(r.slot, |c| c.max(r.slot)));
        }
        (changed, s.registry_alarm.is_some())
    });
    crate::metrics::set_bloch_anchor_conflict(v.is_alert() || alarm);
    if *v == Verdict::Consistent {
        crate::metrics::set_bloch_anchor_corroborated_slot(r.slot);
    }
    if !changed {
        return;
    }
    match v {
        Verdict::Conflict(m) | Verdict::Unknown(m) => error!(
            "BLOCH ANCHOR CONFLICT at slot {}: {m}. The anchor is advisory: nothing was changed; the operator \
             decides with setfinalitycheckpoint / ignorefinalized (docs/OBB-ANCHOR.md)", r.slot),
        Verdict::Ahead => info!("bloch anchor: slot {} block {} is on the selected chain, above own finality",
                                r.slot, hex::encode(&r.block_id[..8])),
        Verdict::Consistent => info!("bloch anchor: slot {} block {} corroborates the node's finalized chain",
                                     r.slot, hex::encode(&r.block_id[..8])),
    }
}

/// Start-up: record the source (`getblochanchor` reports it enabled).
pub fn restore(source: String) {
    with_status(|s| s.source = Some(source));
}

/// Take one registry answer: keep the newest anchor of this run and compare
/// it with the node's chain. Read-only on the DAG.
pub fn take_answer(res: Result<Option<AnchorRecord>, String>, source: &str, dag: &RwLock<GhostDAG>) {
    let chain_id = gnb_crypto::core::node_chain_id().to_u32();
    let held = with_status(|s| {
        s.last_poll = Some(now_secs());
        s.anchor.filter(|r| r.chain_id == chain_id)
    });
    let anchor = match res {
        Ok(Some(fresh)) if fresh.chain_id == chain_id => {
            with_status(|s| s.last_error = None);
            let (a, alarm) = accept_fresh(held, fresh);
            if let Some(m) = &alarm {
                error!("bloch anchor registry alarm: {m}");
            }
            with_status(|s| s.registry_alarm = alarm);
            a
        }
        Ok(Some(other)) => {
            let e = format!("anchor for chain {:#x}, expected {:#x}", other.chain_id, chain_id);
            warn!("bloch anchor: {source}: {e}");
            with_status(|s| s.last_error = Some(e));
            held
        }
        Ok(None) => {
            with_status(|s| s.last_error = None);
            held
        }
        Err(e) => {
            warn!("bloch anchor: {source}: {e}");
            with_status(|s| s.last_error = Some(e));
            held
        }
    };
    if let Some(r) = anchor {
        // Once the node's finalized chain contains the anchor it always will:
        // skip the re-check, whose walk grows with the distance to the pin.
        if with_status(|s| s.anchor == Some(r) && s.verdict == Some(Verdict::Consistent)) {
            return;
        }
        let v = check(&dag.read(), &r);
        note_verdict(&r, &v);
    }
}

/// The poller `main` spawns for `--bloch-rpc`: read the newest anchor every
/// `every`, then compare it on the blocking pool.
pub async fn run(reader: Box<dyn AnchorReader>, every: Duration, dag: std::sync::Arc<RwLock<GhostDAG>>) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let res = reader.latest(gnb_crypto::core::node_chain_id().to_u32()).await;
        let (dag, source) = (dag.clone(), reader.describe());
        if let Err(e) = tokio::task::spawn_blocking(move || take_answer(res, &source, &dag)).await {
            error!("bloch anchor: poll task failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests;
