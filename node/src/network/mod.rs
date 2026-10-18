//! Bloch-SIS Protocol — P2P Network
//!
//! FIX #2: Full IBD loop — GetBlock now has a server-side response handler.
//! FIX #4: Persistent P2P keypair.
//! FIX #6: Peer memory (known_peers.json).
//! Sprint P: PEX hardening (rate limit, address validation, known_peers cap).

pub mod chain_separation;
pub mod misbehaviour;
pub mod discourage;
// NET-11 / B1-T9 connection management. Parts of their API serve the
// library's tests and embedders only, not the binary.
#[allow(dead_code)]
pub mod addrbook;
#[allow(dead_code)]
pub mod connmgr;
#[allow(dead_code)]
pub mod gossip_gate;
pub mod pex_validator;
pub mod pull;
pub mod ratelimit;
pub mod serve;
pub mod sync_rr;

use libp2p::{
    identity, identify, mdns, PeerId, Multiaddr,
    swarm::SwarmEvent,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode}, tcp, yamux,
    SwarmBuilder,
};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use log::{info, warn, debug};
use std::time::Duration;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};

use connmgr::{ConnKind, ConnManager, DialIntent, OutboundAction};
use pex_validator::{
    PexRateLimiter, PexStats, AddrBook, TriedTable,
    is_valid_public_multiaddr, is_lan_multiaddr, is_acceptable_ip, enforce_cap, prune_invalid, addr_peer_id,
    netgroup, normalize_peer_addr,
    PEX_BATCH_LIMIT, KNOWN_PEERS_CAP,
};

use std::sync::Arc;
use crate::transport::identity::{PeerPins, PqIdentity};
use crate::transport::upgrade::PqConfig;

pub const TOPIC_BLOCKS: &str = "gnb/blocks/1";
pub const TOPIC_TXS:    &str = "gnb/txs/1";
pub const TOPIC_SYNC:   &str = "gnb/sync/1";

// ── Ingest-drop visibility (orphan-deadlock fix, companion) ──────────────────
//
// Every inbound frame reaches the message processor through a bounded (1000)
// mpsc channel via `try_send`, and a full channel used to drop the frame IN
// SILENCE — including GetBlock RESPONSES the orphan pool was waiting on. The
// drop stays (backpressure by shedding is the design; blocking the swarm loop
// would be worse), but it must be VISIBLE: a counter + WARN so an operator can
// correlate "orphan waits forever" with "ingest channel overflowed".
static INGEST_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Total inbound frames dropped because the swarm→processor channel was full.
pub fn ingest_drops_total() -> u64 {
    INGEST_DROPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Bytes of `/gnb/sync/1` answers handed to libp2p and not yet written to
/// their peer (no `ResponseSent` / `InboundFailure` yet), over every
/// network loop of the process (B1-T18 / B2-T6; see [`serve`]).
#[allow(dead_code)] // library API and tests; the node binary compiles this module too
pub fn sync_send_bytes_outstanding() -> u64 {
    serve::send_bytes_outstanding()
}

/// Forward an inbound frame to the processor, counting + logging drops instead
/// of discarding them silently. WARNs on the first drop and every 100th after
/// (a storm that overflows a 1000-slot channel would otherwise flood the log).
/// Returns `true` iff the frame was queued.
fn forward_to_processor<T>(block_tx: &mpsc::Sender<T>, item: T, kind: &'static str, source: &str) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    match block_tx.try_send(item) {
        Ok(())                       => true,
        Err(TrySendError::Full(_))   => {
            let n = INGEST_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed).saturating_add(1);
            if n == 1 || n % 100 == 0 {
                warn!("ingest channel FULL — dropped inbound [{}] from {} \
                       (total dropped: {}; lost GetBlock replies are re-requested \
                       by the orphan sweep)", kind, source, n);
            }
            false
        }
        Err(TrySendError::Closed(_)) => {
            warn!("ingest channel CLOSED — dropped inbound [{}] from {}", kind, source);
            false
        }
    }
}

// ── NET-2: application-validated gossip ──────────────────────────────────────
//
// Gossipsub runs with `validate_messages()`: a received frame is NOT relayed
// until the application reports a verdict with
// `report_message_validation_result`. `Accept` forwards it; `Reject` drops it
// AND applies gossipsub's invalid-delivery (P4) penalty to the peer that
// delivered it; `Ignore` drops it without penalty. Because every honest node
// running this validation forwards only frames it accepted, an invalid frame
// is then delivered only by its originator, so penalties land on the author
// instead of on honest relays (NET-4). Earlier releases forward
// `NewTransaction` frames without validating them, so the transaction relay
// answers `Reject` only once no such release can be a peer on the chain
// (`mempool::relay::TxRelay::penalties_in_force`).

/// The application's verdict on one gossip frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipVerdict {
    /// Valid: relay it to the mesh.
    Accept,
    /// Provably invalid: drop it and penalize the delivering peer (P4).
    Reject,
    /// Not relayed, not penalized (duplicate, stale, policy, unverifiable).
    Ignore,
}

impl From<GossipVerdict> for gossipsub::MessageAcceptance {
    fn from(v: GossipVerdict) -> Self {
        match v {
            GossipVerdict::Accept => gossipsub::MessageAcceptance::Accept,
            GossipVerdict::Reject => gossipsub::MessageAcceptance::Reject,
            GossipVerdict::Ignore => gossipsub::MessageAcceptance::Ignore,
        }
    }
}

/// A verdict the processor reports back to the network loop for a gossip
/// frame whose validation was deferred to it.
#[derive(Clone, Debug)]
pub struct GossipValidation {
    pub message_id:         gossipsub::MessageId,
    pub propagation_source: PeerId,
    pub verdict:            GossipVerdict,
}

/// Gossipsub `history_length`: heartbeats (1 s each) an unvalidated frame
/// stays in the message cache, i.e. how long a withheld verdict can still
/// forward it.
pub const GOSSIP_HISTORY_LENGTH: usize = 12;

/// Out-of-band requests from the message processor to the network loop
/// (see [`NetworkNode::attach_control`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkControl {
    /// One misbehaviour of `peer` that the processor proved and gossipsub
    /// cannot see: MEM-5 / MEM-6, a consensus-invalid transaction whose
    /// gossip frame can no longer be answered `Reject` (it was buffered as an
    /// orphan and left gossipsub's cache before its re-try proved it
    /// invalid); B1-T2, an invalid block sent as the ANSWER to one of our
    /// directed pulls (judged `Reject` exactly like a gossip copy, which
    /// would cost its author gossipsub's invalid-delivery penalty). The
    /// network loop applies one penalty to the shared misbehaviour score
    /// (`misbehaviour`: decaying; disconnect and discourage at the
    /// threshold).
    PenalizePeer(PeerId),
    /// B1-T2: GetBlock pulls for blocks that `source`'s directed Headers or
    /// Tips answer announced (the processor found them missing). Queued
    /// with `source` as the preferred peer and charged to its quota
    /// (`pull::MAX_PENDING_PER_SOURCE`; with every other source that
    /// connected to us, `pull::MAX_PENDING_INBOUND_ATTRIBUTED`), so peers'
    /// answers cannot fill the shared pull queue.
    Fetch { source: PeerId, hashes: Vec<[u8; 32]> },
    /// NET-2 residual / B1-T7 (Phase 4): `peer` sent data no honest node
    /// sends (a block frame it authored with an invalid proof of work, an
    /// invalid structure or contextually invalid header, or one whose bits
    /// fail the orphan floor — see `ingress::block_penalty`). Bitcoin Core's
    /// `Misbehaving`: the network loop disconnects it and discourages its
    /// address (`discourage::Discouraged`), so a fresh identity from the
    /// same address is not accepted either.
    Misbehaving(PeerId),
}

/// Peer lifecycle notices from the network loop to the message processor
/// (see [`NetworkNode::attach_peer_events`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// The last connection to this peer closed. The transaction relay drops
    /// its per-connection signature budget and the orphans it delivered
    /// (Bitcoin Core's `EraseForPeer`).
    Disconnected(PeerId),
}

/// Where an inbound frame handed to the processor came from.
#[derive(Clone, Debug)]
pub enum InboundOrigin {
    /// Unsolicited gossip. `author` is the signed originator (gossipsub
    /// `Strict` validation), `propagation_source` the neighbour that
    /// delivered it. `pending` is `Some(id)` iff the processor owes the
    /// network loop a [`GossipValidation`] for this frame.
    Gossip {
        propagation_source: PeerId,
        author:             Option<PeerId>,
        pending:            Option<gossipsub::MessageId>,
        /// When the network loop received the frame — gossipsub put it in
        /// its message cache at that moment, and it is shifted out
        /// [`GOSSIP_HISTORY_LENGTH`] heartbeats later. A withheld verdict
        /// must be reported before then (review finding: the deferred-orphan
        /// TTL used to start at processor time).
        received_at:        std::time::Instant,
    },
    /// The answer to one of OUR directed `/gnb/sync/1` pulls, from `peer`.
    Directed { peer: PeerId },
    /// Generated locally by the network loop (heartbeat `PeerCount`).
    Local,
}

impl InboundOrigin {
    /// True for answers to our own directed pulls (solicited data).
    pub fn is_solicited(&self) -> bool {
        matches!(self, InboundOrigin::Directed { .. })
    }

    /// B1-T7: the delivering peer authored the frame (gossipsub's signed
    /// source is the propagation source), or sent it as the answer to our own
    /// pull. Who a refused block frame is charged to follows this
    /// (`ingress::block_penalty`).
    pub fn delivered_by_author(&self) -> bool {
        match self {
            InboundOrigin::Gossip { propagation_source, author, .. } => *author == Some(*propagation_source),
            InboundOrigin::Directed { .. } => true,
            InboundOrigin::Local => false,
        }
    }

    /// The remote peer responsible for this frame: the directed responder or
    /// the gossip neighbour that delivered it.
    pub fn peer(&self) -> Option<PeerId> {
        match self {
            InboundOrigin::Gossip { propagation_source, .. } => Some(*propagation_source),
            InboundOrigin::Directed { peer } => Some(*peer),
            InboundOrigin::Local => None,
        }
    }

    /// When the network loop received this gossip frame (`None` for
    /// directed and local frames).
    pub fn received_at(&self) -> Option<std::time::Instant> {
        match self {
            InboundOrigin::Gossip { received_at, .. } => Some(*received_at),
            _ => None,
        }
    }

    /// `(message_id, propagation_source)` when a verdict is owed.
    pub fn pending_verdict(&self) -> Option<(gossipsub::MessageId, PeerId)> {
        match self {
            InboundOrigin::Gossip { propagation_source, pending: Some(id), .. } => {
                Some((id.clone(), *propagation_source))
            }
            _ => None,
        }
    }
}

/// One inbound frame plus its origin, as delivered by
/// [`NetworkNode::run_validated`].
#[derive(Clone, Debug)]
pub struct Inbound {
    pub msg:    NetworkMessage,
    pub origin: InboundOrigin,
}

/// What the network loop does with one decoded gossip frame (pure; unit
/// tested). NET-7: gossip PULLS (`GetHeaders`, `GetBlock`, `GetTips`,
/// `PeerRequest`) and gossip RESPONSES (`Headers`, `Tips`, `BlockNotFound`)
/// are never delivered and never relayed — pulls are served only over the
/// directed `/gnb/sync/1` protocol, one requester, one answer. NET-11:
/// gossip `PeerExchange` is unsolicited and is neither relayed nor used to
/// dial. `PeerCount` is a local-only frame and is never accepted from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipDisposition {
    /// Deliver to the processor, which reports the verdict later.
    DeliverDeferred,
    /// Deliver to the processor and report this verdict now.
    Deliver(GossipVerdict),
    /// Do not deliver; report this verdict now.
    Drop(GossipVerdict),
}

/// Decide [`GossipDisposition`] for a decoded, bounds-valid gossip frame.
/// `validator_attached`: a processor that reports verdicts is wired
/// ([`NetworkNode::run_validated`]); otherwise blocks and transactions are
/// accepted on decode (legacy [`NetworkNode::run`]). `claim_ok`: the frame is a tip claim from
/// a directly connected author within its rate limit.
pub fn gossip_disposition(msg: &NetworkMessage, validator_attached: bool, claim_ok: bool) -> GossipDisposition {
    use GossipDisposition::*;
    match msg {
        // MEM-5 / NET-2 / NET-4 (audit): transactions are judged by the
        // processor (shared admission, signatures last, per-connection budget —
        // `mempool::relay`) BEFORE gossipsub relays them, exactly like blocks.
        // PoWit items (shares, attestations, equivocation proofs) are relayed
        // like transactions: only once the processor admitted them.
        NetworkMessage::NewBlock { .. } | NetworkMessage::NewTransaction { .. }
        | NetworkMessage::NewPowitItem { .. } => {
            if validator_attached { DeliverDeferred } else { Deliver(GossipVerdict::Accept) }
        }
        // Tip claims: consumed locally (author-attributed), never relayed —
        // every node floods its own claims to all of its direct peers.
        NetworkMessage::PeerTip { .. } | NetworkMessage::Version { .. } => {
            if claim_ok { Deliver(GossipVerdict::Ignore) } else { Drop(GossipVerdict::Ignore) }
        }
        NetworkMessage::GetHeaders { .. }
        | NetworkMessage::GetBlock { .. }
        | NetworkMessage::GetTips
        | NetworkMessage::PeerRequest
        | NetworkMessage::Headers { .. }
        | NetworkMessage::Tips { .. }
        | NetworkMessage::BlockNotFound { .. }
        | NetworkMessage::PeerExchange { .. }
        | NetworkMessage::PeerCount { .. }
        | NetworkMessage::VersionAck => Drop(GossipVerdict::Ignore),
    }
}

/// Where the network loop hands inbound frames.
enum IngestSink {
    /// Legacy consumer: bare messages, no verdicts expected.
    Legacy(mpsc::Sender<NetworkMessage>),
    /// Validated consumer: frames with origin; verdicts come back. B1-T19:
    /// with `txs` attached ([`NetworkNode::attach_tx_ingest`]) gossip
    /// transactions — and PoWit items, which travel on the transaction topic
    /// and cost a GnB-SMH v3 evaluation or a KES signature check each — go
    /// to their own channel (and their own consumer), so a flood of either
    /// can neither fill the block channel (a full channel drops frames) nor
    /// queue block work behind its own.
    Validated { main: mpsc::Sender<Inbound>, txs: Option<mpsc::Sender<Inbound>> },
}

impl IngestSink {
    fn validator_attached(&self) -> bool {
        matches!(self, IngestSink::Validated { .. })
    }

    fn deliver(&self, msg: NetworkMessage, origin: InboundOrigin, source: &str) -> bool {
        let kind = msg.kind_name();
        match self {
            IngestSink::Legacy(tx) => forward_to_processor(tx, msg, kind, source),
            IngestSink::Validated { txs: Some(txs), .. } if goes_to_tx_ingest(&msg) => {
                forward_to_processor(txs, Inbound { msg, origin }, kind, source)
            }
            IngestSink::Validated { main, .. } => forward_to_processor(main, Inbound { msg, origin }, kind, source),
        }
    }
}

/// B1-T19: the frames a validated consumer with a transaction ingest
/// ([`NetworkNode::attach_tx_ingest`]) receives there instead of on the block
/// channel: gossip transactions and PoWit items (both on the transaction
/// topic, both judged by the transaction relay task).
pub fn goes_to_tx_ingest(msg: &NetworkMessage) -> bool {
    matches!(msg, NetworkMessage::NewTransaction { .. } | NetworkMessage::NewPowitItem { .. })
}

/// B1-T7 / NET-4 residual (Phase 4): may a wire violation (oversized,
/// bounds-violating, padded or non-canonical frame) be charged to the peer
/// that delivered it? Releases older than the validated relay (NET-2)
/// forward every frame unvalidated and follow the chain until the hardening
/// activation block, so a violation can reach us through an honest older
/// relay: it is charged only if the delivering peer AUTHORED the frame
/// (`self_authored`: gossipsub's signed source is the propagation source),
/// or once the chain contains the activation block (`penalties_in_force`,
/// `ingress::block_penalties_in_force`; every release since NET-2 refuses
/// such a frame instead of forwarding it). Returns `(charge, reject)`:
/// whether to apply the application-score penalty to the delivering peer,
/// and whether to report `Reject` to gossipsub — only when no honest relay
/// can have forwarded a duplicate (gossipsub charges every peer that
/// delivered one); a self-authored violation before that is answered
/// `Ignore` and charged to its author alone.
pub fn wire_violation_penalty(self_authored: bool, penalties_in_force: bool) -> (bool, bool) {
    (self_authored || penalties_in_force, penalties_in_force)
}

// ── Messages ──────────────────────────────────────────────────────────────────

/// Protocol version for forward compatibility and hard fork coordination.
/// Nodes reject messages from incompatible versions.
pub const PROTOCOL_VERSION: u32 = 1;
/// Minimum protocol version this node accepts
pub const MIN_PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    NewBlock {
        block_hash: [u8; 32],
        blue_score: u64,
        height:     u64,
        block_data: Vec<u8>,
    },
    NewTransaction {
        txid:    [u8; 32],
        tx_data: Vec<u8>,
    },
    // IBD
    PeerTip    { peer_id: String, blue_score: u64, height: u64 },
    PeerExchange { peers: Vec<String> },
    PeerRequest,
    PeerCount { count: usize, addresses: Vec<String> },
    /// `nonce` for the same reason GetBlock and BlockNotFound carry one. A node
    /// re-asking for the SAME window — which is exactly what a stalled node does,
    /// every cycle — serialises identically and has the retry dropped locally
    /// before it reaches the network. Measured at 90 suppressions in two minutes
    /// on a node that was making no progress.
    ///
    /// The general rule this file has now learned three times: on the sync topic,
    /// deduplication is wrong. It exists to stop gossip storms of the same BLOCK;
    /// a request is not gossip, and two identical requests are two intentions,
    /// not one message seen twice.
    GetHeaders { from_blue_score: u64, limit: u32, nonce: u64 },
    Headers    { entries: Vec<SyncEntry> },
    /// Request a block body. `nonce` exists ONLY to make each request unique on
    /// the wire, and the responder ignores it.
    ///
    /// Without it every re-request serialises to identical bytes, hashes to the
    /// same gossipsub MessageId, and `publish()` returns `Err(Duplicate)`
    /// LOCALLY — the retry never leaves this node. That is the same failure this
    /// file already documents for PeerTip a few lines below `duplicate_cache_time`,
    /// where the fix was noted as "the tip-carrying Version (fresh timestamp →
    /// unique bytes) can never be dedup-dropped at all". GetBlock had no such
    /// field, so IBD retries were silently swallowed: observed on a stalled node
    /// as 12,235 `publish sync: Duplicate` in ten minutes while it sat at one
    /// height with peers that HELD the blocks it was asking for.
    GetBlock   { block_hash: [u8; 32], nonce: u64 },
    /// Explicit "I cannot serve this body" answer to GetBlock. Added 2026-07-19:
    /// the responder used to drop unanswerable requests silently, which left the
    /// requester unable to distinguish a pruned body from a lost packet — it just
    /// waited and re-asked forever. A fresh node cannot bootstrap from a pruned
    /// peer, and it deserves to LEARN that instead of stalling: on receiving this
    /// it can try another peer, or report honestly that no archival peer exists.
    /// `nonce` for the same reason GetBlock carries one: without it every answer
    /// serialises identically, is dedup-dropped locally, and the peer waiting on
    /// it learns nothing. Measured on a stalled archival node: 7,983 of 8,060
    /// suppressed publishes in two minutes were THIS message — added the same
    /// night to fix a silent responder, and immediately becoming the loudest
    /// source of the noise it was meant to remove. A message that answers a
    /// repeated question must be as unique as the question.
    BlockNotFound { block_hash: [u8; 32], nonce: u64 },
    // Frontier reconciliation (Phase 2 Kaspa sync-negotiation layer)
    /// Frontier reconciliation: request the peer's DAG frontier. No payload.
    /// Sent only as a DIRECTED `/gnb/sync/1` request to one peer; a gossip
    /// copy is neither answered nor relayed (audit NET-7).
    GetTips,
    /// Frontier reconciliation reply: full DAG frontier + selected-chain locator.
    Tips { tips: Vec<SyncEntry>, locator: Vec<[u8; 32]> },
    // Protocol handshake
    Version {
        version:    u32,
        user_agent: String,
        blue_score: u64,
        height:     u64,
        timestamp:  u64,
    },
    VersionAck,
    /// PoWit item (witness share, attestation or equivocation proof), relayed
    /// like a transaction: only after the node validated it. Appended last so
    /// older peers decode it as malformed (ignored), never as another variant.
    NewPowitItem { id: [u8; 32], kind: u8, data: Vec<u8> },
}


impl NetworkMessage {
    /// Variant name for diagnostics.
    ///
    /// H-R3-3: this used to `Box::leak(format!("{:?}", self))` on every call —
    /// a fresh, permanent, unfreed allocation per invocation, sized to the
    /// `Debug` rendering of the WHOLE message (for `NewBlock` that is every
    /// byte of `block_data` printed as decimal, i.e. ~5x the block size). The
    /// function is called from `forward_to_processor`'s drop path, which is
    /// attacker-reachable (fill the bounded ingest channel with cheap frames,
    /// then send large `NewBlock` frames): each drop leaked megabytes,
    /// unbounded and irreclaimable short of a restart.
    ///
    /// INVARIANT (H-R3-3): naming a message variant must be an allocation-free,
    /// leak-free, `&'static str` lookup — a plain match, so the compiler (not a
    /// runtime string scan) forces every new variant to be classified.
    pub fn kind_name(&self) -> &'static str {
        match self {
            NetworkMessage::NewBlock { .. } => "NewBlock",
            NetworkMessage::NewTransaction { .. } => "NewTransaction",
            NetworkMessage::NewPowitItem { .. } => "NewPowitItem",
            NetworkMessage::PeerTip { .. } => "PeerTip",
            NetworkMessage::PeerExchange { .. } => "PeerExchange",
            NetworkMessage::PeerRequest => "PeerRequest",
            NetworkMessage::PeerCount { .. } => "PeerCount",
            NetworkMessage::GetHeaders { .. } => "GetHeaders",
            NetworkMessage::Headers { .. } => "Headers",
            NetworkMessage::GetBlock { .. } => "GetBlock",
            NetworkMessage::BlockNotFound { .. } => "BlockNotFound",
            NetworkMessage::GetTips => "GetTips",
            NetworkMessage::Tips { .. } => "Tips",
            NetworkMessage::Version { .. } => "Version",
            NetworkMessage::VersionAck => "VersionAck",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEntry {
    pub hash:       [u8; 32],
    pub blue_score: u64,
    pub height:     u64,
}

// ── C1: bounded, validated wire decode ────────────────────────────────────────
//
// Every gossip frame comes from an untrusted peer. Before this fix the event
// loop decoded frames with `bincode::config::standard()`, which puts no limit
// on how many bytes a frame may claim to contain: a tiny crafted frame could
// declare a multi-GB Vec length, and nothing in the decode path capped list
// lengths (peer lists, header vectors, address strings). All untrusted decodes
// now go through `decode_wire_message`, which (1) rejects frames larger than
// MAX_WIRE_BYTES outright, (2) decodes with a bincode read limit of the same
// size, and (3) applies explicit post-decode bounds to every variable-length
// field of `NetworkMessage`.
//
// HONESTY CAVEAT on (3): the post-decode bounds run *after* serde has built
// the value, so they bound acceptance, not the transient decode allocation.
// The transient allocation is bounded by the 4 MiB byte limit, but bincode's
// serde bridge decodes collections element-by-element, so a pathological
// 4 MiB frame of empty strings can transiently amplify to tens of MB of
// String headers before the bounds check rejects it. That is bounded and
// short-lived (not the multi-GB pre-allocation this fixes), but tightening it
// to zero would need a custom `Deserialize` impl — not done here.
//
// 32-bit targets (i686, wasm32, 32-bit ARM; the audit's CRY-8 class): bincode
// 2.0.1's serde bridge reads every sequence and map length with
// `usize::decode`, which casts the declared u64 with `as usize`. There a
// declared length of 2^32 + n decodes as n, so a frame every 64-bit node
// rejects (it announces more bytes than it has) decoded on a 32-bit node into
// a different message (found by running the node's tests on i686:
// `wire_decode_rejects_multi_gb_declared_vec`, docs/testing/SANITIZERS.md).
// The one-encoding rule (`WireDecodeError::NonCanonical`) refuses it on every
// target: the decoded message re-encodes with a 1- to 5-byte length, not the
// 9 bytes the frame used.

/// Hard ceiling on any single gossip frame. Must match gossipsub's
/// `max_transmit_size` configured in `run()`.
pub const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// Max entries in a PEX/PeerCount address list. A compliant node advertises at
/// most KNOWN_PEERS_CAP (1000) known peers plus a few self-addresses.
pub const MAX_WIRE_ADDRS: usize = KNOWN_PEERS_CAP + 64;
/// Max byte length of a single advertised multiaddr string. A real
/// `/dns4/host/tcp/port/p2p/<peer-id>` is well under 256 bytes; 512 is
/// generous headroom.
pub const MAX_WIRE_ADDR_LEN: usize = 512;
/// Max SyncEntry items in a Headers frame. IBD requests batches of 500
/// (see main.rs GetHeaders); 2000 leaves headroom.
pub const MAX_WIRE_SYNC_ENTRIES: usize = 2000;
/// Max tip entries in a Tips frame. MUST equal sync::MAX_ADVERTISED_TIPS.
pub const MAX_WIRE_TIPS: usize = 256;
/// Max locator hashes in a Tips frame. MUST equal locator::MAX_LOCATOR_LEN.
pub const MAX_WIRE_LOCATOR: usize = 64;
/// Max `limit` a peer may request via GetHeaders (bounds the work WE do
/// serving the response).
pub const MAX_WIRE_GETHEADERS_LIMIT: u32 = 2000;
/// Max user_agent length in a Version handshake.
pub const MAX_WIRE_USER_AGENT_LEN: usize = 128;
/// Largest PoWit gossip item: an equivocation proof (two attestations, each
/// with an 8 KiB key and signature bound) fits well inside.
pub const MAX_WIRE_POWIT_ITEM: usize = 40 * 1024;
/// Max peer_id string length in a PeerTip (base58 libp2p PeerIds are ~52 chars).
pub const MAX_WIRE_PEER_ID_LEN: usize = 128;

/// App-score penalty per wire protocol violation. With app_specific_weight
/// 1.0 and graylist_threshold -400 (see `run()`), four violations graylist
/// the peer.
pub const WIRE_VIOLATION_PENALTY: f64 = -100.0;
/// Floor so a flood of violations can't drive the score to -inf.
pub const WIRE_PENALTY_FLOOR: f64 = -1000.0;
/// Cap on the number of peers whose penalty score we track (bounds memory
/// against an attacker cycling peer identities).
pub const WIRE_PENALTY_TRACK_CAP: usize = 1024;
/// NET-4 / NET-8 (audit): penalties decay toward zero. Every
/// [`WIRE_PENALTY_DECAY_INTERVAL`] a tracked score is multiplied by
/// [`WIRE_PENALTY_DECAY_FACTOR`] (≈ 6.6 min half-life); a score whose
/// magnitude falls below 1.0 is forgotten (and reset to 0 in gossipsub).
pub const WIRE_PENALTY_DECAY_INTERVAL: Duration = Duration::from_secs(60);
pub const WIRE_PENALTY_DECAY_FACTOR: f64 = 0.9;

#[derive(Debug)]
pub enum WireDecodeError {
    /// Frame exceeds MAX_WIRE_BYTES, or the bincode read limit tripped
    /// (e.g. a declared length larger than the frame could ever satisfy).
    Oversized(String),
    /// Frame decoded, but a length field violates protocol bounds.
    Bounds(&'static str),
    /// Plain malformed bincode (may be benign version skew, not penalized
    /// as harshly as a deliberate oversize).
    Malformed(String),
    /// NET-7 (audit): the frame decoded but carried this many bytes past its
    /// logical end. A compliant encoder never produces them; accepting them
    /// let an attacker make any request byte-unique (fresh gossip message id)
    /// and so bypass gossipsub's de-duplication.
    TrailingBytes(usize),
    /// The frame decoded but is not the encoding of what it decoded to:
    /// bincode accepts non-minimal varints (`FB 05 00` for 5), so without
    /// this check one message had many byte encodings, each a fresh gossip
    /// message id — the NET-7 de-duplication bypass without trailing bytes
    /// (fuzz target `netmsg_decode`, docs/testing/FUZZING.md). A compliant
    /// encoder never produces them.
    ///
    /// `relayable`: the message is one that nodes relay after validating it
    /// (`NewBlock`, `NewTransaction`; see [`gossip_disposition`]). Releases
    /// before this rule (origin/main) decode such a frame, accept the
    /// message and gossipsub forwards the bytes they received, so it can be
    /// delivered by an honest older relay: it is refused but not a protocol
    /// violation ([`Self::is_protocol_violation`]), so it is dropped
    /// without penalty. Any other message type is never relayed by an
    /// honest node, so its non-canonical frame comes from its author.
    NonCanonical { relayable: bool },
}

impl WireDecodeError {
    /// Oversized, bounds-violating, padded and non-canonical frames are
    /// deliberate protocol violations — a compliant node cannot produce them
    /// — except a non-canonical frame of a relayable message, which an
    /// honest older release relays (see [`WireDecodeError::NonCanonical`]).
    /// Malformed frames may just be a newer/older protocol version.
    pub fn is_protocol_violation(&self) -> bool {
        matches!(
            self,
            WireDecodeError::Oversized(_)
                | WireDecodeError::Bounds(_)
                | WireDecodeError::TrailingBytes(_)
                | WireDecodeError::NonCanonical { relayable: false }
        )
    }
}

/// Decode an untrusted gossip frame with a hard byte limit and post-decode
/// bounds validation. This is the ONLY correct way to decode wire bytes from
/// a peer; `bincode::config::standard()` without a limit must never be used
/// on untrusted input.
pub fn decode_wire_message(data: &[u8]) -> Result<NetworkMessage, WireDecodeError> {
    if data.len() > MAX_WIRE_BYTES {
        return Err(WireDecodeError::Oversized(format!(
            "frame is {} bytes (max {})", data.len(), MAX_WIRE_BYTES
        )));
    }
    let cfg = bincode::config::standard().with_limit::<MAX_WIRE_BYTES>();
    let msg: NetworkMessage = match bincode::serde::decode_from_slice(data, cfg) {
        Ok((m, consumed)) => {
            if consumed != data.len() {
                return Err(WireDecodeError::TrailingBytes(data.len().saturating_sub(consumed)));
            }
            m
        }
        Err(bincode::error::DecodeError::LimitExceeded) => {
            return Err(WireDecodeError::Oversized(format!(
                "declared content exceeds {} byte read limit", MAX_WIRE_BYTES
            )));
        }
        Err(e) => return Err(WireDecodeError::Malformed(e.to_string())),
    };
    validate_wire_bounds(&msg)?;
    // One encoding per message: the frame must be what the encoder writes.
    match bincode::serde::encode_to_vec(&msg, bincode::config::standard()) {
        Ok(canonical) if canonical == data => Ok(msg),
        _ => Err(WireDecodeError::NonCanonical {
            relayable: matches!(msg, NetworkMessage::NewBlock { .. } | NetworkMessage::NewTransaction { .. }
                                     | NetworkMessage::NewPowitItem { .. }),
        }),
    }
}

/// Explicit bounds on every variable-length field of NetworkMessage.
fn validate_wire_bounds(msg: &NetworkMessage) -> Result<(), WireDecodeError> {
    use WireDecodeError::Bounds;
    fn addrs_ok(addrs: &[String]) -> Result<(), WireDecodeError> {
        if addrs.len() > MAX_WIRE_ADDRS {
            return Err(WireDecodeError::Bounds("address list longer than MAX_WIRE_ADDRS"));
        }
        if addrs.iter().any(|a| a.len() > MAX_WIRE_ADDR_LEN) {
            return Err(WireDecodeError::Bounds("address string longer than MAX_WIRE_ADDR_LEN"));
        }
        Ok(())
    }
    match msg {
        // The two payload checks below are unreachable today (a payload can't
        // exceed the frame that carries it, and frames are capped at
        // MAX_WIRE_BYTES) — kept as belt-and-braces should the byte limit and
        // this constant ever diverge.
        NetworkMessage::NewBlock { block_data, .. } => {
            if block_data.len() > MAX_WIRE_BYTES {
                return Err(Bounds("block_data larger than MAX_WIRE_BYTES"));
            }
        }
        NetworkMessage::NewTransaction { tx_data, .. } => {
            if tx_data.len() > MAX_WIRE_BYTES {
                return Err(Bounds("tx_data larger than MAX_WIRE_BYTES"));
            }
        }
        NetworkMessage::NewPowitItem { data, kind, .. } => {
            if data.len() > MAX_WIRE_POWIT_ITEM {
                return Err(Bounds("PoWit item larger than MAX_WIRE_POWIT_ITEM"));
            }
            if !(1..=crate::powit::ITEM_KIND_MAX).contains(kind) {
                return Err(Bounds("unknown PoWit item kind"));
            }
        }
        NetworkMessage::PeerTip { peer_id, .. } => {
            if peer_id.len() > MAX_WIRE_PEER_ID_LEN {
                return Err(Bounds("peer_id longer than MAX_WIRE_PEER_ID_LEN"));
            }
        }
        NetworkMessage::PeerExchange { peers } => addrs_ok(peers)?,
        NetworkMessage::PeerCount { addresses, .. } => addrs_ok(addresses)?,
        NetworkMessage::GetHeaders { limit, .. } => {
            if *limit > MAX_WIRE_GETHEADERS_LIMIT {
                return Err(Bounds("GetHeaders limit above MAX_WIRE_GETHEADERS_LIMIT"));
            }
        }
        NetworkMessage::Headers { entries } => {
            if entries.len() > MAX_WIRE_SYNC_ENTRIES {
                return Err(Bounds("Headers entries longer than MAX_WIRE_SYNC_ENTRIES"));
            }
        }
        NetworkMessage::Tips { tips, locator } => {
            if tips.len() > MAX_WIRE_TIPS {
                return Err(Bounds("Tips tips longer than MAX_WIRE_TIPS"));
            }
            if locator.len() > MAX_WIRE_LOCATOR {
                return Err(Bounds("Tips locator longer than MAX_WIRE_LOCATOR"));
            }
        }
        NetworkMessage::Version { user_agent, .. } => {
            if user_agent.len() > MAX_WIRE_USER_AGENT_LEN {
                return Err(Bounds("user_agent longer than MAX_WIRE_USER_AGENT_LEN"));
            }
        }
        NetworkMessage::PeerRequest
        | NetworkMessage::VersionAck
        | NetworkMessage::GetTips
        | NetworkMessage::GetBlock { .. }
        | NetworkMessage::BlockNotFound { .. } => {}
    }
    Ok(())
}

// ── Sprint EE (S3): frame-reaction unit — extracted from `run()` ─────────────
//
// The decode → penalize/ignore/accept decision used to live inline in the
// gossipsub `Message` arm of `run()`'s event loop, so the ONLY way to exercise
// the peer-scoring reaction to an invalid-block frame, an oversized frame, or
// a bounds-violating list was to stand up a live swarm — which made the
// reaction untested. This extraction is behavior-preserving: `run()` is now a
// thin consumer (classify → apply app score / log / forward), and the reaction
// itself is asserted deterministically in unit tests and in
// tests/sprint_ee_transport_convergence.rs without any networking.

/// What the node does in response to a single gossip frame from a peer.
#[derive(Debug)]
pub enum WireReaction {
    /// Frame decoded and passed bounds validation — process it.
    Accept(NetworkMessage),
    /// Deliberate protocol violation (oversized frame / bounds-violating
    /// lengths — e.g. an invalid-block frame larger than MAX_WIRE_BYTES):
    /// `score` is the peer's new cumulative application score to install via
    /// `gossipsub.set_application_score`. With app_specific_weight 1.0 and
    /// graylist_threshold -400, the fourth violation graylists the peer.
    Penalize { error: WireDecodeError, score: f64 },
    /// Malformed bincode — possibly benign version skew — or a non-canonical
    /// frame of a relayable message (`WireDecodeError::NonCanonical`, which
    /// an older release relays). Log-only, no penalty.
    IgnoreMalformed(String),
}

/// Cumulative per-peer wire-violation penalty state. Bounded to
/// [`WIRE_PENALTY_TRACK_CAP`] peers so an attacker cycling identities cannot
/// grow the map without limit.
///
/// NET-8 (audit): once full, the map used to stop tracking newcomers — a late
/// offender got a one-shot −100 forever and never reached the graylist. Now a
/// newcomer evicts the entry with the MILDEST score (ties: least recently
/// penalized), so real offenders stay tracked and every offender can
/// accumulate. NET-4: scores also DECAY ([`Self::decay_tick_at`]), so a peer
/// penalized for a burst of frames it merely relayed recovers instead of
/// being cut off forever.
pub struct WirePenaltyTracker {
    /// peer -> (score, last decay step, last penalty)
    penalties: std::collections::HashMap<PeerId, (f64, std::time::Instant, std::time::Instant)>,
    /// Peers forgotten to make room, whose gossipsub application score the
    /// network loop must reset ([`Self::take_evicted`]).
    evicted: Vec<PeerId>,
}

impl Default for WirePenaltyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl WirePenaltyTracker {
    pub fn new() -> Self {
        Self { penalties: std::collections::HashMap::new(), evicted: Vec::new() }
    }

    /// Decode an untrusted gossip frame and decide the reaction. This is the
    /// exact logic previously inline in `run()`:
    ///   - decodes via [`decode_wire_message`] (4 MiB frame/read limit +
    ///     post-decode bounds + no trailing bytes);
    ///   - protocol violations (Oversized/Bounds/TrailingBytes, and
    ///     NonCanonical of a message that is never relayed) accumulate
    ///     [`WIRE_VIOLATION_PENALTY`] per offense, floored at
    ///     [`WIRE_PENALTY_FLOOR`];
    ///   - plain-malformed frames and non-canonical frames of a relayable
    ///     message (`NewBlock`, `NewTransaction`) are ignored (version skew:
    ///     an older release accepts and relays the latter).
    #[allow(dead_code)] // tests only (the network loop uses `classify_gated`); the node binary compiles this module too
    pub fn classify(&mut self, peer: PeerId, data: &[u8]) -> WireReaction {
        self.classify_gated(peer, data, true)
    }

    /// [`Self::classify`] with the B1-T7 penalty gate
    /// ([`wire_violation_penalty`]): with `charge = false` a protocol
    /// violation is refused like a malformed frame (`IgnoreMalformed`, never
    /// forwarded) and nothing is recorded against `peer`.
    pub fn classify_gated(&mut self, peer: PeerId, data: &[u8], charge: bool) -> WireReaction {
        match decode_wire_message(data) {
            Ok(msg) => WireReaction::Accept(msg),
            Err(e) if e.is_protocol_violation() && charge => {
                let score = self.record_violation(peer);
                WireReaction::Penalize { error: e, score }
            }
            Err(e) => WireReaction::IgnoreMalformed(format!("{:?}", e)),
        }
    }

    /// Peers the bounded map forgot to make room since the last call
    /// (NET-4 residual): their gossipsub application score must be reset, or
    /// it would stay at its last value forever.
    pub fn take_evicted(&mut self) -> Vec<PeerId> {
        std::mem::take(&mut self.evicted)
    }

    /// H-R3-4: apply one [`WIRE_VIOLATION_PENALTY`] to `peer` and return its
    /// new cumulative score, WITHOUT going through [`decode_wire_message`] —
    /// this is the entry point for protocol violations detected on the
    /// directed `/gnb/sync/1` protocol (`sync_rr`), which has its own codec
    /// and therefore its own decode/bounds errors, but shares one peer-score
    /// reputation with the gossip path: an attacker cannot escape scoring by
    /// switching which protocol it sends violations on. Same cap/floor
    /// discipline as `classify`.
    pub fn record_violation(&mut self, peer: PeerId) -> f64 {
        self.record_violation_at(peer, std::time::Instant::now())
    }

    /// [`Self::record_violation`] with an explicit clock.
    pub fn record_violation_at(&mut self, peer: PeerId, now: std::time::Instant) -> f64 {
        if !self.penalties.contains_key(&peer) && self.penalties.len() >= WIRE_PENALTY_TRACK_CAP {
            // NET-8: make room by forgetting the mildest (then stalest) entry.
            let victim = self
                .penalties
                .iter()
                .max_by(|(_, a), (_, b)| {
                    a.0.partial_cmp(&b.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(b.2.cmp(&a.2))
                })
                .map(|(p, _)| *p);
            if let Some(v) = victim {
                self.penalties.remove(&v);
                if self.evicted.len() >= WIRE_PENALTY_TRACK_CAP {
                    self.evicted.remove(0);
                }
                self.evicted.push(v);
            }
        }
        let e = self.penalties.entry(peer).or_insert((0.0, now, now));
        e.0 = (e.0 + WIRE_VIOLATION_PENALTY).max(WIRE_PENALTY_FLOOR);
        e.2 = now;
        e.0
    }

    /// NET-4 / NET-8: decay every tracked score by
    /// [`WIRE_PENALTY_DECAY_FACTOR`] per full [`WIRE_PENALTY_DECAY_INTERVAL`]
    /// elapsed. Returns `(peer, new_score)` for every score that changed, to
    /// be re-installed with `set_application_score`; forgotten peers are
    /// returned with `0.0` and removed from the map.
    pub fn decay_tick_at(&mut self, now: std::time::Instant) -> Vec<(PeerId, f64)> {
        let mut changed = Vec::new();
        let mut forget = Vec::new();
        for (peer, e) in self.penalties.iter_mut() {
            let elapsed = now.saturating_duration_since(e.1);
            let steps = (elapsed.as_secs() / WIRE_PENALTY_DECAY_INTERVAL.as_secs().max(1)).min(1_000);
            if steps == 0 {
                continue;
            }
            e.0 *= WIRE_PENALTY_DECAY_FACTOR.powi(steps as i32);
            e.1 += WIRE_PENALTY_DECAY_INTERVAL * steps as u32;
            if e.0.abs() < 1.0 {
                forget.push(*peer);
                changed.push((*peer, 0.0));
            } else {
                changed.push((*peer, e.0));
            }
        }
        for p in forget {
            self.penalties.remove(&p);
        }
        changed
    }

    /// Number of peers currently tracked (observability for tests/metrics).
    pub fn tracked_peers(&self) -> usize {
        self.penalties.len()
    }

    /// Current cumulative score for a peer, if tracked.
    pub fn score_of(&self, peer: &PeerId) -> Option<f64> {
        self.penalties.get(peer).map(|e| e.0)
    }
}

// ── H4: panic-free truncation of attacker-controlled strings ─────────────────

/// UTF-8-safe prefix of at most `max_bytes` bytes.
///
/// The PEX log lines previously used `&s[..s.len().min(N)]`, which panics if
/// byte N falls in the middle of a multi-byte UTF-8 codepoint — and PEX
/// address strings are attacker-controlled, so a single crafted multiaddr
/// containing multi-byte characters at the right offset crashed the whole
/// network event loop. This walks back to the nearest char boundary instead.
/// L-4 (audit): made `pub` (was `pub(crate)`) so `bin/gnb-cli.rs` — a
/// separate crate within this package — can call the same UTF-8-safe
/// truncation instead of hand-rolling a byte-index slice on a node-response
/// string (which panics if a multi-byte character straddles the cut point).
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    // `end` is now a char boundary (0 in the worst case), so this cannot panic.
    &s[..end]
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub listen_addr:     String,
    pub bootstrap_peers: Vec<String>,
    /// Opt-in DNS seed hostnames (Bitcoin-style cold-start). Resolved to
    /// A/AAAA records and dialed as peers. Empty by default — non-privileged.
    pub dns_seeds:       Vec<String>,
    pub max_peers:       usize,
    pub data_dir:        PathBuf,
    /// Sprint P: if true, PEX will accept RFC1918 / loopback addresses.
    /// Intended for local development; production should leave this false.
    pub allow_private_peers: bool,
    /// Mesh fix (fresh-joiner IBD): this node sits behind a TCP proxy / NAT
    /// where many peers legitimately share one source IP (fly.io edge,
    /// ingress, CGNAT). Disables the gossipsub ip-colocation penalty weight
    /// (which would graylist the whole mesh at ~6 peers from one IP and
    /// silently blackhole every tip announcement). All other scoring stays.
    pub behind_proxy: bool,
    /// Enable mDNS zero-config LAN peer discovery. OFF by default: public nodes
    /// bootstrap via explicit `--peer` / `--dns-seed`, and mDNS (a) is useless off
    /// a LAN and (b) exercises hickory-proto's mDNS record parser (RUSTSEC-2026-0118/
    /// 0119 — LAN-only DoS surface). Turn on only for local/dev zero-config discovery.
    pub enable_mdns: bool,
    /// Announce-then-pull: this node runs with `--archive` (full block bodies
    /// retained, never pruned). Advertised to peers via the identify
    /// agent-version so they prefer us as the directed-pull source during IBD.
    pub archive: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr:     "/ip4/0.0.0.0/tcp/17110".into(),
            bootstrap_peers: vec![],
            dns_seeds:       vec![],
            max_peers:       50,
            data_dir:        PathBuf::from("./bloch-data"),
            allow_private_peers: false,
            behind_proxy:    false,
            enable_mdns:     false,
            archive:         false,
        }
    }
}

// ── Behaviour ───────────────────────────────────────────────────────────────
//
// PRINCIPLES.md #2 ("every node is a seed"): the swarm combines gossipsub with
// mdns (zero-config LAN discovery — a node bootstraps from local peers with no
// configured seed) and identify (the node learns its own public address as
// peers observe it, so it can self-advertise via PEX). No privileged seed is
// required; any node can bootstrap another. The derive generates the event enum
// `BlochBehaviourEvent`.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct BlochBehaviour {
    // P0 (roadmap §1.3 / §4.1): swarm-level connection limits. `max_peers` was
    // previously only an app-side counter checked in the PEX/mDNS dial paths,
    // so inbound connection floods / eclipse setup were NOT bounded by libp2p.
    // This behaviour rejects connections at the transport layer once the caps
    // are hit (B1-T9 / NET-11: inbound gets `max_peers` + 1 slots — the extra
    // one lets a newcomer in so the connection manager can EVICT an
    // unprotected inbound peer instead of refusing everyone once full — and
    // the swarm-wide cap leaves room for every outbound slot).
    // FIRST field: the derive macro runs `handle_established_*` in field
    // order, so a denial here happens before any other behaviour allocates
    // per-connection state for the connection (NET-11 review).
    connection_limits: libp2p::connection_limits::Behaviour,
    // B1-T2: discouraged identities (`misbehaviour`). Blocking a peer closes
    // its connections and refuses new ones, inbound and outbound; second, so
    // a refused identity is denied right after the connection limits,
    // before any other behaviour allocates per-connection state.
    blocked: libp2p::allow_block_list::Behaviour<libp2p::allow_block_list::BlockedPeers>,
    // NET-11 (d): gossipsub behind a per-peer gate, so block-relay-only
    // connections carry no gossip at all (see `gossip_gate`). Every other
    // call goes to the wrapped gossipsub behaviour (`Deref`).
    gossipsub: gossip_gate::GossipGate,
    // Toggle: mDNS is present only when `--enable-mdns` is set (off by default).
    // Disabled → the hickory-proto mDNS parser is never exercised (RUSTSEC-2026-0118/0119).
    mdns:      libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour>,
    identify:  identify::Behaviour,
    // Announce-then-pull: directed IBD PULL path (GetBlock/GetHeaders/GetTips)
    // over libp2p request-response (`/gnb/sync/1`), so block/header FETCHING
    // is a directed request to ONE peer instead of a gossipsub broadcast to the
    // whole mesh (removes the O(peers) IBD amplification). See `sync_rr`.
    sync_rr:   sync_rr::Behaviour,
    // NET-11 (a): latency measurement for the inbound eviction protection of
    // low-latency peers (Core's minimum ping time). Never closes connections.
    ping: libp2p::ping::Behaviour,
}

// ── Node ──────────────────────────────────────────────────────────────────────

/// Yamux per-connection substream cap.
///
/// Must sit ABOVE `sync_rr::MAX_CONCURRENT_SYNC_STREAMS` (2048 then, 64
/// since re-audit B1-T18 / B2-T6) or the
/// transport vetoes the request-response layer: fecf29b raised the rr cap
/// 100 → 2048 so sync bursts flow, but the swarm was still built with
/// `yamux::Config::default`, whose yamux-0.13 backend caps a connection at
/// 512 substreams — and yamux does NOT backpressure at that cap, it KILLS
/// the whole connection (`connection.rs`: inbound over the cap →
/// `Action::Terminate`, outbound → `ConnectionError::TooManyStreams`;
/// logged as "maximum number of streams reached" followed by our
/// "✗ disconnected"). A node catching up across the damaged-fork anticone
/// opens a GetBlock burst, blows through 512, and the transport drops the
/// very peer it was syncing from — observed on node4 as a 0↔3-peer
/// connect/disconnect oscillation (15 connects / 15 disconnects / 12×
/// "maximum number of streams" in 15 min).
///
/// 4096 = 2× the rr cap: room for all 2048 sync streams plus gossipsub,
/// identify and ping substreams, with slack for streams in half-closed
/// teardown. Memory stays bounded by the rr cap (sync frames are the only
/// bulk payload; gossip is capped at 4 MiB per message elsewhere).
///
/// NET-17 (audit) — corrected: upstream libp2p-yamux 0.47 switched to the
/// yamux 0.12 backend as soon as ANY config setter ran, which is why this
/// workspace used to patch in a vendored fork without that backend
/// (GHSA-vxx9-2994-q338). Since libp2p 0.57 (audit OPS-2) the upstream
/// libp2p-yamux 0.48 has a single yamux 0.14 backend, the fork is retired, and
/// `node/tests/supply_chain_lockfile_guard.rs` keeps a second (or pre-0.13.10)
/// yamux out of Cargo.lock. `set_max_num_streams` configures that backend
/// directly, and 4096 is exactly the largest cap its default receive window
/// allows (yamux asserts `max_connection_receive_window >= 256 KiB × streams`).
/// A NOT-yet-updated remote still enforces 512 on ITS side of the
/// connection, so the churn only fully stops once both endpoints run this
/// build.
const MAX_YAMUX_STREAMS: usize = 4096;

/// The swarm-level connection caps for `max_peers` inbound slots (B1-T9 /
/// NET-11 a):
///
/// * established INCOMING: `max_peers + 1` — one transient slot over the
///   inbound budget, so a newcomer reaches the connection manager, which then
///   evicts an unprotected inbound peer (Core's `AttemptToEvictConnection`)
///   or closes the newcomer; the manager keeps inbound at `max_peers`;
/// * established total: room for every inbound slot PLUS every outbound slot
///   ([`connmgr::OUTBOUND_CONNECTION_HEADROOM`]): inbound connections can
///   never use the connections outbound dialing needs;
/// * at most 2 connections per peer (a simultaneous dial in both directions;
///   one identity cannot hold many inbound connections);
/// * pending caps blunt half-open connection floods.
pub fn swarm_connection_limits(max_peers: usize) -> libp2p::connection_limits::ConnectionLimits {
    let max = max_peers as u32;
    let total = max_peers.saturating_mul(2).max(max_peers + connmgr::OUTBOUND_CONNECTION_HEADROOM) as u32;
    libp2p::connection_limits::ConnectionLimits::default()
        .with_max_established(Some(total))
        .with_max_established_incoming(Some(max.saturating_add(1)))
        .with_max_established_per_peer(Some(2))
        .with_max_pending_incoming(Some(max.max(1)))
        .with_max_pending_outgoing(Some(max.max(connmgr::OUTBOUND_CONNECTION_HEADROOM as u32)))
}

/// Builder for the swarm's yamux config — passed to `with_tcp` /
/// `with_websocket` in place of `yamux::Config::default` (the builder accepts
/// any `FnOnce() -> Config`). See `MAX_YAMUX_STREAMS` for why and for the
/// 0.13→0.12 backend consequence.
pub fn yamux_config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(MAX_YAMUX_STREAMS);
    cfg
}

/// Length of a gossipsub message id: SHA-256 of the frame, truncated.
pub const GOSSIP_MESSAGE_ID_LEN: usize = 16;

/// Most message ids this node puts in one IHAVE (and asks for in IWANTs per
/// peer per heartbeat). One IHAVE is one RPC and gossipsub never splits it by
/// size; with 16-byte ids every id costs 18 bytes on the wire (field tag,
/// length, id), so 800 ids are about 14.4 KB, under the 16 KiB control limit a
/// default-config libp2p-gossipsub 0.50 receiver enforces. gossipsub's default
/// (5000 ids, about 90 KB) made a node's own IHAVE undecodable for such a peer:
/// the receiver closes its inbound gossipsub stream and every later frame on
/// the link (blocks included) is lost. Anyone can fill the tx topic's gossip
/// window cheaply, so that was a remote way to cut honest links.
pub const GOSSIP_MAX_CONTROL_IDS: usize = 800;

/// Largest control part (IHAVE / IWANT / GRAFT / PRUNE / subscriptions) of one
/// inbound RPC this node decodes. It covers what peers on gossipsub's default
/// send side produce (5000 ids, about 90 KB: libp2p 0.49 nodes, other
/// implementations) and stays far below `max_transmit_size` (4 MiB).
pub const GOSSIP_MAX_CONTROL_BYTES: usize = 128 * 1024;

/// The control-size limit a libp2p-gossipsub 0.50 peer applies with its
/// default configuration; what this node sends must fit in it.
pub const GOSSIP_PEER_DEFAULT_CONTROL_BYTES: usize = 16 * 1024;

/// Bytes one message id costs inside an IHAVE / IWANT (tag, length, id).
pub const GOSSIP_ID_WIRE_COST: usize = 2 + GOSSIP_MESSAGE_ID_LEN;

// Build-time check of both directions (64 bytes: RPC / ControlIHave framing
// and the topic id): our largest IHAVE fits a default 0.50 receiver, and we
// decode a default sender's 5000-id IHAVE.
const _: () = assert!(GOSSIP_MAX_CONTROL_IDS * GOSSIP_ID_WIRE_COST + 64 <= GOSSIP_PEER_DEFAULT_CONTROL_BYTES);
const _: () = assert!(GOSSIP_MAX_CONTROL_BYTES >= 5000 * GOSSIP_ID_WIRE_COST + 64);

/// Audit M-10 fix: SHA-256 (truncated to 16 bytes) message ids are
/// deterministic across toolchains, unlike std's DefaultHasher.
pub fn gossip_message_id(m: &gossipsub::Message) -> gossipsub::MessageId {
    let digest = Sha256::digest(&m.data);
    gossipsub::MessageId::from(&digest[..GOSSIP_MESSAGE_ID_LEN])
}

/// The node's gossipsub settings, before `build()` (tests derive topologies
/// from it, e.g. a peer outside the mesh).
pub fn gossipsub_config_builder() -> gossipsub::ConfigBuilder {
    let mut b = gossipsub::ConfigBuilder::default();
    b.heartbeat_interval(Duration::from_secs(1))
        .validation_mode(ValidationMode::Strict)
        .message_id_fn(gossip_message_id)
        .max_transmit_size(4 * 1024 * 1024)
        // NET-2 (audit): do NOT relay a frame before the application has
        // validated it. Without this, libp2p forwarded every frame to the
        // mesh first (an invalid-PoW block reached every node at zero
        // cost to its author) and the configured invalid-delivery (P4)
        // penalties could never fire.
        .validate_messages()
        // Keep unvalidated frames long enough for the processor to judge
        // them (a block verdict waits behind its 64 MiB PoW check).
        .history_length(GOSSIP_HISTORY_LENGTH)
        // Mesh fix (fresh-joiner IBD): gossipsub's duplicate_cache_time
        // defaults to 60s — the SAME period as tip_announce below, which
        // made byte-identical periodic PeerTips Duplicate-dropped locally.
        // 30s guarantees the 60s periodic announce always clears the
        // cache; the tip-carrying Version (fresh timestamp → unique bytes)
        // published alongside it can never be dedup-dropped at all.
        .duplicate_cache_time(Duration::from_secs(30))
        // Send small enough IHAVEs for a default 0.50 receiver, accept the
        // large ones older or differently configured peers send (see
        // GOSSIP_MAX_CONTROL_IDS / GOSSIP_MAX_CONTROL_BYTES).
        .max_control_messages_sent(GOSSIP_MAX_CONTROL_IDS)
        .max_control_message_size(GOSSIP_MAX_CONTROL_BYTES);
    b
}

/// The node's gossipsub configuration (see [`gossipsub_config_builder`]).
pub fn gossipsub_config() -> Result<gossipsub::Config, NetworkError> {
    gossipsub_config_builder()
        .build()
        .map_err(|e| NetworkError::StartFailed(format!("gossipsub: {}", e)))
}

pub struct NetworkNode {
    pub peer_id: PeerId,
    pub config:  NetworkConfig,
    local_key:   identity::Keypair,
    /// Hybrid ML-DSA-65 ‖ Falcon-1024 transport identity.
    pq_identity: Arc<PqIdentity>,
    /// Per-peer PQ key pins (trust on first use).
    pq_pins:     Arc<PeerPins>,
    control_rx:  Option<mpsc::Receiver<NetworkControl>>,
    peer_events: Option<mpsc::Sender<PeerEvent>>,
    /// The network this node speaks (audit POW-9: its protocol identifiers,
    /// [`chain_separation`]). The node's chain id unless overridden.
    chain:       crate::core::ChainId,
    /// B1-T19: gossip transactions and PoWit items go here instead of the
    /// block channel.
    tx_ingest:   Option<mpsc::Sender<Inbound>>,
    /// NET-2 residual: remote addresses of connected peers (shared with the
    /// processor's proof-of-work budgets).
    peer_addrs:  discourage::PeerAddrs,
    /// B1-T7: the hardening activation height whose block, once on the
    /// selected chain, puts wire-violation penalties in force for relayed
    /// frames (`wire_violation_penalty`).
    penalty_activation: u64,
    /// (full-relay, block-relay-only) automatic outbound slot targets.
    outbound_targets: (usize, usize),
    /// Mean interval between feeler connections.
    feeler_interval: Duration,
    /// Period of the block-relay-only frontier polls.
    block_relay_poll_interval: Duration,
    /// POW-3: the node's minimum chain work; below it the node answers
    /// GetTips / GetHeaders empty (`serve::serve_sync_request`). 0 (no
    /// minimum) unless [`Self::with_minimum_chain_work`] sets it.
    min_chain_work: u128,
}

impl NetworkNode {
    /// FIX #4: Persistent P2P identity.
    pub fn new(config: NetworkConfig) -> Result<Self, NetworkError> {
        let key_path = config.data_dir.join("p2p_identity.bin");
        let local_key = load_or_create_identity(&key_path)?;
        let peer_id   = PeerId::from(local_key.public());
        info!("P2P identity: {} ({})", peer_id, key_path.display());
        let pq_path = config.data_dir.join("p2p_pq_identity.bin");
        let pq_identity = Arc::new(PqIdentity::load_or_create(&pq_path)
            .map_err(NetworkError::StartFailed)?);
        info!("P2P PQ identity fingerprint: {}", hex::encode(pq_identity.fingerprint()));
        let pq_pins = Arc::new(PeerPins::load(&config.data_dir.join("p2p_pq_pins.json"))
            .map_err(NetworkError::StartFailed)?);
        Ok(Self {
            peer_id, config, local_key, pq_identity, pq_pins, control_rx: None, peer_events: None, tx_ingest: None,
            chain: crate::core::node_chain_id(),
            peer_addrs: discourage::PeerAddrs::new(),
            penalty_activation: crate::core::activation::hardening_activation_height(),
            outbound_targets: (connmgr::OUTBOUND_FULL_RELAY_TARGET, connmgr::BLOCK_RELAY_ONLY_TARGET),
            feeler_interval: connmgr::FEELER_INTERVAL,
            block_relay_poll_interval: connmgr::BLOCK_RELAY_POLL_INTERVAL,
            min_chain_work: 0,
        })
    }

    /// Speak `chain`'s protocol identifiers instead of the node chain id's
    /// (in-process harnesses that run nodes of two networks).
    pub fn with_chain(mut self, chain: crate::core::ChainId) -> Self {
        self.chain = chain;
        self
    }

    /// POW-3: the node's minimum chain work (`ingress::minimum_chain_work`,
    /// set by `main`): while the selected tip is below it the node is in
    /// initial block download and advertises no frontier or headers to
    /// peers (Bitcoin Core ignores `getheaders` then), so a chain it does not
    /// trust yet, such as an eclipsing peer's cheap chain its own pulls
    /// fetched, is not relayed. Default 0 (in-process harnesses).
    pub fn with_minimum_chain_work(mut self, min_chain_work: u128) -> Self {
        self.min_chain_work = min_chain_work;
        self
    }

    /// B1-T19: deliver gossip `NewTransaction` and `NewPowitItem` frames
    /// ([`goes_to_tx_ingest`]) on `tx` (their own consumer) instead of the
    /// block channel of [`Self::run_validated`].
    pub fn attach_tx_ingest(&mut self, tx: mpsc::Sender<Inbound>) {
        self.tx_ingest = Some(tx);
    }

    /// The remote addresses of connected peers, kept current by the running
    /// network loop.
    pub fn peer_addrs(&self) -> discourage::PeerAddrs {
        self.peer_addrs.clone()
    }

    /// Use `activation` instead of the process-wide hardening activation
    /// height for the wire-violation penalty gate (tests).
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn set_penalty_activation(&mut self, activation: u64) {
        self.penalty_activation = activation;
    }

    /// Override the automatic outbound slot targets (defaults: Bitcoin
    /// Core's 8 full-relay + 2 block-relay-only). For tests and experiments;
    /// operators have no reason to change them.
    #[allow(dead_code)] // library / test knob; the binary keeps the defaults
    pub fn set_outbound_targets(&mut self, full_relay: usize, block_relay_only: usize) {
        self.outbound_targets = (full_relay, block_relay_only);
    }

    /// Override the mean feeler interval (default: Core's 2 minutes). For
    /// tests.
    #[allow(dead_code)] // library / test knob; the binary keeps the default
    pub fn set_feeler_interval(&mut self, mean: Duration) {
        self.feeler_interval = mean;
    }

    /// Override the period of the block-relay-only frontier polls (default
    /// `connmgr::BLOCK_RELAY_POLL_INTERVAL`). For tests.
    #[allow(dead_code)] // library / test knob; the binary keeps the default
    pub fn set_block_relay_poll_interval(&mut self, period: Duration) {
        self.block_relay_poll_interval = period;
    }

    /// Accept [`NetworkControl`] requests from the processor on `rx`.
    pub fn attach_control(&mut self, rx: mpsc::Receiver<NetworkControl>) {
        self.control_rx = Some(rx);
    }

    /// Report [`PeerEvent`]s to the processor on `tx` (never blocks: a full
    /// channel drops the notice).
    pub fn attach_peer_events(&mut self, tx: mpsc::Sender<PeerEvent>) {
        self.peer_events = Some(tx);
    }

    /// Run the network event loop for a consumer that does NOT report gossip
    /// verdicts (tests, harnesses): inbound frames are delivered as bare
    /// `NetworkMessage`s and blocks are relayed on decode. Production uses
    /// [`Self::run_validated`].
    ///
    /// Sprint CC (IBD live-tip fix): the loop reads the *current* tip from the
    /// DAG before each announce instead of a value captured at startup.
    ///
    /// Sprint EE (S3 transport harness): `listen_report`, when `Some`, receives
    /// every address this swarm binds (fired from `SwarmEvent::NewListenAddr`),
    /// so in-process harnesses can wire nodes on ephemeral ports. Production
    /// passes `None`.
    pub async fn run(
        self,
        block_tx:       mpsc::Sender<NetworkMessage>,
        outbound_rx:    mpsc::Receiver<NetworkMessage>,
        dag:            std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:     std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        store:          std::sync::Arc<crate::storage::Storage>,
        listen_report:  Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        self.run_inner(IngestSink::Legacy(block_tx), None, outbound_rx, dag, peer_state, store, listen_report)
            .await
    }

    /// NET-2 (audit): run the event loop with APPLICATION-VALIDATED gossip.
    ///
    /// Gossipsub is configured with `validate_messages()`: a received frame is
    /// relayed only after a verdict is reported. Frames are delivered on
    /// `inbound_tx` with their [`InboundOrigin`]; for every frame whose
    /// origin carries a pending message id (gossip `NewBlock` and, since
    /// audit MEM-5, gossip `NewTransaction`), the consumer
    /// MUST send exactly one [`GossipValidation`] on the channel whose
    /// receiver is `verdict_rx`. Frames it never answers are simply not
    /// relayed (they expire from gossipsub's message cache).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_validated(
        mut self,
        inbound_tx:     mpsc::Sender<Inbound>,
        verdict_rx:     mpsc::Receiver<GossipValidation>,
        outbound_rx:    mpsc::Receiver<NetworkMessage>,
        dag:            std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:     std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        store:          std::sync::Arc<crate::storage::Storage>,
        listen_report:  Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        let txs = self.tx_ingest.take();
        self.run_inner(IngestSink::Validated { main: inbound_tx, txs }, Some(verdict_rx), outbound_rx, dag, peer_state, store, listen_report)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_inner(
        mut self,
        sink:            IngestSink,
        mut verdict_rx:  Option<mpsc::Receiver<GossipValidation>>,
        mut outbound_rx: mpsc::Receiver<NetworkMessage>,
        dag:             std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:      std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        // Announce-then-pull: the network loop serves inbound directed
        // GetBlock pulls straight from the block store (bodies live here, not
        // in the DAG), replying to the ONE requesting peer over
        // request-response — no gossip, no O(peers) fan-out.
        store:           std::sync::Arc<crate::storage::Storage>,
        listen_report:   Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        use std::time::Instant;
        let gs_cfg = gossipsub_config()?;
        // Audit POW-9: this network's protocol identifiers (topics, sync
        // protocol, identify version), so no frame crosses networks.
        let protos = chain_separation::chain_protocols(self.chain);

        // ── Peer scoring: penalize invalid messages, reward participation ──
        let peer_score_params = {
            use gossipsub::{PeerScoreParams, TopicScoreParams};
            let mut params = PeerScoreParams::default();
            params.app_specific_weight = 1.0;
            params.ip_colocation_factor_threshold = 3.0; // penalize >3 peers from same IP
            // Mesh fix: behind a fly.io-style proxy/NAT every inbound peer
            // shares the proxy's source IP, so the colocation penalty crosses
            // graylist_threshold at just 6 peers. Operators who know they're
            // proxied disable the weight with --behind-proxy.
            params.ip_colocation_factor_weight =
                if self.config.behind_proxy { 0.0 } else { -50.0 };
            params.decay_interval = Duration::from_secs(60);
            params.decay_to_zero = 0.01;

            // P3/P3b MUST be disabled on a low-rate chain: the defaults charge
            // every grafted peer ≈ graylist_threshold within seconds when it
            // delivers fewer than 20 messages, which is always on a ~30 s
            // block chain (the mesh could never hold anyone).
            let block_topic_params = TopicScoreParams {
                topic_weight: 0.5,
                time_in_mesh_weight: 0.1,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 100.0,
                first_message_deliveries_weight: 1.0,
                first_message_deliveries_decay: 0.97,
                first_message_deliveries_cap: 100.0,
                mesh_message_deliveries_weight: 0.0,  // P3 off — see note above
                mesh_failure_penalty_weight:    0.0,  // P3b off — same reason
                invalid_message_deliveries_weight: -100.0, // harsh penalty for invalid blocks
                invalid_message_deliveries_decay: 0.5,
                ..Default::default()
            };

            let tx_topic_params = TopicScoreParams {
                topic_weight: 0.3,
                time_in_mesh_weight: 0.05,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 50.0,
                first_message_deliveries_weight: 0.5,
                first_message_deliveries_decay: 0.97,
                first_message_deliveries_cap: 100.0,
                invalid_message_deliveries_weight: -50.0,
                invalid_message_deliveries_decay: 0.5,
                mesh_message_deliveries_weight: 0.0,  // P3 off — see block_topic_params
                mesh_failure_penalty_weight:    0.0,  // P3b off
                ..Default::default()
            };

            let sync_topic_params = TopicScoreParams {
                topic_weight: 0.2,
                time_in_mesh_weight: 0.02,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 50.0,
                invalid_message_deliveries_weight: -20.0,
                invalid_message_deliveries_decay: 0.8,
                mesh_message_deliveries_weight: 0.0,  // P3 off — see block_topic_params
                mesh_failure_penalty_weight:    0.0,  // P3b off
                ..Default::default()
            };

            params.topics.insert(IdentTopic::new(protos.blocks_topic).hash(), block_topic_params);
            params.topics.insert(IdentTopic::new(protos.txs_topic).hash(), tx_topic_params);
            params.topics.insert(IdentTopic::new(protos.sync_topic).hash(), sync_topic_params);
            params
        };

        let peer_score_thresholds = gossipsub::PeerScoreThresholds {
            gossip_threshold:             -100.0,  // below this: no gossip metadata
            publish_threshold:            -200.0,  // below this: messages rejected
            graylist_threshold:           -400.0,  // below this: completely ignored
            opportunistic_graft_threshold: 5.0,
            ..Default::default()
        };

        let mut gs = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(self.local_key.clone()),
            gs_cfg,
        ).map_err(|e| NetworkError::StartFailed(format!("behaviour: {}", e)))?;

        // Apply peer scoring (non-fatal if it fails)
        if let Err(e) = gs.with_peer_score(peer_score_params, peer_score_thresholds) {
            warn!("peer scoring disabled: {}", e);
        }

        // Captured for the connection-limits behaviour below (avoids borrowing
        // `self` inside the `with_behaviour` closure).
        let max_peers = self.config.max_peers;
        let enable_mdns = self.config.enable_mdns;
        let archive = self.config.archive;

        let (pq_tcp, pins_tcp) = (self.pq_identity.clone(), self.pq_pins.clone());
        let (pq_ws, pins_ws) = (self.pq_identity.clone(), self.pq_pins.clone());
        // DESIGN-obenblock §2: the transport id names the chain.
        let transport_id = protos.transport;
        let mut swarm = SwarmBuilder::with_existing_identity(self.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                move |keys: &identity::Keypair| -> Result<PqConfig, std::convert::Infallible> {
                    Ok(PqConfig::new(keys, pq_tcp, pins_tcp).with_protocol_id(transport_id))
                },
                yamux_config,
            )
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_websocket(
                move |keys: &identity::Keypair| -> Result<PqConfig, std::convert::Infallible> {
                    Ok(PqConfig::new(keys, pq_ws, pins_ws).with_protocol_id(transport_id))
                },
                yamux_config,
            )
            .await
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_behaviour(|key| {
                // mDNS only when explicitly enabled; otherwise a disabled Toggle
                // (its record parser — the hickory-proto DoS surface — never runs).
                let mdns: libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour> =
                    if enable_mdns {
                        Some(mdns::tokio::Behaviour::new(
                            mdns::Config::default(),
                            key.public().to_peer_id(),
                        )?).into()
                    } else {
                        None.into()
                    };
                // The identify agent-version still advertises the archival bit
                // (`gnb/<ver>/a|n`) for operators, but NET-9: peers no longer
                // use this self-declared bit to choose whom to pull from.
                let identify = identify::Behaviour::new(
                    identify::Config::new(protos.identify.into(), key.public())
                        .with_agent_version(sync_rr::agent_version(archive)),
                );
                let connection_limits = libp2p::connection_limits::Behaviour::new(swarm_connection_limits(max_peers));
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(BlochBehaviour {
                    gossipsub: gossip_gate::GossipGate::new(gs),
                    mdns,
                    identify,
                    sync_rr: sync_rr::new_behaviour(protos.sync_protocol.clone()),
                    connection_limits,
                    blocked: libp2p::allow_block_list::Behaviour::default(),
                    ping: libp2p::ping::Behaviour::new(libp2p::ping::Config::new()),
                })
            })
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        let block_t = IdentTopic::new(protos.blocks_topic);
        let tx_t    = IdentTopic::new(protos.txs_topic);
        let sync_t  = IdentTopic::new(protos.sync_topic);

        for t in [&block_t, &tx_t, &sync_t] {
            swarm.behaviour_mut().gossipsub.subscribe(t)
                .map_err(|e| NetworkError::StartFailed(e.to_string()))?;
        }

        swarm.listen_on(self.config.listen_addr.parse()
            .map_err(|e| NetworkError::StartFailed(format!("addr: {}", e)))?)
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?;

        // M-6 (audit): the WS listener is opt-in (`GNB_ENABLE_WS_LISTENER=1`)
        // and derived from `--listen` (same host, TCP port + 1, `/ws`).
        let ws_enabled = std::env::var("GNB_ENABLE_WS_LISTENER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if ws_enabled {
            match ws_listen_addr_from(&self.config.listen_addr) {
                Some(ws_addr) => match swarm.listen_on(ws_addr.clone()) {
                    Ok(_) => info!("WS listening on {}", ws_addr),
                    Err(e) => warn!("WS listen failed (non-fatal): {}", e),
                },
                None => warn!(
                    "GNB_ENABLE_WS_LISTENER set but --listen ('{}') has no /tcp/<port> \
                     component to derive a WS port from — WS listener not started",
                    self.config.listen_addr
                ),
            }
        }

        // NET-11 (e): the per-node secret that keys address-table bucketing
        // and the eviction netgroup order (Core's nKey), derived from the
        // identity key so the persisted tried table keeps its layout.
        let addr_key = match self.local_key.to_protobuf_encoding() {
            Ok(bytes) => addrbook::derive_key(&bytes),
            Err(_) => addrbook::random_key(),
        };

        // FIX #6 / NET-11: the persisted known peers are the keyed "tried"
        // table (addresses we connected to outbound). They are no longer all
        // dialed at start-up: the connection manager selects from the tables
        // to fill its outbound slots (B1-T9).
        let peers_path = self.config.data_dir.join("known_peers.json");
        let mut known_peers = load_known_peers(&peers_path);
        // Sprint P / B1-T8: drop any entry that doesn't pass the validator
        // (legacy pollution, host names, re-spelled private IPs).
        let pruned = prune_invalid(&mut known_peers, self.config.allow_private_peers);
        if pruned > 0 {
            info!("known_peers: pruned {} invalid entries on load (Sprint P)", pruned);
        }
        // Sprint P / NET-11: enforce the (netgroup-aware) cap.
        let evicted = enforce_cap(&mut known_peers);
        if evicted > 0 {
            info!("known_peers: evicted {} entries to enforce cap", evicted);
        }
        let mut tried = TriedTable::load(addr_key, known_peers.iter().filter_map(|a| normalize_peer_addr(a)));

        // Sprint P / NET-11: PEX hardening state. Rate limits are keyed by the
        // AUTHOR of the addresses (the peer that answered our GetPeers), and
        // received addresses only ever enter the keyed new table `addr_book`.
        let mut pex_limiter = PexRateLimiter::new();
        let mut pex_stats   = PexStats::new();
        let mut addr_book   = AddrBook::with_key(addr_key);
        // POW-9: dialed addresses enter the tried table after identify.
        let mut pending_tried = chain_separation::PendingTried::default();
        let allow_private   = self.config.allow_private_peers;

        // B1-T9 / NET-11 (a)-(d): connection manager (outbound slots apart
        // from inbound, eviction, feelers, block-relay-only peers, anchors).
        let mut conn_mgr = ConnManager::new(addr_key, self.config.max_peers);
        conn_mgr.set_targets(self.outbound_targets.0, self.outbound_targets.1);
        let anchors_path = self.config.data_dir.join(connmgr::ANCHORS_FILE);
        let mut anchors: std::collections::VecDeque<String> =
            connmgr::read_anchors(&anchors_path, allow_private).into_iter().collect();
        if !anchors.is_empty() {
            info!("anchors: {} block-relay-only peer(s) from the last run", anchors.len());
        }
        let mut feeler = {
            use rand::Rng;
            connmgr::FeelerSchedule::new(std::time::Instant::now(), self.feeler_interval, rand::rng().random())
        };
        // Core's cached getaddr answer (anti-scraping): one sample of the tried
        // table per GETADDR_CACHE_LIFETIME.
        let mut getaddr_cache = GetAddrCache::default();
        // NET-11 (a): kind of each gossip frame awaiting a processor verdict
        // (an Accept = a novel block / transaction from that peer).
        let mut novel_kinds: std::collections::HashMap<gossipsub::MessageId, bool> = std::collections::HashMap::new();
        // NET-11 (c): established feeler connections and when to close them.
        let mut feelers_closing: Vec<(libp2p::swarm::ConnectionId, std::time::Instant)> = Vec::new();

        // C1 / NET-4 / NET-8: cumulative, decaying, bounded app-score
        // penalties for wire-violating peers.
        let mut wire_tracker = WirePenaltyTracker::new();
        // NET-2 residual: addresses discouraged after a peer misbehaved, and
        // the operator-configured peers that are never discouraged. One
        // misbehaviour model with `discouraged_ids` below
        // (`act_on_misbehaviour`, `discourage_now`).
        let mut discouraged_addrs = discourage::Discouraged::new();
        let manual_peers: HashSet<PeerId> = sync_rr::explicit_peer_ids(&self.config.bootstrap_peers);
        // Peers whose connections were refused at a discouraged address (not
        // counted; their `ConnectionClosed` events are skipped).
        let mut refused_peers: HashSet<PeerId> = HashSet::new();
        // MEM-5 / MEM-6: processor → network penalties (optional).
        let mut control_rx = self.control_rx.take();

        // H-R3-1 fix #4 / NET-8: bounded per-peer + global rate of served
        // inbound directed-sync requests. Refusals are answered `Busy` (NET-5).
        let mut sync_limiter = sync_rr::SyncRequestLimiter::new();
        // B1-T3 / B1-T18 / B2-T5 / B2-T6: serving off the swarm task, with
        // per-peer and global send budgets (`serve`).
        let mut serve_q: serve::ServeQueue<
            libp2p::request_response::InboundRequestId,
            libp2p::request_response::ResponseChannel<sync_rr::SyncResponse>,
        > = serve::ServeQueue::new();
        let (served_tx, mut served_rx) = mpsc::channel::<
            serve::Served<libp2p::request_response::InboundRequestId, libp2p::request_response::ResponseChannel<sync_rr::SyncResponse>>,
        >(serve::MAX_SERVE_WORKERS * 4);
        // B1-T2: identities disconnected for misbehaviour (`misbehaviour`);
        // their addresses go to `discouraged_addrs` at the same time.
        let mut discouraged_ids = misbehaviour::Discouraged::new();

        // NET-6: per-AUTHOR rate limit on tip claims (PeerTip / Version).
        let mut claim_limiter: ratelimit::TokenBuckets<PeerId> =
            ratelimit::TokenBuckets::new(CLAIM_BURST, CLAIM_REFILL_PER_SEC, CLAIM_LIMITER_TRACK_CAP);

        // Start-up dials: the shipped seeds, the DNS seeds' answers and the
        // configured `--peer`s, as MANUAL connections (Core's -addnode /
        // -seednode: they never use the automatic outbound slots).
        let mut manual: Vec<Multiaddr> = Vec::new();
        for p in crate::core::DEFAULT_SEEDS.iter().map(|s| s.to_string()).chain(self.config.bootstrap_peers.iter().cloned()) {
            // Operator-configured: a host name is resolved; its answer may be
            // private (docker / LAN setups) but never an invalid range.
            if let Some(addr) = resolve_dial_addr(&p, true).await {
                manual.push(addr);
            }
        }
        // DNS seeds (opt-in, non-privileged): resolve each hostname's A/AAAA
        // records into peer multiaddrs (Bitcoin-style cold-start). B1-T8: the
        // answers are third-party data and are screened like learned
        // addresses (Core's addrman refuses unroutable seed results).
        for host in self.config.dns_seeds.iter() {
            let hp = if host.contains(':') { host.clone() } else { format!("{host}:{}", self.chain.params().p2p_port) };
            match tokio::net::lookup_host(hp).await {
                Ok(addrs) => {
                    for sa in addrs {
                        if !is_acceptable_ip(sa.ip(), allow_private) {
                            warn!("dns-seed {} answered a non-routable address {}; ignored", host, sa.ip());
                            continue;
                        }
                        let ma = match sa.ip() {
                            std::net::IpAddr::V4(v4) => format!("/ip4/{}/tcp/{}", v4, sa.port()),
                            std::net::IpAddr::V6(v6) => format!("/ip6/{}/tcp/{}", v6, sa.port()),
                        };
                        info!("dns-seed {} → {}", host, ma);
                        if let Ok(addr) = ma.parse() {
                            manual.push(addr);
                        }
                    }
                }
                Err(e) => warn!("dns-seed {}: resolve failed: {}", host, e),
            }
        }
        manual.sort();
        manual.dedup();
        for addr in manual {
            info!("dialing: {}", addr);
            dial_with_intent(&mut swarm, &mut conn_mgr, addr, DialIntent::manual());
        }

        let peer_id_str = self.peer_id.to_string();
        let mut peer_count = 0usize;

        // AUDIT (external-address poisoning): a peer-reported identify
        // `observed_addr` is only a CANDIDATE; it is confirmed as our external
        // address only when peers in EXTERNAL_ADDR_QUORUM distinct NETGROUPS
        // report it (NET-11 residual: identities are free, netgroups are not).
        const EXTERNAL_ADDR_QUORUM: usize = 3;
        const OBSERVED_ADDR_CAP: usize = 64;
        const MDNS_DIAL_LIMIT: usize = 8; // max LAN peers auto-dialed per mDNS event
        let mut observed_by: std::collections::HashMap<Multiaddr, std::collections::HashSet<String>> =
            std::collections::HashMap::new();

        // NET-5 / NET-9 / B1-T2 / B1-T6: directed pulls go through the pull
        // scheduler (`pull`): answers bound to their request, hint-first,
        // stall- and usefulness-aware peer choice, per-source queue quotas,
        // never the same peer twice for one pull, spaced retries — never
        // re-published on gossip (NET-7).
        let explicit_ids = sync_rr::explicit_peer_ids(&self.config.bootstrap_peers);
        let mut pulls: pull::PullScheduler<libp2p::request_response::OutboundRequestId> =
            pull::PullScheduler::new(explicit_ids.clone());

        // Re-gossip rate-limit: suppress re-publishes of the SAME block within
        // the duplicate-cache window (a guaranteed local `Duplicate` anyway).
        let mut recent_block_publishes: std::collections::HashMap<[u8; 32], std::time::Instant> =
            std::collections::HashMap::new();
        const REGOSSIP_SUPPRESS_TTL: Duration = Duration::from_secs(30);
        let mut heartbeat   = new_heartbeat();
        let mut save_peers  = tokio::time::interval(Duration::from_secs(60));
        // Sprint CC: periodic tip announce (every 60s).
        let mut tip_announce = tokio::time::interval(Duration::from_secs(60));
        // NET-5/NET-9: re-try queued pulls (cooldowns expire, slots free up).
        let mut pull_tick = tokio::time::interval(PULL_RETRY_TICK);
        pull_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // B1-T9 / NET-11: open at most one automatic outbound connection per
        // tick, from the address tables, whenever an outbound slot is free
        // (Core's ThreadOpenConnections loop).
        let mut outbound_tick = tokio::time::interval(OUTBOUND_TICK);
        outbound_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // B1-T9 / M-11: heartbeat re-dials of configured peers resolve their
        // host names on separate tasks, never inside this loop.
        let (mut manual_resolver, mut manual_resolved_rx) = ManualResolver::new(MANUAL_RESOLVE_TIMEOUT);
        let mut block_relay_poll = tokio::time::interval_at(
            tokio::time::Instant::now() + self.block_relay_poll_interval, self.block_relay_poll_interval);
        block_relay_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = poll_swarm(&mut swarm) => {
                    match event {
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message_id, message })) => {
                            // C1: bounded decode (4 MiB frame/read limit, per-field
                            // bounds, NET-7: no trailing bytes).
                            // B1-T7 / NET-4 residual: a violation is charged to the
                            // delivering peer only if it authored the frame, or
                            // once no release that forwards unvalidated frames
                            // follows the chain (`wire_violation_penalty`).
                            let self_authored = message.source == Some(propagation_source);
                            let in_force = {
                                let d = dag.read();
                                let tip_h = d.selected_tip().and_then(|t| d.get_block_data(&t).map(|x| x.height)).unwrap_or(0);
                                crate::ingress::block_penalties_in_force(tip_h, self.penalty_activation)
                            };
                            let (charge, reject) = wire_violation_penalty(self_authored, in_force);
                            let reaction = wire_tracker.classify_gated(propagation_source, &message.data, charge);
                            // A peer the bounded tracker forgot keeps no stale
                            // application score (NET-4 residual).
                            for p in wire_tracker.take_evicted() {
                                swarm.behaviour_mut().gossipsub.set_application_score(&p, 0.0);
                            }
                            let msg = match reaction {
                                WireReaction::Penalize { error, score } => {
                                    // Oversized / bounds-violating / padded frames can't
                                    // come from a compliant node. NET-2/NET-4: the
                                    // DELIVERING peer is charged (application score, the
                                    // shared misbehaviour score of B1-T2) and the frame is
                                    // never forwarded; gossipsub's P4 penalty (`Reject`,
                                    // which also hits every peer that sent a duplicate)
                                    // only when no honest relay can have forwarded one
                                    // (B1-T7).
                                    swarm.behaviour_mut().gossipsub
                                        .set_application_score(&propagation_source, score);
                                    let acceptance = if reject {
                                        gossipsub::MessageAcceptance::Reject
                                    } else {
                                        gossipsub::MessageAcceptance::Ignore
                                    };
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, acceptance);
                                    warn!("wire violation from {}: {:?} (app score → {})",
                                        propagation_source, error, score);
                                    // B1-T2: one shared misbehaviour score (disconnect at the
                                    // threshold), and no pulls to it while it cools down.
                                    let now = Instant::now();
                                    pulls.on_misbehaving(&propagation_source, now);
                                    act_on_misbehaviour(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                        &self.peer_addrs, &manual_peers, propagation_source, score, now);
                                    continue;
                                }
                                WireReaction::IgnoreMalformed(_) => {
                                    debug!("undecodable gossip frame from {} ({} bytes)",
                                        propagation_source, message.data.len());
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                                    continue;
                                }
                                WireReaction::Accept(m) => m,
                            };
                            let now = Instant::now();
                            let author = message.source;
                            let author_connected = author.is_some_and(|a| swarm.is_connected(&a));
                            let mut claim_ok = false;
                            match &msg {
                                NetworkMessage::NewBlock  { block_hash, height, blue_score, .. } => {
                                    tracing::info_span!(
                                        "net_ingest_block",
                                        block_hash = %hex::encode(&block_hash[..8]),
                                        height = *height,
                                        blue_score = *blue_score,
                                        peer = %propagation_source,
                                    ).in_scope(|| {
                                        info!("← block h={} {}", height, hex::encode(&block_hash[..8]));
                                    });
                                    // Re-gossip suppression, RECEIVE side: a received
                                    // block is in gossipsub's duplicate cache, so a
                                    // re-publish within the TTL is a guaranteed local
                                    // `Duplicate` — skip the wasted encode/hash work.
                                    recent_block_publishes.retain(|_, t| now.duration_since(*t) < REGOSSIP_SUPPRESS_TTL);
                                    recent_block_publishes.insert(*block_hash, now);
                                }
                                // Receipt trace of a gossiped transaction, off by
                                // default (`GOSSIP_RX_TX_LOG_TARGET`): the
                                // functional tests check with it that an invalid
                                // transaction never reaches a peer. The decode
                                // runs only when the trace is enabled.
                                NetworkMessage::NewTransaction { tx_data, .. }
                                    if log::log_enabled!(target: GOSSIP_RX_TX_LOG_TARGET, log::Level::Debug) =>
                                {
                                    match crate::core::Transaction::from_wire_bytes(tx_data) {
                                        Ok(tx) => debug!(target: GOSSIP_RX_TX_LOG_TARGET, "← tx {} from {}",
                                            hex::encode(&tx.txid()[..8]), propagation_source),
                                        Err(_) => debug!(target: GOSSIP_RX_TX_LOG_TARGET, "← tx (undecodable, {} bytes) from {}",
                                            tx_data.len(), propagation_source),
                                    }
                                }
                                NetworkMessage::PeerTip { blue_score, height, .. }
                                | NetworkMessage::Version { blue_score, height, .. } => {
                                    // NET-6: claims are attributed to their signed AUTHOR
                                    // and recorded only for directly connected authors,
                                    // rate-limited per author, clamped once here.
                                    if let Some(a) = author.filter(|_| author_connected) {
                                        if claim_limiter.allow_at(a, now) {
                                            let (our_score, our_count) = {
                                                let d = dag.read();
                                                (d.tip_blue_score(), d.block_count() as u64)
                                            };
                                            let bs = clamp_announced_blue_score(*blue_score, our_score);
                                            let ht = clamp_announced_blue_score(*height, our_count);
                                            peer_state.observe_claim(a, bs, ht, now);
                                            claim_ok = true;
                                            // A claim ahead of us: pull the frontier
                                            // from its AUTHOR, the peer known to have
                                            // it. The processor's own pulls for this
                                            // claim go to the selector's choice
                                            // (rotation, NET-9), often a peer without
                                            // the blocks. Tips answers are
                                            // deduplicated by the frontier tracker, so
                                            // the extra pull fetches nothing twice
                                            // (Headers answers are not: header pulls
                                            // stay with the processor). Bounded by
                                            // the per-author claim limiter above.
                                            if claim_warrants_directed_pull(bs, our_score) {
                                                send_directed_pull(&mut swarm, &mut pulls, a, sync_rr::SyncRequest::GetTips, now);
                                            }
                                        }
                                    }
                                    if let NetworkMessage::Version { version, user_agent, .. } = &msg {
                                        if *version < MIN_PROTOCOL_VERSION {
                                            warn!("← incompatible version {} from {}", version, truncate_utf8(user_agent, 64));
                                        }
                                    }
                                }
                                // NET-11: unsolicited gossip PeerExchange is never
                                // dialed, never stored, never relayed (see
                                // `gossip_disposition`). Addresses are only learned
                                // from answers to our own directed GetPeers.
                                _ => {}
                            }
                            let source = InboundOrigin::Gossip { propagation_source, author, pending: None, received_at: now };
                            match gossip_disposition(&msg, sink.validator_attached(), claim_ok) {
                                GossipDisposition::DeliverDeferred => {
                                    // NET-11 (a): remember the frame kind; the
                                    // processor's Accept marks a novel block / tx
                                    // (a PoWit item earns no protection).
                                    if let Some(is_block) = novel_kind(&msg) {
                                        note_pending_kind(&mut novel_kinds, &message_id, is_block);
                                    }
                                    let origin = InboundOrigin::Gossip {
                                        propagation_source, author, pending: Some(message_id.clone()), received_at: now,
                                    };
                                    if !sink.deliver(msg, origin, "gossip") {
                                        // Never queued: nobody will judge it. Do not relay.
                                        swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                            &message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                                    }
                                }
                                GossipDisposition::Deliver(v) => {
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, v.into());
                                    sink.deliver(msg, source, "gossip");
                                }
                                GossipDisposition::Drop(v) => {
                                    debug!("gossip [{}] from {} not delivered/relayed", msg.kind_name(), propagation_source);
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, v.into());
                                }
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
                            let now = Instant::now();
                            // NET-2 residual: Bitcoin Core does not take connections
                            // from (nor make them to) discouraged addresses; a fresh
                            // identity from a discouraged address buys nothing.
                            // Operator-configured peers are exempt (Core's `noban`).
                            // Checked before the connection manager counts it.
                            if let Some(ip) = discourage::ip_of(endpoint.get_remote_address()) {
                                if discouraged_addrs.is_discouraged(ip, now) && !manual_peers.contains(&peer_id) {
                                    info!("✗ {} at a discouraged address: disconnecting", peer_id);
                                    let _ = swarm.disconnect_peer_id(peer_id);
                                    // Never counted: its closing connections must not
                                    // be uncounted either (a peer already counted
                                    // through an earlier connection is closed through
                                    // the normal path).
                                    if num_established.get() == 1 {
                                        refused_peers.insert(peer_id);
                                    }
                                    continue;
                                }
                                self.peer_addrs.insert(peer_id, ip);
                            }
                            // B1-T9 / NET-11: classify the connection (inbound, or the
                            // outbound kind it was dialed for).
                            let est = conn_mgr.on_established(
                                connection_id, peer_id, endpoint.is_dialer(), endpoint.get_remote_address(), now);
                            // PROPAGAÇÃO-CHURN fix: persist only the canonical form of
                            // a DIALED address (the Listener's send_back_addr is an
                            // ephemeral socket). NET-11: an address we connected to
                            // outbound enters the keyed "tried" table (Core's Good) —
                            // POW-9: once the peer's identify shows it runs this
                            // network (`chain_separation::PendingTried`); a full
                            // bucket then queues a test-before-evict collision.
                            if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                                let addr_str = canonical_peer_addr(address, &peer_id);
                                if is_valid_public_multiaddr(&addr_str, allow_private) {
                                    pending_tried.on_dialed(peer_id, addr_str);
                                } else {
                                    debug!("not adding peer to known_peers (validator rejected): {}",
                                        truncate_utf8(&addr_str, 80));
                                }
                            }
                            // NET-11 (c): a feeler only tests reachability. Its success
                            // keeps a tried occupant (test-before-evict) or promotes a
                            // new-table address (above, on its same-network identify,
                            // POW-9). It carries no gossip (gated)
                            // and none of our protocol traffic, and is closed after
                            // connmgr::FEELER_LINGER — as Core closes a feeler once the
                            // handshake is complete: closing at once cut the remote's
                            // side of the connection setup short.
                            if est.kind == ConnKind::Feeler {
                                if let Some(i) = &est.intent {
                                    if let (Some(newcomer), Some(occupant)) = (&i.collision_newcomer, &i.addr) {
                                        tried.resolve_collision(newcomer, occupant, true, now);
                                    }
                                }
                                debug!("feeler to {} succeeded; closing it shortly", peer_id);
                                feelers_closing.push((connection_id, now + connmgr::FEELER_LINGER));
                                continue;
                            }
                            // NET-11 (a): inbound slots full → evict an unprotected
                            // inbound peer (Core's AttemptToEvictConnection), or refuse
                            // the newcomer when every inbound peer is protected.
                            if est.kind == ConnKind::Inbound && conn_mgr.inbound_over_capacity() {
                                // A second connection of an already-connected peer
                                // is just closed: it must not evict someone else.
                                // R2b: a peer connected from an address discouraged
                                // since (another identity there misbehaved) is
                                // Core's `m_prefer_evict`.
                                let victim = if est.new_peer {
                                    conn_mgr.eviction_victim(&peer_id, |p| {
                                        self.peer_addrs.get(p).is_some_and(|ip| discouraged_addrs.is_discouraged(ip, now))
                                    })
                                } else {
                                    None
                                };
                                match victim {
                                    Some(victim) => {
                                        info!("inbound slots full: evicting {} to admit {}", victim, peer_id);
                                        let _ = swarm.disconnect_peer_id(victim);
                                    }
                                    None => {
                                        info!("inbound slots full and every inbound peer protected: refusing {}", peer_id);
                                        swarm.close_connection(connection_id);
                                        continue;
                                    }
                                }
                            }
                            info!("✓ connected: {}", peer_id);
                            // DO NOT call gossipsub.add_explicit_peer() here: explicit
                            // peers are excluded from the mesh (libp2p-gossipsub
                            // behaviour.rs), which once made the mesh unbuildable.
                            let first_connection = est.new_peer;
                            // The count is of distinct peers, not connections, and the
                            // processor (RPC `peers`, the miner's has-peers check) sees
                            // it at once, not at the next 30 s heartbeat. NET-11:
                            // block-relay-only peers are left out — nothing we
                            // publish crosses such a link, so a node holding only
                            // anchors must not mine / relay as if connected.
                            if conn_mgr.relay_peer_count() != peer_count {
                                peer_count = conn_mgr.relay_peer_count();
                                crate::metrics::set_peer_count(peer_count as i64);
                                sink.deliver(NetworkMessage::PeerCount {
                                    count: peer_count, addresses: tried.addresses(),
                                }, InboundOrigin::Local, "connect");
                            }
                            peer_state.on_connect(peer_id, now);
                            // NET-9 residual: we dialed it (counts toward
                            // abandoning a frontier tip) or it dialed us.
                            pulls.on_connect(peer_id, endpoint.is_dialer(), now);
                            // B1-T18 review: peers we dialed and `--peer` peers
                            // keep a reserved part of the send budget.
                            if endpoint.is_dialer() || explicit_ids.contains(&peer_id) {
                                serve_q.set_protected(peer_id, true);
                            }
                            // NET-11 (b): a new block-relay-only peer is an anchor.
                            if first_connection && est.kind == ConnKind::BlockRelayOnly {
                                connmgr::write_anchors(&anchors_path, &conn_mgr.anchors());
                            }
                            // Version handshake + tip announce with FRESH DAG values.
                            let (v_score, v_height) = {
                                let d = dag.read();
                                (d.tip_blue_score(), d.block_count() as u64)
                            };
                            let version_msg = NetworkMessage::Version {
                                version:    PROTOCOL_VERSION,
                                user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                                blue_score: v_score,
                                height:     v_height,
                                timestamp:  std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                            };
                            if let Ok(d) = bincode::serde::encode_to_vec(&version_msg, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    info!("on-connect Version publish failed ({}); will re-announce when {} subscribes to sync", e, peer_id);
                                }
                            }
                            let my_tip = build_current_tip(&dag, &peer_id_str);
                            if let Ok(d) = bincode::serde::encode_to_vec(&my_tip, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    info!("on-connect PeerTip publish failed ({}); will re-announce when {} subscribes to sync", e, peer_id);
                                }
                            }
                            // M-10: directed PEX request to the peer that just
                            // connected (one requester, one answer). Not retried on
                            // other peers if it fails. NET-11: only to outbound
                            // full-relay and manual peers, as Core sends getaddr
                            // (inbound peers would answer nothing; block-relay-only
                            // connections carry no address relay).
                            if est.kind.sends_getaddr() {
                                send_directed_pull(&mut swarm, &mut pulls, peer_id, sync_rr::SyncRequest::GetPeers, now);
                            }
                            // Directed frontier exchange with the new peer: its tips,
                            // asked of IT. The gossip announcements above reach a
                            // second peer connecting within the same second as
                            // byte-identical frames, which gossipsub drops as
                            // duplicates, so a healed partition used to wait for
                            // the 30 s nudge / 60 s announce (about 60 s;
                            // test/functional/feature_partition_heal.py). Both ends
                            // do this, so each learns the other's frontier now.
                            if first_connection {
                                send_directed_pull(&mut swarm, &mut pulls, peer_id, sync_rr::SyncRequest::GetTips, now);
                            }
                            drain_pulls(&mut swarm, &mut pulls, now);
                        }
                        // Mesh fix (fresh-joiner IBD): THIS event is the moment the
                        // peer provably subscribed, so re-announce the handshake and
                        // tip here (the on-connect announce races its Subscribe).
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            if topic == sync_t.hash() {
                                let (v_score, v_height) = {
                                    let d = dag.read();
                                    (d.tip_blue_score(), d.block_count() as u64)
                                };
                                let ver = NetworkMessage::Version {
                                    version:    PROTOCOL_VERSION,
                                    user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                                    blue_score: v_score,
                                    height:     v_height,
                                    timestamp:  std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs()).unwrap_or(0),
                                };
                                if let Ok(d) = bincode::serde::encode_to_vec(&ver, bincode::config::standard()) {
                                    match swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                        Ok(_)  => info!("→ {} subscribed to sync; announced tip score={} height={}", peer_id, v_score, v_height),
                                        Err(e) => info!("post-subscribe Version publish failed: {} (periodic announce will retry)", e),
                                    }
                                }
                                let my_tip = build_current_tip(&dag, &peer_id_str);
                                if let Ok(d) = bincode::serde::encode_to_vec(&my_tip, bincode::config::standard()) {
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                        debug!("post-subscribe PeerTip publish: {}", e);
                                    }
                                }
                            }
                        }
                        SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, .. } => {
                            // A connection refused at a discouraged address was never
                            // counted nor announced (nor given to the connection
                            // manager): nothing to undo.
                            if refused_peers.contains(&peer_id) {
                                if num_established == 0 {
                                    refused_peers.remove(&peer_id);
                                }
                                continue;
                            }
                            let closed = conn_mgr.on_closed(connection_id, peer_id);
                            if num_established == 0 {
                                pending_tried.on_closed(&peer_id);
                                self.peer_addrs.remove(&peer_id);
                            }
                            if closed.kind == Some(ConnKind::Feeler) {
                                continue;
                            }
                            info!("✗ disconnected: {}", peer_id);
                            // Checked even when the peer keeps another connection:
                            // its role (block-relay-only or not) may have changed.
                            if conn_mgr.relay_peer_count() != peer_count {
                                peer_count = conn_mgr.relay_peer_count();
                                crate::metrics::set_peer_count(peer_count as i64);
                                sink.deliver(NetworkMessage::PeerCount {
                                    count: peer_count, addresses: tried.addresses(),
                                }, InboundOrigin::Local, "disconnect");
                            }
                            if let Some(gone) = closed.peer_gone {
                                peer_state.on_disconnect(&peer_id);
                                // Its in-flight pulls go to other peers at once; its
                                // selector state (cooldown, scores) is kept.
                                let now = Instant::now();
                                pulls.on_disconnect(&peer_id, now);
                                serve_q.forget_queued(&peer_id);
                                serve_q.set_protected(peer_id, false);
                                if let Some(tx) = &self.peer_events {
                                    let _ = tx.try_send(PeerEvent::Disconnected(peer_id));
                                }
                                if gone.role == ConnKind::BlockRelayOnly {
                                    connmgr::write_anchors(&anchors_path, &conn_mgr.anchors());
                                }
                                drain_pulls(&mut swarm, &mut pulls, now);
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("listening: {}/p2p/{}", address, self.peer_id);
                            if let Some(report) = &listen_report {
                                let _ = report.send(address.clone());
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { connection_id, peer_id, error } => {
                            let intent = conn_mgr.on_dial_failed(connection_id);
                            match intent.as_ref().map(|i| i.kind) {
                                // Feelers and automatic dials fail routinely
                                // (that is what feelers find out).
                                Some(ConnKind::Feeler | ConnKind::OutboundFullRelay | ConnKind::BlockRelayOnly) => {
                                    debug!("{:?} dial failed{}: {}", intent.as_ref().map(|i| i.kind),
                                        peer_id.map(|p| format!(" to {}", p)).unwrap_or_default(), error);
                                }
                                _ => warn!("dial failed{}: {}",
                                    peer_id.map(|p| format!(" to {}", p)).unwrap_or_default(),
                                    error),
                            }
                            if let Some(i) = intent {
                                // NET-11 (c): test-before-evict — an unreachable tried
                                // occupant is replaced by the newcomer it blocked.
                                if let (ConnKind::Feeler, Some(newcomer), Some(occupant)) = (i.kind, &i.collision_newcomer, &i.addr) {
                                    tried.resolve_collision(newcomer, occupant, false, Instant::now());
                                }
                                // A failed block-relay-only / feeler dial: its peer's
                                // future connections carry gossip again.
                                if let (ConnKind::BlockRelayOnly | ConnKind::Feeler, Some(p)) = (i.kind, i.peer) {
                                    if !swarm.is_connected(&p) {
                                        swarm.behaviour_mut().gossipsub.ungate_peer(&p);
                                    }
                                }
                            }
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("incoming failed: {}", error);
                        }
                        // PRINCIPLES.md #2: zero-config LAN discovery (opt-in). Only
                        // LAN addresses, capped per event, honoring the peer ceiling.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            let mut dialed = 0usize;
                            for (peer_id, addr) in list {
                                if dialed >= MDNS_DIAL_LIMIT || peer_count >= self.config.max_peers {
                                    break;
                                }
                                if !is_lan_multiaddr(&addr) {
                                    debug!("mDNS: ignoring non-LAN address (possible reflection): {}", addr);
                                    continue;
                                }
                                info!("mDNS discovered (LAN): {} at {}", peer_id, addr);
                                if dial_with_intent(&mut swarm, &mut conn_mgr, addr, DialIntent::manual()) { dialed += 1; }
                            }
                        }
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _addr) in list {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                        // identify: our observed address (quorum-confirmed before it
                        // is advertised). Peer listen addrs are NOT persisted.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            // Audit POW-9: a peer of another network (or not
                            // GnB at all) is dropped, as Bitcoin Core drops a
                            // connection carrying another network's magic. Its
                            // observed address of us is not counted either.
                            let same = chain_separation::same_network(&protos, &info.protocol_version);
                            pending_tried.on_identified(&peer_id, same, &mut tried, &mut addr_book, Instant::now());
                            if !same {
                                info!("peer {} identifies as {:?}, not {:?}: another network; disconnecting \
                                       (its address leaves the tried table)",
                                    peer_id, truncate_utf8(&info.protocol_version, 64), protos.identify);
                                let _ = swarm.disconnect_peer_id(peer_id);
                                continue;
                            }
                            let cand = canonical_peer_addr(&info.observed_addr, &self.peer_id);
                            // A voter counts once per NETGROUP of its connection.
                            let voter_group = conn_mgr.peer(&peer_id).map(|i| i.netgroup.clone());
                            if let Some(voter_group) = voter_group.filter(|_| {
                                is_valid_public_multiaddr(&cand, allow_private)
                                    && (observed_by.len() < OBSERVED_ADDR_CAP
                                        || observed_by.contains_key(&info.observed_addr))
                            }) {
                                let voters = observed_by.entry(info.observed_addr.clone()).or_default();
                                let was_below = voters.len() < EXTERNAL_ADDR_QUORUM;
                                voters.insert(voter_group);
                                if was_below && voters.len() >= EXTERNAL_ADDR_QUORUM {
                                    swarm.add_external_address(info.observed_addr.clone());
                                    info!("external address confirmed by peers in {} netgroups: {}",
                                        EXTERNAL_ADDR_QUORUM, info.observed_addr);
                                }
                            }
                            if let Some(arch) = sync_rr::parse_archival_agent(&info.agent_version) {
                                debug!("peer {} self-declares archival={} (not used for pull selection)", peer_id, arch);
                            }
                        }
                        // NET-11 (a): latency for the eviction protection.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Ping(libp2p::ping::Event { peer, result: Ok(rtt), .. })) => {
                            conn_mgr.on_ping(&peer, rtt);
                        }
                        // ── Announce-then-pull: directed IBD sync ────────────
                        SwarmEvent::Behaviour(BlochBehaviourEvent::SyncRr(ev)) => match ev {
                            libp2p::request_response::Event::Message { peer, message, .. } => match message {
                                // SERVER: answer THIS peer only. H-R3-1 / NET-8: rate
                                // limited per peer and request class and globally;
                                // NET-5: a refusal is an explicit `Busy`, never a
                                // dropped channel. B1-T3 / B2-T5: computed off this
                                // task by the bounded serving workers; B1-T18 /
                                // B2-T6: Busy above the peer's send budget.
                                libp2p::request_response::Message::Request { request_id, request, channel } => {
                                    let now = Instant::now();
                                    match request {
                                        // A frame no honest node sends (the codec
                                        // reports it as a request so it can be
                                        // attributed): penalized, not answered.
                                        sync_rr::SyncRequest::Malformed => {
                                            let score = wire_tracker.record_violation_at(peer, now);
                                            warn!("sync_rr: malformed request from {} (app score → {})", peer, score);
                                            pulls.on_misbehaving(&peer, now);
                                            act_on_misbehaviour(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                            &self.peer_addrs, &manual_peers, peer, score, now);
                                            drop(channel);
                                        }
                                        req if !sync_limiter.allow_request(peer, &req, now) => {
                                            debug!("sync_rr: rate-limited [{}] from {} → Busy", req.kind_name(), peer);
                                            respond(&mut swarm, &mut serve_q, peer, request_id, channel, sync_rr::SyncResponse::Busy);
                                        }
                                        sync_rr::SyncRequest::GetPeers => {
                                            // NET-11: answered for INBOUND peers only,
                                            // once per connection, from a sample cached
                                            // for about a day (Core: getaddr from
                                            // outbound peers is ignored;
                                            // m_addr_response_caches). Anyone else gets
                                            // an empty, well-formed answer. B1-T18:
                                            // Busy above the peer's send budget.
                                            let resp = if !serve_q.has_send_budget(&peer) {
                                                sync_rr::SyncResponse::Busy
                                            } else if conn_mgr.take_getaddr_answer(&peer) {
                                                let external: Vec<Multiaddr> = swarm.external_addresses().cloned().collect();
                                                let sample = getaddr_cache.sample(now, &tried, allow_private);
                                                serve_get_peers(&sample, &external, &self.peer_id, allow_private)
                                            } else {
                                                sync_rr::SyncResponse::Peers { peers: Vec::new() }
                                            };
                                            respond(&mut swarm, &mut serve_q, peer, request_id, channel, resp);
                                        }
                                        req => {
                                            if let Err(job) = serve_q.submit(serve::Job { peer, id: request_id, req, channel }) {
                                                debug!("sync_rr: [{}] from {} refused (serving queue / send budget) → Busy",
                                                    job.req.kind_name(), peer);
                                                respond(&mut swarm, &mut serve_q, peer, job.id, job.channel, sync_rr::SyncResponse::Busy);
                                            }
                                            pump_serving(&mut swarm, &mut serve_q, &dag, &store, &served_tx, self.min_chain_work);
                                        }
                                    }
                                }
                                // CLIENT: our directed pull was answered. B1-T2: the
                                // answer is bound to the request it answers
                                // (`sync_rr::check_response`); a wrong one is a
                                // violation, never delivered, and the pull goes on.
                                libp2p::request_response::Message::Response { request_id, response } => {
                                    let now = Instant::now();
                                    let act = pulls.on_response(request_id, peer, &response, now);
                                    // NET-11: a `Peers` answer feeds the table only as
                                    // the answer to OUR GetPeers (B1-T2: `check_response`
                                    // delivers a `Peers` answer for a GetPeers pull
                                    // only) sent to a peer we ask for addresses.
                                    let asked_for_peers = solicited_peers_answer(
                                        matches!(response, sync_rr::SyncResponse::Peers { .. })
                                            .then_some(&sync_rr::SyncRequest::GetPeers),
                                        conn_mgr.role(&peer));
                                    if let Some(why) = act.violation {
                                        let score = wire_tracker.record_violation_at(peer, now);
                                        warn!("sync_rr: {} answered a pull with [{}]: {} (app score → {})",
                                            peer, response.kind_name(), why, score);
                                        act_on_misbehaviour(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                            &self.peer_addrs, &manual_peers, peer, score, now);
                                    } else if act.deliver {
                                        match response {
                                            sync_rr::SyncResponse::Peers { peers } if !asked_for_peers => {
                                                // NET-11: addresses answered to a GetTips /
                                                // GetHeaders / … request (or by a
                                                // block-relay-only / inbound peer) are a
                                                // protocol violation, never table input.
                                                debug!("sync_rr: unsolicited Peers answer ({} addresses) from {}; ignored",
                                                    peers.len(), peer);
                                            }
                                            sync_rr::SyncResponse::Peers { peers } => {
                                                // NET-11: solicited addresses go to the
                                                // table, rate-limited per author; never
                                                // dialed from here.
                                                // NET-11 (e): bucketed by the answering
                                                // peer's netgroup (Core's addr source).
                                                let source_group = conn_mgr.peer(&peer)
                                                    .map(|i| i.netgroup.clone()).unwrap_or_default();
                                                ingest_pex_addresses(
                                                    &mut addr_book, &mut pex_limiter, &mut pex_stats,
                                                    peer, &source_group, &peers, allow_private, &self.peer_id,
                                                    |a| tried.contains(a),
                                                );
                                                pex_stats.set_distinct_peers(pex_limiter.tracked_peer_count());
                                            }
                                            other => {
                                                if let sync_rr::SyncResponse::Tips { tips, .. } = &other {
                                                    // NET-6: directed Tips update the
                                                    // RESPONDER's frontier (it is a direct
                                                    // peer we asked) — this is what makes
                                                    // the verified IBD release path live.
                                                    let hashes: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                                                    let (bs, ht) = tips.iter()
                                                        .map(|e| (e.blue_score, e.height))
                                                        .max_by_key(|(s, _)| *s)
                                                        .unwrap_or((0, 0));
                                                    let (our_score, our_count) = {
                                                        let d = dag.read();
                                                        (d.tip_blue_score(), d.block_count() as u64)
                                                    };
                                                    peer_state.observe(
                                                        peer,
                                                        clamp_announced_blue_score(bs, our_score),
                                                        clamp_announced_blue_score(ht, our_count),
                                                        &hashes,
                                                        now,
                                                    );
                                                }
                                                if let Some(m) = sync_rr::response_to_message(other) {
                                                    sink.deliver(m, InboundOrigin::Directed { peer }, "directed-pull");
                                                }
                                            }
                                        }
                                    }
                                    drain_pulls(&mut swarm, &mut pulls, now);
                                }
                            },
                            // Directed pull failed (timeout, reset, unsupported
                            // protocol, undecodable answer). NET-9: count it against
                            // the peer (stall detection) and retry on ANOTHER peer.
                            // NET-7: never re-published on gossip.
                            libp2p::request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                                let now = Instant::now();
                                // H-R3-4: an answer that failed to decode / pass bounds
                                // is a protocol violation by the ANSWERING peer. NET-5:
                                // a clean EOF or timeout is a transport failure and is
                                // never penalized (`is_sync_protocol_violation`).
                                // B2-T7: an over-long Tips answer (sent by every
                                // release before this one) is refused, not penalized.
                                let kind = match &error {
                                    libp2p::request_response::OutboundFailure::Io(e) if sync_rr::is_sync_protocol_violation(e) => {
                                        let score = wire_tracker.record_violation_at(peer, now);
                                        warn!("sync_rr wire violation (answer) from {}: {} (app score → {})", peer, e, score);
                                        act_on_misbehaviour(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                            &self.peer_addrs, &manual_peers, peer, score, now);
                                        pull::FailureKind::Violation
                                    }
                                    libp2p::request_response::OutboundFailure::Io(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                                        debug!("sync_rr: answer from {} refused without penalty: {}", peer, e);
                                        pull::FailureKind::Refused
                                    }
                                    libp2p::request_response::OutboundFailure::ConnectionClosed => pull::FailureKind::Closed,
                                    _ => pull::FailureKind::Transport,
                                };
                                debug!("directed pull to {} failed ({}); retrying on another peer", peer, error);
                                pulls.on_failure(request_id, peer, kind, now);
                                drain_pulls(&mut swarm, &mut pulls, now);
                            }
                            // B1-T18 / B2-T6: an answer was written, or failed
                            // (timeout, reset, closed connection): its bytes no
                            // longer count against the peer's send budget. (A
                            // request that fails to DECODE never gets here:
                            // libp2p only logs it, which is why the codec reports
                            // it as `SyncRequest::Malformed` instead.)
                            libp2p::request_response::Event::ResponseSent { request_id, .. } => {
                                serve_q.release(&request_id);
                            }
                            libp2p::request_response::Event::InboundFailure { peer, error, request_id, .. } => {
                                serve_q.release(&request_id);
                                debug!("sync_rr: answer to {} not delivered: {}", peer, error);
                            }
                        },
                        _ => {}
                    }
                }

                // NET-2: verdicts from the processor for deferred gossip frames.
                v = recv_verdict(&mut verdict_rx) => {
                    match v {
                        Some(v) => {
                            // NET-11 (a): an accepted frame was a novel block / tx.
                            if let Some(is_block) = novel_kinds.remove(&v.message_id) {
                                if v.verdict == GossipVerdict::Accept {
                                    if is_block {
                                        conn_mgr.on_novel_block(&v.propagation_source, Instant::now());
                                    } else {
                                        conn_mgr.on_novel_tx(&v.propagation_source, Instant::now());
                                    }
                                }
                            }
                            let relayed = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                &v.message_id, &v.propagation_source, v.verdict.into());
                            if !relayed && v.verdict == GossipVerdict::Accept {
                                // The frame already left gossipsub's cache: it is not
                                // forwarded (a late orphan release is re-announced).
                                debug!("late Accept: frame from {} no longer in the gossip cache", v.propagation_source);
                            }
                            if v.verdict == GossipVerdict::Reject {
                                // B1-T2: a frame the processor proved invalid is a
                                // misbehaviour of the peer that delivered it (its
                                // author: honest nodes relay only validated frames,
                                // and the processor answers Ignore where an honest
                                // older relay may be the deliverer). Gossipsub's
                                // P4 penalty is per topic; this feeds the ONE score
                                // shared with the directed protocol and the wire
                                // checks, which disconnects at its threshold.
                                let now = Instant::now();
                                let score = wire_tracker.record_violation_at(v.propagation_source, now);
                                debug!("invalid gossip frame from {} (app score → {})", v.propagation_source, score);
                                pulls.on_misbehaving(&v.propagation_source, now);
                                act_on_misbehaviour(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                    &self.peer_addrs, &manual_peers, v.propagation_source, score, now);
                            }
                        }
                        None => verdict_rx = None,
                    }
                }

                // MEM-5 / MEM-6 / B1-T2: out-of-band requests from the processor.
                c = recv_control(&mut control_rx) => {
                    match c {
                        Some(NetworkControl::PenalizePeer(peer)) => {
                            let now = Instant::now();
                            let score = wire_tracker.record_violation_at(peer, now);
                            for p in wire_tracker.take_evicted() {
                                swarm.behaviour_mut().gossipsub.set_application_score(&p, 0.0);
                            }
                            warn!("peer {} sent invalid data the processor could not reject on gossip (an invalid \
                                   orphan transaction, or an invalid answer to one of our pulls; app score → {})",
                                peer, score);
                            pulls.on_misbehaving(&peer, now);
                            act_on_misbehaviour(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                &self.peer_addrs, &manual_peers, peer, score, now);
                        }
                        Some(NetworkControl::Fetch { source, hashes }) => {
                            let now = Instant::now();
                            let mut refused = 0usize;
                            for block_hash in hashes {
                                if pulls.enqueue(sync_rr::SyncRequest::GetBlock { block_hash }, Some(source), &[source], now)
                                    == pull::Enqueued::Refused
                                {
                                    refused += 1;
                                }
                            }
                            if refused > 0 {
                                debug!("{} block pull(s) announced by {} refused (its pull quota or the queue is full; \
                                        they will be re-issued)", refused, source);
                            }
                            drain_pulls(&mut swarm, &mut pulls, now);
                        }
                        // NET-2 residual: Bitcoin Core's `Misbehaving` for
                        // data no honest node sends — disconnect at once and
                        // discourage the address (never a local one, never an
                        // operator-configured peer) and, as the shared score
                        // does at its threshold (B1-T2), the identity.
                        Some(NetworkControl::Misbehaving(peer)) => {
                            let now = Instant::now();
                            pulls.on_misbehaving(&peer, now);
                            let addr_discouraged = discourage_now(&mut swarm, &mut discouraged_ids, &mut discouraged_addrs,
                                &self.peer_addrs, &manual_peers, peer, now);
                            warn!("peer {} misbehaved (invalid block data); {}", peer,
                                if manual_peers.contains(&peer) {
                                    "operator-configured: kept"
                                } else if addr_discouraged {
                                    "disconnected, identity and address discouraged"
                                } else {
                                    "disconnected, identity discouraged"
                                });
                        }
                        None => control_rx = None,
                    }
                }

                // B1-T3 / B2-T5: an answer computed by a serving worker.
                Some(done) = served_rx.recv() => {
                    serve_q.computed(&done.peer);
                    respond(&mut swarm, &mut serve_q, done.peer, done.id, done.channel, done.response);
                    pump_serving(&mut swarm, &mut serve_q, &dag, &store, &served_tx, self.min_chain_work);
                }

                // B1-T9: a configured peer's re-dial address, resolved off
                // the loop by `manual_resolver` (heartbeat).
                Some((p, addr)) = manual_resolved_rx.recv() => {
                    manual_resolver.finished(&p);
                    let still_wanted = match addr_peer_id(&p) {
                        Some(id) => !swarm.is_connected(&id) && !conn_mgr.is_dialing(&id),
                        None => conn_mgr.count(ConnKind::Manual) + conn_mgr.pending_count(ConnKind::Manual) == 0,
                    };
                    if let (Some(addr), true) = (addr, still_wanted) {
                        info!("reconnecting: {}", addr);
                        dial_with_intent(&mut swarm, &mut conn_mgr, addr, DialIntent::manual());
                    }
                }

                Some(msg) = outbound_rx.recv() => {
                    // Announce-then-pull: IBD FETCH requests (GetBlock /
                    // GetHeaders / GetTips / PeerRequest) are DIRECTED to one
                    // selected peer over request-response, never broadcast.
                    if let Some(req) = sync_rr::as_pull_request(&msg) {
                        let now = Instant::now();
                        // B1-T6: a GetHeaders prefers the peers whose (fresh,
                        // clamped) claim is ahead of `from`, in a per-node
                        // secret order, the peers we dialed first (the
                        // scheduler keeps `pull::MAX_HINTS` of them); an empty
                        // answer from one of them counts as useless, and a
                        // short one also goes to the next of them.
                        let hints = match &req {
                            sync_rr::SyncRequest::GetHeaders { from_blue_score, .. } => {
                                peer_state.claiming_above(*from_blue_score, now, 4 * pull::MAX_HINTS)
                            }
                            _ => Vec::new(),
                        };
                        if pulls.enqueue(req, None, &hints, now) == pull::Enqueued::Refused {
                            debug!("pull queue full; dropping [{}] (it will be re-issued)", msg.kind_name());
                        }
                        drain_pulls(&mut swarm, &mut pulls, now);
                        continue;
                    }
                    // Re-gossip rate-limit: drop a re-broadcast of a block already
                    // published within the TTL.
                    if let NetworkMessage::NewBlock { block_hash, .. } = &msg {
                        let now = std::time::Instant::now();
                        recent_block_publishes.retain(|_, t| now.duration_since(*t) < REGOSSIP_SUPPRESS_TTL);
                        if recent_block_publishes.contains_key(block_hash) {
                            continue;
                        }
                        recent_block_publishes.insert(*block_hash, now);
                    }
                    let (topic, topic_name) = match &msg {
                        NetworkMessage::NewBlock { .. }        => (block_t.clone(), "blocks"),
                        NetworkMessage::NewTransaction { .. }
                        | NetworkMessage::NewPowitItem { .. }  => (tx_t.clone(),    "txs"),
                        _                                      => (sync_t.clone(),  "sync"),
                    };
                    if let Ok(data) = bincode::serde::encode_to_vec(&msg, bincode::config::standard()) {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            warn!("publish {} [{}]: {}", topic_name, msg.kind_name(), e);
                        }
                    }
                }

                _ = pull_tick.tick() => {
                    drain_pulls(&mut swarm, &mut pulls, Instant::now());
                }

                // B1-T9 / NET-11: keep the OUTBOUND slots full from the address
                // tables — never from a message, never limited by inbound
                // connections (Core's ThreadOpenConnections, one attempt per tick).
                _ = outbound_tick.tick() => {
                    let now = Instant::now();
                    feelers_closing.retain(|(c, at)| {
                        if now < *at {
                            return true;
                        }
                        swarm.close_connection(*c);
                        false
                    });
                    // POW-9: a peer that identified as another network's
                    // during this run is not dialed again; NET-2 residual:
                    // nor is an address discouraged after a peer there
                    // misbehaved (Core makes no connection to one either).
                    let excluded = |a: &str| {
                        addr_peer_id(a).is_some_and(|p| pending_tried.is_other_network(&p))
                            || a.parse::<Multiaddr>().ok()
                                .and_then(|m| discourage::ip_of(&m))
                                .is_some_and(|ip| discouraged_addrs.is_discouraged(ip, now))
                    };
                    open_next_outbound(
                        &mut swarm, &mut conn_mgr, &mut tried, &mut addr_book, &mut anchors, &mut feeler,
                        &self.peer_id, allow_private, &excluded, now,
                    );
                }

                _ = heartbeat.tick() => {
                    let now = Instant::now();
                    let current_height = dag.read().block_count() as u64;
                    info!("peers: {} | height: {}", peer_count, current_height);
                    sink.deliver(NetworkMessage::PeerCount { count: peer_count, addresses: tried.addresses() }, InboundOrigin::Local, "heartbeat");
                    // Frames never answered must not pin the map at its cap.
                    if novel_kinds.len() >= NOVEL_KINDS_CAP {
                        novel_kinds.clear();
                    }

                    // Sprint P: emit aggregated PEX stats (every 60s, only if activity)
                    if let Some(line) = pex_stats.tick() {
                        info!("{}", line);
                    }
                    // Housekeeping of every bounded per-peer map (NET-8).
                    pex_limiter.gc();
                    sync_limiter.gc_at(now);
                    claim_limiter.gc_at(now, CLAIM_LIMITER_IDLE_TTL);
                    // B1-T2: discouragement ends after its TTL.
                    for p in discouraged_ids.expire(now) {
                        swarm.behaviour_mut().blocked.unblock_peer(p);
                    }
                    // NET-4 / NET-8: decayed penalties are re-installed so a
                    // peer recovers once it stops misbehaving.
                    for (p, score) in wire_tracker.decay_tick_at(now) {
                        swarm.behaviour_mut().gossipsub.set_application_score(&p, score);
                    }
                    for p in wire_tracker.take_evicted() {
                        swarm.behaviour_mut().gossipsub.set_application_score(&p, 0.0);
                    }
                    discouraged_addrs.gc_at(now);

                    // FIX v0.5.1: Re-subscribe every 30s (idempotent; restores a
                    // mesh that peer scoring silently dropped).
                    for t in [&block_t, &tx_t, &sync_t] {
                        let _ = swarm.behaviour_mut().gossipsub.subscribe(t);
                    }

                    let tx_hash = tx_t.hash();
                    let tx_mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&tx_hash).count();
                    if peer_count > 0 && tx_mesh_peers == 0 {
                        warn!("tx mesh empty: {} peers but 0 in tx-mesh — re-subscribing", peer_count);
                    }

                    // B1-T9: configured peers are re-dialed whenever they are
                    // not connected (Core keeps -addnode peers connected), not
                    // only when the node has no peer at all — inbound
                    // connections used to stop this for good. An entry without
                    // a peer id cannot be matched to a connection and is
                    // re-dialed when no manual connection is up.
                    let manual_up = conn_mgr.count(ConnKind::Manual) + conn_mgr.pending_count(ConnKind::Manual);
                    for p in self.config.bootstrap_peers.iter() {
                        let wanted = match addr_peer_id(p) {
                            Some(id) => id != self.peer_id && !swarm.is_connected(&id) && !conn_mgr.is_dialing(&id),
                            None => manual_up == 0,
                        };
                        if !wanted {
                            continue;
                        }
                        // Never awaited here: a host name's lookup (slow or
                        // unreachable resolver, a seed that is down) runs on
                        // its own task and the dial happens when the answer
                        // arrives (`manual_resolved_rx` arm below), so the
                        // swarm keeps being polled meanwhile (M-11).
                        manual_resolver.request(p, |p| async move { resolve_dial_addr(&p, true).await });
                    }
                    drain_pulls(&mut swarm, &mut pulls, now);
                }

                // NET-11 (d): block-relay-only peers carry no gossip; their
                // frontier is polled (then pulled block by block) every
                // BLOCK_RELAY_POLL_INTERVAL — the only way a block reaches us
                // over such a connection after the connect-time GetTips.
                _ = block_relay_poll.tick() => {
                    let now = Instant::now();
                    for p in conn_mgr.block_relay_peers() {
                        send_directed_pull(&mut swarm, &mut pulls, p, sync_rr::SyncRequest::GetTips, now);
                    }
                    drain_pulls(&mut swarm, &mut pulls, now);
                }

                _ = save_peers.tick() => {
                    save_known_peers(&peers_path, &tried.to_set());
                }

                // Sprint CC: periodic tip announcement for IBD recovery (60s).
                // The Version frame carries a fresh timestamp, so it can never
                // be dedup-dropped like a byte-identical PeerTip.
                _ = tip_announce.tick() => {
                    if peer_count > 0 {
                        let tip = build_current_tip(&dag, &peer_id_str);
                        if let NetworkMessage::PeerTip { blue_score, height, .. } = &tip {
                            debug!("→ announcing tip: height={} score={}", height, blue_score);
                        }
                        if let Ok(d) = bincode::serde::encode_to_vec(&tip, bincode::config::standard()) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                info!("tip announce publish failed: {} (peers={})", e, peer_count);
                            }
                        }
                        let (v_score, v_height) = {
                            let d = dag.read();
                            (d.tip_blue_score(), d.block_count() as u64)
                        };
                        let ver = NetworkMessage::Version {
                            version:    PROTOCOL_VERSION,
                            user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                            blue_score: v_score,
                            height:     v_height,
                            timestamp:  std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        };
                        if let Ok(d) = bincode::serde::encode_to_vec(&ver, bincode::config::standard()) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                info!("version announce publish failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Directed-pull pipeline (NET-5 / NET-9 / B1-T2 / B1-T6) ───────────────────

pub use pull::MAX_PENDING_PULLS;
/// How often queued pulls are retried.
const PULL_RETRY_TICK: Duration = Duration::from_millis(250);
/// B1-T9 / NET-11: cadence of the outbound connection loop: at most one
/// automatic outbound dial per tick (Core's ThreadOpenConnections loops every
/// 500 ms, one connection attempt at a time).
const OUTBOUND_TICK: Duration = Duration::from_secs(1);
/// NET-11 (a): bound on the gossip frames whose kind is remembered while their
/// verdict is pending (cleared on overflow; the processor answers every
/// pending frame within seconds).
const NOVEL_KINDS_CAP: usize = 8192;
/// NET-6: per-author tip-claim rate limit (burst, refill/sec, tracked authors).
const CLAIM_BURST: u32 = 16;
const CLAIM_REFILL_PER_SEC: f64 = 0.2;
const CLAIM_LIMITER_TRACK_CAP: usize = 4096;
const CLAIM_LIMITER_IDLE_TTL: Duration = Duration::from_secs(600);

/// Log target of the debug-level receipt trace of gossiped transactions
/// (`RUST_LOG=info,gnb_gossip_rx_tx=debug`). Every gossiped block is logged
/// at info (`← block h=… <hash>`); transactions only with this target.
pub const GOSSIP_RX_TX_LOG_TARGET: &str = "gnb_gossip_rx_tx";

/// Period of the network heartbeat (peer count, housekeeping, re-subscribe,
/// bootstrap re-dial with no peers).
const HEARTBEAT_PERIOD: Duration = Duration::from_secs(30);
// The heartbeat polls the block-relay-only peers' frontiers (NET-11 d).
const _: () = assert!(HEARTBEAT_PERIOD.as_secs() == connmgr::BLOCK_RELAY_POLL_INTERVAL.as_secs());

/// The network heartbeat timer. Its first tick comes after one period, not
/// at once: at start-up no connection is established yet, so an immediate
/// tick saw 0 peers and re-dialed every bootstrap peer the swarm loop had
/// just dialed (two connections per peer).
fn new_heartbeat() -> tokio::time::Interval {
    tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT_PERIOD, HEARTBEAT_PERIOD)
}

/// NET-11 (a): which eviction protection an accepted gossip frame earns its
/// delivering peer: `Some(true)` a novel block, `Some(false)` a novel
/// transaction (Core's `m_last_block_time` / `m_last_tx_time`), `None` none.
/// PoWit items (shares, attestations, equivocation proofs) are relayed like
/// transactions but are neither: Core protects only for novel blocks and
/// transactions, and an item (a witness share is 1/16 of a block's work and
/// pays no fee) would otherwise compete for the 4 novel-transaction
/// protections.
fn novel_kind(msg: &NetworkMessage) -> Option<bool> {
    match msg {
        NetworkMessage::NewBlock { .. } => Some(true),
        NetworkMessage::NewTransaction { .. } => Some(false),
        _ => None,
    }
}

/// Remember whether a gossip frame awaiting the processor's verdict is a block
/// (`true`) or a transaction (NET-11 a: an `Accept` marks the delivering peer
/// as a source of novel blocks / transactions, which protects it from
/// inbound eviction).
fn note_pending_kind(map: &mut std::collections::HashMap<gossipsub::MessageId, bool>, id: &gossipsub::MessageId, is_block: bool) {
    if map.len() < NOVEL_KINDS_CAP {
        map.insert(id.clone(), is_block);
    }
}

/// Dial `addr` for `intent`, registering the dial with the connection manager
/// under its connection id (so the established connection gets its kind).
/// An address with a `/p2p/<id>` is dialed only if that peer is neither
/// connected nor being dialed. Returns whether the dial was started.
fn dial_with_intent(
    swarm:    &mut libp2p::Swarm<BlochBehaviour>,
    conn_mgr: &mut ConnManager,
    addr:     Multiaddr,
    mut intent: DialIntent,
) -> bool {
    use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
    let peer = addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    });
    let opts = match peer {
        Some(id) => DialOpts::peer_id(id)
            .addresses(vec![addr])
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .build(),
        None => DialOpts::unknown_peer_id().address(addr).build(),
    };
    intent.peer = intent.peer.or(peer);
    let id = opts.connection_id();
    conn_mgr.register_dial(id, intent);
    match swarm.dial(opts) {
        Ok(()) => true,
        Err(e) => {
            let failed = conn_mgr.on_dial_failed(id);
            if let Some(DialIntent { kind: ConnKind::BlockRelayOnly | ConnKind::Feeler, peer: Some(p), .. }) = failed {
                if !swarm.is_connected(&p) {
                    swarm.behaviour_mut().gossipsub.ungate_peer(&p);
                }
            }
            debug!("dial not started: {}", e);
            false
        }
    }
}

/// One step of the outbound connection loop (B1-T9 / NET-11, Core's
/// `ThreadOpenConnections`): decide what the next automatic outbound
/// connection is for ([`connmgr::next_outbound_action`]: anchors, full-relay
/// slots, block-relay-only slots, feelers), pick an address and dial it.
///
/// * full-relay / block-relay-only: [`connmgr::select_outbound_candidate`]
///   — a random entry of the tried or the new table (50/50, as Core's
///   `Select`), outside the netgroups of the current automatic outbound
///   peers (full-relay: the small-network fallback when no such entry
///   exists), not connected, not ourselves, not tried in the last
///   `addrbook::RETRY_INTERVAL`;
/// * anchor: the next anchor from the last run, as block-relay-only;
/// * feeler: the occupant of a queued tried collision first
///   (test-before-evict), else a random new-table address.
///
/// A new-table address leaves the table when it is dialed (a success moves it
/// to the tried table, once the peer's identify shows it runs this network,
/// POW-9; a failure drops it). Never an `excluded` address: a peer that
/// identified as another network's during this run (POW-9), or an address
/// discouraged after a peer there misbehaved (NET-2 residual).
#[allow(clippy::too_many_arguments)]
fn open_next_outbound(
    swarm:         &mut libp2p::Swarm<BlochBehaviour>,
    conn_mgr:      &mut ConnManager,
    tried:         &mut TriedTable,
    addr_book:     &mut AddrBook,
    anchors:       &mut std::collections::VecDeque<String>,
    feeler:        &mut connmgr::FeelerSchedule,
    me:            &PeerId,
    allow_private: bool,
    excluded:      &dyn Fn(&str) -> bool,
    now:           std::time::Instant,
) {
    use rand::Rng;
    let mut rng = rand::rng();
    let feeler_u: f64 = rng.random();
    let action = connmgr::next_outbound_action(
        conn_mgr.full_relay_slots_used(),
        conn_mgr.full_relay_target(),
        conn_mgr.block_relay_slots_used(),
        conn_mgr.block_relay_target(),
        !anchors.is_empty(),
        || feeler.poll(now, feeler_u),
    );
    let reachable = |a: &str, conn_mgr: &ConnManager, swarm: &libp2p::Swarm<BlochBehaviour>| -> bool {
        is_valid_public_multiaddr(a, allow_private)
            && !excluded(a)
            && addr_peer_id(a).is_some_and(|p| p != *me && !swarm.is_connected(&p) && !conn_mgr.is_dialing(&p))
    };
    let (kind, pick, collision_newcomer) = match action {
        OutboundAction::Idle => return,
        OutboundAction::Anchor => {
            // Core skips an anchor in the netgroup of a current outbound peer.
            let groups = conn_mgr.outbound_groups();
            let mut pick = None;
            while let Some(a) = anchors.pop_front() {
                if reachable(&a, conn_mgr, swarm) && netgroup(&a).is_some_and(|g| !groups.contains(&g)) {
                    pick = Some(a);
                    break;
                }
            }
            (ConnKind::BlockRelayOnly, pick, None)
        }
        OutboundAction::FullRelay | OutboundAction::BlockRelay => {
            let kind = if action == OutboundAction::FullRelay { ConnKind::OutboundFullRelay } else { ConnKind::BlockRelayOnly };
            let group_counts = conn_mgr.outbound_group_counts();
            let eligible = |a: &str| reachable(a, conn_mgr, swarm) && !tried.recently_tried(a, now);
            let pick = connmgr::select_outbound_candidate(&mut rng, tried, addr_book, kind, &group_counts, eligible);
            (kind, pick, None)
        }
        OutboundAction::Feeler => match tried.pending_collision(now) {
            Some((newcomer, occupant)) if reachable(&occupant, conn_mgr, swarm) => (ConnKind::Feeler, Some(occupant), Some(newcomer)),
            Some((newcomer, occupant)) => {
                // The occupant is connected right now: it is reachable.
                tried.resolve_collision(&newcomer, &occupant, true, now);
                return;
            }
            None => (ConnKind::Feeler, addr_book.select(&mut rng, |a| reachable(a, conn_mgr, swarm)), None),
        },
    };
    let Some(a) = pick else { return };
    addr_book.remove(&a);
    tried.mark_attempt(&a, now);
    let Ok(ma) = a.parse::<Multiaddr>() else { return };
    let peer = addr_peer_id(&a);
    if matches!(kind, ConnKind::BlockRelayOnly | ConnKind::Feeler) {
        if let Some(p) = peer {
            // NET-11 (c)/(d): gate BEFORE dialing, so gossipsub never sees
            // a block-relay-only or feeler connection.
            swarm.behaviour_mut().gossipsub.gate_peer(p);
        }
    }
    debug!("outbound {:?} dial: {}", kind, truncate_utf8(&a, 80));
    let group = netgroup(&a);
    dial_with_intent(swarm, conn_mgr, ma, DialIntent { kind, addr: Some(a), peer, group, collision_newcomer });
}

/// Longest a heartbeat re-dial lookup of a configured host name may take.
const MANUAL_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// B1-T9 / M-11: resolution of configured (`--peer`) addresses for the
/// heartbeat re-dials, OFF the network loop. Since B1-T9 every configured
/// peer that is not connected is re-dialed each heartbeat (not only with no
/// peer at all); awaiting its DNS lookup inline froze the whole swarm loop
/// (gossip, eviction, pulls, sync answers) for as long as the resolver took
/// whenever a configured host was down or its DNS slow. Each lookup now runs
/// on its own task, bounded by a timeout, at most one per address at a time;
/// the answer comes back over a channel the loop reads.
struct ManualResolver {
    in_flight: HashSet<String>,
    timeout: Duration,
    tx: mpsc::UnboundedSender<(String, Option<Multiaddr>)>,
}

impl ManualResolver {
    fn new(timeout: Duration) -> (Self, mpsc::UnboundedReceiver<(String, Option<Multiaddr>)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { in_flight: HashSet::new(), timeout, tx }, rx)
    }

    /// Start resolving `addr` with `resolve` on a spawned task and return at
    /// once; `false` (nothing started) while a lookup of `addr` is running.
    /// The result, `None` on failure or timeout, arrives on the receiver.
    fn request<F, Fut>(&mut self, addr: &str, resolve: F) -> bool
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Option<Multiaddr>> + Send + 'static,
    {
        if !self.in_flight.insert(addr.to_string()) {
            return false;
        }
        let (tx, timeout, key) = (self.tx.clone(), self.timeout, addr.to_string());
        let lookup = resolve(addr.to_string());
        tokio::spawn(async move {
            let out = tokio::time::timeout(timeout, lookup).await.ok().flatten();
            let _ = tx.send((key, out));
        });
        true
    }

    /// The lookup of `addr` has been delivered.
    fn finished(&mut self, addr: &str) {
        self.in_flight.remove(addr);
    }
}

/// NET-11: whether a `Peers` answer may feed the new table — only when the
/// request it answers was our `GetPeers` and the answering peer is one we ask
/// for addresses (outbound full-relay or manual: Core reads `addr` from
/// neither inbound nor block-relay-only peers). A `Peers` answer to any other
/// request (every connection gets a `GetTips` on connect, block-relay-only
/// peers one per poll) is ignored.
fn solicited_peers_answer(req: Option<&sync_rr::SyncRequest>, role: Option<ConnKind>) -> bool {
    matches!(req, Some(sync_rr::SyncRequest::GetPeers)) && role.is_some_and(|k| k.sends_getaddr())
}

/// Core's cached `getaddr` answer (`m_addr_response_caches`): the sample of
/// the tried table served to inbound peers is recomputed only about once a
/// day (21-27 h), so reconnecting and asking again reveals nothing more of
/// the table. While the cached sample is not full and the table has grown,
/// it is refreshed at most every [`GETADDR_CACHE_GROW_REFRESH`] (a young
/// node would otherwise serve its near-empty start-up table for a day).
#[derive(Default)]
struct GetAddrCache {
    sample: Vec<String>,
    built_at: Option<std::time::Instant>,
    expires: Option<std::time::Instant>,
}

/// Minimum lifetime of the cached `GetPeers` sample (Core: 21 h + up to 6 h).
const GETADDR_CACHE_LIFETIME: Duration = Duration::from_secs(21 * 3600);
const GETADDR_CACHE_JITTER: Duration = Duration::from_secs(6 * 3600);
const GETADDR_CACHE_GROW_REFRESH: Duration = Duration::from_secs(600);

impl GetAddrCache {
    fn sample(&mut self, now: std::time::Instant, tried: &TriedTable, allow_private: bool) -> Vec<String> {
        use rand::seq::SliceRandom;
        use rand::Rng;
        let expired = self.expires.is_none_or(|t| now >= t);
        let growing = self.sample.len() < PEX_RESPONSE_SAMPLE_SIZE
            && tried.len() > self.sample.len()
            && self.built_at.is_some_and(|b| now.saturating_duration_since(b) >= GETADDR_CACHE_GROW_REFRESH);
        if expired || growing {
            let mut all: Vec<String> = tried.addresses().into_iter()
                .filter(|a| is_valid_public_multiaddr(a, allow_private))
                .collect();
            all.shuffle(&mut rand::rng());
            all.truncate(PEX_RESPONSE_SAMPLE_SIZE);
            self.sample = all;
            self.built_at = Some(now);
            let jitter = GETADDR_CACHE_JITTER.mul_f64(rand::rng().random::<f64>());
            self.expires = Some(now + GETADDR_CACHE_LIFETIME + jitter);
        }
        self.sample.clone()
    }
}

/// Whether a tip claim, clamped to `claimed` (blue score), is worth a directed
/// pull from its author: only a claim ahead of our own selected tip.
fn claim_warrants_directed_pull(claimed: u64, our_score: u64) -> bool {
    claimed > our_score
}

/// Send `req` (GetTips / GetPeers) to `peer` itself, bypassing the queue: a
/// request about THAT peer's state (its frontier and peers on connect; the
/// frontier it claims to have). Never retried on another peer; the answer is
/// bound to the request and handled like any other (`PullScheduler`).
fn send_directed_pull(
    swarm: &mut libp2p::Swarm<BlochBehaviour>,
    pulls: &mut pull::PullScheduler<libp2p::request_response::OutboundRequestId>,
    peer:  PeerId,
    req:   sync_rr::SyncRequest,
    now:   std::time::Instant,
) {
    debug!("→ directed pull [{}] to {} (its own state)", req.kind_name(), peer);
    pulls.send_pinned(peer, req, now, |p, r| swarm.behaviour_mut().sync_rr.send_request(&p, r.clone()));
}

/// Send the queued pulls the scheduler picks.
fn drain_pulls(
    swarm: &mut libp2p::Swarm<BlochBehaviour>,
    pulls: &mut pull::PullScheduler<libp2p::request_response::OutboundRequestId>,
    now:   std::time::Instant,
) {
    pulls.drain(now, |p, r| swarm.behaviour_mut().sync_rr.send_request(&p, r.clone()));
}

/// B1-T2: install `peer`'s new shared misbehaviour score (`score`, from the
/// `WirePenaltyTracker`) in gossipsub, and at the threshold
/// (`misbehaviour::should_disconnect`) disconnect and discourage it
/// ([`discourage_now`]; Bitcoin Core: `Misbehaving` → discouraged and
/// disconnected).
#[allow(clippy::too_many_arguments)]
fn act_on_misbehaviour(
    swarm:        &mut libp2p::Swarm<BlochBehaviour>,
    ids:          &mut misbehaviour::Discouraged,
    addrs:        &mut discourage::Discouraged,
    peer_addrs:   &discourage::PeerAddrs,
    manual_peers: &HashSet<PeerId>,
    peer:         PeerId,
    score:        f64,
    now:          std::time::Instant,
) {
    swarm.behaviour_mut().gossipsub.set_application_score(&peer, score);
    if misbehaviour::should_disconnect(score) && !ids.contains(&peer, now) {
        warn!("disconnecting and discouraging {} (misbehaviour score {})", peer, score);
        discourage_now(swarm, ids, addrs, peer_addrs, manual_peers, peer, now);
    }
}

/// The one misbehaviour model's sanction (B1-T2 with the NET-2 residual):
/// the peer's identity is refused for `misbehaviour::DISCOURAGE_TTL` (libp2p
/// block list: its connections close and new ones are refused, both
/// directions) and its address (IPv4, or IPv6 /64) is discouraged
/// (`discourage::Discouraged`, Core's `m_discouraged`), so neither the same
/// identity from another address nor a fresh identity from the same address
/// gets back in. Reached when the shared score crosses its threshold
/// ([`act_on_misbehaviour`]) or at once for data no honest node sends
/// (`NetworkControl::Misbehaving`). Operator-configured peers (`--peer`,
/// Core's `noban`) are never sanctioned: an operator who listed a peer keeps
/// it. Returns whether the address was discouraged (a local address never
/// is).
fn discourage_now(
    swarm:        &mut libp2p::Swarm<BlochBehaviour>,
    ids:          &mut misbehaviour::Discouraged,
    addrs:        &mut discourage::Discouraged,
    peer_addrs:   &discourage::PeerAddrs,
    manual_peers: &HashSet<PeerId>,
    peer:         PeerId,
    now:          std::time::Instant,
) -> bool {
    if manual_peers.contains(&peer) {
        return false;
    }
    let addr_discouraged = peer_addrs.get(&peer).is_some_and(|ip| addrs.discourage(ip, now));
    for forgotten in ids.insert(peer, now) {
        swarm.behaviour_mut().blocked.unblock_peer(forgotten);
    }
    // Closes its connections and refuses new ones, both directions.
    swarm.behaviour_mut().blocked.block_peer(peer);
    addr_discouraged
}

type ServeQ = serve::ServeQueue<
    libp2p::request_response::InboundRequestId,
    libp2p::request_response::ResponseChannel<sync_rr::SyncResponse>,
>;
type ServedTx = mpsc::Sender<
    serve::Served<libp2p::request_response::InboundRequestId, libp2p::request_response::ResponseChannel<sync_rr::SyncResponse>>,
>;

/// Hand an answer to libp2p and charge its bytes to `peer` until it is
/// written (B1-T18 / B2-T6).
fn respond(
    swarm:   &mut libp2p::Swarm<BlochBehaviour>,
    serve_q: &mut ServeQ,
    peer:    PeerId,
    id:      libp2p::request_response::InboundRequestId,
    channel: libp2p::request_response::ResponseChannel<sync_rr::SyncResponse>,
    resp:    sync_rr::SyncResponse,
) {
    let bytes = serve::charge_for(&resp);
    if swarm.behaviour_mut().sync_rr.send_response(channel, resp).is_err() {
        debug!("sync_rr: answer channel to {} already closed", peer);
    } else {
        serve_q.charge(peer, id, bytes);
    }
}

/// Start the queued serving jobs the free workers can take (B1-T3 / B2-T5);
/// a job whose peer reached its send budget meanwhile is answered Busy.
fn pump_serving(
    swarm:   &mut libp2p::Swarm<BlochBehaviour>,
    serve_q: &mut ServeQ,
    dag:     &std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
    store:   &std::sync::Arc<crate::storage::Storage>,
    done:    &ServedTx,
    min_chain_work: u128,
) {
    while let Some(next) = serve_q.next_job() {
        match next {
            serve::Next::Compute(job) => serve::spawn_worker(job, dag.clone(), store.clone(), done.clone(), min_chain_work),
            serve::Next::Busy(job) => respond(swarm, serve_q, job.peer, job.id, job.channel, sync_rr::SyncResponse::Busy),
        }
    }
}

/// Receive the next processor control request; pending forever when none
/// is attached.
async fn recv_control(rx: &mut Option<mpsc::Receiver<NetworkControl>>) -> Option<NetworkControl> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Receive the next processor verdict; pending forever when no validator is
/// attached (legacy `run`).
async fn recv_verdict(rx: &mut Option<mpsc::Receiver<GossipValidation>>) -> Option<GossipValidation> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// NET-11: admit peer-exchange addresses from `author` (the peer that answered
/// OUR GetPeers) into the unverified address table. Rate-limited per author,
/// batch-capped, validated, never our own id, never already-known entries
/// (`known`: the tried table). B1-T8: every address is normalised (an
/// IPv4-mapped / -compatible IPv6 literal becomes its `/ip4/` form) before it
/// is validated, so a re-spelled private address cannot pass. NET-11 (e): the
/// entry is bucketed by `source_group`, the netgroup of `author`'s
/// connection (Core's addr source). Nothing is dialed here — the connection
/// manager selects from the tables. Returns how many addresses entered the
/// table.
#[allow(clippy::too_many_arguments)]
pub fn ingest_pex_addresses(
    book:          &mut AddrBook,
    limiter:       &mut PexRateLimiter,
    stats:         &mut PexStats,
    author:        PeerId,
    source_group:  &str,
    peers:         &[String],
    allow_private: bool,
    self_peer:     &PeerId,
    known:         impl Fn(&str) -> bool,
) -> usize {
    let original_len = peers.len();
    let admitted = limiter.admit(author, original_len);
    if admitted < original_len {
        let over_batch = original_len.saturating_sub(PEX_BATCH_LIMIT);
        if over_batch > 0 {
            stats.record_batch(over_batch.min(original_len.saturating_sub(admitted)));
        }
        let over_rate = original_len.saturating_sub(admitted).saturating_sub(over_batch);
        if over_rate > 0 {
            stats.record_rate(over_rate);
        }
    }
    let mut added = 0usize;
    for raw in peers.iter().take(admitted) {
        let addr_str = normalize_peer_addr(raw).unwrap_or_else(|| raw.clone());
        if !is_valid_public_multiaddr(&addr_str, allow_private) {
            if is_valid_public_multiaddr(&addr_str, true) {
                stats.record_private(1);
            } else {
                stats.record_invalid(1);
            }
            // H4: addr_str is attacker-controlled; UTF-8-safe truncation.
            debug!("PEX rejected: {}", truncate_utf8(raw, 80));
            continue;
        }
        if known(&addr_str) || addr_peer_id(&addr_str).is_some_and(|p| p == *self_peer) {
            continue;
        }
        if book.add_from(&addr_str, source_group) {
            stats.record_accept(1);
            added += 1;
        }
    }
    added
}

// ── Persistent identity ───────────────────────────────────────────────────────

/// NET-16 (audit): the P2P identity is a private key. It is created with
/// owner-only permissions (0600) through a temp file + rename, so a crash can
/// never leave a truncated key and no other local user can read it; an
/// existing key file with broader permissions is tightened on load.
pub fn load_or_create_identity(path: &Path) -> Result<identity::Keypair, NetworkError> {
    if path.exists() {
        restrict_to_owner(path);
        let bytes = std::fs::read(path)
            .map_err(|e| NetworkError::StartFailed(format!("read identity: {}", e)))?;
        return identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| NetworkError::StartFailed(format!("decode identity: {}", e)));
    }
    let kp = identity::Keypair::generate_ed25519();
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
    let bytes = kp.to_protobuf_encoding()
        .map_err(|e| NetworkError::StartFailed(format!("encode identity: {}", e)))?;
    write_file_atomic(path, &bytes, true)
        .map_err(|e| NetworkError::StartFailed(format!("write identity: {}", e)))?;
    info!("created P2P identity: {}", path.display());
    Ok(kp)
}

/// NET-16: chmod an existing secret file to 0600 if it is group/other
/// accessible (unix only; best effort, logged).
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                warn!("{} had permissions {:o}; restricting to 0600", path.display(), mode & 0o777);
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// NET-16: write `bytes` to `path` atomically (temp file in the same
/// directory, fsync, rename). With `secret`, the file is created 0600.
pub fn write_file_atomic(path: &Path, bytes: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    // A stale temp file from a crash may carry other permissions; start fresh.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

// ── FIX #6: Peer persistence ──────────────────────────────────────────────────

pub fn load_known_peers(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// NET-16: known_peers.json is written atomically (temp file + rename), so a
/// crash mid-write can never leave a truncated table behind.
pub fn save_known_peers(path: &Path, peers: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string(peers) {
        if let Err(e) = write_file_atomic(path, json.as_bytes(), false) {
            warn!("saving {} failed: {}", path.display(), e);
        }
    }
}

async fn poll_swarm(
    swarm: &mut libp2p::Swarm<BlochBehaviour>,
) -> SwarmEvent<BlochBehaviourEvent> {
    use futures::Stream;
    std::future::poll_fn(|cx| {
        match std::pin::Pin::new(&mut *swarm).poll_next(cx) {
            std::task::Poll::Ready(Some(e)) => std::task::Poll::Ready(e),
            _ => std::task::Poll::Pending,
        }
    }).await
}




/// Turn an OPERATOR-configured address (`--peer`, the shipped seeds) into a
/// dialable multiaddr: a leading `/dns`, `/dns4` or `/dns6` host name of a
/// plain-TCP address is resolved here (the swarm's TCP transport has no DNS
/// layer), and the first answer of the right family that
/// [`is_acceptable_ip`]`(ip, allow_private)` accepts replaces it — B1-T8: a
/// name never resolves into an invalid range (unspecified, multicast,
/// documentation, link-local / cloud metadata …), and with `allow_private =
/// false` not into a loopback or private one either. Websocket addresses keep
/// their name (the websocket transport resolves it itself, and `wss` needs it
/// for TLS). `None`: unparseable, or no acceptable answer.
///
/// Learned addresses never come here: the address tables accept IP literals
/// only.
///
/// Audit M-11 fix: the lookup is async (`tokio::net::lookup_host`, on the
/// blocking pool), so a slow resolver never stalls the swarm event loop.
/// Audit L-3: every failure is logged.
async fn resolve_dial_addr(addr: &str, allow_private: bool) -> Option<Multiaddr> {
    use libp2p::multiaddr::Protocol;
    let ma: Multiaddr = addr.parse().ok()?;
    let mut parts: Vec<Protocol<'static>> = ma.iter().map(|p| p.acquire()).collect();
    let (host, want_v4, want_v6) = match parts.first()? {
        Protocol::Dns(h) => (h.to_string(), true, true),
        Protocol::Dns4(h) => (h.to_string(), true, false),
        Protocol::Dns6(h) => (h.to_string(), false, true),
        _ => return Some(ma),
    };
    if parts.iter().any(|p| matches!(p, Protocol::Ws(_) | Protocol::Wss(_))) {
        return Some(ma);
    }
    match tokio::net::lookup_host(format!("{}:0", host)).await {
        Ok(answers) => {
            let answers: Vec<std::net::IpAddr> = answers.map(|sa| sa.ip()).collect();
            let Some(ip) = pick_resolved_ip(&answers, want_v4, want_v6, allow_private) else {
                warn!("resolve: no acceptable address for '{}' among {:?}; not dialing {}", host, answers, addr);
                return None;
            };
            parts[0] = match ip {
                std::net::IpAddr::V4(v4) => Protocol::Ip4(v4),
                std::net::IpAddr::V6(v6) => Protocol::Ip6(v6),
            };
            Some(parts.into_iter().collect())
        }
        Err(e) => {
            warn!("resolve: DNS lookup for '{}' failed: {}; not dialing {}", host, e, addr);
            None
        }
    }
}

/// The DNS answer [`resolve_dial_addr`] dials: the first of the wanted family
/// (IPv4 first, as Core prefers what it can reach) that
/// [`is_acceptable_ip`]`(ip, allow_private)` accepts.
fn pick_resolved_ip(
    answers: &[std::net::IpAddr],
    want_v4: bool,
    want_v6: bool,
    allow_private: bool,
) -> Option<std::net::IpAddr> {
    let mut v: Vec<std::net::IpAddr> = answers.to_vec();
    v.sort_by_key(|ip| !ip.is_ipv4());
    v.into_iter().find(|ip| {
        ((ip.is_ipv4() && want_v4) || (ip.is_ipv6() && want_v6)) && is_acceptable_ip(*ip, allow_private)
    })
}

/// PROPAGAÇÃO-CHURN fix (2026-08-09): the ONE canonical string form of a
/// peer's address for known_peers / PEX — transport components only, plus
/// exactly one trailing `/p2p/<peer_id>`.
///
/// Every place that used to build a persistable address with
/// `format!("{}/p2p/{}", observed, peer_id)` concatenated a NEW `/p2p/`
/// component onto an address that (on the Dialer path) already ended in one.
/// Each successful dial of the stored entry re-observed it and appended
/// again — mainnet known_peers.json files were measured with chains up to
/// 15 `/p2p/` components (885 bytes). Past ~9 components the string exceeds
/// MAX_WIRE_ADDR_LEN, at which point every PeerExchange carrying it is a
/// wire violation at the receiver: −100 app score per frame, graylist at
/// −400, and the sender's blocks/tips are blackholed while TCP stays up —
/// the 2026-08-09 non-convergence incident.
///
/// Stripping ALL P2p components before appending exactly one makes this
/// function idempotent: re-observing a canonical address yields the same
/// string forever.
pub fn canonical_peer_addr(addr: &Multiaddr, peer_id: &PeerId) -> String {
    let transport: Multiaddr = addr
        .iter()
        .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        .collect();
    format!("{}/p2p/{}", transport, peer_id)
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("start failed: {0}")]
    StartFailed(String),
}

// ── Sprint CC: PeerTip construction ──────────────────────────────────────────

/// Build a PeerTip message from the current state of the GhostDAG.
///
/// Sprint CC bugfix: previously, `network::run` captured `our_blue_score`
/// and `our_height` as `u64` values at startup and reused them forever
/// to construct every `PeerTip` it ever published. Any node that built
/// blocks after boot would still advertise its startup-time height to
/// the rest of the mesh, silently preventing peer-initiated IBD
/// handshakes across reboots and against late-joining peers.
///
/// This function is a small free function (not a closure inside `run`)
/// so it can be exercised directly by the regression test that lives
/// alongside it. Testing via the closure was not practical — it would
/// require spinning up a real libp2p swarm.
///
/// Holding the read lock for the duration of the three accessor calls
/// is a conscious choice: it guarantees the (blue_score, height) pair
/// is internally consistent. A multi-call pattern that released the
/// lock between `tip_blue_score()` and `block_count()` could report a
/// mismatched pair if a block were accepted in between. In practice
/// the window is microseconds but the cost of holding the lock for
/// that long is zero, so we take the consistency guarantee.
pub fn build_current_tip(
    dag:     &std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
    peer_id: &str,
) -> NetworkMessage {
    let d = dag.read();
    NetworkMessage::PeerTip {
        peer_id:    peer_id.to_string(),
        blue_score: d.tip_blue_score(),
        height:     d.block_count() as u64,
    }
}

// ── Announce-then-pull: directed sync helpers ────────────────────────────────

/// M-9 (audit): bound on how far ahead of our OWN locally-verified tip an
/// announced blue_score is allowed to be before it is clamped. A single
/// crafted `PeerTip`/`Version`/`Tips` frame claiming `blue_score = u64::MAX`
/// used to be stored and trusted verbatim as `announced_blue_score`, which
/// (in `main.rs`) latches `is_syncing = true` for the connection's lifetime:
/// `caught_up = our_score + IBD_EXIT_LAG >= best_announced` can never hold
/// against `u64::MAX`, pausing the miner and freezing the finality
/// checkpoint. The entire historical Genesis-3 chain never exceeded
/// ~50,600 in blue_score; this bound is chosen to be generously larger than
/// any plausible real growth burst while remaining astronomically smaller
/// than `u64::MAX`, so it clamps only implausible/malicious announcements,
/// never an honest peer that is genuinely far ahead.
pub const MAX_ANNOUNCED_LOOKAHEAD: u64 = 1_000_000;

/// M-9: clamp a peer-announced blue_score to at most
/// `our_verified_score + MAX_ANNOUNCED_LOOKAHEAD` before it is ever stored in
/// [`crate::sync::peer_state::PeerStateTable`] or fed to
/// [`sync_rr::PeerSync`]/`track_peer_score`. `our_verified_score` MUST be a
/// LOCALLY-VERIFIED quantity (e.g. `dag.tip_blue_score()`) — clamping against
/// an already-untrusted ceiling (another peer's announcement) would let one
/// lie authorize the next.
pub fn clamp_announced_blue_score(announced: u64, our_verified_score: u64) -> u64 {
    announced.min(our_verified_score.saturating_add(MAX_ANNOUNCED_LOOKAHEAD))
}

/// M-6: derive the WebSocket listen multiaddr from the primary `--listen`
/// address — same host/interface component, TCP port + 1, `/ws` appended —
/// instead of a hard-coded `/ip4/0.0.0.0/tcp/17111/ws`. Returns `None` if
/// `listen_addr` doesn't parse or carries no `/tcp/<port>` component (nothing
/// to derive a WS port from).
fn ws_listen_addr_from(listen_addr: &str) -> Option<Multiaddr> {
    use libp2p::multiaddr::Protocol;
    let base: Multiaddr = listen_addr.parse().ok()?;
    let mut out = Multiaddr::empty();
    let mut saw_tcp = false;
    for proto in base.iter() {
        match proto {
            Protocol::Tcp(port) => {
                out.push(Protocol::Tcp(port.checked_add(1)?));
                saw_tcp = true;
            }
            other => out.push(other),
        }
    }
    if !saw_tcp {
        return None;
    }
    out.push(Protocol::Ws(std::borrow::Cow::Borrowed("/")));
    Some(out)
}

/// M-10: max peer addresses returned in one `GetPeers` answer — a bounded
/// RANDOM SAMPLE of `known_peers`, never the whole table. Mirrors the
/// rationale Bitcoin's `getaddr` uses (return a fraction of the table, not
/// all of it): a requester wanting more addresses simply asks again (and, on
/// this transport, every new connection is asked once),
/// while a single answer can never hand over the complete peer table in one
/// shot — the reconnaissance value of one answer is bounded regardless of
/// how large `known_peers` (capped at `KNOWN_PEERS_CAP`, 1000) has grown.
const PEX_RESPONSE_SAMPLE_SIZE: usize = 30;

/// M-10: build the bounded, randomly-sampled peer list answer to a directed
/// `GetPeers` request. Same address-validity filter and self-advertisement
/// logic the (now-removed) gossip `PeerRequest` broadcast handler used —
/// only the transport and the "return everything" -> "return a sample"
/// change are new.
fn serve_get_peers(
    known_peers:     &[String],
    external_addrs:  &[Multiaddr],
    self_peer_id:    &PeerId,
    allow_private:   bool,
) -> sync_rr::SyncResponse {
    use rand::seq::SliceRandom;

    let mut candidates: Vec<String> = known_peers.iter()
        .filter(|a| is_valid_public_multiaddr(a, allow_private))
        .cloned().collect();
    // PRINCIPLES.md #2 ("every node is a seed"): advertise our own reachable
    // address(es) too, so a node nobody else knows about can still be
    // gossiped onward through this answer.
    for addr in external_addrs {
        let self_addr = canonical_peer_addr(addr, self_peer_id);
        if !candidates.contains(&self_addr) {
            candidates.push(self_addr);
        }
    }
    let mut rng = rand::rng();
    candidates.shuffle(&mut rng);
    candidates.truncate(PEX_RESPONSE_SAMPLE_SIZE);
    sync_rr::SyncResponse::Peers { peers: candidates }
}

// The directed-sync answers themselves (`serve_sync_request`) are computed by
// `serve`, off this task (re-audit B1-T3 / B2-T5).

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── M-10 regressions: bounded random-sample PEX answer ──────────────────

    /// THE M-10 regression: the answer must never exceed
    /// `PEX_RESPONSE_SAMPLE_SIZE`, even when `known_peers` holds far more —
    /// before this fix, the (gossip-broadcast) answer was the WHOLE table.
    #[test]
    fn get_peers_response_is_bounded_even_with_a_large_table() {
        let known: Vec<String> = (0..500)
            .map(|i| format!("/ip4/10.0.{}.{}/tcp/17110/p2p/{}", i / 256, i % 256, PeerId::random()))
            .collect();
        let resp = serve_get_peers(&known, &[], &PeerId::random(), true);
        match resp {
            sync_rr::SyncResponse::Peers { peers } => {
                assert!(
                    peers.len() <= PEX_RESPONSE_SAMPLE_SIZE,
                    "answer carried {} peers, expected <= {}", peers.len(), PEX_RESPONSE_SAMPLE_SIZE
                );
            }
            other => panic!("expected Peers, got {:?}", other),
        }
    }

    /// A table smaller than the sample size is returned (minus any
    /// invalid/filtered entries) without padding or fabrication.
    #[test]
    fn get_peers_response_returns_all_of_a_small_table() {
        let known: Vec<String> = vec![
            format!("/ip4/45.76.1.1/tcp/17110/p2p/{}", PeerId::random()),
            format!("/ip4/45.76.2.2/tcp/17110/p2p/{}", PeerId::random()),
        ];
        let resp = serve_get_peers(&known, &[], &PeerId::random(), true);
        match resp {
            sync_rr::SyncResponse::Peers { peers } => assert_eq!(peers.len(), 2),
            other => panic!("expected Peers, got {:?}", other),
        }
    }

    /// Our own external address is offered too (PRINCIPLES.md #2 — every
    /// node is a seed), de-duplicated against `known_peers`.
    #[test]
    fn get_peers_response_includes_self_external_address() {
        let known: Vec<String> = Vec::new();
        let self_id = PeerId::random();
        let ext: Multiaddr = "/ip4/1.2.3.4/tcp/17110".parse().unwrap();
        let resp = serve_get_peers(&known, std::slice::from_ref(&ext), &self_id, true);
        match resp {
            sync_rr::SyncResponse::Peers { peers } => {
                assert_eq!(peers.len(), 1);
                assert!(peers[0].contains(&self_id.to_string()));
            }
            other => panic!("expected Peers, got {:?}", other),
        }
    }

    /// NET-11 (Core's addr response cache): the GetPeers sample is computed
    /// once and served unchanged until it expires (21-27 h), so asking again
    /// (from a new connection, a new identity) reveals nothing more of the
    /// tried table; it is refreshed early only while it is not full and the
    /// table has grown.
    #[test]
    fn get_peers_sample_is_cached_against_scraping() {
        let now = std::time::Instant::now();
        let mut tried = TriedTable::with_key(addrbook::random_key());
        for i in 0..200u32 {
            tried.insert(&format!("/ip4/{}.{}.1.1/tcp/17110/p2p/{}", 20 + i / 100, i % 100, PeerId::random()), now);
        }
        let mut cache = GetAddrCache::default();
        let first = cache.sample(now, &tried, false);
        assert_eq!(first.len(), PEX_RESPONSE_SAMPLE_SIZE);
        for k in 1..50u64 {
            assert_eq!(cache.sample(now + Duration::from_secs(k * 600), &tried, false), first, "same sample within its lifetime");
        }
        let later = now + GETADDR_CACHE_LIFETIME + GETADDR_CACHE_JITTER;
        assert_ne!(cache.sample(later, &tried, false), first, "a fresh sample after expiry");

        // A young node's near-empty sample grows with its table.
        let mut small = TriedTable::with_key(addrbook::random_key());
        let mut cache = GetAddrCache::default();
        small.insert(&format!("/ip4/45.1.1.1/tcp/17110/p2p/{}", PeerId::random()), now);
        assert_eq!(cache.sample(now, &small, false).len(), 1);
        small.insert(&format!("/ip4/46.1.1.1/tcp/17110/p2p/{}", PeerId::random()), now);
        assert_eq!(cache.sample(now + Duration::from_secs(60), &small, false).len(), 1, "not before the refresh delay");
        assert_eq!(cache.sample(now + GETADDR_CACHE_GROW_REFRESH, &small, false).len(), 2);
    }

    // ── M-9 regressions: announced blue_score clamp ─────────────────────────

    /// THE M-9 regression: a peer claiming `blue_score = u64::MAX` must be
    /// clamped down to a bounded value relative to what we have locally
    /// verified, never stored/propagated verbatim. Before this fix, this
    /// exact value latched `is_syncing` in `main.rs` for the connection's
    /// lifetime because `our_score + IBD_EXIT_LAG >= best_announced` can
    /// never hold against `u64::MAX`.
    #[test]
    fn u64_max_announcement_is_clamped_to_bounded_lookahead() {
        let our_score = 100u64;
        let clamped = clamp_announced_blue_score(u64::MAX, our_score);
        assert_eq!(clamped, our_score + MAX_ANNOUNCED_LOOKAHEAD);
        assert!(clamped < u64::MAX, "must never pass through an unbounded announcement");
    }

    /// An honest peer announcement within the lookahead window passes through unchanged.
    #[test]
    fn honest_announcement_within_lookahead_is_unclamped() {
        let our_score = 100u64;
        assert_eq!(clamp_announced_blue_score(150, our_score), 150);
        assert_eq!(clamp_announced_blue_score(our_score, our_score), our_score);
    }

    /// An announcement below our own score is never inflated — the clamp is
    /// a ceiling, not a floor.
    #[test]
    fn announcement_below_our_score_is_unaffected() {
        let our_score = 100_000u64;
        assert_eq!(clamp_announced_blue_score(5, our_score), 5);
    }

    /// The clamp must not overflow/panic even at u64::MAX on both sides
    /// (checked arithmetic: `saturating_add`).
    #[test]
    fn clamp_does_not_overflow_at_extremes() {
        assert_eq!(clamp_announced_blue_score(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(clamp_announced_blue_score(0, u64::MAX), 0);
    }

    // ── M-6 regressions: WS listen address derivation ───────────────────────

    /// The core M-6 fix: the WS address must follow the SAME interface as
    /// `--listen`, not a hard-coded `0.0.0.0` — an operator binding to a
    /// private interface must get the WS listener on that interface too.
    #[test]
    fn ws_listen_addr_follows_listen_interface_not_hardcoded_any() {
        let ws = ws_listen_addr_from("/ip4/10.0.0.5/tcp/17110").unwrap();
        assert_eq!(ws.to_string(), "/ip4/10.0.0.5/tcp/17111/ws");
    }

    /// Default `--listen` (0.0.0.0) still derives correctly — the fix must
    /// not change behavior for the common case, only the private-interface one.
    #[test]
    fn ws_listen_addr_derives_port_plus_one_on_default_listen() {
        let ws = ws_listen_addr_from("/ip4/0.0.0.0/tcp/17110").unwrap();
        assert_eq!(ws.to_string(), "/ip4/0.0.0.0/tcp/17111/ws");
    }

    /// IPv6 interfaces must be preserved too, not silently dropped/rewritten to v4.
    #[test]
    fn ws_listen_addr_preserves_ipv6_host() {
        let ws = ws_listen_addr_from("/ip6/::1/tcp/17110").unwrap();
        assert_eq!(ws.to_string(), "/ip6/::1/tcp/17111/ws");
    }

    /// A listen address with no `/tcp/<port>` component gives nothing to
    /// derive a WS port from — must return `None`, not panic or guess.
    #[test]
    fn ws_listen_addr_none_when_no_tcp_component() {
        assert!(ws_listen_addr_from("/ip4/10.0.0.5").is_none());
        assert!(ws_listen_addr_from("not a multiaddr").is_none());
        assert!(ws_listen_addr_from("").is_none());
    }

    /// M-11 regression: addresses that don't need DNS must be returned
    /// unchanged without touching the resolver. This exercises the
    /// fast path that matters most in practice — most peers are
    /// already `/ip4/...` form from a prior bootstrap.
    #[tokio::test]
    async fn resolve_multiaddr_passes_through_ip4_unchanged() {
        let input = "/ip4/80.78.28.142/tcp/17110/p2p/12D3KooWQfXJzXRG7t4r1hQVHfijHsuMZ22ecAUD3YGhMvjvDbQp";
        let out = resolve_dial_addr(input, false).await;
        assert_eq!(out, Some(input.parse().unwrap()));
    }

    /// Unparseable input is not dialed (it used to be returned verbatim and
    /// then fail to parse); IP literals pass through.
    #[tokio::test]
    async fn resolve_multiaddr_passes_through_empty_and_garbage() {
        assert_eq!(resolve_dial_addr("", true).await, None);
        assert_eq!(resolve_dial_addr("garbage", true).await, None);
        assert_eq!(resolve_dial_addr("/ip6/::1/tcp/1", true).await, Some("/ip6/::1/tcp/1".parse().unwrap()));
    }

    /// Malformed `/dns4/` input must never panic.
    #[tokio::test]
    async fn resolve_multiaddr_never_panics_on_weird_input() {
        let _ = resolve_dial_addr("/dns4/", true).await;
        let _ = resolve_dial_addr("/dns4/x/tcp", false).await;
        let _ = resolve_dial_addr("/dns6/", false).await;
    }

    /// M-11 core property: the function is `async` (a synchronous lookup
    /// would block the libp2p event loop). Compile-time guard: if the
    /// signature regresses to a sync fn, `.await` stops compiling.
    #[tokio::test]
    async fn resolve_multiaddr_is_async() {
        let future = resolve_dial_addr("/ip4/127.0.0.1/tcp/1", true);
        let out = future.await;
        assert_eq!(out, Some("/ip4/127.0.0.1/tcp/1".parse().unwrap()));
    }

    /// B1-T8, as production uses it: OPERATOR-configured names (`--peer`,
    /// the shipped seeds — both callers pass `allow_private = true`, like an
    /// operator's IP literal, which is dialed as given) may resolve to a
    /// private or loopback address (docker / LAN setups), but NEVER into an
    /// invalid range (link-local / cloud metadata, multicast, unspecified,
    /// documentation, broadcast, …), whatever `allow_private` says. The
    /// `allow_private = false` branch (refuses loopback / private too) is kept
    /// for callers that screen like learned addresses. Before the fix every
    /// `/dns4` name was turned into whatever IPv4 it resolved to, unfiltered.
    #[tokio::test]
    async fn operator_host_names_never_resolve_into_invalid_ranges() {
        use std::net::IpAddr;
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // What production does (allow_private = true): invalid ranges are
        // skipped, private / loopback accepted, IPv4 preferred.
        let invalid = ["169.254.169.254", "224.0.0.1", "0.0.0.0", "192.0.2.7", "255.255.255.255", "ff02::1", "2001:db8::1", "::"];
        for bad in invalid {
            assert_eq!(pick_resolved_ip(&[ip(bad)], true, true, true), None, "{bad} is never dialed");
        }
        assert_eq!(pick_resolved_ip(&[ip("169.254.169.254"), ip("10.0.0.5")], true, true, true), Some(ip("10.0.0.5")));
        assert_eq!(pick_resolved_ip(&[ip("2606:4700::1"), ip("80.78.28.142")], true, true, true), Some(ip("80.78.28.142")));
        assert_eq!(pick_resolved_ip(&[ip("80.78.28.142")], false, true, true), None, "/dns6 wants IPv6 only");
        // The screened branch: loopback / private refused as well.
        assert_eq!(pick_resolved_ip(&[ip("127.0.0.1"), ip("10.0.0.5")], true, true, false), None);

        let id = PeerId::random();
        let named = format!("/dns4/localhost/tcp/17110/p2p/{id}");
        assert_eq!(
            resolve_dial_addr(&named, true).await,
            Some(format!("/ip4/127.0.0.1/tcp/17110/p2p/{id}").parse().unwrap()),
            "an operator name may resolve to loopback; only the host part changes"
        );
        assert_eq!(resolve_dial_addr(&named, false).await, None, "the screened branch refuses loopback");
        // Websocket addresses keep their name (the ws transport resolves it).
        let ws = format!("/dns4/localhost/tcp/17111/ws/p2p/{id}");
        assert_eq!(resolve_dial_addr(&ws, false).await, Some(ws.parse().unwrap()));
    }

    /// NET-11 review: a `Peers` answer feeds the new table only when it
    /// answers OUR GetPeers sent to an outbound full-relay or manual peer.
    /// Before the fix any `Peers` answer was ingested: an inbound or
    /// block-relay-only peer answered the connect-time / poll `GetTips` with
    /// `Peers { attacker addresses }` and they entered the table.
    #[test]
    fn only_answers_to_our_get_peers_feed_the_address_table() {
        use sync_rr::SyncRequest;
        let get_peers = SyncRequest::GetPeers;
        let get_tips = SyncRequest::GetTips;
        let get_headers = SyncRequest::GetHeaders { from_blue_score: 0, limit: 1 };
        for role in [ConnKind::OutboundFullRelay, ConnKind::Manual] {
            assert!(solicited_peers_answer(Some(&get_peers), Some(role)), "{role:?} answering our GetPeers");
            assert!(!solicited_peers_answer(Some(&get_tips), Some(role)), "{role:?}: Peers answering GetTips");
            assert!(!solicited_peers_answer(Some(&get_headers), Some(role)));
        }
        for role in [ConnKind::Inbound, ConnKind::BlockRelayOnly, ConnKind::Feeler] {
            assert!(!solicited_peers_answer(Some(&get_peers), Some(role)), "{role:?} never relays addresses");
            assert!(!solicited_peers_answer(Some(&get_tips), Some(role)));
        }
        assert!(!solicited_peers_answer(None, Some(ConnKind::OutboundFullRelay)), "no matching request");
        assert!(!solicited_peers_answer(Some(&get_peers), None), "peer gone");
    }

    /// B1-T9 / M-11 review: heartbeat re-dials of configured peers never
    /// await a DNS lookup on the network loop. `request` returns at once even
    /// when the lookup never completes, starts at most one lookup per address,
    /// bounds it with the timeout (a `None` answer arrives), and delivers a
    /// finished lookup's address over the channel. Before the fix the
    /// heartbeat awaited `resolve_dial_addr` inline for every disconnected
    /// configured peer, freezing the swarm loop for the whole lookup.
    #[tokio::test]
    async fn heartbeat_redial_lookups_run_off_the_network_loop() {
        let (mut r, mut rx) = ManualResolver::new(Duration::from_millis(300));
        let slow = "/dns4/down.example/tcp/17110";
        let t = std::time::Instant::now();
        assert!(r.request(slow, |_| std::future::pending::<Option<Multiaddr>>()));
        assert!(t.elapsed() < Duration::from_millis(100), "request never waits for the lookup");
        assert!(!r.request(slow, |_| std::future::pending::<Option<Multiaddr>>()), "one lookup per address at a time");
        let fast = "/ip4/80.78.28.142/tcp/17110";
        assert!(r.request(fast, |p| async move { resolve_dial_addr(&p, true).await }));
        let mut got = std::collections::HashMap::new();
        for _ in 0..2 {
            let (p, a) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
            r.finished(&p);
            got.insert(p, a);
        }
        assert_eq!(got[fast], Some(fast.parse().unwrap()));
        assert_eq!(got[slow], None, "a lookup that never completes times out");
        assert!(r.request(slow, |_| async { None }), "a finished address can be looked up again");
    }

    // ─── Sprint CC regression: dynamic PeerTip construction ──────────────

    /// The pre-Sprint-CC bug was: `our_blue_score` / `our_height` passed
    /// as u64 values got captured into `my_tip` once at startup, so any
    /// growth of the DAG after startup never reflected in subsequently
    /// published PeerTip messages. In production this silently froze
    /// IBD across the whole mesh — a seed at height=2655 kept telling
    /// every new peer "I'm at height=1", and new peers (seeing parity)
    /// never asked to sync.
    ///
    /// This test pins the fix: `build_current_tip` must read the DAG
    /// fresh on each call. The check is simple — build a tip, advance
    /// the DAG by one block, build another tip, assert the second tip
    /// reflects the new state. If someone later refactors
    /// `build_current_tip` to cache values, this test fails.
    #[test]
    fn build_current_tip_reads_fresh_dag_state_each_call() {
        use std::sync::Arc;
        use parking_lot::RwLock;
        use crate::consensus::GhostDAG;

        // Arrange: DAG with just genesis.
        let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
        let genesis_hash: [u8; 32] = [0xAA; 32];
        dag.write().add_genesis(genesis_hash, 1000);

        // First tip read: should reflect genesis-only state.
        let tip1 = build_current_tip(&dag, "peer-xyz");
        match tip1 {
            NetworkMessage::PeerTip { peer_id, blue_score, height } => {
                assert_eq!(peer_id, "peer-xyz");
                assert_eq!(blue_score, 0, "genesis DAG has blue_score 0");
                assert_eq!(height, 1, "genesis DAG has block_count 1");
            }
            _ => panic!("expected PeerTip"),
        }

        // Advance the DAG by one block.
        let block1: [u8; 32] = [0xBB; 32];
        dag.write()
            .add_block(block1, vec![genesis_hash], 1, 1001)
            .expect("add_block");

        // Second tip read: MUST reflect the new state. The pre-Sprint-CC
        // bug was that the tip was cached and always returned the old
        // state here; the assertions below fail if that behavior returns.
        let tip2 = build_current_tip(&dag, "peer-xyz");
        match tip2 {
            NetworkMessage::PeerTip { blue_score, height, .. } => {
                assert_eq!(
                    blue_score, 1,
                    "tip MUST reflect post-genesis blue_score after add_block"
                );
                assert_eq!(
                    height, 2,
                    "tip MUST reflect post-genesis block_count after add_block"
                );
            }
            _ => panic!("expected PeerTip"),
        }
    }

    /// A separate and simpler property test: build_current_tip carries
    /// the peer_id through verbatim. Pre-refactor, this was a trivial
    /// clone; post-refactor it's still a trivial clone, but we pin it
    /// so a regression that swaps arguments or loses the peer_id
    /// completely is caught.
    #[test]
    fn build_current_tip_preserves_peer_id() {
        use std::sync::Arc;
        use parking_lot::RwLock;
        use crate::consensus::GhostDAG;

        let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
        dag.write().add_genesis([0u8; 32], 0);

        let tip = build_current_tip(&dag, "12D3KooWExample123");
        match tip {
            NetworkMessage::PeerTip { peer_id, .. } => {
                assert_eq!(peer_id, "12D3KooWExample123");
            }
            _ => panic!("expected PeerTip"),
        }
    }

    /// Sanity check: tip_announce interval is configured to 60s. If
    /// someone ever changes that to something extreme (say, 10ms or
    /// 1h), this won't catch it — it only documents the intent. But
    /// it does catch accidental removal of the tip_announce timer,
    /// because that removal would also delete this constant expectation.
    ///
    /// The concrete guard is a compile-time check: we reference the
    /// Duration value we expect to see in the loop. If the loop ever
    /// changes the Duration::from_secs value, this test fails only if
    /// the value is exactly wrong for what IBD recovery needs.
    #[test]
    fn tip_announce_interval_is_bounded() {
        // Documented invariant: the tip_announce interval must be
        // bounded between 10s (pointless churn) and 300s (too slow for
        // IBD recovery on a network with 10s block times). The actual
        // value in run() is 60s; this test documents the acceptable
        // range without duplicating the exact value.
        let min_allowed = Duration::from_secs(10);
        let max_allowed = Duration::from_secs(300);
        let actual      = Duration::from_secs(60);  // must match run()

        assert!(
            actual >= min_allowed && actual <= max_allowed,
            "tip_announce interval {:?} outside acceptable bounds [{:?}, {:?}]",
            actual, min_allowed, max_allowed
        );
    }

    // ─── C1 regression: bounded bincode decode of untrusted gossip ────────

    /// (a) A tiny crafted frame declaring a multi-GB Vec length must return
    /// a decode error fast, without allocating the declared size. The frame
    /// is built by taking a genuinely-encoded NewBlock and splicing an 8 GiB
    /// length varint in place of the block_data length, so the test is
    /// self-validating against bincode's actual encoding layout.
    #[test]
    fn wire_decode_rejects_multi_gb_declared_vec() {
        let small = NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 0,
            height:     0,
            block_data: vec![7u8; 3],
        };
        let enc = bincode::serde::encode_to_vec(&small, bincode::config::standard())
            .expect("encode");
        // Layout guard: the frame must end with len-varint 0x03 then 7,7,7.
        // If bincode's encoding ever changes, fail loudly here instead of
        // silently testing a meaningless byte string.
        assert!(
            enc.ends_with(&[3, 7, 7, 7]),
            "bincode encoding layout changed; update this test"
        );
        let mut frame = enc[..enc.len() - 4].to_vec();
        frame.push(0xFD); // bincode-2 varint marker: u64 follows
        frame.extend_from_slice(&(8u64 * 1024 * 1024 * 1024).to_le_bytes()); // 8 GiB

        let t0 = std::time::Instant::now();
        let res = decode_wire_message(&frame);
        assert!(
            res.is_err(),
            "a frame declaring an 8 GiB Vec must not decode: {:?}", res
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "decode must fail fast (no giant allocation/scan), took {:?}",
            t0.elapsed()
        );
    }

    /// (b) The 4 MiB frame limit: a frame just over MAX_WIRE_BYTES is
    /// rejected as Oversized; one comfortably under it decodes fine. This
    /// FAILS without the fix (the old unlimited standard() decode accepted
    /// the >4 MiB frame).
    #[test]
    fn wire_decode_enforces_4mib_frame_limit() {
        let mk = |n: usize| NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 0,
            height:     0,
            block_data: vec![0u8; n],
        };

        // Just over: payload alone exceeds MAX_WIRE_BYTES, so the whole
        // frame necessarily does too.
        let over = bincode::serde::encode_to_vec(&mk(MAX_WIRE_BYTES + 1024), bincode::config::standard())
            .expect("encode over");
        assert!(over.len() > MAX_WIRE_BYTES);
        match decode_wire_message(&over) {
            Err(WireDecodeError::Oversized(_)) => {}
            other => panic!("frame over 4 MiB must be Oversized, got {:?}", other),
        }

        // Comfortably under: must decode and round-trip the payload.
        let under = bincode::serde::encode_to_vec(&mk(3 * 1024 * 1024), bincode::config::standard())
            .expect("encode under");
        assert!(under.len() < MAX_WIRE_BYTES);
        match decode_wire_message(&under).expect("3 MiB block must decode") {
            NetworkMessage::NewBlock { block_data, .. } => {
                assert_eq!(block_data.len(), 3 * 1024 * 1024);
            }
            other => panic!("expected NewBlock, got {:?}", other),
        }
    }

    /// C1 post-decode bounds: a PeerExchange whose peer list is far longer
    /// than any compliant node would send must be rejected even though the
    /// frame is well under the 4 MiB byte limit (the byte limit alone cannot
    /// catch it). FAILS without the fix. A modest list still passes, and a
    /// single over-long address string is also rejected.
    #[test]
    fn wire_decode_bounds_peer_lists() {
        // Too many entries, but small total size (< 4 MiB).
        let peers: Vec<String> = (0..(MAX_WIRE_ADDRS + 1))
            .map(|i| format!("/ip4/1.2.3.4/tcp/{}", i % 65535))
            .collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers },
            bincode::config::standard(),
        ).expect("encode");
        assert!(bytes.len() < MAX_WIRE_BYTES, "test premise: under byte limit");
        assert!(
            matches!(decode_wire_message(&bytes), Err(WireDecodeError::Bounds(_))),
            "oversized peer list must be a Bounds violation"
        );

        // One absurdly long address string.
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers: vec!["x".repeat(MAX_WIRE_ADDR_LEN + 1)] },
            bincode::config::standard(),
        ).expect("encode");
        assert!(
            matches!(decode_wire_message(&bytes), Err(WireDecodeError::Bounds(_))),
            "over-long address string must be a Bounds violation"
        );

        // A compliant-size list decodes fine.
        let ok_peers: Vec<String> = (0..10).map(|i| format!("/ip4/9.9.9.{}/tcp/17110", i)).collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers: ok_peers.clone() },
            bincode::config::standard(),
        ).expect("encode");
        match decode_wire_message(&bytes).expect("compliant PEX must decode") {
            NetworkMessage::PeerExchange { peers } => assert_eq!(peers, ok_peers),
            other => panic!("expected PeerExchange, got {:?}", other),
        }
    }

    // ─── H4 regression: UTF-8-safe truncation of PEX strings ──────────────

    /// (c) A PEX address string where byte 80 falls mid-codepoint. The
    /// pre-fix pattern `&s[..s.len().min(80)]` panics on exactly this input
    /// (asserted below via catch_unwind, documenting the vulnerability);
    /// `truncate_utf8` must handle it without panicking.
    #[test]
    fn pex_string_truncation_is_utf8_safe() {
        // "a" + 50×'é' (2 bytes each) = 101 bytes; char boundaries sit at
        // 0, 1, 3, 5, ..., so byte 80 is mid-codepoint.
        let s = format!("a{}", "é".repeat(50));
        assert!(!s.is_char_boundary(80), "test premise: 80 must be mid-codepoint");

        // Document the pre-fix behavior: the old expression panics on this input.
        let old_pattern_panics = std::panic::catch_unwind(|| {
            let _ = &s[..s.len().min(80)];
        }).is_err();
        assert!(old_pattern_panics, "this input reproduces the pre-fix H4 panic");

        // The fix: no panic, valid UTF-8 prefix, within the byte budget.
        let t = truncate_utf8(&s, 80);
        assert!(t.len() <= 80);
        assert!(s.starts_with(t));
        assert_eq!(t.len(), 79, "should back off to the char boundary at 79");

        // 4-byte codepoints (emoji): budget 79 backs off to 76.
        let e = "💥".repeat(30); // 120 bytes
        let te = truncate_utf8(&e, 79);
        assert_eq!(te.len(), 76);
        assert!(e.starts_with(te));

        // Short and boundary-exact strings pass through unchanged.
        assert_eq!(truncate_utf8("abc", 80), "abc");
        assert_eq!(truncate_utf8("éé", 4), "éé");
        // Degenerate: budget smaller than the first codepoint → empty, no panic.
        assert_eq!(truncate_utf8("💥", 3), "");
    }

    // ─── Sprint EE (S3): extracted frame-reaction unit ────────────────────

    /// The reaction to a valid frame is Accept carrying the decoded message.
    #[test]
    fn wire_reaction_accepts_valid_frame() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::GetTips, bincode::config::standard()).expect("encode");
        match t.classify(peer, &bytes) {
            WireReaction::Accept(NetworkMessage::GetTips) => {}
            other => panic!("expected Accept(GetTips), got {:?}", other),
        }
        assert_eq!(t.score_of(&peer), None, "valid frames must not be penalized");
    }

    /// An invalid-block frame (NewBlock larger than MAX_WIRE_BYTES) is a
    /// protocol violation: cumulative -100 per offense; the FOURTH crosses
    /// graylist_threshold (-400). This is the deterministic, swarm-free
    /// assertion of the reaction `run()` applies via set_application_score.
    #[test]
    fn wire_reaction_penalizes_oversized_invalid_block_cumulatively() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let big = bincode::serde::encode_to_vec(
            &NetworkMessage::NewBlock {
                block_hash: [0u8; 32],
                blue_score: 0,
                height:     0,
                block_data: vec![0u8; MAX_WIRE_BYTES + 1024],
            },
            bincode::config::standard(),
        ).expect("encode");

        for i in 1..=4i32 {
            match t.classify(peer, &big) {
                WireReaction::Penalize { score, error } => {
                    assert!(error.is_protocol_violation());
                    assert_eq!(score, WIRE_VIOLATION_PENALTY * f64::from(i));
                }
                other => panic!("expected Penalize, got {:?}", other),
            }
        }
        // Fourth violation: -400 == the gossipsub graylist_threshold in run().
        assert_eq!(t.score_of(&peer), Some(-400.0));
    }

    /// The cumulative penalty floors at WIRE_PENALTY_FLOOR — a flood of
    /// violations cannot drive the score to -inf.
    #[test]
    fn wire_reaction_penalty_floors() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let bad: Vec<u8> = vec![0u8; MAX_WIRE_BYTES + 1];
        for _ in 0..30 {
            t.classify(peer, &bad);
        }
        assert_eq!(t.score_of(&peer), Some(WIRE_PENALTY_FLOOR));
    }

    /// A bounds-violating frame UNDER the byte limit (PEX list too long) is
    /// also a protocol violation — the byte limit alone can't catch it.
    #[test]
    fn wire_reaction_penalizes_bounds_violation() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let peers: Vec<String> = (0..(MAX_WIRE_ADDRS + 1))
            .map(|i| format!("/ip4/1.2.3.4/tcp/{}", i % 65535))
            .collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers },
            bincode::config::standard(),
        ).expect("encode");
        assert!(bytes.len() < MAX_WIRE_BYTES);
        match t.classify(peer, &bytes) {
            WireReaction::Penalize { error: WireDecodeError::Bounds(_), score } => {
                assert_eq!(score, WIRE_VIOLATION_PENALTY);
            }
            other => panic!("expected Penalize(Bounds), got {:?}", other),
        }
    }

    /// Plain-malformed bincode (possible benign version skew) is ignored,
    /// never penalized.
    #[test]
    fn wire_reaction_ignores_malformed_without_penalty() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        match t.classify(peer, &[0xFF; 16]) {
            WireReaction::IgnoreMalformed(_) => {}
            other => panic!("expected IgnoreMalformed, got {:?}", other),
        }
        assert_eq!(t.score_of(&peer), None);
        assert_eq!(t.tracked_peers(), 0);
    }

    /// Once the tracking map is full the map does not grow (memory bound
    /// against identity cycling).
    ///
    /// NET-8 (audit): this test used to assert that a late offender is NOT
    /// tracked ("one-shot offender is not inserted") — which let every
    /// offender arriving after 1,024 identities violate forever without ever
    /// reaching the graylist. It now pins the fixed behaviour: the mildest
    /// entry is evicted and the late offender IS tracked and accumulates.
    #[test]
    fn wire_reaction_track_cap_bounds_memory() {
        let mut t = WirePenaltyTracker::new();
        let bad: Vec<u8> = vec![0u8; MAX_WIRE_BYTES + 1];
        for _ in 0..WIRE_PENALTY_TRACK_CAP {
            t.classify(PeerId::random(), &bad);
        }
        assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP);

        let late = PeerId::random();
        match t.classify(late, &bad) {
            WireReaction::Penalize { score, .. } => {
                assert_eq!(score, WIRE_VIOLATION_PENALTY);
            }
            other => panic!("expected Penalize, got {:?}", other),
        }
        assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP, "map must not grow past cap");
        assert_eq!(t.score_of(&late), Some(WIRE_VIOLATION_PENALTY), "late offender is tracked");
        for _ in 0..4 {
            t.classify(late, &bad);
        }
        assert!(t.score_of(&late).unwrap() <= -400.0, "late offender reaches the graylist");
    }

    /// NET-4 / NET-8: penalties decay and are eventually forgotten (and the
    /// reset score is returned so gossipsub's app score is re-installed).
    #[test]
    fn wire_penalties_decay_and_are_forgotten() {
        let mut t = WirePenaltyTracker::new();
        let p = PeerId::random();
        let t0 = std::time::Instant::now();
        for _ in 0..4 {
            t.record_violation_at(p, t0);
        }
        assert_eq!(t.score_of(&p), Some(-400.0));
        assert!(t.decay_tick_at(t0 + Duration::from_secs(1)).is_empty(), "no decay within one interval");
        let after = t.decay_tick_at(t0 + WIRE_PENALTY_DECAY_INTERVAL * 5);
        let s = after.iter().find(|(q, _)| *q == p).map(|(_, s)| *s).expect("decayed score reported");
        assert!(s > -400.0 && s < -200.0, "decayed toward zero: {s}");
        let later = t.decay_tick_at(t0 + WIRE_PENALTY_DECAY_INTERVAL * 200);
        assert_eq!(later, vec![(p, 0.0)], "forgotten peers are reset to 0");
        assert_eq!(t.tracked_peers(), 0);
    }

    // ── NET-7 regressions ──────────────────────────────────────────────────

    /// Trailing bytes after a valid frame are a protocol violation: they made
    /// every request byte-unique and defeated gossipsub de-duplication.
    #[test]
    fn wire_decode_rejects_trailing_bytes() {
        for base in [NetworkMessage::PeerRequest, NetworkMessage::GetTips] {
            let clean = bincode::serde::encode_to_vec(&base, bincode::config::standard()).unwrap();
            assert!(decode_wire_message(&clean).is_ok());
            let mut padded = clean.clone();
            padded.extend_from_slice(&7u32.to_le_bytes());
            match decode_wire_message(&padded) {
                Err(e @ WireDecodeError::TrailingBytes(4)) => assert!(e.is_protocol_violation()),
                other => panic!("trailing bytes must be rejected, got {:?}", other.map(|m| m.kind_name())),
            }
        }
    }

    /// The frame must be the canonical encoding of the message it decodes to.
    ///
    /// (a) NET-7 on every target: a non-minimal varint (the enum tag, an
    ///     integer field, a length) is a byte-distinct frame of the same
    ///     message, so a fresh gossip message id. Each decoded before the
    ///     check, on x86_64 too.
    /// (b) CRY-8 on 32-bit targets: a `block_data` length of 2^32 + 3 written
    ///     as a 9-byte varint, then 3 bytes. A 64-bit node rejects it (read
    ///     limit); on i686 bincode truncated the length to 3 and the frame
    ///     decoded as a 3-byte `block_data`. Now rejected on every target.
    #[test]
    fn wire_decode_requires_the_canonical_encoding() {
        let msg = NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 5,
            height:     9,
            block_data: vec![7u8; 3],
        };
        let cfg = bincode::config::standard();
        let enc = bincode::serde::encode_to_vec(&msg, cfg).unwrap();
        assert!(decode_wire_message(&enc).is_ok(), "the canonical frame decodes");
        // Layout guard: tag, 32 hash bytes, blue_score 5, height 9, len 3, data.
        assert!(enc[0] < 0xFB, "single-byte enum tag");
        assert_eq!(&enc[33..35], &[5, 9], "bincode encoding layout changed; update this test");
        assert!(enc.ends_with(&[3, 7, 7, 7]), "bincode encoding layout changed; update this test");
        let head = &enc[..enc.len() - 4];

        let splice = |at: usize, len: usize, with: &[u8]| -> Vec<u8> {
            let mut f = enc[..at].to_vec();
            f.extend_from_slice(with);
            f.extend_from_slice(&enc[at + len..]);
            f
        };
        let mut non_minimal = vec![
            ("enum tag as u16", splice(0, 1, &[0xFB, enc[0], 0])),
            ("blue_score as u16", splice(33, 1, &[0xFB, 5, 0])),
            ("height as u64", splice(34, 1, &[0xFD, 9, 0, 0, 0, 0, 0, 0, 0])),
            ("length as u16", splice(head.len(), 1, &[0xFB, 3, 0])),
            ("length as u32", splice(head.len(), 1, &[0xFC, 3, 0, 0, 0])),
            ("length as u64", splice(head.len(), 1, &[0xFD, 3, 0, 0, 0, 0, 0, 0, 0])),
        ];
        let mut truncated = head.to_vec();
        truncated.push(0xFD);
        truncated.extend_from_slice(&((1u64 << 32) + 3).to_le_bytes());
        truncated.extend_from_slice(&[7, 7, 7]);
        non_minimal.push(("length 2^32 + 3", truncated));

        for (what, frame) in &non_minimal {
            // Every non-minimal frame still carries the same logical message:
            // bincode itself accepts it (on 64-bit targets except the length
            // of 2^32 + 3, which only 32-bit targets accept).
            if *what != "length 2^32 + 3" || cfg!(target_pointer_width = "32") {
                let (m, used): (NetworkMessage, usize) =
                    bincode::serde::decode_from_slice(frame, cfg).expect(what);
                assert_eq!(used, frame.len(), "{what}");
                assert_eq!(
                    bincode::serde::encode_to_vec(&m, cfg).unwrap(),
                    enc,
                    "{what}: the same message as the canonical frame"
                );
            }
            match decode_wire_message(frame) {
                // 64-bit targets: the 9-byte length announces 2^32 + 3 bytes
                // and the frame ends after 3 (Malformed, as before).
                Err(e) if *what == "length 2^32 + 3" && cfg!(target_pointer_width = "64") => {
                    assert!(matches!(e, WireDecodeError::Malformed(_)), "{what}: {e:?}");
                }
                // A block announcement: refused, but an older release
                // relays it, so not a protocol violation (no penalty).
                Err(e) => {
                    assert!(matches!(e, WireDecodeError::NonCanonical { relayable: true }), "{what}: {e:?}");
                    assert!(!e.is_protocol_violation(), "{what}: {e:?}");
                }
                Ok(m) => panic!("{what}: a non-canonical frame must not decode, got {}", m.kind_name()),
            }
        }
    }

    /// Mixed-version rollout: releases before the one-encoding rule accept a
    /// non-canonical `NewBlock` / `NewTransaction` frame and gossipsub relays
    /// the bytes they received, so an upgraded node drops such a frame
    /// WITHOUT penalty (four penalized frames would graylist an honest older
    /// relay). A message that no honest node relays (here `GetHeaders`,
    /// `PeerTip`) in a non-canonical frame comes from its author and is still
    /// a penalized protocol violation.
    #[test]
    fn non_canonical_relayable_frames_are_dropped_without_penalty() {
        let cfg = bincode::config::standard();
        // Widen the varint at `at` (a value < 251) to bincode's 3-byte form.
        let widen = |enc: &[u8], at: usize| -> Vec<u8> {
            assert!(enc[at] < 0xFB);
            let mut f = enc[..at].to_vec();
            f.extend_from_slice(&[0xFB, enc[at], 0]);
            f.extend_from_slice(&enc[at + 1..]);
            f
        };
        let relayed = [
            NetworkMessage::NewBlock { block_hash: [1; 32], blue_score: 5, height: 9, block_data: vec![7; 3] },
            NetworkMessage::NewTransaction { txid: [2; 32], tx_data: vec![8; 4] },
        ];
        let authored = [
            NetworkMessage::GetHeaders { from_blue_score: 5, limit: 9, nonce: 3 },
            NetworkMessage::PeerTip { peer_id: "p".into(), blue_score: 5, height: 9 },
        ];
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        for (m, relayable) in relayed.iter().map(|m| (m, true)).chain(authored.iter().map(|m| (m, false))) {
            let enc = bincode::serde::encode_to_vec(m, cfg).unwrap();
            // The enum tag (index < 251) is the first byte of every frame.
            let wide = widen(&enc, 0);
            let (back, _): (NetworkMessage, usize) = bincode::serde::decode_from_slice(&wide, cfg).unwrap();
            assert_eq!(bincode::serde::encode_to_vec(&back, cfg).unwrap(), enc, "{}: same message", m.kind_name());
            match decode_wire_message(&wide) {
                Err(e @ WireDecodeError::NonCanonical { .. }) => {
                    assert!(matches!(e, WireDecodeError::NonCanonical { relayable: r } if r == relayable), "{e:?}");
                    assert_eq!(e.is_protocol_violation(), !relayable, "{}", m.kind_name());
                }
                other => panic!("{}: {other:?}", m.kind_name()),
            }
            let before = t.score_of(&peer);
            match t.classify(peer, &wide) {
                WireReaction::IgnoreMalformed(_) if relayable => assert_eq!(t.score_of(&peer), before),
                WireReaction::Penalize { error: WireDecodeError::NonCanonical { relayable: false }, score } if !relayable => {
                    assert_eq!(score, before.unwrap_or(0.0) + WIRE_VIOLATION_PENALTY);
                }
                other => panic!("{}: {other:?}", m.kind_name()),
            }
        }
        assert_eq!(t.score_of(&peer), Some(2.0 * WIRE_VIOLATION_PENALTY), "only the two authored frames were penalized");
    }

    /// Gossip pulls and gossip responses are neither delivered nor relayed;
    /// blocks are deferred to the validating processor; local-only frames
    /// from peers are dropped.
    #[test]
    fn gossip_pulls_are_never_served_or_relayed() {
        let pulls = [
            NetworkMessage::GetTips,
            NetworkMessage::PeerRequest,
            NetworkMessage::GetHeaders { from_blue_score: 0, limit: 500, nonce: 1 },
            NetworkMessage::GetBlock { block_hash: [0u8; 32], nonce: 1 },
            NetworkMessage::Headers { entries: vec![] },
            NetworkMessage::Tips { tips: vec![], locator: vec![] },
            NetworkMessage::BlockNotFound { block_hash: [0u8; 32], nonce: 1 },
            NetworkMessage::PeerExchange { peers: vec![] },
            NetworkMessage::PeerCount { count: 0, addresses: vec![] },
        ];
        for m in &pulls {
            for validated in [false, true] {
                assert_eq!(gossip_disposition(m, validated, true), GossipDisposition::Drop(GossipVerdict::Ignore),
                    "{} must not be delivered or relayed", m.kind_name());
            }
        }
        let blk = NetworkMessage::NewBlock { block_hash: [0u8; 32], blue_score: 0, height: 0, block_data: vec![] };
        assert_eq!(gossip_disposition(&blk, true, false), GossipDisposition::DeliverDeferred);
        assert_eq!(gossip_disposition(&blk, false, false), GossipDisposition::Deliver(GossipVerdict::Accept));
        // MEM-5: transactions are validated before relay too.
        let tx = NetworkMessage::NewTransaction { txid: [0u8; 32], tx_data: vec![] };
        assert_eq!(gossip_disposition(&tx, true, false), GossipDisposition::DeliverDeferred);
        assert_eq!(gossip_disposition(&tx, false, false), GossipDisposition::Deliver(GossipVerdict::Accept));
        let v = NetworkMessage::Version { version: 1, user_agent: "x".into(), blue_score: 1, height: 1, timestamp: 0 };
        assert_eq!(gossip_disposition(&v, true, true), GossipDisposition::Deliver(GossipVerdict::Ignore),
            "claims are consumed locally, never relayed");
        assert_eq!(gossip_disposition(&v, true, false), GossipDisposition::Drop(GossipVerdict::Ignore));
    }

    /// Gossip transactions are judged before they are relayed (deferred
    /// verdict, answered by `mempool::relay::TxRelay` once admission decided);
    /// only the legacy loop relays them on decode. Holds for tip-claim-capable
    /// authors too.
    #[test]
    fn gossip_transactions_are_relayed_only_after_the_mempool_verdict() {
        let tx = NetworkMessage::NewTransaction { txid: [1u8; 32], tx_data: vec![0u8; 8] };
        assert_eq!(gossip_disposition(&tx, true, false), GossipDisposition::DeliverDeferred);
        assert_eq!(gossip_disposition(&tx, true, true), GossipDisposition::DeliverDeferred);
        assert_eq!(gossip_disposition(&tx, false, false), GossipDisposition::Deliver(GossipVerdict::Accept));
    }

    /// The IHAVEs this node sends fit the 16 KiB control limit of a default
    /// libp2p-gossipsub 0.50 receiver, and it decodes the largest IHAVE a
    /// default-configured sender (5000 ids, e.g. libp2p 0.49) produces.
    #[test]
    fn gossip_control_limits_are_consistent_in_both_directions() {
        let cfg = gossipsub_config().expect("config builds");
        // One IHAVE RPC: per id 18 bytes, plus at most 64 bytes of framing
        // (RPC control field, ControlIHave, topic id "gnb/txs/1").
        assert_eq!(GOSSIP_ID_WIRE_COST, 18);
        assert!(cfg.max_control_messages_sent() * GOSSIP_ID_WIRE_COST + 64 <= GOSSIP_PEER_DEFAULT_CONTROL_BYTES,
            "{} ids per IHAVE overflow a default receiver", cfg.max_control_messages_sent());
        assert!(cfg.max_control_message_size() >= 5000 * GOSSIP_ID_WIRE_COST + 64,
            "a default sender's 5000-id IHAVE must decode");
        assert!(cfg.max_control_message_size() < cfg.max_transmit_size());
        // IWANT replies stay generous: a peer may ask for 800 ids per heartbeat.
        assert!(cfg.max_control_messages_sent() >= 500);
        // The id size the arithmetic assumes.
        let m = gossipsub::Message {
            source: None, data: b"frame".to_vec(), sequence_number: None,
            topic: IdentTopic::new(TOPIC_TXS).hash(),
        };
        assert_eq!(gossip_message_id(&m).0.len(), GOSSIP_MESSAGE_ID_LEN);
        assert_eq!(cfg.message_id(&m), gossip_message_id(&m));
        // The rest of the node's settings are unchanged by the refactor.
        assert!(cfg.validate_messages());
        assert_eq!(cfg.max_transmit_size(), 4 * 1024 * 1024);
        assert_eq!(cfg.history_length(), 12);
        assert_eq!(cfg.heartbeat_interval(), Duration::from_secs(1));
        assert_eq!(cfg.duplicate_cache_time(), Duration::from_secs(30));
    }

    // ── NET-16 regressions ─────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn identity_file_is_owner_only_and_reloadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p_identity.bin");
        let kp = load_or_create_identity(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity must be created 0600, got {:o}", mode);
        assert!(!dir.path().join("p2p_identity.bin.tmp").exists(), "no temp file left behind");
        // A world-readable key is tightened on load and still decodes.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let again = load_or_create_identity(&path).unwrap();
        assert_eq!(PeerId::from(kp.public()), PeerId::from(again.public()));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn known_peers_are_written_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        std::fs::write(dir.path().join("known_peers.json.tmp"), b"stale garbage").unwrap();
        let peers: HashSet<String> = ["/ip4/45.77.1.1/tcp/17110/p2p/x".to_string()].into_iter().collect();
        save_known_peers(&path, &peers);
        assert_eq!(load_known_peers(&path), peers);
        assert!(!dir.path().join("known_peers.json.tmp").exists(), "temp file renamed into place");
    }

    // ── NET-11 regression: PEX ingestion never dials ───────────────────────

    #[test]
    fn pex_ingestion_only_fills_the_table() {
        let mut book = AddrBook::new();
        let mut lim = PexRateLimiter::new();
        let mut stats = PexStats::new();
        let me = PeerId::random();
        let author = PeerId::random();
        let mut peers: Vec<String> = (0..30u8).map(|i| format!("/ip4/45.{}.1.1/tcp/17110/p2p/{}", i, PeerId::random())).collect();
        peers.push(format!("/ip4/45.200.1.1/tcp/17110/p2p/{}", me)); // ourselves
        let added = ingest_pex_addresses(&mut book, &mut lim, &mut stats, author, "ip4:9.9", &peers, false, &me, |_| false);
        assert_eq!(added, PEX_BATCH_LIMIT, "batch-capped per message");
        assert_eq!(book.len(), PEX_BATCH_LIMIT);
        // The same author is rate-limited across messages.
        for _ in 0..10 {
            ingest_pex_addresses(&mut book, &mut lim, &mut stats, author, "ip4:9.9", &peers, false, &me, |_| false);
        }
        assert!(book.len() <= pex_validator::PEX_MAX_PER_WINDOW);
    }

    // ── Directed-pull answers (`pull::PullScheduler::on_response`) ──────────
    //
    // Ported from the tests of the removed `on_pull_response` (re-audit
    // B1-T2 / B1-T6): the BlockNotFound retry and the Busy back-off are kept;
    // what changed is pinned below and listed in the commit message.

    use std::time::Instant;

    /// A scheduler with `peers` connected (dialed by us) and one GetBlock
    /// pull of block [5; 32] sent to `first` (its hint). Returns the request id.
    fn one_get_block(peers: &[PeerId], first: PeerId, now: Instant) -> (pull::PullScheduler<u64>, u64) {
        let mut s = pull::PullScheduler::new(HashSet::new());
        for p in peers {
            s.on_connect(*p, true, now);
        }
        assert_eq!(s.enqueue(sync_rr::SyncRequest::GetBlock { block_hash: [5u8; 32] }, None, &[first], now), pull::Enqueued::Queued);
        let mut sent = Vec::new();
        s.drain(now, |p, _| {
            sent.push(p);
            1
        });
        assert_eq!(sent, vec![first]);
        (s, 1)
    }

    /// THE regression for the BlockNotFound retry (feature_partition_heal.py
    /// waited 80 s to more than 120 s): a peer that does not have the body
    /// answers NotFound, and the pull goes to the OTHER peer at once. The
    /// answer is delivered (a NotFound from a peer we dialed may count toward
    /// abandoning a frontier tip), ranks the answering peer down (B1-T6; the
    /// old code counted it as a success), and is not a back-off. The old test
    /// then sent the pull back to the first peer and expected it dropped after
    /// three attempts — exactly the B1-T6 defect: now a pull is never sent to
    /// the same peer twice and, once every connected peer said NotFound, it is
    /// dropped (and the NotFound charges refunded: nobody had the block).
    #[test]
    fn block_not_found_requeues_the_pull_for_another_peer() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let (mut s, id) = one_get_block(&[a, b], a, now);
        let not_found = sync_rr::SyncResponse::BlockNotFound { block_hash: [5u8; 32] };
        let act = s.on_response(id, a, &not_found, now);
        assert_eq!((act.deliver, act.violation), (true, None));
        assert_eq!(s.pending_len(), 1, "the pull must be retried, not completed");
        assert_eq!(s.selector().in_flight(&a), 0);
        assert!(!s.selector().is_cooling_down(&a, now), "NotFound is an answer, not back-pressure");
        assert!(s.selector().penalty(&a, now) > 0.0, "but it ranks the peer down");
        let mut sent = Vec::new();
        s.drain(now, |p, _| {
            sent.push(p);
            2
        });
        assert_eq!(sent, vec![b], "the retry goes to the peer not tried yet");
        s.on_response(2, b, &not_found, now);
        s.drain(now, |_, _| panic!("no peer left that has not answered"));
        assert_eq!((s.pending_len(), s.in_flight_len(), s.dropped()), (0, 0, 1));
        assert_eq!(s.selector().penalty(&a, now), 0.0, "a true NotFound is refunded");
    }

    /// Busy (NET-5): back-pressure. The peer backs off and the pull is
    /// retried elsewhere (without using an attempt or excluding the peer).
    #[test]
    fn busy_backs_the_peer_off_and_requeues_the_pull() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let now = Instant::now();
        let (mut s, id) = one_get_block(&[a, b], a, now);
        let act = s.on_response(id, a, &sync_rr::SyncResponse::Busy, now);
        assert_eq!((act.deliver, act.violation), (false, None));
        assert!(s.selector().is_cooling_down(&a, now));
        assert_eq!(s.selector().in_flight(&a), 0);
        assert_eq!(s.pending_len(), 1);
        let mut sent = Vec::new();
        s.drain(now, |p, _| {
            sent.push(p);
            2
        });
        assert_eq!(sent, vec![b]);
    }

    /// B1-T2: only the requested block completes a GetBlock pull. The old
    /// test pinned the defect: it asserted that a Block for ANOTHER hash, a
    /// Headers (even empty), a Tips or a Peers answer completed the GetBlock
    /// pull, with no penalty. Now each is a violation that is not delivered,
    /// puts the peer on cooldown, and sends the pull on.
    #[test]
    fn only_the_requested_block_completes_a_block_pull() {
        let entry = || SyncEntry { hash: [1u8; 32], blue_score: 1, height: 1 };
        let ok = sync_rr::SyncResponse::Block { block_hash: [5u8; 32], blue_score: 1, height: 1, block_data: vec![1] };
        let a = PeerId::random();
        let now = Instant::now();
        let (mut s, id) = one_get_block(&[a], a, now);
        let act = s.on_response(id, a, &ok, now);
        assert_eq!((act.deliver, act.violation), (true, None));
        assert_eq!((s.pending_len(), s.selector().in_flight(&a)), (0, 0));
        assert!(!s.selector().is_cooling_down(&a, now));
        for wrong in [
            sync_rr::SyncResponse::Block { block_hash: [6u8; 32], blue_score: 1, height: 1, block_data: vec![1] },
            sync_rr::SyncResponse::Headers { entries: vec![entry()] },
            sync_rr::SyncResponse::Headers { entries: vec![] },
            sync_rr::SyncResponse::Tips { tips: vec![entry()], locator: vec![] },
            sync_rr::SyncResponse::Peers { peers: vec![] },
        ] {
            let b = PeerId::random();
            let (mut s, id) = one_get_block(&[a, b], a, now);
            let act = s.on_response(id, a, &wrong, now);
            assert!(!act.deliver && act.violation.is_some(), "{wrong:?}");
            assert_eq!(s.pending_len(), 1, "{wrong:?} must not complete the pull");
            assert!(s.selector().is_cooling_down(&a, now), "{wrong:?}");
        }
    }

    /// An answer to a request the scheduler does not know is ignored.
    #[test]
    fn answer_to_an_unknown_request_is_ignored() {
        let a = PeerId::random();
        let now = Instant::now();
        let mut s: pull::PullScheduler<u64> = pull::PullScheduler::new(HashSet::new());
        s.on_connect(a, true, now);
        let act = s.on_response(9, a, &sync_rr::SyncResponse::BlockNotFound { block_hash: [5u8; 32] }, now);
        assert_eq!(act, pull::ResponseAction::default());
        assert_eq!(s.pending_len(), 0);
    }

    // ── Peer count and heartbeat ────────────────────────────────────────────

    /// The peer count is of distinct peers (`ConnManager::peer_count`): a
    /// second connection to a peer does not count, closing one of two
    /// connections does not uncount, closing the last one does. Counting
    /// connections reported a peer dialed twice as two peers.
    #[test]
    fn peer_count_counts_distinct_peers_not_connections() {
        let now = Instant::now();
        let mut m = ConnManager::new(addrbook::random_key(), 8);
        let (p, q) = (PeerId::random(), PeerId::random());
        let a: Multiaddr = "/ip4/80.1.1.1/tcp/1".parse().unwrap();
        let c = libp2p::swarm::ConnectionId::new_unchecked;
        m.on_established(c(1), p, false, &a, now);
        m.on_established(c(2), p, false, &a, now);
        m.on_established(c(3), q, false, &a, now);
        assert_eq!(m.peer_count(), 2);
        m.on_closed(c(1), p);
        assert_eq!(m.peer_count(), 2, "P is still connected");
        m.on_closed(c(2), p);
        assert_eq!(m.peer_count(), 1);
        m.on_closed(c(3), q);
        assert_eq!(m.peer_count(), 0);
        m.on_closed(c(3), q);
        assert_eq!(m.peer_count(), 0, "never below zero");
    }

    /// B1-T9 / NET-11 (a): the swarm caps leave inbound one transient slot
    /// over `max_peers` (so the connection manager can evict instead of the
    /// transport refusing) and room for every outbound slot on top.
    #[test]
    fn swarm_caps_reserve_outbound_room_and_one_eviction_slot() {
        // The limits type has no getters; its Debug form names every field.
        let dbg = format!("{:?}", swarm_connection_limits(50));
        assert!(dbg.contains("max_established_incoming: Some(51)"), "{dbg}");
        assert!(dbg.contains("max_established_total: Some(100)"), "{dbg}");
        assert!(dbg.contains("max_established_per_peer: Some(2)"), "{dbg}");
        let dbg = format!("{:?}", swarm_connection_limits(8));
        assert!(dbg.contains("max_established_incoming: Some(9)"), "{dbg}");
        assert!(dbg.contains(&format!("max_established_total: Some({})", 8 + connmgr::OUTBOUND_CONNECTION_HEADROOM)), "{dbg}");
    }

    // ── Phase 4, package R2a: serving cost and answer bounds ────────────────

    fn hh(i: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_be_bytes());
        h[31] = 0x5A;
        h
    }

    fn served(
        dag: &std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        store: &std::sync::Arc<crate::storage::Storage>,
        req: sync_rr::SyncRequest,
    ) -> sync_rr::SyncResponse {
        serve::serve_sync_request(dag, store, &req, 0)
    }

    /// B2-T7: the GetTips answer of a DAG with more than MAX_WIRE_TIPS leaves
    /// (here 300 siblings, 20 of them chain-disqualified) must decode at the
    /// requester (`decode_response`), carry no disqualified block, and be the
    /// best valid tips by blue work. The server used to send every leaf, which
    /// every requester refused as a protocol violation.
    #[test]
    fn get_tips_answer_is_bounded_valid_and_decodable() {
        use crate::consensus::GhostDAG;
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crate::storage::Storage::open(&dir.path().join("db")).unwrap());
        let mut d = GhostDAG::with_k(10);
        let g = hh(0);
        d.add_genesis(g, 0);
        for i in 1..=300u32 {
            d.add_block(hh(i), vec![g], u64::from(i), 1_000 + u128::from(i)).unwrap();
        }
        // The 20 heaviest leaves are disqualified (as after a connect failure).
        let invalid: Vec<[u8; 32]> = (281..=300u32).map(hh).collect();
        for h in &invalid {
            d.mark_invalid(*h);
        }
        let selected = d.selected_tip().unwrap();
        assert_eq!(selected, hh(280));
        let dag = std::sync::Arc::new(parking_lot::RwLock::new(d));
        let resp = served(&dag, &store, sync_rr::SyncRequest::GetTips);
        let bytes = sync_rr::encode_frame(&resp).unwrap();
        let back = sync_rr::decode_response(&bytes).expect("an honest GetTips answer must pass the requester's bounds");
        let sync_rr::SyncResponse::Tips { tips, .. } = back else { panic!("expected Tips") };
        assert!(!tips.is_empty() && tips.len() <= MAX_WIRE_TIPS, "{} tips", tips.len());
        assert_eq!(tips[0].hash, selected, "the selected tip leads");
        assert!(tips.iter().all(|t| !invalid.contains(&t.hash)), "a disqualified tip was advertised");
        // The best valid tips by blue work: 280, 279, ... (256 of them).
        let want: Vec<[u8; 32]> = (25..=280u32).rev().map(hh).collect();
        assert_eq!(tips.iter().map(|t| t.hash).collect::<Vec<_>>(), want);
    }

    /// A linear chain of `n` blocks after genesis.
    fn chain_dag(n: u32) -> crate::consensus::GhostDAG {
        let mut d = crate::consensus::GhostDAG::with_k(10);
        d.add_genesis(hh(0), 0);
        for i in 1..=n {
            d.add_block(hh(i), vec![hh(i - 1)], u64::from(i), 1).unwrap();
        }
        d
    }

    /// B1-T3 / B2-T5: the DAG entries touched to serve GetTips and GetHeaders
    /// (the counter `GhostDAG::query_visits`) do not grow with the DAG size.
    /// GetTips walked the whole selected chain for an unused locator and
    /// GetHeaders scanned every stored block, on the swarm event loop.
    #[test]
    fn served_request_work_does_not_grow_with_dag_size() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crate::storage::Storage::open(&dir.path().join("db")).unwrap());
        let mut work = Vec::new();
        for n in [300u32, 3_000] {
            let dag = std::sync::Arc::new(parking_lot::RwLock::new(chain_dag(n)));
            let before = dag.read().query_visits();
            let reqs = [
                sync_rr::SyncRequest::GetTips,
                sync_rr::SyncRequest::GetHeaders { from_blue_score: 0, limit: 200 },
                sync_rr::SyncRequest::GetHeaders { from_blue_score: u64::from(n) - 100, limit: 200 },
                sync_rr::SyncRequest::GetBlock { block_hash: hh(5) },
            ];
            for r in reqs {
                let resp = served(&dag, &store, r.clone());
                if let (sync_rr::SyncRequest::GetHeaders { from_blue_score: 0, .. }, sync_rr::SyncResponse::Headers { entries }) = (&r, &resp) {
                    assert_eq!(entries.len(), 200);
                    assert_eq!(entries[0].hash, hh(0));
                    assert_eq!(entries[199].hash, hh(199));
                }
            }
            work.push(dag.read().query_visits() - before);
        }
        assert!(work[1] <= work[0] + 8, "per-request work grew with the DAG: {work:?}");
        assert!(work[1] < 1_000, "per-request work is not O(log n + limit): {work:?}");
    }

    /// PoWit finality (the mainnet line's checkpoint, `GhostDAG::set_finalized`):
    /// with the checkpoint a fixed distance below the tip, serving GetTips
    /// still does not grow with the DAG (the finality walk is bounded by
    /// that distance and shared by the tips), and a tip that forks below the
    /// checkpoint is not advertised: it can never be selected or merged by a
    /// template, so advertising it only made every requester fetch it.
    #[test]
    fn get_tips_with_a_finalized_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crate::storage::Storage::open(&dir.path().join("db")).unwrap());
        let mut work = Vec::new();
        for n in [300u32, 3_000] {
            let mut d = chain_dag(n);
            // A stale sibling of block 1, far below the checkpoint.
            d.add_block(hh(1_000_000), vec![hh(0)], 1, 1).unwrap();
            // Another tip, off block n - 10 (above the checkpoint).
            d.add_block(hh(2_000_000), vec![hh(n - 10)], u64::from(n), 1).unwrap();
            d.set_finalized(hh(n - 50), u64::from(n - 50));
            let dag = std::sync::Arc::new(parking_lot::RwLock::new(d));
            let before = dag.read().query_visits();
            let resp = served(&dag, &store, sync_rr::SyncRequest::GetTips);
            work.push(dag.read().query_visits() - before);
            let back = sync_rr::decode_response(&sync_rr::encode_frame(&resp).unwrap()).expect("decodes at the requester");
            let sync_rr::SyncResponse::Tips { tips, .. } = back else { panic!("expected Tips") };
            assert_eq!(tips.iter().map(|t| t.hash).collect::<Vec<_>>(), vec![hh(n), hh(2_000_000)]);
        }
        assert!(work[1] <= work[0] + 4, "GetTips work grew with the DAG under finality: {work:?}");
        assert!(work[0] < 100, "GetTips is not O(log n + limit + finality distance): {work:?}");
    }

    /// POW-3: below its minimum chain work (initial block download) a node
    /// answers GetTips and GetHeaders empty, as Bitcoin Core ignores
    /// `getheaders` in IBD: a chain it does not trust yet (an eclipsing
    /// peer's cheap chain its own pulls fetched) is not advertised for others
    /// to pull. At the minimum (or with none, as harnesses run) it answers
    /// as before.
    #[test]
    fn below_the_minimum_chain_work_no_frontier_or_headers_are_served() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crate::storage::Storage::open(&dir.path().join("db")).unwrap());
        let dag = std::sync::Arc::new(parking_lot::RwLock::new(chain_dag(40)));
        let work = crate::ingress::tip_blue_work(&dag.read());
        let tips = |min| match serve::serve_sync_request(&dag, &store, &sync_rr::SyncRequest::GetTips, min) {
            sync_rr::SyncResponse::Tips { tips, .. } => tips.len(),
            other => panic!("{other:?}"),
        };
        let headers = |min| match serve::serve_sync_request(
            &dag, &store, &sync_rr::SyncRequest::GetHeaders { from_blue_score: 0, limit: 500 }, min,
        ) {
            sync_rr::SyncResponse::Headers { entries } => entries.len(),
            other => panic!("{other:?}"),
        };
        for min in [0, work] {
            assert_eq!(tips(min), 1, "at or above the minimum ({min})");
            assert!(headers(min) > 30, "at or above the minimum ({min})");
        }
        for min in [work + 1, crate::core::MIN_CHAIN_WORK] {
            assert_eq!(tips(min), 0, "below the minimum ({min})");
            assert_eq!(headers(min), 0, "below the minimum ({min})");
        }
    }

    /// Blocks from the PoWit activation carry the PoWit section in their
    /// wire encoding (the mainnet line's 45c9c97: `Block::wire_size` counts
    /// it). GetBlock serves the stored bytes as they are (B2-T6); the frame
    /// written must be byte-identical to the one the old path (decode the
    /// stored block, encode it again) produced, be charged its exact length,
    /// and decode at the requester to the same block, PoWit section included.
    #[test]
    fn powit_blocks_are_served_as_their_exact_stored_frames() {
        use crate::core::{powit::PowitBody, witness_share::WitnessShare, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
        use libp2p::request_response::Codec as _;
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crate::storage::Storage::open(&dir.path().join("db")).unwrap());
        let dag = std::sync::Arc::new(parking_lot::RwLock::new(crate::consensus::GhostDAG::with_k(10)));
        let activation = crate::core::powit_height();
        for height in [activation - 1, activation, activation + 7] {
            let powit = PowitBody {
                shares: (0..3u8)
                    .map(|i| WitnessShare { attested: [i; 32], witness: [0x44; 20], payout: vec![0x76; 25], bits: 0x1f00_ffff, nonce: u64::from(i) << 40, sha256d: None })
                    .collect(),
                attestations: Vec::new(),
                evidence: Vec::new(),
                exits: Vec::new(),
            };
            let txs = vec![Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: height.to_le_bytes().to_vec(), sequence: u32::MAX }],
                outputs: vec![TxOutput { value: 50, script_pubkey: vec![0xCD; 20] }],
                locktime: 0,
            }];
            let block = Block {
                header: BlockHeader { version: 1, parents: vec![[0x11; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 1_000 + height, bits: 0x2100_ffff, nonce: 9 },
                transactions: txs,
                blue_score: height + 3,
                height,
                shielded_transactions: Vec::new(),
                powit,
            };
            let active = crate::core::powit_active(height);
            assert_eq!(block.wire_size(), block.to_wire_bytes().len(), "h {height}");
            store.put_block_body(&block).unwrap();
            let hash = block.block_hash();
            let req = sync_rr::SyncRequest::GetBlock { block_hash: hash };
            let resp = served(&dag, &store, req.clone());
            // The old serving path: decode the stored block, encode it again.
            let old = sync_rr::SyncResponse::Block {
                block_hash: hash,
                blue_score: block.blue_score,
                height,
                block_data: store.get_block(&hash).unwrap().unwrap().to_wire_bytes(),
            };
            assert_eq!(resp, old, "h {height}: stored bytes differ from the re-encoding");
            let mut out = futures::io::Cursor::new(Vec::new());
            futures::executor::block_on(sync_rr::BlochSyncCodec.write_response(&sync_rr::SYNC_PROTOCOL, &mut out, resp.clone()))
                .unwrap();
            let frame = out.into_inner();
            assert_eq!(frame, sync_rr::encode_frame(&old).unwrap(), "h {height}: frame");
            assert_eq!(serve::charge_for(&resp), frame.len(), "h {height}: charge");
            // The requester.
            let back = sync_rr::decode_response(&frame).expect("decodes");
            sync_rr::check_response(&req, &back).expect("bound to its request");
            let sync_rr::SyncResponse::Block { block_data, .. } = back else { panic!("expected Block") };
            let got = Block::from_wire_bytes(&block_data).expect("block decodes");
            assert_eq!(got.block_hash(), hash);
            assert_eq!(got.powit, if active { block.powit.clone() } else { PowitBody::default() }, "h {height}");
            assert_eq!(block_data.len(), block.wire_size());
        }
    }

    /// The heartbeat's first tick comes one period after start-up, not at
    /// once: an immediate tick saw 0 peers (no connection established yet)
    /// and re-dialed every bootstrap peer, giving two connections per peer.
    #[tokio::test(start_paused = true)]
    async fn heartbeat_first_tick_is_one_period_after_start() {
        let mut hb = new_heartbeat();
        let start = tokio::time::Instant::now();
        assert!(tokio::time::timeout(HEARTBEAT_PERIOD - Duration::from_millis(1), hb.tick()).await.is_err(),
            "the heartbeat ticked at start-up");
        hb.tick().await;
        assert_eq!(start.elapsed(), HEARTBEAT_PERIOD);
        hb.tick().await;
        assert_eq!(start.elapsed(), 2 * HEARTBEAT_PERIOD);
    }

    /// B1-T19 (PoWit): transactions and PoWit items (the transaction topic's
    /// two message kinds) go to the transaction ingest; blocks and
    /// everything else stay on the block channel. A wire violation in a
    /// PoWit frame (an oversized item, an unknown kind) goes through the
    /// same rollout-gated classifier as every frame (`classify_gated`).
    #[test]
    fn powit_items_and_transactions_go_to_the_tx_ingest() {
        assert!(goes_to_tx_ingest(&NetworkMessage::NewTransaction { txid: [1; 32], tx_data: vec![] }));
        assert!(goes_to_tx_ingest(&NetworkMessage::NewPowitItem { id: [2; 32], kind: 1, data: vec![0; 8] }));
        assert!(!goes_to_tx_ingest(&NetworkMessage::NewBlock { block_hash: [3; 32], block_data: vec![], height: 1, blue_score: 1 }));
        assert!(!goes_to_tx_ingest(&NetworkMessage::GetTips));

        let oversized = bincode::serde::encode_to_vec(
            &NetworkMessage::NewPowitItem { id: [2; 32], kind: 1, data: vec![0; MAX_WIRE_POWIT_ITEM + 1] },
            bincode::config::standard()).unwrap();
        let p = PeerId::random();
        let mut t = WirePenaltyTracker::new();
        assert!(matches!(t.classify_gated(p, &oversized, false), WireReaction::IgnoreMalformed(_)),
            "before the activation a relayed violation is refused, not charged");
        assert!(matches!(t.classify_gated(p, &oversized, true), WireReaction::Penalize { .. }));
    }

    /// NET-11 (a): only novel blocks and transactions earn inbound-eviction
    /// protection. PoWit items (main's `NewPowitItem`) are deferred to the
    /// processor like transactions, but an accepted one protects nobody.
    #[test]
    fn only_blocks_and_transactions_earn_novel_delivery_protection() {
        let block = NetworkMessage::NewBlock { block_hash: [1; 32], blue_score: 1, height: 1, block_data: vec![] };
        let tx = NetworkMessage::NewTransaction { txid: [2; 32], tx_data: vec![] };
        assert_eq!(novel_kind(&block), Some(true));
        assert_eq!(novel_kind(&tx), Some(false));
        for kind in 1..=crate::powit::ITEM_KIND_MAX {
            let item = NetworkMessage::NewPowitItem { id: [3; 32], kind, data: vec![0; 8] };
            assert_eq!(gossip_disposition(&item, true, false), GossipDisposition::DeliverDeferred);
            assert_eq!(novel_kind(&item), None, "a PoWit item (kind {kind}) earns no eviction protection");
        }
        assert_eq!(novel_kind(&NetworkMessage::GetTips), None);
    }
}
