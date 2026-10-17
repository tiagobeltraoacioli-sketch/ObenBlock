# GnB peer-to-peer security

## Transport: `/gnb/pq/2.0.0`

Every connection (TCP and WebSocket) is secured by a post-quantum handshake
(`node/src/transport/upgrade.rs`):

| Part | Construction |
| --- | --- |
| Key exchange | ML-KEM-768 (FIPS 203) **and** X25519, both ephemeral. Session keys come from HKDF-SHA256 over both shared secrets, salted with the transcript hash, so the session stays confidential unless both are broken. |
| Authentication | Each side signs the transcript with its libp2p key (Ed25519, from which the `PeerId` is derived) **and** its PQ identity key (hybrid ML-DSA-65 ‖ Falcon-1024, the consensus scheme, verified in the strict enveloped canonical form). |
| Mutual binding | The responder signs the transcript of both opening messages; the initiator then signs the full transcript in a third message. Neither side accepts the connection before verifying the other's signatures. |
| Cipher | ChaCha20-Poly1305, monotonic counters (replay and reorder rejected), frame length bound into the AEAD. |

Rejected outright: other handshake versions, a non-hybrid PQ key, a low-order
X25519 point, a wrong-size ML-KEM key, oversized handshake frames, and
connections to oneself.

The ephemeral ML-KEM-768 decapsulation key and both shared secrets live in
locked, wiped `SecretBytes` regions (audit CRY-4: the `pqcrypto` wrapper's
were `Copy` arrays kept unwiped in the handshake's state); the
decapsulation key is wiped as soon as it is used, and the stack the C code
used is scrubbed after each KEM call. The PQ identity key is held the same
way for the node's whole run (`docs/RUNNING.md`, "Secret key memory"). The
connection's ChaCha20-Poly1305 stream keys and the libp2p Ed25519 identity
key are not (wiped on drop, not locked; same section).

### Identities and pinning

- `p2p_identity.bin`: libp2p Ed25519 key (owner-only permissions).
- `p2p_pq_identity.bin`: PQ identity key (owner-only, written atomically,
  self-tested on load; a corrupt file stops the node instead of being
  replaced).
- `p2p_pq_pins.json`: `PeerId` → PQ key fingerprint. The first handshake with
  a peer pins its PQ key; any later handshake for that `PeerId` with another
  PQ key is refused. Forging the Ed25519 key of a known peer is therefore not
  enough to impersonate it. A malformed pin file stops the node (dropping pins
  would re-open every known peer to impersonation).

The node logs its PQ fingerprint at start. To rotate a node's PQ key, its
peers must remove its entry from their pin files.

Not claimed: identity hiding (identities travel in clear), traffic-analysis
resistance, a formal proof, a third-party audit.

## Blocks at the network edge

GnB-SMH costs as much to verify as one mining attempt (v1: ~0.5 s, 64 MiB;
v3, from the PoW + PoWit activation: ~90 ms, 4 MiB), so a block received
from a peer is evaluated only after every cheap check, and never on the
message processor (`node/src/ingress.rs`, `node/src/pow/verifier.rs`; the
merge of the audit replaced `network/pow_gate.rs` with them;
docs/CONSENSUS.md, "Anti-DoS work rule" and the sections after it):

1. Blocks already known are dropped. An unsolicited block claiming a height
   more than 1,000 above the tip is dropped before decoding.
2. A block this node did not ask for is processed only if its chain can
   reach the work of the selected-chain block 11 below the tip, and not at
   all while the node is below the minimum chain work (initial sync) unless
   its own chain reaches it (Bitcoin Core's `AcceptBlock`).
3. Context-free checks: structure (size, Merkle root, coinbase, the PoWit
   section's shape), id and height bound to the content.
4. Every parent known: the anti-DoS work rule, then height, `bits`
   (`expected_bits`, exactly) and timestamp, as block acceptance requires.
   A parent unknown (an orphan): `bits` no easier than 16 times the target a
   child of the tip would carry now, in the orphan's own algorithm.
5. The proof is evaluated on a bounded worker pool (half the logical CPUs, 1
   to 4) off the processor. Gossip evaluations are charged to the
   delivering peer (4, then one per minute) and its network group (IPv4
   /16, IPv6 /32: 8, then one per 30 s) and refunded when the proof is
   valid; a peer or group out of budget, or a full queue, gets `Ignore`.
   Blocks this node requested go first and are charged only when invalid.
6. A peer that delivers an invalid block it authored (or, once the chain
   contains the hardening activation block, relays one with an invalid
   proof, structure or encoding) is disconnected and its address (IPv4, or
   IPv6 /64) refused for 24 hours; `--peer` peers and loopback are exempt.

Gossiped transactions are relayed only after this node's mempool accepted
them, budgeted per connection and node-wide (docs/MEMPOOL.md). PoWit items
(witness shares, attestations, equivocation proofs) are relayed only after
this node admitted them; they are verified with transactions, off the block
path, on a bounded pool with per-peer and per-network-group budgets of
failed verifications, and an item whose id, encoding, share proof or
witness signature is invalid counts against its sender like an invalid
block.

Gossip is validated before it is relayed (`validate_messages`): a block is
relayed only after its proof verified, an orphan only once it connects.

## Peers and addresses

Connection management follows Bitcoin Core (details: `docs/RUNNING.md`,
"Peers and connections"):

- 8 full-relay and 2 block-relay-only outbound connections are kept whatever
  the inbound count; inbound connections never use those slots.
- When the inbound slots are full, an inbound peer is evicted as Core's
  `SelectNodeToEvict` chooses (netgroup diversity, low latency, novel blocks
  and transactions, uptime are protected; the youngest peer of the largest
  netgroup goes).
- Block-relay-only connections carry no gossip at all (no transactions, PoWit
  items, addresses or block announcements); blocks are polled over them.
  They are saved as anchors (`anchors.json`) and re-dialed first after a
  restart.
- Feeler connections test new-table addresses about every 2 minutes.
- Addresses live in keyed new and tried tables (Core's addrman with a secret
  key derived from the node's identity), learned only from answers to the
  node's own `GetPeers`; peer exchange carries public IP literals only (host
  names and IPv6 forms embedding a private IPv4 are refused).
- Sync requests are rate limited per peer; peers whose budget has refilled
  are forgotten, so the limiter never locks new peers out.

## Mempool policy

- Transactions spend confirmed outputs only (no unconfirmed chains).
- Replace-by-fee: a transaction conflicting with pool entries replaces all of
  them only if it pays their total fee plus 1 sat/byte of its own size, has a
  strictly higher fee rate than each, replaces at most 100, and fits without
  further eviction. Otherwise the first-seen transaction stays.
- A full pool evicts its lowest fee-rate entry only for a newcomer paying at
  least 1 sat/byte more (incremental relay fee).
- Entries expire after 72 hours.
