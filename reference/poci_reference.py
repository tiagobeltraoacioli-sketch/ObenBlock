"""PoCI (Proof of Corruption or Integrity): ObenBlock's strict finality --
executable reference specification.

The normative definition of docs/DESIGN-obenblock-poci.md (package O11):
the frozen configuration of an epoch and its id, the v3 attestation message,
the strict quorum, Casper FFG justification and finality under one
configuration, the handoff between configurations, Proof of Corruption
(equivocation evidence and the 100-epoch exclusion) and Proof of Integrity
(the finality certificate, its encoding and verification). ObenBlock only:
GnB keeps the PoWit rules of `powit_reference.py`. Written from the
specification with hashlib only; the KES key id is `powit_reference`'s.
The Rust implementation must reproduce `poci_vectors.json` exactly.

    python3 reference/poci_reference.py            # regenerate poci_vectors.json
    python3 reference/poci_reference.py --check    # CI: the file is what this generates
    python3 reference/poci_reference_test.py -v    # the reference's own tests

Hashes. sha256d(b) = SHA-256(SHA-256(b)); tagged(tag, m) = SHA-256(SHA-256(tag)
|| SHA-256(tag) || m) (the repo's tagged-hash convention, gnb_merkle.py).
Every integer is little endian; weights and totals are u128.

Parameters digest (section 2, `params_digest`):

    params_digest = sha256d( "OBB-POCI-v1/params" || u32le(chain_id)
        || u64le(epoch_len) || u64le(checkpoint_interval) || u64le(window_epochs)
        || u64le(vote_ttl) || u64le(max_attestations_per_block)
        || u64le(max_evidence_per_block) || u64le(ban_epochs)
        || u64le(bootstrap_epochs) || u64le(launch_bury) || u64le(growth_div)
        || u64le(g_min_epoch_div) || u32le(quorum_num) || u32le(quorum_den) )   118-byte preimage

Launch (section 9): no finality during the first bootstrap_epochs (4) epochs.
C_bootstrap is computed from the history below the checkpoint opening epoch
bootstrap_epochs, and enters into force, with that checkpoint justified and
finalized, only at the first block whose height is at least
launch_height = opening(bootstrap_epochs) + launch_bury (launch_bury =
epoch_len: one epoch, 720 blocks on mainnet), i.e. once the checkpoint is
buried by launch_bury blocks on the selected chain. Before that block no
state carries a finalized checkpoint above genesis (nothing to pin), so a
fork at the epoch-4 boundary is resolved by work like any PoW fork.
`PociChain.launch` models that block.

Configuration of epoch e (section 2). entries: (key_id[20], weight u128) with
weight > 0, strictly ascending by key_id (so no duplicate key); total = their
exact sum, which must fit in u128.

    leaf(k, w)        = tagged("OBB-POCI-v1/leaf", key_id || u128le(w))      36-byte message
    node(l, r)        = tagged("OBB-POCI-v1/node", l || r)
    tree_root([])     = 32 zero bytes
    tree_root(leaves) = pair adjacent nodes left to right, an odd last node is
                        carried up unchanged (gnb_merkle.tagged_merkle_root's shape)
    merkle_root(E)    = tagged("OBB-POCI-v1/root", u32le(len(E)) || tree_root(E))
    config_id         = sha256d( "OBB-POCI-v1/config" || u32le(chain_id) || u64le(e)
                                 || u128le(total) || merkle_root(E) || params_digest )   110-byte preimage

A Merkle path of entry i (of n) lists the siblings bottom up; a level where i
is the carried odd last node contributes no sibling, so (i, n) fix the
path's shape and its length.

Attestation message v3 (section 2), signed by the KES leaf of epoch(target):

    msg_v3 = SHA3-256( u32le(18) || "OBB-POCI-v1/attest" || u32le(chain_id)
                       || config_id[32] || u8(depth) || root[32]
                       || u64le(source.height) || source.hash[32]
                       || u64le(target.height) || target.hash[32] )            171-byte preimage

The KES public key (depth, root) is committed as in v2 (PoWit audit finding 1:
without it one leaf signature re-roots into valid signatures of other keys,
which would make Proof of Corruption forgeable). key_id = witness_id(depth,
root) = SHA3-256("GNB-KES-v1/id" || u8(depth) || root)[0:20].

Quorum (section 3), exact integers (no saturation):

    quorum(got, total) <=> 3 * got > 2 * total

where got is the weight, in the configuration, of the distinct keys of the
configuration with a valid v3 vote for the link naming its config_id.

FFG under the configuration in force (section 3): the source of every
counted vote is the justified checkpoint J; a quorum for a checkpoint slot
t > J justifies t; if t.height == J.height + checkpoint_interval it also
finalizes J.

Handoff (section 4): when a checkpoint F is finalized under C_e and
x = epoch(F) > e, the chain steps through every epoch boundary in order:
C_{e+1}, C_{e+2}, ..., C_x enter into force one after the other, each
computed strictly from the configuration before it and the history up to
ledger height opening(y) of its own epoch y (the bans, rejoins and absence
of section 4.1 are cut there, the presence window and the quorum gate are
those of y, and the provider reads share work of epochs < y - 1); bans and
rejoins that start in an intermediate epoch take effect there. Otherwise
C_e stays. C_x is then a function of the history only, whatever
checkpoints were finalized on the way: two chains with the same history up
to opening(x) hold the same C_x. If a step would be empty, it carries the
entries of the configuration before it forward unchanged (and the prunings
that step started are void): a handoff never leaves a configuration that
can reach no quorum.

Proof of Corruption (section 5): two distinct v3 attestations, same KES key,
same config_id, a known configuration that has the key as an entry, both
signatures valid, and a double vote (same target height, different targets)
or a strict surround (s1 < s2 and t2 < t1, either way round). A block at
height h may carry it unless the key already has a ban pending or not yet
over, or was already banned for that config_id. ban_start = the epoch of the
first configuration entering into force (a handoff step) at or after the
finalization of the block holding the evidence whose epoch x has the
evidence at or below opening(x) (included_at <= opening(x); the steps of the
handoff triggered by that same finalization count when they do). The key is not an entry of C_x for ban_start <= x < ban_start +
ban_epochs (100). Configurations already in force or past never change.

Absence pruning by the old committee (section 4.1, PRUNE_AFTER = 4 epochs).
A vote is "included at" ledger height h (the node passes block height + 1,
the convention of the evidence height above: h <= F.height means the block is
in the history finalized by F). At each handoff step C_e -> C_x (x = e + 1,
section 4) of a finalization of F, with cut = opening(x) <= F.height, after
the ban starts (evidence included at h <= cut):

  1. rejoins: every pending rejoin included at h <= cut ends its key's
     pruning; the key is no longer excluded from x on.
  2. pruning: a key k of C_e is present iff a vote of k was included at a
     height h with opening(x - PRUNE_AFTER) < h <= cut (the blocks of epochs
     x - 4 .. x - 1). If the present keys hold a strict quorum of C_e
     (3 * present weight > 2 * total(C_e)), every key k of C_e that is not
     pruned yet, not present, and has been an entry of every configuration
     in force since epoch x - PRUNE_AFTER or earlier (walking the
     configurations newest first, k is an entry of each one until one whose
     epoch is <= x - PRUNE_AFTER; a key that entered later is in its grace
     period) is pruned (excluded from x on, until a rejoin). Otherwise C_e
     was not operating in the window (a finality stall: the committee that
     ends it has no votes there) and nobody is pruned at this handoff.
  3. C_x = the provider's candidate weights minus the keys banned at x and
     the pruned keys. A pruned key absent from the candidate weights (no
     share work left in its window) is forgotten: its later share work counts
     as a new key's. Included votes are kept only for the keys of C_x. If
     C_x is empty, it holds C_e's entries instead and this handoff's
     prunings are void.

Rejoin (section 4.1): a pruned key returns by publishing, signed with the KES
leaf of `epoch`,

    rejoin_msg = SHA3-256( u32le(18) || "OBB-POCI-v1/rejoin" || u32le(chain_id)
                           || u8(depth) || root[32] || u64le(epoch) )          67-byte preimage

A block of epoch E may carry it iff epoch in {E-1, E}, the key is pruned and
has no rejoin pending, and the signature is valid (checked last). Its share
work counts again from the first handoff to an epoch x with the rejoin at or
below opening(x), as new weight under the growth cap.

Finality certificate (section 6), wire encoding:

    u8(version = 1) || u32le(chain_id) || config_id[32]
    || u64le(source.height) || source.hash[32] || u64le(target.height) || target.hash[32]
    || varint(n) || n x ( u8(depth) || root[32] || signature )

varint is Bitcoin's, minimal; votes strictly ascending by key_id =
witness_id(depth, root). `signature` is KesSignature's wire encoding on the
node; in these vectors it is the test scheme below, encoded as
varint(len) || bytes. Verification, first failure wins: decode (version,
truncated, varint, trailing), chain_id, config_id against the trusted
configuration, link (both heights checkpoint slots and target = source +
checkpoint_interval), order (strictly ascending; equal ids are a duplicate),
membership, quorum, signatures.

With a registry proof instead of the entries (section 6, "entries + Merkle
paths"), the verifier holds a trusted config_id and receives

    u64le(epoch) || u128le(total) || u32le(n) || tree_root[32]
    || per vote, in the certificate's order: u128le(weight) || u32le(index) || u8(len) || len x sibling[32]

It recomputes config_id from them (reason "config_id" on mismatch) and each
voter's leaf through its path to tree_root (reason "path"; an index >= n or a
wrong path length is "path" too).

Test signature scheme (vectors only, NOT a signature scheme: anyone can
compute it): sig = sha256d("OBB-POCI-test/sig" || u8(depth) || root ||
u64le(kes_epoch) || msg), 32 bytes, kes_epoch = epoch(target.height).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import powit_reference as powit  # noqa: E402
import obb_growth_cap as gc  # noqa: E402

VECTOR_FILE = Path(__file__).with_name("poci_vectors.json")

CHAIN_OBB_MAINNET = 0x4F42_0001
CHAIN_OBB_REGTEST = 0x4F42_0002
U128_MAX = 2**128 - 1
ZERO32 = bytes(32)

DS_PARAMS = b"OBB-POCI-v1/params"
DS_CONFIG = b"OBB-POCI-v1/config"
DS_LEAF = b"OBB-POCI-v1/leaf"
DS_NODE = b"OBB-POCI-v1/node"
DS_ROOT = b"OBB-POCI-v1/root"
DS_ATTEST_V3 = b"OBB-POCI-v1/attest"
DS_REJOIN = b"OBB-POCI-v1/rejoin"
DS_TEST_SIG = b"OBB-POCI-test/sig"
CERT_VERSION = 1
# Absence pruning (section 4.1): a rule constant, like the domain tags (not
# part of params_digest, so the configuration ids of section 2 are unchanged).
PRUNE_AFTER_EPOCHS = 4

# ObenBlock PoWit parameters under PoCI. Mainnet: 6-hour epochs of 720 blocks
# (DESIGN-obenblock.md §6.2), slots every 60, the 112-epoch window, the
# 100-epoch ban and 4 bootstrap epochs (DESIGN-obenblock-poci.md §5, §9), the
# growth cap of §6.3. Regtest: the GnB testnet clock (20 / 5 / ttl 20, as
# core::powit::params_for maps ObenBlock regtest), the same window and ban.
PARAMS = {
    "mainnet": {"chain_id": CHAIN_OBB_MAINNET, "epoch_len": 720, "checkpoint_interval": 60,
                "window_epochs": 112, "vote_ttl": 720, "max_attestations_per_block": 32,
                "max_evidence_per_block": 4, "ban_epochs": 100, "bootstrap_epochs": 4,
                "launch_bury": 720, "growth_div": 64, "g_min_epoch_div": 8, "quorum_num": 2, "quorum_den": 3},
    "regtest": {"chain_id": CHAIN_OBB_REGTEST, "epoch_len": 20, "checkpoint_interval": 5,
                "window_epochs": 112, "vote_ttl": 20, "max_attestations_per_block": 32,
                "max_evidence_per_block": 4, "ban_epochs": 100, "bootstrap_epochs": 4,
                "launch_bury": 20, "growth_div": 64, "g_min_epoch_div": 8, "quorum_num": 2, "quorum_den": 3},
}
PARAM_U64_FIELDS = ("epoch_len", "checkpoint_interval", "window_epochs", "vote_ttl",
                    "max_attestations_per_block", "max_evidence_per_block", "ban_epochs",
                    "bootstrap_epochs", "launch_bury", "growth_div", "g_min_epoch_div")


# ── Primitives ───────────────────────────────────────────────────────────────

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def tagged(tag: bytes, msg: bytes) -> bytes:
    t = sha256(tag)
    return sha256(t + t + msg)


def u8(v: int) -> bytes:
    return v.to_bytes(1, "little")


def u32le(v: int) -> bytes:
    return v.to_bytes(4, "little")


def u64le(v: int) -> bytes:
    return v.to_bytes(8, "little")


def u128le(v: int) -> bytes:
    return v.to_bytes(16, "little")


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


class DecodeError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def int(self, n: int) -> int:
        return int.from_bytes(self.take(n), "little")

    def varint(self) -> int:
        first = self.int(1)
        if first < 0xFD:
            return first
        size, low = {0xFD: (2, 0xFD), 0xFE: (4, 0x1_0000), 0xFF: (8, 0x1_0000_0000)}[first]
        v = self.int(size)
        if v < low:
            raise DecodeError("varint")
        return v

    def done(self) -> bool:
        return self.pos == len(self.data)


def epoch_of(params: dict, height: int) -> int:
    return height // params["epoch_len"]          # PoWit from height 0 on ObenBlock (act = 0)


def is_slot(params: dict, height: int) -> bool:
    return height % params["checkpoint_interval"] == 0


def checkpoint_opening(params: dict, epoch: int) -> int:
    return epoch * params["epoch_len"]


def launch_height(params: dict) -> int:
    """Section 9: the first block at or above this height puts C_bootstrap in
    force (the checkpoint opening epoch bootstrap_epochs, buried by
    launch_bury blocks)."""
    return checkpoint_opening(params, params["bootstrap_epochs"]) + params["launch_bury"]


# ── Keys and the test signature scheme ───────────────────────────────────────

@dataclass(frozen=True)
class KesKey:
    depth: int
    root: bytes

    @property
    def key_id(self) -> bytes:
        return powit.witness_id(self.depth, self.root)


def test_sign(key: KesKey, kes_epoch: int, msg: bytes) -> bytes:
    return sha256d(DS_TEST_SIG + u8(key.depth) + key.root + u64le(kes_epoch) + msg)


def test_verify(key: KesKey, kes_epoch: int, msg: bytes, sig: bytes) -> bool:
    return sig == test_sign(key, kes_epoch, msg)


# ── Parameters and configuration ─────────────────────────────────────────────

def params_preimage(params: dict) -> bytes:
    out = DS_PARAMS + u32le(params["chain_id"])
    for f in PARAM_U64_FIELDS:
        out += u64le(params[f])
    return out + u32le(params["quorum_num"]) + u32le(params["quorum_den"])


def params_digest(params: dict) -> bytes:
    return sha256d(params_preimage(params))


def check_entries(entries: list[tuple[bytes, int]]) -> str | None:
    """None if entries are a valid registry, else the reason."""
    prev = None
    total = 0
    for k, w in entries:
        if len(k) != 20:
            return "key_len"
        if not 0 < w <= U128_MAX:
            return "weight"
        if prev is not None and k <= prev:
            return "duplicate" if k == prev else "order"
        prev = k
        total += w
    if total > U128_MAX:
        return "total_overflow"
    return None


def leaf_hash(key_id: bytes, weight: int) -> bytes:
    return tagged(DS_LEAF, key_id + u128le(weight))


def node_hash(left: bytes, right: bytes) -> bytes:
    return tagged(DS_NODE, left + right)


def _next_level(level: list[bytes]) -> list[bytes]:
    nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])
    return nxt


def tree_root(entries) -> bytes:
    if not entries:
        return ZERO32
    level = [leaf_hash(k, w) for k, w in entries]
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_root_from_tree(n: int, troot: bytes) -> bytes:
    return tagged(DS_ROOT, u32le(n) + troot)


def merkle_root(entries) -> bytes:
    return merkle_root_from_tree(len(entries), tree_root(entries))


def merkle_path(entries, index: int) -> list[bytes]:
    level = [leaf_hash(k, w) for k, w in entries]
    path, i = [], index
    while len(level) > 1:
        if not (i == len(level) - 1 and len(level) % 2):
            path.append(level[i ^ 1])
        level = _next_level(level)
        i //= 2
    return path


def path_root(leaf: bytes, index: int, n: int, path: list[bytes]) -> bytes | None:
    """The tree root that `path` proves for `leaf` at `index` of `n`, or None
    if the shape is wrong (index out of range, too few or too many siblings)."""
    if not 0 <= index < n:
        return None
    cur, i, width, used = leaf, index, n, 0
    while width > 1:
        if not (i == width - 1 and width % 2):
            if used == len(path):
                return None
            s = path[used]
            used += 1
            cur = node_hash(s, cur) if i % 2 else node_hash(cur, s)
        i //= 2
        width = (width + 1) // 2
    return cur if used == len(path) else None


def config_preimage_parts(chain: int, epoch: int, total: int, mroot: bytes, pdigest: bytes) -> bytes:
    return DS_CONFIG + u32le(chain) + u64le(epoch) + u128le(total) + mroot + pdigest


def config_id_from(chain: int, epoch: int, total: int, mroot: bytes, pdigest: bytes) -> bytes:
    return sha256d(config_preimage_parts(chain, epoch, total, mroot, pdigest))


@dataclass(frozen=True)
class Config:
    params_name: str
    epoch: int
    entries: tuple            # ((key_id, weight), ...) strictly ascending

    @property
    def params(self) -> dict:
        return PARAMS[self.params_name]

    @property
    def chain(self) -> int:
        return self.params["chain_id"]

    @cached_property
    def total(self) -> int:
        return sum(w for _, w in self.entries)

    @cached_property
    def _weights(self) -> dict:
        return dict(self.entries)

    def weight(self, key_id: bytes) -> int | None:
        return self._weights.get(key_id)

    def preimage(self) -> bytes:
        return config_preimage_parts(self.chain, self.epoch, self.total, merkle_root(self.entries),
                                     params_digest(self.params))

    @cached_property
    def id(self) -> bytes:
        return sha256d(self.preimage())


def make_config(params_name: str, epoch: int, weights: dict[bytes, int]) -> Config:
    """C_e from candidate weights (already excluding banned keys): keys of
    weight 0 are dropped, the rest sorted by key_id."""
    entries = tuple(sorted((k, w) for k, w in weights.items() if w > 0))
    reason = check_entries(list(entries))
    if reason:
        raise ValueError(reason)
    return Config(params_name, epoch, entries)


# ── Messages, votes and the quorum ───────────────────────────────────────────

def message_v3_preimage(chain: int, config_id: bytes, key: KesKey, src: tuple[int, bytes],
                        tgt: tuple[int, bytes]) -> bytes:
    assert len(config_id) == 32 and len(key.root) == 32 and len(src[1]) == 32 and len(tgt[1]) == 32
    return (u32le(len(DS_ATTEST_V3)) + DS_ATTEST_V3 + u32le(chain) + config_id + u8(key.depth) + key.root
            + u64le(src[0]) + src[1] + u64le(tgt[0]) + tgt[1])


def message_v3(chain: int, config_id: bytes, key: KesKey, src, tgt) -> bytes:
    return sha3(message_v3_preimage(chain, config_id, key, src, tgt))


def quorum(got: int, total: int) -> bool:
    """Strictly more than two thirds, exact integers. (GnB: 3 got >= 2 total.)"""
    return 3 * got > 2 * total


def quorum_u128(got: int, total: int) -> bool:
    """The same test the way u128 code can do it without overflow, given
    got <= total: 3g > 2t <=> g > 2(t - g); 2(t - g) overflowing u128 means
    t - g > 2^127 > g."""
    assert 0 <= got <= total <= U128_MAX
    d = total - got
    if d > U128_MAX // 2:
        return False
    return got > 2 * d


@dataclass(frozen=True)
class Vote:
    """One v3 attestation."""
    config_id: bytes
    key: KesKey
    source: tuple
    target: tuple
    sig: bytes

    def message(self, chain: int) -> bytes:
        return message_v3(chain, self.config_id, self.key, self.source, self.target)

    def verify(self, chain: int, params: dict) -> bool:
        return (self.target[0] > self.source[0]
                and test_verify(self.key, epoch_of(params, self.target[0]), self.message(chain), self.sig))

    def to_json(self) -> dict:
        return {"config_id": self.config_id.hex(), "depth": self.key.depth, "root": self.key.root.hex(),
                "key_id": self.key.key_id.hex(),
                "source": {"height": self.source[0], "hash": self.source[1].hex()},
                "target": {"height": self.target[0], "hash": self.target[1].hex()},
                "sig": self.sig.hex()}


def sign_vote(chain: int, params: dict, config_id: bytes, key: KesKey, src, tgt,
              kes_epoch: int | None = None) -> Vote:
    e = epoch_of(params, tgt[0]) if kes_epoch is None else kes_epoch
    return Vote(config_id, key, src, tgt, test_sign(key, e, message_v3(chain, config_id, key, src, tgt)))


def counted_keys(config: Config, votes, src, tgt) -> list:
    """The distinct keys of `config` with a valid vote for src->tgt naming
    config.id, in vote order (a vote naming another configuration counts
    nowhere)."""
    seen: set[bytes] = set()
    out = []
    for v in votes:
        if v.config_id != config.id or v.source != src or v.target != tgt:
            continue
        k = v.key.key_id
        w = config.weight(k)
        if w is None or k in seen or not v.verify(config.chain, config.params):
            continue
        seen.add(k)
        out.append(k)
    return out


def counted_weight(config: Config, votes, src, tgt) -> int:
    """Weight of the distinct keys of `config` with a valid vote for src->tgt
    naming config.id (a vote naming another configuration counts nowhere)."""
    return sum(config.weight(k) for k in counted_keys(config, votes, src, tgt))


# ── Rejoin (section 4.1) ─────────────────────────────────────────────────────

def rejoin_preimage(chain: int, key: KesKey, epoch: int) -> bytes:
    assert len(key.root) == 32
    return u32le(len(DS_REJOIN)) + DS_REJOIN + u32le(chain) + u8(key.depth) + key.root + u64le(epoch)


def rejoin_message(chain: int, key: KesKey, epoch: int) -> bytes:
    return sha3(rejoin_preimage(chain, key, epoch))


@dataclass(frozen=True)
class Rejoin:
    """A pruned key's rejoin message, signed by the KES leaf of `epoch`."""
    key: KesKey
    epoch: int
    sig: bytes

    def verify(self, chain: int) -> bool:
        return test_verify(self.key, self.epoch, rejoin_message(chain, self.key, self.epoch), self.sig)

    def to_json(self) -> dict:
        return {"depth": self.key.depth, "root": self.key.root.hex(), "key_id": self.key.key_id.hex(),
                "epoch": self.epoch, "sig": self.sig.hex()}


def sign_rejoin(chain: int, key: KesKey, epoch: int) -> Rejoin:
    return Rejoin(key, epoch, test_sign(key, epoch, rejoin_message(chain, key, epoch)))


# ── Proof of Corruption ──────────────────────────────────────────────────────

def conflict(a: Vote, b: Vote) -> str | None:
    if a.target[0] == b.target[0] and a.target != b.target:
        return "double"
    if (a.source[0] < b.source[0] and b.target[0] < a.target[0]) or \
       (b.source[0] < a.source[0] and a.target[0] < b.target[0]):
        return "surround"
    return None


def check_evidence(a: Vote, b: Vote, configs: dict[bytes, Config]) -> tuple[str | None, str]:
    """Context-free part: (kind, "ok") or (None, reason). `configs` are the
    configurations the chain has had in force (id -> Config)."""
    if a.key != b.key:
        return None, "different_keys"
    if a.config_id != b.config_id:
        return None, "different_configs"
    if a == b:
        return None, "identical"
    cfg = configs.get(a.config_id)
    if cfg is None:
        return None, "unknown_config"
    if cfg.weight(a.key.key_id) is None:
        return None, "non_member"
    kind = conflict(a, b)
    if kind is None:
        return None, "no_conflict"
    if not a.verify(cfg.chain, cfg.params) or not b.verify(cfg.chain, cfg.params):
        return None, "signature"
    return kind, "ok"


# ── The chain: FFG, handoff and bans ─────────────────────────────────────────

@dataclass
class Ban:
    config_id: bytes          # the configuration the evidence named
    height: int               # the block that holds the evidence
    start: int | None = None  # ban_start, set at the first handoff after that block is final

    def end(self, ban_epochs: int) -> int | None:
        return None if self.start is None else self.start + ban_epochs


@dataclass
class Prune:
    """Absence pruning (section 4.1): the key is excluded from epoch `start`
    on; `until` is set (transiently, while the handoff that ends it computes
    C_x) when a finalized rejoin ends it."""
    start: int
    until: int | None = None

    def covers(self, epoch: int) -> bool:
        return self.start <= epoch and (self.until is None or epoch < self.until)


@dataclass
class PociChain:
    """Linear model of one honest node's PoCI state. `provider(epoch,
    finalized)` returns the candidate weights {key_id: weight} of C_epoch
    computed from the finalized history up to `finalized` (the window and
    growth cap of DESIGN-obenblock.md §6.3, package O10), including keys that
    are excluded at that epoch (`excluded_at` says which, for every epoch the
    handoff covers); bans and pruning are applied here."""
    params_name: str
    provider: object
    checkpoint_hash: object = None
    config: Config = None
    justified: tuple = None
    finalized: tuple = None
    configs: dict = field(default_factory=dict)
    history: list = field(default_factory=list)      # configs in order of entry into force
    bans: dict = field(default_factory=dict)         # key_id -> [Ban] (latest last)
    pruned: dict = field(default_factory=dict)       # key_id -> Prune
    rejoins: dict = field(default_factory=dict)      # key_id -> height of the block holding its rejoin
    seen: dict = field(default_factory=dict)         # key_id -> [heights where a vote of it was included]
    log: list = field(default_factory=list)

    @property
    def params(self) -> dict:
        return PARAMS[self.params_name]

    def cp(self, height: int) -> tuple:
        return (height, self.checkpoint_hash(height))

    def launch(self) -> None:
        """Section 9: C_bootstrap from the chain up to the checkpoint opening
        epoch `bootstrap_epochs`, which is justified and finalized: what the
        first block at or above `launch_height` does (the checkpoint is then
        buried by `launch_bury` blocks)."""
        e = self.params["bootstrap_epochs"]
        self.justified = self.finalized = self.cp(checkpoint_opening(self.params, e))
        self._enter(e)

    def banned_at(self, key_id: bytes, epoch: int) -> bool:
        n = self.params["ban_epochs"]
        return any(b.start is not None and b.start <= epoch < b.start + n for b in self.bans.get(key_id, []))

    def pruned_at(self, key_id: bytes, epoch: int) -> bool:
        p = self.pruned.get(key_id)
        return p is not None and p.covers(epoch)

    def excluded_at(self, key_id: bytes, epoch: int) -> bool:
        """Banned or pruned at `epoch` (what a provider leaves out of the
        epochs a handoff covers)."""
        return self.banned_at(key_id, epoch) or self.pruned_at(key_id, epoch)

    def _enter(self, epoch: int) -> None:
        candidates = self.provider(epoch, self.finalized)
        # A pruned key without candidate weight (no share work left) is forgotten.
        for k in [k for k, p in self.pruned.items() if p.until is None and candidates.get(k, 0) == 0]:
            del self.pruned[k]
            self.rejoins.pop(k, None)
        weights = {k: w for k, w in candidates.items() if not self.excluded_at(k, epoch)}
        if not weights and self.config is not None:
            # Never an empty configuration at a handoff: C_e's entries carry
            # forward unchanged and this handoff's prunings are void.
            for k in [k for k, p in self.pruned.items() if p.start == epoch and p.until is None]:
                del self.pruned[k]
            weights = dict(self.config.entries)
        self.config = make_config(self.params_name, epoch, weights)
        self.configs[self.config.id] = self.config
        self.history.append(self.config)
        self.pruned = {k: p for k, p in self.pruned.items() if p.until is None}
        self.seen = {k: hs for k, hs in self.seen.items() if self.config.weight(k) is not None}

    def include(self, height: int, key_ids) -> list:
        """A block at ledger height `height` included votes of `key_ids`
        under the configuration in force: only its entries can have one."""
        out = []
        for k in key_ids:
            if self.config.weight(k) is not None:
                self.seen.setdefault(k, []).append(height)
                out.append(k)
        return out

    def votes(self, target: tuple, votes, included_at: int | None = None) -> dict:
        """Count votes for justified -> target under the configuration in
        force. The counted ones are included at `included_at` (default
        target height + 1: the first block that may carry them)."""
        src = self.justified
        keys = counted_keys(self.config, votes, src, target)
        got = sum(self.config.weight(k) for k in keys)
        self.include(target[0] + 1 if included_at is None else included_at, keys)
        q = quorum(got, self.config.total)
        out = {"weight": got, "total": self.config.total, "quorum": q, "justified": False,
               "finalized": False, "handoff": False}
        if q and target[0] > src[0] and is_slot(self.params, target[0]):
            self.justified = target
            out["justified"] = True
            if target[0] == src[0] + self.params["checkpoint_interval"]:
                out["finalized"] = True
                out["handoff"] = self._finalize(src)
        return out

    def present(self, key_id: bytes, x: int) -> bool:
        """A vote of the key included in the blocks of epochs x - 4 .. x - 1:
        at a ledger height h with opening(x - PRUNE_AFTER) < h <= opening(x)."""
        lo = checkpoint_opening(self.params, x - PRUNE_AFTER_EPOCHS)
        hi = checkpoint_opening(self.params, x)
        return any(lo < h <= hi for h in self.seen.get(key_id, []))

    def present_weight(self, x: int) -> int:
        """The weight of C_e (in force) whose keys are present for x."""
        return sum(w for k, w in self.config.entries if self.present(k, x))

    def prune_eligible(self, key_id: bytes, x: int) -> bool:
        """k has been an entry of every configuration in force since epoch
        x - PRUNE_AFTER or earlier."""
        for c in reversed(self.history):
            if c.weight(key_id) is None:
                return False
            if c.epoch <= x - PRUNE_AFTER_EPOCHS:
                return True
        return False

    def _finalize(self, f: tuple) -> bool:
        """Finalizing `f` under C_e hands off iff x = epoch(f) > e, one epoch
        boundary at a time (section 4): C_{e+1}, C_{e+2}, ..., C_x, each from
        the configuration before it and the history up to the opening of its
        own epoch only, so C_x is a function of the history whatever
        checkpoints were finalized on the way."""
        self.finalized = f
        x = epoch_of(self.params, f[0])
        if x <= self.config.epoch:
            return False
        for y in range(self.config.epoch + 1, x + 1):
            self._step(y)
        return True

    def _step(self, y: int) -> None:
        """One handoff step C_{y-1} -> C_y (section 4.1, "Order at the
        handoff"), from the history up to cut = opening(y)."""
        assert y == self.config.epoch + 1
        cut = checkpoint_opening(self.params, y)
        for bans in self.bans.values():
            for b in bans:
                if b.start is None and b.height <= cut:
                    b.start = y
        for k in [k for k, h in self.rejoins.items() if h <= cut]:
            del self.rejoins[k]
            self.pruned[k].until = y
        if quorum(self.present_weight(y), self.config.total):
            for k, _ in self.config.entries:
                if k not in self.pruned and self.prune_eligible(k, y) and not self.present(k, y):
                    self.pruned[k] = Prune(y)
        self._enter(y)

    def evidence(self, height: int, a: Vote, b: Vote) -> str:
        """A block at `height` (above the finalized checkpoint) carries the
        evidence; returns "ok" or the reason it is invalid."""
        if height <= self.finalized[0]:
            return "below_finality"
        kind, reason = check_evidence(a, b, self.configs)
        if kind is None:
            return reason
        k = a.key.key_id
        n = self.params["ban_epochs"]
        for ban in self.bans.get(k, []):
            if ban.config_id == a.config_id:
                return "already_banned_for_config"
            if ban.start is None or self.config.epoch < ban.start + n:
                return "ban_pending_or_active"
        self.bans.setdefault(k, []).append(Ban(a.config_id, height))
        return "ok"

    def rejoin(self, height: int, block_epoch: int, rj: Rejoin) -> str:
        """A block at ledger height `height` of PoWit epoch `block_epoch`
        carries the rejoin; returns "ok" or the reason it is invalid (first
        failure wins, the signature last)."""
        if height <= self.finalized[0]:
            return "below_finality"
        if not (rj.epoch <= block_epoch <= rj.epoch + 1):
            return "epoch"
        k = rj.key.key_id
        p = self.pruned.get(k)
        if p is None or p.until is not None:
            return "not_pruned"
        if k in self.rejoins:
            return "pending"
        if not rj.verify(self.params["chain_id"]):
            return "signature"
        self.rejoins[k] = height
        return "ok"


# ── Finality certificate ─────────────────────────────────────────────────────

@dataclass
class Certificate:
    chain: int
    config_id: bytes
    source: tuple
    target: tuple
    votes: list               # [(KesKey, sig bytes)]
    version: int = CERT_VERSION

    def encode(self) -> bytes:
        out = (u8(self.version) + u32le(self.chain) + self.config_id
               + u64le(self.source[0]) + self.source[1] + u64le(self.target[0]) + self.target[1]
               + varint(len(self.votes)))
        for key, sig in self.votes:
            out += u8(key.depth) + key.root + varint(len(sig)) + sig
        return out


def decode_certificate(data: bytes) -> Certificate:
    r = Reader(data)
    version = r.int(1)
    if version != CERT_VERSION:
        raise DecodeError("version")
    chain = r.int(4)
    cid = r.take(32)
    src = (r.int(8), r.take(32))
    tgt = (r.int(8), r.take(32))
    n = r.varint()
    votes = []
    for _ in range(n):
        key = KesKey(r.int(1), r.take(32))
        votes.append((key, r.take(r.varint())))
    if not r.done():
        raise DecodeError("trailing")
    return Certificate(chain, cid, src, tgt, votes, version)


def make_certificate(config: Config, src, tgt, keys, kes_epoch: int | None = None) -> Certificate:
    votes = []
    for key in sorted(keys, key=lambda k: k.key_id):
        v = sign_vote(config.chain, config.params, config.id, key, src, tgt, kes_epoch)
        votes.append((key, v.sig))
    return Certificate(config.chain, config.id, src, tgt, votes)


def _check_shape(cert: Certificate, chain: int, params: dict, trusted_id: bytes) -> str | None:
    if cert.chain != chain:
        return "chain_id"
    if cert.config_id != trusted_id:
        return "config_id"
    s, t = cert.source[0], cert.target[0]
    if not (is_slot(params, s) and is_slot(params, t) and t == s + params["checkpoint_interval"]):
        return "link"
    prev = None
    for key, _ in cert.votes:
        k = key.key_id
        if prev is not None and k <= prev:
            return "duplicate" if k == prev else "order"
        prev = k
    return None


def _check_signatures(cert: Certificate, params: dict) -> str | None:
    for key, sig in cert.votes:
        v = Vote(cert.config_id, key, cert.source, cert.target, sig)
        if not v.verify(cert.chain, params):
            return "signature"
    return None


def verify_certificate(data: bytes, config: Config) -> str:
    """Verify against a trusted configuration (its entries); "ok" or the reason."""
    try:
        cert = decode_certificate(data)
    except DecodeError as e:
        return e.reason
    reason = _check_shape(cert, config.chain, config.params, config.id)
    if reason:
        return reason
    got = 0
    for key, _ in cert.votes:
        w = config.weight(key.key_id)
        if w is None:
            return "non_member"
        got += w
    if not quorum(got, config.total):
        return "quorum"
    return _check_signatures(cert, config.params) or "ok"


@dataclass
class RegistryProof:
    epoch: int
    total: int
    n: int
    tree_root: bytes
    members: list             # per vote: (weight, index, [sibling])

    def encode(self) -> bytes:
        out = u64le(self.epoch) + u128le(self.total) + u32le(self.n) + self.tree_root
        for w, i, path in self.members:
            out += u128le(w) + u32le(i) + u8(len(path)) + b"".join(path)
        return out


def decode_registry_proof(data: bytes, n_votes: int) -> RegistryProof:
    r = Reader(data)
    epoch, total, n, troot = r.int(8), r.int(16), r.int(4), r.take(32)
    members = []
    for _ in range(n_votes):
        w, i, m = r.int(16), r.int(4), r.int(1)
        members.append((w, i, [r.take(32) for _ in range(m)]))
    if not r.done():
        raise DecodeError("trailing")
    return RegistryProof(epoch, total, n, troot, members)


def make_registry_proof(config: Config, cert: Certificate) -> RegistryProof:
    idx = {k: i for i, (k, _) in enumerate(config.entries)}
    members = []
    for key, _ in cert.votes:
        i = idx[key.key_id]
        members.append((config.entries[i][1], i, merkle_path(list(config.entries), i)))
    return RegistryProof(config.epoch, config.total, len(config.entries), tree_root(config.entries), members)


def verify_certificate_with_proof(data: bytes, proof_bytes: bytes, params_name: str, trusted_id: bytes) -> str:
    """Verify against a trusted config_id and a registry proof; "ok" or the reason."""
    params = PARAMS[params_name]
    try:
        cert = decode_certificate(data)
        proof = decode_registry_proof(proof_bytes, len(cert.votes))
    except DecodeError as e:
        return e.reason
    reason = _check_shape(cert, params["chain_id"], params, trusted_id)
    if reason:
        return reason
    cid = config_id_from(params["chain_id"], proof.epoch, proof.total,
                         merkle_root_from_tree(proof.n, proof.tree_root), params_digest(params))
    if cid != trusted_id:
        return "config_id"
    got = 0
    for (key, _), (w, i, path) in zip(cert.votes, proof.members):
        if not 0 < w <= U128_MAX or path_root(leaf_hash(key.key_id, w), i, proof.n, path) != proof.tree_root:
            return "path"
        got += w
    if got > proof.total:
        return "path"           # impossible for a registry whose total is the sum of its leaves
    if not quorum(got, proof.total):
        return "quorum"
    return _check_signatures(cert, params) or "ok"


# ── Vectors ──────────────────────────────────────────────────────────────────

def vkey(label: str, i: int) -> KesKey:
    return KesKey(12, sha256d(b"poci-vector-key" + label.encode() + u32le(i)))


def cp_hash(height: int, branch: int = 0) -> bytes:
    return sha256d(b"poci-vector-cp" + u64le(height) + u32le(branch))


def cpj(c: tuple) -> dict:
    return {"height": c[0], "hash": c[1].hex()}


def entries_json(entries) -> list:
    return [[k.hex(), str(w)] for k, w in entries]


def config_json(c: Config) -> dict:
    return {"params": c.params_name, "epoch": c.epoch, "entries": entries_json(c.entries),
            "total": str(c.total), "tree_root": tree_root(c.entries).hex(),
            "merkle_root": merkle_root(c.entries).hex(), "preimage": c.preimage().hex(), "config_id": c.id.hex()}


def gen_params() -> list:
    return [{"params": name, "values": PARAMS[name], "preimage": params_preimage(PARAMS[name]).hex(),
             "params_digest": params_digest(PARAMS[name]).hex()} for name in PARAMS]


def gen_configs() -> list:
    out = []
    ks = [vkey("cfg", i).key_id for i in range(7)]
    cases = [
        ("empty", "mainnet", 4, {}),
        ("one", "mainnet", 4, {ks[0]: 1}),
        ("two", "mainnet", 5, {ks[0]: 1, ks[1]: 2}),
        ("three_odd_carry", "mainnet", 6, {ks[0]: 10, ks[1]: 20, ks[2]: 30}),
        ("seven", "mainnet", 4, {k: 1_000 + i for i, k in enumerate(ks)}),
        ("seven_regtest", "regtest", 4, {k: 1_000 + i for i, k in enumerate(ks)}),
        ("seven_next_epoch", "mainnet", 5, {k: 1_000 + i for i, k in enumerate(ks)}),
        ("seven_one_weight_changed", "mainnet", 4, {**{k: 1_000 + i for i, k in enumerate(ks)}, ks[3]: 1_004}),
        ("u128_extremes", "mainnet", 2**64 - 1, {ks[0]: U128_MAX - 1, ks[1]: 1}),
    ]
    for name, net, e, weights in cases:
        c = make_config(net, e, weights)
        d = config_json(c)
        d["name"] = name
        d["paths"] = [{"index": i, "leaf": leaf_hash(k, w).hex(),
                       "path": [s.hex() for s in merkle_path(list(c.entries), i)]}
                      for i, (k, w) in enumerate(c.entries)]
        out.append(d)
    invalid = [
        ("unsorted", [(ks[1], 1), (ks[0], 1)]),
        ("duplicate", [(ks[0], 1), (ks[0], 2)]),
        ("zero_weight", [(ks[0], 0)]),
        ("total_overflow", sorted([(ks[0], U128_MAX), (ks[1], 1)])),
    ]
    for name, ents in invalid:
        out.append({"name": name, "entries": entries_json(ents), "invalid": check_entries(ents)})
    return out


def gen_messages() -> list:
    out = []
    src = (720 * 4, cp_hash(720 * 4))
    tgt = (720 * 4 + 60, cp_hash(720 * 4 + 60))
    cid = make_config("mainnet", 4, {vkey("msg", 0).key_id: 5}).id
    for chain in (CHAIN_OBB_MAINNET, CHAIN_OBB_REGTEST):
        for key in (vkey("msg", 0), KesKey(1, vkey("msg", 1).root), KesKey(16, ZERO32)):
            for c in (cid, ZERO32):
                pre = message_v3_preimage(chain, c, key, src, tgt)
                out.append({"chain_id": chain, "config_id": c.hex(), "depth": key.depth, "root": key.root.hex(),
                            "key_id": key.key_id.hex(), "source": cpj(src), "target": cpj(tgt),
                            "preimage": pre.hex(), "msg_v3": sha3(pre).hex(),
                            "test_sig": test_sign(key, epoch_of(PARAMS["mainnet"], tgt[0]), sha3(pre)).hex()})
    return out


def gen_rejoin_messages() -> list:
    out = []
    for chain in (CHAIN_OBB_MAINNET, CHAIN_OBB_REGTEST):
        for key in (vkey("rejoin", 0), KesKey(16, ZERO32)):
            for e in (0, 9, 2**64 - 1):
                pre = rejoin_preimage(chain, key, e)
                out.append({"chain_id": chain, "depth": key.depth, "root": key.root.hex(), "key_id": key.key_id.hex(),
                            "epoch": e, "preimage": pre.hex(), "rejoin_msg": sha3(pre).hex(),
                            "test_sig": test_sign(key, e, sha3(pre)).hex()})
    return out


def gen_quorum() -> list:
    pairs = [(0, 0), (0, 1), (1, 1), (2, 3), (3, 3), (1, 2), (2, 2), (200, 300), (201, 300),
             (6_666, 10_000), (6_667, 10_000), (6_666_666, 9_999_999), (6_666_667, 9_999_999),
             (U128_MAX // 3 * 2, U128_MAX // 3 * 3), (U128_MAX // 3 * 2 + 1, U128_MAX // 3 * 3),
             (U128_MAX - (U128_MAX // 3), U128_MAX), (U128_MAX - (U128_MAX // 3) - 1, U128_MAX),
             (U128_MAX // 2, U128_MAX), (U128_MAX, U128_MAX), (0, U128_MAX)]
    return [{"got": str(g), "total": str(t), "quorum": quorum(g, t), "gnb_two_thirds": powit.two_thirds(g, t)}
            for g, t in pairs]


def _std_chain(name: str, weights_by_epoch, keys) -> PociChain:
    calls = {}

    def provider(e, fin):
        w = weights_by_epoch(e)
        calls[e] = {"finalized": cpj(fin), "weights": entries_json(sorted(w.items()))}
        return w
    ch = PociChain("mainnet", provider, cp_hash)
    ch.calls = calls
    ch.name = name
    ch.launch()
    return ch


class GrowthCapProvider:
    """The consensus provider of ObenBlock (DESIGN-obenblock.md §6.3,
    `obb_growth_cap.advance`) over a fixed share-work history: at each launch
    or handoff to x it runs the cap from the ledger's epoch to x, the keys
    excluded at each epoch y it steps being the chain's (`excluded_at(k, y)`:
    banned or pruned; this handoff's bans and prunings are already recorded).
    It reads share work and first-block bits of epochs <= x - 2 only, below
    opening(x). Returns every key with credit, excluded ones included."""

    def __init__(self, history: dict, params: dict):
        self.history, self.params = history, params
        self.ledger = gc.empty_ledger()
        self.chain = None

    def __call__(self, e: int, fin=None) -> dict:
        keys = {k for m in self.history["share_work"].values() for k in m}
        excl = []
        if self.chain is not None:
            for y in range(self.ledger["epoch"], e + 1):
                excl += [(k, y, y + 1) for k in sorted(keys) if self.chain.excluded_at(k, y)]
        self.ledger, _ = gc.advance(self.ledger, self.history, e, excl, self.params)
        return gc.ledger_weights(self.ledger)


def _vote_set(ch: PociChain, keys, target, config: Config | None = None, source=None, bad_sig=()):
    cfg = config or ch.config
    src = source or ch.justified
    out = []
    for k in keys:
        v = sign_vote(cfg.chain, cfg.params, cfg.id, k, src, target)
        if k in bad_sig:
            v = Vote(v.config_id, v.key, v.source, v.target, bytes(32))
        out.append(v)
    return out


def _state(ch: PociChain) -> dict:
    return {"config_epoch": ch.config.epoch, "config_id": ch.config.id.hex(), "total": str(ch.config.total),
            "justified": cpj(ch.justified), "finalized": cpj(ch.finalized)}


def gen_sequences() -> list:
    """Handoff and ban sequences on mainnet parameters (slot 60, epoch 720).
    Each step names the voters (indices into `keys`), the configuration they
    name ("current" or "previous"), and the expected outcome and state."""
    P = PARAMS["mainnet"]
    I, L = P["checkpoint_interval"], P["epoch_len"]
    keys = [vkey("seq", i) for i in range(10)]
    kid = [k.key_id for k in keys]
    seqs = []

    def run(name, weights_by_epoch, steps):
        ch = _std_chain(name, weights_by_epoch, keys)
        if isinstance(weights_by_epoch, GrowthCapProvider):
            weights_by_epoch.chain = ch
        out_steps = []
        initial = _state(ch)
        for st in steps:
            rec = dict(st)
            if st["op"] == "votes":
                tgt = ch.cp(st["target"])
                cfg = ch.history[-2] if st.get("config") == "previous" else ch.config
                src = ch.cp(st["source"]) if "source" in st else None
                bad = [keys[i] for i in st.get("bad_sig", [])]
                vs = _vote_set(ch, [keys[i] for i in st["voters"]], tgt, cfg, src, bad)
                rec["named_config_id"] = cfg.id.hex()
                rec["result"] = ch.votes(tgt, vs, st.get("included_at"))
                rec["result"]["weight"] = str(rec["result"]["weight"])
                rec["result"]["total"] = str(rec["result"]["total"])
            elif st["op"] == "include":
                rec["result"] = [k.hex() for k in ch.include(st["height"], [kid[i] for i in st["voters"]])]
            elif st["op"] == "rejoin":
                k = keys[st["key"]]
                rj = sign_rejoin(P["chain_id"] if not st.get("other_chain") else CHAIN_OBB_REGTEST, k, st["epoch"])
                if st.get("bad_sig"):
                    rj = Rejoin(rj.key, rj.epoch, bytes(32))
                rec["rejoin"] = rj.to_json()
                rec["result"] = ch.rejoin(st["height"], st["block_epoch"], rj)
            elif st["op"] == "evidence":
                a, b = st["links"]
                cfg = ch.history[-2] if st.get("config") == "previous" else ch.config
                k = keys[st["key"]]
                va = sign_vote(cfg.chain, P, cfg.id, k, ch.cp(a[0]), ch.cp(a[1]) if len(a) == 2 else (a[1], cp_hash(a[1], a[2])))
                vb = sign_vote(cfg.chain, P, cfg.id, k, ch.cp(b[0]), ch.cp(b[1]) if len(b) == 2 else (b[1], cp_hash(b[1], b[2])))
                rec["a"], rec["b"] = va.to_json(), vb.to_json()
                rec["result"] = ch.evidence(st["height"], va, vb)
            rec["state"] = _state(ch)
            rec["bans"] = {k.hex(): [{"config_id": b.config_id.hex(), "height": b.height, "start": b.start,
                                      "end": b.end(P["ban_epochs"])} for b in bl] for k, bl in sorted(ch.bans.items())}
            rec["pruned"] = {k.hex(): p.start for k, p in sorted(ch.pruned.items())}
            rec["rejoins"] = {k.hex(): h for k, h in sorted(ch.rejoins.items())}
            out_steps.append(rec)
        seq = {"name": name, "params": "mainnet", "keys": [{"depth": k.depth, "root": k.root.hex(),
                                                            "key_id": k.key_id.hex()} for k in keys],
               "initial": initial, "provider_calls": {str(e): v for e, v in sorted(ch.calls.items())},
               "configs": [config_json(c) for c in ch.history], "steps": out_steps}
        if isinstance(weights_by_epoch, GrowthCapProvider):
            h = weights_by_epoch.history
            seq["growth_cap"] = {
                "params": "obenblock",
                "share_work": {str(n): {k.hex(): str(w) for k, w in sorted(m.items())}
                               for n, m in sorted(h["share_work"].items())},
                "first_block_bits": {str(n): b for n, b in sorted(h["first_block_bits"].items())}}
        seqs.append(seq)
        return ch

    flat = lambda e: {kid[i]: 100 for i in range(6)}      # noqa: E731  total 600: quorum needs 401 (5 keys)
    b4 = 4 * L
    # 1. Steady progress inside epoch 4, then the handoff at the opening of epoch 5.
    steps = []
    h = b4
    while h < 5 * L:
        steps.append({"op": "votes", "target": h + I, "voters": [0, 1, 2, 3, 4]})
        h += I
    steps.append({"op": "votes", "target": 5 * L + I, "voters": [0, 1, 2, 3, 4]})
    run("handoff_at_epoch_opening", lambda e: {**flat(e), kid[5]: 100 + e}, steps)

    # 2. Exactly two thirds never justifies; just above does.
    run("exactly_two_thirds_stalls", lambda e: {kid[0]: 200, kid[1]: 200, kid[2]: 200}, [
        {"op": "votes", "target": b4 + I, "voters": [0, 1]},
        {"op": "votes", "target": b4 + I, "voters": [0, 1, 2]},
    ])
    run("just_above_two_thirds", lambda e: {kid[0]: 201, kid[1]: 200, kid[2]: 200}, [
        {"op": "votes", "target": b4 + I, "voters": [1, 2]},
        {"op": "votes", "target": b4 + I, "voters": [0, 1]},
    ])

    # 3. Stall: no quorum for epochs; C stays, its total never changes; votes
    #    naming another configuration or with bad signatures count nowhere.
    run("stall_keeps_the_configuration", flat, [
        {"op": "votes", "target": b4 + I, "voters": [0, 1, 2, 3]},
        {"op": "votes", "target": 6 * L, "voters": [0, 1, 2, 3]},
        {"op": "votes", "target": 9 * L, "voters": [0, 1, 2, 3, 4], "bad_sig": [4]},
        {"op": "votes", "target": 9 * L, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 9 * L + I, "voters": [0, 1, 2, 3, 4]},
    ])

    # 4. Skipped epochs: a jump from epoch 4 to epoch 7 (not its opening slot).
    run("handoff_skips_epochs", lambda e: {**flat(e), kid[5]: 10 * e}, [
        {"op": "votes", "target": 7 * L + 3 * I, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 7 * L + 4 * I, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 7 * L + 5 * I, "voters": [0, 1, 2, 3, 4, 5]},
        {"op": "votes", "target": 7 * L + 6 * I, "voters": [0, 1, 2, 3, 4], "config": "previous"},
    ])

    # 5. Ban: evidence included at a height, finalized, then the next handoff
    #    sets ban_start; no retroactive change of the configuration in force.
    steps = [
        {"op": "evidence", "height": b4 + 10, "key": 5, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
        {"op": "votes", "target": b4 + I, "voters": [0, 1, 2, 3, 5]},
        {"op": "votes", "target": b4 + 2 * I, "voters": [0, 1, 2, 3, 5]},
        {"op": "evidence", "height": b4 + 2 * I + 1, "key": 5, "links": [[b4, b4 + I], [b4, b4 + I, 2]]},
        {"op": "evidence", "height": b4 + 2 * I + 1, "key": 4, "links": [[b4, b4 + 4 * I], [b4 + I, b4 + 3 * I]]},
        {"op": "votes", "target": 5 * L, "voters": [0, 1, 2, 3, 4]},
        # included above the checkpoint the next handoff finalizes: stays pending
        {"op": "evidence", "height": 5 * L + 30, "key": 3, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
        {"op": "votes", "target": 5 * L + I, "voters": [0, 1, 2, 3, 4]},
        {"op": "evidence", "height": 5 * L + I + 1, "key": 3, "links": [[5 * L, 5 * L + 2 * I], [5 * L, 5 * L + 2 * I, 1]]},
        {"op": "votes", "target": 5 * L + 2 * I, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 6 * L, "voters": [0, 1, 2, 3]},
        {"op": "votes", "target": 6 * L + I, "voters": [0, 1, 2, 3]},
        {"op": "votes", "target": 6 * L + 2 * I, "voters": [0, 1, 2]},
    ]
    run("ban_start_and_window", flat, steps)

    # 6. Ban window end: the key returns at ban_start + 100 (skipped handoffs).
    steps = [
        {"op": "evidence", "height": b4 + 1, "key": 5, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
        {"op": "votes", "target": b4 + I, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 5 * L, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 5 * L + I, "voters": [0, 1, 2, 3, 4]},
        # The voters kept voting during the jump (section 4.1: no pruning).
        {"op": "include", "height": 104 * L - 30, "voters": [0, 1, 2, 3, 4, 5]},
        {"op": "votes", "target": 104 * L, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 104 * L + I, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 105 * L, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 105 * L + I, "voters": [0, 1, 2, 3, 4]},
    ]
    run("ban_ends_after_100_epochs", flat, steps)

    # 7. Evidence that is not corruption, and evidence against keys outside C.
    steps = [
        {"op": "evidence", "height": b4 + 1, "key": 0, "links": [[b4, b4 + I], [b4, b4 + I]]},
        {"op": "evidence", "height": b4 + 1, "key": 0, "links": [[b4, b4 + I], [b4 + I, b4 + 2 * I]]},
        {"op": "evidence", "height": b4 + 1, "key": 0, "links": [[b4, b4 + 2 * I], [b4, b4 + 3 * I]]},
        {"op": "evidence", "height": b4 + 1, "key": 0, "links": [[b4, b4 + 3 * I], [b4 + I, b4 + 3 * I]]},
        {"op": "evidence", "height": b4 + 1, "key": 5, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
        {"op": "evidence", "height": b4, "key": 0, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
        {"op": "evidence", "height": b4 + 1, "key": 0, "links": [[b4, b4 + 3 * I], [b4 + I, b4 + 2 * I]]},
        {"op": "evidence", "height": b4 + 2, "key": 0, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
    ]
    run("evidence_rejections", lambda e: {kid[i]: 100 for i in range(5)}, steps)

    # 8. Absence pruning (section 4.1) and rejoin. Keys 0..4 vote at every
    #    handoff; key 5 votes once in epoch 5 and fades out; key 6 never votes.
    #    Key 5 has no share work in epoch 12's window (forgotten) and is back
    #    as a new key from 13.
    def fading(e):
        w = {kid[i]: 100 for i in range(5)}
        w[kid[6]] = 10
        if e != 12:
            w[kid[5]] = 100
        return w

    def handoff(x, voters, last=None):
        return [{"op": "votes", "target": x * L, "voters": voters},
                {"op": "votes", "target": x * L + I, "voters": last or voters}]
    core = [0, 1, 2, 3, 4]
    steps = [{"op": "votes", "target": 5 * L, "voters": core + [5]},
             {"op": "votes", "target": 5 * L + I, "voters": core}]
    for x in (6, 7):
        steps += handoff(x, core)
    steps += handoff(8, core)                      # key 6: an entry since 4, nothing included: pruned at 8
    steps += handoff(9, core)                      # key 5: included at 5L+1 > opening(5): present at 9
    steps += handoff(10, core, core + [5])         # key 5's vote for 10L+I is above F = 10L: pruned at 10
    steps += [
        {"op": "rejoin", "height": 10 * L + I + 1, "block_epoch": 10, "key": 6, "epoch": 9},
        {"op": "rejoin", "height": 10 * L + I + 2, "block_epoch": 10, "key": 6, "epoch": 10},
        {"op": "rejoin", "height": 10 * L + I + 2, "block_epoch": 10, "key": 6, "epoch": 10},
        {"op": "rejoin", "height": 10 * L + I + 2, "block_epoch": 10, "key": 0, "epoch": 10},
        {"op": "rejoin", "height": 10 * L + I + 2, "block_epoch": 10, "key": 5, "epoch": 8},
        {"op": "rejoin", "height": 10 * L + I + 2, "block_epoch": 10, "key": 5, "epoch": 10, "bad_sig": True},
        {"op": "rejoin", "height": 10 * L + I + 2, "block_epoch": 10, "key": 5, "epoch": 10, "other_chain": True},
        {"op": "rejoin", "height": 10 * L, "block_epoch": 10, "key": 5, "epoch": 10},
        {"op": "rejoin", "height": 10 * L + I + 3, "block_epoch": 11, "key": 7, "epoch": 10},
    ]
    steps += handoff(11, core)                     # key 6's rejoin is final: back in C_11 (grace to 15)
    steps += handoff(12, core)                     # key 5 has no candidate weight: forgotten
    steps += handoff(13, core)                     # key 5 is a new key again
    steps += handoff(14, core)
    steps += handoff(15, core)                     # key 6 (entry since 11) still silent: pruned again
    run("absence_pruning_and_rejoin", fading, steps)

    # 9. A jump from epoch 4 to 9 with a committee that kept voting, stepped
    #    C_5 .. C_9 (section 4). Key 5's evidence is included below opening(5):
    #    banned from 5. Votes included in the blocks of epochs 5..8 count
    #    (keys 0..3: 400 of C_8's 500, a strict quorum present, so the absent
    #    are pruned), the votes of the finalizing links (above opening(9)) do
    #    not: key 4, included only at exactly opening(5), is present at 8 and
    #    pruned at 9.
    steps = [
        {"op": "evidence", "height": b4 + 10, "key": 5, "links": [[b4, b4 + I], [b4, b4 + I, 1]]},
        {"op": "votes", "target": b4 + I, "voters": [0, 1, 2]},
        {"op": "include", "height": 6 * L + 3, "voters": [0, 1, 2, 3, 5]},
        {"op": "include", "height": 5 * L, "voters": [4]},
        {"op": "votes", "target": 9 * L, "voters": [0, 1, 2, 3, 4]},
        {"op": "votes", "target": 9 * L + I, "voters": [0, 1, 2, 3, 4]},
    ]
    run("stall_prunes_from_finalized_history", flat, steps)

    # 10. More than a third vanishes at once: no quorum, no handoff, so
    #     nobody is pruned (no local timeout) and C_4 stays.
    steps = [{"op": "votes", "target": b4 + k * I, "voters": [0, 1, 2]} for k in range(1, 4)]
    steps += [{"op": "include", "height": 30 * L, "voters": [0, 1, 2]},
              {"op": "votes", "target": 30 * L, "voters": [0, 1, 2]},
              {"op": "votes", "target": 30 * L + I, "voters": [0, 1, 2]}]
    run("mass_absence_halts_without_pruning", lambda e: {kid[i]: 100 for i in range(5)}, steps)

    # 11. A stall longer than PRUNE_AFTER ends (DESIGN §4.1, review HIGH):
    #     nothing of C_4 was included in epochs 16..19, so the present keys
    #     hold no quorum of C_4 and the handoff to 20 that the returning
    #     committee authorizes prunes nobody, not even key 5 (never voted).
    #     The next handoff has a committee present in its window: key 5 is
    #     pruned at 21.
    steps = [{"op": "votes", "target": b4 + I, "voters": [0, 1, 2]},
             {"op": "votes", "target": 20 * L, "voters": [0, 1, 2, 3, 4]},
             {"op": "votes", "target": 20 * L + I, "voters": [0, 1, 2, 3, 4]}]
    steps += handoff(21, core)
    run("stall_end_keeps_the_returning_committee", flat, steps)

    # 12. One C_x per epoch x (DESIGN §4, review MEDIUM): C_x is a function of
    #     the history up to opening(x). Both chains share it (key 5 pruned at
    #     8, its rejoin included in epoch 8); chain a finalizes opening(9),
    #     chain b skips it, includes evidence against key 4 and the votes of
    #     key 5's return above opening(9), and finalizes 9L + I. Both hold
    #     the same C_9 (the evidence stays pending on b).
    def unique_prefix():
        st = [{"op": "votes", "target": 5 * L, "voters": core},
              {"op": "votes", "target": 5 * L + I, "voters": core}]
        for x in (6, 7, 8):
            st += handoff(x, core)
        return st + [{"op": "rejoin", "height": 8 * L + I + 1, "block_epoch": 8, "key": 5, "epoch": 8}]
    run("handoff_unique_per_epoch_a", flat, unique_prefix() + handoff(9, core))
    run("handoff_unique_per_epoch_b", flat, unique_prefix() + [
        {"op": "votes", "target": 9 * L, "voters": [0, 1, 2]},
        {"op": "evidence", "height": 9 * L + 5, "key": 4, "links": [[8 * L + I, 9 * L], [8 * L + I, 9 * L, 1]]},
        {"op": "votes", "target": 9 * L + I, "voters": core},
        {"op": "votes", "target": 9 * L + 2 * I, "voters": core},
    ])

    # 13. A handoff never leaves an empty configuration: the provider gives
    #     no weight at 6 (all share work expired), so C_6 carries C_5's
    #     entries forward; C_7 is the provider's again.
    steps = handoff(5, core) + handoff(6, core) + handoff(7, core)
    run("empty_handoff_carries_the_configuration", lambda e: {} if e == 6 else flat(e), steps)

    # 14. Pruned, then rejoin, under the growth cap (DESIGN §4.1, §6.3): six
    #     keys mine 400 per epoch (share work 1 per share, G_min = 1440);
    #     key 5 never votes, is pruned at 8 and gets no credit while pruned
    #     (it keeps its earlier credits), rejoins in epoch 9 and competes as
    #     new weight from C_10 on. The provider is GrowthCapProvider; the
    #     vector carries its history (growth_cap).
    hist = {"share_work": {n: {kid[i]: 400 for i in range(6)} for n in range(16)},
            "first_block_bits": {n: gc.EASY_BITS for n in range(16)}}
    steps = handoff(5, core)
    for x in (6, 7, 8):
        steps += handoff(x, core)
    steps += [{"op": "rejoin", "height": 9 * L + 1, "block_epoch": 9, "key": 5, "epoch": 9}]
    steps += handoff(9, core) + handoff(10, core) + handoff(11, core)
    run("growth_cap_pruned_then_rejoin", GrowthCapProvider(hist, gc.PARAMS["obenblock"]), steps)

    # 15. Path independence (DESIGN §4, re-review MEDIUM): one history, two
    #     finalization paths. Key 5's vote is included at 8L + 3, above
    #     opening(8). Chain a finalizes opening(9) under C_7 and steps through
    #     C_8 (key 5 absent from (opening(4), opening(8)]: pruned at 8) to
    #     C_9; chain b finalizes 9L - I, a checkpoint of epoch 8, then 9L.
    #     Both hold the same C_8 and C_9.
    def path_prefix():
        st = [{"op": "votes", "target": 5 * L, "voters": core},
              {"op": "votes", "target": 5 * L + I, "voters": core}]
        for x in (6, 7):
            st += handoff(x, core)
        return st + [{"op": "include", "height": 8 * L + 3, "voters": [5]}]
    run("handoff_path_independent_a", flat, path_prefix() + [
        {"op": "votes", "target": 9 * L, "voters": core, "included_at": 9 * L + 1},
        {"op": "votes", "target": 9 * L + I, "voters": core, "included_at": 9 * L + I + 1},
    ])
    run("handoff_path_independent_b", flat, path_prefix() + [
        {"op": "votes", "target": 9 * L - I, "voters": core, "included_at": 9 * L + 2},
        {"op": "votes", "target": 9 * L, "voters": core, "included_at": 9 * L + 3},
        {"op": "votes", "target": 9 * L + I, "voters": core, "included_at": 9 * L + I + 1},
    ])

    # 16. Staggered return after a stall (DESIGN §4.1, re-review LOW): nobody
    #     votes in epochs 4..8 until keys 0..4 return late in epoch 8 and
    #     finalize 9L - 2I (steps 5..8, no quorum present: nobody pruned).
    #     Key 5 returns at the first block of epoch 9 and votes in the link
    #     that finalizes opening(9); its votes are above opening(9) and keys
    #     0..4 hold a present quorum, so it is pruned at 9 (never banned). Its
    #     node publishes a rejoin in epoch 9: back in C_10.
    run("staggered_return_rejoins", flat, [
        {"op": "votes", "target": 9 * L - 2 * I, "voters": core},
        {"op": "votes", "target": 9 * L - I, "voters": core},
        {"op": "votes", "target": 9 * L, "voters": core + [5]},
        {"op": "votes", "target": 9 * L + I, "voters": core + [5]},
        {"op": "rejoin", "height": 9 * L + I + 2, "block_epoch": 9, "key": 5, "epoch": 9},
    ] + handoff(10, core, core + [5]))
    return seqs


def gen_evidence_items() -> list:
    """Context-free evidence checks (check_evidence) with full attestations."""
    P = PARAMS["mainnet"]
    k = [vkey("ev", i) for i in range(3)]
    c1 = make_config("mainnet", 4, {k[0].key_id: 10, k[1].key_id: 10})
    c2 = make_config("mainnet", 5, {k[0].key_id: 10, k[1].key_id: 10})
    configs = {c1.id: c1, c2.id: c2}
    b = 4 * 720

    def cp(h, br=0):
        return (h, cp_hash(h, br))

    def v(cfg, key, s, t, sig=None):
        x = sign_vote(cfg.chain, P, cfg.id, key, s, t)
        return x if sig is None else Vote(x.config_id, x.key, x.source, x.target, sig)
    cases = [
        ("double", v(c1, k[0], cp(b), cp(b + 60)), v(c1, k[0], cp(b), cp(b + 60, 1))),
        ("double_different_sources", v(c1, k[0], cp(b), cp(b + 120)), v(c1, k[0], cp(b + 60), cp(b + 120, 1))),
        ("surround", v(c1, k[0], cp(b), cp(b + 240)), v(c1, k[0], cp(b + 60), cp(b + 180))),
        ("surround_reversed", v(c1, k[0], cp(b + 60), cp(b + 180)), v(c1, k[0], cp(b), cp(b + 240))),
        ("surround_shared_source", v(c1, k[0], cp(b), cp(b + 240)), v(c1, k[0], cp(b), cp(b + 180))),
        ("surround_shared_target", v(c1, k[0], cp(b), cp(b + 240)), v(c1, k[0], cp(b + 60), cp(b + 240))),
        ("consecutive", v(c1, k[0], cp(b), cp(b + 60)), v(c1, k[0], cp(b + 60), cp(b + 120))),
        ("identical", v(c1, k[0], cp(b), cp(b + 60)), v(c1, k[0], cp(b), cp(b + 60))),
        ("different_configs", v(c1, k[0], cp(b), cp(b + 60)), v(c2, k[0], cp(b), cp(b + 60, 1))),
        ("different_keys", v(c1, k[0], cp(b), cp(b + 60)), v(c1, k[1], cp(b), cp(b + 60, 1))),
        ("non_member", v(c1, k[2], cp(b), cp(b + 60)), v(c1, k[2], cp(b), cp(b + 60, 1))),
        ("bad_signature", v(c1, k[0], cp(b), cp(b + 60)), v(c1, k[0], cp(b), cp(b + 60, 1), bytes(32))),
        ("wrong_kes_epoch", v(c1, k[0], cp(b), cp(b + 60)),
         Vote(c1.id, k[0], cp(b), cp(b + 60, 1),
              test_sign(k[0], 3, message_v3(c1.chain, c1.id, k[0], cp(b), cp(b + 60, 1))))),
        ("second_config", v(c2, k[1], cp(b), cp(b + 720)), v(c2, k[1], cp(b), cp(b + 720, 1))),
    ]
    unknown = make_config("mainnet", 9, {k[0].key_id: 10})
    cases.append(("unknown_config", v(unknown, k[0], cp(b), cp(b + 60)), v(unknown, k[0], cp(b), cp(b + 60, 1))))
    out = []
    for name, a, bb in cases:
        kind, reason = check_evidence(a, bb, configs)
        out.append({"name": name, "a": a.to_json(), "b": bb.to_json(), "kind": kind, "verdict": reason})
    return {"configs": [config_json(c1), config_json(c2)], "cases": out}


def gen_certificates() -> dict:
    P = PARAMS["mainnet"]
    keys = [vkey("cert", i) for i in range(5)]
    weights = {keys[0].key_id: 300, keys[1].key_id: 200, keys[2].key_id: 200, keys[3].key_id: 200,
               keys[4].key_id: 100}                                   # total 1000: quorum needs 667
    cfg = make_config("mainnet", 4, weights)
    src = (4 * 720 + 120, cp_hash(4 * 720 + 120))
    tgt = (4 * 720 + 180, cp_hash(4 * 720 + 180))
    heavy = [k for k in keys if k.key_id in (keys[0].key_id, keys[1].key_id, keys[2].key_id)]  # 700
    outsider = vkey("cert-outsider", 0)
    cases = []

    def add(name, cert_or_bytes, proof=None, config=cfg):
        data = cert_or_bytes if isinstance(cert_or_bytes, bytes) else cert_or_bytes.encode()
        c = {"name": name, "certificate": data.hex(), "verdict": verify_certificate(data, config)}
        try:
            dc = decode_certificate(data)
            pr = proof if proof is not None else make_registry_proof(config, dc).encode() \
                if all(config.weight(k.key_id) is not None for k, _ in dc.votes) else None
        except DecodeError:
            dc, pr = None, proof
        if pr is not None:
            c["registry_proof"] = pr.hex()
            c["verdict_with_proof"] = verify_certificate_with_proof(data, pr, "mainnet", config.id)
        cases.append(c)

    good = make_certificate(cfg, src, tgt, heavy)
    add("valid_700_of_1000", good)
    add("valid_all", make_certificate(cfg, src, tgt, keys))
    exact_cfg = make_config("mainnet", 4, {keys[0].key_id: 200, keys[1].key_id: 200, keys[2].key_id: 200})
    add("exactly_two_thirds", make_certificate(exact_cfg, src, tgt, keys[:2]), config=exact_cfg)
    above_cfg = make_config("mainnet", 4, {keys[0].key_id: 201, keys[1].key_id: 200, keys[2].key_id: 200})
    add("just_above_two_thirds", make_certificate(above_cfg, src, tgt, keys[:2]), config=above_cfg)
    add("below_quorum_500", make_certificate(cfg, src, tgt, [keys[1], keys[2], keys[4]]))
    add("empty", Certificate(cfg.chain, cfg.id, src, tgt, []))
    # Duplicate key: the same vote twice (sorted, so adjacent).
    v0 = good.votes
    add("duplicate_key", Certificate(cfg.chain, cfg.id, src, tgt, [v0[0], v0[0], v0[1]]))
    add("unsorted", Certificate(cfg.chain, cfg.id, src, tgt, [v0[1], v0[0], v0[2]]))
    out_cert = make_certificate(cfg, src, tgt, heavy[:2])
    osig = sign_vote(cfg.chain, P, cfg.id, outsider, src, tgt).sig
    add("key_outside_config", Certificate(cfg.chain, cfg.id, src, tgt,
                                          sorted(out_cert.votes + [(outsider, osig)], key=lambda kv: kv[0].key_id)))
    bad = list(v0)
    bad[1] = (bad[1][0], bytes(32))
    add("bad_signature", Certificate(cfg.chain, cfg.id, src, tgt, bad))
    add("wrong_kes_epoch", make_certificate(cfg, src, tgt, heavy, kes_epoch=3))
    add("wrong_chain_id", Certificate(CHAIN_OBB_REGTEST, cfg.id, src, tgt, v0))
    forged_cfg = make_config("mainnet", 4, {**weights, keys[4].key_id: 1})     # forged weights: other id
    add("forged_weights_config_id", make_certificate(forged_cfg, src, tgt, heavy[:2] + [keys[4]]))
    add("not_direct_child", make_certificate(cfg, src, (tgt[0] + 60, cp_hash(tgt[0] + 60)), heavy))
    add("not_a_slot", make_certificate(cfg, (src[0] + 1, src[1]), (tgt[0] + 1, tgt[1]), heavy))
    enc = good.encode()
    add("version_2", b"\x02" + enc[1:])
    add("truncated", enc[:-1])
    add("trailing_byte", enc + b"\x00")
    head = 1 + 4 + 32 + 40 + 40
    add("non_minimal_varint", enc[:head] + b"\xfd" + (3).to_bytes(2, "little") + enc[head + 1:])
    # Registry proofs that lie.
    dc = decode_certificate(enc)
    pr = make_registry_proof(cfg, dc)
    lie_w = RegistryProof(pr.epoch, pr.total, pr.n, pr.tree_root,
                          [(pr.members[0][0] + 100, pr.members[0][1], pr.members[0][2])] + pr.members[1:])
    add("proof_forged_weight", good, proof=lie_w.encode())
    lie_t = RegistryProof(pr.epoch, pr.total - 300, pr.n, pr.tree_root, pr.members)
    add("proof_forged_total", good, proof=lie_t.encode())
    lie_p = RegistryProof(pr.epoch, pr.total, pr.n, pr.tree_root,
                          [(pr.members[0][0], pr.members[0][1], pr.members[0][2][:-1])] + pr.members[1:])
    add("proof_short_path", good, proof=lie_p.encode())
    lie_i = RegistryProof(pr.epoch, pr.total, pr.n, pr.tree_root,
                          [(pr.members[0][0], pr.n, pr.members[0][2])] + pr.members[1:])
    add("proof_index_out_of_range", good, proof=lie_i.encode())
    add("proof_trailing", good, proof=pr.encode() + b"\x00")
    return {"params": "mainnet", "trusted_config": config_json(cfg), "keys": [
        {"depth": k.depth, "root": k.root.hex(), "key_id": k.key_id.hex()} for k in keys + [outsider]],
        "cases": cases}


def generate() -> dict:
    return {
        "format": "obb-poci-vectors-v1",
        "description": "PoCI configurations, v3 messages, strict quorum, FFG + handoff + bans, "
                       "evidence and finality certificates (reference/poci_reference.py)",
        "constants": {
            "chain_obb_mainnet": CHAIN_OBB_MAINNET, "chain_obb_regtest": CHAIN_OBB_REGTEST,
            "ds_params": DS_PARAMS.decode(), "ds_config": DS_CONFIG.decode(), "ds_leaf": DS_LEAF.decode(),
            "ds_node": DS_NODE.decode(), "ds_root": DS_ROOT.decode(), "ds_attest_v3": DS_ATTEST_V3.decode(),
            "ds_test_sig": DS_TEST_SIG.decode(), "certificate_version": CERT_VERSION,
            "ds_rejoin": DS_REJOIN.decode(), "prune_after_epochs": PRUNE_AFTER_EPOCHS,
            "rejoin_preimage_len": len(rejoin_preimage(CHAIN_OBB_MAINNET, KesKey(0, ZERO32), 0)),
            "v3_preimage_len": len(message_v3_preimage(CHAIN_OBB_MAINNET, ZERO32, KesKey(0, ZERO32),
                                                       (0, ZERO32), (1, ZERO32))),
            "config_preimage_len": len(config_preimage_parts(0, 0, 0, ZERO32, ZERO32)),
            "params_preimage_len": len(params_preimage(PARAMS["mainnet"])),
            "launch_height": {name: launch_height(PARAMS[name]) for name in PARAMS},
        },
        "notes": {
            "numbers": "weights and totals are decimal strings (u128); heights and epochs are JSON integers",
            "test_signature": "sig = sha256d(ds_test_sig || u8(depth) || root || u64le(epoch(target.height)) || msg_v3); "
                              "a stand-in for kes::sign, anyone can compute it",
            "sequences": "a PociChain on mainnet parameters launched at the checkpoint opening epoch 4 "
                         "(height 2880, justified and finalized). Checkpoint hashes are cp_hash(height, branch) = "
                         "sha256d('poci-vector-cp' || u64le(height) || u32le(branch)), branch 0 unless a link names "
                         "[source_height, target_height, branch]. provider_calls[e] are the candidate weights of C_e "
                         "before bans. A votes step: every listed voter (index into keys) signs justified -> target "
                         "under the named configuration ('current' = in force, 'previous' = the one before it); "
                         "voters in bad_sig carry 32 zero bytes instead. result.weight/total are the counted weight "
                         "and the total of the configuration in force when the votes were counted; state is after "
                         "the step. An evidence step: the block at `height` carries attestations a and b. "
                         "Absence pruning (section 4.1): the votes counted in a votes step are included at "
                         "`included_at` (default target height + 1); an include step records votes of the listed "
                         "keys included at `height` (only entries of the configuration in force; result = the keys "
                         "recorded); a rejoin step: the block at `height` of epoch `block_epoch` carries the "
                         "rejoin (signed for chain 0x4F420002 when other_chain, 32 zero bytes when bad_sig). "
                         "pruned: key -> the epoch its pruning started; rejoins: key -> height of its pending rejoin. "
                         "A handoff to C_x reads the history up to opening(x) only (bans, rejoins, the absence "
                         "window (opening(x-4), opening(x)] and its quorum gate). growth_cap (when present): the "
                         "provider is the growth cap (obb_growth_cap.advance with params 'obenblock') over this "
                         "share-work history, the keys excluded at each epoch it steps being the chain's; "
                         "provider_calls are its outputs.",
            "certificates": "verdict: verify_certificate against trusted_config's entries; verdict_with_proof: "
                            "verify_certificate_with_proof against trusted_config.config_id and registry_proof "
                            "(absent when the certificate does not decode or names a key outside the configuration)",
        },
        "params": gen_params(),
        "configs": gen_configs(),
        "messages": gen_messages(),
        "rejoin_messages": gen_rejoin_messages(),
        "quorum": gen_quorum(),
        "evidence": gen_evidence_items(),
        "sequences": gen_sequences(),
        "certificates": gen_certificates(),
    }


def serialized() -> bytes:
    return (json.dumps(generate(), indent=1, sort_keys=False) + "\n").encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if poci_vectors.json differs")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if not VECTOR_FILE.exists() or VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("poci vectors differ from the reference; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    doc = json.loads(contents)
    print(f"{len(doc['configs'])} configs, {len(doc['messages'])} messages, {len(doc['quorum'])} quorum cases, "
          f"{len(doc['evidence']['cases'])} evidence, {len(doc['sequences'])} sequences, "
          f"{len(doc['certificates']['cases'])} certificates; sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
