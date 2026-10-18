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
        || u64le(bootstrap_epochs) || u64le(growth_div) || u64le(g_min_epoch_div)
        || u32le(quorum_num) || u32le(quorum_den) )                    110-byte preimage

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
epoch(F) > e, C_epoch(F) enters into force (it is computed from the finalized
history up to F; epochs e+1 .. epoch(F)-1 are skipped). Otherwise C_e stays.

Proof of Corruption (section 5): two distinct v3 attestations, same KES key,
same config_id, a known configuration that has the key as an entry, both
signatures valid, and a double vote (same target height, different targets)
or a strict surround (s1 < s2 and t2 < t1, either way round). A block at
height h may carry it unless the key already has a ban pending or not yet
over, or was already banned for that config_id. ban_start = the epoch of the
first configuration entering into force at or after the finalization of the
block holding the evidence (the handoff triggered by that same finalization
counts: its configuration is computed from a history that holds the
evidence). The key is not an entry of C_x for ban_start <= x < ban_start +
ban_epochs (100). Configurations already in force or past never change.

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
DS_TEST_SIG = b"OBB-POCI-test/sig"
CERT_VERSION = 1

# ObenBlock PoWit parameters under PoCI. Mainnet: 6-hour epochs of 720 blocks
# (DESIGN-obenblock.md §6.2), slots every 60, the 112-epoch window, the
# 100-epoch ban and 4 bootstrap epochs (DESIGN-obenblock-poci.md §5, §9), the
# growth cap of §6.3. Regtest: the GnB testnet clock (20 / 5 / ttl 20, as
# core::powit::params_for maps ObenBlock regtest), the same window and ban.
PARAMS = {
    "mainnet": {"chain_id": CHAIN_OBB_MAINNET, "epoch_len": 720, "checkpoint_interval": 60,
                "window_epochs": 112, "vote_ttl": 720, "max_attestations_per_block": 32,
                "max_evidence_per_block": 4, "ban_epochs": 100, "bootstrap_epochs": 4,
                "growth_div": 64, "g_min_epoch_div": 8, "quorum_num": 2, "quorum_den": 3},
    "regtest": {"chain_id": CHAIN_OBB_REGTEST, "epoch_len": 20, "checkpoint_interval": 5,
                "window_epochs": 112, "vote_ttl": 20, "max_attestations_per_block": 32,
                "max_evidence_per_block": 4, "ban_epochs": 100, "bootstrap_epochs": 4,
                "growth_div": 64, "g_min_epoch_div": 8, "quorum_num": 2, "quorum_den": 3},
}
PARAM_U64_FIELDS = ("epoch_len", "checkpoint_interval", "window_epochs", "vote_ttl",
                    "max_attestations_per_block", "max_evidence_per_block", "ban_epochs",
                    "bootstrap_epochs", "growth_div", "g_min_epoch_div")


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


def counted_weight(config: Config, votes, src, tgt) -> int:
    """Weight of the distinct keys of `config` with a valid vote for src->tgt
    naming config.id (a vote naming another configuration counts nowhere)."""
    seen: set[bytes] = set()
    got = 0
    for v in votes:
        if v.config_id != config.id or v.source != src or v.target != tgt:
            continue
        k = v.key.key_id
        w = config.weight(k)
        if w is None or k in seen or not v.verify(config.chain, config.params):
            continue
        seen.add(k)
        got += w
    return got


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
class PociChain:
    """Linear model of one honest node's PoCI state. `provider(epoch,
    finalized)` returns the candidate weights {key_id: weight} of C_epoch
    computed from the finalized history up to `finalized` (the window and
    growth cap of DESIGN-obenblock.md §6.3, package O10); bans are applied
    here."""
    params_name: str
    provider: object
    checkpoint_hash: object = None
    config: Config = None
    justified: tuple = None
    finalized: tuple = None
    configs: dict = field(default_factory=dict)
    history: list = field(default_factory=list)      # configs in order of entry into force
    bans: dict = field(default_factory=dict)         # key_id -> [Ban] (latest last)
    log: list = field(default_factory=list)

    @property
    def params(self) -> dict:
        return PARAMS[self.params_name]

    def cp(self, height: int) -> tuple:
        return (height, self.checkpoint_hash(height))

    def launch(self) -> None:
        """Section 9: C_bootstrap from the chain up to the checkpoint opening
        epoch `bootstrap_epochs`, which is justified and finalized."""
        e = self.params["bootstrap_epochs"]
        self.justified = self.finalized = self.cp(checkpoint_opening(self.params, e))
        self._enter(e)

    def banned_at(self, key_id: bytes, epoch: int) -> bool:
        n = self.params["ban_epochs"]
        return any(b.start is not None and b.start <= epoch < b.start + n for b in self.bans.get(key_id, []))

    def _enter(self, epoch: int) -> None:
        weights = {k: w for k, w in self.provider(epoch, self.finalized).items() if not self.banned_at(k, epoch)}
        self.config = make_config(self.params_name, epoch, weights)
        self.configs[self.config.id] = self.config
        self.history.append(self.config)

    def votes(self, target: tuple, votes) -> dict:
        """Count votes for justified -> target under the configuration in force."""
        src = self.justified
        got = counted_weight(self.config, votes, src, target)
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

    def _finalize(self, f: tuple) -> bool:
        self.finalized = f
        e = epoch_of(self.params, f[0])
        if e <= self.config.epoch:
            return False
        for bans in self.bans.values():
            for b in bans:
                if b.start is None and b.height <= f[0]:
                    b.start = e
        self._enter(e)
        return True

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
    keys = [vkey("seq", i) for i in range(6)]
    kid = [k.key_id for k in keys]
    seqs = []

    def run(name, weights_by_epoch, steps):
        ch = _std_chain(name, weights_by_epoch, keys)
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
                rec["result"] = ch.votes(tgt, vs)
                rec["result"]["weight"] = str(rec["result"]["weight"])
                rec["result"]["total"] = str(rec["result"]["total"])
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
            out_steps.append(rec)
        seqs.append({"name": name, "params": "mainnet", "keys": [{"depth": k.depth, "root": k.root.hex(),
                                                                   "key_id": k.key_id.hex()} for k in keys],
                     "initial": initial, "provider_calls": {str(e): v for e, v in sorted(ch.calls.items())},
                     "configs": [config_json(c) for c in ch.history], "steps": out_steps})
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
            "v3_preimage_len": len(message_v3_preimage(CHAIN_OBB_MAINNET, ZERO32, KesKey(0, ZERO32),
                                                       (0, ZERO32), (1, ZERO32))),
            "config_preimage_len": len(config_preimage_parts(0, 0, 0, ZERO32, ZERO32)),
            "params_preimage_len": len(params_preimage(PARAMS["mainnet"])),
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
                         "the step. An evidence step: the block at `height` carries attestations a and b.",
            "certificates": "verdict: verify_certificate against trusted_config's entries; verdict_with_proof: "
                            "verify_certificate_with_proof against trusted_config.config_id and registry_proof "
                            "(absent when the certificate does not decode or names a key outside the configuration)",
        },
        "params": gen_params(),
        "configs": gen_configs(),
        "messages": gen_messages(),
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
