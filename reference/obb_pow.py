"""ObenBlock SHA-256d proof of work -- executable reference specification.

docs/DESIGN-obenblock.md §4. This file is the normative definition of the
80-byte header, the block id, the proof check, chain work, the pow limits,
the launch bits and the slow-start subsidy. `crates/gnb-smh/src/sha256d.rs`
and `crates/gnb-crypto/src/core/pow_scheme.rs` must reproduce
`obb_pow_vectors.json` exactly (`crates/gnb-smh/tests/vectors_sha256d.rs`,
`crates/gnb-crypto/tests/obb_pow_vectors.rs`). Compact bits and ASERT are
GnB's, from `gnb_difficulty.py`, with ObenBlock's anchor and pow limit.

    pow_header = u32le(version) || parents_commitment || merkle_root
               || u32le(time) || u32le(bits) || u32le(nonce)                80 bytes
    parents_commitment = SHA-256d("OBB-PARENTS-v1" || u32le(n) || parent_0 || ... )
    block_id   = SHA-256d(pow_header)
    valid     <=> le256(block_id) <= target(bits)
    work       = floor(2^256 / (target + 1)), saturating at 2^128 - 1; work(0) = 0

A header is valid under SHA-256d iff, in this order: its u64 timestamp and
nonce fit u32; version & ~0x1fffe000 == block version (BIP 320); its parents
are strictly ascending and at most 256; bits is canonical; target <= pow
limit; the id meets the target. The expected bits are ASERT (30 s, 2 h)
anchored at the genesis block (height 0, genesis bits, genesis timestamp),
clamped to the pow limit, at every height.
"""

from __future__ import annotations

import hashlib

import gnb_difficulty as d

POW_HEADER_LEN = 80
PARENTS_TAG = b"OBB-PARENTS-v1"
NONCANONICAL_ID_TAG = b"OBB-NONCANONICAL-HEADER-v1"
POW_LIMIT_BITS = 0x1D00FFFF            # mainnet, Bitcoin's
REGTEST_POW_LIMIT_BITS = 0x207FFFFF    # regtest, Bitcoin regtest's
BIP320_VERSION_MASK = 0x1FFFE000
BLOCK_VERSION = 0x20000000
MAX_PARENTS = 256
TARGET_SPACING = d.TARGET_SPACING
HALFLIFE = d.HALFLIFE
LAUNCH_HASHRATE_HPS = 10 ** 18
SLOW_START_BLOCKS = 5_760
U32_MAX = (1 << 32) - 1
U128_MAX = (1 << 128) - 1


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parents_commitment(parents: list[bytes]) -> bytes:
    return sha256d(PARENTS_TAG + len(parents).to_bytes(4, "little") + b"".join(parents))


def check_parents(parents: list[bytes], max_parents: int = MAX_PARENTS) -> str | None:
    """None if canonical, else TooMany / Duplicate / NotSorted."""
    if len(parents) > max_parents:
        return "TooMany"
    for a, b in zip(parents, parents[1:]):
        if a == b:
            return "Duplicate"
        if a > b:
            return "NotSorted"
    return None


def pow_header(version: int, commitment: bytes, merkle_root: bytes, time: int, bits: int, nonce: int) -> bytes:
    assert len(commitment) == 32 and len(merkle_root) == 32
    return (version.to_bytes(4, "little") + commitment + merkle_root + time.to_bytes(4, "little")
            + bits.to_bytes(4, "little") + nonce.to_bytes(4, "little"))


def meets_target(block_id: bytes, target: int) -> bool:
    return target != 0 and int.from_bytes(block_id, "little") <= target


def verify_header(header80: bytes) -> bool:
    bits = int.from_bytes(header80[72:76], "little")
    try:
        target = d.bits_to_target(bits)
    except d.BitsError:
        return False
    return meets_target(sha256d(header80), target)


def version_ok(version: int, block_version: int = BLOCK_VERSION) -> bool:
    return block_version & BIP320_VERSION_MASK == 0 and version & ~BIP320_VERSION_MASK & U32_MAX == block_version


def work(target: int) -> int:
    if target == 0:
        return 0
    return min((1 << 256) // (target + 1), U128_MAX)


def work_from_bits(bits: int) -> int:
    return work(d.bits_to_target_or_zero(bits))


def target_for_hashes(hashrate: int, spacing: int) -> int:
    h = hashrate * spacing
    if h > U128_MAX:
        return 1
    if h <= 1:
        return (1 << 256) - 1
    return max((1 << 256) // h - 1, 1)


LAUNCH_BITS = d.target_to_bits(target_for_hashes(LAUNCH_HASHRATE_HPS, TARGET_SPACING))


def legacy_pow_preimage(h: dict) -> bytes:
    """GnB's BlockHeader::pow_preimage (u64 timestamp)."""
    return (h["version"].to_bytes(4, "little") + len(h["parents"]).to_bytes(4, "little")
            + b"".join(h["parents"]) + h["merkle_root"] + h["timestamp"].to_bytes(8, "little")
            + h["bits"].to_bytes(4, "little"))


def block_id(h: dict) -> bytes:
    """Block id of a DAG header dict (version, parents, merkle_root, timestamp, bits, nonce)."""
    if h["timestamp"] > U32_MAX or h["nonce"] > U32_MAX:
        return sha256d(NONCANONICAL_ID_TAG + legacy_pow_preimage(h) + h["nonce"].to_bytes(8, "little"))
    return sha256d(pow_header(h["version"], parents_commitment(h["parents"]), h["merkle_root"],
                              h["timestamp"], h["bits"], h["nonce"]))


def check_header(h: dict, pow_limit_bits: int, block_version: int = BLOCK_VERSION) -> str | None:
    """None if the header passes every SHA-256d PoW rule, else the first
    failing rule (the Rust `Sha256dHeaderError` variant name)."""
    if h["timestamp"] > U32_MAX:
        return "TimeOutOfRange"
    if h["nonce"] > U32_MAX:
        return "NonceOutOfRange"
    if not version_ok(h["version"], block_version):
        return "Version"
    p = check_parents(h["parents"])
    if p is not None:
        return "Parents:" + p
    if not d.is_canonical_bits(h["bits"]):
        return "BitsNotCanonical"
    target = d.bits_to_target(h["bits"])
    if target > d.bits_to_target(pow_limit_bits):
        return "AbovePowLimit"
    if not meets_target(block_id(h), target):
        return "InsufficientWork"
    return None


def expected_bits(parent_time: int, height: int, genesis_time: int,
                  genesis_bits: int = LAUNCH_BITS, pow_limit_bits: int = POW_LIMIT_BITS) -> int:
    return d.asert_next_bits(parent_time, height, anchor_height=0, anchor_bits=genesis_bits,
                             anchor_time=genesis_time, pow_limit_bits=pow_limit_bits)


def slow_start_subsidy(full: int, height: int) -> int:
    return full if height >= SLOW_START_BLOCKS else full * height // SLOW_START_BLOCKS
