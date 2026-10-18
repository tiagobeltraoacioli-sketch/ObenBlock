"""Reference for the ObenBlock anchor record (docs/OBB-ANCHOR.md).

Independent of the Rust code (crates/gnb-crypto/src/obb_anchor.rs): the
record encoding, the witness-set digest and the decoding rules, plus the
generator of `obb_anchor_vectors.json`.

    python3 reference/obb_anchor.py           # self-test
    python3 reference/obb_anchor.py --write   # regenerate the vectors
    python3 reference/obb_anchor.py --check   # vectors file is up to date

Standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

RECORD_LEN = 84
W_DIGEST_TAG = b"OBB-ANCHOR-v1/W"
VECTOR_FILE = Path(__file__).with_name("obb_anchor_vectors.json")

CHAIN_OBB_MAINNET = 0x4F420001
CHAIN_OBB_REGTEST = 0x4F420002
CHAIN_GNB_MAINNET = 0x474E0001
U64_MAX = 2**64 - 1
U128_MAX = 2**128 - 1


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def w_digest(entries) -> bytes:
    """entries: iterable of (20-byte key, weight); any order, no duplicates."""
    items = sorted(entries, key=lambda kw: kw[0])
    keys = [k for k, _ in items]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    out = bytearray(W_DIGEST_TAG)
    out += struct.pack("<I", len(items))
    for k, w in items:
        if len(k) != 20 or not 0 <= w <= U128_MAX:
            raise ValueError("bad entry")
        out += k + w.to_bytes(16, "little")
    return sha256d(bytes(out))


def encode(chain_id: int, slot: int, block_id: bytes, finalized_at: int, wd: bytes) -> bytes:
    assert len(block_id) == 32 and len(wd) == 32
    return struct.pack("<IQ", chain_id, slot) + block_id + struct.pack("<Q", finalized_at) + wd


def decode(b: bytes) -> dict:
    if len(b) != RECORD_LEN:
        raise ValueError("length")
    chain_id, slot = struct.unpack_from("<IQ", b, 0)
    block_id = b[12:44]
    (finalized_at,) = struct.unpack_from("<Q", b, 44)
    wd = b[52:84]
    if block_id == bytes(32):
        raise ValueError("zero block id")
    if finalized_at <= slot:
        raise ValueError("finalized_at not above slot")
    return {"chain_id": chain_id, "slot": slot, "block_id": block_id,
            "finalized_at": finalized_at, "w_digest": wd}


def key(i: int) -> bytes:
    return hashlib.sha256(b"obb-anchor-vector-key" + bytes([i])).digest()[:20]


def generate() -> dict:
    sets = {
        "empty": [],
        "one": [(key(1), 1)],
        "three_heaviest_first": [(key(2), 9000), (key(3), 500), (key(4), 7)],
        "extremes": [(bytes(20), 0), (b"\xff" * 20, U128_MAX), (key(5), 2**64)],
    }
    w_cases = []
    for name, entries in sets.items():
        w_cases.append({
            "name": name,
            "set": [{"key": k.hex(), "weight": str(w)} for k, w in entries],
            "digest": w_digest(entries).hex(),
        })

    def block(i: int) -> bytes:
        return sha256d(b"obb-anchor-vector-block" + bytes([i]))

    records = [
        ("obb_mainnet_epoch1", CHAIN_OBB_MAINNET, 720, block(1), 845, w_digest(sets["three_heaviest_first"])),
        ("obb_regtest_epoch3", CHAIN_OBB_REGTEST, 60, block(2), 71, w_digest(sets["one"])),
        ("gnb_chain_id", CHAIN_GNB_MAINNET, 1_440, block(3), 1_500, w_digest(sets["empty"])),
        ("max_fields", 0xFFFFFFFF, U64_MAX - 1, b"\xff" * 32, U64_MAX, b"\xff" * 32),
    ]
    r_cases = []
    for name, cid, slot, bid, fat, wd in records:
        raw = encode(cid, slot, bid, fat, wd)
        assert decode(raw)["slot"] == slot
        r_cases.append({
            "name": name, "chain_id": cid, "slot": slot, "block_id": bid.hex(),
            "finalized_at": fat, "w_digest": wd.hex(), "record": raw.hex(),
            "record_id": sha256d(raw).hex(),
        })

    good = encode(CHAIN_OBB_MAINNET, 720, block(1), 845, bytes(32))
    invalid = [
        ("short", good[:83]),
        ("long", good + b"\x00"),
        ("zero_block_id", encode(CHAIN_OBB_MAINNET, 720, bytes(32), 845, bytes(32))),
        ("finalized_at_equal_slot", encode(CHAIN_OBB_MAINNET, 720, block(1), 720, bytes(32))),
        ("finalized_at_below_slot", encode(CHAIN_OBB_MAINNET, 720, block(1), 719, bytes(32))),
    ]
    for _, raw in invalid:
        try:
            decode(raw)
        except ValueError:
            continue
        raise AssertionError("invalid vector decoded")
    return {
        "format": "obb-anchor-v1",
        "record_len": RECORD_LEN,
        "w_digest_tag": W_DIGEST_TAG.decode(),
        "w_digest": w_cases,
        "records": r_cases,
        "invalid_records": [{"name": n, "record": raw.hex()} for n, raw in invalid],
    }


def render() -> str:
    return json.dumps(generate(), indent=1) + "\n"


def self_test() -> None:
    a, b = (key(1), 5), (key(2), 50)
    assert w_digest([a, b]) == w_digest([b, a])
    try:
        w_digest([a, a])
        raise AssertionError("duplicate accepted")
    except ValueError:
        pass
    raw = encode(CHAIN_OBB_MAINNET, 720, b"\x07" * 32, 845, b"\x09" * 32)
    assert raw[:4] == bytes([0x01, 0x00, 0x42, 0x4F]) and len(raw) == RECORD_LEN
    assert decode(raw)["finalized_at"] == 845
    generate()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    self_test()
    if a.write:
        VECTOR_FILE.write_text(render())
        print(f"wrote {VECTOR_FILE.name}")
    elif a.check:
        if VECTOR_FILE.read_text() != render():
            print(f"{VECTOR_FILE.name} is stale: run with --write", file=sys.stderr)
            return 1
        print(f"{VECTOR_FILE.name} up to date")
    else:
        print("self-test ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
