"""ObenBlock header Merkle root and body commitment -- executable reference.

docs/CONSENSUS.md, "Header Merkle root and body commitment (ObenBlock)".
On ObenBlock (the SHA-256d proof-of-work scheme) the header's merkle_root is
Bitcoin's transaction Merkle root, so stock Stratum V1 firmware, which
rebuilds the root itself from coinb1 || extranonce1 || extranonce2 || coinb2
and the merkle branch, produces valid headers:

    txid(tx)      = SHA-256d(wire(tx, include_script_sig = is_coinbase(tx)))
                    (a coinbase: exactly the bytes a stratum pool hashes;
                    see docs/CONSENSUS.md for the non-coinbase encoding)
    root([])      = 32 zero bytes
    level_0       = [txid_0, ..., txid_n]                     (block order)
    level_{k+1}   = SHA-256d(l || r) over the pairs of level_k, after a copy
                    of the last node is appended to a level of odd length
    mutated       = some level, BEFORE that copy, has level[2i] == level[2i+1]
                    (Bitcoin Core's ComputeMerkleRoot; CVE-2012-2459)
    valid        <=> header.merkle_root == root and not mutated

Every other byte of the body is committed through the coinbase commitment
(80 bytes at the start of the coinbase script_sig, docs/CONSENSUS.md), whose
bytes 48..80 on ObenBlock are

    body_commitment = tagged("OBB/coinbase/body",
                             witness_root || shielded_root || powit_root)
    tagged(t, m)    = SHA-256(SHA-256(t) || SHA-256(t) || m)
    witness_root    = gnb_merkle.witness_root (tagged tree over
                      [0^32, wtxid_1, ..., wtxid_n])
    shielded_root   = SHA3-256("gnb:block:shielded:v1" || SHA3-256(stx)...)
    powit_root      = SHA3-256("GNB-POWIT-v1/body" || PoWit section wire,
                      exits list included)

`crates/gnb-crypto/src/core/pow_scheme.rs` must reproduce
`obb_merkle_vectors.json` (`crates/gnb-crypto/tests/obb_merkle_vectors.rs`).

Usage:  python3 obb_merkle.py --check | --write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTOR_FILE = HERE / "obb_merkle_vectors.json"
BODY_COMMITMENT_TAG = b"OBB/coinbase/body"


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def tagged(tag: bytes, msg: bytes) -> bytes:
    t = hashlib.sha256(tag).digest()
    return hashlib.sha256(t + t + msg).digest()


def node(left: bytes, right: bytes) -> bytes:
    return sha256d(left + right)


def bitcoin_merkle_root(ids: list[bytes]) -> tuple[bytes, bool]:
    """(root, mutated), Bitcoin Core's ComputeMerkleRoot."""
    if not ids:
        return bytes(32), False
    level = list(ids)
    mutated = False
    while len(level) > 1:
        for i in range(0, len(level) - 1, 2):
            if level[i] == level[i + 1]:
                mutated = True
        if len(level) % 2:
            level.append(level[-1])
        level = [node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0], mutated


def merkle_branch(ids: list[bytes]) -> list[bytes]:
    """Siblings of position 0 (the coinbase) bottom-up; ids[0] is ignored."""
    branch = []
    level = list(ids)
    while len(level) > 1:
        branch.append(level[1])
        if len(level) % 2:
            level.append(level[-1])
        level = [node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return branch


def fold_branch(coinbase_txid: bytes, branch: list[bytes]) -> bytes:
    """What stratum firmware computes: cur = SHA-256d(cur || sibling)."""
    cur = coinbase_txid
    for s in branch:
        cur = node(cur, s)
    return cur


def body_commitment(witness_root: bytes, shielded_root: bytes, powit_root: bytes) -> bytes:
    return tagged(BODY_COMMITMENT_TAG, witness_root + shielded_root + powit_root)


def stratum_prevhash(header_bytes: bytes) -> str:
    """Stratum's prevhash: each 4-byte word of the header bytes reversed."""
    assert len(header_bytes) == 32
    return b"".join(header_bytes[i:i + 4][::-1] for i in range(0, 32, 4)).hex()


# Bitcoin mainnet data (txids in Bitcoin's display order, i.e. reversed).
BITCOIN_GENESIS_COINBASE = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054"
    "696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f7574"
    "20666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea"
    "1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
BITCOIN_BLOCK1_COINBASE = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100"
    "f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f81417"
    "81e62294721166bf621e73a82cbf2342c858eeac00000000")
BITCOIN_BLOCKS = [
    {"name": "bitcoin block 1", "coinbase_wire_hex": BITCOIN_BLOCK1_COINBASE,
     "txids_display": ["0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"],
     "merkle_root_display": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"},
    {"name": "bitcoin block 170", "coinbase_wire_hex": None,
     "txids_display": ["b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082",
                       "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"],
     "merkle_root_display": "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"},
    {"name": "bitcoin block 100000", "coinbase_wire_hex": None,
     "txids_display": ["8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
                       "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
                       "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
                       "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"],
     "merkle_root_display": "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"},
]


def bitcoin_vectors() -> list[dict]:
    out = []
    for b in BITCOIN_BLOCKS:
        ids = [bytes.fromhex(t)[::-1] for t in b["txids_display"]]
        root, mutated = bitcoin_merkle_root(ids)
        assert not mutated and root[::-1].hex() == b["merkle_root_display"], b["name"]
        assert fold_branch(ids[0], merkle_branch(ids)) == root
        if b["coinbase_wire_hex"]:
            assert sha256d(bytes.fromhex(b["coinbase_wire_hex"])) == ids[0]
        out.append({**b, "txids": [i.hex() for i in ids], "merkle_root": root.hex(),
                    "branch": [s.hex() for s in merkle_branch(ids)]})
    return out


def tree_vectors() -> list[dict]:
    rng = random.Random(0x0BB3E4C1)
    out = []
    for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17]:
        ids = [rng.randbytes(32) for _ in range(n)]
        root, mutated = bitcoin_merkle_root(ids)
        assert not mutated
        if n:
            assert fold_branch(ids[0], merkle_branch(ids)) == root
        out.append({"ids": [i.hex() for i in ids], "root": root.hex(), "mutated": False,
                    "branch": [s.hex() for s in merkle_branch(ids)] if n else []})
    return out


def mutation_vectors() -> list[dict]:
    """CVE-2012-2459: lists with an identical adjacent pair on some level."""
    rng = random.Random(0x2459)
    a, b, c, e, f = (rng.randbytes(32) for _ in range(5))
    cases = [
        ("tail duplicated: [a,b,c] vs [a,b,c,c]", [a, b, c], [a, b, c, c]),
        ("two equal leaves: [a,a]", None, [a, a]),
        ("odd tail duplicated: [a,b,c,e,f] vs [a,b,c,e,f,f]", [a, b, c, e, f], [a, b, c, e, f, f]),
        ("equal inner nodes: [a,b,a,b]", None, [a, b, a, b]),
        ("equal pair deep in a long list", None, [a, b, c, e, f, a, b, c, e, f, f, f]),
    ]
    out = []
    for name, honest, mutated_list in cases:
        root, m = bitcoin_merkle_root(mutated_list)
        assert m, name
        v = {"name": name, "ids": [i.hex() for i in mutated_list], "root": root.hex(), "mutated": True}
        if honest is not None:
            hr, hm = bitcoin_merkle_root(honest)
            assert not hm and hr == root, name
            v["honest_ids"] = [i.hex() for i in honest]
        out.append(v)
    # Not a mutation: the duplication of an odd level's last node itself.
    root, m = bitcoin_merkle_root([a, b, c])
    assert not m
    return out


def body_commitment_vectors() -> list[dict]:
    rng = random.Random(0xB0D1)
    out = []
    empty_shielded = hashlib.sha3_256(b"gnb:block:shielded:v1").digest()
    empty_powit_with_exits = hashlib.sha3_256(b"GNB-POWIT-v1/body" + bytes(4)).digest()
    for wr, sr, pr in [(bytes(32), empty_shielded, empty_powit_with_exits),
                       (rng.randbytes(32), rng.randbytes(32), rng.randbytes(32))]:
        out.append({"witness_root": wr.hex(), "shielded_root": sr.hex(), "powit_root": pr.hex(),
                    "body_commitment": body_commitment(wr, sr, pr).hex()})
    return out


def vectors() -> dict:
    display = bytes.fromhex("00000000440b921e1b77c6c0487ae5616de67f788f44ae2a5af6e2194d16b6f8")
    return {
        "spec": "docs/CONSENSUS.md, Header Merkle root and body commitment (ObenBlock); reference/obb_merkle.py",
        "bitcoin_genesis_coinbase": {"wire_hex": BITCOIN_GENESIS_COINBASE,
                                     "txid": sha256d(bytes.fromhex(BITCOIN_GENESIS_COINBASE)).hex(),
                                     "txid_display": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"},
        "bitcoin_blocks": bitcoin_vectors(),
        "trees": tree_vectors(),
        "mutations": mutation_vectors(),
        "body_commitment_tag": BODY_COMMITMENT_TAG.decode(),
        "body_commitments": body_commitment_vectors(),
        "stratum_prevhash": {"header_bytes": display[::-1].hex(),
                             "prevhash": stratum_prevhash(display[::-1])},
    }


def render() -> str:
    v = vectors()
    g = v["bitcoin_genesis_coinbase"]
    assert bytes.fromhex(g["txid"])[::-1].hex() == g["txid_display"]
    assert v["stratum_prevhash"]["prevhash"] == "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000"
    return json.dumps(v, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    args = ap.parse_args()
    text = render()
    if args.write:
        VECTOR_FILE.write_text(text)
        print(f"wrote {VECTOR_FILE.name}")
        return 0
    if VECTOR_FILE.read_text() != text:
        print(f"FAIL: {VECTOR_FILE.name} differs from the reference (run --write after a deliberate change)")
        return 1
    print(f"{VECTOR_FILE.name}: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
