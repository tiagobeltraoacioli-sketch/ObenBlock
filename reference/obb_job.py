"""ObenBlock SHA-256d header jobs -- executable reference for a job server.

docs/OBENBLOCK-MINING.md. What a pool computes from the `sha256d.header_job`
of `getblocktemplate` (and the top-level `coinbase_merkle_branch`) to hand
an ASIC an 80-byte header for any extranonce, and to check its shares:

    coinbase      = coinb1 || extranonce (8 bytes) || coinb2
    coinbase_txid = SHA-256d(coinbase)
    tx_root       = fold over the branch: cur = leaf(coinbase_txid);
                    cur = node(cur, sibling) for each sibling, bottom-up
                    leaf(x)    = tagged("GnB/merkle/leaf", x)
                    node(l, r) = tagged("GnB/merkle/node", l || r)
                    tagged(t, m) = SHA-256(SHA-256(t) || SHA-256(t) || m)
    merkle_root   = SHA3-256("gnb:block:body:v2" || tx_root || shielded_root || powit_root)
                    (rule "gnb-body-v2"; rule "gnb-tagged-v1": tx_root itself)
    header        = obb_pow.pow_header(version, parents_commitment, merkle_root, time, bits, nonce)

A share is a block when SHA-256d(header), read little-endian, is at most
target(bits); its rolled fields go back to the node with
`submitblock [block_hex, {"version", "time", "nonce"}]`.
`node/src/mining/sha256d.rs` must reproduce `obb_job_vectors.json`
(node/tests/obb_sha256d_mining.rs); `obb_job_test.py` recomputes it here.
"""

from __future__ import annotations

import hashlib

import obb_pow

EXTRANONCE_LEN = 8
LEAF_TAG = b"GnB/merkle/leaf"
NODE_TAG = b"GnB/merkle/node"
BODY_V2_TAG = b"gnb:block:body:v2"
SHIELDED_TAG = b"gnb:block:shielded:v1"


def tagged(tag: bytes, msg: bytes) -> bytes:
    t = hashlib.sha256(tag).digest()
    return hashlib.sha256(t + t + msg).digest()


def leaf(x: bytes) -> bytes:
    return tagged(LEAF_TAG, x)


def node(l: bytes, r: bytes) -> bytes:
    return tagged(NODE_TAG, l + r)


def tagged_merkle_root(ids: list[bytes]) -> bytes:
    """The whole tree (the odd last node is carried up), for cross-checks."""
    if not ids:
        return bytes(32)
    level = [leaf(i) for i in ids]
    while len(level) > 1:
        level = [node(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return level[0]


def coinbase_merkle_branch(ids: list[bytes]) -> list[bytes]:
    """Siblings of position 0 bottom-up (ids[0] is ignored)."""
    branch = []
    level = [leaf(i) for i in ids]
    while len(level) > 1:
        branch.append(level[1])
        level = [node(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return branch


def empty_shielded_root() -> bytes:
    return hashlib.sha3_256(SHIELDED_TAG).digest()


def coinbase_txid(coinb1: bytes, extranonce: bytes, coinb2: bytes) -> bytes:
    assert len(extranonce) == EXTRANONCE_LEN
    return obb_pow.sha256d(coinb1 + extranonce + coinb2)


def merkle_root(rule: str, cb_txid: bytes, branch: list[bytes], shielded_root: bytes, powit_root: bytes) -> bytes:
    cur = leaf(cb_txid)
    for s in branch:
        cur = node(cur, s)
    if rule == "gnb-tagged-v1":
        return cur
    assert rule == "gnb-body-v2", rule
    return hashlib.sha3_256(BODY_V2_TAG + cur + shielded_root + powit_root).digest()


def job_header(job: dict, parents: list[bytes], extranonce: bytes, version: int, time: int, nonce: int) -> bytes:
    """The 80-byte header of `job` (vector / RPC field names) for one share."""
    txid = coinbase_txid(bytes.fromhex(job["coinb1"]), extranonce, bytes.fromhex(job["coinb2"]))
    root = merkle_root(job["merkle_root_rule"], txid, [bytes.fromhex(b) for b in job["coinbase_merkle_branch"]],
                       bytes.fromhex(job["shielded_root"]), bytes.fromhex(job["powit_root"]))
    return obb_pow.pow_header(version, obb_pow.parents_commitment(parents), root, time, job["bits"], nonce)
