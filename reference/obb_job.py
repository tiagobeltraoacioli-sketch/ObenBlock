"""ObenBlock SHA-256d header jobs -- executable reference for a job server.

docs/OBENBLOCK-MINING.md. ObenBlock's header root is Bitcoin's transaction
Merkle root (docs/CONSENSUS.md, reference/obb_merkle.py), so a header job is
an ordinary Stratum V1 job and stock firmware computes the root itself:

    coinbase      = coinb1 || extranonce1 || extranonce2 || coinb2
                    (len(extranonce1) + len(extranonce2) = extranonce_size = 8)
    coinbase_txid = SHA-256d(coinbase)
    merkle_root   = fold over merkle_branch: cur = coinbase_txid;
                    cur = SHA-256d(cur || sibling) for each sibling, bottom-up
    header        = u32le(version) || parents_commitment || merkle_root
                    || u32le(ntime) || u32le(nbits) || u32le(nonce)

`mining.notify` carries prevhash as stratum does (each 4-byte word of the
header bytes reversed, `stratum_prevhash`), and version, nbits and ntime as
big-endian hex of the u32. ntime must stay in [mintime, maxtime] (the window
in which the job's bits are the consensus bits, stall relief).

A share is a block when SHA-256d(header), read little-endian, is at most
target(bits); it goes back to the node with
`submitblock [job.block, {"version", "time", "nonce", "extranonce"}]`.
`node/src/mining/sha256d.rs` must reproduce `obb_job_vectors.json`
(node/tests/obb_sha256d_mining.rs); `obb_job_test.py` recomputes it here.
"""

from __future__ import annotations

import obb_merkle as om
import obb_pow

EXTRANONCE_LEN = 8
MERKLE_RULE = "bitcoin-sha256d"


def coinbase_txid(coinb1: bytes, extranonce: bytes, coinb2: bytes) -> bytes:
    assert len(extranonce) == EXTRANONCE_LEN
    return obb_pow.sha256d(coinb1 + extranonce + coinb2)


def merkle_root(cb_txid: bytes, branch: list[bytes]) -> bytes:
    return om.fold_branch(cb_txid, branch)


def job_header(job: dict, parents: list[bytes], extranonce: bytes, version: int, time: int, nonce: int) -> bytes:
    """The 80-byte header of `job` (vector / RPC field names) for one share."""
    assert job["merkle_root_rule"] == MERKLE_RULE
    txid = coinbase_txid(bytes.fromhex(job["coinb1"]), extranonce, bytes.fromhex(job["coinb2"]))
    root = merkle_root(txid, [bytes.fromhex(b) for b in job["merkle_branch"]])
    return obb_pow.pow_header(version, obb_pow.parents_commitment(parents), root, time, job["bits"], nonce)


def stock_firmware_header(notify: dict, extranonce1: bytes, extranonce2: bytes, ntime: int, nonce: int,
                          version_bits: int = 0) -> bytes:
    """What an unmodified Stratum V1 miner builds from `mining.notify` alone
    (the `stratum` object of a header job): no ObenBlock knowledge."""
    prev_words = bytes.fromhex(notify["prevhash"])
    prev = b"".join(prev_words[i:i + 4][::-1] for i in range(0, 32, 4))
    cb = bytes.fromhex(notify["coinb1"]) + extranonce1 + extranonce2 + bytes.fromhex(notify["coinb2"])
    root = obb_pow.sha256d(cb)
    for s in notify["merkle_branch"]:
        root = obb_pow.sha256d(root + bytes.fromhex(s))
    version = int(notify["version"], 16) | version_bits
    bits = int(notify["nbits"], 16)
    return (version.to_bytes(4, "little") + prev + root + ntime.to_bytes(4, "little")
            + bits.to_bytes(4, "little") + nonce.to_bytes(4, "little"))
