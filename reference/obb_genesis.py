"""ObenBlock genesis blocks -- executable reference specification.

docs/DESIGN-obenblock.md §3. Rebuilds both ObenBlock genesis blocks from
their constants, independently of the Rust code
(`crates/gnb-crypto/src/core/genesis.rs`), and writes / checks
`obb_genesis_vectors.json`, which `crates/gnb-crypto/tests/obb_genesis_vectors.rs`
checks the Rust code against.

    coinbase   = Tx(version 1,
                    in:  prev_txid 0^32, prev_index 0xffffffff, sequence 0xffffffff,
                         script_sig = coinbase_commitment(0, [], witness_root([coinbase])) || text,
                    out: value 0 to 0^20, locktime 0)
    tx_root    = legacy_merkle_root([txid(coinbase)]) = txid(coinbase)
                 (the genesis is outside the hardening block rules: h >= 1)
    body_root  = SHA3-256("gnb:block:body:v2" || tx_root
                          || SHA3-256("gnb:block:shielded:v1")
                          || SHA3-256("GNB-POWIT-v1/body" || 00 00 00 00))
                 (PoWit and liveness from height 0: the v2 body root, empty
                 shares, attestations, evidence and exits)
    header     = pow_header(version, parents_commitment([]), body_root, time, bits, nonce)   80 bytes
    block_id   = SHA-256d(header)

Mainnet's bits are the pow limit 0x1d00ffff and regtest's 0x207fffff; the
version is 0x20000000 plus any BIP 320 bits the search rolled. The mainnet
timestamp, version and nonce are fixed at launch (owner decision); until then
the vectors carry the template (everything but those three) and one
rehearsal solution at an example timestamp, which proves the launch search
end to end (`gnb-mine-genesis --chain obenblock --timestamp 1792281600`).

Usage:  python3 obb_genesis.py --check   (CI: regenerate in memory, compare)
        python3 obb_genesis.py --write   (after a deliberate change)
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import gnb_difficulty as d
import gnb_merkle as m
import obb_pow as o

HERE = Path(__file__).resolve().parent
VECTOR_FILE = HERE / "obb_genesis_vectors.json"
SNAPSHOT_GZ = HERE.parent / "genesis" / "bloch-g3-carryover.tsv.gz"
VESTING_JSON = HERE.parent / "crates" / "gnb-crypto" / "genesis" / "vesting.json"

# The consensus hashes the text commits to (core::carryover, core::vesting).
CARRYOVER_SNAPSHOT_SHA3 = "3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d"
VESTING_SPEC_SHA3 = "e24828c3cc6d56fe635581b8214af8733f4b060784d13bd92f2d558940d90d20"


def genesis_text(network: str) -> str:
    return (f"ObenBlock {network} genesis: SHA-256d proof of work, PoWit finality, every rule from height 0, "
            f"12.5M OBB cap. Carryover Bloch G3 terminal snapshot sha3 {CARRYOVER_SNAPSHOT_SHA3} "
            "3810744000 BLCH -> 1000000 OBB, the key hashes of GnB's genesis. "
            "Team 1250000 + founder 1250000 OBB locked, 1y cliff + 36 monthly, keys sha3 "
            f"{VESTING_SPEC_SHA3}.")


NETWORKS = {
    # LAUNCH PLACEHOLDER: at launch add "timestamp", "version" and "nonce"
    # (the constants gnb-mine-genesis printed) and run --write.
    "mainnet": {"bits": o.POW_LIMIT_BITS},
    "regtest": {"bits": o.REGTEST_POW_LIMIT_BITS,
                "timestamp": 1_792_281_600, "version": o.BLOCK_VERSION, "nonce": 0},
}
# A mainnet solution at an example timestamp (2026-10-18 00:00 UTC), found by
# the launch tool; NOT the mainnet genesis.
MAINNET_REHEARSAL = {"timestamp": 1_792_281_600, "version": o.BLOCK_VERSION, "nonce": 1_492_736_395}

EMPTY_SHIELDED_ROOT = hashlib.sha3_256(b"gnb:block:shielded:v1").digest()
EMPTY_POWIT_ROOT = hashlib.sha3_256(b"GNB-POWIT-v1/body" + b"\x00\x00\x00\x00").digest()


def coinbase(text: str) -> m.Tx:
    cb = m.Tx(version=1,
              inputs=[m.TxIn(prev_txid=bytes(32), prev_index=0xFFFFFFFF, script_sig=b"", sequence=0xFFFFFFFF)],
              outputs=[m.TxOut(value=0, script_pubkey=bytes(20))], locktime=0)
    commitment = m.coinbase_commitment(0, [], m.witness_root([cb]))
    cb.inputs[0].script_sig = commitment + text.encode()
    assert m.check_coinbase_commitment(0, [], [cb]) is None
    return cb


def body_root(cb: m.Tx) -> bytes:
    tx_root = m.legacy_merkle_root([cb.txid()])
    assert tx_root == cb.txid()
    return hashlib.sha3_256(b"gnb:block:body:v2" + tx_root + EMPTY_SHIELDED_ROOT + EMPTY_POWIT_ROOT).digest()


def header(network: str, version: int, timestamp: int, nonce: int) -> bytes:
    cb = coinbase(genesis_text(network))
    return o.pow_header(version, o.parents_commitment([]), body_root(cb), timestamp, NETWORKS[network]["bits"], nonce)


def solution(network: str, version: int, timestamp: int, nonce: int) -> dict:
    h = header(network, version, timestamp, nonce)
    target = d.bits_to_target(NETWORKS[network]["bits"])
    bid = o.sha256d(h)
    assert o.version_ok(version) and o.meets_target(bid, target), f"{network}: not a solution"
    return {"timestamp": timestamp, "version": version, "nonce": nonce, "header_hex": h.hex(),
            "block_id_hex": bid.hex(), "block_id_display_hex": bid[::-1].hex()}


def template(network: str) -> dict:
    text = genesis_text(network)
    cb = coinbase(text)
    return {
        "text": text,
        "bits": NETWORKS[network]["bits"],
        "coinbase_wire_hex": cb.wire(True).hex(),
        "coinbase_txid_hex": cb.txid().hex(),
        "parents_commitment_hex": o.parents_commitment([]).hex(),
        "merkle_root_hex": body_root(cb).hex(),
    }


def network_vectors(network: str) -> dict:
    n = NETWORKS[network]
    v = template(network)
    if "timestamp" in n:
        v.update(solution(network, n["version"], n["timestamp"], n["nonce"]))
    return v


def vectors() -> dict:
    return {
        "spec": "docs/DESIGN-obenblock.md §3; reference/obb_genesis.py",
        "mainnet": {**network_vectors("mainnet"), "launched": "timestamp" in NETWORKS["mainnet"],
                    "rehearsal": solution("mainnet", **MAINNET_REHEARSAL)},
        "regtest": network_vectors("regtest"),
    }


def check_ledger_files() -> list[str]:
    """The files the text commits to hash to the committed values."""
    errs = []
    if SNAPSHOT_GZ.exists():
        got = hashlib.sha3_256(gzip.decompress(SNAPSHOT_GZ.read_bytes())).hexdigest()
        if got != CARRYOVER_SNAPSHOT_SHA3:
            errs.append(f"carryover snapshot sha3 {got} != {CARRYOVER_SNAPSHOT_SHA3}")
    if VESTING_JSON.exists():
        got = hashlib.sha3_256(VESTING_JSON.read_bytes()).hexdigest()
        if got != VESTING_SPEC_SHA3:
            errs.append(f"vesting spec sha3 {got} != {VESTING_SPEC_SHA3}")
    return errs


def render() -> str:
    return json.dumps(vectors(), indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--write", action="store_true")
    args = ap.parse_args()
    errs = check_ledger_files()
    for e in errs:
        print("FAIL:", e)
    text = render()
    if args.write:
        VECTOR_FILE.write_text(text)
        print(f"wrote {VECTOR_FILE.name}")
        return 1 if errs else 0
    if VECTOR_FILE.read_text() != text:
        print(f"FAIL: {VECTOR_FILE.name} differs from the reference (run --write after a deliberate change)")
        return 1
    print(f"{VECTOR_FILE.name}: OK")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
