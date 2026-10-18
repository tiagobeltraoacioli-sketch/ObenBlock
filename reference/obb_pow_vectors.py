"""Generate obb_pow_vectors.json from the reference (obb_pow.py).

Deterministic: the "random" cases come from SHAKE-256 of a fixed label, so the
file is reproducible byte for byte. `--check` compares the regenerated JSON
bytes with the file without writing (CI).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import gnb_difficulty as d
import obb_pow as o

VECTOR_FILE = Path(__file__).with_name("obb_pow_vectors.json")
GENESIS_TIME = 1_800_000_000          # an example anchor time (O6c fixes the real one)
FULL_SUBSIDY = 107_020_547            # tokenomics::INITIAL_SUBSIDY_SAT


class Rng:
    def __init__(self, label: bytes):
        self.label = label
        self.i = 0

    def bytes(self, n: int) -> bytes:
        self.i += 1
        return hashlib.shake_256(self.label + self.i.to_bytes(8, "little")).digest(n)

    def below(self, n: int) -> int:
        return int.from_bytes(self.bytes(40), "little") % n


def bitcoin_headers():
    genesis = o.pow_header(1, bytes(32),
                           bytes.fromhex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")[::-1],
                           1231006505, 0x1D00FFFF, 2083236893)
    g_id = o.sha256d(genesis)
    block1 = o.pow_header(1, g_id,
                          bytes.fromhex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")[::-1],
                          1231469665, 0x1D00FFFF, 2573394689)
    out = []
    for name, h in (("bitcoin-genesis", genesis), ("bitcoin-block-1", block1),
                    ("bitcoin-genesis-nonce+1", genesis[:76] + (2083236894).to_bytes(4, "little"))):
        out.append({"name": name, "header_hex": h.hex(), "id_display_hex": o.sha256d(h)[::-1].hex(),
                    "valid": o.verify_header(h)})
    return out


def parent_cases():
    rng = Rng(b"obb-pow-vectors/parents")
    lists = [[], [bytes(32)], [b"\x01" * 32, b"\x02" * 32], [b"\x02" * 32, b"\x01" * 32],
             [b"\x05" * 32, b"\x05" * 32]]
    for n in (3, 10):
        lists.append(sorted(rng.bytes(32) for _ in range(n)))
    lists.append([i.to_bytes(32, "big") for i in range(257)])
    return [{"parents": [p.hex() for p in ps], "commitment_hex": o.parents_commitment(ps).hex(),
             "check": o.check_parents(ps)} for ps in lists]


def work_cases():
    rng = Rng(b"obb-pow-vectors/work")
    targets = [0, 1, 2, (1 << 128) - 1, 1 << 128, (1 << 128) + 1, 1 << 192, (1 << 255), (1 << 256) - 1,
               d.bits_to_target(o.POW_LIMIT_BITS), d.bits_to_target(o.REGTEST_POW_LIMIT_BITS),
               d.bits_to_target(o.LAUNCH_BITS)]
    for _ in range(40):
        bits = rng.below(257)
        targets.append(rng.below(1 << bits) if bits else 0)
    return [{"target_hex": t.to_bytes(32, "big").hex(), "work": str(o.work(t))} for t in targets]


def launch_cases():
    cases = [(1, 30), (2, 30), (7, 30), (1 << 32, 1), (10 ** 15, 30), (10 ** 18, 30), (0, 30), (1, 1),
             (1 << 127, 2), (1 << 127, 3)]
    return [{"hashrate": str(r), "spacing": s, "target_hex": o.target_for_hashes(r, s).to_bytes(32, "big").hex()}
            for r, s in cases]


def mine(h: dict, limit_bits: int) -> dict:
    h = dict(h)
    while o.check_header(h, limit_bits) == "InsufficientWork":
        h["nonce"] += 1
    return h


def header_json(h: dict) -> dict:
    return {"version": h["version"], "parents": [p.hex() for p in h["parents"]],
            "merkle_root_hex": h["merkle_root"].hex(), "timestamp": h["timestamp"], "bits": h["bits"],
            "nonce": h["nonce"]}


def header_cases():
    rng = Rng(b"obb-pow-vectors/headers")
    out = []
    for i in range(8):
        parents = sorted({rng.bytes(32) for _ in range(1 + rng.below(4))})
        base = {"version": o.BLOCK_VERSION | (rng.below(1 << 16) << 13 if i % 2 else 0),
                "parents": parents, "merkle_root": rng.bytes(32),
                "timestamp": GENESIS_TIME + rng.below(1 << 20), "bits": o.REGTEST_POW_LIMIT_BITS, "nonce": 0}
        good = mine(base, o.REGTEST_POW_LIMIT_BITS)
        variants = [("mined", good)]
        if i == 0:
            variants += [
                ("nonce-u32-overflow", dict(good, nonce=good["nonce"] + (1 << 32))),
                ("time-u32-overflow", dict(good, timestamp=1 << 32)),
                ("version-bit-12", dict(good, version=good["version"] | 0x1000)),
                ("version-bit-30", dict(good, version=good["version"] | 0x40000000)),
                ("parents-reversed", dict(good, parents=good["parents"][::-1])),
                ("parents-duplicate", dict(good, parents=[good["parents"][0]] * 2)),
                ("bits-non-canonical", dict(good, bits=0x2100_7FFF)),
                ("bits-malformed", dict(good, bits=0x0080_0001)),
                ("bits-above-limit", dict(good, bits=0x2100_FFFF)),
                ("genesis-no-parents", mine(dict(base, parents=[]), o.REGTEST_POW_LIMIT_BITS)),
            ]
        for name, h in variants:
            out.append({"name": f"{i}-{name}", "header": header_json(h), "block_id_hex": o.block_id(h).hex(),
                        "check_regtest": o.check_header(h, o.REGTEST_POW_LIMIT_BITS),
                        "check_mainnet": o.check_header(h, o.POW_LIMIT_BITS)})
    return out


def expected_bits_cases():
    rng = Rng(b"obb-pow-vectors/asert")
    cases = [(GENESIS_TIME, 1), (GENESIS_TIME + 30 * 99, 100), (GENESIS_TIME + 7200, 1),
             (GENESIS_TIME - 7200, 1), (GENESIS_TIME + 10_000_000, 1), (GENESIS_TIME, 5_760),
             (GENESIS_TIME + 30 * 5_759 + 600, 5_760)]
    for _ in range(30):
        h = 1 + rng.below(100_000)
        cases.append((GENESIS_TIME + 30 * (h - 1) + rng.below(40_000) - 20_000, h))
    out = []
    for net, gbits, lbits in (("mainnet", o.LAUNCH_BITS, o.POW_LIMIT_BITS),
                              ("regtest", o.REGTEST_POW_LIMIT_BITS, o.REGTEST_POW_LIMIT_BITS)):
        for pt, h in cases:
            out.append({"network": net, "parent_time": pt, "height": h,
                        "bits": o.expected_bits(pt, h, GENESIS_TIME, gbits, lbits)})
    return out


def generate():
    return {
        "description": "ObenBlock SHA-256d PoW vectors from reference/obb_pow.py (docs/DESIGN-obenblock.md §4). "
                       "Targets are 32-byte big-endian hex, ids raw digest hex (Bitcoin displays them reversed), "
                       "work decimal strings.",
        "constants": {
            "pow_limit_bits": o.POW_LIMIT_BITS, "regtest_pow_limit_bits": o.REGTEST_POW_LIMIT_BITS,
            "launch_hashrate_hps": str(o.LAUNCH_HASHRATE_HPS), "launch_bits": o.LAUNCH_BITS,
            "block_version": o.BLOCK_VERSION, "bip320_mask": o.BIP320_VERSION_MASK,
            "max_parents": o.MAX_PARENTS, "slow_start_blocks": o.SLOW_START_BLOCKS,
            "genesis_time": GENESIS_TIME, "full_subsidy_sat": FULL_SUBSIDY,
            "slow_start_withheld_sat": sum(FULL_SUBSIDY - o.slow_start_subsidy(FULL_SUBSIDY, h)
                                           for h in range(1, o.SLOW_START_BLOCKS)),
        },
        "bitcoin_headers": bitcoin_headers(),
        "parents": parent_cases(),
        "work": work_cases(),
        "target_for_hashes": launch_cases(),
        "headers": header_cases(),
        "expected_bits": expected_bits_cases(),
        "slow_start": [{"height": h, "subsidy_sat": o.slow_start_subsidy(FULL_SUBSIDY, h)}
                       for h in (0, 1, 2, 2_879, 2_880, 5_759, 5_760, 5_761, 10 ** 9)],
    }


def serialized() -> bytes:
    return (json.dumps(generate(), indent=1) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("obb_pow vectors differ; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    print(f"obb_pow vectors ok; sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
