"""ObenBlock witness shares on SHA-256d and the long witness window --
executable reference specification.

docs/DESIGN-obenblock.md §6. This file is the normative definition of the
SHA-256d share (job chunk selection, job commitment, 80-byte share header,
share target, work, id, wire encoding and the order of its checks) and of
ObenBlock's witness-weight window. `crates/gnb-crypto/src/core/witness_share/sha256d.rs`
and `core::powit::obenblock_window` must reproduce `obb_shares_vectors.json`
exactly (`crates/gnb-crypto/tests/obb_share_vectors.rs`). Written from the
specification with hashlib only; compact bits are GnB's (`gnb_difficulty.py`),
SHA-256d, the 80-byte layout and work are `obb_pow.py`'s, the witness set is
`powit_reference.py`'s.

    python3 reference/obb_shares.py            # regenerate obb_shares_vectors.json
    python3 reference/obb_shares.py --check    # CI: the file is what this generates
    python3 reference/obb_shares_test.py -v    # the reference's own tests

    stream(B)      = wire(tx_0, with witness) || wire(tx_1) || ...      64-byte chunks, last zero-padded
    n_chunks       = max(1, ceil(len(stream) / 64))
    idx_k          = u64le(SHA-256d("OBB-WSHARE-v1/idx" || attested || SHA-256d(payout)
                                    || u64le(job_nonce) || u8(k))[0:8]) mod n_chunks      k = 0..7
    job_commitment = SHA-256d("OBB-WSHARE-v1/job" || attested || witness || SHA-256d(payout)
                              || u64le(job_nonce) || chunk[idx_0] || ... || chunk[idx_7])
    share_header   = u32le(version) || attested || job_commitment || u32le(time)
                     || u32le(bits) || u32le(nonce)                                       80 bytes
    share_target   = min(target(bits) * 16, 2^256 - 1)
    valid         <=> le256(SHA-256d(share_header)) <= share_target
    work           = floor(2^256 / (share_target + 1))
    share_id       = SHA-256d("OBB-WSHARE-v1/id" || attested || witness || SHA-256d(payout)
                              || u32le(bits) || u64le(job_nonce) || u32le(version)
                              || u32le(time) || u32le(nonce))
    wire           = attested || witness || varint(len(payout)) || payout || u32le(bits)
                     || u64le(job_nonce) || u32le(version) || u32le(time) || u32le(nonce)

Checks, in this order (the first failing one names the verdict, the Rust
`ShareError` variant): payout longer than 128 bytes (PayoutTooLong); no
SHA-256d header fields (WrongScheme); attested differs from the attested
block's id (WrongAttestedBlock); bits differ from the attested block's
(WrongBits); version & ~0x1fffe000 != block version (Version, BIP 320);
time != the attested block's timestamp (WrongTime); target(bits) == 0
(BadTarget); the header misses the share target (InsufficientWork).

Window: W(e) as in powit_reference.py with window_epochs = ban_epochs = 112
(28 days of 6-hour epochs) on ObenBlock mainnet's clock.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import gnb_difficulty as d
import obb_pow as o
import powit_reference as pr

VECTOR_FILE = Path(__file__).with_name("obb_shares_vectors.json")

DS_IDX = b"OBB-WSHARE-v1/idx"
DS_JOB = b"OBB-WSHARE-v1/job"
DS_ID = b"OBB-WSHARE-v1/id"
SHARE_TARGET_SHIFT = 4
SAMPLE_CHUNKS = 8
CHUNK_BYTES = 64
MAX_PAYOUT_SCRIPT = 128
MAX_TARGET = (1 << 256) - 1
OBB_WINDOW_EPOCHS = 112
EASY_BITS = 0x20010000        # block target 2^248: one share in 16 hashes
OBB_PARAMS = dict(pr.PARAMS["mainnet"], window_epochs=OBB_WINDOW_EPOCHS, ban_epochs=OBB_WINDOW_EPOCHS)


def sha256d(b: bytes) -> bytes:
    return o.sha256d(b)


def n_chunks(stream: bytes) -> int:
    return max(1, -(-len(stream) // CHUNK_BYTES))


def chunk(stream: bytes, i: int) -> bytes:
    return stream[i * CHUNK_BYTES:(i + 1) * CHUNK_BYTES].ljust(CHUNK_BYTES, b"\0")


def sample_indices(attested: bytes, payout: bytes, job_nonce: int, n: int) -> list[int]:
    ph = sha256d(payout)
    return [int.from_bytes(sha256d(DS_IDX + attested + ph + job_nonce.to_bytes(8, "little") + bytes([k]))[:8],
                           "little") % n for k in range(SAMPLE_CHUNKS)]


def job_commitment(attested: bytes, witness: bytes, payout: bytes, job_nonce: int, stream: bytes) -> bytes:
    idx = sample_indices(attested, payout, job_nonce, n_chunks(stream))
    return sha256d(DS_JOB + attested + witness + sha256d(payout) + job_nonce.to_bytes(8, "little")
                   + b"".join(chunk(stream, i) for i in idx))


def share_header(version: int, attested: bytes, job: bytes, time: int, bits: int, nonce: int) -> bytes:
    return o.pow_header(version, attested, job, time, bits, nonce)


def share_target(block_target: int) -> int:
    return min(block_target << SHARE_TARGET_SHIFT, MAX_TARGET)


def share_id(s: dict) -> bytes:
    return sha256d(DS_ID + s["attested"] + s["witness"] + sha256d(s["payout"]) + s["bits"].to_bytes(4, "little")
                   + s["job_nonce"].to_bytes(8, "little") + s["version"].to_bytes(4, "little")
                   + s["time"].to_bytes(4, "little") + s["nonce"].to_bytes(4, "little"))


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFF_FFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def wire(s: dict) -> bytes:
    return (s["attested"] + s["witness"] + varint(len(s["payout"])) + s["payout"] + s["bits"].to_bytes(4, "little")
            + s["job_nonce"].to_bytes(8, "little") + s["version"].to_bytes(4, "little")
            + s["time"].to_bytes(4, "little") + s["nonce"].to_bytes(4, "little"))


def header_of(s: dict, stream: bytes) -> bytes:
    job = job_commitment(s["attested"], s["witness"], s["payout"], s["job_nonce"], stream)
    return share_header(s["version"], s["attested"], job, s["time"], s["bits"], s["nonce"])


def verify(s: dict, attested: dict, block_version: int = o.BLOCK_VERSION) -> tuple[str | None, int]:
    """(None, work) if the share is valid against the attested block's parts
    (id, bits, timestamp, stream), else (the first failing check, 0). A
    share without header fields has s["version"] is None."""
    if len(s["payout"]) > MAX_PAYOUT_SCRIPT:
        return "PayoutTooLong", 0
    if s.get("version") is None:
        return "WrongScheme", 0
    if s["attested"] != attested["id"]:
        return "WrongAttestedBlock", 0
    if s["bits"] != attested["bits"]:
        return "WrongBits", 0
    if not o.version_ok(s["version"], block_version):
        return "Version", 0
    if s["time"] != attested["timestamp"]:
        return "WrongTime", 0
    bt = d.bits_to_target_or_zero(s["bits"])
    if bt == 0:
        return "BadTarget", 0
    t = share_target(bt)
    if not o.meets_target(sha256d(header_of(s, attested["stream"])), t):
        return "InsufficientWork", 0
    return None, o.work(t)


# ── Vectors ──────────────────────────────────────────────────────────────────

class Rng:
    def __init__(self, label: bytes):
        self.label = label
        self.i = 0

    def bytes(self, n: int) -> bytes:
        self.i += 1
        return hashlib.shake_256(self.label + self.i.to_bytes(8, "little")).digest(n)

    def below(self, n: int) -> int:
        return int.from_bytes(self.bytes(40), "little") % n


def job_cases() -> list:
    rng = Rng(b"obb-share-vectors/jobs")
    out = []
    for length in (0, 1, 63, 64, 65, 300, 1_000, 4_097):
        for job_nonce in (0, 1, (1 << 64) - 1, rng.below(1 << 64)):
            attested, witness = rng.bytes(32), rng.bytes(20)
            payout = rng.bytes(rng.below(40))
            stream = rng.bytes(length)
            out.append({"attested_hex": attested.hex(), "witness_hex": witness.hex(), "payout_hex": payout.hex(),
                        "job_nonce": str(job_nonce), "stream_hex": stream.hex(),
                        "n_chunks": n_chunks(stream),
                        "indices": sample_indices(attested, payout, job_nonce, n_chunks(stream)),
                        "job_commitment_hex": job_commitment(attested, witness, payout, job_nonce, stream).hex()})
    return out


def grind(s: dict, attested: dict) -> dict:
    s = dict(s)
    while verify(s, attested)[0] == "InsufficientWork":
        s["nonce"] += 1
    return s


def share_cases() -> list:
    rng = Rng(b"obb-share-vectors/shares")
    out = []
    for i in range(10):
        bits = EASY_BITS if i < 8 else (o.REGTEST_POW_LIMIT_BITS if i == 8 else o.POW_LIMIT_BITS)
        stream = rng.bytes(rng.below(2_000))
        attested = {"id": rng.bytes(32), "bits": bits, "timestamp": 1_800_000_000 + rng.below(1 << 24),
                    "stream": stream}
        base = {"attested": attested["id"], "witness": rng.bytes(20), "payout": rng.bytes(1 + rng.below(30)),
                "bits": bits, "job_nonce": rng.below(1 << 64),
                "version": o.BLOCK_VERSION | (rng.below(1 << 16) << 13 if i % 2 else 0),
                "time": attested["timestamp"], "nonce": rng.below(1 << 31)}
        good = grind(base, attested) if bits != o.POW_LIMIT_BITS else base
        variants = [("mined" if bits != o.POW_LIMIT_BITS else "mainnet-unmined", good)]
        if i == 0:
            variants += [
                ("payout-too-long", dict(good, payout=b"\x51" * (MAX_PAYOUT_SCRIPT + 1))),
                ("payout-max", grind(dict(good, payout=b"\x52" * MAX_PAYOUT_SCRIPT), attested)),
                ("other-attested", dict(good, attested=bytes(32))),
                ("other-bits", dict(good, bits=o.POW_LIMIT_BITS)),
                ("version-bit-12", dict(good, version=good["version"] | 0x1000)),
                ("version-bit-30", dict(good, version=good["version"] | 0x4000_0000)),
                ("time-plus-one", dict(good, time=good["time"] + 1)),
                ("time-minus-one", dict(good, time=good["time"] - 1)),
                ("re-pointed-witness", dict(good, witness=b"\x77" * 20)),
                ("next-job", dict(good, job_nonce=(good["job_nonce"] + 1) % (1 << 64))),
                ("max-fields", grind(dict(good, job_nonce=(1 << 64) - 1, nonce=0,
                                          version=o.BLOCK_VERSION | o.BIP320_VERSION_MASK), attested)),
            ]
            zero = dict(attested, bits=0)
            out.append(case("zero-target", dict(good, bits=0), zero))
        for name, s in variants:
            out.append(case(f"{i}-{name}", s, attested))
    return out


def case(name: str, s: dict, attested: dict) -> dict:
    verdict, w = verify(s, attested)
    return {
        "name": name,
        "attested": {"id_hex": attested["id"].hex(), "bits": attested["bits"], "timestamp": attested["timestamp"],
                     "stream_hex": attested["stream"].hex()},
        "share": {"attested_hex": s["attested"].hex(), "witness_hex": s["witness"].hex(),
                  "payout_hex": s["payout"].hex(), "bits": s["bits"], "job_nonce": str(s["job_nonce"]),
                  "version": s["version"], "time": s["time"], "nonce": s["nonce"]},
        "header_hex": header_of(s, attested["stream"]).hex(),
        "share_id_hex": share_id(s).hex(),
        "wire_hex": wire(s).hex(),
        "verdict": verdict,
        "work": str(w),
    }


def window_cases() -> list:
    k = [pr.key("obb-window", i) for i in range(4)]
    a, b, c, e = k
    sets = []
    # One key's work in epoch 0 only: weight in W(2) ..= W(113).
    st = {"epoch_work": {0: {a: 1_000}}, "banned": {}, "decay": {}}
    sets.append(("epoch0_counts_112_epochs", st, [1, 2, 3, 30, 31, 112, 113, 114, 115]))
    # Steady work by three keys over 120 epochs, a ban of 112 epochs, saturation.
    # (Inactivity decay is package O4's: ObenBlock halves, docs §5.2.)
    st = {"epoch_work": {x: {a: 10_000, b: 3_000 + x, c: 7} for x in range(120)}, "banned": {c: 5 + 112},
          "decay": {}}
    st["epoch_work"][50][e] = pr.U128_MAX
    sets.append(("steady_ban_saturation", st, [2, 29, 30, 50, 52, 116, 117, 118, 121, 122, 160, 164, 165]))
    out = []
    for name, st, epochs in sets:
        out.append({"name": name, "state": pr.state_json(st), "epochs": [{
            "epoch": x,
            "obenblock": pr.ws_json(pr.witness_set(st, OBB_PARAMS, x, pr.H2)),
            "total_obenblock": str(pr.total_weight(st, OBB_PARAMS, x, pr.H2)),
            "gnb_mainnet": pr.ws_json(pr.witness_set(st, pr.PARAMS["mainnet"], x, pr.H2)),
        } for x in epochs]})
    return out


def generate() -> dict:
    return {
        "format": "obb-share-vectors-v1",
        "description": "ObenBlock SHA-256d witness shares and the 112-epoch window (reference/obb_shares.py)",
        "constants": {
            "ds_idx": DS_IDX.decode(), "ds_job": DS_JOB.decode(), "ds_id": DS_ID.decode(),
            "share_target_factor": 1 << SHARE_TARGET_SHIFT, "sample_chunks": SAMPLE_CHUNKS,
            "chunk_bytes": CHUNK_BYTES, "max_payout_script": MAX_PAYOUT_SCRIPT,
            "block_version": o.BLOCK_VERSION, "window_epochs": OBB_WINDOW_EPOCHS,
            "params": OBB_PARAMS,
        },
        "jobs": job_cases(),
        "shares": share_cases(),
        "windows": window_cases(),
    }


def serialized() -> bytes:
    return (json.dumps(generate(), indent=1) + "\n").encode()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    data = serialized()
    if args.check:
        if VECTOR_FILE.read_bytes() != data:
            raise SystemExit(f"{VECTOR_FILE.name} is stale: run python3 reference/obb_shares.py")
        print(f"{VECTOR_FILE.name}: up to date")
        return
    VECTOR_FILE.write_bytes(data)
    print(f"wrote {VECTOR_FILE.name}")


if __name__ == "__main__":
    main()
