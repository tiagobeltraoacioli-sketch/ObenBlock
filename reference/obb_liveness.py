"""ObenBlock liveness -- executable reference specification.

docs/DESIGN-obenblock.md section 5: the stall relief of block production
(5.1), the faster inactivity leak of finality (5.2) and the witness exit
message. Written from the specification with hashlib and the GnB
difficulty reference only. `crates/gnb-smh/src/stall_relief.rs`,
`crates/gnb-crypto/src/core/liveness.rs` and `crates/gnb-crypto/src/core/powit.rs`
must reproduce `liveness_vectors.json` exactly
(`crates/gnb-crypto/tests/liveness_vectors.rs`).

    python3 reference/obb_liveness.py            # regenerate liveness_vectors.json
    python3 reference/obb_liveness.py --check    # CI: the file is what this generates
    python3 reference/obb_liveness_test.py -v    # the reference's own tests

Activation. Each chain selects a liveness activation height L (GnB mainnet
and testnet: never; ObenBlock: 0). Stall relief applies to a block at header
height h iff h >= L; a block may carry witness exits iff h >= L, and only then
does its PoWit section carry the exits list on the wire. The leak rule is a
PoWit parameter of the chain (GnB: 1/16, ObenBlock: 1/2), because decay
steps are stored as counts.

Stall relief (5.1). For a block stamped `time` whose ASERT bits are
`base_bits` (from `parent_time`, the latest timestamp over its parents):

    late     = max(0, time - parent_time - 180)
    steps    = floor(late / 60)
    exponent = floor(steps * 60 * 65536 / 1800)
    shifts   = floor(exponent / 65536);  frac = exponent mod 65536
    factor   = 65536 + ((195766423245049*frac + 971821376*frac^2 + 5127*frac^3 + 2^47) >> 48)
    relaxed  = floor(target(base_bits) * factor * 2^(shifts - 16))
    bits     = base_bits                                          if steps = 0
               bits(max(target(base_bits), min(pow_limit, relaxed)))  otherwise
               (and base_bits again when that max is target(base_bits) itself)

Leak (5.2). After `leak_after_epochs` epochs without finality, every member
of W(e) whose votes were not included in epoch e gains one decay step at the
boundary e -> e+1 (unchanged). A weight after n steps is

    GnB (1/16):      n' = min(n, 64) times  w -= w // 16
    ObenBlock (1/2): ceil(w / 2^min(n, 128))

Witness exit. A witness signs, with the KES leaf of epoch `epoch`,

    msg_exit = SHA3-256( u32le(17) || "OBB-POWIT-v1/exit" || u32le(chain_id)
                         || u8(depth) || root[32] || u64le(epoch) )      # 66-byte preimage

A block of PoWit epoch E (h >= L) may carry at most 4 exits; an exit is
valid in it iff epoch <= E <= epoch + 1, its key k = witness_id(depth, root)
has share work in the state's kept epochs, k has not exited already (in the
state or earlier in the block), and the signature verifies. It records
exited[k] = E + 1: from W(E+1) on, k is not a member; shares credited to k are
invalid while the record lives; k stays provable for equivocation while the
record lives. The record is dropped at an epoch boundary once k has no share
work left in the kept epochs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import gnb_difficulty as d
import powit_reference as pr

VECTOR_FILE = Path(__file__).with_name("liveness_vectors.json")

# Chain ids (DESIGN-obenblock.md section 2; ObenBlock's are raw u32 here).
CHAIN_GNB_MAINNET = 0x474E_0001
CHAIN_GNB_TESTNET = 0x474E_0002
CHAIN_OBB_MAINNET = 0x4F42_0001
CHAIN_OBB_REGTEST = 0x4F42_0002

# Stall relief.
TARGET_SPACING = 30
GRACE_SECS = 6 * TARGET_SPACING
STEP_SECS = 60
RELIEF_HALFLIFE = 1_800
OBB_POW_LIMIT_BITS = 0x1D00FFFF
MAX_FUTURE_SECS = 600

# Leak.
LEAK_SIXTEENTH = "sixteenth"
LEAK_HALF = "half"
HALF_STEP_CAP = 128

# Exits.
DS_EXIT = b"OBB-POWIT-v1/exit"
MAX_EXITS_PER_BLOCK = 4
U128_MAX = 2**128 - 1


# ── Stall relief ─────────────────────────────────────────────────────────────

def relief_steps(parent_time: int, time: int) -> int:
    late = max(0, time - parent_time - GRACE_SECS)
    return late // STEP_SECS


def relieved_target(base: int, parent_time: int, time: int, pow_limit: int) -> int:
    steps = relief_steps(parent_time, time)
    if steps == 0 or base == 0:
        return base
    exponent = (steps * STEP_SECS * 65536) // RELIEF_HALFLIFE
    shifts = exponent >> 16
    frac = exponent & 0xFFFF
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac ** 2
                       + 5127 * frac ** 3 + (1 << 47)) >> 48)
    if shifts >= 256:
        relaxed = pow_limit
    else:
        net = shifts - 16
        product = base * factor
        relaxed = product << net if net >= 0 else product >> -net
        relaxed = min(relaxed, pow_limit)
    return max(relaxed, base)


def relieved_bits(base_bits: int, parent_time: int, time: int, pow_limit_bits: int) -> int:
    if relief_steps(parent_time, time) == 0:
        return base_bits
    try:
        base = d.bits_to_target(base_bits)
    except d.BitsError:
        return base_bits
    t = relieved_target(base, parent_time, time, d.bits_to_target_or_zero(pow_limit_bits))
    return base_bits if t == base else d.target_to_bits(t)


def expected_block_bits(parent_time: int, height: int, time: int, *, anchor_bits: int, anchor_time: int,
                        pow_limit_bits: int, liveness_height: int = 0) -> int:
    """ASERT bits from an anchor at height 0 (no GnB-SMH v3 shift), then the
    relief when `height >= liveness_height`."""
    base = d.asert_next_bits(parent_time, height, anchor_bits=anchor_bits, anchor_time=anchor_time,
                             pow_limit_bits=pow_limit_bits)
    if height < liveness_height:
        return base
    return relieved_bits(base, parent_time, time, pow_limit_bits)


# ── Leak ─────────────────────────────────────────────────────────────────────

def decayed_with(leak: str, w: int, steps: int) -> int:
    if leak == LEAK_SIXTEENTH:
        return pr.decayed(w, steps)
    s = min(steps, HALF_STEP_CAP)
    return (w + (1 << s) - 1) >> s


def halvings_needed(absent: int, present: int) -> int:
    """Smallest n with 3 * present >= 2 * (present + ceil(absent / 2^n))."""
    n = 0
    while not pr.two_thirds(present, present + decayed_with(LEAK_HALF, absent, n)):
        n += 1
    return n


def resume_epoch(absent: int, present: int, leak: str, leak_after: int, phase: int, epoch_len: int):
    """First epoch whose W(e) lets the present weight justify, when the last
    finality was at height `phase` (0 <= phase < epoch_len) of epoch 0: the
    boundary into epoch n is applied by a block at height n * epoch_len and
    adds a step iff n * epoch_len - phase >= leak_after * epoch_len (the
    stalled test of `PowitState::apply_at`). None when the leak never gets
    there: the GnB rule counts at most 64 steps (15/16^64 ~ 1.6 %), so it
    cannot restore finality once more than about 97 % of the weight left."""
    steps, n = 0, 0
    while not pr.two_thirds(present, present + decayed_with(leak, absent, steps)):
        n += 1
        if n * epoch_len - phase >= leak_after * epoch_len:
            steps += 1
        if steps > HALF_STEP_CAP + 1:
            return None
    return n


# ── Exit ─────────────────────────────────────────────────────────────────────

def exit_preimage(chain: int, depth: int, root: bytes, epoch: int) -> bytes:
    assert 0 <= depth <= 255 and len(root) == 32
    return b"".join([pr.u32le(len(DS_EXIT)), DS_EXIT, pr.u32le(chain), bytes([depth]), root, pr.u64le(epoch)])


def exit_message(chain: int, depth: int, root: bytes, epoch: int) -> bytes:
    return pr.sha3(exit_preimage(chain, depth, root, epoch))


def exit_epoch_ok(block_epoch: int, exit_epoch: int) -> bool:
    return exit_epoch <= block_epoch <= exit_epoch + 1


def witness_set(state: dict, params: dict, epoch: int, leak: str) -> list[tuple[bytes, int]]:
    """W(epoch) from the second hardening activation (every key with
    weight) with the chain's leak and the exits: a key with exited[k] <= epoch
    is not a member."""
    if epoch < 2:
        return []
    lo, hi = pr.window(params, epoch)
    total: dict[bytes, int] = {}
    for e, m in state["epoch_work"].items():
        if lo <= e <= hi:
            for k, w in m.items():
                total[k] = pr.sat_add(total.get(k, 0), w)
    out = []
    for k in sorted(total):
        if pr.is_banned(state, k, epoch):
            continue
        x = state.get("exited", {}).get(k)
        if x is not None and x <= epoch:
            continue
        w = decayed_with(leak, total[k], state["decay"].get(k, 0))
        if w > 0:
            out.append((k, w))
    out.sort(key=lambda kw: (-kw[1], kw[0]))
    return out


# ── Vectors ──────────────────────────────────────────────────────────────────

def key(label: str, i: int) -> bytes:
    return pr.sha3(b"liveness-vector-key", label.encode(), pr.u32le(i))[:20]


def generate() -> dict:
    limit = OBB_POW_LIMIT_BITS
    relief = []
    for base_bits in [0x1B0404CB, 0x1D00FFFF, 0x1C7FFFFF, 0x17053894, 0x1A01E0FF]:
        for dt in [-5, 0, 179, 180, 239, 240, 241, 299, 300, 1_979, 1_980, 3_780, 3_839,
                   7_380, 21_600, 21_600 + MAX_FUTURE_SECS, 86_400, 10**7, 2**40]:
            parent = 1_800_000_000
            relief.append({"base_bits": base_bits, "parent_time": parent, "time": parent + dt,
                           "pow_limit_bits": limit, "steps": relief_steps(parent, parent + dt),
                           "bits": relieved_bits(base_bits, parent, parent + dt, limit)})
    # Large lateness against a GnB-style limit, and a base above the limit.
    for base_bits, lim, dt in [(0x1F0E9036, 0x2100FFFF, 500_000), (0x1E00FFFF, 0x1D00FFFF, 50_000),
                               (0x2000FFFF, 0x2100FFFF, 3_600)]:
        relief.append({"base_bits": base_bits, "parent_time": 0, "time": dt, "pow_limit_bits": lim,
                       "steps": relief_steps(0, dt), "bits": relieved_bits(base_bits, 0, dt, lim)})

    anchor_bits, anchor_time = 0x1B0404CB, 1_800_000_000
    blocks = []
    for height, parent_off, dt, lh in [(1, 0, 30, 0), (1, 0, 600, 0), (2, 30, 3_600, 0), (100, 2_970, 200, 0),
                                       (100, 2_970, 10_000, 0), (100, 2_970, 10_000, 101), (5, -7_200, 7_400, 0),
                                       (1_000, 50_000, 21_600, 0), (10, 300, 100_000_000, 0)]:
        pt = anchor_time + parent_off
        blocks.append({"height": height, "parent_time": pt, "time": pt + dt, "liveness_height": lh,
                       "asert_bits": d.asert_next_bits(pt, height, anchor_bits=anchor_bits, anchor_time=anchor_time,
                                                       pow_limit_bits=limit),
                       "bits": expected_block_bits(pt, height, pt + dt, anchor_bits=anchor_bits,
                                                   anchor_time=anchor_time, pow_limit_bits=limit,
                                                   liveness_height=lh)})

    decayed = []
    for w in [0, 1, 2, 3, 15, 16, 17, 1_000_003, 2**64 + 1, U128_MAX]:
        for n in [0, 1, 2, 3, 7, 64, 65, 127, 128, 129, 1_000]:
            decayed.append({"weight": str(w), "steps": n, "half": str(decayed_with(LEAK_HALF, w, n)),
                            "sixteenth": str(decayed_with(LEAK_SIXTEENTH, w, n))})

    mp = pr.PARAMS["mainnet"]
    schedule = []
    for a_pct in [34, 50, 75, 90, 99]:
        absent, present = a_pct * 10**16, (100 - a_pct) * 10**16
        row = {"absent_pct": a_pct, "halvings": halvings_needed(absent, present), "resume": {}}
        for leak in [LEAK_HALF, LEAK_SIXTEENTH]:
            row["resume"][leak] = {
                "best_epoch": resume_epoch(absent, present, leak, mp["leak_after_epochs"], 0, mp["epoch_len"]),
                "worst_epoch": resume_epoch(absent, present, leak, mp["leak_after_epochs"], mp["epoch_len"] - 1,
                                            mp["epoch_len"]),
            }
        schedule.append(row)

    exits = []
    for chain in [CHAIN_GNB_MAINNET, CHAIN_GNB_TESTNET, CHAIN_OBB_MAINNET, CHAIN_OBB_REGTEST]:
        for depth, root_i, epoch in [(12, 0, 0), (12, 1, 7), (1, 2, 1), (12, 3, 4095), (255, 4, 2**64 - 1)]:
            root = pr.sha3(b"liveness-vector-root", pr.u32le(root_i))
            exits.append({"chain_id": chain, "depth": depth, "root": root.hex(), "epoch": str(epoch),
                          "preimage": exit_preimage(chain, depth, root, epoch).hex(),
                          "message": exit_message(chain, depth, root, epoch).hex(),
                          "witness_id": pr.witness_id(depth, root).hex()})
    exit_epochs = [{"block_epoch": b, "exit_epoch": e, "ok": exit_epoch_ok(b, e)}
                   for b in [0, 1, 5] for e in [0, 1, 4, 5, 6]]

    tp = pr.PARAMS["testnet"]
    ks = [key("w", i) for i in range(5)]
    state = {"epoch_work": {3: {ks[0]: 100, ks[1]: 200, ks[2]: 300}, 4: {ks[0]: 50, ks[3]: 400, ks[4]: 7}},
             "banned": {ks[4]: 9}, "decay": {ks[1]: 2, ks[3]: 1},
             "exited": {ks[0]: 6, ks[2]: 7}}
    sets = []
    for epoch in [5, 6, 7, 8]:
        for leak in [LEAK_HALF, LEAK_SIXTEENTH]:
            sets.append({"epoch": epoch, "leak": leak,
                         "set": [[k.hex(), str(w)] for k, w in witness_set(state, tp, epoch, leak)]})
    state_j = pr.state_json(state)
    state_j["exited"] = {k.hex(): x for k, x in sorted(state["exited"].items())}

    return {
        "about": "ObenBlock liveness (DESIGN-obenblock.md section 5): reference/obb_liveness.py",
        "constants": {"grace_secs": GRACE_SECS, "step_secs": STEP_SECS, "relief_halflife": RELIEF_HALFLIFE,
                      "max_exits_per_block": MAX_EXITS_PER_BLOCK, "exit_preimage_len": 66,
                      "half_step_cap": HALF_STEP_CAP},
        "relief": relief,
        "blocks": {"anchor_bits": anchor_bits, "anchor_time": anchor_time, "pow_limit_bits": limit,
                   "cases": blocks},
        "decayed": decayed,
        "leak_schedule": {"params": "mainnet", "rows": schedule},
        "exit_messages": exits,
        "exit_epochs": exit_epochs,
        "witness_sets": {"params": "testnet", "state": state_j, "cases": sets},
    }


def serialized() -> bytes:
    return (json.dumps(generate(), indent=1) + "\n").encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if liveness_vectors.json differs")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if not VECTOR_FILE.exists() or VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("liveness vectors differ from the reference; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    print(f"sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
