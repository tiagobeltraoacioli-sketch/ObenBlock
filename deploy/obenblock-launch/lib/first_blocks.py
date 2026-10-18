#!/usr/bin/env python3
"""When do the first ObenBlock mainnet blocks come, for a given hashrate?

    first_blocks.py [--start-delay SECONDS] [--runs N] [HASHRATE ...]

HASHRATE in hashes per second, with an optional k/M/G/T/P/E suffix
(default: a table from 3 GH/s, the three CPU hosts, to 1 EH/s).
--start-delay is how long after the genesis timestamp the hashrate starts.

Model (docs/DESIGN-obenblock.md §4.2 and §5.1; consensus code in
crates/gnb-smh/src/stall_relief.rs and the ASERT of gnb_smh::difficulty):
  * ASERT anchored at the genesis with the launch bits 0x19009d69 (1 EH/s):
    target(h) = launch * 2^((parent_time - T - 30 (h - 1)) / 7200);
  * stall relief: once a block is 180 s later than its parent its target
    doubles every 1,800 s of lateness, in 60 s steps;
  * both capped at the pow limit 0x1d00ffff (difficulty 1).
The block time a miner stamps is the moment it finds the block (a stratum
proxy and the CPU miner use the current time). Monte Carlo over --runs runs;
medians are printed. The fixed-point details of the consensus code change
the numbers by well under one percent. Standard library only.
"""
import argparse
import math
import random
import statistics

T_BLOCK, HALFLIFE = 30, 7200
GRACE, STEP, RELIEF_HALFLIFE = 180, 60, 1800
LAUNCH_WORK = 30_000_392_575_492_696_099      # sha256d_block_work(0x19009d69)
LIMIT_WORK = 2 ** 256 // (0xFFFF * 2 ** (8 * (0x1D - 3)) + 1)  # difficulty 1, about 2^32
SUFFIX = {"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}


def parse_rate(s):
    unit = s[-1] if s[-1] in SUFFIX and not s[-1].isdigit() else ""
    return float(s[:-1] if unit else s) * SUFFIX[unit]


def human(h):
    for u in ("E", "P", "T", "G", "M", "k"):
        if h >= SUFFIX[u]:
            return f"{h / SUFFIX[u]:g} {u}H/s"
    return f"{h:g} H/s"


def dur(s):
    if s < 120:
        return f"{s:.0f} s"
    if s < 7200:
        return f"{s / 60:.0f} min"
    if s < 172800:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} d"


def expected_hashes(parent_time, height, now, genesis_time):
    """Work (expected hashes) of a block found at `now` on a parent at height-1."""
    asert = (parent_time - genesis_time - T_BLOCK * (height - 1)) / HALFLIFE
    late = max(0.0, now - parent_time - GRACE)
    relief = math.floor(late / STEP) * STEP / RELIEF_HALFLIFE
    return max(LIMIT_WORK, LAUNCH_WORK / 2 ** (asert + relief))


def next_block(rate, parent_time, height, start, genesis_time):
    """Sample the time of the next block (piecewise constant hazard)."""
    need = random.expovariate(1.0)
    t = max(start, parent_time)
    # Step k covers lateness [k*STEP, (k+1)*STEP) after the grace; k = -1 is
    # the grace period. The hazard is constant inside a step.
    late = t - parent_time - GRACE
    k = -1 if late < 0 else int(late // STEP)
    while True:
        nxt = parent_time + GRACE + (k + 1) * STEP
        span = max(nxt - t, 0.0)
        lam = rate / expected_hashes(parent_time, height, parent_time + GRACE + max(k, 0) * STEP + (0 if k >= 0 else -1), genesis_time)
        if lam * span >= need:
            return t + need / lam
        need -= lam * span
        t, k = nxt, k + 1


def simulate(rate, delay, runs, marks):
    out = {m: [] for m in marks}
    for _ in range(runs):
        parent, h = 0.0, 0
        while h < max(marks):
            h += 1
            parent = next_block(rate, parent, h, delay, 0.0)
            if h in out:
                out[h].append(parent)
    return {m: statistics.median(v) for m, v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start-delay", type=float, default=0.0)
    ap.add_argument("--runs", type=int, default=200)
    ap.add_argument("rates", nargs="*")
    a = ap.parse_args()
    rates = [parse_rate(r) for r in a.rates] or [3e9, 1e14, 1e15, 1e16, 1e17, 1e18]
    marks = (1, 10, 100, 1000)
    print("hashrate      block 1    block 10   block 100  block 1000  (median times after the genesis timestamp)")
    for r in rates:
        m = simulate(r, a.start_delay, a.runs, marks)
        print("%-12s %-10s %-10s %-10s %-10s" % (human(r), *(dur(m[k]) for k in marks)))


if __name__ == "__main__":
    main()
