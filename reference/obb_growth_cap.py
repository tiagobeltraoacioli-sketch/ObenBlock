"""ObenBlock growth cap on the finality weight W -- executable reference.

docs/DESIGN-obenblock.md §6.3 (owner, 2026-10-18), under PoCI
(docs/DESIGN-obenblock-poci.md §2 and §4): the cap computes the weights of
every new finality configuration. ObenBlock only; GnB's PoWit rules
(powit_reference.py) are unchanged. Written from the specification with
integer arithmetic only. The Rust implementation must reproduce
`obb_growth_cap_vectors.json` exactly.

    python3 reference/obb_growth_cap.py            # regenerate obb_growth_cap_vectors.json
    python3 reference/obb_growth_cap.py --check    # CI: the file is what this generates
    python3 reference/obb_growth_cap_test.py -v    # the reference's own tests

Credits, not raw work. The weight of key k in configuration C_x is the sum
of its admitted CREDITS over the window epochs of x, n in
max(0, x-1-window) ..= x-2 (the PoWit window, lag 2; ObenBlock window =
112). A credit is what the cap admitted of the key's finalized share work of
epoch n. Raw share work that the cap does not admit is dropped and never
counted later.

One cap step builds C_x from C_{x-1} (x >= 2). The epoch entering the window
is n = x-2, the one leaving it is o = x-2-window (none while o < 0):

    W     = total(C_{x-1})                       eligible weight of the previous
                                                 configuration (0 when it is empty)
    N_k   = finalized share work of key k in epoch n        (u128, as PoWit sums it)
    R_k   = credit of key k in epoch o (leaving the window; 0 if none)
    N_k   = 0 for every key excluded at x (banned or exited): its work is
            dropped and does not compete for the budget
    renew_k = min(N_k, R_k)                      renewal first
    x_k     = N_k - renew_k
    G       = max(floor(W / 64), G_min(n))       GROWTH_DIV = 64
    S       = sum over k of x_k                  exact (see "Arithmetic")
    admit_k = x_k                                if S <= G
            = floor(x_k * G / S)                 otherwise (pro rata, exact product)
    credit_k(n) = renew_k + admit_k
    weight_k(x) = weight_k(x-1) - R_k + credit_k(n)    = sum of k's credits in x's window
    C_x     = (k, weight_k(x)) for every key not excluded at x with weight > 0,
              sorted by key_id ascending; total(C_x) = sum of those weights.

    G_min(n) = floor(epoch_len * MAX_SHARES_PER_BLOCK * share_work(b_n) / 8)
               (saturating at 2^128-1), b_n = the compact bits of the first
               block of epoch n (height act + n * epoch_len; on a chain, the
               first block of epoch n on its selected chain that has a PoWit
               state, so for n = 0 the block at height 1), share_work(b) =
               min(floor(2^256 / (share_target + 1)), 2^128-1), share_target =
               min(target(b) * 16, 2^256-1), malformed bits -> 0 work.
               That is 1/8 of the share work an epoch can carry (16 slots per
               block, every share at the epoch's share target).

Handoffs (PoCI §4). A handoff from C_e to C_{e+j} (j >= 1) runs the step for
x = e+1, ..., e+j in order, each from finalized history, so C_x depends on
the finalized history only, never on when handoffs happened. Exclusions
(bans, exits) are evaluated at each x; an excluded key keeps the credits it
already has (they expire on schedule) and is back in C with them when the
exclusion ends.

Arithmetic. Every N_k, R_k, credit, weight and total is a u128 (weights and
totals saturate at 2^128-1 exactly as powit_reference.py's sums; real
difficulty keeps them far below). S and x_k * G need more than 128 bits in
the worst case (up to 11,520 shares per epoch): the reference computes them
exactly, the Rust code must use 256-bit intermediates (u128 x u128 -> U256,
then a U256 / U256 floor). Saturating S would shrink the denominator and admit
more than G; it is not allowed.

Interface for the PoCI reference and the Rust consensus code:

- `cap_step(prev_weights, new_work, expiring, g_min, w_total=None,
   excluded=()) -> StepResult`: one step on plain dicts {key_id: int}.
   prev_weights holds every key with weight > 0 including excluded ones;
   w_total defaults to the total of prev_weights over the keys not excluded.
- `advance(ledger, history, to_epoch, exclusions, params) -> (ledger, reports)`
   and `configuration(ledger, exclusions) -> [(key_id_hex, weight_int)]`:
   the stateful form. ledger = {"epoch": x, "credits": {n: {key: credit}}}
   holding the window epochs of x; history = {"share_work": {n: {key: work}},
   "first_block_bits": {n: bits}}; exclusions = [(key, from, until)],
   excluded at x iff from <= x < until.
- JSON (vectors): keys are lowercase hex key ids (20 bytes, PoWit witness
   ids), every u128 is a decimal string, entries are [key_hex, "weight"]
   lists sorted by key; see `generate()` for the case layout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import gnb_difficulty as d

VECTOR_FILE = Path(__file__).with_name("obb_growth_cap_vectors.json")

U128_MAX = 2**128 - 1
GROWTH_DIV = 64
G_MIN_DIV = 8
MAX_SHARES_PER_BLOCK = 16
SHARE_TARGET_SHIFT = 4
MAX_TARGET = 2**256 - 1

PARAMS = {
    # ObenBlock mainnet (DESIGN-obenblock.md §6.2): 6-hour epochs of 720 blocks, 112-epoch window.
    "obenblock": {"epoch_len": 720, "window_epochs": 112},
    # Small window for readable vectors only (not a network's parameters).
    "small": {"epoch_len": 20, "window_epochs": 3},
}


def sat_add(a: int, b: int) -> int:
    return min(a + b, U128_MAX)


# ── G_min ────────────────────────────────────────────────────────────────────

def share_target(block_target: int) -> int:
    return min(block_target << SHARE_TARGET_SHIFT, MAX_TARGET)


def share_work(bits: int) -> int:
    t = d.bits_to_target_or_zero(bits)
    if t == 0:
        return 0
    return min((1 << 256) // (share_target(t) + 1), U128_MAX)


def g_min(epoch_len: int, bits: int) -> int:
    return min(epoch_len * MAX_SHARES_PER_BLOCK * share_work(bits) // G_MIN_DIV, U128_MAX)


# ── One step ─────────────────────────────────────────────────────────────────

@dataclass
class StepResult:
    weights: dict           # key -> weight after the step (every key with weight > 0, excluded too)
    credit: dict            # key -> credit of the entering epoch (> 0 only)
    w: int                  # W used for the budget
    g: int                  # growth budget G
    sum_x: int              # S: excess over renewal, before the cap
    renewed: int            # sum of renew_k
    admitted: int           # sum of admit_k
    dropped: int            # sum of N_k not credited (excess cut by the cap and excluded keys' work)
    admitted_new: int = 0   # admitted to keys without weight before the step
    excluded_work: int = 0  # part of `dropped` that excluded keys mined
    per_key: dict = field(default_factory=dict)   # key -> (N, R, renew, x, admit)


def cap_step(prev_weights: dict, new_work: dict, expiring: dict, g_min_value: int,
             w_total: int | None = None, excluded=frozenset()) -> StepResult:
    for k, r in expiring.items():
        if r > prev_weights.get(k, 0):
            raise ValueError(f"expiring credit of {k!r} exceeds its weight")
    if w_total is None:
        w_total = 0
        for k, w in prev_weights.items():
            if k not in excluded:
                w_total = sat_add(w_total, w)
    renew, xs, excl = {}, {}, 0
    for k, n in new_work.items():
        if n < 0 or n > U128_MAX:
            raise ValueError("share work must be a u128")
        if n == 0:
            continue
        if k in excluded:
            excl += n
            continue
        rn = min(n, expiring.get(k, 0))
        renew[k] = rn
        xs[k] = n - rn
    g = max(w_total // GROWTH_DIV, g_min_value)
    s = sum(xs.values())
    admit = dict(xs) if s <= g else {k: x * g // s for k, x in xs.items()}
    credit = {}
    for k in sorted(set(renew) | set(admit)):
        c = renew.get(k, 0) + admit.get(k, 0)
        if c:
            credit[k] = c
    weights = {}
    for k in set(prev_weights) | set(credit):
        w = sat_add(prev_weights.get(k, 0) - expiring.get(k, 0), credit.get(k, 0))
        if w:
            weights[k] = w
    total_n = sum(new_work.values())
    per_key = {k: (new_work.get(k, 0), expiring.get(k, 0), renew.get(k, 0), xs.get(k, 0), admit.get(k, 0))
               for k in sorted(set(new_work) | set(expiring))}
    return StepResult(
        weights=weights, credit=credit, w=w_total, g=g, sum_x=s,
        renewed=sum(renew.values()), admitted=sum(admit.values()),
        dropped=total_n - sum(credit.values()),
        admitted_new=sum(a for k, a in admit.items() if prev_weights.get(k, 0) == 0),
        excluded_work=excl, per_key=per_key)


# ── Stateful form: ledger of credits, handoffs ───────────────────────────────

def empty_ledger() -> dict:
    """The ledger of C_1 (and C_0): no window epoch yet."""
    return {"epoch": 1, "credits": {}}


def is_excluded(exclusions, key, x: int) -> bool:
    return any(k == key and lo <= x < hi for k, lo, hi in exclusions)


def excluded_at(exclusions, x: int) -> frozenset:
    return frozenset(k for k, lo, hi in exclusions if lo <= x < hi)


def ledger_weights(ledger: dict) -> dict:
    out = {}
    for n in sorted(ledger["credits"]):
        for k, c in ledger["credits"][n].items():
            out[k] = sat_add(out.get(k, 0), c)
    return {k: w for k, w in out.items() if w}


def configuration(ledger: dict, exclusions=()) -> list:
    """C_x of the ledger at epoch x: [(key_id_hex, weight)], sorted by key."""
    ex = excluded_at(exclusions, ledger["epoch"])
    return [(k.hex(), w) for k, w in sorted(ledger_weights(ledger).items()) if k not in ex]


def total(entries: list) -> int:
    t = 0
    for _, w in entries:
        t = sat_add(t, w)
    return t


def advance(ledger: dict, history: dict, to_epoch: int, exclusions=(), params=PARAMS["obenblock"]):
    """Run the cap from the ledger's epoch to `to_epoch` (a handoff, possibly
    skipping epochs). Returns (new ledger, [per-step reports])."""
    x0 = ledger["epoch"]
    if to_epoch < x0:
        raise ValueError("the window only moves forward")
    credits = {n: dict(m) for n, m in ledger["credits"].items()}
    weights = ledger_weights(ledger)
    reports = []
    for x in range(x0 + 1, to_epoch + 1):
        n = x - 2
        o = x - 2 - params["window_epochs"]
        prev_ex = excluded_at(exclusions, x - 1)
        w_total = 0
        for k, w in weights.items():
            if k not in prev_ex:
                w_total = sat_add(w_total, w)
        if n < 0:
            reports.append(None)
            continue
        expiring = credits.pop(o, {}) if o >= 0 else {}
        gm = g_min(params["epoch_len"], history["first_block_bits"][n])
        r = cap_step(weights, history["share_work"].get(n, {}), expiring, gm, w_total, excluded_at(exclusions, x))
        if r.credit:
            credits[n] = r.credit
        weights = r.weights
        reports.append(r)
    return {"epoch": to_epoch, "credits": credits}, reports


# ── Bound ────────────────────────────────────────────────────────────────────

def epochs_to_grow(factor_num: int, factor_den: int = 1) -> int:
    """Smallest t with (65/64)^t > factor (exact): W_t = W_0 (65/64)^t at most."""
    t = 0
    while (GROWTH_DIV + 1) ** t * factor_den <= factor_num * GROWTH_DIV ** t:
        t += 1
    return t


# ── Vectors ──────────────────────────────────────────────────────────────────

def key(label: str, i: int) -> bytes:
    return hashlib.sha3_256(b"obb-growth-cap-key" + label.encode() + i.to_bytes(4, "little")).digest()[:20]


EASY_BITS = 0x207FFFFF        # regtest-like target: share work 1 (G_min = epoch_len * 16 / 8)
POW_LIMIT_BITS = 0x1D00FFFF   # Bitcoin's pow limit


def kmap(m: dict) -> dict:
    return {k.hex(): str(v) for k, v in sorted(m.items())}


def step_json(r: StepResult) -> dict:
    return {"w": str(r.w), "g": str(r.g), "sum_x": str(r.sum_x), "renewed": str(r.renewed),
            "admitted": str(r.admitted), "dropped": str(r.dropped), "admitted_new": str(r.admitted_new),
            "credit": kmap(r.credit), "weights": kmap(r.weights)}


def step_cases() -> list:
    a, b, c, z = (key("step", i) for i in range(4))
    cases = [
        ("under_budget_all_admitted", {a: 6_400}, {a: 60, b: 40}, {}, 0, None, []),
        ("renewal_first_then_pro_rata", {a: 6_400, b: 6_400}, {a: 300, b: 10, c: 900}, {a: 200, b: 200}, 0, None, []),
        ("g_min_dominates", {a: 64}, {b: 1_000}, {}, 37, None, []),
        ("pro_rata_floors", {a: 64 * 7}, {b: 1, c: 1, z: 1}, {}, 0, None, []),
        ("expiry_without_renewal", {a: 500, b: 500}, {}, {a: 200}, 0, None, []),
        ("excluded_work_dropped_and_not_competing", {a: 6_400, b: 6_400}, {a: 500, c: 500}, {a: 100}, 0, None, [a]),
        ("explicit_w_total", {a: 6_400}, {c: 10_000}, {}, 0, 12_800, []),
        ("exact_256_bit_intermediates", {a: U128_MAX}, {b: U128_MAX, c: U128_MAX - 1, z: 3}, {}, 0, None, []),
    ]
    out = []
    for name, pw, nw, ex, gm, wt, excl in cases:
        r = cap_step(pw, nw, ex, gm, wt, frozenset(excl))
        out.append({"name": name, "prev_weights": kmap(pw), "new_work": kmap(nw), "expiring": kmap(ex),
                    "g_min": str(gm), "w_total": None if wt is None else str(wt),
                    "excluded": sorted(k.hex() for k in excl), "result": step_json(r)})
    return out


def sequence_cases() -> list:
    """Stateful cases on the small window: handoffs, skips, exclusions."""
    p = PARAMS["small"]
    a, b, c, z = (key("seq", i) for i in range(4))
    hist = {"share_work": {0: {a: 400, b: 400}, 1: {a: 400, b: 400, c: 4_000}, 2: {a: 400, b: 400, c: 4_000},
                           3: {a: 400, c: 4_000}, 4: {b: 400, c: 4_000, z: 50}, 5: {a: 1, b: 800, c: 4_000},
                           6: {a: 400, b: 400}, 7: {}},
            "first_block_bits": {n: EASY_BITS for n in range(8)}}
    out = []
    for name, handoffs, excl in (
        ("every_epoch", list(range(2, 10)), []),
        ("skipping_handoffs", [4, 9], []),
        ("ban_of_c_from_4_to_7", list(range(2, 10)), [(c, 4, 7)]),
    ):
        led = empty_ledger()
        steps = []
        for h in handoffs:
            led, reps = advance(led, hist, h, excl, p)
            steps.append({"to_epoch": h, "steps": [None if r is None else step_json(r) for r in reps],
                          "credits": {str(n): kmap(m) for n, m in sorted(led["credits"].items())},
                          "configuration": [[k, str(w)] for k, w in configuration(led, excl)],
                          "total": str(total(configuration(led, excl)))})
        out.append({"name": name, "params": "small",
                    "history": {"share_work": {str(n): kmap(m) for n, m in sorted(hist["share_work"].items())},
                                "first_block_bits": {str(n): b_ for n, b_ in sorted(hist["first_block_bits"].items())}},
                    "exclusions": [[k.hex(), lo, hi] for k, lo, hi in excl], "handoffs": steps})
    return out


def flood_scenario(k_mult: int, epochs: int = 130, honest_keys: int = 10, attacker_keys: int = 5,
                   per_key: int = 1_000_000, params=PARAMS["obenblock"]):
    """Honest-only W at steady state over the full window (every honest key
    credits `per_key` each epoch), then from epoch x0 an attacker brings
    k_mult times the honest share work on new keys. Returns the per-epoch
    trace: (x, W, attacker weight, honest weights, report)."""
    win = params["window_epochs"]
    honest = [key("honest", i) for i in range(honest_keys)]
    attacker = [key(f"attacker-{k_mult}", i) for i in range(attacker_keys)]
    x0 = win + 2
    led = {"epoch": x0 - 1, "credits": {n: {h: per_key for h in honest} for n in range(0, win)}}
    attack_per_key = k_mult * per_key * honest_keys // attacker_keys
    hist = {"share_work": {}, "first_block_bits": {}}
    for n in range(0, x0 + epochs):
        m = {h: per_key for h in honest}
        if n >= x0 - 2:
            m.update({a: attack_per_key for a in attacker})
        hist["share_work"][n] = m
        hist["first_block_bits"][n] = EASY_BITS
    trace = []
    for x in range(x0, x0 + epochs):
        led, (rep,) = advance(led, hist, x, (), params)
        w = ledger_weights(led)
        trace.append((x, sum(w.values()), sum(w.get(a, 0) for a in attacker), [w.get(h, 0) for h in honest], rep))
    return trace, honest, attacker


def first_strict_two_thirds(trace) -> int | None:
    for i, (_, tot, att, _, _) in enumerate(trace):
        if 3 * att > 2 * tot:
            return i + 1
    return None


def flood_cases() -> list:
    out = []
    for k in (2, 10, 100):
        trace, honest, attacker = flood_scenario(k)
        out.append({"k": k, "epochs_to_strict_two_thirds": first_strict_two_thirds(trace),
                    "trace": [{"epoch": x, "total": str(t), "attacker": str(a), "g": str(r.g),
                               "admitted_new": str(r.admitted_new), "dropped": str(r.dropped)}
                              for x, t, a, _, r in trace[:75]]})
    return out


def launch_case() -> dict:
    """From genesis: one honest pool filling every slot (8 G_min per epoch)."""
    p = PARAMS["obenblock"]
    gm = g_min(p["epoch_len"], POW_LIMIT_BITS)
    full = 8 * gm
    h = [key("launch", i) for i in range(4)]
    hist = {"share_work": {n: {k: full // 4 for k in h} for n in range(80)},
            "first_block_bits": {n: POW_LIMIT_BITS for n in range(80)}}
    led = empty_ledger()
    rows = []
    for x in range(2, 80):
        led, (r,) = advance(led, hist, x, (), p)
        rows.append({"epoch": x, "w": str(r.w), "g": str(r.g), "admitted": str(r.admitted),
                     "total": str(total(configuration(led)))})
    return {"bits": POW_LIMIT_BITS, "share_work": str(share_work(POW_LIMIT_BITS)), "g_min": str(gm),
            "work_per_epoch": str(full), "steps": rows}


def generate() -> dict:
    gmins = [{"epoch_len": el, "bits": b, "share_work": str(share_work(b)), "g_min": str(g_min(el, b))}
             for el in (720, 20) for b in (POW_LIMIT_BITS, 0x17034219, EASY_BITS, 0x1D00FFFF | 0x00800000, 0x03000001)]
    return {
        "format": "obb-growth-cap-vectors-v1",
        "description": "ObenBlock growth cap on W (docs/DESIGN-obenblock.md §6.3; reference/obb_growth_cap.py)",
        "constants": {"growth_div": GROWTH_DIV, "g_min_div": G_MIN_DIV, "max_shares_per_block": MAX_SHARES_PER_BLOCK,
                      "share_target_shift": SHARE_TARGET_SHIFT, "params": PARAMS,
                      "epochs_to_triple_w": epochs_to_grow(3), "epochs_to_double_w": epochs_to_grow(2)},
        "g_min": gmins,
        "steps": step_cases(),
        "sequences": sequence_cases(),
        "floods": flood_cases(),
        "launch": launch_case(),
    }


def serialized() -> bytes:
    return (json.dumps(generate(), indent=1) + "\n").encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if obb_growth_cap_vectors.json differs")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if not VECTOR_FILE.exists() or VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("growth cap vectors differ from the reference; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    doc = json.loads(contents)
    print(f"{len(doc['steps'])} steps, {len(doc['sequences'])} sequences, {len(doc['floods'])} floods; "
          f"sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
