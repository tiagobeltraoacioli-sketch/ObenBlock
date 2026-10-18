"""Tests of the ObenBlock growth-cap reference (reference/obb_growth_cap.py):
the rules of docs/DESIGN-obenblock.md §6.3 and the attacks they must stop.

    python3 reference/obb_growth_cap_test.py -v
"""
from __future__ import annotations

import math
import random
import unittest

import obb_growth_cap as g

OBB = g.PARAMS["obenblock"]
SMALL = g.PARAMS["small"]


def K(label, i=0):
    return g.key(label, i)


class Step(unittest.TestCase):
    def test_invariants_on_random_inputs(self):
        rng = random.Random(0x0B10A)
        keys = [K("fuzz", i) for i in range(12)]
        for _ in range(3_000):
            prev = {k: rng.choice([0, rng.randrange(1, 10**6), rng.randrange(1, 2**127)]) for k in keys}
            prev = {k: w for k, w in prev.items() if w}
            expiring = {k: rng.randrange(0, w + 1) for k, w in prev.items() if rng.random() < 0.5}
            new = {k: rng.choice([0, rng.randrange(1, 10**6), rng.randrange(1, 2**128)]) for k in keys if rng.random() < 0.6}
            excluded = frozenset(k for k in keys if rng.random() < 0.1)
            gm = rng.choice([0, 1, rng.randrange(1, 10**9)])
            r = g.cap_step(prev, new, expiring, gm, None, excluded)
            w = sum(v for k, v in prev.items() if k not in excluded)
            self.assertEqual(r.w, min(w, g.U128_MAX))
            self.assertEqual(r.g, max(r.w // 64, gm))
            self.assertLessEqual(r.admitted, r.g, "the growth budget is never exceeded")
            self.assertEqual(r.dropped + sum(r.credit.values()), sum(new.values()))
            if r.sum_x <= r.g:
                self.assertEqual(r.admitted, r.sum_x, "under budget everything is admitted")
            else:
                self.assertGreater(r.admitted + len(new), r.g - 1, "pro rata loses less than one unit per key")
            for k, (n, rr, rn, x, a) in r.per_key.items():
                if k in excluded:
                    self.assertNotIn(k, r.credit)
                    continue
                self.assertEqual(rn, min(n, rr))
                self.assertLessEqual(a, x)
                self.assertEqual(r.credit.get(k, 0), rn + a)
            for k in set(prev) | set(r.credit):
                want = min(prev.get(k, 0) - expiring.get(k, 0) + r.credit.get(k, 0), g.U128_MAX)
                self.assertEqual(r.weights.get(k, 0), want)

    def test_renewal_comes_before_growth(self):
        a, b, c = K("r", 0), K("r", 1), K("r", 2)
        r = g.cap_step({a: 6_400, b: 6_400}, {a: 300, b: 10, c: 900}, {a: 200, b: 200}, 0)
        self.assertEqual(r.g, 200)
        self.assertEqual(r.renewed, 210)
        self.assertEqual(r.credit, {a: 200 + 100 * 200 // 1000, b: 10, c: 900 * 200 // 1000})

    def test_expiring_more_than_the_weight_is_refused(self):
        a = K("bad")
        with self.assertRaises(ValueError):
            g.cap_step({a: 5}, {}, {a: 6}, 0)

    def test_excluded_keys_neither_gain_nor_take_budget(self):
        a, c = K("ex", 0), K("ex", 1)
        r = g.cap_step({a: 6_400, c: 64_000}, {c: 10_000, K("ex", 2): 10_000}, {}, 0, None, frozenset({c}))
        self.assertEqual(r.w, 6_400, "W is the eligible total")
        self.assertEqual(r.credit, {K("ex", 2): 100})
        r = g.cap_step({a: 6_400}, {a: 10_000, c: 10_000}, {}, 0, None, frozenset({a}))
        self.assertEqual(r.credit, {})  # W = 0 and G_min = 0: nothing admitted
        r = g.cap_step({a: 6_400, c: 6_400}, {a: 10_000, c: 10_000}, {}, 0, None, frozenset({a}))
        self.assertEqual(r.credit, {c: 100})
        self.assertEqual(r.excluded_work, 10_000)

    def test_exact_intermediates(self):
        a, b, c = K("big", 0), K("big", 1), K("big", 2)
        r = g.cap_step({a: g.U128_MAX}, {b: g.U128_MAX, c: g.U128_MAX}, {}, 0)
        self.assertEqual(r.sum_x, 2 * g.U128_MAX, "S is exact, not saturated")
        self.assertEqual(r.credit, {b: g.U128_MAX // 128, c: g.U128_MAX // 128})
        self.assertLessEqual(r.admitted, r.g)


class GMin(unittest.TestCase):
    def test_formula(self):
        bits = g.POW_LIMIT_BITS
        t = g.d.bits_to_target(bits)
        sw = 2**256 // (16 * t + 1)
        self.assertEqual(g.share_work(bits), sw)
        self.assertEqual(g.g_min(720, bits), 720 * 16 * sw // 8)
        self.assertEqual(g.g_min(720, bits), 90 * 16 * sw, "1/8 of the 16-slot epoch")
        self.assertEqual(g.g_min(720, g.EASY_BITS), 1_440)
        self.assertEqual(g.g_min(720, 0x1D00FFFF | 0x00800000), 0, "malformed bits carry no work")
        self.assertEqual(g.g_min(720, 0x03000001), g.U128_MAX, "saturates")


class Bound(unittest.TestCase):
    def test_spec_numbers(self):
        self.assertEqual(g.epochs_to_grow(3), 71)
        self.assertEqual(math.ceil(math.log(3) / math.log(65 / 64)), 71)
        self.assertEqual(g.epochs_to_grow(2), 45)


class Flood(unittest.TestCase):
    """docs §6.3: a k-times flood of new keys against honest-only weight."""

    @classmethod
    def setUpClass(cls):
        cls.traces = {k: g.flood_scenario(k) for k in (2, 10, 100)}

    def test_new_weight_never_exceeds_the_cap(self):
        for k, (trace, honest, attacker) in self.traces.items():
            w0 = trace[0][1] - trace[0][2]
            att_prev = 0
            for t, (x, tot, att, hw, r) in enumerate(trace, start=1):
                self.assertLessEqual(r.admitted, r.g, (k, x))
                self.assertLessEqual(att - att_prev, r.g, (k, x))
                self.assertEqual(r.g, max(r.w // 64, 1_440))
                # Cumulative: W_t <= W_0 (65/64)^t, so attacker weight <= W_0 ((65/64)^t - 1).
                self.assertLessEqual(att * 64**t, w0 * (65**t - 64**t), (k, t))
                att_prev = att

    def test_incumbents_keep_their_weight(self):
        for k, (trace, honest, attacker) in self.traces.items():
            for x, tot, att, hw, r in trace:
                self.assertEqual(hw, [1_000_000 * OBB["window_epochs"]] * len(honest), (k, x))

    def test_strict_two_thirds_needs_at_least_71_epochs(self):
        for k, (trace, _, _) in self.traces.items():
            t = g.first_strict_two_thirds(trace)
            self.assertTrue(t is None or t >= 71, (k, t))
            for x, tot, att, _, _ in trace[:70]:
                self.assertLessEqual(3 * att, 2 * tot, (k, x))
        self.assertEqual(g.first_strict_two_thirds(self.traces[100][0]), 71, "the bound is tight")
        self.assertEqual(g.first_strict_two_thirds(self.traces[10][0]), 71)
        self.assertIsNone(g.first_strict_two_thirds(self.traces[2][0]), "k = 2 never gets there")

    def test_flood_size_does_not_matter_once_capped(self):
        a10 = [att for _, _, att, _, _ in self.traces[10][0]]
        a100 = [att for _, _, att, _, _ in self.traces[100][0]]
        self.assertEqual(a10[:71], a100[:71])

    def test_honest_growth_competes_pro_rata(self):
        # Honest keys also bring new work (a new honest pool): the attacker's
        # share of each budget shrinks, it never grows.
        win = SMALL["window_epochs"]
        h, newh, att = K("hh"), K("newh"), K("att")
        hist = {"share_work": {n: {h: 1_000, **({newh: 50_000, att: 500_000} if n >= win else {})} for n in range(60)},
                "first_block_bits": {n: g.EASY_BITS for n in range(60)}}
        led, reps = g.advance(g.empty_ledger(), hist, 50, (), SMALL)
        for r in reps[win + 1:]:
            if r is None:
                continue
            na, nn = r.per_key[att][4], r.per_key[newh][4]
            self.assertLessEqual(na + nn, r.g)
            self.assertLessEqual(nn * 500_000, (na + 1) * 50_000 + 500_000)

    def test_dropped_work_is_not_deferred(self):
        h, a = K("dh"), K("da")
        hist = {"share_work": {n: {h: 6_400} for n in range(40)}, "first_block_bits": {n: g.EASY_BITS for n in range(40)}}
        hist["share_work"][10] = {h: 6_400, a: 10**20}
        led, reps = g.advance(g.empty_ledger(), hist, 39, (), SMALL)
        credited = [r.credit.get(a, 0) for r in reps if r is not None]
        self.assertEqual(sum(1 for c in credited if c), 1, "credited once, in its own epoch")
        r12 = reps[12 - 2]
        self.assertLessEqual(r12.credit[a], r12.g)
        self.assertNotIn(a, g.ledger_weights(led), "and it expired with the window")

    def test_incumbent_attacker_cannot_renew_more_than_expires(self):
        h, a = K("ih"), K("ia")
        win = SMALL["window_epochs"]
        hist = {"share_work": {n: {h: 64_000, a: 1_000 if n < 5 else 10**12} for n in range(30)},
                "first_block_bits": {n: g.EASY_BITS for n in range(30)}}
        led, reps = g.advance(g.empty_ledger(), hist, 29, (), SMALL)
        for x, r in enumerate(reps, start=2):
            if r is None or x - 2 < 5 + win:
                continue
            n, rr, rn, xa, ad = r.per_key[a]
            self.assertEqual(rn, rr)
            self.assertLessEqual(ad, r.g)


class Launch(unittest.TestCase):
    def test_fill_with_g_min(self):
        case = g.launch_case()
        gm = int(case["g_min"])
        for row in case["steps"]:
            w, gg, adm = int(row["w"]), int(row["g"]), int(row["admitted"])
            self.assertEqual(gg, max(w // 64, gm))
            self.assertLessEqual(adm, gg)
            self.assertGreater(adm, gg - 4, "a full epoch fills the budget, less the pro-rata floors of 4 keys")
            if w < 64 * gm:
                self.assertEqual(gg, gm)
        first = case["steps"][0]
        self.assertEqual(int(first["total"]), gm, "C_2: G_min of epoch 0's work")
        c4 = case["steps"][2]
        self.assertEqual(int(c4["total"]), 3 * gm, "C_4 (PoCI bootstrap): three budgets")
        self.assertGreater(int(case["steps"][-1]["g"]), gm, "W/64 takes over after about 64 epochs")

    def test_empty_epochs_and_no_work(self):
        led, reps = g.advance(g.empty_ledger(), {"share_work": {}, "first_block_bits": {n: g.EASY_BITS for n in range(10)}},
                              11, (), SMALL)
        self.assertEqual(g.configuration(led), [])
        self.assertTrue(all(r is None or r.admitted == 0 for r in reps))


class Handoff(unittest.TestCase):
    def hist(self):
        rng = random.Random(7)
        keys = [K("hk", i) for i in range(6)]
        return {"share_work": {n: {k: rng.randrange(0, 5_000) for k in keys if rng.random() < 0.7} for n in range(40)},
                "first_block_bits": {n: g.EASY_BITS for n in range(40)}}, keys

    def test_path_independence(self):
        hist, keys = self.hist()
        bans = [(keys[1], 9, 14), (keys[4], 20, 25)]
        one, _ = g.advance(g.empty_ledger(), hist, 38, bans, SMALL)
        step = g.empty_ledger()
        for x in range(2, 39):
            step, _ = g.advance(step, hist, x, bans, SMALL)
        rng = random.Random(3)
        skip = g.empty_ledger()
        x = 1
        while x < 38:
            x = min(38, x + rng.randrange(1, 7))
            skip, _ = g.advance(skip, hist, x, bans, SMALL)
        self.assertEqual(one, step)
        self.assertEqual(one, skip)
        self.assertEqual(g.configuration(one, bans), g.configuration(skip, bans))

    def test_ledger_weights_are_the_window_credits(self):
        hist, keys = self.hist()
        led, _ = g.advance(g.empty_ledger(), hist, 30, (), SMALL)
        lo, hi = 30 - 1 - SMALL["window_epochs"], 30 - 2
        self.assertEqual(sorted(led["credits"]), [n for n in range(lo, hi + 1) if n in led["credits"]])
        self.assertTrue(all(lo <= n <= hi for n in led["credits"]))

    def test_ban_drops_work_and_restores_unexpired_credit(self):
        a, b = K("ban", 0), K("ban", 1)
        p = {"epoch_len": 20, "window_epochs": 10}
        hist = {"share_work": {n: {a: 640, b: 640} for n in range(30)}, "first_block_bits": {n: g.EASY_BITS for n in range(30)}}
        bans = [(a, 12, 15)]
        led, reps = g.advance(g.empty_ledger(), hist, 20, bans, p)
        for x, r in enumerate(reps, start=2):
            if 12 <= x < 15:
                self.assertNotIn(a, r.credit)
                self.assertEqual(r.excluded_work, 640)
        led14, _ = g.advance(g.empty_ledger(), hist, 14, bans, p)
        self.assertNotIn(a.hex(), dict(g.configuration(led14, bans)))
        led15, _ = g.advance(led14, hist, 15, bans, p)
        cfg = dict(g.configuration(led15, bans))
        self.assertIn(a.hex(), cfg, "back with its unexpired credits")
        self.assertEqual(cfg[a.hex()], sum(c.get(a, 0) for c in led15["credits"].values()))

    def test_entries_are_sorted_plain_pairs(self):
        hist, keys = self.hist()
        led, _ = g.advance(g.empty_ledger(), hist, 20, (), SMALL)
        cfg = g.configuration(led)
        self.assertEqual(cfg, sorted(cfg))
        self.assertTrue(all(isinstance(k, str) and len(k) == 40 and isinstance(w, int) and w > 0 for k, w in cfg))


class Vectors(unittest.TestCase):
    def test_file_is_what_the_reference_generates(self):
        self.assertTrue(g.VECTOR_FILE.exists())
        self.assertEqual(g.VECTOR_FILE.read_bytes(), g.serialized())


if __name__ == "__main__":
    unittest.main()
