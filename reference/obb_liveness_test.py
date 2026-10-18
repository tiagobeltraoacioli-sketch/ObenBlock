"""Tests of the ObenBlock liveness reference (reference/obb_liveness.py): the
rules it specifies and the numbers of DESIGN-obenblock.md section 5,
independently of the Rust implementation.

    python3 reference/obb_liveness_test.py -v
"""
from __future__ import annotations

import math
import unittest

import gnb_difficulty as d
import obb_liveness as r

LIMIT = d.bits_to_target(r.OBB_POW_LIMIT_BITS)


class StallRelief(unittest.TestCase):
    BASE = d.bits_to_target(0x1B0404CB)

    def test_nothing_changes_within_three_minutes(self):
        for dt in [-100, 0, 179, 180, 239]:
            self.assertEqual(r.relieved_bits(0x1B0404CB, 0, dt, r.OBB_POW_LIMIT_BITS), 0x1B0404CB)

    def test_doubles_every_thirty_minutes_in_minute_steps(self):
        for k in range(1, 12):
            t = r.relieved_target(self.BASE, 0, 180 + k * 1800, LIMIT)
            self.assertEqual(t, self.BASE << k)
            self.assertEqual(r.relieved_target(self.BASE, 0, 180 + k * 1800 + 59, LIMIT), t, "within a step")

    def test_monotone_never_harder_and_clamped(self):
        prev = self.BASE
        for dt in range(0, 400_000, 53):
            t = r.relieved_target(self.BASE, 0, dt, LIMIT)
            self.assertGreaterEqual(t, prev)
            self.assertLessEqual(t, LIMIT)
            prev = t
        easy = d.bits_to_target(0x1E00FFFF)
        self.assertEqual(r.relieved_target(easy, 0, 10**6, LIMIT), easy)

    def test_abuse_bound(self):
        # MAX_FUTURE_SECS of claimed lateness relax a block by at most 2^(600/1800).
        for lag in [180, 1_000, 5_000]:
            honest = r.relieved_target(self.BASE, 0, lag, LIMIT)
            lie = r.relieved_target(self.BASE, 0, lag + r.MAX_FUTURE_SECS, LIMIT)
            self.assertLessEqual(lie / honest, 2 ** (600 / 1800) * 1.0002)

    def test_expected_wait_bound(self):
        # With a fraction q of the hashrate left, P(no block by t) with the
        # relief is exp(-int q*rate(s) ds); its median is below the design's
        # 3 min + 30 min * log2(1/q) worst-case estimate.
        for q, bound_h in [(0.1, 1.75), (0.001, 5.0)]:
            hazard, t = 0.0, 0
            while hazard < math.log(2):
                rate = q * (r.relieved_target(self.BASE, 0, t, LIMIT) / self.BASE) / 30
                hazard += rate
                t += 1
            self.assertLess(t / 3600, bound_h, q)


class Leak(unittest.TestCase):
    def test_half_is_ceiling_halving(self):
        for w in [0, 1, 5, 2**127 + 3]:
            x = w
            for n in range(1, 140):
                x = x - x // 2
                self.assertEqual(r.decayed_with(r.LEAK_HALF, w, n), x if n <= 128 else r.decayed_with(r.LEAK_HALF, w, 128))

    def test_design_table(self):
        # 24 h + 6 h * ceil(log2(2a/(1-a))): 50 % -> 30 h, 90 % -> 54 h, 99 % -> 72 h (worst phase).
        for a, hours in [(50, 30), (90, 54), (99, 72)]:
            k = math.ceil(math.log2(2 * a / (100 - a)))
            self.assertEqual(r.halvings_needed(a * 10**16, (100 - a) * 10**16), k)
            e = r.resume_epoch(a * 10**16, (100 - a) * 10**16, r.LEAK_HALF, 4, 719, 720)
            self.assertEqual(e * 6, hours)

    def test_gnb_leak_cannot_recover_from_99_percent(self):
        self.assertIsNone(r.resume_epoch(99, 1, r.LEAK_SIXTEENTH, 4, 0, 720))


class Exit(unittest.TestCase):
    def test_preimage_layout(self):
        root = bytes([7]) * 32
        pre = r.exit_preimage(r.CHAIN_OBB_MAINNET, 12, root, 9)
        self.assertEqual(len(pre), 66)
        self.assertEqual(pre[:4], (17).to_bytes(4, "little"))
        self.assertEqual(pre[4:21], b"OBB-POWIT-v1/exit")
        self.assertEqual(pre[21:25], r.CHAIN_OBB_MAINNET.to_bytes(4, "little"))
        self.assertEqual(pre[25], 12)
        self.assertEqual(pre[26:58], root)
        self.assertEqual(pre[58:66], (9).to_bytes(8, "little"))

    def test_epoch_window(self):
        self.assertTrue(r.exit_epoch_ok(5, 5))
        self.assertTrue(r.exit_epoch_ok(6, 5))
        self.assertFalse(r.exit_epoch_ok(7, 5))
        self.assertFalse(r.exit_epoch_ok(4, 5))

    def test_exit_leaves_from_the_recorded_epoch(self):
        p = r.pr.PARAMS["testnet"]
        k = b"\x01" * 20
        st = {"epoch_work": {0: {k: 10}}, "banned": {}, "decay": {}, "exited": {k: 3}}
        self.assertEqual(r.witness_set(st, p, 2, r.LEAK_HALF), [(k, 10)])
        self.assertEqual(r.witness_set(st, p, 3, r.LEAK_HALF), [])


class VectorsAreCurrent(unittest.TestCase):
    def test_file_matches(self):
        self.assertEqual(r.VECTOR_FILE.read_bytes(), r.serialized())


if __name__ == "__main__":
    unittest.main()
