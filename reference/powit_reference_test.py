"""Tests of the PoWit reference (reference/powit_reference.py): the rules it
specifies, independently of the Rust implementation.

    python3 reference/powit_reference_test.py -v
"""
from __future__ import annotations

import unittest

import powit_reference as r

T = r.PARAMS["testnet"]


class Messages(unittest.TestCase):
    SRC = (10_000, bytes(range(32)))
    TGT = (10_060, bytes(range(32, 64)))

    def test_v2_preimage_layout(self):
        root = bytes([0xAB]) * 32
        pre = r.message_v2_preimage(r.CHAIN_TESTNET, 12, root, self.SRC, self.TGT)
        self.assertEqual(len(pre), 140)
        self.assertEqual(pre[:4], (19).to_bytes(4, "little"))
        self.assertEqual(pre[4:23], b"GNB-POWIT-v2/attest")
        self.assertEqual(pre[23:27], r.CHAIN_TESTNET.to_bytes(4, "little"))
        self.assertEqual(pre[27], 12)
        self.assertEqual(pre[28:60], root)
        self.assertEqual(pre[60:68], self.SRC[0].to_bytes(8, "little"))
        self.assertEqual(pre[68:100], self.SRC[1])
        self.assertEqual(pre[100:108], self.TGT[0].to_bytes(8, "little"))
        self.assertEqual(pre[108:140], self.TGT[1])

    def test_v2_commits_the_key_and_v1_does_not(self):
        a = r.message_v2(r.CHAIN_MAINNET, 12, bytes(32), self.SRC, self.TGT)
        self.assertNotEqual(a, r.message_v2(r.CHAIN_MAINNET, 12, bytes([1]) + bytes(31), self.SRC, self.TGT))
        self.assertNotEqual(a, r.message_v2(r.CHAIN_MAINNET, 11, bytes(32), self.SRC, self.TGT))
        self.assertNotEqual(a, r.message_v2(r.CHAIN_TESTNET, 12, bytes(32), self.SRC, self.TGT))
        self.assertNotEqual(a, r.message_v1(r.CHAIN_MAINNET, self.SRC, self.TGT))

    def test_the_version_follows_the_target_height(self):
        root = bytes(32)
        for h2, v2 in ((0, True), (10_060, True), (10_061, False), (r.NEVER, False)):
            want = (r.message_v2(r.CHAIN_MAINNET, 12, root, self.SRC, self.TGT) if v2
                    else r.message_v1(r.CHAIN_MAINNET, self.SRC, self.TGT))
            self.assertEqual(r.message_at(r.CHAIN_MAINNET, h2, 12, root, self.SRC, self.TGT), want, h2)


class WitnessSet(unittest.TestCase):
    def test_finding4_numbers(self):
        st, honest, attacker = r.finding4_state()
        v1 = dict(r.witness_set(st, T, 2, r.V1))
        self.assertEqual(len(v1), 64)
        self.assertTrue(all(k in v1 for k in attacker))
        total_v1 = r.total_weight(st, T, 2, r.V1)
        self.assertEqual(total_v1, 3_140)
        self.assertTrue(r.two_thirds(3_000, total_v1), "old rule: the 30% attacker justifies alone")
        self.assertFalse(r.two_thirds(sum(v1.get(k, 0) for k in honest), total_v1), "and the 70% cannot")
        total = r.total_weight(st, T, 2, r.H2)
        self.assertEqual(total, 10_000)
        self.assertFalse(r.two_thirds(3_000, total), "hardening 2: the attacker cannot justify alone")
        self.assertTrue(r.two_thirds(7_000, total), "nor stall: the honest 70% justify without it")
        self.assertFalse(r.two_thirds(35 * 190, total))
        self.assertTrue(r.two_thirds(35 * 191, total))

    def test_safety_bound_two_quorums_overlap_in_a_third_of_all_weight(self):
        # Any two subsets each holding >= 2/3 of the total share >= 1/3 of it.
        st, honest, attacker = r.finding4_state()
        ws = dict(r.witness_set(st, T, 2, r.H2))
        total = r.total_weight(st, T, 2, r.H2)
        keys = sorted(ws)
        q1 = keys[: 190]
        q2 = keys[70:]
        if r.two_thirds(sum(ws[k] for k in q1), total) and r.two_thirds(sum(ws[k] for k in q2), total):
            both = set(q1) & set(q2)
            self.assertGreaterEqual(3 * sum(ws[k] for k in both), total)

    def test_window_lag_bans_and_decay(self):
        a, b = b"a" * 20, b"b" * 20
        st = {"epoch_work": {0: {a: 10}, 1: {b: 50}}, "banned": {b: 5}, "decay": {a: 1}}
        self.assertEqual(r.witness_set(st, T, 1, r.H2), [])
        self.assertEqual(r.witness_set(st, T, 2, r.H2), [(a, 10)])
        self.assertEqual(r.witness_set(st, T, 3, r.H2), [(a, 10)], "b barred until epoch 5")
        self.assertEqual(r.witness_set(st, T, 5, r.H2), [(b, 50)], "epoch 0 left the window")

    def test_the_cap_applies_only_before_hardening2(self):
        st = {"epoch_work": {0: {bytes([i]) * 20: 1 + i for i in range(100)}}, "banned": {}, "decay": {}}
        self.assertEqual(len(r.witness_set(st, T, 2, r.V1)), 64)
        self.assertEqual(len(r.witness_set(st, T, 2, r.H2)), 100)

    def test_decay(self):
        self.assertEqual(r.decayed(16, 1), 15)
        self.assertEqual(r.decayed(1, 1_000), 1, "a positive weight never decays to zero")
        self.assertEqual(r.decayed(1_000_000, 65), r.decayed(1_000_000, 64))


class Evidence(unittest.TestCase):
    def test_evidence_epochs(self):
        self.assertEqual(r.evidence_epochs(0), [0, 1])
        self.assertEqual(r.evidence_epochs(6), [5, 6, 7])

    def test_members_of_the_three_sets_and_nobody_else(self):
        k = [bytes([i]) * 20 for i in range(5)]
        st = {"epoch_work": {e: {k[0]: 1} for e in range(7)}, "banned": {}, "decay": {}}
        for e, x in ((1, k[1]), (5, k[2]), (6, k[3])):
            st["epoch_work"][e][x] = 1
        got = [r.may_be_proven_h2(st, T, 6, x) for x in k]
        self.assertEqual(got, [True, True, True, False, False])

    def test_a_barred_key_is_no_member(self):
        k = b"k" * 20
        st = {"epoch_work": {e: {k: 1} for e in range(7)}, "banned": {k: 9}, "decay": {}}
        self.assertFalse(r.may_be_proven_h2(st, T, 6, k))


class Regime(unittest.TestCase):
    def test_boundary_is_inclusive(self):
        self.assertEqual(r.regime_at(17_499, 17_500), r.V1)
        self.assertEqual(r.regime_at(17_500, 17_500), r.H2)
        self.assertEqual(r.regime_at(r.NEVER - 1, r.NEVER), r.V1)

    def test_finding3_the_window_freezes_at_finalized_history(self):
        p = r.PARAMS["testnet"]
        a, n = r.key("t3", 0), r.key("t3", 1)
        work = {e: {a: 1_000, **({n: 5_000} if e >= 4 else {})} for e in range(10)}
        lag = {"epoch_work": work, "banned": {}, "decay": {}, "activation": 100, "finalized_height": 165}
        self.assertEqual(r.finalized_epochs(lag, p), 3)
        for e in (5, 9, 11):
            self.assertEqual(r.h2_window_epoch(lag, p, e), 4)
            self.assertEqual([k for k, _ in r.witness_set(lag, p, e, r.H2)], [a], "the newcomer is not final")
            if e >= 6:  # the old window reaches the newcomer's first epoch, 4
                self.assertIn(n, [k for k, _ in r.witness_set(lag, p, e, r.V1)], "the old rule admits it")
        up = dict(lag, finalized_height=100 + 8 * 20)
        self.assertEqual(r.h2_window_epoch(up, p, 9), 9, "finality keeps up: the old window")
        nothing = dict(lag, finalized_height=100)
        self.assertEqual(r.h2_window_epoch(nothing, p, 9), 9, "nothing final: the chain's own window")
        empty = {"epoch_work": {e: {n: 1} for e in range(5, 10)}, "banned": {}, "decay": {},
                 "activation": 100, "finalized_height": 165}
        self.assertEqual(r.h2_window_epoch(empty, p, 9), 9, "an empty frozen window gives way")

    def test_vectors_are_current(self):
        self.assertEqual(r.VECTOR_FILE.read_bytes(), r.serialized())


if __name__ == "__main__":
    unittest.main()
