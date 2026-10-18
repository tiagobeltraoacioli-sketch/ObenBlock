"""Required outcomes of the partition simulator (reference/sim/partition_sim.py)
for ObenBlock package O11 (docs/DESIGN-obenblock-poci.md §1, §4, §5, §10).

    python3 -I reference/sim/partition_sim_test.py -v
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import partition_sim as p  # noqa: E402

S = p.SLOTS_PER_EPOCH
SC = {sc.name: sc for sc in p.scenarios()}
PARTITIONS = [n for n, sc in SC.items() if sc.sides is not None]
HONEST = [n for n in PARTITIONS if not any(w.role == "byz" for w in SC[n].witnesses)]

_cache: dict = {}


def run(name: str, rules: p.Rules) -> p.Sim:
    k = (name, rules.name)
    if k not in _cache:
        _cache[k] = p.Sim(SC[name], rules).run()
    return _cache[k]


def res(name: str, rules: p.Rules) -> dict:
    return run(name, rules).result()


class RuleSet1DoubleFinalizes(unittest.TestCase):
    """§1: the leak lets both sides of a long partition finalize, with nobody
    signing twice."""

    def test_obenblock_half_leak_50_50_double_finalizes_in_epoch_6(self):
        # Partition at epoch 2, last finalization at slot 23 (end of epoch 1).
        # Boundary 5 -> 6 is the first with 4 stalled epochs: the absent half
        # halves, 3 * 50 >= 2 * 75 (inclusive), both sides justify at slot 72
        # and finalize it at slot 73: start + leak_after_epochs.
        r = res("p50-long", p.R1_OBB)
        self.assertEqual(r["conflict_epoch"], 6)
        self.assertEqual(r["conflict_slot"], 73)
        self.assertEqual(r["conflict_epoch"], SC["p50-long"].start + p.R1_OBB.leak_after)
        self.assertEqual(r["evidence_keys"], [])
        self.assertTrue(r["split_after_heal"])

    def test_gnb_sixteenth_leak_50_50_double_finalizes_in_epoch_17(self):
        r = res("p50-long", p.R1_GNB)
        self.assertEqual(r["conflict_epoch"], 17)
        self.assertEqual(r["evidence_keys"], [])

    def test_uneven_splits_and_the_window_also_double_finalize(self):
        want = {("p60-long", "R1-OBB"): 7, ("p70-long", "R1-OBB"): 8, ("p67-exact", "R1-OBB"): 7,
                ("p60-long", "R1-GnB"): 23, ("p70-long", "R1-GnB"): 31, ("p67-exact", "R1-GnB"): 28,
                ("p50-window", "R1-OBB"): 6, ("p70-window", "R1-GnB"): 31}
        for (name, rules), epoch in want.items():
            r = res(name, {"R1-OBB": p.R1_OBB, "R1-GnB": p.R1_GNB}[rules])
            self.assertEqual(r["conflict_epoch"], epoch, (name, rules))
            self.assertEqual(r["honest_evidence"], [], (name, rules))

    def test_a_partition_shorter_than_the_leak_delay_heals_cleanly(self):
        for rules in (p.R1_OBB, p.R1_GNB):
            r = res("p50-short", rules)
            self.assertIsNone(r["conflict_epoch"])
            self.assertEqual(r["resume_epoch"], 4)

    def test_inclusive_quorum_finalizes_at_exactly_two_thirds(self):
        r = res("p67-exact", p.R1_OBB)
        self.assertEqual(r["branches"]["A"]["first_finalized_after_fork_epoch"], 2)
        self.assertFalse(res("p67-exact", p.POCI)["branches"]["A"]["finalized_in_partition"])


class PoCISafety(unittest.TestCase):
    def test_never_two_conflicting_finalized_checkpoints(self):
        for name in HONEST + ["byz33-p50"]:
            r = res(name, p.POCI)
            self.assertIsNone(r["conflict_slot"], name)
            self.assertFalse(r["split_after_heal"], name)

    def test_only_a_side_with_more_than_two_thirds_of_the_original_config_advances(self):
        for name in PARTITIONS:
            if name == "byz34-p50":
                continue
            r = res(name, p.POCI)
            total = r["original_total"]
            for lbl, b in r["branches"].items():
                strong = 3 * b["weight"] > 2 * total
                self.assertEqual(b["finalized_in_partition"], strong, (name, lbl, b["weight"], total))

    def test_finality_resumes_after_heal(self):
        for name in PARTITIONS:
            if name == "byz34-p50":
                continue
            sim = run(name, p.POCI)
            r = sim.result()
            self.assertEqual(r["resume_epoch"], sim.heal, name)
            self.assertEqual(len(sim.branches), 1, name)
            # and keeps going to the end of the run
            self.assertGreaterEqual(sim.branches[0].finalized, (sim.end - 1) * S - 2, name)

    def test_beyond_the_window_the_frozen_config_does_not_age(self):
        for name in ("p50-window", "p60-window"):
            sim = run(name, p.POCI)
            for b in sim.branches + sim.dead:
                cfgs = {b.config_by_epoch[e] for e in range(sim.sc.start, sim.heal)}
                self.assertEqual(len(cfgs), 1, (name, b.label))
            self.assertEqual({b.config_by_epoch[sim.heal - 1] for b in sim.branches + sim.dead}.__len__(), 1)

    def test_conflict_needs_more_than_a_third_equivocating(self):
        # 33 % on both sides: one side only; 34 %: both, with evidence > 1/3 of C.
        r33 = res("byz33-p50", p.POCI)
        self.assertEqual(len(r33["evidence_keys"]), 33)
        r34 = res("byz34-p50", p.POCI)
        self.assertEqual(r34["conflict_epoch"], 2)
        sim = run("byz34-p50", p.POCI)
        cfg = sim.partition_config
        ev = sum(cfg.weight(k) for k in r34["evidence_keys"])
        self.assertGreater(3 * ev, cfg.total)
        self.assertEqual(r34["honest_evidence"], [])

    def test_no_honest_key_is_ever_proven_or_refused(self):
        for name in SC:
            for rules in p.RULE_SETS:
                r = res(name, rules)
                self.assertEqual(r["honest_evidence"], [], (name, rules.name))
                self.assertEqual(r["refused_votes"], 0, (name, rules.name))

    def test_every_certificate_verifies_against_its_named_config(self):
        for name in SC:
            self.assertTrue(res(name, p.POCI)["certificates_verify"], name)


class StallExitBanExpiry(unittest.TestCase):
    """§10: exit, ban and expiry during a stall."""

    def setUp(self):
        self.sim = run("stall-exit-ban-expiry", p.POCI)
        self.b = self.sim.branches[0]

    def test_poci_one_config_through_the_stall_and_one_handoff(self):
        ids = {self.b.config_by_epoch[e] for e in range(3, 16)}
        self.assertEqual(len(ids), 1)
        r = self.sim.result()
        self.assertFalse(r["stall"]["finalized_during"])
        self.assertEqual(r["stall"]["resume_epoch"], 15)
        after = [h for h in self.b.handoffs if h["at_slot"] >= 3 * S]
        self.assertEqual((after[0]["from_epoch"], after[0]["to_epoch"]), (2, 15))
        self.assertEqual(after[1]["from_epoch"], 15)
        # exit (k00), ban (k01) and expiry (k02, stopped mining at 1) all land there
        c15 = self.sim.registry[after[0]["config_id"]]
        for k in ("k00", "k01", "k02"):
            self.assertEqual(c15.weight(k), 0, k)
        self.assertGreater(self.sim.registry[self.b.config_by_epoch[10]].weight("k00"), 0)

    def test_ban_start_and_end_are_exact(self):
        self.assertEqual(self.b.bans, {"k01": (15, 115)})
        by_epoch = {c.epoch: c for c in self.sim.registry.values()}
        for e in range(15, 116):
            self.assertEqual(by_epoch[e].weight("k01"), 0, e)
        # Eligible again at 115; its work during the ban is dropped (conservative
        # reading), so it holds weight from C_116 (one epoch of new work).
        self.assertFalse(self.sim.banned_at(self.b, "k01", 115))
        self.assertTrue(self.sim.banned_at(self.b, "k01", 114))
        self.assertEqual(by_epoch[116].weight("k01"), 10)

    def test_no_ban_for_absence(self):
        self.assertEqual(sorted(self.b.bans), ["k01"])

    def test_rule1_leak_changes_the_denominator_during_the_stall(self):
        r = res("stall-exit-ban-expiry", p.R1_OBB)
        self.assertTrue(r["stall"]["finalized_during"])
        self.assertGreater(len(set(r["stall"]["totals"])), 2)
        self.assertEqual(len(set(res("stall-exit-ban-expiry", p.POCI)["stall"]["totals"][:-1])), 1)

    def test_same_config_on_both_sides_when_one_side_includes_exit_and_evidence(self):
        sim = run("p50-exit-ban", p.POCI)
        sides = sim.branches + sim.dead
        for e in range(3, 12):
            self.assertEqual(len({b.config_by_epoch[e] for b in sides}), 1, e)
        r1 = run("p50-exit-ban", p.R1_OBB)
        a, b = sorted(r1.branches + r1.dead, key=lambda x: x.label)
        self.assertNotEqual(a.total_by_epoch[5], b.total_by_epoch[5])
        # after the heal the exit and the evidence reach the surviving branch
        win = sim.branches[0]
        cfg = sim.registry[win.handoffs[-1]["config_id"]]
        self.assertEqual(cfg.weight("a00"), 0)
        self.assertEqual(cfg.weight("a01"), 0)


class AbsencePruning(unittest.TestCase):
    """§4.1 and §10: weight that fades out is pruned at handoffs and finality
    never halts; more than a third vanishing at once halts finality and no
    node prunes locally; keys that come back after a halt rejoin."""

    def test_fading_weight_is_pruned_and_finality_never_halts(self):
        sim = run("fade-10pct-daily", p.POCI)
        b = sim.branches[0]
        r = sim.result()
        epochs = {e for e in range(4, 40) if any(epoch_ok(f["at"], e) for f in b.fin_log)}
        self.assertEqual(epochs, set(range(4, 40)), "a finalization in every epoch")
        self.assertEqual(sorted(r["pruned"]), ["k06", "k07", "k08", "k09"])
        last = sim.registry[b.handoffs[-1]["config_id"]]
        self.assertEqual(sorted(k for k, _ in last.entries), [f"k{i:02d}" for i in range(6)])

    def test_forty_percent_at_once_halts_and_nobody_is_pruned(self):
        sim = run("vanish-40pct", p.POCI)
        r = sim.result()
        self.assertFalse(r["stall"]["finalized_during"])
        self.assertIsNone(r["stall"]["resume_epoch"])
        self.assertEqual(r["pruned"], {})
        self.assertEqual(len(set(r["stall"]["totals"])), 1, "the same C and denominator throughout")
        # Rule set 1 resumes through the leak (and would on both sides of a partition).
        self.assertTrue(res("vanish-40pct", p.R1_OBB)["stall"]["finalized_during"])

    def test_keys_back_after_a_halt_are_pruned_then_rejoin(self):
        sim = run("stall-exit-ban-expiry", p.POCI)
        b = sim.branches[0]
        h15 = next(h for h in b.handoffs if h["to_epoch"] == 15)
        back = ("k06", "k07", "k08", "k09")
        # Their votes that ended the halt are above the finalized checkpoint.
        self.assertTrue(all(k not in h15["entries"] for k in back))
        later = next(h for h in b.handoffs if h["to_epoch"] > 16)
        self.assertTrue(all(k in later["entries"] for k in back), later)
        self.assertEqual(b.pruned, {})


def epoch_ok(at_slot: int, e: int) -> bool:
    return at_slot // S == e


class Certificates(unittest.TestCase):
    def setUp(self):
        self.sim = run("p70-long", p.POCI)
        self.cert = dict(self.sim.branches[0].certs[-1])
        self.cfg = self.sim.registry[self.cert["config_id"]]

    def test_valid(self):
        self.assertTrue(p.verify_certificate(self.cert, self.cfg, p.POCI, self.sim.votes))

    def test_duplicate_key_refused(self):
        c = dict(self.cert, votes=sorted(self.cert["votes"] + self.cert["votes"][:1]))
        self.assertFalse(p.verify_certificate(c, self.cfg, p.POCI))

    def test_key_outside_config_refused(self):
        c = dict(self.cert, votes=sorted(self.cert["votes"] + ["zz99"]))
        self.assertFalse(p.verify_certificate(c, self.cfg, p.POCI))

    def test_forged_weight_refused(self):
        entries = tuple((k, w * 2 if i == 0 else w) for i, (k, w) in enumerate(self.cfg.entries))
        forged = p.Config(self.cfg.epoch, entries, self.cfg.total, self.cfg.id)
        self.assertFalse(p.verify_certificate(self.cert, forged, p.POCI))

    def test_two_thirds_exactly_is_not_enough(self):
        cfg = p.make_config(p.POCI, 7, {"a": 2, "b": 1})
        c = {"config_id": cfg.id, "votes": ["a"], "source": [0, "x"], "target": [1, "y"]}
        self.assertFalse(p.verify_certificate(c, cfg, p.POCI))
        cfg = p.make_config(p.POCI, 7, {"a": 201, "b": 100})
        c["config_id"] = cfg.id
        self.assertTrue(p.verify_certificate(c, cfg, p.POCI))


class Mechanics(unittest.TestCase):
    def test_quorum(self):
        self.assertTrue(p.quorum(p.R1_OBB, 2, 3))
        self.assertFalse(p.quorum(p.POCI, 2, 3))
        self.assertFalse(p.quorum(p.POCI, 0, 0))

    def test_decay(self):
        self.assertEqual(p.decayed(50, 1, 2), 25)
        self.assertEqual(p.decayed(160, 1, 16), 150)
        self.assertEqual(p.decayed(1 << 100, 100, 2), (1 << 100) >> 64)

    def test_growth_cap_renews_before_admitting(self):
        sc = p.Scenario("t", "t", [p.Witness("a", 64), p.Witness("n", 6400)], 1, window=4)
        sim = p.Sim(sc, p.POCI)
        b = sim.branches[0]
        b.work[0] = {"a": 64, "n": 6400}
        sim.ledger(b, 1)
        # W_0 = 4*64 + 4*6400; G = max(W_0 // 64, g_min); both renew their own
        # leaving work first (64, 6400) and nothing else is new.
        self.assertEqual(b.admitted[0], {"a": 64, "n": 6400})
        b.work[1] = {"a": 64, "n": 6400, "x": 100_000}
        sim.ledger(b, 2)
        w1 = 4 * 64 + 4 * 6400
        self.assertEqual(b.admitted[1], {"a": 64, "n": 6400, "x": max(w1 // 64, sim.g_min)})

    def test_deterministic_and_the_results_file_is_current(self):
        a = p.serialized(p.run_all())
        self.assertEqual(a, p.serialized(p.run_all()))
        self.assertEqual(a, p.RESULT_FILE.read_bytes())


if __name__ == "__main__":
    unittest.main()
