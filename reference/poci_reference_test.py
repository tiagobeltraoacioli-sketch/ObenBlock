"""Tests of the PoCI reference (reference/poci_reference.py): the rules of
docs/DESIGN-obenblock-poci.md, independently of any Rust implementation.

    python3 reference/poci_reference_test.py -v
"""
from __future__ import annotations

import itertools
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import poci_reference as r  # noqa: E402
import gnb_merkle  # noqa: E402

P = r.PARAMS["mainnet"]
L, I = P["epoch_len"], P["checkpoint_interval"]


def keys(n, label="t"):
    return [r.vkey(label, i) for i in range(n)]


def cp(h, branch=0):
    return (h, r.cp_hash(h, branch))


class Configuration(unittest.TestCase):
    def test_layouts(self):
        self.assertEqual(len(r.params_preimage(P)), 118)
        pp = r.params_preimage(P)
        self.assertEqual(pp[78:86], (4).to_bytes(8, "little"), "bootstrap_epochs")
        self.assertEqual(pp[86:94], (720).to_bytes(8, "little"), "launch_bury = epoch_len")
        c = r.make_config("mainnet", 4, {keys(1)[0].key_id: 7})
        pre = c.preimage()
        self.assertEqual(len(pre), 110)
        self.assertEqual(pre[:18], b"OBB-POCI-v1/config")
        self.assertEqual(pre[18:22], r.CHAIN_OBB_MAINNET.to_bytes(4, "little"))
        self.assertEqual(pre[22:30], (4).to_bytes(8, "little"))
        self.assertEqual(pre[30:46], (7).to_bytes(16, "little"))
        self.assertEqual(pre[46:78], r.merkle_root(c.entries))
        self.assertEqual(pre[78:110], r.params_digest(P))
        self.assertEqual(c.id, r.sha256d(pre))

    def test_the_tree_has_the_repo_shape(self):
        # Same pairing and odd-node carry as gnb_merkle.tagged_merkle_root,
        # with PoCI's own tags.
        ks = keys(5)
        ents = sorted((k.key_id, 10 + i) for i, k in enumerate(ks))
        l = [r.leaf_hash(k, w) for k, w in ents]
        n = r.node_hash
        self.assertEqual(r.tree_root(ents), n(n(n(l[0], l[1]), n(l[2], l[3])), l[4]))
        self.assertEqual(r.tree_root([]), bytes(32))
        self.assertEqual(r.tagged(b"x", b"y"), gnb_merkle.tagged_hash(b"x", b"y"))

    def test_the_root_commits_the_count(self):
        ents = sorted((k.key_id, 1) for k in keys(3))
        self.assertNotEqual(r.merkle_root(ents), r.tree_root(ents))
        self.assertEqual(r.merkle_root(ents), r.merkle_root_from_tree(3, r.tree_root(ents)))
        self.assertNotEqual(r.merkle_root_from_tree(2, r.tree_root(ents)), r.merkle_root(ents))

    def test_every_input_changes_the_id(self):
        ks = keys(3)
        w = {k.key_id: 100 for k in ks}
        base = r.make_config("mainnet", 4, w)
        others = [
            r.make_config("regtest", 4, w),
            r.make_config("mainnet", 5, w),
            r.make_config("mainnet", 4, {**w, ks[0].key_id: 101}),
            r.make_config("mainnet", 4, {k: v for k, v in w.items() if k != ks[2].key_id}),
        ]
        ids = {base.id} | {c.id for c in others}
        self.assertEqual(len(ids), 5)
        p2 = dict(P, ban_epochs=99)
        self.assertNotEqual(r.params_digest(p2), r.params_digest(P))
        self.assertNotEqual(r.params_digest(dict(P, launch_bury=60)), r.params_digest(P))

    def test_entries_rules(self):
        a, b = sorted(k.key_id for k in keys(2))
        self.assertIsNone(r.check_entries([(a, 1), (b, 1)]))
        self.assertEqual(r.check_entries([(b, 1), (a, 1)]), "order")
        self.assertEqual(r.check_entries([(a, 1), (a, 1)]), "duplicate")
        self.assertEqual(r.check_entries([(a, 0)]), "weight")
        self.assertEqual(r.check_entries([(a, r.U128_MAX), (b, 1)]), "total_overflow")
        self.assertEqual(r.make_config("mainnet", 4, {a: 0, b: 3}).entries, ((b, 3),), "weight 0 is not an entry")

    def test_merkle_paths_round_trip_for_every_size(self):
        for n in range(1, 18):
            ents = sorted((k.key_id, i + 1) for i, k in enumerate(keys(n, f"p{n}")))
            root = r.tree_root(ents)
            for i, (k, w) in enumerate(ents):
                path = r.merkle_path(ents, i)
                self.assertEqual(r.path_root(r.leaf_hash(k, w), i, n, path), root, (n, i))
                self.assertIsNone(r.path_root(r.leaf_hash(k, w), i, n, path + [bytes(32)]))
                if path:
                    self.assertIsNone(r.path_root(r.leaf_hash(k, w), i, n, path[:-1]))
                self.assertNotEqual(r.path_root(r.leaf_hash(k, w + 1), i, n, path), root)
            self.assertIsNone(r.path_root(bytes(32), n, n, []))


class Messages(unittest.TestCase):
    def test_v3_layout(self):
        k = keys(1)[0]
        cid = bytes([0xCD]) * 32
        s, t = cp(2880), cp(2940)
        pre = r.message_v3_preimage(r.CHAIN_OBB_MAINNET, cid, k, s, t)
        self.assertEqual(len(pre), 171)
        self.assertEqual(pre[:4], (18).to_bytes(4, "little"))
        self.assertEqual(pre[4:22], b"OBB-POCI-v1/attest")
        self.assertEqual(pre[22:26], r.CHAIN_OBB_MAINNET.to_bytes(4, "little"))
        self.assertEqual(pre[26:58], cid)
        self.assertEqual(pre[58], k.depth)
        self.assertEqual(pre[59:91], k.root)
        self.assertEqual(pre[91:99], s[0].to_bytes(8, "little"))
        self.assertEqual(pre[99:131], s[1])
        self.assertEqual(pre[131:139], t[0].to_bytes(8, "little"))
        self.assertEqual(pre[139:171], t[1])

    def test_v3_commits_config_key_and_chain(self):
        k0, k1 = keys(2)
        s, t = cp(2880), cp(2940)
        a = r.message_v3(r.CHAIN_OBB_MAINNET, bytes(32), k0, s, t)
        self.assertNotEqual(a, r.message_v3(r.CHAIN_OBB_MAINNET, bytes([1]) + bytes(31), k0, s, t))
        self.assertNotEqual(a, r.message_v3(r.CHAIN_OBB_MAINNET, bytes(32), k1, s, t))
        self.assertNotEqual(a, r.message_v3(r.CHAIN_OBB_MAINNET, bytes(32), r.KesKey(k0.depth + 1, k0.root), s, t))
        self.assertNotEqual(a, r.message_v3(r.CHAIN_OBB_REGTEST, bytes(32), k0, s, t))
        self.assertNotEqual(a, r.powit.message_v2(r.CHAIN_OBB_MAINNET, k0.depth, k0.root, s, t))


class Quorum(unittest.TestCase):
    def test_strictly_more_than_two_thirds(self):
        self.assertFalse(r.quorum(2, 3))
        self.assertTrue(r.powit.two_thirds(2, 3), "GnB counts >=")
        self.assertFalse(r.quorum(200, 300))
        self.assertTrue(r.quorum(201, 300))
        self.assertFalse(r.quorum(0, 0), "an empty configuration never finalizes")
        self.assertTrue(r.quorum(1, 1))

    def test_u128_form_agrees(self):
        rng = random.Random(7)
        cases = [(g, t) for t in range(0, 40) for g in range(t + 1)]
        for _ in range(20_000):
            t = rng.choice([rng.randrange(r.U128_MAX + 1), r.U128_MAX - rng.randrange(1000), rng.randrange(10**6)])
            g = rng.choice([rng.randrange(t + 1), t - rng.randrange(min(t, 5) + 1), (2 * t) // 3 + rng.randrange(-2, 3)])
            if 0 <= g <= t:
                cases.append((g, t))
        for g, t in cases:
            self.assertEqual(r.quorum(g, t), r.quorum_u128(g, t), (g, t))

    def test_two_quorums_intersect_in_more_than_a_third(self):
        rng = random.Random(1)
        for _ in range(300):
            ws = [rng.randrange(1, 50) for _ in range(rng.randrange(1, 9))]
            total = sum(ws)
            qs = [set(s) for n in range(len(ws) + 1) for s in itertools.combinations(range(len(ws)), n)
                  if r.quorum(sum(ws[i] for i in s), total)]
            for a in qs:
                for b in qs:
                    self.assertGreater(3 * sum(ws[i] for i in a & b), total)


def chain(weights_by_epoch):
    ch = r.PociChain("mainnet", lambda e, f: weights_by_epoch(e), r.cp_hash)
    ch.launch()
    return ch


def votes(ch, ks, target, config=None, source=None):
    cfg = config or ch.config
    return [r.sign_vote(cfg.chain, P, cfg.id, k, source or ch.justified, target) for k in ks]


class Finality(unittest.TestCase):
    def test_launch(self):
        self.assertEqual(r.launch_height(P), 5 * L, "opening(4) buried by one epoch")
        self.assertEqual(r.launch_height(r.PARAMS["regtest"]), 100)
        ks = keys(3)
        ch = chain(lambda e: {k.key_id: 1 for k in ks})
        self.assertEqual(ch.config.epoch, 4)
        self.assertEqual(ch.finalized, ch.justified)
        self.assertEqual(ch.finalized[0], 4 * L)

    def test_votes_count_with_registry_weight_once_per_key(self):
        ks = keys(3)
        ch = chain(lambda e: {ks[0].key_id: 10, ks[1].key_id: 10, ks[2].key_id: 10})
        t = ch.cp(4 * L + I)
        vs = votes(ch, [ks[0], ks[0], ks[1]], t)
        self.assertEqual(r.counted_weight(ch.config, vs, ch.justified, t), 20)
        self.assertFalse(ch.votes(t, vs)["quorum"], "20 of 30 is exactly two thirds")
        self.assertTrue(ch.votes(t, vs + votes(ch, [ks[2]], t))["finalized"])

    def test_a_partition_never_finalizes_on_both_sides(self):
        # With PoCI the denominator of each side is the whole C: no decay,
        # whatever the stall's length.
        for split in (50, 60, 66, 67, 70):
            ks = keys(100, f"part{split}")
            ch_a = chain(lambda e: {k.key_id: 1 for k in ks})
            ch_b = chain(lambda e: {k.key_id: 1 for k in ks})
            side_a, side_b = ks[:split], ks[split:]
            fin = []
            for ch, side, br in ((ch_a, side_a, 1), (ch_b, side_b, 2)):
                for step in range(1, 30):
                    t = (4 * L + step * I, r.cp_hash(4 * L + step * I, br))
                    ch.votes(t, votes(ch, side, t))
                fin.append(ch.finalized[0] > 4 * L)
                if not fin[-1]:
                    self.assertEqual(ch.config.epoch, 4, "a stalled side keeps its configuration")
                    self.assertEqual(ch.config.total, 100)
            self.assertFalse(all(fin), split)
            self.assertEqual(fin, [split > 66, 100 - split > 66], split)

    def test_handoff_only_by_finality_and_skips(self):
        ks = keys(5)
        seen = []

        def provider(e, f):
            seen.append((e, f[0]))
            return {k.key_id: 100 + e for k in ks}
        ch = r.PociChain("mainnet", provider, r.cp_hash)
        ch.launch()
        t = ch.cp(9 * L + 2 * I)
        ch.votes(t, votes(ch, ks, t))
        self.assertEqual(ch.config.epoch, 4, "justified is not finalized")
        t2 = ch.cp(9 * L + 3 * I)
        out = ch.votes(t2, votes(ch, ks, t2))
        self.assertTrue(out["handoff"])
        self.assertEqual(ch.config.epoch, 9)
        self.assertEqual(seen, [(4, 4 * L), (9, 9 * L + 2 * I)])
        self.assertEqual([c.epoch for c in ch.history], [4, 9])

    def test_votes_naming_an_old_config_do_not_count(self):
        ks = keys(4)
        ch = chain(lambda e: {k.key_id: 1 for k in ks})
        old = ch.config
        for h in (5 * L, 5 * L + I):
            ch.votes(ch.cp(h), votes(ch, ks, ch.cp(h)))
        self.assertEqual(ch.config.epoch, 5)
        t = ch.cp(5 * L + 2 * I)
        self.assertEqual(ch.votes(t, votes(ch, ks, t, config=old))["weight"], 0)


class Corruption(unittest.TestCase):
    def setUp(self):
        self.ks = keys(4)
        self.ch = chain(lambda e: {k.key_id: 100 for k in self.ks})

    def ev(self, key, a, b, cfg=None):
        cfg = cfg or self.ch.config
        return (r.sign_vote(cfg.chain, P, cfg.id, key, a[0], a[1]),
                r.sign_vote(cfg.chain, P, cfg.id, key, b[0], b[1]))

    def advance(self, *heights):
        for h in heights:
            t = self.ch.cp(h)
            self.ch.votes(t, votes(self.ch, self.ks[:3], t))

    def test_ban_start_end_and_no_retroactive_change(self):
        b = 4 * L
        k = self.ks[3]
        a, bb = self.ev(k, (cp(b), cp(b + I)), (cp(b), cp(b + I, 1)))
        self.assertEqual(self.ch.evidence(b + 1, a, bb), "ok")
        c4 = self.ch.config
        self.assertEqual(c4.weight(k.key_id), 100, "the configuration in force is not changed")
        self.advance(b + I, 5 * L, 5 * L + I)
        self.assertEqual(self.ch.config.epoch, 5)
        self.assertIsNone(self.ch.config.weight(k.key_id))
        self.assertEqual(self.ch.bans[k.key_id][0].start, 5)
        self.assertEqual(self.ch.configs[c4.id], c4, "the past configuration is kept unchanged")
        self.assertTrue(self.ch.banned_at(k.key_id, 104))
        self.assertFalse(self.ch.banned_at(k.key_id, 105))
        self.assertFalse(self.ch.banned_at(k.key_id, 4))

    def test_evidence_above_the_handoff_checkpoint_waits_for_the_next(self):
        b = 4 * L
        k = self.ks[3]
        self.advance(b + I, 5 * L)
        a, bb = self.ev(k, (cp(b), cp(b + I)), (cp(b), cp(b + I, 1)))
        self.assertEqual(self.ch.evidence(5 * L + 1, a, bb), "ok")
        self.advance(5 * L + I)            # finalizes 5L < 5L + 1: the evidence block is not final
        self.assertEqual(self.ch.config.epoch, 5)
        self.assertEqual(self.ch.config.weight(k.key_id), 100)
        self.advance(6 * L, 6 * L + I)
        self.assertEqual(self.ch.config.epoch, 6)
        self.assertIsNone(self.ch.config.weight(k.key_id))
        self.assertEqual(self.ch.bans[k.key_id][0].start, 6)

    def test_never_punished(self):
        b = 4 * L
        k = self.ks[0]
        # Absence for many epochs: nothing, not even a weight change.
        before = self.ch.config
        for h in range(b + I, b + 50 * I, I):
            self.ch.votes(self.ch.cp(h), votes(self.ch, [k], self.ch.cp(h)))
        self.assertEqual(self.ch.config, before)
        self.assertEqual(self.ch.bans, {})
        # Same vote twice, consecutive links, a vote for a losing branch.
        for a, bb in (((cp(b), cp(b + I)), (cp(b), cp(b + I))),
                      ((cp(b), cp(b + I)), (cp(b + I), cp(b + 2 * I))),
                      ((cp(b), cp(b + 2 * I, 1)), (cp(b + 2 * I, 1), cp(b + 3 * I, 1)))):
            self.assertNotEqual(self.ch.evidence(b + 1, *self.ev(k, a, bb)), "ok")
        self.assertEqual(self.ch.bans, {})

    def test_evidence_needs_one_config(self):
        b = 4 * L
        k = self.ks[0]
        c4 = self.ch.config
        self.advance(5 * L, 5 * L + I)
        x = r.sign_vote(c4.chain, P, c4.id, k, cp(b), cp(b + I))
        y = r.sign_vote(c4.chain, P, self.ch.config.id, k, cp(b), cp(b + I, 1))
        self.assertEqual(self.ch.evidence(5 * L + I + 1, x, y), "different_configs")
        y_old = r.sign_vote(c4.chain, P, c4.id, k, cp(b), cp(b + I, 1))
        self.assertEqual(self.ch.evidence(5 * L + I + 1, x, y_old), "ok", "evidence about a past configuration")

    def test_a_returning_key_may_be_banned_again(self):
        b = 4 * L
        k = self.ks[3]
        self.assertEqual(self.ch.evidence(b + 1, *self.ev(k, (cp(b), cp(b + I)), (cp(b), cp(b + I, 1)))), "ok")
        self.advance(b + I, 5 * L, 5 * L + I, 105 * L, 105 * L + I)
        self.assertEqual(self.ch.config.epoch, 105)
        self.assertEqual(self.ch.config.weight(k.key_id), 100)
        j = self.ch.justified[0]
        e2 = self.ev(k, (cp(j), cp(j + I)), (cp(j), cp(j + I, 1)))
        self.assertEqual(self.ch.evidence(j + 1, *e2), "ok")
        old = self.ev(k, (cp(b), cp(b + 2 * I)), (cp(b), cp(b + 2 * I, 1)), cfg=self.ch.history[0])
        self.assertEqual(self.ch.evidence(j + 1, *old), "already_banned_for_config")


class Pruning(unittest.TestCase):
    """Section 4.1: absence pruning by the old committee, and rejoin."""

    def handoff(self, ch, ks, x, last=None, included_at=None):
        for h, voters in ((x * L, ks), (x * L + I, last or ks)):
            t = ch.cp(h)
            out = ch.votes(t, votes(ch, voters, t), included_at)
        self.assertTrue(out["handoff"], x)
        self.assertEqual(ch.config.epoch, x)

    def test_message_layout(self):
        k = keys(1)[0]
        pre = r.rejoin_preimage(r.CHAIN_OBB_MAINNET, k, 9)
        self.assertEqual(len(pre), 67)
        self.assertEqual(pre[:4], (18).to_bytes(4, "little"))
        self.assertEqual(pre[4:22], b"OBB-POCI-v1/rejoin")
        self.assertEqual(pre[22:26], r.CHAIN_OBB_MAINNET.to_bytes(4, "little"))
        self.assertEqual(pre[26], k.depth)
        self.assertEqual(pre[27:59], k.root)
        self.assertEqual(pre[59:], (9).to_bytes(8, "little"))
        # Not an exit, not a vote: its own domain.
        self.assertNotEqual(r.rejoin_message(r.CHAIN_OBB_MAINNET, k, 9), r.rejoin_message(r.CHAIN_OBB_REGTEST, k, 9))
        self.assertNotEqual(r.rejoin_message(r.CHAIN_OBB_MAINNET, k, 9), r.rejoin_message(r.CHAIN_OBB_MAINNET, k, 10))

    def test_grace_and_the_exact_window(self):
        ks = keys(6, "pr")
        ch = chain(lambda e: {k.key_id: 100 for k in ks})
        core, quiet = ks[:5], ks[5]
        for x in (5, 6, 7):
            self.handoff(ch, core, x)
            self.assertIsNotNone(ch.config.weight(quiet.key_id), f"grace at {x}")
        self.handoff(ch, core, 8)
        self.assertIsNone(ch.config.weight(quiet.key_id), "an entry since 4 with nothing included")
        self.assertEqual(ch.pruned[quiet.key_id].start, 8)

    def test_only_inclusions_in_the_window_below_the_opening_count(self):
        ks = keys(6, "fin")
        k5 = ks[5].key_id
        core = [k.key_id for k in ks[:5]]
        # The window is (opening(x - 4), opening(x)]: exactly opening(5) is
        # outside, one above inside; exactly opening(9) inside, one above
        # (the blocks of epoch 9, the finalizing links among them) outside.
        for h, pruned in ((5 * L, True), (5 * L + 1, False), (9 * L, False), (9 * L + 1, True)):
            c = chain(lambda e: {k.key_id: 100 for k in ks})
            c.include(6 * L, core)
            c.include(h, [k5])
            self.handoff(c, ks[:5], 9)
            self.assertEqual(c.config.weight(k5) is None, pruned, h)
        # A vote in the finalizing link does not count either.
        ch = chain(lambda e: {k.key_id: 100 for k in ks})
        ch.include(6 * L, core)
        self.handoff(ch, ks[:5], 9, last=ks)
        self.assertIsNone(ch.config.weight(k5))

    def test_a_stall_longer_than_the_window_ends_without_pruning(self):
        # Review HIGH: every key is silent for more than PRUNE_AFTER epochs,
        # then the committee returns. Its votes are above opening(x), so no
        # key of C_4 is present: no quorum of C_4 present, nobody pruned, and
        # the returning committee stays in C_x (it is not pruned by the
        # handoff it authorizes). Same with 60 % online through the stall.
        ks = keys(5, "stall")
        for online in ([], ks[:3]):
            ch = chain(lambda e: {k.key_id: 100 for k in ks})
            for h in range(4 * L + I, 20 * L, I):
                t = ch.cp(h)
                ch.votes(t, votes(ch, online, t))
            self.assertEqual(ch.config.epoch, 4)
            self.handoff(ch, ks, 20)
            self.assertEqual((ch.config.total, ch.pruned), (500, {}), len(online))
            # Finality goes on, and pruning resumes once a committee is present.
            self.handoff(ch, ks[:4], 21)
            self.handoff(ch, ks[:4], 22)
            self.assertEqual(ch.config.total, 500, "key 4: an entry of C_20 only, in its grace period")
            for x in (23, 24, 25):
                self.handoff(ch, ks[:4], x)
            self.assertEqual(sorted(ch.pruned), [ks[4].key_id])

    def test_a_handoff_never_leaves_an_empty_configuration(self):
        ks = keys(4, "empty")
        ch = chain(lambda e: {} if e == 6 else {k.key_id: 100 for k in ks})
        self.handoff(ch, ks, 5)
        c5 = ch.config
        self.handoff(ch, ks, 6)
        self.assertEqual((ch.config.epoch, ch.config.entries), (6, c5.entries))
        self.assertNotEqual(ch.config.id, c5.id)
        self.handoff(ch, ks, 7)
        self.assertEqual(ch.config.total, 400)

    def test_one_configuration_per_epoch(self):
        # Review MEDIUM: two chains with the same history up to opening(9)
        # finalize different checkpoints of epoch 9 first, and differ above
        # opening(9) (a rejoin, evidence, votes of a returning key). C_9 is
        # the same on both.
        ks = keys(6, "uniq")
        w = lambda e: {k.key_id: 100 for k in ks}  # noqa: E731
        out = []
        for skip in (False, True):
            ch = chain(w)
            for x in (5, 6, 7, 8):
                self.handoff(ch, ks[:5], x)
            self.assertTrue(ch.pruned_at(ks[5].key_id, 8))
            self.assertEqual(ch.rejoin(8 * L + I + 1, 8, r.sign_rejoin(r.CHAIN_OBB_MAINNET, ks[5], 8)), "ok")
            if not skip:
                self.handoff(ch, ks[:5], 9)
            else:
                t = ch.cp(9 * L)
                ch.votes(t, votes(ch, ks[:3], t))
                cfg = ch.config
                a = r.sign_vote(cfg.chain, P, cfg.id, ks[4], ch.justified, ch.cp(9 * L))
                b = r.sign_vote(cfg.chain, P, cfg.id, ks[4], ch.justified, cp(9 * L, 1))
                self.assertEqual(ch.evidence(9 * L + 5, a, b), "ok")
                self.assertEqual(ch.rejoin(9 * L + 6, 9, r.sign_rejoin(r.CHAIN_OBB_MAINNET, ks[5], 9)), "pending")
                for h in (9 * L + I, 9 * L + 2 * I):
                    t = ch.cp(h)
                    ch.votes(t, votes(ch, ks[:5], t))
                self.assertEqual(ch.finalized[0], 9 * L + I)
                self.assertIsNone(ch.bans[ks[4].key_id][0].start, "above opening(9): pending")
            self.assertEqual(ch.config.epoch, 9)
            out.append(ch.config.id)
        self.assertEqual(out[0], out[1])

    def test_pruned_then_rejoin_under_the_growth_cap(self):
        ks = keys(6, "gcap")
        hist = {"share_work": {n: {k.key_id: 400 for k in ks} for n in range(16)},
                "first_block_bits": {n: r.gc.EASY_BITS for n in range(16)}}
        prov = r.GrowthCapProvider(hist, r.gc.PARAMS["obenblock"])
        ch = r.PociChain("mainnet", prov, r.cp_hash)
        ch.launch()
        prov.chain = ch
        q = ks[5].key_id
        for x in (5, 6, 7, 8):
            self.handoff(ch, ks[:5], x)
        self.assertIsNone(ch.config.weight(q))
        held = r.gc.ledger_weights(prov.ledger)[q]
        self.assertEqual(ch.rejoin(9 * L + 1, 9, r.sign_rejoin(r.CHAIN_OBB_MAINNET, ks[5], 9)), "ok")
        self.handoff(ch, ks[:5], 9)
        self.assertIsNone(ch.config.weight(q), "the rejoin is above opening(9)")
        self.assertEqual(r.gc.ledger_weights(prov.ledger)[q], held, "no credit while pruned")
        self.handoff(ch, ks[:5], 10)
        wq, w0 = ch.config.weight(q), ch.config.weight(ks[0].key_id)
        self.assertLess(held, wq)
        self.assertLess(wq, w0, "back as new weight under the cap, without the credits it missed")

    def test_a_key_that_entered_later_has_its_grace(self):
        ks = keys(6, "late")
        ch = chain(lambda e: {k.key_id: 100 for k in (ks if e >= 6 else ks[:5])})
        for x in (5, 6, 7, 8, 9):
            self.handoff(ch, ks[:5], x)
        self.assertIsNotNone(ch.config.weight(ks[5].key_id), "an entry since 6: grace until 10")
        self.handoff(ch, ks[:5], 10)
        self.assertIsNone(ch.config.weight(ks[5].key_id))

    def test_rejoin_returns_from_the_handoff_that_finalizes_it(self):
        ks = keys(6, "rj")
        ch = chain(lambda e: {k.key_id: 100 for k in ks})
        for x in (5, 6, 7, 8):
            self.handoff(ch, ks[:5], x)
        k = ks[5]
        self.assertTrue(ch.pruned_at(k.key_id, 8))
        rj = r.sign_rejoin(r.CHAIN_OBB_MAINNET, k, 8)
        self.assertEqual(ch.rejoin(8 * L + I + 1, 8, rj), "ok")
        self.assertEqual(ch.rejoin(8 * L + I + 2, 8, rj), "pending")
        # Finalizing a checkpoint below the rejoin's block does not end it.
        t = ch.cp(8 * L + 2 * I)
        ch.votes(t, votes(ch, ks[:5], t))
        self.assertEqual(ch.finalized[0], 8 * L + I)
        self.assertIn(k.key_id, ch.rejoins)
        self.handoff(ch, ks[:5], 9)
        self.assertEqual(ch.config.weight(k.key_id), 100)
        self.assertNotIn(k.key_id, ch.pruned)
        self.assertEqual(ch.rejoins, {})
        # Grace again: pruned at 13 if it stays silent.
        for x in (10, 11, 12):
            self.handoff(ch, ks[:5], x)
            self.assertIsNotNone(ch.config.weight(k.key_id))
        self.handoff(ch, ks[:5], 13)
        self.assertIsNone(ch.config.weight(k.key_id))

    def test_rejoin_verdicts(self):
        ks = keys(6, "rv")
        ch = chain(lambda e: {k.key_id: 100 for k in ks})
        for x in (5, 6, 7, 8):
            self.handoff(ch, ks[:5], x)
        h = ch.finalized[0] + 1
        k = ks[5]
        self.assertEqual(ch.rejoin(h, 8, r.sign_rejoin(r.CHAIN_OBB_MAINNET, ks[0], 8)), "not_pruned")
        self.assertEqual(ch.rejoin(h, 8, r.sign_rejoin(r.CHAIN_OBB_MAINNET, k, 6)), "epoch")
        self.assertEqual(ch.rejoin(h, 8, r.sign_rejoin(r.CHAIN_OBB_MAINNET, k, 9)), "epoch")
        self.assertEqual(ch.rejoin(h, 8, r.sign_rejoin(r.CHAIN_OBB_REGTEST, k, 8)), "signature")
        self.assertEqual(ch.rejoin(h - 1, 8, r.sign_rejoin(r.CHAIN_OBB_MAINNET, k, 8)), "below_finality")
        self.assertEqual(ch.rejoin(h, 9, r.sign_rejoin(r.CHAIN_OBB_MAINNET, k, 8)), "ok", "the next epoch too")

    def test_forgotten_without_share_work(self):
        ks = keys(6, "fg")
        ch = chain(lambda e: {k.key_id: 100 for k in (ks if e < 9 or e > 9 else ks[:5])})
        for x in (5, 6, 7, 8):
            self.handoff(ch, ks[:5], x)
        k = ks[5].key_id
        self.assertIn(k, ch.pruned)
        self.handoff(ch, ks[:5], 9)
        self.assertNotIn(k, ch.pruned, "no candidate weight: forgotten")
        self.handoff(ch, ks[:5], 10)
        self.assertEqual(ch.config.weight(k), 100, "back as a new key")

    def test_mass_absence_halts_and_nobody_prunes(self):
        ks = keys(5, "mass")
        ch = chain(lambda e: {k.key_id: 100 for k in ks})
        for h in range(4 * L + I, 40 * L, I):
            t = ch.cp(h)
            self.assertFalse(ch.votes(t, votes(ch, ks[:3], t))["quorum"])
        self.assertEqual((ch.config.epoch, ch.config.total, ch.pruned), (4, 500, {}))

    def test_fading_weight_never_halts_finality(self):
        # One key in ten goes offline every day (4 epochs), 40 % in all: a key
        # is pruned about five epochs after its last included vote, so at most
        # two are absent from C_x at once, the online weight stays above two
        # thirds and every handoff happens.
        ks = keys(10, "fade")
        ch = chain(lambda e: {k.key_id: 100 for k in ks})
        off = {ks[9].key_id: 5, ks[8].key_id: 9, ks[7].key_id: 13, ks[6].key_id: 17}
        for x in range(5, 30):
            online = [k for k in ks if off.get(k.key_id, 10**9) > x]
            self.handoff(ch, online, x)
            absent = sum(w for kk, w in ch.config.entries if off.get(kk, 10**9) <= x)
            self.assertLess(3 * absent, ch.config.total, x)
        self.assertEqual(ch.config.total, 600)
        self.assertEqual(sorted(ch.pruned), sorted(off))

    def test_a_partition_side_cannot_prune_its_way_to_a_quorum(self):
        # 50/50: neither side finalizes, so neither side prunes the other.
        ks = keys(10, "split")
        for side in (ks[:5], ks[5:]):
            ch = chain(lambda e: {k.key_id: 100 for k in ks})
            for h in range(4 * L + I, 30 * L, I):
                t = ch.cp(h)
                ch.votes(t, votes(ch, side, t))
            self.assertEqual((ch.config.epoch, ch.pruned, ch.finalized[0]), (4, {}, 4 * L))


class Certificates(unittest.TestCase):
    def setUp(self):
        self.ks = keys(4)
        self.cfg = r.make_config("mainnet", 4, {k.key_id: 100 for k in self.ks})
        self.s, self.t = cp(4 * L), cp(4 * L + I)

    def test_round_trip_and_proof(self):
        cert = r.make_certificate(self.cfg, self.s, self.t, self.ks[:3])
        data = cert.encode()
        self.assertEqual(r.decode_certificate(data), cert)
        self.assertEqual(r.verify_certificate(data, self.cfg), "ok")
        proof = r.make_registry_proof(self.cfg, cert).encode()
        self.assertEqual(r.verify_certificate_with_proof(data, proof, "mainnet", self.cfg.id), "ok")

    def test_certificate_votes_are_the_chain_votes(self):
        ch = chain(lambda e: {k.key_id: 100 for k in self.ks})
        cert = r.make_certificate(ch.config, ch.justified, ch.cp(4 * L + I), self.ks[:3])
        vs = [r.Vote(cert.config_id, k, cert.source, cert.target, sig) for k, sig in cert.votes]
        self.assertTrue(ch.votes(cert.target, vs)["finalized"])

    def test_vectors_are_current(self):
        self.assertEqual(r.VECTOR_FILE.read_bytes(), r.serialized())

    def test_vector_verdicts(self):
        doc = r.generate()
        got = {c["name"]: (c["verdict"], c.get("verdict_with_proof")) for c in doc["certificates"]["cases"]}
        self.assertEqual(got["valid_700_of_1000"], ("ok", "ok"))
        self.assertEqual(got["exactly_two_thirds"][0], "quorum")
        self.assertEqual(got["just_above_two_thirds"][0], "ok")
        self.assertEqual(got["duplicate_key"][0], "duplicate")
        self.assertEqual(got["key_outside_config"][0], "non_member")
        self.assertEqual(got["forged_weights_config_id"][0], "config_id")
        self.assertEqual(got["proof_forged_weight"][1], "path")
        self.assertEqual(got["proof_forged_total"][1], "config_id")


if __name__ == "__main__":
    unittest.main()
