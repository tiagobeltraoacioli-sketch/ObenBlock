"""PoWit finality under network partitions: a deterministic discrete-event
simulator of the current rules against PoCI (ObenBlock package O11).

Research tool, not a consensus reference: it models the finality rules at
checkpoint granularity and compares two rule sets on the same scenarios.

    python3 -I reference/sim/partition_sim.py            # summary table
    python3 -I reference/sim/partition_sim.py --write    # regenerate partition_sim_results.json
    python3 -I reference/sim/partition_sim.py --check    # CI: the file is what this generates
    python3 -I reference/sim/partition_sim_test.py -v    # the required outcomes as tests

Rule sets (docs/DESIGN-obenblock-poci.md, docs/DESIGN-obenblock.md §5.2 and
§6.3, docs/CONSENSUS.md "PoWit"):

  R1-OBB  current rules with the ObenBlock §5.2 leak: inclusive quorum
          (3 got >= 2 total), W from the frozen finalized window (H2 rule),
          112-epoch window, after leak_after_epochs (4) stalled epochs every
          member of W(e) whose votes were not included in e loses half its
          weight (w -= w // 2, at most 64 steps), decay cleared on
          finalization; the exit message removes the key from W from the next
          epoch; a ban bars the key at once on the chain that included it.
  R1-GnB  the same with the GnB leak (w -= w // 16), a 28-epoch window and no
          exit message (an exiting key just stops voting).
  PoCI    strict quorum (3 got > 2 total) over the frozen configuration C_e
          named by the vote; C_{x} enters into force only when C_e finalizes a
          checkpoint of epoch x > e (handoff, may skip epochs); weights from
          the finalized history with the §6.3 growth cap; exits, bans and
          expiry only at a handoff; no leak; evidence = double or surround vote
          by one key under one config_id; ban for 100 epochs from the first
          configuration computed after the evidence is finalized; C_x reads
          the history up to opening(x) only (evidence, exits and rejoins at
          slots <= opening(x), DESIGN-obenblock-poci.md §4); absence
          pruning (§4.1): at a handoff to C_x, if the keys of C_e with a vote
          included in slots [opening(x-4), opening(x)) hold a strict quorum
          of C_e, a key that has been an entry of every configuration since
          epoch x - 4 or earlier and has no such vote is left out until a
          rejoin is finalized (an honest online key that is pruned publishes
          one at the next epoch start, as its operator would); without that
          quorum nobody is pruned; C_x is never empty (it then carries C_e's
          entries).

Model:

- Slot = checkpoint (60 blocks); SLOTS_PER_EPOCH = 12 (720 / 60). Slot 0 is the
  genesis checkpoint, justified and finalized. Each live branch appends one
  checkpoint per slot; every voter present on the branch votes
  (branch justified checkpoint -> the new checkpoint) and the vote is included
  in the same slot (best case for liveness, which only makes the rule-1
  double finalization earlier, never safer). A supermajority link justifies
  its target; a justified direct child (target = source + 1 slot) finalizes the
  source (Casper FFG).
- Share work: each witness mines `rate` per epoch on the branch it is on while
  online; the history before epoch 0 is seeded with every witness's rate for
  max(window) epochs (a running chain, no bootstrap period).
- Partition: at epoch `start` the chain forks into one branch per side; honest
  keys vote and mine only on their side; `byz` keys vote and mine on every
  side (worst case). Heal at epoch `heal`: if the branches' finalized
  checkpoints conflict, nodes keep their sticky pin and the split persists;
  otherwise every node adopts the branch holding the highest finalized
  checkpoint (ties: the most share work since the fork, then the label) and
  the equivocation evidence seen in the other branches is included in it.
- Honest signers keep a monotone record (§8): they never sign at or below a
  target height already signed nor with a source below one already used.
- `config_id` here is SHA-256d over a sim-local encoding (merkle root of
  (key, u128le weight) leaves, params digest of this file's rule set). It is
  NOT the normative encoding; only the equality of ids matters to the checks.

Interfaces for the Rust work: `partition_sim_results.json` (format in
docs/research/obenblock-partition-sim.md) lists every scenario, its witnesses
and events, and per rule set the outcome: finalized slots per side, the
conflict epoch, handoffs (at_slot, from_epoch, to_epoch, total, entries),
bans (start, end) and the evidence keys. Integer arithmetic only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

RESULT_FILE = Path(__file__).with_name("partition_sim_results.json")

SLOTS_PER_EPOCH = 12
CHAIN_ID = 0x4F42_0001  # sim-local
MAX_DECAY_STEPS = 64
POCI_BAN_EPOCHS = 100
GROWTH_DIV = 64
PRUNE_AFTER_EPOCHS = 4


# ── Rules ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rules:
    name: str
    poci: bool
    strict: bool
    decay_div: int | None  # w -= w // decay_div per leak step; None: no leak
    window: int
    ban_epochs: int
    exit_message: bool
    growth_cap: bool
    leak_after: int = 4

    def with_window(self, w: int | None) -> "Rules":
        if w is None:
            return self
        return Rules(self.name, self.poci, self.strict, self.decay_div, w, self.ban_epochs,
                     self.exit_message, self.growth_cap, self.leak_after)

    def digest(self) -> bytes:
        enc = json.dumps([self.name, self.poci, self.strict, self.decay_div, self.window, self.ban_epochs,
                          self.exit_message, self.growth_cap, self.leak_after, SLOTS_PER_EPOCH],
                         separators=(",", ":")).encode()
        return sha256d(b"OBB-SIM/params", enc)


R1_OBB = Rules("R1-OBB", poci=False, strict=False, decay_div=2, window=112, ban_epochs=28,
               exit_message=True, growth_cap=False)
R1_GNB = Rules("R1-GnB", poci=False, strict=False, decay_div=16, window=28, ban_epochs=28,
               exit_message=False, growth_cap=False)
POCI = Rules("PoCI", poci=True, strict=True, decay_div=None, window=112, ban_epochs=POCI_BAN_EPOCHS,
             exit_message=True, growth_cap=True)
RULE_SETS = (R1_OBB, R1_GNB, POCI)


def quorum(rules: Rules, got: int, total: int) -> bool:
    if total == 0:
        return False
    if rules.strict:
        return 3 * got > 2 * total
    return 3 * got >= 2 * total


def decayed(w: int, steps: int, div: int) -> int:
    for _ in range(min(steps, MAX_DECAY_STEPS)):
        w -= w // div
    return w


def sha256d(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return hashlib.sha256(h.digest()).digest()


def u128le(v: int) -> bytes:
    return v.to_bytes(16, "little")


def epoch_of(slot: int) -> int:
    return slot // SLOTS_PER_EPOCH


# ── Configuration (PoCI) ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class Config:
    epoch: int
    entries: tuple[tuple[str, int], ...]  # sorted by key, weight > 0
    total: int
    id: str

    def weight(self, key: str) -> int:
        for k, w in self.entries:
            if k == key:
                return w
        return 0


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return bytes(32)
    level = leaves
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
        level = [sha256d(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def make_config(rules: Rules, epoch: int, weights: dict[str, int]) -> Config:
    entries = tuple(sorted((k, w) for k, w in weights.items() if w > 0))
    total = sum(w for _, w in entries)
    leaves = [sha256d(k.encode(), u128le(w)) for k, w in entries]
    cid = sha256d(b"OBB-POCI-v1/config", CHAIN_ID.to_bytes(4, "little"), epoch.to_bytes(8, "little"),
                  u128le(total), merkle_root(leaves), rules.digest())
    return Config(epoch, entries, total, cid.hex()[:16])


# ── Scenario ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Witness:
    key: str
    rate: int  # share work per epoch
    role: str = "honest"  # honest | byz (on every side) | faulty (equivocates on events)


@dataclass
class Scenario:
    name: str
    title: str
    witnesses: list[Witness]
    epochs: int  # minimum run length; a heal adds after_heal epochs past it
    sides: dict[str, list[str]] | None = None  # honest / faulty keys per side
    start: int | None = None
    heal: int | None = None  # absolute epoch, or None: never
    heal_after_window: int | None = None  # heal = start + window + this (per rule set)
    events: list[tuple[int, str, str, str | None]] = field(default_factory=list)
    offline: dict[str, tuple[int, int]] = field(default_factory=dict)  # key -> [from, to)
    window: int | None = None  # override every rule set's window
    after_heal: int = 10
    stall: tuple[int, int] | None = None  # [from, to) epochs reported as a stall (single chain)

    def resolve(self, rules: Rules) -> tuple[Rules, int | None, int]:
        r = rules.with_window(self.window)
        heal = self.heal
        if self.heal_after_window is not None:
            heal = self.start + r.window + self.heal_after_window
        end = self.epochs if heal is None else max(self.epochs, heal + self.after_heal)
        return r, heal, end


# ── Branch state ─────────────────────────────────────────────────────────────

@dataclass
class Branch:
    label: str
    chain: list[str]
    members: set[str]
    work: dict[int, dict[str, int]]
    fork_slot: int = 0
    fork_epoch: int = 0
    justified: int = 0
    finalized: int = 0
    finalized_at: int = 0
    # rule set 1
    decay: dict[str, int] = field(default_factory=dict)
    active: set[str] = field(default_factory=set)
    banned_until: dict[str, int] = field(default_factory=dict)
    exit_from: dict[str, int] = field(default_factory=dict)  # R1: out of W from this epoch
    win_cache: dict[int, dict[str, int]] = field(default_factory=dict)
    # PoCI
    config: Config | None = None
    admitted: dict[int, dict[str, int]] = field(default_factory=dict)
    exits: list[tuple[int, str]] = field(default_factory=list)  # (slot included, key)
    evidence: list[tuple[int, str]] = field(default_factory=list)
    used_evidence: set[tuple[int, str]] = field(default_factory=set)
    bans: dict[str, tuple[int, int]] = field(default_factory=dict)
    excluded: set[str] = field(default_factory=set)  # exited keys, for good
    handoffs: list[dict] = field(default_factory=list)
    config_by_epoch: dict[int, str] = field(default_factory=dict)
    total_by_epoch: dict[int, int] = field(default_factory=dict)
    fin_log: list[dict] = field(default_factory=list)
    certs: list[dict] = field(default_factory=list)
    seen: dict[str, list[int]] = field(default_factory=dict)  # key -> slots whose votes were included
    pruned: dict[str, list] = field(default_factory=dict)  # key -> [start, until or None] (§4.1)
    rejoins: list[tuple[int, str]] = field(default_factory=list)  # (slot included, key)
    cfg_hist: list = field(default_factory=list)  # configurations in force, oldest first

    def fork(self, label: str, members: set[str], slot: int) -> "Branch":
        b = Branch(label, list(self.chain), set(members),
                   {e: dict(m) for e, m in self.work.items()}, slot, epoch_of(slot + 1),
                   self.justified, self.finalized, self.finalized_at,
                   dict(self.decay), set(self.active), dict(self.banned_until), dict(self.exit_from),
                   dict(self.win_cache), self.config, {e: dict(m) for e, m in self.admitted.items()},
                   list(self.exits), list(self.evidence), set(self.used_evidence), dict(self.bans),
                   set(self.excluded), list(self.handoffs), dict(self.config_by_epoch),
                   dict(self.total_by_epoch), list(self.fin_log), list(self.certs),
                   {k: list(v) for k, v in self.seen.items()}, {k: list(v) for k, v in self.pruned.items()},
                   list(self.rejoins), list(self.cfg_hist))
        return b

    def has(self, slot: int, cp: str) -> bool:
        return slot < len(self.chain) and self.chain[slot] == cp

    def work_since_fork(self) -> int:
        return sum(w for e, m in self.work.items() if e >= self.fork_epoch for w in m.values())


# ── Simulator ────────────────────────────────────────────────────────────────

class Sim:
    def __init__(self, sc: Scenario, rules: Rules):
        self.sc = sc
        self.rules, self.heal, self.end = sc.resolve(rules)
        self.w = {x.key: x for x in sc.witnesses}
        self.keys = sorted(self.w)
        self.total_rate = sum(x.rate for x in sc.witnesses)
        self.g_min = max(1, self.total_rate // 8)
        self.registry: dict[str, Config] = {}
        self.votes: dict[str, list[tuple]] = {k: [] for k in self.keys}  # (scope, src_slot, src_cp, tgt_slot, tgt_cp)
        self.signer: dict[str, tuple[int, int]] = {}  # key -> (max_tgt, max_src)
        self.refused = 0
        self.exited: set[str] = set()
        self.stopped: dict[str, int] = {}
        self.conflict_slot: int | None = None
        self.split = False
        self.dead: list[Branch] = []
        self.probes: list[dict] = []
        seed = max(self.rules.window, 1) + 2
        work = {e: {k: self.w[k].rate for k in self.keys} for e in range(-seed, 0)}
        main = Branch("M", ["M0"], set(self.keys), work)
        if self.rules.poci:
            main.admitted = {e: dict(m) for e, m in work.items()}
            cfg = self.poci_config(main, 0, 0)
            main.config = cfg
            main.cfg_hist.append(cfg)
            main.config_by_epoch[0] = cfg.id
            main.total_by_epoch[0] = cfg.total
        self.branches = [main]
        self.partition_config: Config | None = None

    # ── weights, rule set 1 ──────────────────────────────────────────────
    def r1_window(self, b: Branch, x: int) -> dict[str, int]:
        got = b.win_cache.get(x)
        if got is None:
            lo, hi = x - 1 - self.rules.window, x - 2
            got = {}
            for e in range(lo, hi + 1):
                for k, w in b.work.get(e, {}).items():
                    got[k] = got.get(k, 0) + w
            b.win_cache[x] = got
        return got

    def r1_members(self, b: Branch, e: int) -> dict[str, int]:
        nf = b.finalized // SLOTS_PER_EPOCH
        x = e if nf == 0 else min(e, nf + 1)

        def members(x: int) -> dict[str, int]:
            out = {}
            for k, w in self.r1_window(b, x).items():
                if b.banned_until.get(k, -1) > e or b.exit_from.get(k, 1 << 62) <= e:
                    continue
                d = decayed(w, b.decay.get(k, 0), self.rules.decay_div)
                if d > 0:
                    out[k] = d
            return out
        m = members(x)
        if not m and x != e:
            m = members(e)
        return m

    # ── weights, PoCI ────────────────────────────────────────────────────
    def banned_at(self, b: Branch, k: str, e: int) -> bool:
        s = b.bans.get(k)
        return s is not None and s[0] <= e < s[1]

    def pruned_at(self, b: Branch, k: str, e: int) -> bool:
        p = b.pruned.get(k)
        return p is not None and p[0] <= e and (p[1] is None or e < p[1])

    def prune(self, b: Branch, x: int, f_slot: int) -> None:
        """§4.1 at the handoff to C_x triggered by finalizing slot f_slot:
        history up to opening(x) only (§4)."""
        cut = x * SLOTS_PER_EPOCH
        for slot, k in list(b.rejoins):
            if slot <= cut:
                b.rejoins.remove((slot, k))
                if k in b.pruned:
                    b.pruned[k][1] = x
        lo = (x - PRUNE_AFTER_EPOCHS) * SLOTS_PER_EPOCH

        def present(k: str) -> bool:
            return any(lo <= s < cut for s in b.seen.get(k, []))
        if not quorum(self.rules, sum(w for k, w in b.config.entries if present(k)), b.config.total):
            return  # no committee present in the window (a stall): nobody is pruned
        for k, _ in b.config.entries:
            if k in b.pruned:
                continue
            eligible = False
            for c in reversed(b.cfg_hist):
                if c.weight(k) == 0:
                    break
                if c.epoch <= x - PRUNE_AFTER_EPOCHS:
                    eligible = True
                    break
            if eligible and not present(k):
                b.pruned[k] = [x, None]

    def ledger(self, b: Branch, upto: int) -> None:
        """Growth-capped admitted work (§6.3) for every epoch < upto."""
        win = self.rules.window
        e = max(b.admitted) + 1
        while e < upto:
            w_e = sum(sum(b.admitted.get(i, {}).values()) for i in range(e - win, e))
            leaving = b.admitted.get(e - win, {})
            new = {k: (0 if self.banned_at(b, k, e) or self.pruned_at(b, k, e) else n)
                   for k, n in b.work.get(e, {}).items()}
            renew = {k: min(n, leaving.get(k, 0)) for k, n in new.items()}
            extra = {k: new[k] - renew[k] for k in new}
            g = max(w_e // GROWTH_DIV, self.g_min)
            sx = sum(extra.values())
            if not self.rules.growth_cap or sx <= g:
                admit = extra
            else:
                admit = {k: x * g // sx for k, x in extra.items()}
            b.admitted[e] = {k: renew[k] + admit[k] for k in new if renew[k] + admit[k] > 0}
            e += 1

    def poci_config(self, b: Branch, x: int, upto_slot: int) -> Config:
        """C_x from the finalized history up to upto_slot (opening(x) at a
        handoff)."""
        for ev in b.evidence:
            slot, k = ev
            if slot <= upto_slot and ev not in b.used_evidence:
                b.used_evidence.add(ev)
                if not self.banned_at(b, k, x):
                    b.bans[k] = (x, x + self.rules.ban_epochs)
        for slot, k in b.exits:
            if slot <= upto_slot:
                b.excluded.add(k)
        self.ledger(b, x)
        weights: dict[str, int] = {}
        for e in range(x - self.rules.window, x):
            for k, w in b.admitted.get(e, {}).items():
                weights[k] = weights.get(k, 0) + w
        for k in [k for k, v in b.pruned.items() if v[1] is None and weights.get(k, 0) == 0]:
            del b.pruned[k]  # no weight left: forgotten (§4.1)
            b.rejoins = [(s, k2) for s, k2 in b.rejoins if k2 != k]
        weights = {k: w for k, w in weights.items()
                   if k not in b.excluded and not self.banned_at(b, k, x) and not self.pruned_at(b, k, x)}
        if not weights and b.config is not None:
            # Never empty (§4): C_e's entries carry forward, this handoff's prunings are void.
            b.pruned = {k: v for k, v in b.pruned.items() if not (v[0] == x and v[1] is None)}
            weights = dict(b.config.entries)
        b.pruned = {k: v for k, v in b.pruned.items() if v[1] is None}
        cfg = make_config(self.rules, x, weights)
        self.registry[cfg.id] = cfg
        return cfg

    # ── signing ──────────────────────────────────────────────────────────
    def may_sign(self, k: str, src: int, tgt: int) -> bool:
        rec = self.signer.get(k)
        if rec is None:
            return True
        max_tgt, max_src = rec
        return tgt > max_tgt and src >= max_src

    def sign(self, k: str, scope, src: int, src_cp: str, tgt: int, tgt_cp: str) -> None:
        self.votes[k].append((scope, src, src_cp, tgt, tgt_cp))
        if self.w[k].role == "honest":
            mt, ms = self.signer.get(k, (-1, -1))
            self.signer[k] = (max(mt, tgt), max(ms, src))

    # ── one slot on one branch ───────────────────────────────────────────
    def voters(self, b: Branch, slot: int) -> list[str]:
        e = epoch_of(slot)
        out = []
        for k in sorted(b.members):
            off = self.sc.offline.get(k)
            if off and off[0] <= e < off[1]:
                continue
            if k in self.exited:
                continue
            out.append(k)
        return out

    def step(self, b: Branch, slot: int) -> None:
        b.chain.append(f"{b.label}{slot}")
        e = epoch_of(slot)
        src, src_cp, tgt_cp = b.justified, b.chain[b.justified], b.chain[slot]
        if self.rules.poci:
            cfg = b.config
            scope, total = cfg.id, cfg.total
            weight = cfg.weight
        else:
            m = self.r1_members(b, e)
            scope, total = None, sum(m.values())
            weight = lambda k: m.get(k, 0)  # noqa: E731
        got, signed = 0, []
        for k in self.voters(b, slot):
            w = weight(k)
            if w == 0:
                continue  # not a member: the vote is not includable
            if self.w[k].role == "honest" and not self.may_sign(k, src, slot):
                self.refused += 1
                continue
            self.sign(k, scope, src, src_cp, slot, tgt_cp)
            got += w
            signed.append(k)
            b.active.add(k)
            if self.rules.poci:
                b.seen.setdefault(k, []).append(slot)
        if quorum(self.rules, got, total):
            if slot == b.justified + 1:
                self.finalize(b, src, slot, signed, scope, got, total)
            b.justified = slot

    def finalize(self, b: Branch, src: int, at: int, signed: list[str], scope, got: int, total: int) -> None:
        b.finalized, b.finalized_at = src, at
        b.decay.clear()
        cert = {"config_id": scope, "source": [src, b.chain[src]], "target": [at, b.chain[at]],
                "votes": sorted(signed), "weight": got, "total": total}
        b.certs.append(cert)
        b.fin_log.append({"slot": src, "cp": b.chain[src], "at": at, "config_id": scope})
        if self.rules.poci:
            x = epoch_of(src)
            if x > b.config.epoch:
                old = b.config
                self.prune(b, x, src)
                cfg = self.poci_config(b, x, x * SLOTS_PER_EPOCH)
                b.config = cfg
                b.cfg_hist.append(cfg)
                b.seen = {k: v for k, v in b.seen.items() if cfg.weight(k) > 0}
                b.handoffs.append({"at_slot": at, "from_epoch": old.epoch, "to_epoch": x, "config_id": cfg.id,
                                   "total": cfg.total, "entries": [k for k, _ in cfg.entries]})
        self.check_conflict(at)

    def check_conflict(self, at: int) -> None:
        if self.conflict_slot is not None:
            return
        live = self.branches + self.dead
        for i, a in enumerate(live):
            for c in live[i + 1:]:
                if not (c.has(a.finalized, a.chain[a.finalized]) or a.has(c.finalized, c.chain[c.finalized])):
                    self.conflict_slot = at
                    return

    # ── epoch boundary (rule set 1 leak) ─────────────────────────────────
    def boundary(self, b: Branch, e: int) -> None:
        if not self.rules.poci and self.rules.decay_div:
            stalled = (e + 1) * SLOTS_PER_EPOCH - b.finalized_at >= self.rules.leak_after * SLOTS_PER_EPOCH
            if stalled:
                for k in self.r1_members(b, e):
                    if k not in b.active:
                        b.decay[k] = b.decay.get(k, 0) + 1
        b.active = set()
        if self.rules.poci:
            b.config_by_epoch[e + 1] = b.config.id
            b.total_by_epoch[e + 1] = b.config.total
        else:
            b.total_by_epoch[e + 1] = sum(self.r1_members(b, e + 1).values())

    # ── topology ─────────────────────────────────────────────────────────
    def partition(self, e: int) -> None:
        main = self.branches[0]
        slot = e * SLOTS_PER_EPOCH - 1
        byz = {k for k in self.keys if self.w[k].role == "byz"}
        self.branches = [main.fork(lbl, set(ks) | byz, slot) for lbl, ks in sorted(self.sc.sides.items())]
        self.partition_config = main.config

    def evidence_keys(self) -> dict[str, list]:
        """Keys with a double or surround vote under one scope (config_id; all
        votes under rule set 1): {key: [kind, vote_a, vote_b]}."""
        out = {}
        for k in self.keys:
            by_scope: dict = {}
            for v in self.votes[k]:
                by_scope.setdefault(v[0], []).append(v)
            for scope in sorted(by_scope, key=str):
                vs = by_scope[scope]
                seen: dict[int, tuple] = {}
                hit = None
                for v in vs:
                    o = seen.get(v[3])
                    if o is not None and o[4] != v[4]:
                        hit = ["double", list(o[1:]), list(v[1:])]
                        break
                    seen.setdefault(v[3], v)
                if hit is None:
                    ordered = sorted(vs, key=lambda v: (v[1], v[3]))
                    best = None  # vote with the highest target among strictly lower sources
                    i = 0
                    while i < len(ordered) and hit is None:
                        j = i
                        while j < len(ordered) and ordered[j][1] == ordered[i][1]:
                            if best is not None and best[3] > ordered[j][3]:
                                hit = ["surround", list(best[1:]), list(ordered[j][1:])]
                                break
                            j += 1
                        for v in ordered[i:j]:
                            if best is None or v[3] > best[3]:
                                best = v
                        i = j
                if hit is not None:
                    out[k] = hit
                    break
        return out

    def heal_now(self, e: int) -> None:
        self.check_conflict(e * SLOTS_PER_EPOCH)
        if self.conflict_slot is not None:
            self.split = True  # sticky pins: nodes keep the finality they reached
            return
        top = max(self.branches, key=lambda b: b.finalized)
        cands = [b for b in self.branches if b.has(top.finalized, top.chain[top.finalized])]
        win = sorted(cands, key=lambda b: (-b.work_since_fork(), b.label))[0]
        slot = e * SLOTS_PER_EPOCH
        for b in self.branches:
            if b is not win:
                win.members |= b.members
                self.dead.append(b)
                # Exit messages are gossip: the ones the other side included are
                # included again on the surviving branch.
                for _, k in b.exits:
                    if all(k != k2 for _, k2 in win.exits):
                        win.exits.append((slot, k))
                for k, x in sorted(b.exit_from.items()):
                    if k not in win.exit_from:
                        win.exit_from[k] = e + 1
        for k in sorted(self.evidence_keys()):
            if self.rules.poci:
                win.evidence.append((slot, k))
            else:
                win.banned_until[k] = e + self.rules.ban_epochs
        self.branches = [win]

    def apply_event(self, e: int, kind: str, k: str, where: str | None) -> None:
        slot = e * SLOTS_PER_EPOCH
        targets = [b for b in self.branches if (where is None or b.label == where) and k in b.members]
        if kind == "exit":
            self.exited.add(k)
            if self.rules.exit_message:
                for b in targets:
                    if self.rules.poci:
                        b.exits.append((slot, k))
                    else:
                        b.exit_from[k] = e + 1
        elif kind == "stop_mining":
            self.stopped[k] = e
        elif kind == "equivocate":
            for b in targets:
                src, scope = b.justified, (b.config.id if self.rules.poci else None)
                self.sign(k, scope, src, b.chain[src], slot, f"X{slot}")
                self.sign(k, scope, src, b.chain[src], slot, f"Y{slot}")
                if self.rules.poci:
                    b.evidence.append((slot, k))
                else:
                    b.banned_until[k] = e + self.rules.ban_epochs
        else:
            raise ValueError(kind)

    def rejoin_pruned(self, e: int) -> None:
        """Operators of honest online keys that were pruned publish a rejoin."""
        slot = e * SLOTS_PER_EPOCH
        for b in self.branches:
            for k, v in sorted(b.pruned.items()):
                off = self.sc.offline.get(k)
                online = not (off and off[0] <= e < off[1]) and k not in self.exited and k in b.members
                if v[1] is None and online and self.w[k].role == "honest" and all(k != k2 for _, k2 in b.rejoins):
                    b.rejoins.append((slot, k))

    def mine(self, e: int) -> None:
        for b in self.branches:
            m = b.work.setdefault(e, {})
            for k in sorted(b.members):
                off = self.sc.offline.get(k)
                if off and off[0] <= e < off[1]:
                    continue
                if k in self.exited or self.stopped.get(k, 1 << 62) <= e:
                    continue
                m[k] = self.w[k].rate

    def run(self) -> "Sim":
        for e in range(self.end):
            if self.sc.start is not None and e == self.sc.start:
                self.partition(e)
            if self.heal is not None and e == self.heal and len(self.branches) > 1:
                self.heal_now(e)
            for (ee, kind, k, where) in self.sc.events:
                if ee == e:
                    self.apply_event(e, kind, k, where)
            if self.rules.poci:
                self.rejoin_pruned(e)
            self.mine(e)
            for slot in range(max(1, e * SLOTS_PER_EPOCH), (e + 1) * SLOTS_PER_EPOCH):
                for b in self.branches:
                    self.step(b, slot)
            for b in self.branches:
                self.boundary(b, e)
        return self

    # ── outcome ──────────────────────────────────────────────────────────
    def verify_certs(self) -> bool:
        if not self.rules.poci:
            return True
        for b in self.branches + self.dead:
            for c in b.certs:
                if not verify_certificate(c, self.registry.get(c["config_id"]), self.rules, self.votes):
                    return False
        return True

    def side_weight(self, label: str) -> int | None:
        if self.sc.sides is None:
            return None
        cfg = self.partition_config
        keys = set(self.sc.sides[label]) | {k for k in self.keys if self.w[k].role == "byz"}
        if cfg is not None:
            return sum(cfg.weight(k) for k in keys)
        return sum(self.w[k].rate for k in keys)

    def result(self) -> dict:
        S = SLOTS_PER_EPOCH
        ev = self.evidence_keys()
        out = {"rules": self.rules.name, "window": self.rules.window, "epochs": self.end,
               "heal": self.heal, "split_after_heal": self.split,
               "conflict_slot": self.conflict_slot,
               "conflict_epoch": None if self.conflict_slot is None else epoch_of(self.conflict_slot),
               "evidence_keys": sorted(ev),
               "honest_evidence": sorted(k for k in ev if self.w[k].role == "honest"),
               "refused_votes": self.refused, "certificates_verify": self.verify_certs()}
        sides = {}
        start_slot = None if self.sc.start is None else self.sc.start * S - 1
        heal_slot = None if self.heal is None else self.heal * S
        for b in sorted(self.branches + self.dead, key=lambda b: b.label):
            during = [f for f in b.fin_log
                      if start_slot is not None and f["slot"] > start_slot
                      and (heal_slot is None or f["at"] < heal_slot)]
            first = next((f for f in b.fin_log if start_slot is not None and f["slot"] > start_slot), None)
            sides[b.label] = {
                "finalized_slot": b.finalized,
                "finalized_in_partition": bool(during),
                "first_finalized_after_fork_epoch": None if first is None else epoch_of(first["at"]),
                "survives": b in self.branches,
            }
            if self.sc.sides and b.label in self.sc.sides:
                w = self.side_weight(b.label)
                base = self.partition_config.total if self.partition_config is not None else self.total_rate
                sides[b.label]["weight"] = w
                sides[b.label]["weight_pct_x100"] = 10_000 * w // base
        out["branches"] = sides
        out["original_total"] = (self.partition_config.total if self.partition_config is not None
                                 else (self.branches[0].config.total if self.rules.poci else None))
        if heal_slot is not None and not self.split:
            win = self.branches[0]
            first = next((f for f in win.fin_log if f["at"] >= heal_slot), None)
            out["resume_epoch"] = None if first is None else epoch_of(first["at"])
        else:
            out["resume_epoch"] = None
        if self.sc.stall is not None:
            lo, hi = (x * S for x in self.sc.stall)
            log = self.branches[0].fin_log
            during = [f for f in log if lo <= f["at"] < hi]
            after = next((f for f in log if f["at"] >= hi), None)
            out["stall"] = {"finalized_during": bool(during),
                            "first_epoch_during": epoch_of(during[0]["at"]) if during else None,
                            "resume_epoch": None if after is None else epoch_of(after["at"]),
                            "totals": [self.branches[0].total_by_epoch.get(e)
                                       for e in range(self.sc.stall[0], self.sc.stall[1] + 1)]}
        if self.rules.poci:
            b = self.branches[0]
            out["handoffs"] = b.handoffs
            out["bans"] = {k: list(v) for k, v in sorted(b.bans.items())}
            out["pruned"] = {k: v[0] for k, v in sorted(b.pruned.items())}
        return out


def verify_certificate(cert: dict, cfg: Config | None, rules: Rules, votes: dict | None = None) -> bool:
    """Proof of Integrity: the named config exists and matches its id, the
    voters are distinct entries of it, their registry weight is a strict
    supermajority, and (with `votes`) each voter signed exactly that link."""
    if cfg is None or cfg.id != cert["config_id"]:
        return False
    if make_config(rules, cfg.epoch, dict(cfg.entries)).id != cfg.id:
        return False  # forged weights or total
    ks = cert["votes"]
    if len(set(ks)) != len(ks) or ks != sorted(ks):
        return False
    got = 0
    for k in ks:
        w = cfg.weight(k)
        if w == 0:
            return False
        if votes is not None:
            link = (cfg.id, cert["source"][0], cert["source"][1], cert["target"][0], cert["target"][1])
            if link not in votes.get(k, []):
                return False
        got += w
    return 3 * got > 2 * cfg.total


# ── Scenarios ────────────────────────────────────────────────────────────────

def keyed(n: int, rate: int, prefix: str, role: str = "honest", start: int = 0) -> list[Witness]:
    return [Witness(f"{prefix}{i:02d}", rate, role) for i in range(start, start + n)]


def split(name: str, title: str, a: int, b: int, start: int, heal: int | None = None,
          heal_after_window: int | None = None, epochs: int = 0) -> Scenario:
    ws = keyed(a, 10, "a") + keyed(b, 10, "b")
    return Scenario(name, title, ws, epochs, {"A": [w.key for w in ws[:a]], "B": [w.key for w in ws[a:]]},
                    start, heal, heal_after_window)


def scenarios() -> list[Scenario]:
    out = [
        split("p50-short", "50/50, 2 epochs (under the leak delay), heal", 5, 5, 2, heal=4),
        split("p50-long", "50/50, 30 epochs (7.5 days), heal", 5, 5, 2, heal=32),
        split("p60-long", "60/40, 30 epochs, heal", 6, 4, 2, heal=32),
        split("p70-long", "70/30, 30 epochs, heal", 7, 3, 2, heal=32),
        split("p50-window", "50/50, window + 8 epochs, heal", 5, 5, 2, heal_after_window=8),
        split("p60-window", "60/40, window + 8 epochs, heal", 6, 4, 2, heal_after_window=8),
        split("p70-window", "70/30, window + 8 epochs, heal", 7, 3, 2, heal_after_window=8),
        split("p67-exact", "exactly 2/3 vs 1/3, 30 epochs, heal", 6, 3, 2, heal=32),
    ]
    # Byzantine keys that vote on both sides of a 50/50 split (100 keys of 1).
    hon_a, hon_b, byz = keyed(34, 1, "a"), keyed(33, 1, "b"), keyed(33, 1, "z", "byz")
    out.append(Scenario("byz33-p50", "33 % equivocators on both sides, 34/33 honest", hon_a + hon_b + byz, 0,
                        {"A": [w.key for w in hon_a], "B": [w.key for w in hon_b]}, 2, 12))
    hon_a, hon_b, byz = keyed(33, 1, "a"), keyed(33, 1, "b"), keyed(34, 1, "z", "byz")
    out.append(Scenario("byz34-p50", "34 % equivocators on both sides, 33/33 honest", hon_a + hon_b + byz, 0,
                        {"A": [w.key for w in hon_a], "B": [w.key for w in hon_b]}, 2, 12))
    # §10: exit, ban and expiry during a stall (single chain, 40 % offline).
    ws = keyed(10, 10, "k")
    ws[1] = Witness("k01", 10, "faulty")
    out.append(Scenario(
        "stall-exit-ban-expiry", "40 % offline epochs 3-15; exit, evidence, expiry during the stall",
        ws, 125, None, None, None, None,
        events=[(1, "stop_mining", "k02", None), (5, "exit", "k00", None), (6, "equivocate", "k01", None)],
        offline={k: (3, 15) for k in ("k06", "k07", "k08", "k09")}, window=6, stall=(3, 15)))
    # §10 in a partition: exit and evidence included on side A only.
    ws = keyed(5, 10, "a") + keyed(5, 10, "b")
    ws[1] = Witness("a01", 10, "faulty")
    out.append(Scenario(
        "p50-exit-ban", "50/50 epochs 2-12; side A includes an exit and an evidence",
        ws, 0, {"A": [w.key for w in ws[:5]], "B": [w.key for w in ws[5:]]}, 2, 12,
        events=[(3, "exit", "a00", "A"), (4, "equivocate", "a01", "A")]))
    # §10 / §4.1: weight that fades out (one key in ten goes for good every
    # day, 40 % in all) against 40 % vanishing at once (single chain).
    ws = keyed(10, 10, "k")
    out.append(Scenario(
        "fade-10pct-daily", "one key in ten offline for good every 4 epochs from epoch 3 (40 % in all)",
        ws, 40, offline={f"k{9 - i:02d}": (3 + 4 * i, 1 << 30) for i in range(4)}, stall=(3, 40)))
    out.append(Scenario(
        "vanish-40pct", "40 % offline for good at epoch 3", keyed(10, 10, "k"), 40,
        offline={f"k{i:02d}": (3, 1 << 30) for i in range(6, 10)}, stall=(3, 40)))
    return out


def run_all() -> dict:
    res = {"format": "obenblock-partition-sim/1", "slots_per_epoch": SLOTS_PER_EPOCH,
           "rule_sets": {r.name: {"poci": r.poci, "strict": r.strict, "decay_div": r.decay_div,
                                  "window": r.window, "ban_epochs": r.ban_epochs,
                                  "exit_message": r.exit_message, "growth_cap": r.growth_cap,
                                  "leak_after": r.leak_after} for r in RULE_SETS},
           "scenarios": []}
    for sc in scenarios():
        entry = {"name": sc.name, "title": sc.title,
                 "witnesses": [[w.key, w.rate, w.role] for w in sc.witnesses],
                 "sides": sc.sides, "start": sc.start, "heal": sc.heal,
                 "heal_after_window": sc.heal_after_window, "window_override": sc.window,
                 "events": [list(x) for x in sc.events],
                 "offline": {k: list(v) for k, v in sorted(sc.offline.items())},
                 "results": {}}
        for r in RULE_SETS:
            entry["results"][r.name] = Sim(sc, r).run().result()
        res["scenarios"].append(entry)
    return res


def serialized(res: dict) -> bytes:
    return (json.dumps(res, indent=1, sort_keys=True) + "\n").encode()


def table(res: dict) -> str:
    hdr = ("scenario", "rules", "W", "A/B weight", "A final", "B final", "conflict ep", "resume ep",
           "evidence", "honest ev")
    rows = []
    for sc in res["scenarios"]:
        for name, r in sc["results"].items():
            br = r["branches"]

            def side(lbl: str) -> str:
                if lbl == "A" and "stall" in r:
                    st = r["stall"]
                    return f"stall:yes@{st['first_epoch_during']}" if st["finalized_during"] else "stall:no"
                b = br.get(lbl)
                if b is None:
                    return "-"
                if not b["finalized_in_partition"]:
                    return "no"
                return f"yes@{b['first_finalized_after_fork_epoch']}"
            wts = "-"
            if "A" in br and "weight" in br["A"]:
                wts = f"{br['A']['weight_pct_x100'] / 100:.1f}/{br['B']['weight_pct_x100'] / 100:.1f}"
            resume = "split" if r["split_after_heal"] else ("-" if r["resume_epoch"] is None else str(r["resume_epoch"]))
            if "stall" in r and r["stall"]["resume_epoch"] is not None:
                resume = str(r["stall"]["resume_epoch"])
            rows.append((sc["name"], name, str(r["window"]), wts, side("A"), side("B"),
                         "-" if r["conflict_epoch"] is None else str(r["conflict_epoch"]), resume,
                         str(len(r["evidence_keys"])), str(len(r["honest_evidence"]))))
    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(hdr)]
    line = lambda cells: "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"  # noqa: E731
    return "\n".join([line(hdr), "|" + "|".join("-" * (w + 2) for w in widths) + "|"] + [line(r) for r in rows])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--write", action="store_true", help="regenerate partition_sim_results.json")
    ap.add_argument("--check", action="store_true", help="fail if the results file differs")
    args = ap.parse_args()
    res = run_all()
    data = serialized(res)
    if args.check:
        if not RESULT_FILE.exists() or RESULT_FILE.read_bytes() != data:
            print(f"{RESULT_FILE.name} differs from what this generates", file=sys.stderr)
            sys.exit(1)
        print(f"{RESULT_FILE.name}: ok")
        return
    if args.write:
        RESULT_FILE.write_bytes(data)
    print(table(res))


if __name__ == "__main__":
    main()
