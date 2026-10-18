"""PoWit witness set, justification threshold, evidence rule and attestation
messages -- executable reference specification.

The normative definition of the PoWit rules that the second hardening
upgrade changes (docs/CONSENSUS.md, "PoWit"; docs/DESIGN-pow-powit.md, sections
3-5 and 7.4; PoWit audit findings 1, 3 and 4). Written from the specification with
hashlib only. `crates/gnb-crypto/src/core/powit.rs` must reproduce
`powit_vectors.json` exactly (`crates/gnb-crypto/tests/powit_vectors.rs`).

    python3 reference/powit_reference.py            # regenerate powit_vectors.json
    python3 reference/powit_reference.py --check    # CI: the file is what this generates
    python3 reference/powit_reference_test.py -v    # the reference's own tests

Regime. A block at height h is checked under the old rules (V1) when
h < H2 and under the second hardening rules (H2) when h >= H2, where H2 is
the second hardening activation height (mainnet: not scheduled, testnet and
regtest: 0). An attestation's MESSAGE version follows its TARGET height
instead (a witness signs before any block includes the vote): v2 iff
target.height >= H2, and every message checked in a V1 block is v1.

    msg_v1 = SHA3-256( u32le(19) || "GNB-POWIT-v1/attest" || u32le(chain_id)
                       || u64le(src.height) || src.hash || u64le(tgt.height) || tgt.hash )
    msg_v2 = SHA3-256( u32le(19) || "GNB-POWIT-v2/attest" || u32le(chain_id)
                       || u8(depth) || root
                       || u64le(src.height) || src.hash || u64le(tgt.height) || tgt.hash )
    witness_id(depth, root) = SHA3-256("GNB-KES-v1/id" || u8(depth) || root)[0:20]

Witness set W(e) of a state (epochs counted from the PoWit activation):

    W(e) = {} for e < 2; otherwise for every key k with share work in
    epochs max(0, e-1-window) ..= e-2:
        weight(k) = decayed(sum of that work, decay[k])      (sums saturate at 2^128-1)
    keeping keys not barred at e (banned[k] > e) with weight > 0, sorted by
    weight descending then key ascending;
    V1: the first max_witnesses (64) of them; H2: all of them.
    decayed(w, n) = w after min(n, 64) steps of w -= w // 16.

H2 reads finalized history (PoWit audit finding 3). With act the state's
PoWit activation height and nf = (finalized.height - act) // epoch_len (the
epochs entirely below the state's finalized checkpoint):

    anchored(e)        = e if nf == 0 else min(e, nf + 1)
    h2_window_epoch(e) = e if anchored(e) != e and the window of anchored(e)
                           has no member at e, else anchored(e)
    W_H2(e)            = the members of h2_window_epoch(e)'s window (epochs
                         max(0, x-1-window) ..= x-2 for x = h2_window_epoch(e)),
                         bars applied at e, uncapped.

While finality keeps up h2_window_epoch(e) = e; when it lags the set freezes
at the last finalized window until another checkpoint is finalized.

Justification: votes for a target t from the justified source justify t iff
total(W(epoch(t))) != 0 and 3 * sum(votes) >= 2 * total (both sides
saturating at 2^128-1); V1 counts total over the 64 heaviest, H2 over every
key (two thirds of all the window weight, as Casper FFG counts all stake).

Evidence (H2 blocks only): a block of PoWit epoch E may carry an
equivocation proof against key k only if k is a member of W(x) for some x in
E-1 ..= E+1 (saturating at 0), computed on the block's state after its epoch
step; V1 blocks accept a proof against any key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

VECTOR_FILE = Path(__file__).with_name("powit_vectors.json")

CHAIN_MAINNET = 0x474E_0001
CHAIN_TESTNET = 0x474E_0002
NEVER = 2**64 - 1
U128_MAX = 2**128 - 1

DS_ATTEST_V1 = b"GNB-POWIT-v1/attest"
DS_ATTEST_V2 = b"GNB-POWIT-v2/attest"
DS_KES_ID = b"GNB-KES-v1/id"

PARAMS = {
    "mainnet": {"epoch_len": 720, "checkpoint_interval": 60, "window_epochs": 28, "max_witnesses": 64,
                "max_attestations_per_block": 32, "max_evidence_per_block": 4, "vote_ttl": 720,
                "leak_after_epochs": 4, "ban_epochs": 28},
    "testnet": {"epoch_len": 20, "checkpoint_interval": 5, "window_epochs": 3, "max_witnesses": 64,
                "max_attestations_per_block": 32, "max_evidence_per_block": 4, "vote_ttl": 20,
                "leak_after_epochs": 4, "ban_epochs": 3},
}

V1 = "v1"
H2 = "hardening2"


def sha3(*parts: bytes) -> bytes:
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def u32le(v: int) -> bytes:
    return v.to_bytes(4, "little")


def u64le(v: int) -> bytes:
    return v.to_bytes(8, "little")


def sat_add(a: int, b: int) -> int:
    return min(a + b, U128_MAX)


def sat_mul(a: int, b: int) -> int:
    return min(a * b, U128_MAX)


# ── Activation ───────────────────────────────────────────────────────────────

def regime_at(height: int, h2: int) -> str:
    return H2 if height >= h2 else V1


# ── Messages ─────────────────────────────────────────────────────────────────

def message_v1(chain: int, src: tuple[int, bytes], tgt: tuple[int, bytes]) -> bytes:
    return sha3(u32le(len(DS_ATTEST_V1)), DS_ATTEST_V1, u32le(chain),
                u64le(src[0]), src[1], u64le(tgt[0]), tgt[1])


def message_v2_preimage(chain: int, depth: int, root: bytes, src: tuple[int, bytes], tgt: tuple[int, bytes]) -> bytes:
    assert 0 <= depth <= 255 and len(root) == 32 and len(src[1]) == 32 and len(tgt[1]) == 32
    return b"".join([u32le(len(DS_ATTEST_V2)), DS_ATTEST_V2, u32le(chain), bytes([depth]), root,
                     u64le(src[0]), src[1], u64le(tgt[0]), tgt[1]])


def message_v2(chain: int, depth: int, root: bytes, src: tuple[int, bytes], tgt: tuple[int, bytes]) -> bytes:
    return sha3(message_v2_preimage(chain, depth, root, src, tgt))


def message_at(chain: int, h2: int, depth: int, root: bytes, src, tgt) -> bytes:
    """The message for a link: v2 iff the target height is >= H2."""
    return message_v2(chain, depth, root, src, tgt) if tgt[0] >= h2 else message_v1(chain, src, tgt)


def witness_id(depth: int, root: bytes) -> bytes:
    return sha3(DS_KES_ID, bytes([depth]), root)[:20]


# ── Witness set and threshold ────────────────────────────────────────────────

def decayed(w: int, steps: int) -> int:
    for _ in range(min(steps, 64)):
        w -= w // 16
    return w


def is_banned(state: dict, key: bytes, epoch: int) -> bool:
    until = state["banned"].get(key)
    return until is not None and epoch < until


def window(params: dict, epoch: int) -> tuple[int, int]:
    return max(0, epoch - 1 - params["window_epochs"]), epoch - 2


def window_members(state: dict, params: dict, window_epoch: int, bar_epoch: int) -> list[tuple[bytes, int]]:
    """Every key with positive decayed work in window_epoch's window, not
    barred at bar_epoch: [(key, weight)] in key order."""
    if window_epoch < 2:
        return []
    lo, hi = window(params, window_epoch)
    total: dict[bytes, int] = {}
    for e, m in state["epoch_work"].items():
        if lo <= e <= hi:
            for k, w in m.items():
                total[k] = sat_add(total.get(k, 0), w)
    out = []
    for k in sorted(total):
        if is_banned(state, k, bar_epoch):
            continue
        w = decayed(total[k], state["decay"].get(k, 0))
        if w > 0:
            out.append((k, w))
    return out


def finalized_epochs(state: dict, params: dict) -> int:
    act = state.get("activation", 0)
    return max(0, state.get("finalized_height", act) - act) // params["epoch_len"]


def anchored_epoch(state: dict, params: dict, epoch: int) -> int:
    nf = finalized_epochs(state, params)
    return epoch if nf == 0 else min(epoch, nf + 1)


def h2_window_epoch(state: dict, params: dict, epoch: int) -> int:
    a = anchored_epoch(state, params, epoch)
    if a != epoch and not window_members(state, params, a, epoch):
        return epoch
    return a


def witness_set(state: dict, params: dict, epoch: int, regime: str) -> list[tuple[bytes, int]]:
    """W(epoch): [(key, weight)], heaviest first, ties by key."""
    if regime == V1:
        out = window_members(state, params, epoch, epoch)
    else:
        out = window_members(state, params, h2_window_epoch(state, params, epoch), epoch)
    out.sort(key=lambda kw: (-kw[1], kw[0]))
    if regime == V1:
        out = out[:params["max_witnesses"]]
    return out


def member_weight_h2(state: dict, params: dict, epoch: int, key: bytes):
    for k, w in witness_set(state, params, epoch, H2):
        if k == key:
            return w
    return None


def total_weight(state: dict, params: dict, epoch: int, regime: str) -> int:
    t = 0
    for _, w in witness_set(state, params, epoch, regime):
        t = sat_add(t, w)
    return t


def two_thirds(got: int, total: int) -> bool:
    return total != 0 and sat_mul(got, 3) >= sat_mul(total, 2)


def evidence_epochs(epoch: int) -> list[int]:
    return list(range(max(0, epoch - 1), epoch + 2))


def may_be_proven_h2(state: dict, params: dict, epoch: int, key: bytes) -> bool:
    return any(member_weight_h2(state, params, x, key) is not None for x in evidence_epochs(epoch))


# ── Vectors ──────────────────────────────────────────────────────────────────

def key(label: str, i: int) -> bytes:
    return sha3(b"powit-vector-key", label.encode(), u32le(i))[:20]


def hash32(label: str, i: int) -> bytes:
    return sha3(b"powit-vector-hash", label.encode(), u32le(i))


def state_json(state: dict) -> dict:
    out = {
        "epoch_work": {str(e): {k.hex(): str(w) for k, w in sorted(m.items())} for e, m in sorted(state["epoch_work"].items())},
        "banned": {k.hex(): u for k, u in sorted(state["banned"].items())},
        "decay": {k.hex(): d for k, d in sorted(state["decay"].items())},
    }
    for f in ("activation", "finalized_height"):
        if f in state:
            out[f] = state[f]
    return out


def ws_json(ws) -> list:
    return [[k.hex(), str(w)] for k, w in ws]


def finding4_state() -> tuple[dict, list[bytes], list[bytes]]:
    """PoWit audit finding 4: 200 honest keys with 0.35% of the share work
    each and an attacker with 30% split over 60 keys of 0.5% (weights 35 and
    50 of 10,000), all in epoch 0 (W(2) counts epoch 0 only)."""
    honest = [key("honest", i) for i in range(200)]
    attacker = [key("attacker", i) for i in range(60)]
    work = {k: 35 for k in honest}
    work.update({k: 50 for k in attacker})
    return {"epoch_work": {0: work}, "banned": {}, "decay": {}}, honest, attacker


def generate() -> dict:
    root = hash32("root", 0)
    src = (10_000, hash32("source", 0))
    tgt = (10_060, hash32("target", 0))
    messages = []
    for chain in (CHAIN_MAINNET, CHAIN_TESTNET):
        for depth, r in ((12, root), (1, hash32("root", 1)), (16, bytes(32))):
            for h2 in (0, 10_060, 10_061, NEVER):
                messages.append({
                    "chain_id": chain, "depth": depth, "root": r.hex(),
                    "source": {"height": src[0], "hash": src[1].hex()},
                    "target": {"height": tgt[0], "hash": tgt[1].hex()},
                    "hardening2_height": str(h2),
                    "v1": message_v1(chain, src, tgt).hex(),
                    "v2_preimage": message_v2_preimage(chain, depth, r, src, tgt).hex(),
                    "v2": message_v2(chain, depth, r, src, tgt).hex(),
                    "message_at": message_at(chain, h2, depth, r, src, tgt).hex(),
                    "witness_id": witness_id(depth, r).hex(),
                })

    regimes = [{"height": h, "hardening2_height": str(a), "regime": regime_at(h, a)}
               for h, a in ((0, 0), (17_499, 17_500), (17_500, 17_500), (2**63, NEVER), (NEVER - 1, NEVER))]

    decays = [{"weight": str(w), "steps": s, "decayed": str(decayed(w, s))}
              for w in (0, 1, 15, 16, 17, 1_000_000, U128_MAX) for s in (0, 1, 2, 16, 64, 65, 1_000)]

    thresholds = [{"got": str(g), "total": str(t), "justifies": two_thirds(g, t)}
                  for g, t in ((0, 0), (5, 0), (2, 3), (1, 3), (129, 190), (129, 199), (132, 199), (133, 199),
                               (6_667, 10_000), (6_666, 10_000), (3_000, 3_140), (3_000, 10_000),
                               (U128_MAX, U128_MAX), (U128_MAX // 2, U128_MAX))]

    # Witness sets: the cap, the window, bans, decay, ties, and the evidence epochs.
    sets = []
    p = PARAMS["testnet"]
    fill = [key("filler", i) for i in range(70)]
    a, b, c, d = (key("member", i) for i in range(4))
    st = {"epoch_work": {0: {a: 43, b: 43, c: 43, **{k: 1 for k in fill}}}, "banned": {}, "decay": {}}
    sets.append(("cap_decides_the_threshold", "testnet", st, [2, 3, 4, 5], []))
    st = {"epoch_work": {0: {a: 10}, 1: {b: 50}, 2: {c: 7}, 3: {d: 5}, 5: {a: 1}},
          "banned": {b: 5}, "decay": {a: 3, c: 70}}
    sets.append(("window_bans_decay", "testnet", st, [1, 2, 3, 4, 5, 6, 7, 8], [(e, k) for e in (3, 5, 6, 7) for k in (a, b, c, d)]))
    st = {"epoch_work": {e: {d: 1_000} for e in range(7)}, "banned": {}, "decay": {}}
    for e, k in ((1, a), (5, b), (6, c)):
        st["epoch_work"][e][k] = 1_000
    sets.append(("evidence_epochs", "testnet", st, [5, 6, 7, 8], [(6, k) for k in (a, b, c, d, key("nobody", 0))]))
    st = {"epoch_work": {e: {a: 5_000, b: 7, c: U128_MAX} for e in range(30)}, "banned": {c: 31}, "decay": {}}
    sets.append(("mainnet_window_saturation", "mainnet", st, [2, 29, 30, 31, 32], [(30, k) for k in (a, b, c)]))
    st, honest, attacker = finding4_state()
    sets.append(("finding4", "testnet", st, [2], [(2, honest[0]), (2, attacker[0])]))
    # Finding 3: W from finalized history (testnet epochs of 20 blocks,
    # activation 100). Two witnesses a, b every epoch; a newcomer n from
    # epoch 4 on, with as much work as both.
    work = {e: {a: 1_000, b: 1_000, **({n: 2_000} if e >= 4 else {})} for e in range(10)
            for n in [key("newcomer", 0)]}
    n = key("newcomer", 0)
    st = {"epoch_work": work, "banned": {}, "decay": {}, "activation": 100, "finalized_height": 100 + 8 * 20 + 5}
    sets.append(("finalized_history_keeps_up", "testnet", st, list(range(2, 12)), [(9, n)]))
    st = {"epoch_work": work, "banned": {}, "decay": {}, "activation": 100, "finalized_height": 100 + 3 * 20 + 5}
    sets.append(("finalized_history_lags_frozen", "testnet", st, list(range(2, 12)), [(e, n) for e in (4, 5, 6, 9)]))
    st = {"epoch_work": {e: {n: 2_000} for e in range(5, 10)}, "banned": {}, "decay": {},
          "activation": 100, "finalized_height": 100 + 3 * 20 + 5}
    sets.append(("finalized_history_empty_frozen_window", "testnet", st, [4, 5, 6, 7, 9, 11], [(9, n)]))
    st = {"epoch_work": {0: {a: 1_000}, 1: {a: 1_000}, 2: {b: 500}, 5: {c: 3_000}, 6: {c: 3_000}},
          "banned": {a: 8}, "decay": {b: 2}, "activation": 100, "finalized_height": 100 + 3 * 20 + 5}
    sets.append(("finalized_history_bars_at_the_epoch", "testnet", st, [4, 5, 7, 8, 9], [(e, k) for e in (7, 8) for k in (a, b, c)]))

    witness_sets = []
    for name, net, st, epochs, proofs in sets:
        p = PARAMS[net]
        witness_sets.append({
            "name": name, "params": net, "state": state_json(st),
            "epochs": [{
                "epoch": e,
                "v1": ws_json(witness_set(st, p, e, V1)),
                "hardening2": ws_json(witness_set(st, p, e, H2)),
                "total_v1": str(total_weight(st, p, e, V1)),
                "total_hardening2": str(total_weight(st, p, e, H2)),
            } for e in epochs],
            "evidence": [{"block_epoch": e, "key": k.hex(), "may_be_proven": may_be_proven_h2(st, p, e, k),
                          "member_weights": {str(x): (None if (w := member_weight_h2(st, p, x, k)) is None else str(w))
                                             for x in evidence_epochs(e)}} for e, k in proofs],
        })

    # Finding 4 in numbers: who can justify W(2)'s target alone.
    st, honest, attacker = finding4_state()
    p = PARAMS["testnet"]
    f4 = {}
    for regime in (V1, H2):
        ws = dict(witness_set(st, p, 2, regime))
        total = total_weight(st, p, 2, regime)
        att = sum(ws.get(k, 0) for k in attacker)
        hon = sum(ws.get(k, 0) for k in honest)
        f4[regime] = {
            "members": len(ws), "total": str(total),
            "attacker_weight_in_w": str(att), "honest_weight_in_w": str(hon),
            "attacker_alone_justifies": two_thirds(att, total),
            "honest_alone_justify": two_thirds(hon, total),
            "honest_voters_needed": next(n for n in range(len(honest) + 1) if two_thirds(35 * n, total))
            if two_thirds(hon, total) else None,
        }

    return {
        "format": "gnb-powit-vectors-v1",
        "description": "PoWit messages, witness sets, threshold and evidence rule (reference/powit_reference.py)",
        "constants": {
            "chain_mainnet": CHAIN_MAINNET, "chain_testnet": CHAIN_TESTNET, "never": str(NEVER),
            "ds_attest_v1": DS_ATTEST_V1.decode(), "ds_attest_v2": DS_ATTEST_V2.decode(),
            "v2_preimage_len": len(message_v2_preimage(CHAIN_MAINNET, 12, root, src, tgt)),
            "params": PARAMS,
        },
        "messages": messages,
        "regimes": regimes,
        "decayed": decays,
        "two_thirds": thresholds,
        "witness_sets": witness_sets,
        "finding4": f4,
    }


def serialized() -> bytes:
    return (json.dumps(generate(), indent=1, sort_keys=False) + "\n").encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if powit_vectors.json differs")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if not VECTOR_FILE.exists() or VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("powit vectors differ from the reference; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    doc = generate()
    print(f"{len(doc['messages'])} messages, {len(doc['witness_sets'])} witness-set cases, "
          f"{len(doc['two_thirds'])} thresholds; sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
