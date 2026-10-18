"""Deterministic ObenBlock/GnB address-family vectors; no Rust codec calls.

Each case is one string parsed by one family ("gnb" or "obenblock"). Accepted
cases carry the network, the output script and the family's display of the
string (`normalize_legacy_address_in`). Expected verdicts come from the
construction rules (which family emitted the string, what was changed), and
are cross-checked by obb_address.decode. `--check` compares the bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import obb_address as o

VECTOR_FILE = Path(__file__).with_name("obb_address_vectors.json")
SEED = b"ObenBlock address-family corpus / 2026-10 / v1"
FAMILIES = ("gnb", "obenblock")


def _flip_last_hex(s):
    return s[:-1] + ("1" if s[-1] == "0" else "0")


def generate():
    cases = []

    def case(name, address, family, valid, rule, network=None, kind=None, payload=None, display=None):
        c = {"name": name, "address": address, "family": family, "valid": valid, "rule": rule}
        if valid:
            c.update(network=network, kind=kind, script_hex=o.script(kind, payload).hex(), display=display)
        else:
            c["display"] = address
        cases.append(c)

    for network in o.NETWORKS:
        for kind, length in (("single-key", 20), ("policy", 32)):
            label = f"{network}-{kind}"
            patterns = [bytes(length), bytes([255]) * length]
            patterns += [hashlib.shake_256(SEED + label.encode() + bytes([i])).digest(length) for i in range(3)]
            for index, payload in enumerate(patterns):
                forms = {}
                for emitter in FAMILIES:
                    forms[f"{emitter}-legacy"] = (emitter, "legacy", o.render(emitter, network, kind, payload, "legacy"))
                    forms[f"{emitter}-v2"] = (emitter, "v2", o.render(emitter, network, kind, payload, "v2"))
                if kind == "single-key":
                    body = forms["gnb-legacy"][2][len(o.KEY_PREFIX["gnb"][network]):]
                    forms["bloch-legacy"] = ("bloch", "legacy", o.BLOCH_KEY_PREFIX[network] + body)
                for form_name, (emitter, form, address) in forms.items():
                    for family in FAMILIES:
                        name = f"{label}-{index}-{form_name}-in-{family}"
                        accepted = emitter == "bloch" or emitter in o.ACCEPTS[family]
                        if not accepted:
                            case(name, address, family, False, "family-does-not-accept")
                            continue
                        if family == "gnb":
                            display = o.normalize(address, "gnb")
                        else:
                            display = o.render("obenblock", network, kind, payload, form)
                        case(name, address, family, True, "alias" if emitter != family else "own",
                             network, kind, payload, display)
                    if form == "v2":
                        upper = address.upper()
                        for family in FAMILIES:
                            if emitter in o.ACCEPTS[family]:
                                display = upper if family == "gnb" else o.render("obenblock", network, kind, payload, "v2")
                                case(f"{label}-{index}-{form_name}-upper-in-{family}", upper, family, True,
                                     "v2-uppercase", network, kind, payload, display)
                # Tampering, all parsed by ObenBlock (it accepts every form).
                gnb_legacy = forms["gnb-legacy"][2]
                obb_legacy = forms["obenblock-legacy"][2]
                case(f"{label}-{index}-obb-legacy-bad-checksum", _flip_last_hex(obb_legacy), "obenblock", False, "checksum")
                case(f"{label}-{index}-gnb-legacy-bad-checksum", _flip_last_hex(gnb_legacy), "obenblock", False, "checksum")
                if kind == "policy":
                    # The policy checksum covers the prefix: swapping gnb1m
                    # for obb1m without recomputing it must fail, both ways.
                    gp, op = o.POLICY_PREFIX["gnb"][network], o.POLICY_PREFIX["obenblock"][network]
                    case(f"{label}-{index}-policy-prefix-gnb-to-obb", op + gnb_legacy[len(gp):], "obenblock", False,
                         "policy-checksum-binds-prefix")
                    case(f"{label}-{index}-policy-prefix-obb-to-gnb", gp + obb_legacy[len(op):], "obenblock", False,
                         "policy-checksum-binds-prefix")
                    other = "testnet" if network == "mainnet" else "mainnet"
                    case(f"{label}-{index}-policy-network-swap", o.POLICY_PREFIX["obenblock"][other] + obb_legacy[len(op):],
                         "obenblock", False, "policy-checksum-binds-network")
                obb_v2 = forms["obenblock-v2"][2]
                hrp = o.HRP["obenblock"][network]
                for other_hrp in ("gnb", "tgnb", "obb", "tobb"):
                    if other_hrp != hrp:
                        case(f"{label}-{index}-v2-hrp-{other_hrp}", other_hrp + obb_v2[len(hrp):], "obenblock", False,
                             "checksum-binds-hrp")
                case(f"{label}-{index}-v2-mixed-case", obb_v2[0].upper() + obb_v2[1:], "obenblock", False, "uniform-case")
                case(f"{label}-{index}-legacy-upper-prefix", obb_legacy[:5].upper() + obb_legacy[5:], "obenblock", False,
                     "case-sensitive-prefix")

    for name, address in (
        ("empty", ""), ("bloch-policy-not-an-alias", "bloch1m" + "0" * 72),
        ("bitcoin", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        ("obb-short", "obb1qshort"), ("obb-z-short", "obb1zqqqq"),
        ("obb-non-ascii", "obb1zéqqqqqq"), ("tobb-only", "tobb1z"),
    ):
        for family in FAMILIES:
            case(f"{name}-in-{family}", address, family, False, "framing")

    for c in cases:
        try:
            network, kind, payload, _ = o.decode(c["address"], c["family"])
            got = {"valid": True, "network": network, "kind": kind, "script_hex": o.script(kind, payload).hex()}
        except (o.AddressError, o.v2.AddressError):
            got = {"valid": False}
        want = {k: c[k] for k in ("valid", "network", "kind", "script_hex") if k in c}
        if got != want:
            raise SystemExit(f"construction and decoder disagree on {c['name']}: {got} != {want}")
        if o.normalize(c["address"], c["family"]) != c["display"]:
            raise SystemExit(f"display disagrees on {c['name']}")
    return {
        "format": "obenblock-address-family-v1", "seed_hex": SEED.hex(),
        "description": "obb/gnb/bloch address strings parsed per family (DESIGN-obenblock.md §2).",
        "cases": cases,
    }


def serialized():
    return (json.dumps(generate(), indent=2, ensure_ascii=True) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("obb address vectors differ; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    cases = generate()["cases"]
    valid = sum(c["valid"] for c in cases)
    print(f"{len(cases)} vectors: {valid} accepted, {len(cases) - valid} rejected; sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
