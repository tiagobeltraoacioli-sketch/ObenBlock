#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extract the SLH-DSA-SHAKE-128s cases from NIST's ACVP-Server FIPS 205 files.

Usage: extract-acvp-slhdsa.py <dir with the three internalProjection.json files> <output.json>

The inputs are the unmodified `internalProjection.json` files of
`gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/` at the pinned
ACVP-Server commit (see ACVP-SLHDSA-PROVENANCE.md); their SHA-256 digests are
checked before anything is read. Only the SLH-DSA-SHAKE-128s groups with the
pure or internal signature interface are kept (GnB never pre-hashes). Hex is
lower-cased; sigGen's expected signatures are replaced by their SHA-256 (the
test compares the digest of the produced signature), sigVer's secret keys and
the unused `deferred` / `hashAlg` / `reason` fields are dropped. Nothing else
is transformed and no expected value is computed here.
"""
import hashlib
import json
from pathlib import Path
import sys

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
FILES = {
    "keyGen": "d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920",
    "sigGen": "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba",
    "sigVer": "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
}
PARAMETER_SET = "SLH-DSA-SHAKE-128s"


def load(directory: Path, mode: str) -> dict:
    raw = (directory / f"SLH-DSA-{mode}-internalProjection.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != FILES[mode]:
        raise SystemExit(f"unreviewed ACVP {mode} file")
    doc = json.loads(raw)
    if doc["algorithm"] != "SLH-DSA" or doc["revision"] != "FIPS205" or doc["mode"] != mode:
        raise SystemExit(f"unexpected ACVP {mode} header")
    return doc


def lower(case: dict, keys) -> dict:
    out = {}
    for k in keys:
        if k in case:
            v = case[k]
            out[k] = v.lower() if isinstance(v, str) else v
    return out


def main() -> None:
    directory, output = Path(sys.argv[1]), Path(sys.argv[2])
    fixture = {"source": f"usnistgov/ACVP-Server@{COMMIT}", "parameterSet": PARAMETER_SET,
               "keyGen": [], "sigGen": [], "sigVer": []}
    for group in load(directory, "keyGen")["testGroups"]:
        if group["parameterSet"] != PARAMETER_SET:
            continue
        for case in group["tests"]:
            fixture["keyGen"].append(lower(case, ["tcId", "skSeed", "skPrf", "pkSeed", "sk", "pk"]))
    for group in load(directory, "sigGen")["testGroups"]:
        if group["parameterSet"] != PARAMETER_SET or group.get("preHash") == "preHash":
            continue
        meta = {"tgId": group["tgId"], "deterministic": group["deterministic"],
                "signatureInterface": group["signatureInterface"], "preHash": group["preHash"]}
        for case in group["tests"]:
            c = lower(case, ["tcId", "sk", "pk", "message", "context", "additionalRandomness"])
            c["signatureSha256"] = hashlib.sha256(bytes.fromhex(case["signature"])).hexdigest()
            c["signatureLen"] = len(case["signature"]) // 2
            fixture["sigGen"].append({**meta, **c})
    for group in load(directory, "sigVer")["testGroups"]:
        if group["parameterSet"] != PARAMETER_SET or group.get("preHash") == "preHash":
            continue
        meta = {"tgId": group["tgId"], "signatureInterface": group["signatureInterface"],
                "preHash": group["preHash"]}
        for case in group["tests"]:
            c = lower(case, ["tcId", "pk", "message", "context", "signature", "testPassed"])
            fixture["sigVer"].append({**meta, **c})
    if (len(fixture["keyGen"]), len(fixture["sigGen"]), len(fixture["sigVer"])) != (10, 28, 28):
        raise SystemExit("unexpected number of SLH-DSA-SHAKE-128s cases")
    output.write_text(json.dumps(fixture, indent=1) + "\n")


if __name__ == "__main__":
    main()
