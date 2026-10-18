#!/usr/bin/env python3
"""Write a mined ObenBlock mainnet genesis into the source tree.

    apply_genesis.py status <src>
        "placeholder" or "launched <timestamp> <display id> <raw id>"; exit 0.
    apply_genesis.py parse <mine.log>
        The constants gnb-mine-genesis printed, as shell assignments.
    apply_genesis.py apply <src> <mine.log>
        Replace the LAUNCH PLACEHOLDER in crates/gnb-crypto/src/core/genesis.rs
        and in reference/obb_genesis.py with the mined constants (the
        procedure of docs/OBENBLOCK-GENESIS.md, steps 3 and 4). The vectors
        are then rewritten with `python3 reference/obb_genesis.py --write`
        (Python 3.10+, run on the build host).

The tool only edits text it recognises exactly; anything unexpected (an
already launched tree, a changed placeholder) is refused, never guessed.
Python 3.9 or later, standard library only.
"""
import re
import sys
from pathlib import Path

GENESIS_RS = "crates/gnb-crypto/src/core/genesis.rs"
REFERENCE_PY = "reference/obb_genesis.py"
DOC_MD = "docs/OBENBLOCK-GENESIS.md"

PLACEHOLDER_RS = {
    "timestamp": "pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = 0;",
    "version": "pub const OBB_MAINNET_GENESIS_VERSION: u32 = OBB_BLOCK_VERSION;",
    "nonce": "pub const OBB_MAINNET_GENESIS_NONCE: u64 = 0;",
    "hash": "pub const OBB_MAINNET_GENESIS_HASH: [u8; 32] = [0u8; 32];",
}
PLACEHOLDER_COMMENT_RS = (
    "// LAUNCH PLACEHOLDER (owner decision, docs/DESIGN-obenblock.md §3: the\n"
    "// mainnet genesis is mined at launch). The three values below and\n"
    "// `OBB_MAINNET_GENESIS_HASH` are produced by\n"
    "// `OBB_MAINNET_GENESIS_MINE_COMMAND` with the launch timestamp; until then\n"
    "// the timestamp is 0 and a node refuses to start ObenBlock mainnet.\n"
)
PLACEHOLDER_PY = '    "mainnet": {"bits": o.POW_LIMIT_BITS},\n'
PLACEHOLDER_COMMENT_PY = (
    "    # LAUNCH PLACEHOLDER: at launch add \"timestamp\", \"version\" and \"nonce\"\n"
    "    # (the constants gnb-mine-genesis printed) and run --write.\n"
)


class Refused(Exception):
    pass


def parse_log(text):
    """The four constants of the mainnet block the tool printed."""
    out = {}
    m = re.search(r"pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = (\d+);", text)
    if m:
        out["timestamp"] = int(m.group(1))
    m = re.search(r"pub const OBB_MAINNET_GENESIS_VERSION: u32 = 0x([0-9A-Fa-f]{8});", text)
    if m:
        out["version"] = int(m.group(1), 16)
    m = re.search(r"pub const OBB_MAINNET_GENESIS_NONCE: u64 = (\d+);", text)
    if m:
        out["nonce"] = int(m.group(1))
    m = re.search(r"pub const OBB_MAINNET_GENESIS_HASH: \[u8; 32\] = \[(.*?)\];", text, re.S)
    if m:
        raw = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
        if len(raw) == 32:
            out["hash"] = raw
    m = re.search(r"genesis block id \(Bitcoin display order\): ([0-9a-f]{64})", text)
    if m:
        out["display"] = m.group(1)
    missing = [k for k in ("timestamp", "version", "nonce", "hash", "display") if k not in out]
    if missing:
        raise Refused("the mining log lacks " + ", ".join(missing) + " (not a finished mainnet run)")
    if out["hash"][::-1].hex() != out["display"]:
        raise Refused("the raw and display block ids in the log disagree")
    if out["timestamp"] == 0 or out["timestamp"] >= 2 ** 32 or out["nonce"] >= 2 ** 32:
        raise Refused("timestamp or nonce out of range")
    if out["version"] & ~0x1FFFE000 != 0x20000000:
        raise Refused("version 0x%08x breaks the BIP 320 rule" % out["version"])
    if not out["display"].startswith("00000000"):
        raise Refused("the block id does not meet difficulty 1")
    return out


def rust_bytes(b):
    rows = [", ".join("0x%02x" % x for x in b[i:i + 8]) for i in range(0, 32, 8)]
    return "[\n" + "".join("    %s,\n" % r for r in rows) + "]"


def status(src):
    text = (src / GENESIS_RS).read_text()
    if PLACEHOLDER_RS["timestamp"] in text:
        return "placeholder"
    ts = re.search(r"pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = ([\d_]+);", text)
    h = re.search(r"pub const OBB_MAINNET_GENESIS_HASH: \[u8; 32\] = \[(.*?)\];", text, re.S)
    if not ts or not h:
        raise Refused(f"{GENESIS_RS}: mainnet constants not found")
    raw = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", h.group(1)))
    return "launched %s %s %s" % (ts.group(1).replace("_", ""), raw[::-1].hex(), raw.hex())


def apply(src, c):
    rs_path, py_path = src / GENESIS_RS, src / REFERENCE_PY
    rs, py = rs_path.read_text(), py_path.read_text()
    for key, line in PLACEHOLDER_RS.items():
        if rs.count(line) != 1:
            raise Refused(f"{GENESIS_RS}: placeholder line for {key} not found exactly once (already launched?)")
    if rs.count(PLACEHOLDER_COMMENT_RS) != 1:
        raise Refused(f"{GENESIS_RS}: LAUNCH PLACEHOLDER comment changed; update this tool")
    if py.count(PLACEHOLDER_PY) != 1 or py.count(PLACEHOLDER_COMMENT_PY) != 1:
        raise Refused(f"{REFERENCE_PY}: mainnet placeholder not found exactly once (already launched?)")

    rs = rs.replace(PLACEHOLDER_COMMENT_RS, (
        "// LAUNCHED: mined with `OBB_MAINNET_GENESIS_MINE_COMMAND` at the launch\n"
        "// timestamp (docs/OBENBLOCK-GENESIS.md; deploy/obenblock-launch). Block id\n"
        f"// {c['display']} (display order).\n"))
    rs = rs.replace(PLACEHOLDER_RS["timestamp"], "pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = %d;" % c["timestamp"])
    rs = rs.replace(PLACEHOLDER_RS["version"], "pub const OBB_MAINNET_GENESIS_VERSION: u32 = 0x%08X;" % c["version"])
    rs = rs.replace(PLACEHOLDER_RS["nonce"], "pub const OBB_MAINNET_GENESIS_NONCE: u64 = %d;" % c["nonce"])
    rs = rs.replace(PLACEHOLDER_RS["hash"], "pub const OBB_MAINNET_GENESIS_HASH: [u8; 32] = %s;" % rust_bytes(c["hash"]))
    rs = rs.replace("/// **0 = not launched (placeholder).**\n", "")
    rs = rs.replace("/// BIP 320 bits the genesis search rolled. **Placeholder until launch.**",
                    "/// BIP 320 bits the genesis search rolled.")
    rs = rs.replace("/// Nonce of the mainnet genesis. **Placeholder until launch.**", "/// Nonce of the mainnet genesis.")
    rs = rs.replace("/// Block id of the mainnet genesis. **All zero = not launched (placeholder).**",
                    "/// Block id of the mainnet genesis (raw SHA-256d digest).")

    py = py.replace(PLACEHOLDER_COMMENT_PY, "    # LAUNCHED: the constants gnb-mine-genesis printed at launch.\n")
    py = py.replace(PLACEHOLDER_PY, '    "mainnet": {"bits": o.POW_LIMIT_BITS,\n'
                    '                "timestamp": %d, "version": 0x%08X, "nonce": %d},\n'
                    % (c["timestamp"], c["version"], c["nonce"]))
    rs_path.write_text(rs)
    py_path.write_text(py)

    doc = src / DOC_MD
    notes = []
    if doc.exists():
        d = doc.read_text()
        rows = {
            "| timestamp | **set at launch** |": "| timestamp | %d |" % c["timestamp"],
            "| version | `0x20000000` + rolled BIP 320 bits, **set at launch** |": "| version | `0x%08x` |" % c["version"],
            "| nonce | **set at launch** |": "| nonce | %d |" % c["nonce"],
            "| block id (display order) | **set at launch** |": "| block id (display order) | `%s` |" % c["display"],
        }
        for old, new in rows.items():
            if d.count(old) == 1:
                d = d.replace(old, new)
            else:
                notes.append(f"{DOC_MD}: row not found, update by hand: {old}")
        doc.write_text(d)
    return notes


def main(argv):
    try:
        if len(argv) == 3 and argv[1] == "status":
            print(status(Path(argv[2])))
            return 0
        if len(argv) == 3 and argv[1] == "parse":
            c = parse_log(Path(argv[2]).read_text(errors="replace"))
            print("GENESIS_TIMESTAMP=%d" % c["timestamp"])
            print("GENESIS_VERSION=0x%08x" % c["version"])
            print("GENESIS_NONCE=%d" % c["nonce"])
            print("GENESIS_HASH_RAW=%s" % c["hash"].hex())
            print("GENESIS_HASH=%s" % c["display"])
            return 0
        if len(argv) == 4 and argv[1] == "apply":
            src = Path(argv[2])
            c = parse_log(Path(argv[3]).read_text(errors="replace"))
            for n in apply(src, c):
                print("note:", n, file=sys.stderr)
            print("applied timestamp %d version 0x%08x nonce %d id %s" % (c["timestamp"], c["version"], c["nonce"], c["display"]))
            return 0
    except Refused as e:
        print("apply_genesis.py: refused:", e, file=sys.stderr)
        return 1
    print(__doc__.strip(), file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
