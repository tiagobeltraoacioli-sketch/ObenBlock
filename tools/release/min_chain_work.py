#!/usr/bin/env python3
"""Read the mainnet minimum chain work for a release (`core::MIN_CHAIN_WORK`).

Bitcoin Core's release process sets `nMinimumChainWork` to the chain work
(`getblockheader` "chainwork") of a block somewhat below the tip at release
time, read from the node(s) of the person cutting the release. GnB does the
same with its unit, the selected-chain block's `blue_work`
(docs/RUNNING.md, "Initial sync and minimum chain work"):

1. On every node given with --rpc (at least two, run by different people on
   different machines): `getnetworkinfo` (the network, not syncing),
   `getdaginfo` (tip, `tip_blue_work`, the node's `minimum_chain_work`),
   `getselectedchain [depth, 1]` (the selected-chain block `depth` blocks
   below that node's tip; 2,880 by default, about a day at 30 s) and
   `getblockdag [hash]` (its `blue_work`, height and time).
2. The LOWER of the readings is the candidate. Its block must be on the
   selected chain of every node (`getblockdag` colour "chain") with the same
   blue work on each (blue work is a pure function of the block's past):
   otherwise the nodes are not on one chain and nothing is printed.
3. The value is the candidate rounded DOWN to two significant digits, so it
   stays below the real chain whatever the nodes' small differences, and is
   easy to review. It must not be below the value the nodes already run.

It prints the readings and the line to put in
crates/gnb-crypto/src/core/mod.rs, plus the `--minimumchainwork` hex form,
and the assumed-valid block of the release (Bitcoin Core's
`defaultAssumeValid`, which Core's release process sets from the same block
as `nMinimumChainWork`): the candidate block's hash and DAG height, as the
line for `MAINNET_ASSUME_VALID` in node/src/assumevalid.rs and the
`--assumevalid` form. The node skips signature checks only for that block's
selected-chain ancestors buried two weeks below its best block
(docs/RUNNING.md). The same block is the release finality checkpoint
(weak subjectivity, PoWit finding 3): the line for
`MAINNET_FINALITY_CHECKPOINT` in node/src/powit.rs. Nothing is written.
Standard library only.

    python3 tools/release/min_chain_work.py \\
        --rpc http://127.0.0.1:17210 --rpc https://node2.example:17210

`GNB_RPC_API_KEY` (or --api-key-env NAME) is sent as `x-api-key`, as
gnb-cli does: over https, or plain http to a loopback address only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

DEFAULT_DEPTH = 2_880  # selected-chain blocks below the tip: ~1 day at 30 s
MIN_NODES = 2


class ReadingError(RuntimeError):
    pass


def round_down(value: int, digits: int = 2) -> int:
    """`value` rounded down to `digits` significant decimal digits."""
    if value < 0:
        raise ValueError("chain work is never negative")
    s = str(value)
    if len(s) <= digits:
        return value
    scale = 10 ** (len(s) - digits)
    return value // scale * scale


def _loopback(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_caller(url: str, api_key: str | None, cafile: str | None, timeout: float = 30.0):
    """A `call(method, params) -> result` for the JSON-RPC endpoint `url`
    (POST /, JSON-RPC 2.0, as gnb-cli)."""
    if "://" not in url:
        url = "http://" + url
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise ReadingError(f"{url}: http:// or https:// only")
    if api_key and scheme == "http" and not _loopback(url):
        raise ReadingError(f"{url}: the API key goes over https, or plain http to a loopback address only")
    ctx = ssl.create_default_context(cafile=cafile) if scheme == "https" else None

    def call(method: str, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": [] if params is None else params}).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        if api_key:
            req.add_header("x-api-key", api_key)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            doc = json.loads(resp.read(8 << 20))
        if doc.get("error"):
            raise ReadingError(f"{url} {method}: {doc['error']}")
        result = doc.get("result")
        if isinstance(result, dict) and result.get("error"):
            raise ReadingError(f"{url} {method}: {result['error']}")
        return result

    return call


def read_node(name: str, call, depth: int, network: str) -> dict:
    """One node's reading: the selected-chain block `depth` below its tip."""
    info = call("getnetworkinfo")
    if info.get("network") != network:
        raise ReadingError(f"{name}: runs {info.get('network')!r}, not {network!r}")
    dag = call("getdaginfo")
    page = call("getselectedchain", [depth, 1])
    blocks = page.get("blocks") or []
    if not blocks:
        raise ReadingError(f"{name}: the selected chain has {page.get('chain_length')} blocks, "
                           f"none {depth} below the tip")
    block = call("getblockdag", [blocks[0]["hash"]])
    if block.get("colour") != "chain":
        raise ReadingError(f"{name}: block {block.get('hash')} is not on its selected chain")
    return {
        "name": name,
        "syncing": bool(info.get("syncing")),
        "version": info.get("version"),
        "tip": dag.get("tip"),
        "tip_height": dag.get("tip_height"),
        "tip_blue_work": int(dag.get("tip_blue_work") or 0),
        # Releases before this tool do not report it.
        "running_minimum": int(dag["minimum_chain_work"]) if "minimum_chain_work" in dag else None,
        "hash": block["hash"],
        "height": block["height"],
        "timestamp": block.get("timestamp"),
        "blue_work": int(block["blue_work"]),
    }


def choose(readings: list[dict], calls: dict, allow_single: bool = False) -> tuple[dict, int, list[str]]:
    """(candidate reading, value to set, warnings). Raises when the readings
    cannot be trusted."""
    if len(readings) < MIN_NODES and not allow_single:
        raise ReadingError(f"read {len(readings)} node(s): a release needs at least {MIN_NODES} independent ones")
    warnings = []
    for r in readings:
        if r["syncing"]:
            warnings.append(f"{r['name']} reports syncing: its tip may be behind (its reading is only lower)")
    cand = min(readings, key=lambda r: (r["blue_work"], r["name"]))
    for r in readings:
        seen = calls[r["name"]]("getblockdag", [cand["hash"]])
        if seen.get("colour") != "chain":
            raise ReadingError(f"{r['name']}: block {cand['hash']} (from {cand['name']}) is not on its "
                               f"selected chain ({seen.get('colour')!r}): the nodes are not on one chain")
        if int(seen["blue_work"]) != cand["blue_work"]:
            raise ReadingError(f"{r['name']}: block {cand['hash']} has blue work {seen['blue_work']}, "
                               f"{cand['name']} says {cand['blue_work']}")
    value = round_down(cand["blue_work"])
    if value == 0:
        raise ReadingError("the candidate block carries no work")
    running = [r["running_minimum"] for r in readings if r["running_minimum"] is not None]
    if running and value < max(running):
        raise ReadingError(f"value {value} is below the minimum chain work a node already runs "
                           f"({max(running)}): the minimum never goes down between releases")
    for r in readings:
        if value > r["tip_blue_work"]:
            raise ReadingError(f"value {value} is above {r['name']}'s tip work {r['tip_blue_work']}")
    return cand, value, warnings


def assume_valid_line(cand: dict) -> str:
    """The `MAINNET_ASSUME_VALID` line of node/src/assumevalid.rs for the
    candidate block (its id as the RPC prints it, and its DAG height)."""
    h = cand["hash"]
    if not (isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h)):
        raise ReadingError(f"block id {h!r} is not 64 lowercase hex digits")
    if not isinstance(cand["height"], int) or cand["height"] < 1:
        raise ReadingError(f"block {h} has no DAG height above the genesis")
    return (f"    pub const MAINNET_ASSUME_VALID: Option<AssumedValidBlock> =\n"
            f"        Some(AssumedValidBlock::from_hex(\"{h}\", {cand['height']}));")


def finality_checkpoint_line(cand: dict) -> str:
    """The `MAINNET_FINALITY_CHECKPOINT` line of node/src/powit.rs (the
    release finality checkpoint, weak subjectivity) for the candidate block."""
    assume_valid_line(cand)  # the same checks on the block id and height
    return (f"    pub const MAINNET_FINALITY_CHECKPOINT: Option<ReleaseCheckpoint> =\n"
            f"        Some(ReleaseCheckpoint::from_hex(\"{cand['hash']}\", {cand['height']}));")


def report(readings: list[dict], cand: dict, value: int, depth: int, warnings: list[str]) -> str:
    lines = [f"Readings (selected-chain block {depth} below each node's tip):"]
    for r in readings:
        lines.append(f"  {r['name']}: tip height {r['tip_height']} work {r['tip_blue_work']:,}; "
                     f"block {r['hash'][:16]}… height {r['height']} work {r['blue_work']:,}"
                     + ("" if r["running_minimum"] is None else f"; runs minimum {r['running_minimum']:,}"))
    for w in warnings:
        lines.append(f"  warning: {w}")
    lines += [
        f"Lower reading: {cand['name']}, block {cand['hash']} (height {cand['height']}, "
        f"time {cand['timestamp']}), blue work {cand['blue_work']:,}, on every node's selected chain.",
        f"Value (rounded down to two significant digits): {value:,} = {value:#x}",
        "",
        "crates/gnb-crypto/src/core/mod.rs:",
        f"    pub const MIN_CHAIN_WORK: u128 = {value:_};",
        f"--minimumchainwork {value:x}",
        "",
        "node/src/assumevalid.rs (the assumed-valid block, the same block):",
        assume_valid_line(cand),
        f"--assumevalid {cand['hash']}",
        "",
        "node/src/powit.rs (the release finality checkpoint, the same block):",
        finality_checkpoint_line(cand),
        "",
        "Then update the reading in its documentation and in docs/MAINNET-READINESS.md §1,",
        "the arithmetic test (`min_chain_work_cross_check`) and the node tests that pin",
        "the value (`assumevalid::tests::release_values_and_core_burial` for the",
        "assumed-valid block), and confirm a fresh sync from the seeds leaves initial",
        "block download.",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rpc", action="append", required=True, metavar="URL",
                    help="JSON-RPC endpoint of a node (repeat; at least two independent nodes)")
    ap.add_argument("--depth", type=int, default=DEFAULT_DEPTH,
                    help=f"selected-chain blocks below the tip (default {DEFAULT_DEPTH}, about a day)")
    ap.add_argument("--network", default="mainnet", choices=("mainnet", "testnet"))
    ap.add_argument("--api-key-env", default="GNB_RPC_API_KEY", metavar="NAME")
    ap.add_argument("--cafile", help="CA certificate (PEM) for https endpoints with a private CA")
    ap.add_argument("--allow-single-node", action="store_true",
                    help="accept one node (rehearsals only, never for a release)")
    args = ap.parse_args(argv)
    if args.depth < 1:
        ap.error("--depth must be at least 1")
    api_key = os.environ.get(args.api_key_env) or None
    try:
        calls = {u: make_caller(u, api_key, args.cafile) for u in args.rpc}
        readings = [read_node(u, calls[u], args.depth, args.network) for u in args.rpc]
        cand, value, warnings = choose(readings, calls, args.allow_single_node)
    except (ReadingError, OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(report(readings, cand, value, args.depth, warnings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
