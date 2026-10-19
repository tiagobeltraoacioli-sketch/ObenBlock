#!/usr/bin/env python3
"""Build launch.json for scripts/site-launch-fill.mjs (the obenblock.xyz
launch placeholders) from the launch facts, and check it against the pages.

    site_launch.py --site <site dir> --genesis-hash <display hex>
                   --launch-ts <unix> --seeds "<ip> ..." [--p2p-port 18110]
                   --stratum "<ip>=<v2 authority key b58> ..."
                   [--v1-port 3333] [--v2-port 3334]
                   --release <id> --release-sha256 <hex> [--release-url URL]
                   [--dns-seed none|default] [--network mainnet|regtest]
                   [--out launch.json]

    site_launch.py --wrangler <wrangler.toml> --origins <https://...,...>
                   --fallback-origins <...> --chain-id 0x4f420001
                   --genesis-raw <getblockhash 0> [--zone obenblock.xyz]
        Set the Worker's [vars] (OBB_ORIGIN_ZONE, OBB_ORIGINS,
        OBB_FALLBACK_ORIGINS, OBB_CHAIN_ID, OBB_GENESIS_HASH) in a copy of
        wrangler.toml; each line must exist exactly once.

Every key that a page carries (data-launch="KEY" in index.html,
downloads.html, brand.html) gets a value, and no other key is written, so
`site-launch-fill.mjs launch.json <site> --strict` leaves nothing open.
Values are plain text (the fill script escapes them). Standard library only.
"""
import argparse
import json
import os
import re
import sys
import time

PAGES = ("index.html", "downloads.html", "brand.html")
KEY_RE = re.compile(r'<(?:span|p|code|td)\b[^>]*?\sdata-launch="([A-Z0-9_]+)"')
LAUNCH_BITS = "0x19009d69"


def page_keys(site):
    keys = set()
    for page in PAGES:
        path = os.path.join(site, page)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                keys.update(KEY_RE.findall(fh.read()))
    return keys


def utc(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def build(a):
    if not re.fullmatch(r"[0-9a-f]{64}", a.genesis_hash):
        raise SystemExit(f"--genesis-hash must be 64 lowercase hex digits, got {a.genesis_hash!r}")
    if a.network == "mainnet" and not a.genesis_hash.startswith("00000000"):
        raise SystemExit("--genesis-hash: a mainnet genesis id starts with 00000000 (display order)")
    seeds = a.seeds.split()
    if not seeds or any(not re.fullmatch(r"[0-9.]+", s) for s in seeds):
        raise SystemExit("--seeds must be IPv4 addresses")
    v2 = {}
    for item in a.stratum.split():
        ip, _, key = item.partition("=")
        if ip not in seeds:
            raise SystemExit(f"--stratum: {ip} is not one of the seeds")
        if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{40,60}", key):
            raise SystemExit(f"--stratum: {ip}: {key!r} is not a Base58 authority key (the node writes it on first start)")
        v2[ip] = key
    missing = [s for s in seeds if s not in v2]
    if missing:
        raise SystemExit("--stratum: no V2 authority key for " + ", ".join(missing))
    if not re.fullmatch(r"[0-9a-f]{64}", a.release_sha256):
        raise SystemExit("--release-sha256 must be 64 hex digits")
    when = utc(a.launch_ts)
    short = f"{a.genesis_hash[:8]}…{a.genesis_hash[-8:]}"
    v1_list = ", ".join(f"stratum+tcp://{ip}:{a.v1_port}" for ip in seeds)
    v2_list = ", ".join(f"stratum2+tcp://{ip}:{a.v2_port}/{v2[ip]}" for ip in seeds)
    release = f"{a.release} · tarball SHA-256 {a.release_sha256}" + (f" · {a.release_url}" if a.release_url else "")
    values = {
        "BANNER": f"OBENBLOCK · MAINNET LIVE SINCE {time.strftime('%d %b %Y', time.gmtime(a.launch_ts)).upper()} · GENESIS {short}",
        "STATUS": "Live",
        "LAUNCH_TIME": f"{when} (Unix {a.launch_ts})",
        "GENESIS_HASH": a.genesis_hash,
        "SEED_NODES": " · ".join(f"{ip}:{a.p2p_port}" for ip in seeds),
        "DNS_SEED": "Live" if a.dns_seed == "default" else "Not live yet: use the seed nodes",
        "STRATUM_ENDPOINT": (f"Stratum V1: {v1_list} · Stratum V2 (pin the key): {v2_list} · "
                             f"worker = your obb1 address (optionally .rig name), password x, solo: "
                             f"each block pays the worker's address"),
        "RELEASE": release,
        "GENESIS_TARGET": f"bits {LAUNCH_BITS} (sized for 1 EH/s of SHA-256d at 30 s blocks)",
        "FAQ_LIVE": (f"Yes. ObenBlock mainnet launched at {when}. The genesis block is {a.genesis_hash}. "
                     f"Seed nodes, the stratum endpoints and the release are listed under Mainnet launch. "
                     f"PoCI finality starts at block 3,600."),
        "FOOTER_STATUS": f"MAINNET LIVE SINCE {when.upper()} · GENESIS {short}",
    }
    return values


def set_wrangler_vars(path, values):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for name, value in values.items():
        if not re.fullmatch(r"[A-Za-z0-9:/.,_-]*", value):
            raise SystemExit(f"{name}: value {value!r} has characters outside a URL list or hex")
        pat = re.compile(rf'^{name} = ".*"$', re.M)
        if len(pat.findall(text)) != 1:
            raise SystemExit(f"{path}: the line {name} = \"...\" is not there exactly once (worker/README.md changed?)")
        text = pat.sub(f'{name} = "{value}"', text)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"set {', '.join(values)} in {path}", file=sys.stderr)


def wrangler_main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--wrangler", required=True)
    ap.add_argument("--origins", required=True)
    ap.add_argument("--fallback-origins", default="")
    ap.add_argument("--chain-id", required=True)
    ap.add_argument("--genesis-raw", required=True)
    ap.add_argument("--zone", default="obenblock.xyz")
    a = ap.parse_args(argv[1:])
    if not re.fullmatch(r"0x[0-9a-f]{8}", a.chain_id):
        raise SystemExit("--chain-id must be 0x + 8 hex digits")
    if not re.fullmatch(r"[0-9a-f]{64}", a.genesis_raw):
        raise SystemExit("--genesis-raw must be the 64-hex getblockhash 0")
    for o in [x for x in a.origins.split(",") if x]:
        host = re.fullmatch(r"https://([a-z0-9.-]+):\d+", o)
        if not host or not (host.group(1) == a.zone or host.group(1).endswith("." + a.zone)):
            raise SystemExit(f"--origins: {o!r} is not https://<name in {a.zone}>:<port> (the Worker ignores it)")
    set_wrangler_vars(a.wrangler, {"OBB_ORIGIN_ZONE": a.zone, "OBB_ORIGINS": a.origins,
                                   "OBB_FALLBACK_ORIGINS": a.fallback_origins, "OBB_CHAIN_ID": a.chain_id,
                                   "OBB_GENESIS_HASH": a.genesis_raw})
    return 0


def main(argv):
    if "--wrangler" in argv:
        return wrangler_main(argv)
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True)
    ap.add_argument("--genesis-hash", required=True)
    ap.add_argument("--launch-ts", type=int, required=True)
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--p2p-port", type=int, default=18110)
    ap.add_argument("--stratum", required=True)
    ap.add_argument("--v1-port", type=int, default=3333)
    ap.add_argument("--v2-port", type=int, default=3334)
    ap.add_argument("--release", required=True)
    ap.add_argument("--release-sha256", required=True)
    ap.add_argument("--release-url", default="")
    ap.add_argument("--dns-seed", default="none", choices=("none", "default"))
    ap.add_argument("--network", default="mainnet", choices=("mainnet", "regtest"))
    ap.add_argument("--out", default="-")
    a = ap.parse_args(argv[1:])
    values = build(a)
    keys = page_keys(a.site)
    if not keys:
        raise SystemExit(f"{a.site}: no launch placeholders found (not the obenblock.xyz site, or already filled)")
    extra, open_keys = sorted(set(values) - keys), sorted(keys - set(values))
    if open_keys:
        raise SystemExit("the pages carry keys this tool does not fill: " + ", ".join(open_keys))
    for k in extra:
        del values[k]
    text = json.dumps(values, indent=2, ensure_ascii=False) + "\n"
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {a.out}: {len(values)} keys ({', '.join(sorted(values))})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
