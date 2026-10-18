#!/usr/bin/env python3
"""Tests of the ObenBlock launch kit (deploy/obenblock-launch).

Run: python3 deploy/obenblock-launch/test_launch_kit.py
Linux with bash, sha256sum, systemd-analyze and shellcheck runs everything;
elsewhere the tests that need a missing tool are skipped.
"""
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

KIT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(KIT))
sys.path.insert(0, os.path.join(KIT, "lib"))
sys.path.insert(0, os.path.join(REPO, "deploy"))
sys.path.insert(0, os.path.join(REPO, "reference"))

import apply_genesis  # noqa: E402
import first_blocks  # noqa: E402
import obb_address  # noqa: E402
import test_deploy_files  # noqa: E402  (REQUIRED, parse_unit, MAX_EXPOSURE)

# The documented rehearsal solution (docs/OBENBLOCK-GENESIS.md, "Example run").
REHEARSAL = {"timestamp": 1_792_281_600, "version": 0x20000000, "nonce": 1_492_736_395,
             "display": "00000000721a9cb402747bea3f34d0ecc7095952173a5606cd50711230c74d6d"}
UNITS = ["obenblock-node.service", "obenblock-explorer-api.service", "obenblock-stratum.service"]
SH_SCRIPTS = ["host/obenblock-launch", "host/obenblock-stratum-launch"]
BASH_SCRIPTS = ["obb-launch.sh", "lib/common.sh", "host/install.sh", "host/rollback.sh",
                "host/genesis-build.sh", "host/release-build.sh", "host/explorer-tls.sh", "rehearse-regtest.sh"]
OWNER = obb_address.key_string("obenblock", "mainnet", hashlib.sha3_256(b"kit test owner").digest()[:20])
REG_OWNER = obb_address.key_string("obenblock", "testnet", hashlib.sha3_256(b"kit test owner").digest()[:20])


def mine_log(c=REHEARSAL):
    raw = bytes.fromhex(c["display"])[::-1]
    arr = ", ".join("0x%02x" % b for b in raw)
    return ("ObenBlock mainnet genesis search (SHA-256d)\n\nFound in 9.8 s. Paste into ...:\n\n"
            f"pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = {c['timestamp']};\n"
            f"pub const OBB_MAINNET_GENESIS_VERSION: u32 = 0x{c['version']:08X};\n"
            f"pub const OBB_MAINNET_GENESIS_NONCE: u64 = {c['nonce']};\n"
            f"pub const OBB_MAINNET_GENESIS_HASH: [u8; 32] = [\n    {arr},\n];\n\n"
            f"genesis block id (raw digest): {raw.hex()}\n"
            f"genesis block id (Bitcoin display order): {c['display']}\n")


def rd(path):
    with open(path, errors="replace") as fh:
        return fh.read()


def wr(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def have(tool):
    return shutil.which(tool) is not None


def copy_genesis_files(dst):
    for rel in (apply_genesis.GENESIS_RS, apply_genesis.REFERENCE_PY, apply_genesis.DOC_MD):
        os.makedirs(os.path.join(dst, os.path.dirname(rel)), exist_ok=True)
        shutil.copy(os.path.join(REPO, rel), os.path.join(dst, rel))


class ApplyGenesis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        copy_genesis_files(self.tmp)
        with open(os.path.join(self.tmp, "mine.log"), "w") as fh:
            fh.write(mine_log())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_the_repository_is_still_the_placeholder(self):
        self.assertEqual(apply_genesis.status(apply_genesis.Path(REPO)), "placeholder",
                         "the mainnet genesis must only be written at launch")

    def test_apply_writes_every_constant_and_refuses_a_second_time(self):
        from pathlib import Path
        src = Path(self.tmp)
        c = apply_genesis.parse_log(mine_log())
        self.assertEqual(apply_genesis.apply(src, c), [])
        rs = (src / apply_genesis.GENESIS_RS).read_text()
        self.assertIn("pub const OBB_MAINNET_GENESIS_TIMESTAMP: u64 = 1792281600;", rs)
        self.assertIn("pub const OBB_MAINNET_GENESIS_VERSION: u32 = 0x20000000;", rs)
        self.assertIn("pub const OBB_MAINNET_GENESIS_NONCE: u64 = 1492736395;", rs)
        self.assertNotIn("LAUNCH PLACEHOLDER", rs)
        raw = bytes.fromhex(REHEARSAL["display"])[::-1].hex()
        self.assertEqual(apply_genesis.status(src), f"launched 1792281600 {REHEARSAL['display']} {raw}")
        py = (src / apply_genesis.REFERENCE_PY).read_text()
        self.assertIn('"timestamp": 1792281600, "version": 0x20000000, "nonce": 1492736395', py)
        doc = (src / apply_genesis.DOC_MD).read_text()
        self.assertIn(REHEARSAL["display"], doc)
        with self.assertRaises(apply_genesis.Refused):
            apply_genesis.apply(src, c)

    def test_bad_logs_are_refused(self):
        with self.assertRaises(apply_genesis.Refused):
            apply_genesis.parse_log("Found in 1 s\n")
        bad = dict(REHEARSAL, display="1" + REHEARSAL["display"][1:])
        with self.assertRaises(apply_genesis.Refused):
            apply_genesis.parse_log(mine_log(bad))  # not difficulty 1
        with self.assertRaises(apply_genesis.Refused):
            apply_genesis.parse_log(mine_log(dict(REHEARSAL, version=0x40000000)))
        text = mine_log().replace(REHEARSAL["display"], "00000000" + "ab" * 28)
        with self.assertRaises(apply_genesis.Refused):
            apply_genesis.parse_log(text)  # raw and display ids disagree


class Address(unittest.TestCase):
    def run_check(self, addr, net):
        return subprocess.run([sys.executable, "-I", os.path.join(KIT, "lib/check_address.py"),
                               os.path.join(REPO, "reference"), addr, net], capture_output=True, text=True).returncode

    def test_owner_address_check(self):
        self.assertEqual(self.run_check(OWNER, "mainnet"), 0)
        self.assertEqual(self.run_check(REG_OWNER, "regtest"), 0)
        self.assertNotEqual(self.run_check(REG_OWNER, "mainnet"), 0)
        self.assertNotEqual(self.run_check(OWNER, "regtest"), 0)
        self.assertNotEqual(self.run_check("gnb1q" + OWNER[5:], "mainnet"), 0, "GnB notation refused")
        self.assertNotEqual(self.run_check(OWNER[:-1] + ("0" if OWNER[-1] != "0" else "1"), "mainnet"), 0, "checksum")


class Launchers(unittest.TestCase):
    def launch(self, **env):
        base = {"PATH": os.environ["PATH"], "OBB_LAUNCH_PRINT": "1", "OBB_CARRYOVER": __file__}
        base.update(env)
        return subprocess.run(["sh", os.path.join(KIT, "host/obenblock-launch")], env=base, capture_output=True, text=True)

    def test_mainnet_arguments(self):
        p = self.launch(OBB_MINER_ADDRESS=OWNER, OBB_MINE_THREADS="auto",
                        OBB_PEERS="/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110",
                        OBB_RPC_KEY_FILE="/etc/obenblock/rpc.key")
        self.assertEqual(p.returncode, 0, p.stderr)
        args = p.stdout.split()
        self.assertEqual(args[0], "/opt/obenblock/current/obenblock")
        self.assertEqual(args[1:3], ["--chain", "obenblock"])
        self.assertNotIn("--regtest", args)
        joined = " ".join(args)
        self.assertIn("--listen /ip4/0.0.0.0/tcp/18110 --rpc-port 18210 --archive", joined)
        self.assertIn(f"--mine --miner-address {OWNER} --mine-threads {max(1, os.cpu_count() - 1)}", joined)
        self.assertIn("--peer /ip4/209.250.236.240/tcp/18110 --peer /ip4/152.236.5.112/tcp/18110", joined)
        self.assertIn("--no-default-dns-seed", args)
        self.assertNotIn("--rpc-public", args)

    def test_regtest_and_overrides(self):
        p = self.launch(OBB_NETWORK="regtest", OBB_MINER_ADDRESS=REG_OWNER, OBB_MINE_THREADS="2",
                        OBB_P2P_PORT="28111", OBB_RPC_PORT="28211", OBB_LISTEN_IP="127.0.0.1", OBB_DNS_SEED="default")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("--chain obenblock --regtest", p.stdout)
        self.assertIn("--listen /ip4/127.0.0.1/tcp/28111 --rpc-port 28211", p.stdout)
        self.assertNotIn("--no-default-dns-seed", p.stdout)

    def test_injection_is_refused(self):
        for env in ({"OBB_PEERS": "/ip4/1.2.3.4/tcp/1;rm"}, {"OBB_PEERS": "--rpc-public"},
                    {"OBB_MINER_ADDRESS": "obb1q --rpc-public"}, {"OBB_MINER_ADDRESS": OWNER, "OBB_MINE_THREADS": "4 --rpc-public"}, {"OBB_MINE_THREADS": "x"},
                    {"OBB_NETWORK": "testnet"}, {"OBB_DNS_SEED": "evil.example"}):
            with self.subTest(env=env):
                p = self.launch(**env)
                self.assertEqual(p.returncode, 64, p.stdout + p.stderr)

    def test_stratum_launcher_refuses_until_configured(self):
        tmp = tempfile.mkdtemp()
        try:
            exe = os.path.join(tmp, "obenblock-stratum")
            with open(exe, "w") as fh:
                fh.write("#!/bin/sh\necho stratum \"$@\" \"$OBB_STRATUM_LISTEN\"\n")
            os.chmod(exe, 0o755)
            run = lambda **e: subprocess.run(["sh", os.path.join(KIT, "host/obenblock-stratum-launch")],
                                             env={"PATH": os.environ["PATH"], "OBB_RELEASE_DIR": tmp, **e},
                                             capture_output=True, text=True)
            p = run(OBB_STRATUM_EXEC="obenblock-stratum", OBB_STRATUM_ARGS="LAUNCH-PLACEHOLDER fill")
            self.assertEqual(p.returncode, 64)
            self.assertEqual(run(OBB_STRATUM_EXEC="../bin/sh", OBB_STRATUM_ARGS="").returncode, 64)
            self.assertEqual(run(OBB_STRATUM_EXEC="missing", OBB_STRATUM_ARGS="").returncode, 64)
            self.assertEqual(run(OBB_STRATUM_EXEC="obenblock-stratum", OBB_STRATUM_ARGS="--x $(id)").returncode, 64)
            p = run(OBB_STRATUM_EXEC="obenblock-stratum", OBB_STRATUM_ARGS="--listen 0.0.0.0:3333",
                    OBB_STRATUM_LISTEN="0.0.0.0:3333")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), "stratum --listen 0.0.0.0:3333 0.0.0.0:3333")
        finally:
            shutil.rmtree(tmp)


@unittest.skipUnless(have("bash") and have("sha256sum"), "needs bash and sha256sum (Linux)")
class InstallStaged(unittest.TestCase):
    def make_release(self, root, rid, genesis="ab" * 32):
        rel = os.path.join(root, "obenblock-release-" + rid)
        os.makedirs(os.path.join(rel, "units"))
        os.makedirs(os.path.join(rel, "share"))
        for u in UNITS:
            shutil.copy(os.path.join(KIT, "host", u), os.path.join(rel, "units", u))
        with gzip.open(os.path.join(rel, "share", "bloch-g3-carryover.tsv.gz"), "wb") as fh:
            fh.write(b"snapshot\n")
        shutil.copy(os.path.join(REPO, "deploy/explorer-api/cloudflare-ips-v4.txt"), os.path.join(rel, "share"))
        for name in ("obenblock", "obenblock-launch"):
            with open(os.path.join(rel, name), "w") as fh:
                fh.write("#!/bin/sh\n")
        with open(os.path.join(rel, "RELEASE"), "w") as fh:
            fh.write(f"id={rid}\ngenesis={genesis}\nstratum=obenblock-stratum\n")
        subprocess.run("find . -type f ! -name SHA256SUMS | sed 's|^./||' | sort | xargs sha256sum > SHA256SUMS",
                       shell=True, cwd=rel, check=True)
        return rel

    def install(self, rel, stage, *extra, owner=OWNER):
        return subprocess.run(["bash", os.path.join(KIT, "host/install.sh"), "--release", rel, "--owner", owner,
                               "--peers", "/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110",
                               "--root", stage, *extra], capture_output=True, text=True)

    def test_staged_install_and_upgrade(self):
        tmp = tempfile.mkdtemp()
        try:
            stage = os.path.join(tmp, "stage")
            r1 = self.make_release(tmp, "aaa-g1")
            p = self.install(r1, stage, "--stratum", "--explorer", "letsencrypt")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            etc = os.path.join(stage, "etc/obenblock")
            env = rd(os.path.join(etc, "obenblock.env"))
            self.assertIn(f"OBB_MINER_ADDRESS={OWNER}\n", env)
            self.assertIn('OBB_PEERS="/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110"\n', env)
            self.assertIn("OBB_NETWORK=mainnet\n", env)
            self.assertEqual(os.stat(os.path.join(etc, "obenblock.env")).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.join(etc, "rpc.key")).st_mode & 0o777, 0o640)
            self.assertRegex(rd(os.path.join(etc, "rpc.key")), r"^[0-9a-f]{64}$")
            self.assertIn("GNB_API_PORT=2087", rd(os.path.join(etc, "explorer-api.env")))
            stratum = rd(os.path.join(etc, "stratum.env"))
            self.assertIn(f"OBB_STRATUM_PAYOUT_ADDRESS={OWNER}\n", stratum)
            self.assertIn("OBB_STRATUM_RPC=127.0.0.1:18210\n", stratum)
            self.assertIn("OBB_STRATUM_EXEC=obenblock-stratum\n", stratum)
            self.assertEqual(os.readlink(os.path.join(stage, "opt/obenblock/current")), "releases/aaa-g1")
            self.assertEqual(rd(os.path.join(stage, "opt/obenblock/share/bloch-g3-carryover.tsv")), "snapshot\n")
            for u in UNITS:
                self.assertTrue(os.path.exists(os.path.join(stage, "etc/systemd/system", u)), u)
            key1 = rd(os.path.join(etc, "rpc.key"))
            # Upgrade: the previous release is recorded, keys and stratum.env stay.
            r2 = self.make_release(tmp, "bbb-g1")
            p = self.install(r2, stage, "--explorer", "none")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(os.readlink(os.path.join(stage, "opt/obenblock/current")), "releases/bbb-g1")
            self.assertEqual(os.readlink(os.path.join(stage, "opt/obenblock/previous")), "releases/aaa-g1")
            self.assertEqual(rd(os.path.join(etc, "rpc.key")), key1)
            self.assertIn("GNB_API_BIND=127.0.0.1", rd(os.path.join(etc, "explorer-api.env")))
            self.assertTrue(os.path.exists(os.path.join(stage, "etc/systemd/system/obenblock-explorer-api.service.d/loopback.conf")))
        finally:
            shutil.rmtree(tmp)

    def test_refusals(self):
        tmp = tempfile.mkdtemp()
        try:
            stage = os.path.join(tmp, "stage")
            rel = self.make_release(tmp, "ccc-g1")
            self.assertNotEqual(self.install(rel, stage, owner=REG_OWNER).returncode, 0, "regtest owner on mainnet")
            self.assertNotEqual(self.install(rel, stage, owner="gnb1q" + OWNER[5:]).returncode, 0)
            self.assertNotEqual(self.install(rel, stage, "--threads", "4;id").returncode, 0)
            nog = self.make_release(tmp, "ddd-nogenesis", genesis="none")
            p = self.install(nog, stage)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("no mainnet genesis", p.stderr)
            with open(os.path.join(rel, "obenblock"), "a") as fh:
                fh.write("tampered\n")
            p = self.install(rel, stage)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("checksums", p.stderr)
        finally:
            shutil.rmtree(tmp)


class Units(unittest.TestCase):
    def service(self, name):
        return test_deploy_files.parse_unit(os.path.join(KIT, "host", name))["Service"]

    def test_sandbox_directives(self):
        for name in UNITS:
            svc = self.service(name)
            for key, want in test_deploy_files.REQUIRED.items():
                with self.subTest(unit=name, directive=key):
                    self.assertEqual(svc.get(key, [None])[-1], want)
            self.assertIn("@system-service", svc.get("SystemCallFilter", []))
            families = set(" ".join(svc.get("RestrictAddressFamilies", [])).split())
            self.assertLessEqual(families, test_deploy_files.ALLOWED_FAMILIES)

    def test_separate_unprivileged_users(self):
        users = {n: self.service(n)["User"][-1] for n in UNITS}
        self.assertEqual(users["obenblock-node.service"], "obenblock")
        self.assertEqual(len(set(users.values())), 3, users)
        for n in UNITS:
            self.assertEqual(self.service(n)["Group"][-1], users[n])
        self.assertNotIn("gnb", users.values())

    def test_no_foreign_unit_is_named(self):
        for path in BASH_SCRIPTS + SH_SCRIPTS:
            text = rd(os.path.join(KIT, path))
            for line in text.splitlines():
                if re.search(r"systemctl\s+(stop|disable|restart|start|mask|kill)\b", line):
                    self.assertNotRegex(line, r"gnb-node|bloch", f"{path}: {line}")

    @unittest.skipUnless(have("systemd-analyze"), "systemd-analyze not installed")
    def test_systemd_analyze(self):
        paths = [os.path.join(KIT, "host", u) for u in UNITS]
        p = subprocess.run(["systemd-analyze", "verify", "--man=no", *paths], capture_output=True, text=True, timeout=60)
        problems = [l for l in (p.stdout + p.stderr).splitlines()
                    if l.strip() and "is not executable: No such file or directory" not in l
                    and "Failed to resolve" not in l and "No such file or directory" not in l]
        self.assertEqual(problems, [], "\n".join(problems))
        for path in paths:
            p = subprocess.run(["systemd-analyze", "security", "--offline=true", "--no-pager", path],
                               capture_output=True, text=True, timeout=60)
            m = re.search(r"Overall exposure level for \S+: (\d+\.\d+)", p.stdout + p.stderr)
            if m is None:
                self.skipTest("systemd-analyze security --offline unsupported")
            self.assertLessEqual(float(m.group(1)), test_deploy_files.MAX_EXPOSURE, f"{path}: {m.group(1)}")


class Scripts(unittest.TestCase):
    def test_posix_launchers_parse(self):
        for s in SH_SCRIPTS:
            path = os.path.join(KIT, s)
            self.assertEqual(rd(path).splitlines()[0], "#!/bin/sh")
            p = subprocess.run(["sh", "-n", path], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)

    @unittest.skipUnless(have("bash"), "bash not installed")
    def test_bash_scripts_parse(self):
        for s in BASH_SCRIPTS:
            p = subprocess.run(["bash", "-n", os.path.join(KIT, s)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, f"{s}: {p.stderr}")

    @unittest.skipUnless(have("shellcheck"), "shellcheck not installed")
    def test_shellcheck(self):
        p = subprocess.run(["shellcheck", "-S", "warning", *[os.path.join(KIT, s) for s in BASH_SCRIPTS + SH_SCRIPTS]],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_english_only(self):
        pt = re.compile(r"\b(senha|não|servidor|usuário|chave|aguarde|erro)\b", re.I)
        for root, _, files in os.walk(KIT):
            for f in files:
                if f == "test_launch_kit.py" or "/state" in root:
                    continue
                if f.endswith((".sh", ".py", ".md", ".service", ".exp", ".example")) or f in ("obenblock-launch", "obenblock-stratum-launch"):
                    path = os.path.join(root, f)
                    for i, line in enumerate(rd(path).splitlines(), 1):
                        if "senha:" in line or "gnb-servidor-teste-152.txt" in line:
                            continue  # the password file's own name and field
                        self.assertIsNone(pt.search(line), f"{path}:{i}: {line.strip()}")


class Verify(unittest.TestCase):
    def status(self, **over):
        st = {"nproc": 32, "units": {"obenblock-node": {"active": "active", "enabled": "enabled"},
                                     "obenblock-explorer-api": {"active": "active", "enabled": "enabled"},
                                     "obenblock-stratum": {"active": "inactive", "enabled": "disabled"}},
              "gnb_node": {"active": "inactive"}, "gnb_processes": 0,
              "node_processes": [{"pid": 1, "threads": 60, "mine": True, "mine_threads": "31"}],
              "rpc_ok": True, "network": {"chain_id": "0x4f420001", "peers": 2},
              "genesis": "aa" * 32, "tip": {"tip_height": 10}, "listening": [], "hashrate": "1 GH/s"}
        st.update(over)
        return "some line\nOBB-STATUS " + json.dumps(st) + "\n"

    def run_verify(self, statuses, *extra):
        tmp = tempfile.mkdtemp()
        try:
            args = []
            for i, s in enumerate(statuses):
                path = os.path.join(tmp, f"h{i}")
                wr(path, s)
                args.append(f"h{i}={path}")
            return subprocess.run([sys.executable, os.path.join(KIT, "lib/verify_summary.py"), *extra, *args],
                                  capture_output=True, text=True)
        finally:
            shutil.rmtree(tmp)

    def test_ok_and_failures(self):
        ok = [self.status(), self.status(), self.status()]
        p = self.run_verify(ok, "--genesis", "aa" * 32)
        self.assertEqual(p.returncode, 0, p.stdout)
        two = self.status(node_processes=[{"pid": 1, "mine": True, "mine_threads": "31", "threads": 1}] * 2)
        p = self.run_verify([two, self.status(), self.status()])
        self.assertEqual(p.returncode, 1)
        self.assertIn("2 node processes", p.stdout)
        p = self.run_verify([self.status(genesis="bb" * 32), self.status(), self.status()])
        self.assertIn("disagree on the genesis", p.stdout)
        p = self.run_verify([self.status(network={"chain_id": "0x4f420001", "peers": 1})] * 3)
        self.assertIn("1 peers", p.stdout)
        p = self.run_verify([self.status(node_processes=[{"pid": 1, "mine": True, "mine_threads": "8", "threads": 1}])])
        self.assertIn("mine threads 8, expected 31", p.stdout)
        p = self.run_verify([self.status(stratum_metrics={"obb_stratum_shares_bitcoin_root_total": 12.0})])
        self.assertIn("Bitcoin's Merkle root", p.stdout)
        p = self.run_verify([self.status(gnb_node={"active": "active"})])
        self.assertIn("GnB gnb-node is active", p.stdout)
        self.assertEqual(p.returncode, 0, "a running GnB node is a warning, not a failure")
        p = self.run_verify(["nothing\n"])
        self.assertIn("no status", p.stdout)


class TimingModel(unittest.TestCase):
    def test_on_schedule_at_the_launch_hashrate_and_slower_below(self):
        first_blocks.random.seed(7)
        at_target = first_blocks.simulate(1e18, 0, 60, (1, 100))
        self.assertLess(at_target[1], 120)
        self.assertTrue(40 * 60 < at_target[100] < 65 * 60, at_target)
        low = first_blocks.simulate(1e15, 0, 60, (1,))
        self.assertTrue(30 * 60 < low[1] < 4 * 3600, low)  # stall relief: hours, not 11 days
        self.assertGreater(first_blocks.simulate(1e14, 0, 60, (1,))[1], low[1])


if __name__ == "__main__":
    unittest.main()
