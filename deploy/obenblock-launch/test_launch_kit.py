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
import site_launch  # noqa: E402,F401
import first_blocks  # noqa: E402
import obb_address  # noqa: E402
import test_deploy_files  # noqa: E402  (REQUIRED, parse_unit, MAX_EXPOSURE)

# The documented rehearsal solution (reference/obb_genesis_vectors.json
# mainnet.rehearsal: Bitcoin's header Merkle root and the body commitment).
REHEARSAL = {"timestamp": 1_792_281_600, "version": 0x20000000, "nonce": 3_461_588_150,
             "display": "00000000f9db8f81e92e293fae6032d359f731c1c7afebcaca1b75f47bfc32bc"}
UNITS = ["obenblock-node.service", "obenblock-cpu-miner.service", "obenblock-explorer-api.service",
         "obenblock-stratum.service"]
FIREWALL_UNITS = ["obenblock-explorer-firewall.service", "obenblock-explorer-firewall-reapply.service",
                  "obenblock-explorer-firewall-reapply.timer"]
SH_SCRIPTS = ["host/obenblock-launch", "host/obenblock-miner-launch", "host/obenblock-stratum-launch"]
# The owner's GnB miner key and its ObenBlock form (kit.conf.example).
OWNER_GNB = "gnb1q52273b58c1032291d562f582c413bbf05efabcdd0df82055"
OWNER_OBB = "obb1q52273b58c1032291d562f582c413bbf05efabcdd0df82055"
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
        self.assertIn("pub const OBB_MAINNET_GENESIS_NONCE: u64 = 3461588150;", rs)
        self.assertNotIn("LAUNCH PLACEHOLDER", rs)
        raw = bytes.fromhex(REHEARSAL["display"])[::-1].hex()
        self.assertEqual(apply_genesis.status(src), f"launched 1792281600 {REHEARSAL['display']} {raw}")
        py = (src / apply_genesis.REFERENCE_PY).read_text()
        self.assertIn('"timestamp": 1792281600, "version": 0x20000000, "nonce": 3461588150', py)
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

    def test_owner_is_the_gnb_miner_key_in_obb_form(self):
        self.assertEqual(obb_address.normalize(OWNER_GNB, "obenblock"), OWNER_OBB)
        self.assertEqual(obb_address.decode(OWNER_GNB, "obenblock")[:3], obb_address.decode(OWNER_OBB, "obenblock")[:3])
        self.assertEqual(self.run_check(OWNER_OBB, "mainnet"), 0)
        conf = rd(os.path.join(KIT, "kit.conf.example"))
        self.assertIn(f'OWNER_ADDRESS="{OWNER_OBB}"', conf)
        self.assertIn(f'OWNER_ADDRESS_GNB="{OWNER_GNB}"', conf)


class Launchers(unittest.TestCase):
    def launch(self, script="host/obenblock-launch", **env):
        base = {"PATH": os.environ["PATH"], "OBB_LAUNCH_PRINT": "1", "OBB_CARRYOVER": __file__}
        base.update(env)
        return subprocess.run(["sh", os.path.join(KIT, script)], env=base, capture_output=True, text=True)

    def mainnet_env(self, **over):
        env = {"OBB_PAYOUT_ADDRESS": OWNER, "OBB_PEERS": "/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110",
               "OBB_RPC_KEY_FILE": "/etc/obenblock/rpc.key", "OBB_STRATUM": "on", "OBB_STRATUM_V1_PORT": "3333",
               "OBB_STRATUM_V2": "on", "OBB_STRATUM_V2_PORT": "3334",
               "OBB_STRATUM_V2_KEY": "/var/lib/obenblock/stratum-v2-authority.json", "OBB_NODE_MINE": "off",
               "OBB_WITNESS": "on", "OBB_WITNESS_KEY": __file__, "OBB_WITNESS_PASSWORD_FILE": "/etc/obenblock/witness.pw",
               "OBB_WITNESS_PAYOUT": OWNER, "OBB_SHARE_THREADS": "1", "OBB_METRICS": "on"}
        env.update(over)
        return env

    def test_mainnet_arguments(self):
        p = self.launch(**self.mainnet_env())
        self.assertEqual(p.returncode, 0, p.stderr)
        args = p.stdout.split()
        self.assertEqual(args[0], "/opt/obenblock/current/obenblock")
        self.assertEqual(args[1:3], ["--chain", "obenblock"])
        self.assertNotIn("--regtest", args)
        joined = " ".join(args)
        self.assertIn("--listen /ip4/0.0.0.0/tcp/18110 --rpc-port 18210 --archive", joined)
        self.assertIn("--rpc-api-key-file /etc/obenblock/rpc.key", joined)
        self.assertIn("--stratum --stratum-addr 0.0.0.0:3333 --stratum-max-sessions 1024 --stratum-max-sessions-per-ip 256", joined)
        self.assertIn("--stratum-v2 --stratum-v2-addr 0.0.0.0:3334 --stratum-v2-key /var/lib/obenblock/stratum-v2-authority.json "
                      "--stratum-v2-max-sessions 1024 --stratum-v2-max-sessions-per-ip 64", joined)
        self.assertIn(f"--stratum-payout {OWNER} --miner-address {OWNER}", joined)
        self.assertIn(f"--witness-key {__file__} --witness-password-file /etc/obenblock/witness.pw --witness-payout {OWNER} --share-threads 1", joined)
        self.assertIn("--metrics --metrics-addr 127.0.0.1 --metrics-port 18310", joined)
        self.assertNotIn("--mine", args, "the CPU miner unit mines, not the node")
        self.assertIn("--peer /ip4/209.250.236.240/tcp/18110 --peer /ip4/152.236.5.112/tcp/18110", joined)
        self.assertIn("--no-default-dns-seed", args)
        self.assertNotIn("--rpc-public", args)

    def test_node_mine_when_asked(self):
        p = self.launch(**self.mainnet_env(OBB_NODE_MINE="on", OBB_MINE_THREADS="auto"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"--mine --mine-threads {max(1, os.cpu_count() - 1)}", p.stdout)

    def test_regtest_and_overrides(self):
        p = self.launch(OBB_NETWORK="regtest", OBB_PAYOUT_ADDRESS=REG_OWNER, OBB_STRATUM="on", OBB_STRATUM_V1_PORT="28331",
                        OBB_STRATUM_IP="127.0.0.1", OBB_P2P_PORT="28111", OBB_RPC_PORT="28211",
                        OBB_LISTEN_IP="127.0.0.1", OBB_DNS_SEED="default")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("--chain obenblock --regtest", p.stdout)
        self.assertIn("--listen /ip4/127.0.0.1/tcp/28111 --rpc-port 28211", p.stdout)
        self.assertIn("--stratum --stratum-addr 127.0.0.1:28331", p.stdout)
        self.assertNotIn("--stratum-v2", p.stdout)
        self.assertNotIn("--no-default-dns-seed", p.stdout)

    def test_injection_is_refused(self):
        for env in ({"OBB_PEERS": "/ip4/1.2.3.4/tcp/1;rm"}, {"OBB_PEERS": "--rpc-public"},
                    {"OBB_PAYOUT_ADDRESS": "obb1q --rpc-public"}, {"OBB_NODE_MINE": "on", "OBB_MINE_THREADS": "4 --rpc-public"},
                    {"OBB_NODE_MINE": "maybe"}, {"OBB_STRATUM": "on", "OBB_STRATUM_V1_PORT": "3333 --rpc-public"},
                    {"OBB_STRATUM_V2": "on", "OBB_STRATUM_V2_KEY": "relative.json"},
                    {"OBB_STRATUM_V2": "on", "OBB_STRATUM_V2_KEY": "/x/$(id).json"},
                    {"OBB_STRATUM": "on", "OBB_PAYOUT_ADDRESS": ""}, {"OBB_STRATUM_IP": "0.0.0.0 --rpc-public"}, {"OBB_STRATUM": "on", "OBB_STRATUM_MAX_PER_IP": "9 --rpc-public"},
                    {"OBB_WITNESS": "on"}, {"OBB_WITNESS": "on", "OBB_WITNESS_KEY": "/nonexistent/k.json",
                                            "OBB_WITNESS_PASSWORD_FILE": "/etc/pw"},
                    {"OBB_NETWORK": "testnet"}, {"OBB_DNS_SEED": "evil.example"}):
            with self.subTest(env=env):
                base = {"OBB_PAYOUT_ADDRESS": OWNER}
                base.update(env)
                p = self.launch(**base)
                self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn("/opt/obenblock/current/obenblock ", p.stdout)

    def miner(self, **env):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        exe = os.path.join(tmp, "obenblock-cpu-miner")
        wr(exe, "#!/bin/sh\n")
        os.chmod(exe, 0o755)
        return self.launch("host/obenblock-miner-launch", OBB_RELEASE_DIR=tmp, **env)

    def test_miner_launcher(self):
        p = self.miner(OBB_MINER_URL="stratum+tcp://127.0.0.1:3333", OBB_MINER_USER=f"{OWNER}.cpu-136-244-93-186",
                       OBB_MINER_THREADS="auto")
        self.assertEqual(p.returncode, 0, p.stderr)
        t = max(1, os.cpu_count() - 2)
        self.assertTrue(p.stdout.endswith(f"-o stratum+tcp://127.0.0.1:3333 -u {OWNER}.cpu-136-244-93-186 -p d={t * 0.03:.4f} "
                                          f"-t {t}\n"), p.stdout)
        p = self.miner(OBB_MINER_USER=f"{OWNER}.x", OBB_MINER_THREADS="3", OBB_MINER_KERNEL="avx512", OBB_MINER_START_DIFF="2.5")
        self.assertIn("-p d=2.5 -t 3 --kernel avx512", p.stdout)
        for env in ({"OBB_MINER_USER": ""}, {"OBB_MINER_USER": "rig1"}, {"OBB_MINER_USER": f"{OWNER} -t 99"},
                    {"OBB_MINER_USER": OWNER, "OBB_MINER_URL": "stratum+tcp://203.0.113.9:3333"},
                    {"OBB_MINER_USER": OWNER, "OBB_MINER_THREADS": "0"}, {"OBB_MINER_USER": OWNER, "OBB_MINER_THREADS": "2;id"},
                    {"OBB_MINER_USER": OWNER, "OBB_MINER_KERNEL": "fast"}, {"OBB_MINER_USER": OWNER, "OBB_MINER_START_DIFF": "1 -t 9"}):
            with self.subTest(env=env):
                self.assertEqual(self.miner(**env).returncode, 64)
        self.assertEqual(self.launch("host/obenblock-miner-launch", OBB_RELEASE_DIR="/nonexistent",
                                     OBB_MINER_USER=OWNER).returncode, 64)

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
            p = run(OBB_STRATUM_EXEC="obenblock-stratum", OBB_STRATUM_ARGS="--listen 0.0.0.0:3335",
                    OBB_STRATUM_LISTEN="0.0.0.0:3335")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), "stratum --listen 0.0.0.0:3335 0.0.0.0:3335")
        finally:
            shutil.rmtree(tmp)


@unittest.skipUnless(have("bash") and have("sha256sum"), "needs bash and sha256sum (Linux)")
class InstallStaged(unittest.TestCase):
    def make_release(self, root, rid, genesis="ab" * 32, extra=""):
        rel = os.path.join(root, "obenblock-release-" + rid)
        os.makedirs(os.path.join(rel, "units"))
        os.makedirs(os.path.join(rel, "share"))
        for u in UNITS:
            shutil.copy(os.path.join(KIT, "host", u), os.path.join(rel, "units", u))
        with gzip.open(os.path.join(rel, "share", "bloch-g3-carryover.tsv.gz"), "wb") as fh:
            fh.write(b"snapshot\n")
        shutil.copy(os.path.join(REPO, "deploy/explorer-api/cloudflare-ips-v4.txt"), os.path.join(rel, "share"))
        os.makedirs(os.path.join(rel, "host"))
        shutil.copy(os.path.join(REPO, "deploy/explorer-api/firewall-cloudflare.sh"), os.path.join(rel, "host"))
        for u in FIREWALL_UNITS:
            shutil.copy(os.path.join(REPO, "deploy/explorer-api", u), os.path.join(rel, "units", u))
        for name in ("obenblock", "obenblock-launch", "obenblock-cpu-miner", "obenblock-stratum", "obenblock-miner-launch"):
            wr(os.path.join(rel, name), "#!/bin/sh\n" + extra)
            os.chmod(os.path.join(rel, name), 0o755)
        # A fake witnesskeygen: writes its last argument, prints the id line.
        wr(os.path.join(rel, "obenblock-cli"), '#!/bin/sh\nfor a; do last=$a; done\n'
           '[ -n "$GNB_WALLET_PASSWORD" ] || exit 1\necho kes > "$last"\necho "Witness id:        00aa11bb"\n')
        os.chmod(os.path.join(rel, "obenblock-cli"), 0o755)
        with open(os.path.join(rel, "RELEASE"), "w") as fh:
            fh.write(f"id={rid}\ngenesis={genesis}\n")
        subprocess.run("find . -type f ! -name SHA256SUMS | sed 's|^./||' | sort | xargs sha256sum > SHA256SUMS",
                       shell=True, cwd=rel, check=True)
        return rel

    def install(self, rel, stage, *extra, owner=OWNER):
        return subprocess.run(["bash", os.path.join(KIT, "host/install.sh"), "--release", rel, "--owner", owner,
                               "--peers", "/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110",
                               "--miner-label", "cpu-136-244-93-186", "--root", stage, *extra],
                              capture_output=True, text=True)

    def test_staged_install_and_upgrade(self):
        tmp = tempfile.mkdtemp()
        try:
            stage = os.path.join(tmp, "stage")
            r1 = self.make_release(tmp, "aaa-g1-c1")
            p = self.install(r1, stage, "--explorer", "letsencrypt")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("witness id 00aa11bb", p.stdout)
            etc = os.path.join(stage, "etc/obenblock")
            env = rd(os.path.join(etc, "obenblock.env"))
            for line in (f"OBB_PAYOUT_ADDRESS={OWNER}", 'OBB_PEERS="/ip4/209.250.236.240/tcp/18110 /ip4/152.236.5.112/tcp/18110"',
                         "OBB_NETWORK=mainnet", "OBB_STRATUM=on", "OBB_STRATUM_V1_PORT=3333", "OBB_STRATUM_V2=on",
                         "OBB_STRATUM_V2_PORT=3334", "OBB_NODE_MINE=off", "OBB_WITNESS=on",
                         "OBB_WITNESS_KEY=/var/lib/obenblock/witness/witness-key.json",
                         "OBB_WITNESS_PASSWORD_FILE=credential:witness.pw", f"OBB_WITNESS_PAYOUT={OWNER}", "OBB_METRICS=on"):
                self.assertIn(line + "\n", env)
            self.assertEqual(os.stat(os.path.join(etc, "obenblock.env")).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(os.path.join(etc, "witness.pw")).st_mode & 0o777, 0o600)
            self.assertEqual(rd(os.path.join(stage, "var/lib/obenblock/witness/witness-key.json")), "kes\n")
            self.assertIn("LoadCredential=witness.pw:/etc/obenblock/witness.pw",
                          rd(os.path.join(stage, "etc/systemd/system/obenblock-node.service.d/witness.conf")))
            miner = rd(os.path.join(etc, "miner.env"))
            self.assertIn("OBB_MINER_URL=stratum+tcp://127.0.0.1:3333\n", miner)
            self.assertIn(f"OBB_MINER_USER={OWNER}.cpu-136-244-93-186\n", miner)
            self.assertIn("OBB_MINER_THREADS=auto\n", miner)
            self.assertEqual(os.stat(os.path.join(etc, "rpc.key")).st_mode & 0o777, 0o640)
            self.assertRegex(rd(os.path.join(etc, "rpc.key")), r"^[0-9a-f]{64}$")
            api_env = rd(os.path.join(etc, "explorer-api.env"))
            self.assertIn("OBB_API_PORT=2087", api_env)
            self.assertIn("OBB_API_AUTH=hmac+static\n", api_env)
            dropin = rd(os.path.join(stage, "etc/systemd/system/obenblock-explorer-api.service.d/firewall.conf"))
            self.assertIn("Requires=obenblock-explorer-firewall.service", dropin)
            self.assertIn("ExecStartPre=+/usr/sbin/nft list table inet gnb_explorer", dropin)
            for u in FIREWALL_UNITS:
                self.assertTrue(os.path.exists(os.path.join(stage, "etc/systemd/system", u)), u)
            self.assertTrue(os.path.exists(os.path.join(stage, "opt/obenblock/bin/firewall-cloudflare.sh")))
            self.assertFalse(os.path.exists(os.path.join(etc, "stratum.env")), "the external proxy is opt-in")
            self.assertEqual(os.readlink(os.path.join(stage, "opt/obenblock/current")), "releases/aaa-g1-c1")
            self.assertEqual(rd(os.path.join(stage, "opt/obenblock/share/bloch-g3-carryover.tsv")), "snapshot\n")
            for u in ("obenblock-node.service", "obenblock-cpu-miner.service", "obenblock-explorer-api.service"):
                self.assertTrue(os.path.exists(os.path.join(stage, "etc/systemd/system", u)), u)
            self.assertFalse(os.path.exists(os.path.join(stage, "etc/systemd/system/obenblock-stratum.service")))
            key1 = rd(os.path.join(etc, "rpc.key"))
            pw1 = rd(os.path.join(etc, "witness.pw"))
            # Upgrade: previous recorded, keys kept, the witness key not regenerated.
            r2 = self.make_release(tmp, "bbb-g1-c2")
            p = self.install(r2, stage, "--explorer", "none", "--stratum-proxy", "on")
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertEqual(os.readlink(os.path.join(stage, "opt/obenblock/current")), "releases/bbb-g1-c2")
            self.assertEqual(os.readlink(os.path.join(stage, "opt/obenblock/previous")), "releases/aaa-g1-c1")
            self.assertEqual(rd(os.path.join(etc, "rpc.key")), key1)
            self.assertEqual(rd(os.path.join(etc, "witness.pw")), pw1)
            self.assertIn("OBB_API_BIND=127.0.0.1", rd(os.path.join(etc, "explorer-api.env")))
            self.assertIn("OBB_STRATUM_LISTEN=0.0.0.0:3335\n", rd(os.path.join(etc, "stratum.env")))
            self.assertTrue(os.path.exists(os.path.join(stage, "etc/systemd/system/obenblock-explorer-api.service.d/loopback.conf")))
            self.assertFalse(os.path.exists(os.path.join(stage, "etc/systemd/system/obenblock-explorer-api.service.d/firewall.conf")))
            # Same id, other contents: refused, never silently kept.
            r3 = self.make_release(os.path.join(tmp, "again"), "bbb-g1-c2", extra="# rebuilt\n")
            p = self.install(r3, stage)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("already installed with other contents", p.stderr)
            # Witness off removes the credential drop-in.
            p = self.install(r2, stage, "--witness", "off")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("OBB_WITNESS=off\n", rd(os.path.join(etc, "obenblock.env")))
            self.assertFalse(os.path.exists(os.path.join(stage, "etc/systemd/system/obenblock-node.service.d/witness.conf")))
        finally:
            shutil.rmtree(tmp)

    def test_refusals(self):
        tmp = tempfile.mkdtemp()
        try:
            stage = os.path.join(tmp, "stage")
            rel = self.make_release(tmp, "ccc-g1")
            self.assertNotEqual(self.install(rel, stage, owner=REG_OWNER).returncode, 0, "regtest owner on mainnet")
            self.assertNotEqual(self.install(rel, stage, owner="gnb1q" + OWNER[5:]).returncode, 0)
            for bad in (("--miner-threads", "4;id"), ("--miner-label", "a b"), ("--miner-label", "x" * 25),
                        ("--stratum-v2-port", "3333"), ("--witness", "maybe"), ("--share-threads", "1x"),
                        ("--stratum-proxy", "on", "--stratum-proxy-port", "3334")):
                with self.subTest(bad=bad):
                    self.assertNotEqual(self.install(rel, stage, *bad).returncode, 0)
            nog = self.make_release(tmp, "ddd-nogenesis", genesis="none")
            p = self.install(nog, stage)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("no mainnet genesis", p.stderr)
            nominer = self.make_release(tmp, "fff-g1")
            os.remove(os.path.join(nominer, "obenblock-cpu-miner"))
            self.assertIn("no obenblock-cpu-miner", self.install(nominer, stage).stderr)
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
        self.assertEqual(users["obenblock-cpu-miner.service"], "obenblock-miner")
        self.assertEqual(len(set(users.values())), len(UNITS), users)
        for n in UNITS:
            self.assertEqual(self.service(n)["Group"][-1], users[n])
        self.assertNotIn("gnb", users.values())

    def test_miner_is_loopback_only_and_low_priority(self):
        svc = self.service("obenblock-cpu-miner.service")
        self.assertEqual(svc["IPAddressDeny"][-1], "any")
        self.assertEqual(svc["IPAddressAllow"][-1], "localhost")
        self.assertEqual(svc["Nice"][-1], "19")

    def test_no_foreign_unit_is_named(self):
        for path in BASH_SCRIPTS + SH_SCRIPTS:
            text = rd(os.path.join(KIT, path))
            for line in text.splitlines():
                if re.search(r"systemctl\s+(stop|disable|restart|start|mask|kill)\b", line):
                    self.assertNotRegex(line, r"gnb-node|bloch", f"{path}: {line}")

    def test_acme_hooks_are_scoped(self):
        text = rd(os.path.join(KIT, "host/explorer-tls.sh"))
        self.assertIn('--pre-hook "$hooks/pre.sh"', text)
        self.assertNotIn("ufw --force delete allow 80/tcp", text, "never deletes another service's 80/tcp rule")
        self.assertNotRegex(text, r"> \"?/etc/letsencrypt/renewal-hooks", "no host-wide hooks")

    def test_secrets_never_synced(self):
        common = rd(os.path.join(KIT, "lib/common.sh"))
        self.assertIn("--exclude /deploy/obenblock-launch/state", common)
        self.assertIn('rsync -az --delete "${KIT_SRC_EXCLUDES[@]}"', common)
        self.assertIn('rsync -a "${KIT_SRC_EXCLUDES[@]}"', rd(os.path.join(KIT, "obb-launch.sh")))

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
                if f.endswith((".sh", ".py", ".md", ".service", ".exp", ".example")) or f in ("obenblock-launch", "obenblock-miner-launch", "obenblock-stratum-launch"):
                    path = os.path.join(root, f)
                    for i, line in enumerate(rd(path).splitlines(), 1):
                        if "senha:" in line or "gnb-servidor-teste-152.txt" in line:
                            continue  # the password file's own name and field
                        self.assertIsNone(pt.search(line), f"{path}:{i}: {line.strip()}")


class Verify(unittest.TestCase):
    HOSTS = ["136.244.93.186", "209.250.236.240", "152.236.5.112"]

    def status(self, me="136.244.93.186", tip=4000, **over):
        others = [h for h in self.HOSTS if h != me]
        st = {"nproc": 32, "release_dir": "/opt/obenblock/releases/r1",
              "units": {u: {"active": "active", "enabled": "enabled"}
                        for u in ("obenblock-node", "obenblock-cpu-miner", "obenblock-explorer-api")},
              "gnb_node": {"active": "inactive"}, "gnb_processes": 0,
              "node_processes": [{"pid": 1, "threads": 60, "exe": "/opt/obenblock/releases/r1/obenblock", "mine": False,
                                  "stratum": "0.0.0.0:3333", "stratum_v2": "0.0.0.0:3334", "witness": True,
                                  "rpc_key": True, "rpc_public": False}],
              "miner_processes": [{"pid": 2, "threads": "30", "exe": "/opt/obenblock/releases/r1/obenblock-cpu-miner",
                                   "cpu_cores_busy": 29.5}],
              "metrics": {"stratum_sessions_active.v1": 1.0, "stratum_blocks_found_total.v1": 3.0},
              "stratum_v2_key": {"public_b58": "9bXk3pQpYc5r3JqvW1o2x8k7ZtV6sN4mH2gF1dE9cB8aA7zY6xW5"},
              "listening": ["0.0.0.0:3333", "0.0.0.0:3334", "0.0.0.0:18110"], "stratum_ports": [3333, 3334],
              "rpc_ok": True, "network": {"chain_id": "0x4f420001", "peers": 2, "syncing": False, "behind_by": 0},
              "peer_list": [f"/ip4/{o}/tcp/18110" for o in others],
              "genesis": "aa" * 32, "tip": {"tip_height": tip}, "tip_later": tip + 1, "sample_secs": 15,
              "hashes": {str(h): f"{h:064x}" for h in range(tip - 29, tip + 1)},
              "finality": {"pin_height": 3900, "pin_hash": "f" * 64},
              "powit": {"tip_height": tip, "params": {"epoch_len": 720, "checkpoint_interval": 60},
                        "poci": {"active": True, "launch_height": 3600}, "pool": {"shares": 0}},
              "witness": [{"key": "ab" * 20, "weight": "100", "votes_in_chain": 4, "last_vote_target": tip - 60,
                           "halted": False}],
              "hashrate": "1 GH/s"}
        st.update(over)
        return "some line\nOBB-STATUS " + json.dumps(st) + "\n"

    def run_verify(self, statuses, *extra):
        tmp = tempfile.mkdtemp()
        try:
            args = []
            for label, s in statuses:
                path = os.path.join(tmp, label)
                wr(path, s)
                args.append(f"{label}={path}")
            return subprocess.run([sys.executable, os.path.join(KIT, "lib/verify_summary.py"), *extra, *args],
                                  capture_output=True, text=True)
        finally:
            shutil.rmtree(tmp)

    def three(self, **over_by_host):
        return [(h, self.status(h, **over_by_host.get(h.split(".")[0], {}))) for h in self.HOSTS]

    def test_ok(self):
        p = self.run_verify(self.three(), "--genesis", "aa" * 32)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("STRATUM 136.244.93.186 v1=0.0.0.0:3333 v2=0.0.0.0:3334 key=9bXk", p.stdout)

    def assert_fails(self, statuses, text, *extra):
        p = self.run_verify(statuses, *extra)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn(text, p.stdout)

    def test_split_and_sync(self):
        forked = {str(h): f"{h + 7:064x}" for h in range(3971, 4001)}
        self.assert_fails(self.three(**{"152": {"hashes": forked}}), "CHAIN SPLIT: block ids at height 4000")
        self.assert_fails(self.three(**{"152": {"finality": {"pin_height": 3900, "pin_hash": "e" * 64}}}),
                          "different finalized checkpoints at height 3900")
        self.assert_fails(self.three(**{"152": {"tip": 3950}}),
                          "tips more than 29 blocks apart")
        self.assert_fails(self.three(**{"209": {"peer_list": ["/ip4/203.0.113.7/tcp/18110", "/ip4/198.51.100.2/tcp/18110"]}}),
                          "136.244.93.186 is not among its peers")
        self.assert_fails(self.three(**{"136": {"network": {"chain_id": "0x4f420001", "peers": 2, "syncing": True}}}),
                          "syncing=True")

    def test_process_and_release(self):
        two = self.status(node_processes=[{"pid": 1, "exe": "/opt/obenblock/releases/r1/obenblock"}] * 2)
        self.assert_fails([("136.244.93.186", two)], "2 node processes", "--no-peer-check")
        old = self.status(node_processes=[dict(json.loads(self.status().split("OBB-STATUS ")[1])["node_processes"][0],
                                               exe="/opt/obenblock/releases/r0/obenblock")])
        self.assert_fails([("136.244.93.186", old)], "not the installed release", "--no-peer-check")
        self.assert_fails([("h", self.status(miner_processes=[]))], "0 obenblock-cpu-miner processes", "--no-peer-check")
        self.assert_fails([("h", self.status(miner_processes=[{"pid": 2, "threads": "8"}]))], "threads 8, expected 30",
                          "--no-peer-check")
        self.assert_fails([("h", self.status(miner_processes=[{"pid": 2, "threads": "30", "cpu_cores_busy": 0.1}]))],
                          "not hashing", "--no-peer-check")
        self.assert_fails([("h", self.status(metrics={"stratum_sessions_active.v1": 0.0}))], "no Stratum V1 session",
                          "--no-peer-check")
        self.assert_fails([("h", self.status(listening=["0.0.0.0:3333"]))], "nothing listens on :3334", "--no-peer-check")
        st = json.loads(self.status().split("OBB-STATUS ")[1])
        st["node_processes"][0]["mine"] = True
        self.assert_fails([("h", "OBB-STATUS " + json.dumps(st))], "runs --mine as well", "--no-peer-check")

    def test_rehearsal_options(self):
        # --paced-miner: a miner that pauses after each block is not "not hashing".
        idle = [("h", self.status(miner_processes=[{"pid": 2, "threads": "30", "cpu_cores_busy": 0.1}]))]
        p = self.run_verify(idle, "--no-peer-check", "--paced-miner")
        self.assertEqual(p.returncode, 0, p.stdout)
        # --miner-hosts: the other hosts must run no miner, the named ones one.
        p = self.run_verify([("n2", self.status(miner_processes=[]))], "--no-peer-check", "--miner-hosts", "n1,")
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assert_fails([("n2", self.status())], "expected none on this host", "--no-peer-check", "--miner-hosts", "n1,")
        self.assert_fails([("n1", self.status(miner_processes=[]))], "0 obenblock-cpu-miner processes",
                          "--no-peer-check", "--miner-hosts", "n1,")
        # --min-finalized.
        self.assert_fails([("h", self.status(finality={"pin_height": 79, "pin_hash": "e" * 64}))],
                          "finalized height 79, expected at least 140", "--no-peer-check", "--min-finalized", "140")

    def test_witness(self):
        self.assert_fails([("h", self.status(witness=[]))], "no PoWit signer", "--no-peer-check")
        self.assert_fails([("h", self.status(witness=[{"key": "ab" * 20, "weight": None, "votes_in_chain": 3}]))],
                          "not in the PoCI configuration in force", "--no-peer-check")
        self.assert_fails([("h", self.status(witness=[{"key": "ab" * 20, "weight": "1", "votes_in_chain": 0}]))],
                          "no vote included", "--no-peer-check")
        self.assert_fails([("h", self.status(powit={"tip_height": 4000, "params": {"epoch_len": 720, "checkpoint_interval": 60},
                                                    "poci": {"active": False, "launch_height": 3600}}))],
                          "PoCI not active", "--no-peer-check")
        # In the bootstrap epochs no vote is expected yet.
        boot = self.status(tip=500, powit={"tip_height": 500, "params": {"epoch_len": 720, "checkpoint_interval": 60},
                                           "poci": {"active": False, "launch_height": 3600}},
                           witness=[{"key": "ab" * 20, "weight": "5", "votes_in_chain": 0}], finality={})
        p = self.run_verify([("h", boot)], "--no-peer-check")
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_warnings(self):
        p = self.run_verify([(h, s) for h, s in self.three(**{"136": {"gnb_node": {"active": "active"}, "tip_later": 4000}})])
        self.assertEqual(p.returncode, 0, "a running GnB node and a still tip are warnings: " + p.stdout)
        self.assertIn("GnB gnb-node is active", p.stdout)
        self.assertIn("the tip did not move", p.stdout)
        p = self.run_verify([("h", "nothing\n")])
        self.assertIn("no status", p.stdout)


class SiteLaunch(unittest.TestCase):
    def test_launch_json_fills_every_page_key(self):
        import site_launch
        keys = site_launch.page_keys(os.path.join(REPO, "site"))
        self.assertTrue({"GENESIS_HASH", "STRATUM_ENDPOINT", "SEED_NODES", "LAUNCH_TIME", "RELEASE"} <= keys, keys)
        out = os.path.join(tempfile.mkdtemp(), "launch.json")
        self.addCleanup(shutil.rmtree, os.path.dirname(out))
        key = "9bXk3pQpYc5r3JqvW1o2x8k7ZtV6sN4mH2gF1dE9cB8aA7zY6xW5"
        p = subprocess.run([sys.executable, os.path.join(KIT, "lib/site_launch.py"), "--site", os.path.join(REPO, "site"),
                            "--genesis-hash", REHEARSAL["display"], "--launch-ts", "1792281600",
                            "--seeds", " ".join(Verify.HOSTS), "--stratum", " ".join(f"{h}={key}" for h in Verify.HOSTS),
                            "--release", "abc-gbc-c1", "--release-sha256", "cd" * 32, "--out", out],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        values = json.loads(rd(out))
        self.assertEqual(set(values), keys)
        self.assertEqual(values["GENESIS_HASH"], REHEARSAL["display"])
        self.assertIn("stratum+tcp://136.244.93.186:3333", values["STRATUM_ENDPOINT"])
        self.assertIn(f"stratum2+tcp://152.236.5.112:3334/{key}", values["STRATUM_ENDPOINT"])
        self.assertIn("209.250.236.240:18110", values["SEED_NODES"])
        self.assertIn("2026-10-18 00:00:00 UTC", values["LAUNCH_TIME"])
        bad = subprocess.run([sys.executable, os.path.join(KIT, "lib/site_launch.py"), "--site", os.path.join(REPO, "site"),
                              "--genesis-hash", REHEARSAL["display"], "--launch-ts", "1", "--seeds", "136.244.93.186",
                              "--stratum", "", "--release", "x", "--release-sha256", "cd" * 32], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0, "a missing V2 key is refused")


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
