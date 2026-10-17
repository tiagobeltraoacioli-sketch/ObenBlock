#!/usr/bin/env python3
"""Checks of the deployment files (audit OPS-3).

* Every systemd unit (node, explorer API, Cloudflare Tunnel) keeps its
  sandboxing directives, runs as an unprivileged user, and the explorer API
  runs as its OWN user, not the node's (`gnb`): a compromise of the
  internet-facing API must not reach the node's data dir.
* `systemd-analyze security --offline=true` rates every unit at most
  MAX_EXPOSURE, and `systemd-analyze verify` finds nothing but the absent
  executables of this checkout (when systemd-analyze is installed, as on
  the CI runners).
* Every shell script parses (`sh -n`) and passes ShellCheck when it is
  installed (CI installs it; set GNB_REQUIRE_TOOLS=1 to fail without the
  tools instead of skipping).

Run: python3 deploy/test_deploy_files.py
"""

import os
import re
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
UNITS = {
    "node": os.path.join(HERE, "gnb-node.service"),
    "explorer-api": os.path.join(HERE, "explorer-api", "gnb-explorer-api.service"),
    "cloudflared": os.path.join(HERE, "explorer-api", "cloudflared-gnb-explorer.service"),
    "bloch-anchor": os.path.join(HERE, "bloch-anchor", "bloch-anchor.service"),
}
SCRIPTS = [
    os.path.join(HERE, "gnb-launch"),
    os.path.join(HERE, "install-host.sh"),
    os.path.join(HERE, "explorer-api", "firewall-cloudflare.sh"),
]
# systemd-analyze security exposure (0 = fully sandboxed, 10 = none). The
# node scored 1.5, the API and the tunnel 8.3 before OPS-3.
MAX_EXPOSURE = 2.0
REQUIRE_TOOLS = os.environ.get("GNB_REQUIRE_TOOLS") == "1"

# Directive -> required value, for every unit.
REQUIRED = {
    "NoNewPrivileges": "true",
    "ProtectSystem": "strict",
    "ProtectHome": "true",
    "PrivateTmp": "true",
    "PrivateDevices": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectKernelLogs": "true",
    "ProtectControlGroups": "true",
    "ProtectClock": "true",
    "ProtectHostname": "true",
    "ProtectProc": "invisible",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "RestrictNamespaces": "true",
    "RestrictRealtime": "true",
    "RestrictSUIDSGID": "true",
    "LockPersonality": "true",
    "MemoryDenyWriteExecute": "true",
    "SystemCallArchitectures": "native",
    "UMask": "0077",
}
ALLOWED_FAMILIES = {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}


def parse_unit(path):
    """{section: {key: [values in order]}} (comments and blanks skipped)."""
    sections, cur = {}, None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = sections.setdefault(line[1:-1], {})
                continue
            key, sep, value = line.partition("=")
            if not sep or cur is None:
                raise ValueError(f"{path}: cannot parse {line!r}")
            cur.setdefault(key.strip(), []).append(value.strip())
    return sections


def tool(name):
    path = shutil.which(name)
    if path is None and REQUIRE_TOOLS:
        raise AssertionError(f"{name} is required (GNB_REQUIRE_TOOLS=1) but not installed")
    return path


class UnitHardening(unittest.TestCase):
    def service(self, name):
        return parse_unit(UNITS[name])["Service"]

    def test_every_unit_keeps_its_sandbox(self):
        for name in UNITS:
            svc = self.service(name)
            for key, want in REQUIRED.items():
                with self.subTest(unit=name, directive=key):
                    self.assertIn(key, svc, f"{name}: {key}= missing")
                    self.assertEqual(svc[key][-1], want, f"{name}: {key}={svc[key][-1]!r}, want {want!r}")
            with self.subTest(unit=name, directive="RestrictAddressFamilies"):
                families = set(" ".join(svc.get("RestrictAddressFamilies", [])).split())
                self.assertTrue(families, f"{name}: RestrictAddressFamilies= missing")
                self.assertLessEqual(families, ALLOWED_FAMILIES, f"{name}: {families - ALLOWED_FAMILIES}")
            with self.subTest(unit=name, directive="SystemCallFilter"):
                filters = svc.get("SystemCallFilter", [])
                self.assertIn("@system-service", filters, f"{name}: SystemCallFilter=@system-service missing")

    def test_services_run_as_unprivileged_users_and_the_api_has_its_own(self):
        users = {name: self.service(name).get("User", [""])[-1] for name in UNITS}
        for name, user in users.items():
            self.assertNotIn(user, ("", "root"), f"{name} must not run as root")
            self.assertEqual(self.service(name).get("Group", [""])[-1], user, f"{name}: Group= must match User=")
        self.assertEqual(users["node"], "gnb")
        self.assertNotEqual(users["explorer-api"], users["node"],
                            "the explorer API must not run as the node's user (audit OPS-3)")
        self.assertNotEqual(users["cloudflared"], users["node"])
        self.assertNotEqual(users["cloudflared"], users["explorer-api"])
        self.assertNotIn(users["bloch-anchor"], (users["node"], users["explorer-api"]),
                         "the anchoring wallet must not be readable by the node or the API")

    def test_the_explorer_api_writes_nothing_and_reaches_loopback_only(self):
        svc = self.service("explorer-api")
        self.assertNotIn("ReadWritePaths", svc)
        self.assertEqual(svc.get("IPAddressDeny"), ["any"])
        self.assertEqual(svc.get("IPAddressAllow"), ["localhost"])
        self.assertEqual(svc.get("Environment", []).count("GNB_API_BIND=127.0.0.1"), 1)

    def test_readme_installs_the_api_for_its_own_user(self):
        with open(os.path.join(HERE, "explorer-api", "README.md"), encoding="utf-8") as fh:
            readme = fh.read()
        self.assertIn("useradd --system", readme)
        self.assertIn("-g gnb-api", readme)
        self.assertNotIn("-g gnb ", readme)

    def test_systemd_analyze_security_rates_every_unit_sandboxed(self):
        sa = tool("systemd-analyze")
        if sa is None:
            self.skipTest("systemd-analyze not installed")
        for name, path in UNITS.items():
            with self.subTest(unit=name):
                p = subprocess.run([sa, "security", "--offline=true", "--no-pager", path],
                                   capture_output=True, text=True, timeout=60)
                m = re.search(r"Overall exposure level for \S+: (\d+\.\d+)", p.stdout + p.stderr)
                if m is None and "offline" in (p.stderr or "") and not REQUIRE_TOOLS:
                    self.skipTest("this systemd-analyze has no --offline (systemd < 252)")
                self.assertIsNotNone(m, p.stdout + p.stderr)
                self.assertLessEqual(float(m.group(1)), MAX_EXPOSURE, f"{name}: exposure {m.group(1)}")

    def test_systemd_analyze_verify_finds_nothing_but_absent_executables(self):
        sa = tool("systemd-analyze")
        if sa is None:
            self.skipTest("systemd-analyze not installed")
        p = subprocess.run([sa, "verify", "--man=no", *UNITS.values()], capture_output=True, text=True,
                           timeout=60, cwd=HERE)
        problems = [line for line in (p.stdout + p.stderr).splitlines()
                    if line.strip() and "is not executable: No such file or directory" not in line]
        self.assertEqual(problems, [], "\n".join(problems))


class ShellScripts(unittest.TestCase):
    def test_every_script_parses(self):
        for path in SCRIPTS:
            with self.subTest(script=os.path.basename(path)):
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(fh.readline().strip(), "#!/bin/sh", "POSIX sh scripts only")
                p = subprocess.run(["sh", "-n", path], capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 0, p.stderr)

    def test_shellcheck_is_clean(self):
        sc = tool("shellcheck")
        if sc is None:
            self.skipTest("shellcheck not installed")
        p = subprocess.run([sc, "--shell=sh", *SCRIPTS], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
