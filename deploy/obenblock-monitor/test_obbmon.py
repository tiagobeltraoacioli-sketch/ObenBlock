#!/usr/bin/env python3
"""Tests of the ObenBlock monitor's parsing and checks (no network, no SSH).

    python3 -I deploy/obenblock-monitor/test_obbmon.py

testdata/probe-healthy.json is one host's probe document whose RPC results
have the shapes of the node's handlers (getnetworkinfo/getdaginfo/... in
node/src/rpc/mod.rs, getpowitinfo/getfinalityinfo in node/src/powit.rs,
the Bloch anchor in node/src/anchoring.rs, getselectedchain in
node/src/rpc/explorer.rs); the values are synthetic. The other files are
raw `ps`, Prometheus, journal and /proc/meminfo text in the formats the
probe reads. Every scenario below derives from them.
"""
import copy
import importlib.util
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "testdata")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


probe = load("obb_probe_t", "probe.py")
obbmon = load("obbmon_t", "obbmon.py")


def text_of(path):
    with open(path) as fh:
        return fh.read()


def text(name):
    return text_of(os.path.join(DATA, name))


BASE = json.loads(text("probe-healthy.json"))
NOW = BASE["time"]


def host(name, tip_shift=0, fork_from=None, fork_tag="d0"):
    """A copy of the healthy probe as host `name`, its tip `tip_shift` blocks
    above the base; from height `fork_from` up its chain carries other
    hashes (a fork)."""
    d = copy.deepcopy(BASE)
    d["host"] = name
    chain = d["rpc"]["getselectedchain"]["blocks"]
    top = chain[0]["height"] + tip_shift
    t0 = chain[0]["timestamp"]
    new = []
    for i in range(len(chain)):
        hgt = top - i
        hsh = (f"c0{hgt:014x}") * 4
        if fork_from is not None and hgt >= fork_from:
            hsh = (f"{fork_tag}{hgt:014x}") * 4
        new.append({"hash": hsh, "height": hgt, "timestamp": t0 - 30 * i + 30 * tip_shift, "blue_score": hgt + 200})
    d["rpc"]["getselectedchain"]["blocks"] = new
    d["rpc"]["getdaginfo"]["tip"] = new[0]["hash"]
    d["rpc"]["getdaginfo"]["tip_height"] = top
    return d


def summaries(*docs, now=NOW, cfg=None):
    return [obbmon.summarize(d["host"], d, cfg, now) for d in docs]


def codes(alerts):
    return sorted({a["code"] for a in alerts})


class ProbeParsers(unittest.TestCase):
    def test_ps_keeps_only_the_node_process(self):
        rows = probe.parse_ps(text("ps.txt"), "obenblock")
        self.assertEqual([r["pid"] for r in rows], [41237])
        r = rows[0]
        self.assertEqual((r["etime"], r["etimes"], r["pcpu"], r["rss_kb"]), ("1-02:03:04", 93784, 187.5, 1843200))
        self.assertIn("--mine-threads 27", r["args"])

    def test_prometheus_stratum_proxy(self):
        m = probe.parse_prometheus(text("stratum.prom"))
        self.assertEqual(m["obb_stratum_workers_active"], 2)
        self.assertEqual(m["obb_stratum_blocks_rejected_total"], 1)
        self.assertEqual(m["obb_stratum_pplns_window_weight"], 1.5e9)
        self.assertNotIn("# HELP", "".join(m))

    def test_prometheus_node_sums_labels_and_drops_foreign_series(self):
        m = probe.parse_prometheus(text("node.prom"))
        self.assertEqual(m["gnb_rpc_requests_total"], 150)
        self.assertEqual(m["gnb_stratum_sessions_active"], 2)
        self.assertEqual(m["gnb_block_validation_seconds_count"], 1001)
        self.assertEqual(m["gnb_info"], 1)
        self.assertNotIn("process_cpu_seconds_total", m)

    def test_cpu_miner_journal_takes_the_newest_rate(self):
        r = probe.parse_cpu_miner_journal(text("journal-cpu-miner.txt"))
        self.assertEqual((r["kind"], r["mhs"], r["accepted"], r["rejected"]), ("rate", 203.9, 7, 1))
        self.assertAlmostEqual(r["at"], 1792999061.500005)

    def test_cpu_miner_journal_start_line_only(self):
        lines = text("journal-cpu-miner.txt").splitlines()[:3]
        r = probe.parse_cpu_miner_journal("\n".join(lines))
        self.assertEqual((r["kind"], r["mhs"], r["threads"], r["kernel"]), ("start", 196.5, 31, "avx2"))
        self.assertIsNone(probe.parse_cpu_miner_journal("-- No entries --"))

    def test_meminfo(self):
        m = probe.parse_meminfo(text("meminfo.txt"))
        self.assertEqual(m["MemAvailable"], 96543210 * 1024)
        self.assertEqual(set(m), {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"})

    def test_trim_chain_and_errors_pass_through(self):
        full = {"chain_length": 3, "offset": 0, "blocks": [
            {"hash": "aa", "height": 2, "timestamp": 5, "blue_score": 9, "parents": 1, "miner": "obb1x", "reward": "1"}]}
        self.assertEqual(probe.trim_chain(full), {"chain_length": 3, "blocks": [
            {"hash": "aa", "height": 2, "timestamp": 5, "blue_score": 9}]})
        self.assertEqual(probe.trim_chain({"error": "no selected tip yet"}), {"error": "no selected tip yet"})

    def test_rpc_to_a_closed_port_is_an_error_object(self):
        r = probe.rpc(1, "getnetworkinfo", timeout=2)
        self.assertIn("error", r)

    def test_parse_probe_output_through_an_expect_pty(self):
        out = "ubuntu@152.236.5.112's password: \r\nOBB-PROBE " + json.dumps(BASE) + "\r\n"
        self.assertEqual(obbmon.parse_probe_output(out)["host"], "obb-mainnet-136")
        self.assertEqual(obbmon.parse_probe_output(json.dumps(BASE))["rpc_port"], 18210)
        self.assertIsNone(obbmon.parse_probe_output("Permission denied (password)."))


class HostSummary(unittest.TestCase):
    def test_healthy_host_has_no_alert(self):
        s = obbmon.summarize("136", BASE, now=NOW)
        self.assertEqual(s["alerts"], [])
        self.assertEqual(s["tip"]["height"], 1000)
        self.assertEqual(s["tip"]["age_secs"], 20)
        self.assertEqual(s["tip"]["avg_block_secs"], 30.0)
        self.assertEqual(s["peers"]["count"], 2)
        self.assertEqual(s["poci"]["config_epoch"], 30)
        self.assertEqual(s["poci"]["finalized"], {"slot": 30, "hash": BASE["rpc"]["getfinalityinfo"]["pin"]["hash"]})
        self.assertAlmostEqual(s["poci"]["absent"]["frac"], 1 / 30, places=3)
        self.assertTrue(s["poci"]["certificate"])
        self.assertEqual(s["bloch"]["status"], "consistent")
        self.assertEqual(s["stratum"]["proxy"]["blocks_found_total"], 37)
        self.assertTrue(s["cpu_mining"]["node_miner"])
        self.assertEqual(s["cpu_mining"]["node_mine_threads"], "27")
        self.assertEqual(s["system"]["disk"][0]["used_pct"], 30.0)
        txt = obbmon.render([s], [], NOW)
        self.assertIn("RESULT OK", txt)
        self.assertIn("120.00 TH/s", txt)

    def test_unreachable(self):
        s = obbmon.summarize("152", {"transport_error": "exit 255: Permission denied"}, now=NOW)
        self.assertEqual(codes(s["alerts"]), ["UNREACHABLE"])
        self.assertIn("UNREACHABLE", obbmon.render([s], [], NOW))

    def test_node_down_rpc_down(self):
        d = copy.deepcopy(BASE)
        d["processes"] = []
        d["units"]["obenblock-node"] = "failed"
        d["rpc"] = {"getnetworkinfo": {"error": "URLError: <urlopen error [Errno 111] Connection refused>"}}
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual(codes(s["alerts"]), ["NODE_NOT_RUNNING", "RPC_DOWN", "UNIT_NOT_ACTIVE"])
        obbmon.render([s], [], NOW)  # renders without the RPC sections

    def test_stalled_tip_by_timestamp(self):
        s = obbmon.summarize("136", BASE, now=NOW + 2000)
        self.assertIn("STALLED", codes(s["alerts"]))

    def test_finality_conflict_and_anchor_alerts(self):
        d = copy.deepcopy(BASE)
        fi = d["rpc"]["getfinalityinfo"]
        fi["conflict"] = [{"hash": "aa" * 32, "block_height": 960}, {"hash": "bb" * 32, "block_height": 960}]
        fi["conflicting_finalized"] = 1
        fi["conflict_resolution"] = "own_finality"
        fi["anchor_status"] = "unknown"
        fi["anchor_overdue"] = True
        d["rpc"]["getpowitinfo"]["finality_conflict"] = True
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual(codes(s["alerts"]), ["FINALITY_ANCHOR_UNKNOWN", "FINALITY_CONFLICT"])

    def test_bloch_anchor_conflict(self):
        d = copy.deepcopy(BASE)
        b = d["rpc"]["getfinalityinfo"]["bloch_anchor"]
        b.update(status="conflict", alert=True, detail="slot 15 names block e1.. off the finalized chain")
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual(codes(s["alerts"]), ["BLOCH_ANCHOR_CONFLICT"])

    def test_bloch_poll_error_is_a_warning(self):
        d = copy.deepcopy(BASE)
        d["rpc"]["getfinalityinfo"]["bloch_anchor"]["last_error"] = "connection refused"
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual([(a["level"], a["code"]) for a in s["alerts"]], [("WARN", "BLOCH_ANCHOR_ERROR")])

    def test_poci_absent_over_a_third_and_signer_halted(self):
        d = copy.deepcopy(BASE)
        last = d["rpc"]["getfinalityinfo"]["poci"]["absent_weight"][-1]
        last.update(weight="200000000000000000000000000000000000", keys=2, over_a_third=True)
        pw = d["rpc"]["getpowitinfo"]
        pw["signer_halted"] = True
        pw["signers"][0].update(halted=True, alert="second instance of key a1a1..")
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual(codes(s["alerts"]), ["POCI_ABSENT_OVER_THIRD", "SIGNER_HALTED"])

    def test_poci_bootstrap_reports_launch_height(self):
        d = copy.deepcopy(BASE)
        boot = {"active": False, "bootstrap_epochs": 4, "launch_height": 1152}
        d["rpc"]["getfinalityinfo"]["poci"] = boot
        d["rpc"]["getpowitinfo"]["poci"] = boot
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual(s["poci"], {"active": False, "launch_height": 1152, "bootstrap_epochs": 4,
                                     "blocks_to_launch": 152})
        self.assertIn("launch_height 1152", obbmon.render([s], [], NOW))

    def test_gnb_style_answer_without_poci(self):
        d = copy.deepcopy(BASE)
        del d["rpc"]["getfinalityinfo"]["poci"]
        d["rpc"]["getpowitinfo"]["poci"] = None
        s = obbmon.summarize("136", d, now=NOW)
        self.assertNotIn("poci", s)
        self.assertEqual(s["alerts"], [])

    def test_resources_peers_stratum(self):
        d = copy.deepcopy(BASE)
        d["system"]["disk"][1]["free"] = 50_000_000_000
        d["system"]["mem"]["MemAvailable"] = d["system"]["mem"]["MemTotal"] // 20
        d["rpc"]["getpeers"] = {"peer_count": 0, "peers": []}
        d["metrics"]["stratum"]["obb_stratum_blocks_rejected_total"] = 2.0
        d["processes"].append(dict(d["processes"][0], pid=41238))
        s = obbmon.summarize("136", d, now=NOW)
        self.assertEqual(codes(s["alerts"]), ["DISK_FULL", "MEMORY_LOW", "NODE_DUPLICATE", "NO_PEERS",
                                              "STRATUM_BLOCKS_REJECTED"])

    def test_node_metrics_builtin_stratum_and_cpu_miner(self):
        d = copy.deepcopy(BASE)
        d["metrics"]["node"] = probe.parse_prometheus(text("node.prom"))
        d["cpu_miner"] = probe.parse_cpu_miner_journal(text("journal-cpu-miner.txt"))
        d["units"]["obenblock-cpu-miner"] = "active"
        s = obbmon.summarize("209", d, now=1792999061 + 60)
        self.assertEqual(s["stratum"]["builtin"]["sessions_active"], 2)
        self.assertEqual(s["cpu_mining"]["cpu_miner_mhs"], 203.9)
        self.assertNotIn("CPU_MINER_SILENT", codes(s["alerts"]))
        s = obbmon.summarize("209", d, now=1792999061 + 900)
        self.assertIn("CPU_MINER_SILENT", codes(s["alerts"]))
        self.assertIn("203.9 MH/s", obbmon.render([s], [], NOW))


class CrossHost(unittest.TestCase):
    def test_three_healthy_hosts_agree(self):
        sums = summaries(host("136"), host("209", 1), host("152", 2))
        cross = obbmon.cross_check(sums, now=NOW)
        self.assertEqual(codes(cross), ["TIPS_DIFFER"])  # INFO only: within split_depth
        self.assertEqual(obbmon.worst(cross), 0)

    def test_split_below_the_tolerance(self):
        a = host("136")
        b = host("209", fork_from=995)  # differs 5 blocks below its tip
        cross = obbmon.cross_check(summaries(a, b, host("152")), now=NOW)
        split = [x for x in cross if x["code"] == "SPLIT_TIPS"]
        self.assertEqual(len(split), 1)
        self.assertIn("height 998", split[0]["msg"])
        self.assertIn("209", split[0]["msg"])
        self.assertEqual(obbmon.worst(cross), 2)

    def test_tips_that_differ_only_in_the_last_two_blocks_are_not_a_split(self):
        a = host("136")
        b = host("209", fork_from=999)
        self.assertNotIn("SPLIT_TIPS", codes(obbmon.cross_check(summaries(a, b), now=NOW)))

    def test_height_spread_and_unchecked_window(self):
        a = host("136")
        b = host("209", 40)  # 40 blocks ahead: its 32-block window misses height 998
        cross = obbmon.cross_check(summaries(a, b), now=NOW)
        self.assertEqual(codes(cross), ["HEIGHT_SPREAD", "SPLIT_UNCHECKED", "TIPS_DIFFER"])

    def test_finality_divergence_and_pin_off_chain(self):
        a, b = host("136"), host("209")
        other = "ee" * 32
        b["rpc"]["getfinalityinfo"]["finalized"][0]["hash"] = other
        b["rpc"]["getfinalityinfo"]["poci"]["finalized"]["hash"] = other
        # Pins inside the 32-block window (969..1000): a's on the chains, b's not.
        a["rpc"]["getfinalityinfo"]["pin"] = {"hash": ("c0" + f"{976:014x}") * 4, "block_height": 976}
        b["rpc"]["getfinalityinfo"]["pin"] = {"hash": other, "block_height": 976}
        cross = obbmon.cross_check(summaries(a, b), now=NOW)
        self.assertEqual(codes(cross), ["FINALITY_DIVERGENCE", "PIN_DIVERGENCE", "PIN_OFF_CHAIN"])

    def test_poci_configuration_divergence(self):
        a, b = host("136"), host("209")
        b["rpc"]["getfinalityinfo"]["poci"]["config_id"] = "77" * 32
        cross = obbmon.cross_check(summaries(a, b), now=NOW)
        self.assertEqual(codes(cross), ["POCI_CONFIG_DIVERGENCE"])

    def test_bloch_anchor_divergence(self):
        a, b, c = host("136"), host("209"), host("152")
        for d in (b, c):
            bl = d["rpc"]["getfinalityinfo"]["bloch_anchor"]
            bl["anchor"]["record_id"] = "f2" * 32
            bl.update(status="conflict", alert=True, detail="registry answered another record")
        sums = summaries(a, b, c)
        cross = obbmon.cross_check(sums, now=NOW)
        self.assertEqual(codes(cross), ["BLOCH_ANCHOR_CONFLICT_MULTI", "BLOCH_ANCHOR_DIVERGENCE"])

    def test_genesis_and_chain_id_mismatch(self):
        a, b = host("136"), host("209")
        b["rpc"]["genesis"] = "47" * 32
        b["rpc"]["getnetworkinfo"]["chain_id"] = "0x474e0001"
        cross = obbmon.cross_check(summaries(a, b), now=NOW)
        self.assertEqual(codes(cross), ["CHAIN_ID_MISMATCH", "GENESIS_MISMATCH"])

    def test_stalled_height_over_runs(self):
        state = {}
        docs = (host("136"), host("209"))
        self.assertEqual(obbmon.cross_check(summaries(*docs), state=state, now=NOW), [])
        self.assertEqual(obbmon.cross_check(summaries(*docs, now=NOW + 600), state=state, now=NOW + 600), [])
        later = NOW + 1000
        cross = obbmon.cross_check(summaries(*docs, now=later), state=state, now=later)
        self.assertEqual(codes(cross), ["NETWORK_STALLED", "STALLED_HEIGHT"])
        # One host moves: its stall ends, the network's too.
        docs2 = (host("136", 1), host("209"))
        cross = obbmon.cross_check(summaries(*docs2, now=later + 30), state=state, now=later + 30)
        self.assertEqual([a["msg"].split(":")[0] for a in cross if a["code"] == "STALLED_HEIGHT"], ["209"])
        self.assertNotIn("NETWORK_STALLED", codes(cross))

    def test_unreachable_host_is_left_out_of_the_comparison(self):
        sums = summaries(host("136"), host("209"))
        sums.append(obbmon.summarize("152", {"transport_error": "timed out after 90s"}, now=NOW))
        self.assertEqual(obbmon.cross_check(sums, now=NOW), [])


class Commands(unittest.TestCase):
    def test_offline_command_json_and_exit_status(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name, doc in (("136", host("136")), ("209", host("209", fork_from=990))):
                p = os.path.join(tmp, f"{name}.json")
                with open(p, "w") as fh:
                    fh.write("noise\nOBB-PROBE " + json.dumps(doc) + "\n")
                paths.append(f"{name}={p}")
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "obbmon.py"), "offline", *paths, "--json"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out["result"], "CRIT")
            self.assertIn("SPLIT_TIPS", codes(out["cross"]))
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "obbmon.py"), "offline", paths[0]],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("RESULT OK", r.stdout)
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "obbmon.py"), "offline"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 3, "a usage error is not the critical status 2")

    def test_remote_command_is_shell_safe_and_runs_the_probe(self):
        cmd = obbmon.remote_command(["--rpc-port", "1", "--chain-window", "4"])
        self.assertTrue(cmd.startswith('python3 -I -c "'))
        inner = cmd[len('python3 -I -c "'):cmd.rindex('"')]
        self.assertFalse(set(inner) & set('"$`\\!'), "nothing the remote shell expands inside the quotes")
        with self.assertRaises(SystemExit):
            obbmon.remote_command(["--rpc-port", "1; rm -rf /"])
        # Run the shipped code locally through a shell, as ssh would: the
        # probe answers even with nothing listening (RPC_DOWN, not a crash).
        r = subprocess.run(["/bin/sh", "-c", cmd.replace("python3", sys.executable, 1)],
                           capture_output=True, text=True, timeout=120)
        doc = obbmon.parse_probe_output(r.stdout)
        self.assertIsNotNone(doc, r.stderr)
        self.assertIn("error", doc["rpc"]["getnetworkinfo"])
        self.assertEqual(doc["rpc_port"], 1)

    def test_pw_run_never_prints_the_password(self):
        with open(os.path.join(HERE, "pw-run.exp")) as fh:
            src = fh.read()
        self.assertNotIn("puts $pw", src)
        self.assertNotIn("log_file", src)
        import re
        self.assertEqual(len(re.findall(r"\$pw\b", src)), 2)  # the empty check and the one send
        self.assertIn('send -- "$pw\\r"', src)

    def test_systemd_units_write_only_their_state_dir(self):
        unit = text_of(os.path.join(HERE, "systemd", "obenblock-monitor.service"))
        for line in ("Type=oneshot", "DynamicUser=yes", "StateDirectory=obenblock-monitor", "ProtectSystem=strict",
                     "NoNewPrivileges=true", "CapabilityBoundingSet=", "ProtectHome=true"):
            self.assertIn(line + "\n", unit)
        self.assertIn("--out /var/lib/obenblock-monitor/status.json", unit)
        timer = text_of(os.path.join(HERE, "systemd", "obenblock-monitor.timer"))
        self.assertIn("OnUnitActiveSec=", timer)


if __name__ == "__main__":
    unittest.main(verbosity=1)
