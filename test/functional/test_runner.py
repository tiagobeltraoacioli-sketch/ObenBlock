#!/usr/bin/env python3
"""Run the GnB functional tests in parallel, each with a timeout.

    test/functional/test_runner.py                 # build, then run every test
    test/functional/test_runner.py rpc_auth.py     # a subset
    test/functional/test_runner.py --jobs 4 --timeout 300 --bindir DIR

Steps: resolve the test-only binaries once (cargo build of the node's
`test-pow-limit` feature, or --bindir / --no-build) and snapshot them; build
the shared start states (genesis data dir, mined chain with a funded wallet)
once; then run each test script as its own process group with its own port
window and temp dir. A test that exceeds --timeout is terminated (SIGTERM,
then SIGKILL to the whole group); after every test, any process still running
from its temp dir is killed and the temp dir removed (kept with
--keep-failed for a failed test). Exit code 0 requires every selected test
to pass. Local runs may explicitly accept skips with --allow-skips; CI uses
--ci, which cannot be combined with that local mode.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from test_framework import binaries  # noqa: E402
from test_framework.cache import Cache  # noqa: E402
from test_framework.util import PortAllocator  # noqa: E402

# Every functional test. Longest first, so parallel runs finish sooner.
ALL_TESTS = [
    "mining_full_template.py",
    "feature_partition_heal.py",
    "p2p_block_propagation.py",
    "feature_activation_testnet.py",
    "feature_restart_persistence.py",
    "feature_invalidateblock.py",
    "p2p_invalid_blocks_txs.py",
    "wallet_coinbase_maturity.py",
    "wallet_descriptor_restore.py",
    "mempool_tx_relay.py",
    "mempool_replacement.py",
    "mining_getblocktemplate_submitblock.py",
    "rpc_gettxoutsetinfo.py",
    "rpc_auth.py",
    "feature_assumevalid.py",
    "feature_test_build_guard.py",
]

EXIT_PASSED, EXIT_SKIPPED = 0, 77


def kill_strays(marker: str) -> int:
    """Kill every process whose command line mentions `marker` (a test's temp
    dir: every node it started has its data dir there). Linux /proc only."""
    killed = 0
    if not os.path.isdir("/proc"):
        return 0
    me = os.getpid()
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == me:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if marker in cmd:
            try:
                os.kill(int(pid), signal.SIGKILL)
                killed += 1
            except OSError:
                pass
    return killed


class Job:
    def __init__(self, name: str, index: int, args, bindir: str, tmproot: str):
        self.name = name
        self.tmpdir = os.path.join(tmproot, os.path.splitext(name)[0])
        os.makedirs(self.tmpdir, exist_ok=True)
        self.log_path = os.path.join(tmproot, os.path.splitext(name)[0] + ".out")
        cmd = [sys.executable, os.path.join(HERE, name), "--bindir", bindir, "--cachedir", args.cachedir,
               "--tmpdir", self.tmpdir, f"--portseed={index * 7 + os.getpid() % 50}",
               f"--timeout-factor={args.timeout_factor}"]
        if args.keep_failed:
            cmd.append("--keep-failed")
        self.out = open(self.log_path, "wb")
        self.start = time.monotonic()
        self.proc = subprocess.Popen(cmd, stdout=self.out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True, cwd=HERE)
        self.status = None
        self.duration = 0.0
        self.timed_out = False

    def poll(self, timeout: float) -> bool:
        if self.proc.poll() is not None:
            return True
        if time.monotonic() - self.start > timeout:
            self.timed_out = True
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)  # the test cleans up on SIGTERM
                self.proc.wait(timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except OSError:
                pass
            self.proc.wait()
            return True
        return False

    def finish(self, keep_failed: bool) -> None:
        self.duration = time.monotonic() - self.start
        self.out.close()
        rc = self.proc.returncode
        self.status = ("Timeout" if self.timed_out else
                       "Passed" if rc == EXIT_PASSED else "Skipped" if rc == EXIT_SKIPPED else "Failed")
        strays = kill_strays(self.tmpdir)
        if strays:
            self.status = "Failed" if self.status == "Passed" else self.status
            with open(self.log_path, "a") as f:
                f.write(f"\ntest_runner: killed {strays} stray process(es) left by the test\n")
        if self.status in ("Passed", "Skipped") or not keep_failed:
            shutil.rmtree(self.tmpdir, ignore_errors=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("tests", nargs="*", help="test scripts to run (default: all)")
    p.add_argument("--jobs", "-j", type=int, default=min(4, max(1, (os.cpu_count() or 2) // 2)),
                   help="tests run in parallel (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=240, help="seconds per test (default: %(default)s)")
    p.add_argument("--timeout-factor", type=float, default=1.0, help="passed to every test")
    p.add_argument("--bindir", help="test-pow-limit gnb + gnb-cli (default: cargo build)")
    p.add_argument("--no-build", action="store_true", help="use $CARGO_TARGET_DIR/debug without building")
    p.add_argument("--cachedir", default=os.environ.get("GNB_FUNCTIONAL_CACHE") or
                   os.path.join(tempfile.gettempdir(), f"gnb-functional-cache-{os.getuid()}"))
    p.add_argument("--tmpdir", help="root for the run's temp dirs (default: a new system temp dir)")
    p.add_argument("--keep-failed", action="store_true", help="keep the temp dir (logs) of failed tests")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--ci", action="store_true", help="require every selected test to pass (the default)")
    mode.add_argument("--allow-skips", action="store_true", help="local runs only: accept skips, reported separately")
    p.add_argument("--list", action="store_true", help="list the tests and exit")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    log = logging.getLogger("test_runner")
    if args.list:
        print("\n".join(ALL_TESTS))
        return 0
    tests = [os.path.basename(t) for t in args.tests] or ALL_TESTS
    unknown = [t for t in tests if t not in ALL_TESTS]
    if unknown:
        log.error("unknown test(s): %s", ", ".join(unknown))
        return 1

    os.makedirs(args.cachedir, exist_ok=True)
    tmproot = args.tmpdir or tempfile.mkdtemp(prefix="gnb_functional_")
    os.makedirs(tmproot, exist_ok=True)
    started = time.monotonic()

    snap = binaries.resolve(args.bindir, not args.no_build, args.cachedir, log)
    bindir = os.path.dirname(snap["gnb"])
    log.info("binaries: %s (test-pow-limit build, refuses mainnet: verified)", bindir)
    cache = Cache(args.cachedir, snap, binaries.REPO_ROOT, log)
    cache.ensure_carryover()
    ports = PortAllocator(os.getpid() % 50 + 400)
    cache.base_dir(ports)
    cache.chain_dir(ports)
    log.info("start states ready (%.0fs); running %d test(s), %d at a time, %ds timeout each",
             time.monotonic() - started, len(tests), args.jobs, args.timeout)

    pending = list(tests)
    running: list[Job] = []
    done: list[Job] = []
    index = 0
    try:
        while pending or running:
            while pending and len(running) < args.jobs:
                name = pending.pop(0)
                running.append(Job(name, index, args, bindir, tmproot))
                index += 1
            for job in list(running):
                if job.poll(args.timeout):
                    job.finish(args.keep_failed)
                    running.remove(job)
                    done.append(job)
                    log.info("%-42s %-8s %6.1fs", job.name, job.status, job.duration)
                    if job.status != "Passed" and not (args.allow_skips and job.status == "Skipped"):
                        with open(job.log_path, "rb") as f:
                            sys.stdout.write(f.read().decode("utf-8", "replace")[-20000:])
                        sys.stdout.flush()
            time.sleep(0.2)
    except KeyboardInterrupt:
        log.error("interrupted; stopping running tests")
        for job in running:
            try:
                os.killpg(job.proc.pid, signal.SIGKILL)
            except OSError:
                pass
            kill_strays(job.tmpdir)
        return 1

    passed = [j for j in done if j.status == "Passed"]
    skipped = [j for j in done if j.status == "Skipped"]
    failed = [j for j in done if j.status not in ("Passed", "Skipped")]
    complete = len(done) == len(tests)
    successful = complete and not failed and (not skipped or args.allow_skips)
    print("\n" + "-" * 64)
    for j in sorted(done, key=lambda j: j.name):
        print(f"{j.name:<44} {j.status:<8} {j.duration:6.1f}s")
    print("-" * 64)
    print(f"{'SUCCESS' if successful else 'FAILED'}: {len(passed)} passed, {len(skipped)} skipped, "
          f"{len(failed)} failed; {len(done)}/{len(tests)} completed in {time.monotonic() - started:.0f}s")
    if skipped:
        print("skips explicitly allowed for this local run" if args.allow_skips else
              "skips are not passes: every selected CI scenario must execute and pass")
    if not args.tmpdir and successful:
        shutil.rmtree(tmproot, ignore_errors=True)
    elif not successful:
        print(f"logs: {tmproot}")
    return 0 if successful else 1


if __name__ == "__main__":
    sys.exit(main())
