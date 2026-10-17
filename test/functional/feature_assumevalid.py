#!/usr/bin/env python3
"""The assumed-valid block option (P5-G, Bitcoin Core's -assumevalid).

* `--assumevalid` takes 0 or a block id of exactly 64 hex digits; anything
  else is refused at start-up with exit code 2, before the node serves RPC.
* With a block id the node starts, logs the setting (Core: "Assuming
  ancestors of block ... have valid signatures"), and syncs and serves blocks
  as before: on a chain without that block nothing is skipped and every
  block is accepted the same way.
* `--assumevalid 0` and testnet's default (no release value) log that every
  signature is checked.
"""

import os
import shutil

from test_framework.cache import copy_datadir
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_true, wait_until

BLOCK_ID = "ab" * 32


class AssumeValidTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        pass  # the refusals run first; the nodes are started in run_test

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("a malformed --assumevalid is refused with exit code 2")
        for bad in ["1", "ab" * 31, "zz" * 32, "none"]:
            node0.assert_start_fails(["--assumevalid", bad], "--assumevalid", code=2)

        self.log.info("testnet has no release value: every signature is checked")
        node0.start()
        assert_true(node0.log_contains("assumed-valid block: none for this network"), "default logged")
        height = node0.getblockcount()

        self.log.info("a block id is accepted and logged; a fresh node syncs node0's chain as before")
        # node1 starts from the genesis-only state, not the cached chain.
        shutil.rmtree(os.path.join(node1.datadir, "db"))
        copy_datadir(self.cache.base_dir(self.ports), node1.datadir)
        node1.start(["--assumevalid", BLOCK_ID], peers=[node0.p2p_addr])
        assert_true(node1.getblockcount() < height, "node1 starts behind")
        assert_true(node1.log_contains(f"assumed-valid block {BLOCK_ID}"), "the setting is logged")
        assert_true(node1.log_contains("--assumevalid"), "and where it came from")
        wait_until(lambda: node1.getblockcount() == height, timeout=60, desc="node1 syncs node0's chain")
        assert_equal(node1.getdaginfo()["tip"], node0.getdaginfo()["tip"])

        self.log.info("--assumevalid 0 turns it off")
        node1.restart(["--assumevalid", "0"])
        assert_true(node1.log_contains("assumed-valid block: off (--assumevalid=0)"), "off logged")
        assert_equal(node1.getblockcount(), height)


if __name__ == "__main__":
    AssumeValidTest().main()
