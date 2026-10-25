#!/usr/bin/env python3
"""gettxoutsetinfo: the UTXO set against the issuance (audit VAL-11).

* On the cached chain (genesis ledger + mined blocks) the set holds no
  more than the genesis ledger (carryover + locked team and founder
  allocations) + the subsidy of every connected block, there is one undo
  record per chain position, and the scan agrees with the aggregates the
  node maintains.
* A payment and the block that confirms it (its coinbase claims subsidy +
  fee) leave the unclaimed amount unchanged: fees are not issuance.
* A block whose coinbase claims 1,234 sat less than allowed raises the
  unclaimed amount by exactly that.
* Two synced nodes report the same count, total and hash; a restart changes
  nothing.
"""

from test_framework.messages import address_to_script_pubkey, block_from_template, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_true

PAYEE = hash_to_address(bytes(range(90, 110)))
MINER = hash_to_address(bytes(range(110, 130)))


class GetTxOutSetInfoTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def audit(self, node) -> dict:
        info = node.gettxoutsetinfo()
        assert_true("error" not in info, f"node{node.index}: {info}")
        assert_true(info["ok"], f"node{node.index}: {info}")
        assert_true(info["supply_ok"] and info["chain_ok"] and info["aggregates"]["ok"], str(info))
        assert_equal(info["bestblock"], node.tip())
        assert_equal(info["height"], node.height())
        assert_equal(info["applied_blocks"], info["height"])
        assert_equal((info["undo_off_chain"], info["chain_without_undo"]), (0, 0))
        assert_equal(info["undecodable_txouts"], 0)
        exp = info["expected"]
        issued = int(exp["carryover_sat"]) + int(exp["locked_sat"]) + int(exp["subsidy_sat"])
        assert_equal(int(exp["max_supply_sat"]), issued)
        assert_equal(int(info["total_amount_sat"]) + int(info["unclaimed_sat"]), issued)
        assert_true(int(exp["subsidy_sat"]) <= int(exp["schedule_issued_sat"]), str(exp))
        return info

    @staticmethod
    def same_set(a: dict, b: dict) -> None:
        for k in ("bestblock", "height", "txouts", "total_amount_sat", "hash_serialized", "unclaimed_sat"):
            assert_equal(a[k], b[k], k)

    def run_test(self):
        n0, n1 = self.nodes

        self.log.info("the cached chain: the set is within the issuance and agrees with the aggregates")
        start = self.audit(n0)
        self.same_set(start, self.audit(n1))
        assert_true(start["txouts"] > 0 and int(start["expected"]["carryover_sat"]) > 0, str(start))
        # 2 x 1,250,000 GNB in 72 timelocked tranches (core::vesting).
        assert_equal(int(start["expected"]["locked_sat"]), 2 * 100_000 * 10**8)

        self.log.info("a payment and its block: fees move value, unclaimed is unchanged")
        n1.cli_send(self.wallet_copy(), PAYEE, "3")
        self.sync_mempools()
        n0.generate(1, MINER)
        self.sync_blocks()
        paid = self.audit(n0)
        assert_equal(paid["unclaimed_sat"], start["unclaimed_sat"])
        assert_equal(int(paid["expected"]["subsidy_sat"]) - int(start["expected"]["subsidy_sat"]),
                     int(paid["total_amount_sat"]) - int(start["total_amount_sat"]))
        assert_true(paid["hash_serialized"] != start["hash_serialized"])
        self.same_set(paid, self.audit(n1))

        self.log.info("an under-claiming coinbase: unclaimed grows by exactly the shortfall")
        tmpl = n0.fresh_template()
        allowed = int(tmpl["subsidy_sat"]) + int(tmpl["total_fees"])
        block = block_from_template(tmpl, address_to_script_pubkey(MINER), coinbase_value=allowed - 1234)
        h = n0.submit_block(block)
        self.sync_blocks()
        assert_equal(n1.tip(), h)
        short = self.audit(n0)
        assert_equal(int(short["unclaimed_sat"]) - int(paid["unclaimed_sat"]), 1234)
        self.same_set(short, self.audit(n1))

        self.log.info("a restart changes nothing")
        n1.restart(peers=[n0.p2p_addr])
        self.same_set(short, self.audit(n1))


if __name__ == "__main__":
    GetTxOutSetInfoTest().main()
