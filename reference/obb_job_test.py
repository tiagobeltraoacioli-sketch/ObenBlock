"""Recompute reference/obb_job_vectors.json (produced by the node,
node/tests/obb_sha256d_mining.rs) from the job fields alone, as a pool does
(reference/obb_job.py), and check the reference against its own invariants."""

import json
import os
import unittest

import gnb_difficulty as d
import obb_job as j
import obb_pow

HERE = os.path.dirname(os.path.abspath(__file__))


class ObbJobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "obb_job_vectors.json")) as f:
            cls.v = json.load(f)

    def test_constants(self):
        self.assertEqual(self.v["extranonce_bytes"], j.EXTRANONCE_LEN)
        self.assertEqual(self.v["bip320_mask"], obb_pow.BIP320_VERSION_MASK)
        self.assertEqual(bytes.fromhex(self.v["coinbase_tag"]), b"/obb/")

    def test_branch_fold_equals_the_whole_tree(self):
        for n in range(1, 12):
            ids = [bytes([i]) * 32 for i in range(n)]
            cur = j.leaf(ids[0])
            for s in j.coinbase_merkle_branch(ids):
                cur = j.node(cur, s)
            self.assertEqual(cur, j.tagged_merkle_root(ids), n)

    def test_vectors(self):
        self.assertEqual(len(self.v["cases"]), 3)
        for c in self.v["cases"]:
            job, exp = c["job"], c["expect"]
            parents = [bytes.fromhex(p) for p in c["parents"]]
            self.assertIsNone(obb_pow.check_parents(parents), c["name"])
            en = bytes.fromhex(job["extranonce"])
            coinb1 = bytes.fromhex(job["coinb1"])
            # The extranonce sits at the end of the coinbase script_sig, after
            # the 80-byte commitment and the tag.
            self.assertTrue(coinb1.endswith(bytes.fromhex(self.v["coinbase_tag"])), c["name"])
            txid = j.coinbase_txid(coinb1, en, bytes.fromhex(job["coinb2"]))
            self.assertEqual(txid.hex(), exp["coinbase_txid"], c["name"])
            # The branch is the tree's over [coinbase] + txids.
            ids = [txid] + [bytes.fromhex(t) for t in c["txids"]]
            self.assertEqual([b.hex() for b in j.coinbase_merkle_branch(ids)], job["coinbase_merkle_branch"])
            self.assertEqual(bytes.fromhex(job["shielded_root"]), j.empty_shielded_root())
            h = j.job_header(job, parents, en, job["version"], job["time"], 0)
            self.assertEqual(h[36:68].hex(), exp["merkle_root"], c["name"])
            self.assertEqual(h.hex(), exp["header"], c["name"])
            self.assertEqual(obb_pow.sha256d(h).hex(), exp["block_id"], c["name"])
            target = d.bits_to_target(job["bits"])
            for s in c["shares"]:
                self.assertTrue(obb_pow.version_ok(s["version"]), s)
                h = j.job_header(job, parents, en, s["version"], s["time"], s["nonce"])
                self.assertEqual(h.hex(), s["header"])
                bid = obb_pow.sha256d(h)
                self.assertEqual(bid.hex(), s["block_id"])
                self.assertEqual(obb_pow.meets_target(bid, target), s["meets_target"])
                self.assertEqual(obb_pow.verify_header(h), s["meets_target"])
            # Another extranonce gives another root (a pool's work units differ).
            other = j.job_header(job, parents, bytes(8) if en != bytes(8) else b"\x01" * 8, job["version"], job["time"], 0)
            self.assertNotEqual(other[36:68].hex(), exp["merkle_root"])


if __name__ == "__main__":
    unittest.main()
