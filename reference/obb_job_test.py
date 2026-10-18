"""Recompute reference/obb_job_vectors.json (produced by the node,
node/tests/obb_sha256d_mining.rs) from the job fields alone, as a pool does
(reference/obb_job.py), and as unmodified Stratum V1 firmware does from the
`mining.notify` fields alone."""

import json
import os
import unittest

import gnb_difficulty as d
import obb_job as j
import obb_merkle as om
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
        self.assertEqual(self.v["merkle_root_rule"], j.MERKLE_RULE)

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
            # The branch is Bitcoin's over [coinbase] + txids, and the header
            # root is Bitcoin's root of the block's txids.
            ids = [txid] + [bytes.fromhex(t) for t in c["txids"]]
            self.assertEqual([b.hex() for b in om.merkle_branch(ids)], job["merkle_branch"])
            root, mutated = om.bitcoin_merkle_root(ids)
            self.assertFalse(mutated)
            self.assertEqual(root.hex(), exp["merkle_root"], c["name"])
            h = j.job_header(job, parents, en, job["version"], job["time"], 0)
            self.assertEqual(h[36:68].hex(), exp["merkle_root"], c["name"])
            self.assertEqual(h.hex(), exp["header"], c["name"])
            self.assertEqual(obb_pow.sha256d(h).hex(), exp["block_id"], c["name"])
            # Stock firmware from mining.notify alone, with the pool's split
            # of the extranonce, builds the same header.
            n = c["stratum"]
            self.assertEqual(n["prevhash"], om.stratum_prevhash(obb_pow.parents_commitment(parents)))
            self.assertLessEqual(n["ntime_min"], job["time"])
            self.assertLessEqual(job["time"], n["ntime_max"])
            fw = j.stock_firmware_header(n, en[:4], en[4:], int(n["ntime"], 16), 0)
            self.assertEqual(fw.hex(), exp["header"], c["name"])
            target = d.bits_to_target(job["bits"])
            for s in c["shares"]:
                self.assertTrue(obb_pow.version_ok(s["version"]), s)
                h = j.job_header(job, parents, en, s["version"], s["time"], s["nonce"])
                self.assertEqual(h.hex(), s["header"])
                fw = j.stock_firmware_header(n, en[:4], en[4:], s["time"], s["nonce"],
                                             s["version"] & obb_pow.BIP320_VERSION_MASK)
                self.assertEqual(fw, h)
                bid = obb_pow.sha256d(h)
                self.assertEqual(bid.hex(), s["block_id"])
                self.assertEqual(obb_pow.meets_target(bid, target), s["meets_target"])
                self.assertEqual(obb_pow.verify_header(h), s["meets_target"])
            # Another extranonce gives another root (a pool's work units differ).
            other = j.job_header(job, parents, bytes(8) if en != bytes(8) else b"\x01" * 8, job["version"], job["time"], 0)
            self.assertNotEqual(other[36:68].hex(), exp["merkle_root"])


if __name__ == "__main__":
    unittest.main()
