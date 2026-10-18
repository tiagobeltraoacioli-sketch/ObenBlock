"""Independent checks of obb_pow.py against facts outside this repository
(Bitcoin's headers and chain work) and its own invariants."""

import unittest

import gnb_difficulty as d
import obb_pow as o


class ObbPowTest(unittest.TestCase):
    def test_bitcoin_genesis(self):
        h = o.pow_header(1, bytes(32),
                         bytes.fromhex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")[::-1],
                         1231006505, 0x1D00FFFF, 2083236893)
        self.assertEqual(len(h), 80)
        self.assertEqual(o.sha256d(h)[::-1].hex(),
                         "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        self.assertTrue(o.verify_header(h))

    def test_bitcoin_block_1(self):
        prev = bytes.fromhex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")[::-1]
        h = o.pow_header(1, prev,
                         bytes.fromhex("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098")[::-1],
                         1231469665, 0x1D00FFFF, 2573394689)
        self.assertEqual(o.sha256d(h)[::-1].hex(),
                         "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048")

    def test_work_is_bitcoin_core(self):
        self.assertEqual(o.work_from_bits(0x1D00FFFF), 0x100010001)
        self.assertEqual(o.work(0), 0)
        self.assertEqual(o.work((1 << 256) - 1), 1)
        self.assertEqual(o.work(1), o.U128_MAX)

    def test_comparison_inclusive(self):
        t = d.bits_to_target(0x1D00FFFF)
        self.assertTrue(o.meets_target(t.to_bytes(32, "little"), t))
        self.assertFalse(o.meets_target((t + 1).to_bytes(32, "little"), t))

    def test_launch(self):
        self.assertEqual(o.LAUNCH_BITS, 0x19009D69)
        t = o.target_for_hashes(o.LAUNCH_HASHRATE_HPS, 30)
        self.assertGreaterEqual(o.work(t), 3 * 10 ** 19)
        self.assertLess(o.work(t + 1), 3 * 10 ** 19)

    def test_versions(self):
        self.assertTrue(o.version_ok(0x3FFFE000))
        self.assertFalse(o.version_ok(0x20001000))
        self.assertFalse(o.version_ok(0x60000000))

    def test_slow_start_withheld(self):
        full = 107_020_547
        withheld = sum(full - o.slow_start_subsidy(full, h) for h in range(1, o.SLOW_START_BLOCKS))
        self.assertEqual(withheld // 10 ** 8, 3_081)


if __name__ == "__main__":
    unittest.main()
