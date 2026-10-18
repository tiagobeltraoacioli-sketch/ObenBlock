"""Contract tests for the ObenBlock address-family reference (obb_address.py)."""
import unittest

import obb_address as o
import obb_address_vectors as v

ZERO20 = bytes(20)
ZERO32 = bytes(32)


class ObbAddressTests(unittest.TestCase):
    def test_gnb_goldens_are_unchanged(self):
        # The GnB strings pinned in crates/gnb-crypto/tests/address_v2.rs.
        self.assertEqual(o.key_string("gnb", "mainnet", ZERO20),
                         "gnb1q0000000000000000000000000000000000000000335d2ee7")
        self.assertEqual(o.policy_string("gnb", "mainnet", ZERO32),
                         "gnb1m000000000000000000000000000000000000000000000000000000000000000073aa6055")
        self.assertEqual(o.v2_string("gnb", "mainnet", "single-key", ZERO20),
                         "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw")

    def test_obb_single_key_differs_only_in_prefix(self):
        gnb = o.key_string("gnb", "mainnet", ZERO20)
        self.assertEqual(o.key_string("obenblock", "mainnet", ZERO20), "obb1q" + gnb[5:])
        self.assertEqual(o.normalize(gnb, "obenblock"), "obb1q" + gnb[5:])
        self.assertEqual(o.normalize("bloch1q" + gnb[5:], "obenblock"), "obb1q" + gnb[5:])

    def test_policy_checksum_binds_the_family_prefix(self):
        gnb = o.policy_string("gnb", "mainnet", ZERO32)
        obb = o.policy_string("obenblock", "mainnet", ZERO32)
        self.assertNotEqual(gnb[-8:], obb[-8:])
        self.assertEqual(o.normalize(gnb, "obenblock"), obb)
        with self.assertRaises(o.AddressError):
            o.decode("obb1m" + gnb[5:], "obenblock")

    def test_gnb_family_refuses_obb_strings(self):
        for s in (o.key_string("obenblock", "mainnet", ZERO20),
                  o.v2_string("obenblock", "testnet", "policy", ZERO32)):
            with self.assertRaises((o.AddressError, o.v2.AddressError)):
                o.decode(s, "gnb")
            self.assertEqual(o.normalize(s, "gnb"), s)

    def test_vector_file_is_current(self):
        with open(v.VECTOR_FILE, "rb") as f:
            self.assertEqual(f.read(), v.serialized())


if __name__ == "__main__":
    unittest.main()
