"""Independent checks of obb_shares.py: the share header is Bitcoin's layout,
the share target and work, the per-job custody binding, the order of the
checks, and the 112-epoch window."""

import hashlib
import unittest

import gnb_difficulty as d
import obb_pow as o
import obb_shares as s
import powit_reference as pr


def share(attested: dict, **kw) -> dict:
    base = {"attested": attested["id"], "witness": b"\x09" * 20, "payout": b"pay", "bits": attested["bits"],
            "job_nonce": 7, "version": o.BLOCK_VERSION, "time": attested["timestamp"], "nonce": 0}
    base.update(kw)
    return base


ATTESTED = {"id": b"\x05" * 32, "bits": s.EASY_BITS, "timestamp": 1_800_000_123, "stream": bytes(range(256)) * 3}


class ShareTest(unittest.TestCase):
    def test_header_is_bitcoin_layout(self):
        h = s.share_header(0x2000_0000, b"\x01" * 32, b"\x02" * 32, 3, 0x1D00FFFF, 4)
        self.assertEqual(len(h), 80)
        self.assertEqual(h[4:36], b"\x01" * 32)        # hashPrevBlock position
        self.assertEqual(h[36:68], b"\x02" * 32)       # hashMerkleRoot position
        self.assertEqual(h[72:76], (0x1D00FFFF).to_bytes(4, "little"))

    def test_sha256d_is_double_sha256(self):
        self.assertEqual(s.sha256d(b"abc"), hashlib.sha256(hashlib.sha256(b"abc").digest()).digest())

    def test_share_target_and_work(self):
        t = d.bits_to_target(s.EASY_BITS)
        self.assertEqual(t, 1 << 248)
        self.assertEqual(s.share_target(t), 1 << 252)
        self.assertEqual(o.work(s.share_target(t)), 15)
        self.assertEqual(s.share_target(d.bits_to_target(o.REGTEST_POW_LIMIT_BITS)), s.MAX_TARGET)
        # On mainnet bits the share work is the block work over 16, rounded.
        bw = o.work_from_bits(o.POW_LIMIT_BITS)
        sw = o.work(s.share_target(d.bits_to_target(o.POW_LIMIT_BITS)))
        self.assertTrue(bw // 16 - 1 <= sw <= bw // 16 + 1)

    def test_indices_in_range_and_cover(self):
        seen = set()
        for jn in range(200):
            idx = s.sample_indices(b"\x01" * 32, b"p", jn, 37)
            self.assertTrue(all(0 <= i < 37 for i in idx))
            seen.update(idx)
        self.assertEqual(seen, set(range(37)))
        self.assertEqual(s.n_chunks(b""), 1)
        self.assertEqual(s.n_chunks(b"x" * 64), 1)
        self.assertEqual(s.n_chunks(b"x" * 65), 2)
        self.assertEqual(s.chunk(b"x" * 65, 1), b"x" + bytes(63))

    def test_mined_share_and_custody(self):
        good = s.grind(share(ATTESTED), ATTESTED)
        verdict, w = s.verify(good, ATTESTED)
        self.assertIsNone(verdict)
        self.assertEqual(w, 15)
        # Different block data under the same id: the job changes.
        other = dict(ATTESTED, stream=bytes(len(ATTESTED["stream"])))
        self.assertNotEqual(s.header_of(good, ATTESTED["stream"]), s.header_of(good, other["stream"]))

    def test_check_order(self):
        good = s.grind(share(ATTESTED), ATTESTED)
        self.assertEqual(s.verify(dict(good, payout=b"x" * 129, version=None), ATTESTED)[0], "PayoutTooLong")
        self.assertEqual(s.verify(dict(good, version=None, attested=bytes(32)), ATTESTED)[0], "WrongScheme")
        self.assertEqual(s.verify(dict(good, attested=bytes(32), bits=1), ATTESTED)[0], "WrongAttestedBlock")
        self.assertEqual(s.verify(dict(good, bits=1, version=1), ATTESTED)[0], "WrongBits")
        self.assertEqual(s.verify(dict(good, version=1, time=0), ATTESTED)[0], "Version")
        self.assertEqual(s.verify(dict(good, time=0), ATTESTED)[0], "WrongTime")
        rolled = s.grind(dict(good, version=o.BLOCK_VERSION | (0xABCD << 13)), ATTESTED)
        self.assertIsNone(s.verify(rolled, ATTESTED)[0])

    def test_id_and_wire(self):
        good = share(ATTESTED)
        self.assertEqual(len(s.wire(good)), 32 + 20 + 1 + 3 + 4 + 8 + 12)
        ids = {s.share_id(dict(good, **{k: v})) for k, v in
               (("nonce", 1), ("time", 1), ("version", 1), ("job_nonce", 1), ("bits", 1), ("payout", b"q"),
                ("witness", bytes(20)), ("attested", bytes(32)))}
        ids.add(s.share_id(good))
        self.assertEqual(len(ids), 9)


class WindowTest(unittest.TestCase):
    def test_112_epochs_is_28_days(self):
        p = s.OBB_PARAMS
        self.assertEqual(p["window_epochs"] * p["epoch_len"] * 30, 28 * 24 * 3600)
        self.assertEqual(p["ban_epochs"], p["window_epochs"])

    def test_epoch_zero_work_lifetime(self):
        k = pr.key("t", 0)
        st = {"epoch_work": {0: {k: 5}}, "banned": {}, "decay": {}}
        live = [e for e in range(200) if pr.witness_set(st, s.OBB_PARAMS, e, pr.H2)]
        self.assertEqual(live, list(range(2, 114)))
        live_gnb = [e for e in range(200) if pr.witness_set(st, pr.PARAMS["mainnet"], e, pr.H2)]
        self.assertEqual(live_gnb, list(range(2, 30)))


if __name__ == "__main__":
    unittest.main()
