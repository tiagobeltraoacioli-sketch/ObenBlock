"""Contract tests for the independent public descriptor reference.

The initial test-only commit is not a runtime reproduction of a missing product
feature. Product reproduction is recorded separately by the core package.
"""
import hashlib
import json
import unittest

import descriptor as d


def key(index=0):
    return hashlib.shake_256(b"gnb-descriptor-public-fixture-v1" + index.to_bytes(4, "little")).digest(3745).hex()


def body(network="mainnet", expression=None):
    return f"gnbd1({network},{expression or 'pkh(' + key() + ')'})"


def create(network="mainnet", expression=None):
    return d.public_request({"action": "create", "network": network, "body": body(network, expression)})


class DescriptorTests(unittest.TestCase):
    def test_bip380_primary_checksum_vector(self):
        self.assertEqual(d.add_checksum("raw(deadbeef)"), "raw(deadbeef)#89f8spxm")
        self.assertEqual(d.check_checksum("raw(deadbeef)#89f8spxm"), "raw(deadbeef)")
        for text in ("raw(deadbeef)", "raw(deadbeef)#", "raw(deadbeef)#89f8spxmx", "raw(deadbeef)#89f8spx", "raw(deedbeef)#89f8spxm", "raw(deedbeef)##9f8spxm", "raw(Ü)#00000000"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                d.check_checksum(text)

    def test_both_networks_all_three_kinds(self):
        policy = f"policy(2,17,9,{key()},{key(1)})"
        expressions = [f"pkh({key()})", policy, f"tree({policy},policy(1,0,0,{key(2)}))"]
        for network in ("mainnet", "testnet"):
            for expression, kind in zip(expressions, ("pkh", "policy", "tree")):
                info = create(network, expression)
                self.assertEqual(info["kind"], kind)
                self.assertEqual(info["network"], network)
                self.assertEqual(info["requires_policy_tree_activation"], kind == "tree")
                self.assertEqual(d.public_request({"action": "inspect", "network": network, "descriptor": info["descriptor"]}), info)

    def test_key_bytes_are_not_normalized(self):
        raw, wrapped = create(), create(expression=f"pkh(b10c0100{key()})")
        self.assertEqual(raw["script_pubkey"], hashlib.sha3_256(bytes.fromhex(key())).digest()[:20].hex())
        self.assertNotEqual(raw["script_pubkey"], wrapped["script_pubkey"])
        # PF-4: a raw key and its envelope are one signer (key identity =
        # the enveloped encoding), so one policy or branch may not list both.
        for twin in (f"policy(2,0,0,{key()},b10c0100{key()})", f"policy(1,0,0,b10c0100{key()},{key()})",
                     f"tree(policy(1,0,0,{key(1)}),policy(2,0,0,{key()},b10c0100{key()}))"):
            with self.assertRaises(d.DescriptorError):
                create(expression=twin)
            # An existing descriptor (an earlier release created it) is still
            # inspected and restored, flagged; the flag is absent otherwise.
            text = d.add_checksum(f"gnbd1(mainnet,{twin})")
            info = d.public_request({"action": "inspect", "network": "mainnet", "descriptor": text})
            self.assertIs(info["twin_key_encodings"], True)
            pool = d.public_request({"action": "export", "network": "mainnet", "descriptors": [text]})
            self.assertIs(pool["entries"][0]["twin_key_encodings"], True)
        self.assertNotIn("twin_key_encodings", create(expression=f"policy(2,0,0,{key()},{key(1)})"))
        # Distinct keys in either encoding are fine.
        create(expression=f"policy(2,0,0,{key()},b10c0100{key(1)})")
        magic_raw = "b10cffff" + key()[8:]
        create(expression=f"pkh({magic_raw})")

    def test_policy_encoding_and_order(self):
        keys = [bytes.fromhex(key(i)) for i in range(2)]
        encoded = b"\x01\x02\x02" + b"".join(len(k).to_bytes(4, "little") + k for k in keys) + (17).to_bytes(4, "little") + (9).to_bytes(4, "little")
        expected = b"\x02" + hashlib.sha3_256(b"GNB-POLICY-v1" + encoded).digest()
        first = create(expression=f"policy(2,17,9,{key()},{key(1)})")
        self.assertEqual(first["script_pubkey"], expected.hex())
        self.assertNotEqual(first["script_pubkey"], create(expression=f"policy(2,17,9,{key(1)},{key()})")["script_pubkey"])

    def test_tree_three_branch_padding_and_order(self):
        # Build the binary commitment directly, independently of parser state.
        encoded = []
        for index in range(3):
            raw = bytes.fromhex(key(index))
            encoded.append(b"\x01\x01\x01" + len(raw).to_bytes(4, "little") + raw + index.to_bytes(4, "little") + b"\0" * 4)
        sha = lambda raw: hashlib.sha3_256(raw).digest()
        leaves = [sha(b"GNB-POLICY-v2/leaf" + raw) for raw in encoded]
        leaves.append(sha(b"GNB-POLICY-v2/empty"))
        left = sha(b"GNB-POLICY-v2/node" + leaves[0] + leaves[1])
        right = sha(b"GNB-POLICY-v2/node" + leaves[2] + leaves[3])
        root = sha(b"GNB-POLICY-v2/node" + left + right)
        expected = b"\x02" + sha(b"GNB-POLICY-v1\x02\x03" + root)
        branches = [f"policy(1,{i},0,{key(i)})" for i in range(3)]
        info = create(expression="tree(" + ",".join(branches) + ")")
        self.assertEqual(info["script_pubkey"], expected.hex())
        swapped = create(expression="tree(" + ",".join(reversed(branches)) + ")")
        self.assertNotEqual(info["script_pubkey"], swapped["script_pubkey"])

    def test_pool_roundtrip_canonical_order_and_network(self):
        entries = [create(), create(expression=f"policy(1,0,0,{key(1)})")]
        request = {"action": "export", "network": "mainnet", "descriptors": [e["descriptor"] for e in entries]}
        result = d.public_request(request)
        self.assertEqual(result["entries"], entries)
        self.assertEqual(result["count"], 2)
        self.assertTrue(result["bundle"].startswith('{"format":"gnb-watch-only-v1","network":"mainnet","descriptors":['))
        self.assertEqual(result, d.public_request({"action": "import", "network": "mainnet", "bundle": result["bundle"]}))
        with self.assertRaises(ValueError):
            d.public_request({"action": "import", "network": "testnet", "bundle": result["bundle"]})

    def test_pool_limits_and_duplicate_identity(self):
        pool = d.public_request({"action": "pool", "network": "mainnet", "public_keys": [key(i) for i in range(64)]})
        self.assertEqual(pool["count"], 64)
        for keys in ([], [key()] * 2, [key(i) for i in range(65)]):
            with self.assertRaises(ValueError):
                d.public_request({"action": "pool", "network": "mainnet", "public_keys": keys})
        with self.assertRaises(ValueError):
            d.public_request({"action": "import", "network": "mainnet", "bundle": " " * (d.MAX_POOL_BYTES + 1)})

    def test_pool_json_strictness(self):
        bundle = d.public_request({"action": "pool", "network": "mainnet", "public_keys": [key()]})["bundle"]
        malformed = [bundle + "x", bundle[:-1] + ',"format":"gnb-watch-only-v1"}', bundle[:-1] + ',"unknown":1}', bundle.replace('"gnb-watch-only-v1"', '"v2"'), bundle.replace('"network":"mainnet"', '"network":null')]
        for text in malformed:
            with self.subTest(case=text[:100]), self.assertRaises(ValueError):
                d.public_request({"action": "import", "network": "mainnet", "bundle": text})

    def test_pool_byte_limit_includes_whitespace(self):
        original = d.public_request({"action": "pool", "network": "mainnet", "public_keys": [key()]})
        exact = original["bundle"] + " " * (d.MAX_POOL_BYTES - len(original["bundle"].encode("utf-8")))
        self.assertEqual(len(exact.encode("utf-8")), d.MAX_POOL_BYTES)
        self.assertEqual(d.public_request({"action": "import", "network": "mainnet", "bundle": exact}), original)
        with self.assertRaises(ValueError):
            d.public_request({"action": "import", "network": "mainnet", "bundle": exact + " "})

    def test_grammar_and_key_boundaries(self):
        invalid = [body().upper(), body() + " ", body().replace("pkh(", "pkh( "), body(expression="pkh(00)"), body(expression=f"pkh(b10c0200{key()})"), body(expression=f"pkh({key()}/0)"), body(expression=f"pkh({key()}*)"), body(expression=f"policy(01,0,0,{key()})"), body(expression=f"policy(0,0,0,{key()})"), body(expression=f"policy(2,0,0,{key()})"), body(expression=f"policy(1,4294967296,0,{key()})"), body(expression=f"policy(1,0,0,{key()},{key()})"), body(expression=f"tree(policy(1,0,0,{key()}))"), "a" * d.MAX_DESCRIPTOR_BYTES]
        for value in invalid:
            with self.subTest(case=value[:80]), self.assertRaises(ValueError):
                d.public_request({"action": "create", "network": "mainnet", "body": value})
        create(expression=f"policy(7,4294967295,4294967295,{','.join(key(i) for i in range(7))})")

    def test_request_contract(self):
        valid = {"action": "create", "network": "mainnet", "body": body()}
        self.assertEqual(d.public_request(valid), d.public_request({**valid, "op": "descriptor"}))
        for request in ([], None, {}, {**valid, "op": "wipe"}, {**valid, "extra": 0}, {**valid, "body": None}, {**valid, "network": "testnet"}, {**valid, "network": False}):
            with self.subTest(request=str(request)[:80]), self.assertRaises(ValueError):
                d.public_request(request)

    def test_json_lines_reject_duplicate_fields(self):
        result = d.oracle_line('{"network":"mainnet","network":"testnet","action":"pool","public_keys":[]}')
        self.assertEqual(result, {"ok": False})

    def test_generated_campaign_is_seeded_and_verdicts_are_by_construction(self):
        import descriptor_generated as generated
        rows = list(generated.cases(24))
        self.assertEqual(rows, list(generated.cases(24)))
        self.assertNotEqual(rows, list(generated.cases(24, seed=generated.DEFAULT_SEED + 1)))
        self.assertEqual(len(rows), 24)
        for name, line, accepted in rows:
            with self.subTest(name=name):
                self.assertEqual(d.oracle_line(line)["ok"], accepted)


if __name__ == "__main__":
    unittest.main()
