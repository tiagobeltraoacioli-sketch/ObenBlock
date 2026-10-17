"""Independent stdlib-only GnB static public descriptor and pool reference.

Specification: docs/DESCRIPTORS.md and the frozen round-5 contract. Sources
for existing script identities are the pre-R5 policy/key/address formats.
No new Rust descriptor implementation was read to write this reference.
This module contains no key derivation, signing, network I/O or wallet state.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys

import address_v2

MAX_DESCRIPTOR_BYTES = 262_144
MAX_POOL_BYTES = 1_048_576
MAX_POOL_ENTRIES = 64
RAW_KEY_BYTES = 3745
NETWORKS = ("mainnet", "testnet")
POOL_FORMAT = "gnb-watch-only-v1"

# BIP380 primary specification, checksum only, not its Bitcoin key language:
# https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#checksum
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATORS = (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)


class DescriptorError(ValueError):
    """Public input fails the descriptor, network or pool contract."""


def _sha3(data):
    return hashlib.sha3_256(data).digest()


def _checksum_symbols(text):
    group = []
    for char in text:
        try:
            value = INPUT_CHARSET.index(char)
        except ValueError as exc:
            raise DescriptorError("checksum alphabet") from exc
        yield value & 31
        group.append(value >> 5)
        if len(group) == 3:
            yield group[0] * 9 + group[1] * 3 + group[2]
            group.clear()
    if group:
        yield group[0] if len(group) == 1 else group[0] * 3 + group[1]


def _polymod(symbols):
    register = 1
    for symbol in symbols:
        high = register >> 35
        register = ((register & 0x7FFFFFFFF) << 5) ^ symbol
        for bit, generator in enumerate(GENERATORS):
            if high & (1 << bit):
                register ^= generator
    return register


def _ascii(text, limit):
    if not isinstance(text, str) or len(text) > limit or not text.isascii():
        raise DescriptorError("ASCII text or length")
    return text


def add_checksum(body):
    """Add the BIP380 checksum; grammar validation belongs to create()."""
    _ascii(body, MAX_DESCRIPTOR_BYTES - 9)
    if "#" in body:
        raise DescriptorError("extra checksum delimiter")
    remainder = _polymod([*_checksum_symbols(body), *([0] * 8)]) ^ 1
    return body + "#" + "".join(CHECKSUM_CHARSET[(remainder >> shift) & 31] for shift in range(35, -1, -5))


def check_checksum(descriptor):
    _ascii(descriptor, MAX_DESCRIPTOR_BYTES)
    if descriptor.count("#") != 1 or len(descriptor) < 9 or descriptor[-9] != "#":
        raise DescriptorError("checksum delimiter or length")
    body, suffix = descriptor[:-9], descriptor[-8:]
    if any(char not in CHECKSUM_CHARSET for char in suffix):
        raise DescriptorError("checksum alphabet")
    if _polymod([*_checksum_symbols(body), *[CHECKSUM_CHARSET.index(char) for char in suffix]]) != 1:
        raise DescriptorError("checksum mismatch")
    return body


def public_key(text):
    if not isinstance(text, str) or len(text) not in (RAW_KEY_BYTES * 2, (RAW_KEY_BYTES + 4) * 2):
        raise DescriptorError("public key length")
    if re.fullmatch("[0-9a-f]+", text) is None:
        raise DescriptorError("lowercase public key hex required")
    raw = bytes.fromhex(text)
    # Existing predicate is a shape check, not verification. Exact raw length
    # takes priority, even when the raw bytes start with envelope magic.
    if len(raw) != RAW_KEY_BYTES and raw[:4] != bytes.fromhex("b10c0100"):
        raise DescriptorError("unsupported hybrid public key envelope")
    return raw


def key_identity(raw):
    """PF-4: the identity of a policy key is its enveloped encoding.

    A raw hybrid key (3,745 bytes) and its envelope ``b10c0100 || raw`` are
    one signer (sighash v3 verifies a signature under either encoding), so a
    policy may not list both (docs/CONSENSUS.md, "Spend-policy key identity
    (PF-4)"). Exact raw length takes priority, as in public_key().
    """
    return bytes.fromhex("b10c0100") + raw if len(raw) == RAW_KEY_BYTES else raw


class _Parser:
    """Fixed-depth grammar: one expression, with only policy leaves in trees.

    ``strict`` (create) refuses a policy or branch listing one key in its raw
    and enveloped encodings (PF-4); otherwise (inspect, export, import: an
    existing descriptor is restored) it is accepted and ``twin`` is set.
    """

    def __init__(self, text, strict=True):
        self.text, self.offset, self.strict, self.twin = text, 0, strict, False

    def literal(self, value):
        if not self.text.startswith(value, self.offset):
            raise DescriptorError("descriptor grammar")
        self.offset += len(value)

    def token(self):
        start = self.offset
        while self.offset < len(self.text) and self.text[self.offset] not in ",()":
            self.offset += 1
        return self.text[start:self.offset]

    def integer(self):
        text = self.token()
        if len(text) > 10 or re.fullmatch("0|[1-9][0-9]*", text) is None:
            raise DescriptorError("minimal unsigned decimal required")
        value = int(text)
        if value > 0xFFFFFFFF:
            raise DescriptorError("integer exceeds u32")
        return value

    def policy(self):
        self.literal("policy(")
        threshold = self.integer()
        self.literal(",")
        after = self.integer()
        self.literal(",")
        older = self.integer()
        keys = []
        while self.text.startswith(",", self.offset):
            if len(keys) == 7:
                raise DescriptorError("too many policy keys")
            self.literal(",")
            key = public_key(self.token())
            if key in keys:
                raise DescriptorError("duplicate serialized key")
            if key_identity(key) in (key_identity(k) for k in keys):
                if self.strict:
                    raise DescriptorError("one key in raw and enveloped encodings (PF-4)")
                self.twin = True
            keys.append(key)
        self.literal(")")
        if not 1 <= threshold <= len(keys):
            raise DescriptorError("threshold")
        return bytes([1, threshold, len(keys)]) + b"".join(len(key).to_bytes(4, "little") + key for key in keys) + after.to_bytes(4, "little") + older.to_bytes(4, "little")

    def expression(self):
        if self.text.startswith("pkh(", self.offset):
            self.literal("pkh(")
            key = public_key(self.token())
            self.literal(")")
            return "pkh", _sha3(key)[:20]
        if self.text.startswith("policy(", self.offset):
            return "policy", b"\x02" + _sha3(b"GNB-POLICY-v1" + self.policy())
        self.literal("tree(")
        branches = [self.policy()]
        while self.text.startswith(",", self.offset):
            if len(branches) == 4:
                raise DescriptorError("too many branches")
            self.literal(",")
            branches.append(self.policy())
        self.literal(")")
        if len(branches) < 2:
            raise DescriptorError("too few branches")
        leaves = [_sha3(b"GNB-POLICY-v2/leaf" + branch) for branch in branches]
        width = 2 if len(leaves) == 2 else 4
        leaves.extend([_sha3(b"GNB-POLICY-v2/empty")] * (width - len(leaves)))
        while len(leaves) > 1:
            leaves = [_sha3(b"GNB-POLICY-v2/node" + leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
        commitment = bytes([2, len(branches)]) + leaves[0]
        return "tree", b"\x02" + _sha3(b"GNB-POLICY-v1" + commitment)


def _network(network):
    if not isinstance(network, str) or network not in NETWORKS:
        raise DescriptorError("network")
    return network


def _info(body, expected_network, strict=True):
    _ascii(body, MAX_DESCRIPTOR_BYTES - 9)
    if body != body.lower() or any(char.isspace() for char in body):
        raise DescriptorError("noncanonical text")
    parser = _Parser(body, strict)
    parser.literal("gnbd1(")
    network = _network(parser.token())
    if network != expected_network:
        raise DescriptorError("wrong network")
    parser.literal(",")
    kind, script = parser.expression()
    parser.literal(")")
    if parser.offset != len(body):
        raise DescriptorError("trailing descriptor text")
    if kind == "pkh":
        payload, prefix, v2_kind = script, ("gnb1q" if network == "mainnet" else "gnb1t"), "single-key"
        checksum = _sha3(_sha3(payload))[:4]
    else:
        payload, prefix, v2_kind = script[1:], ("gnb1m" if network == "mainnet" else "gnb1n"), "policy"
        checksum = _sha3(_sha3(prefix.encode("ascii") + payload))[:4]
    info = {"descriptor": add_checksum(body), "network": network, "kind": kind, "script_pubkey": script.hex(), "address": prefix + (payload + checksum).hex(), "bech32m": address_v2.encode(network, v2_kind, payload), "requires_policy_tree_activation": kind == "tree"}
    # PF-4: only on a restored descriptor whose policy or a tree branch lists
    # one key twice (raw and enveloped); absent otherwise.
    if parser.twin:
        info["twin_key_encodings"] = True
    return info


def _strict_object(pairs):
    result = {}
    for field, value in pairs:
        if field in result:
            raise DescriptorError("duplicate JSON field")
        result[field] = value
    return result


def _invalid_constant(_value):
    raise DescriptorError("non-JSON constant")


def strict_json(text):
    return json.loads(text, object_pairs_hook=_strict_object, parse_constant=_invalid_constant)


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _pool(network, descriptors):
    if not isinstance(descriptors, list) or not 1 <= len(descriptors) <= MAX_POOL_ENTRIES:
        raise DescriptorError("pool entry count")
    entries = [_info(check_checksum(item), network, strict=False) for item in descriptors]
    if len({entry["script_pubkey"] for entry in entries}) != len(entries):
        raise DescriptorError("duplicate script identity")
    bundle = compact({"format": POOL_FORMAT, "network": network, "descriptors": [entry["descriptor"] for entry in entries]})
    if len(bundle.encode("utf-8")) > MAX_POOL_BYTES:
        raise DescriptorError("pool byte limit")
    return {"bundle": bundle, "count": len(entries), "entries": entries}


def public_request(request):
    if not isinstance(request, dict):
        raise DescriptorError("request object required")
    network = _network(request.get("network"))
    action = request.get("action")
    fields = {"create": "body", "inspect": "descriptor", "export": "descriptors", "import": "bundle", "pool": "public_keys"}
    if not isinstance(action, str) or action not in fields:
        raise DescriptorError("unknown action")
    field = fields[action]
    if set(request) - {"action", "network", "op", field} or field not in request:
        raise DescriptorError("unknown or missing request field")
    if "op" in request and request["op"] != "descriptor":
        raise DescriptorError("invalid public operation")
    value = request[field]
    if action == "create":
        return _info(value, network)
    if action == "inspect":
        return _info(check_checksum(value), network, strict=False)
    if action == "export":
        return _pool(network, value)
    if action == "pool":
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_POOL_ENTRIES:
            raise DescriptorError("public key count")
        descriptors = []
        for key in value:
            public_key(key)
            descriptors.append(add_checksum(f"gnbd1({network},pkh({key}))"))
        return _pool(network, descriptors)
    # Check encoded size before parsing. Surrogates have no valid UTF-8 form.
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_POOL_BYTES:
        raise DescriptorError("pool byte limit or type")
    bundle = strict_json(value)
    if not isinstance(bundle, dict) or set(bundle) != {"format", "network", "descriptors"}:
        raise DescriptorError("pool JSON schema")
    if bundle["format"] != POOL_FORMAT or bundle["network"] != network:
        raise DescriptorError("pool format or network")
    return _pool(network, bundle["descriptors"])


def oracle(request):
    try:
        return {"ok": True, "result": public_request(request)}
    except (ValueError, TypeError, OverflowError, RecursionError):
        return {"ok": False}


def oracle_line(line):
    try:
        return oracle(strict_json(line))
    except (ValueError, TypeError, OverflowError, RecursionError):
        return {"ok": False}


if __name__ == "__main__":
    for line in sys.stdin:
        print(compact(oracle_line(line)), flush=True)
