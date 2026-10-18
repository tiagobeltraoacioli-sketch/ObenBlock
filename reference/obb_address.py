"""Stdlib-only reference for ObenBlock (`obb`) addresses and their GnB aliases.

The contract is docs/DESIGN-obenblock.md §2 and docs/ADDRESS-V2.md. It was
written from those documents, not from the Rust code:

* legacy single-key: ``prefix || hex(hash20 || SHA3(SHA3(hash20))[:4])``;
  the checksum does not cover the prefix, so the forms of one hash differ in
  the prefix only;
* legacy policy: ``prefix || hex(hash32 || SHA3(SHA3(prefix || hash32))[:4])``;
  the checksum covers the prefix, so ``gnb1m`` and ``obb1m`` strings of one
  policy differ in the checksum too;
* v2: Bech32m (BIP350), data words ``[2, kind] || hash``, HRP per family and
  network (the generic codec is ``address_v2``).

Family "gnb" accepts only its own forms and the Bloch single-key aliases.
Family "obenblock" accepts its own forms and every GnB form (and the Bloch
aliases), parsed as the same output script, and displays ``obb``. ObenBlock
regtest occupies the GnB testnet slot. No key derivation or signing here.
"""
from __future__ import annotations

import hashlib

import address_v2 as v2

NETWORKS = ("mainnet", "testnet")
KEY_PREFIX = {
    "gnb": {"mainnet": "gnb1q", "testnet": "gnb1t"},
    "obenblock": {"mainnet": "obb1q", "testnet": "obb1t"},
}
POLICY_PREFIX = {
    "gnb": {"mainnet": "gnb1m", "testnet": "gnb1n"},
    "obenblock": {"mainnet": "obb1m", "testnet": "obb1n"},
}
HRP = {
    "gnb": {"mainnet": "gnb", "testnet": "tgnb"},
    "obenblock": {"mainnet": "obb", "testnet": "tobb"},
}
BLOCH_KEY_PREFIX = {"mainnet": "bloch1q", "testnet": "bloch1t"}
ACCEPTS = {"gnb": ("gnb",), "obenblock": ("obenblock", "gnb")}


class AddressError(ValueError):
    """The string is not an address the family accepts."""


def _sha3d(data):
    return hashlib.sha3_256(hashlib.sha3_256(data).digest()).digest()


def key_string(family, network, hash20):
    return KEY_PREFIX[family][network] + (hash20 + _sha3d(hash20)[:4]).hex()


def policy_string(family, network, hash32):
    prefix = POLICY_PREFIX[family][network]
    return prefix + (hash32 + _sha3d(prefix.encode("ascii") + hash32)[:4]).hex()


def v2_string(family, network, kind, payload):
    tag = 0 if kind == "single-key" else 1
    return v2._encode_words(HRP[family][network], [2, tag] + v2._hash_words(payload))


def _is_v2(address, family):
    # ASCII case-insensitive "<hrp>1z" for an accepted HRP.
    for accepted in ACCEPTS[family]:
        for network in NETWORKS:
            head = HRP[accepted][network] + "1z"
            if len(address) >= len(head) and all(
                c.isascii() and c.lower() == h for c, h in zip(address, head)
            ):
                return True
    return False


def _hex_payload(rest, length):
    if len(rest) != 2 * (length + 4):
        raise AddressError("length")
    if any(c not in "0123456789abcdefABCDEF" for c in rest):
        raise AddressError("hex")
    raw = bytes.fromhex(rest)
    return raw[:length], raw[length:]


def decode(address, family):
    """Return (network, kind, hash, form) or raise AddressError."""
    if _is_v2(address, family):
        hrp, words = v2._decode_words(address)
        for accepted in ACCEPTS[family]:
            for network in NETWORKS:
                if HRP[accepted][network] == hrp:
                    break
            else:
                continue
            break
        else:
            raise AddressError("hrp")
        if len(words) < 2 or words[0] != 2 or words[1] not in (0, 1):
            raise AddressError("version or kind")
        payload = v2._words_hash(words[2:])
        kind = "single-key" if words[1] == 0 else "policy"
        if len(payload) != (20 if kind == "single-key" else 32):
            raise AddressError("hash length")
        return network, kind, payload, "v2"
    for accepted in ACCEPTS[family]:
        for network in NETWORKS:
            prefix = POLICY_PREFIX[accepted][network]
            if address.startswith(prefix):
                payload, check = _hex_payload(address[len(prefix):], 32)
                if check != _sha3d(prefix.encode("ascii") + payload)[:4]:
                    raise AddressError("policy checksum")
                return network, "policy", payload, "legacy"
    for network in NETWORKS:
        aliases = [BLOCH_KEY_PREFIX[network]] + [KEY_PREFIX[f][network] for f in ACCEPTS[family]]
        for prefix in aliases:
            if address.startswith(prefix):
                payload, check = _hex_payload(address[len(prefix):], 20)
                if check != _sha3d(payload)[:4]:
                    raise AddressError("checksum")
                return network, "single-key", payload, "legacy"
    raise AddressError("prefix")


def render(family, network, kind, payload, form):
    if form == "v2":
        return v2_string(family, network, kind, payload)
    if kind == "single-key":
        return key_string(family, network, payload)
    return policy_string(family, network, payload)


def script(kind, payload):
    return payload if kind == "single-key" else b"\x02" + payload


def normalize(address, family):
    """The family's display of an accepted string (same form); else unchanged.

    For family "gnb" only the Bloch aliases change (``normalize_legacy_address``).
    """
    if family == "gnb":
        for network in NETWORKS:
            if address.startswith(BLOCH_KEY_PREFIX[network]):
                return KEY_PREFIX["gnb"][network] + address[len(BLOCH_KEY_PREFIX[network]):]
        return address
    try:
        network, kind, payload, form = decode(address, family)
    except (AddressError, v2.AddressError):
        return address
    return render(family, network, kind, payload, form)
