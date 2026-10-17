# Static public descriptors and public pools

This format describes existing ObenBlock output scripts. It is a partial delivery of
technology item 4.2: static public descriptors and restoration of public script
identities. It does not derive child keys, import private keys, restore signing
capability, obtain balances/history, create a persistent wallet index, or add a
spending language. An owner supplies already-derived public keys. No consensus
rule or activation height changes.

## Descriptor text

The complete descriptor is `body#checksum`, with exactly one `#` and an
8-character checksum. Creation takes a checksum-free body. Inspection and pool
import require the checksum. The complete descriptor has at most 262,144 ASCII
bytes, including `#` and checksum (therefore a creation body has at most 262,135
bytes). There is no leading, embedded or trailing whitespace, uppercase text,
trailing data, wildcard, path, key-origin expression, `xpub` or private-key form.

```text
body       = "gnbd1(" network "," expression ")"
network    = "mainnet" | "testnet"
expression = "pkh(" KEY ")" | policy | tree
policy     = "policy(" threshold "," after "," older "," KEY ("," KEY)* ")"
tree       = "tree(" policy "," policy ("," policy){0,2} ")"
```

`threshold`, `after` and `older` are minimal unsigned decimal: `0`, or a
nonzero digit followed by digits. `after` and `older` are at most 4,294,967,295.
A policy has 1–7 keys and `1 <= threshold <= key count`. A tree has 2–4 policy
branches. Key order and branch order are significant and preserved. Repeated
branches are not prohibited by the existing tree constructor.

`KEY` is lowercase hexadecimal of an existing accepted hybrid public-key
representation. The format predicate accepts either exactly 3,745 raw bytes
(ML-DSA-65 public key 1,952 bytes followed by Falcon-1024 public key 1,793 bytes),
or exactly 3,749 bytes beginning with `b1 0c 01 00` followed by that raw body.
Exact raw length takes priority even if its leading bytes look like an envelope.
This is the existing shape predicate, not proof that a supplied byte string is
a usable public key or that someone possesses its private key.

Every byte is preserved when hashing. A raw public key and its envelope are
different serialized keys and can produce different scripts. They are one
signer, though (sighash v3 verifies a signature under either encoding), so a
new policy may not list both (PF-4): `create` builds every policy and tree
branch with `SpendPolicy::new`, which refuses two keys with the same
`policy::key_identity` (the enveloped encoding) at every height, and
consensus refuses a spend of such a policy or branch from the second
hardening height (`docs/CONSENSUS.md`, "Spend-policy key identity (PF-4)").
An existing checksummed descriptor of that shape (the release before PF-4
created and exported them) is still restored by `inspect`, `export` and
`import` under the consensus policy checks only (byte-distinct keys), so a
pool that holds one restores whole; its descriptor info then carries
`twin_key_encodings: true`. Move the funds of such an output before the
second hardening height: from it, that policy (or that tree branch; the
other branches are unaffected) cannot be spent, and the wallets' policy
signers refuse to sign or finalize a spend of it for a block at or above the
height. The descriptor keeps the bytes it was given: no key is normalized
and no signature is verified here.

## Checksum

The checksum is exactly [BIP380's descriptor checksum](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#checksum)
over the complete body, including `gnbd1` and the network. This borrows the
checksum only, not Bitcoin's script or key-expression language.

The ordered input alphabet below is followed by one ASCII space (0x20):

```text
0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\
```

For each character's index `v`, append `v & 31`. After each three characters,
append `9*(v0 >> 5) + 3*(v1 >> 5) + (v2 >> 5)`. A final group of one contributes
`v0 >> 5`; a final group of two contributes `3*(v0 >> 5) + (v1 >> 5)`. Starting
with register 1, update for every symbol `s` with `top = register >> 35` and
`register = ((register & 0x7ffffffff) << 5) XOR s`, then XOR generator `i` when
bit `i` of `top` is set. The generators, in order, are:

```text
f5dee51989 a9fdca3312 1bab10e32d 3706b1677a 644d626ffd
```

For creation append eight zero symbols, compute the register and XOR it with
1. Encode its eight 5-bit groups from most significant to least significant
using `qpzry9x8gf2tvdw0s3jn54khce6mua7l`. For verification, append the eight
checksum symbols to the expanded body and require final register 1.
The primary checksum example is `raw(deadbeef)#89f8spxm`; its body is not a
valid GnB descriptor.

Large PQ descriptors can exceed BIP380's length ranges for several guaranteed
multi-symbol error detections. This format does not extend those guarantees
up to its 262,144-byte limit. The checksum detects transcription mistakes; it
does not authenticate the sender or establish ownership of the public keys.

## Script and address bytes

`SHA3` means SHA3-256, not Keccak-256. `u32le` means exactly four little-endian
bytes. Concatenation preserves field order and uses no implicit separators.

For `pkh(KEY)`:

```text
script = SHA3(exact KEY bytes)[0:20]
```

For a policy, let `n` be its number of keys and `m` its threshold:

```text
encoded = 0x01 || u8(m) || u8(n)
          || (u32le(key_length) || key_bytes) for each key in input order
          || u32le(after) || u32le(older)
script  = 0x02 || SHA3(ASCII("GNB-POLICY-v1") || encoded)
```

For a tree with `n` branches, compute:

```text
leaf_i     = SHA3(ASCII("GNB-POLICY-v2/leaf") || branch_i.encoded)
empty      = SHA3(ASCII("GNB-POLICY-v2/empty"))
node(l, r) = SHA3(ASCII("GNB-POLICY-v2/node") || l || r)
commitment = 0x02 || u8(n) || root
script     = 0x02 || SHA3(ASCII("GNB-POLICY-v1") || commitment)
```

A 2-branch tree combines its two leaves. A 3-branch tree appends one empty leaf;
a 4-branch tree uses all four leaves. Combine consecutive left/right pairs,
then combine the resulting pair. No sorting occurs. These are existing
`SpendPolicy` and `PolicyTree` identities, not a new on-chain serialization.
A tree descriptor reports `requires_policy_tree_activation: true`; parsing or
rendering it does not prove that a branch spend is active on a caller's chain.

The legacy single-key address uses prefix `gnb1q` (mainnet) or `gnb1t` (testnet),
followed by lowercase hex of `hash20 || SHA3(SHA3(hash20))[0:4]`. The legacy
policy/tree address uses prefix `gnb1m` or `gnb1n`, followed by lowercase hex of
`hash32 || SHA3(SHA3(ASCII(prefix) || hash32))[0:4]`. The optional Bech32m form
follows [ADDRESS-V2.md](ADDRESS-V2.md), preserving the same script identity.

## Public request interface

Each request is an object containing `network` (`mainnet` or `testnet`) and
`action`. An optional `op`, if present, must equal the string `descriptor`;
`null`, another operation or another type is invalid. Each action accepts only
its listed input in addition to those common fields. Unknown fields, missing
fields and wrong types are rejected. No operation signs, pays, wipes a wallet,
or accesses unlocked session keys.

| action | required input | returned value |
| --- | --- | --- |
| `create` | `body`: string without checksum | descriptor info |
| `inspect` | `descriptor`: checksummed string | descriptor info |
| `export` | `descriptors`: array of checksummed strings | pool response |
| `import` | `bundle`: string containing pool JSON | pool response |
| `pool` | `public_keys`: array of lowercase key hex strings | pkh pool response |

Descriptor info contains exactly `descriptor`, `network`, `kind`
(`pkh`, `policy` or `tree`), `script_pubkey` (lowercase hex), `address` (legacy),
`bech32m` and `requires_policy_tree_activation` (true only for a tree), plus
`twin_key_encodings: true` only for a restored descriptor whose policy or a
tree branch lists one key in its raw and enveloped encodings (PF-4, above;
the field is absent otherwise, so every other descriptor's info is unchanged).
The requested network must match every descriptor or imported pool. There is
no implicit network default in this interface.

## Public pool file

Canonical export is compact UTF-8 JSON with this exact field order:

```json
{"format":"gnb-watch-only-v1","network":"mainnet","descriptors":["..."]}
```

The schema has exactly those three fields; it accepts only format
`gnb-watch-only-v1`. It holds 1–64 descriptors, all on the same network, in
input order, with unique complete script bytes. Equal descriptors therefore
cannot appear twice. A raw key and its envelope are not merged: their script
identities differ under the existing hashing rules.

The complete input pool JSON is at most 1,048,576 UTF-8 bytes, checked before
JSON deserialization. Whitespace and a different JSON object field order are
accepted on import and replaced by canonical export. Unknown fields, duplicate
fields (even identical values), non-JSON constants, wrong types and trailing
non-whitespace bytes are refused. Escaped JSON strings are interpreted before
descriptor grammar validation. The size bound still applies to the original
UTF-8 input, including whitespace/escapes. Canonical output is also bounded.

The response has `bundle` (canonical JSON string), `count` and `entries` (the
complete descriptor infos). Export/import preserves entry order and exact
public script identities. This is a public descriptor pool, not a secret-key
backup or a currently funded wallet.

## Executable reference and vectors

The independent Python implementation is [descriptor.py](../reference/descriptor.py),
written from the frozen contract, BIP380 and the pre-existing script/key/address
formats without reading the new Rust descriptor implementation. Its address-v2
renderer reuses the existing independent Python address reference. It uses only
the Python standard library and performs no cryptographic signing or keygen.

[descriptor_vectors.py](../reference/descriptor_vectors.py) deterministically
constructs both networks, all kinds, raw/enveloped/magic-prefix keys, ordered
policies and padded trees, checksum changes, grammar and integer boundaries,
strict request/bundle JSON, network mismatches and descriptor/pool limits.
[descriptor_vectors.json](../reference/descriptor_vectors.json) stores synthetic
public key byte fixtures plus SHA256 pins of each exact request line and full
response. It also stores script/address/checksum fields for successful single
descriptors. The fixtures meet the existing byte-shape predicate; they are not
asserted to be generated usable cryptographic keys. This corpus is finite and
does not establish full consensus equivalence or a fuzzing volume claim.

```sh
python3 reference/descriptor_test.py
python3 reference/descriptor_vectors.py --check
python3 reference/descriptor_differential.py /path/to/prebuilt/descriptor_oracle
python3 reference/descriptor_differential.py /path/to/prebuilt/descriptor_oracle --generated 128 --seed 0x474e424435
```

The JSON-lines oracles accept one public request per line and return
`{"ok":true,"result":...}` or `{"ok":false}`. Duplicate outer JSON fields are
rejected by the oracle adapter, before conversion to an ordinary object.
Rejection text is not compared; accepted responses are compared in full.
The differential driver first checks request and response pins, then compares
the Python reference with the prebuilt Rust oracle. It does not build Rust or
inspect Rust source.

In addition to the pinned corpus, the differential driver defaults to 128
generated requests from seed `0x474e424435`. [descriptor_generated.py](../reference/descriptor_generated.py)
varies synthetic key bytes, raw/enveloped forms, key/branch order, threshold,
timelocks, networks and all three descriptor kinds. It generates valid public
byte substitutions and pool roundtrips, and invalid checksums, network choices,
grammar and duplicate JSON fields by construction. `--generated 0` selects
only pinned cases; 0–4096 generated requests are supported. The output reports
the separate counts, seed and SHA256 of the generated request stream. This is
a deterministic generated comparison campaign, not a coverage-guided fuzz run,
nor a claim of 10^7 cases or complete consensus coverage.
