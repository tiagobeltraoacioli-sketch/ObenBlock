# ObenBlock address v2

This document specifies an opt-in representation of existing ObenBlock payment
destinations. It changes no output script, transaction byte, signature message,
key derivation, or consensus rule. A recipient must explicitly choose v2 output
until the application supports it. Existing legacy address formats remain
accepted with their existing bytes and checksums. The strings below use the
`gnb` prefixes the code implements today; ObenBlock's address prefixes are
specified in [DESIGN-obenblock.md](DESIGN-obenblock.md) §2 and not implemented
yet.

The checksum and alphabet are the generic Bech32m format from
[BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#bech32m),
using the framing and case rules from
[BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32).
Bitcoin Core adopted the Bech32m checksum in
[bitcoin/bitcoin#20861](https://github.com/bitcoin/bitcoin/pull/20861).
GnB v2 is a custom application of this encoding. Its first data word is a GnB
format version, not a Bitcoin witness version. It is not a Bitcoin Segwit
address and must not be passed through a Segwit script constructor.

## Destination and network mapping

| Network | Human-readable part (HRP) |
| --- | --- |
| Mainnet | `gnb` |
| Testnet | `tgnb` |

No other HRP is valid. An application operating on a particular network must
compare the decoded network with that network and reject mismatches. A valid
address for the other network is not a recipient on the current network.
Changing the HRP without recomputing the checksum must fail. The checksum is
error detection, not authentication: someone can create another valid address
or recompute its checksum.

| Kind word | Meaning | Hash bytes | Output script bytes |
| --- | --- | --- | --- |
| `0` | Single-key destination | Exactly 20 | The same 20 hash bytes |
| `1` | Policy destination | Exactly 32 | `02` followed by those 32 hash bytes |

Every other kind is invalid. Policy v2 preserves the existing 33-byte
`0x02 || policy_hash` script. The address alone does not establish ownership,
the existence of an output, or that a policy can be satisfied.

## Encoding, word by word

1. Select the lowercase HRP for the destination network.
2. Form a sequence of 5-bit unsigned words. The first word is the integer
   `2` (format version); the second is the kind `0` or `1`.
3. Append the hash bits, most significant bit first within each byte, split
   into 5-bit words. Pad only the final word on its right with zero bits.
   A 20-byte hash contributes 32 words and no padding. A 32-byte hash
   contributes 52 words, with four zero low bits in its final word.
4. Calculate the six Bech32m checksum words over the expanded HRP and all
   data words, using constant `0x2bc830a3`, not Bech32's constant `1`.
5. Emit `hrp || "1" || alphabet(data_words || checksum_words)` in lowercase.

The alphabet at indices 0 through 31 is:

```text
qpzry9x8gf2tvdw0s3jn54khce6mua7l
```

For checksum construction, HRP expansion is the high five bits of each ASCII
character, one zero word, then the low five bits of each character. Start a
30-bit register at 1. For each word, save its top five bits, shift the low
25 bits left by five and XOR the new word; XOR the generator corresponding
to each set bit of the saved five bits. The generators, in low-bit order,
are `0x3b6a57b2`, `0x26508e6d`, `0x1ea119fa`, `0x3d4233dd`, `0x2a1462b3`.
For creation, process HRP expansion, data and six zero words; XOR the result
with `0x2bc830a3`; emit that result as six words, most significant first.
For verification, processing HRP expansion plus data and checksum must leave
exactly `0x2bc830a3`.

| Destination | First characters | Total ASCII characters |
| --- | --- | --- |
| Mainnet single-key | `gnb1zq` | 44 |
| Testnet single-key | `tgnb1zq` | 45 |
| Mainnet policy | `gnb1zp` | 64 |
| Testnet policy | `tgnb1zp` | 65 |

## Decoding and rejection rules

The decoder accepts at most 90 characters, all printable US-ASCII
(`0x21` through `0x7e`). It does not trim whitespace or normalize Unicode.
Uniform lowercase and uniform uppercase are accepted; mixed case is rejected.
Only after this check may it lowercase the string for checksum processing.

The final `1` separates the nonempty HRP from the data and checksum. At least
six symbols must follow it. Every following symbol must belong to the alphabet.
The six checksum symbols are removed only after successful Bech32m verification.
A checksum valid only under Bech32 is invalid here.

The HRP must be known, at least two data words must remain, the version must
be 2, and the kind must be 0 or 1. Convert only the words after those two
metadata words back into bytes. Discarded trailing bits must number at most
four and must all be zero. Discarding a full zero word is forbidden. The
decoded hash must have exactly the kind's specified byte length. Extra words,
truncated hashes, unknown metadata and nonzero padding are rejected even if
the sender recomputes a valid checksum.

Successful decoding returns the network and the existing output script from
the mapping above. Re-encoding returns the canonical lowercase address.
Canonicalization never changes a hash or converts between networks.

## Fixed vectors

These four vectors use all-zero hashes. Their scripts are exactly 20 zero
bytes for single-key and `02` followed by 32 zero bytes for policy.

| Network and kind | Address |
| --- | --- |
| Mainnet single-key | `gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw` |
| Testnet single-key | `tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc` |
| Mainnet policy | `gnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqggmvny` |
| Testnet policy | `tgnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqht5fkx` |

## Executable reference and corpus

`reference/address_v2.py` is a Python standard-library implementation of this
contract. It implements no network calls, signing, secret handling or legacy
decoder. It was developed independently of the new Rust address-v2 codec,
from this contract, the BIPs and the existing output script representation.
Its bit-string hash conversion is deliberately distinct from a streaming
bit accumulator. Independence does not establish correctness on its own.

`reference/address_v2_vectors.py` generates the versioned corpus in
`reference/address_v2_vectors.json`. It contains 502 application cases:
128 accepted and 374 rejected. Verdicts are assigned by construction rules,
then checked by the reference tests. The generator includes fixed patterns,
12 deterministic SHAKE-derived hashes per network/kind, metadata and padding
rejections with recomputed checksums, wrong-network contexts and bounded
character mutations. Counts describe these finite tests, not comprehensive
fuzzing or a proof of all typographical errors.

Generic BIP350 vectors are tested separately: a valid generic checksum with
an unknown HRP is not a valid GnB destination. The shared corpus omits valid
legacy addresses because the **v2-only reference** does not implement them,
while the production unified parser must accept them. Separate production
tests must establish legacy compatibility. The Rust oracle may therefore
call that public parser directly, without a preliminary v2 syntax gate that
could mask a production parsing defect.

Run the reference and exact corpus reproducibility checks:

```sh
python3 reference/address_v2_test.py -v
python3 reference/address_v2_vectors.py --check
```

For a built Rust `address_v2_oracle` binary, compare all corpus decodes and
all 128 positive encodes (630 requests), plus 42 bounded JSON-envelope cases
(672 requests total):

```sh
python3 reference/address_v2_differential.py /path/to/address_v2_oracle
```

The differential driver requires exact verdicts and exact decoded fields,
reports the binary/reference/corpus hashes, and exits with failure on any
disagreement. A reported zero means zero differences in this finite corpus
and envelope set only.

The reference also exposes a JSON-lines oracle on standard input. Requests
are either `{"op":"decode","address":"...","expected_network":"mainnet"}`
(the expected network may be omitted or `null`, both meaning unconstrained) or
`{"op":"encode","network":"mainnet","kind":"single-key","hash_hex":"..."}`.
Hash input uses lowercase even-length hexadecimal. The kind is `single-key`
or `policy`; the network is `mainnet` or `testnet`. Success returns `ok: true`
and `address`, `network`, `kind`, `hash_hex`, `script_hex`; rejection returns
only `{"ok":false}`. Error wording is not part of the contract.
Requests must be objects. The decode operation permits exactly `op`, `address`
and optional `expected_network`; the encode operation requires exactly `op`,
`network`, `kind` and `hash_hex`. Unknown fields, missing required fields and
incorrect field types are rejected. Apart from optional `expected_network`,
the fields above must be strings; `null` is not a substitute for a required
string. These rules describe the local test adapters, not a node RPC method.

## Compatibility and scope

Legacy single-key and policy representations remain available and retain
their original serialization. A legacy single-key checksum does not cover
its network prefix; accepting that historical format does not fix that
limitation. Callers must still check their expected network for every format.
V2 generation is additive and opt-in, without a consensus activation height.

This specification establishes neither full frontend adoption nor deployment
readiness. RPC, CLI, wallet and WASM integration, independent review and CI
results must be recorded separately in the round's evidence ledger.
