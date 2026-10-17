# ObenBlock PQ-PSBT version 1

PQ-PSBT carries an unsigned ObenBlock transaction and public policy-signing
metadata between creator, updater, signer, combiner, finalizer and extractor
roles. It contains no private keys. This is a wallet format of ObenBlock,
introduced in GnB, **not Bitcoin PSBT wire compatibility**, and does not
change consensus, activation heights, transaction IDs or signature messages.

For CLI, RPC and WASM examples, see [PQ-PSBT usage](PQ-PSBT-USAGE.md).

The role separation and checking a supplied previous transaction against its
outpoint follow the rationale in [BIP174, Roles and Signer](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#roles).
Explicit format versioning, distinct from the transaction version, follows
[BIP370, Specification](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#specification).
Their Bitcoin maps, field identifiers and version rules are not used here.
GnB rejects unknown fields and conflicting combined claims instead of retaining
extensions or selecting one of two conflicting values.

## Binary encoding

All integers are unsigned and little-endian unless stated otherwise. `u8`,
`u16`, `u32` and `u64` occupy exactly 1, 2, 4 and 8 bytes. `blob32` is a `u32`
byte length followed by exactly that many bytes; its length excludes the four
length bytes. There is no alignment or padding. Parse the following fields
in this exact order:

| Field | Encoding | Meaning |
| --- | --- | --- |
| magic | 8 fixed bytes | `47 4e 42 50 53 42 54 ff` (`GNBPSBT` + `ff`) |
| format version | `u16` | `01 00` |
| network | `u8` | `00` mainnet; `01` testnet |
| transaction | `blob32` | canonical full unsigned transaction wire bytes |
| policy | `blob32` | selected spend policy, encoding below |
| tree | `blob32` | complete policy tree; zero length means absent |
| branch | `u8` | `ff` exactly when tree absent; otherwise zero-based selected branch |
| input count | `u16` | exactly the transaction's input count |
| inputs | repeated input records | one for each transaction input, in transaction order |

The fixed overhead, excluding input records and blob contents, is 26 bytes.
The transaction length begins at offset 11. For transaction byte length `T`,
the policy length begins at `15 + T`; later offsets depend on preceding blob
lengths. No bytes may follow the final input record. Unknown versions and
networks are errors; there is no extension-field retention mechanism.

Each input record is:

| Field | Encoding |
| --- | --- |
| spent value, in satoshis | `u64` |
| spent locking script | `blob32` |
| complete previous transaction | `blob32`; zero length means absent |
| derivation count | `u8` |
| each derivation | key index `u8`, fingerprint 4 raw bytes, path length `u8`, path elements `u32` each |
| partial-signature count | `u8` |
| each partial signature | key index `u8`, signature `blob32` |

Each of the two index lists is independently strictly increasing and every
index is less than the selected policy's key count. Duplicate indices and
unsorted lists are errors; a derivation and signature may name the same key.
There is no signature-count requirement equal to the threshold during
interchange: incomplete signing is valid. A present signature is 1–8,192 bytes.
Its cryptographic validity is checked by signing/finalization code, not by
this structural reference.

## Bounds and canonical embedded encodings

Check total input size before parsing and each declared length/count before
allocating or copying the corresponding variable field.

| Item | Maximum |
| --- | ---: |
| Complete binary | 8,388,608 bytes (8 MiB) |
| JSON source/output, UTF-8 bytes | 17,039,360 bytes (`2 × 8 MiB + 256 KiB`) |
| Transaction or each previous transaction | 1,000,000 bytes |
| Policy | 65,536 bytes |
| Tree | 262,144 bytes |
| Locking script | 10,000 bytes |
| Unsigned transaction inputs / outputs | 64 / 64; each count is at least 1 |
| Derivations / signatures per input | 7 / 7 |
| Path elements per derivation | 16 |
| Signature | 8,192 bytes; minimum 1 |

These are wallet-boundary bounds. Some structural limits are tighter than
these container caps: for example the selected policy's locking script is
exactly 33 bytes. JSON must also encode within the binary size cap. Every valid binary has a
canonical JSON representation within the JSON cap. Hex payloads occupy at most
twice the binary byte count. A conservative upper bound for the remaining
canonical JSON metadata is:

```text
256 + 64 × (256 + 7 × (128 + 16 × 11) + 7 × 64) = 181,504 bytes
```

The first 256 covers top-level fields. Per input, 256 covers its fixed field
names, punctuation, up to 20 decimal amount digits and separators; each of
seven derivations adds at most 128 fixed bytes plus sixteen 10-digit u32
numbers with separators; each of seven signatures adds at most 64 fixed
bytes. These allowances also cover the empty lists and null options; all
canonical text is ASCII. The 262,144-byte allowance exceeds this bound. An
executable maximal-metadata construction measures 121,337 bytes, providing an
additional check of the conservative calculation. JSON above the cap is
rejected before parsing, and serialization also checks its result. Arbitrary
source whitespace is not part of the canonical representation guarantee.

This derived limit replaces an initial 16 MiB proposal before publication:
a real valid binary at the 8 MiB boundary needs more than 16 MiB when its hex
payloads and JSON metadata are combined. The binary limit is unchanged.

A transaction is the existing GnB wire format:

```text
version u32
input_count CompactSize
  (previous_txid 32 bytes, previous_index u32,
   script_sig_length CompactSize, script_sig bytes, sequence u32)*
output_count CompactSize
  (value u64, script_length CompactSize, script bytes)*
locktime u32
```

`CompactSize` encodes 0–252 as one byte; 253–65,535 as `fd || u16`;
65,536–4,294,967,295 as `fe || u32`; larger u64 values as `ff || u64`.
Only the shortest form is accepted. A transaction must consume its entire
blob and re-encode identically. Every unsigned transaction input's
`script_sig` is empty, including its zero length byte in the full encoding.
Previous transactions use the full encoding and may contain witnesses. Their
existing parser caps are 100,000 inputs/outputs, 114,834 script-signature bytes
and 10,000 output-script bytes, also bounded by the 1,000,000-byte blob cap.

A policy is `01 || threshold u8 || key_count u8 || (blob32 key)* || after u32 ||
older u32`. Require `1 <= threshold <= key_count <= 7`, distinct key bytes,
no trailing bytes, and the existing hybrid public-key shape: either 3,745
legacy bytes or `b1 0c 01 00` followed by 3,745 body bytes. This shape check is
not public-key cryptographic validation. The output script is
`02 || SHA3-256("GNB-POLICY-v1" || policy)`; quoted domains are ASCII without
NUL terminators.

A complete tree is `02 || branch_count u8 || (blob32 policy)*`, with 2–4
branches. The selected branch must equal the separately carried policy byte
for byte. Each leaf is `SHA3-256("GNB-POLICY-v2/leaf" || policy)`; pad three
leaves to four with `SHA3-256("GNB-POLICY-v2/empty")`. A parent is
`SHA3-256("GNB-POLICY-v2/node" || left || right)`. The locking script is
`02 || SHA3-256("GNB-POLICY-v1" || 02 || branch_count u8 || root)`.
Tree interchange does not imply that tree spending is activated on a network.

## Structural consistency and signing boundary

The decoder accepts transaction versions 1 and 3, rejects an unsigned
coinbase, repeated outpoints, nonempty unsigned input scripts, and outputs
other than a 20-byte pubkey hash or `02` followed by a 32-byte policy hash.
Each output must be at least 546 satoshis. The transaction's locktime must
meet the selected policy's `after`. Every input must spend the same selected
policy/tree branch: heterogeneous policies and single-key inputs are outside
v1's supported scope. Outputs may use either supported output type.

Input values and output values, and their respective sums, fit u64. The
input sum must cover the output sum. This wallet codec does not additionally
apply the consensus `MAX_SUPPLY_SAT` bound; structural acceptance, including
a vector with the exact u64 maximum, is not a consensus-validity verdict.
The fee is the exact input sum minus output sum, with no floating-point
conversion. Contextual review applies the existing shared MoneyRange checks:
`core::limits::check_tx_money_range` for outputs and
`core::limits::money_add` for input amounts and their sum. The structural
codec's u64 acceptance does not bypass those signing/finalization checks.

A supplied previous transaction is checked for either spending transaction
version. Its existing GnB transaction ID must equal the outpoint's 32 bytes,
without display-byte reversal; the selected output index must exist and its
value and script must equal the input metadata. GnB computes this ID with
double SHA-256. For non-coinbase previous transactions the preimage omits the
**entire script_sig field, including its length prefix**, from every input.
For a coinbase (one input with zero txid and index `ffffffff`) it uses the full
wire encoding. Altering a non-coinbase previous witness therefore does not
alter this ID; altering a coinbase witness does.

The decoder permits absent previous transactions so an updater can add them.
Before signing v1, all previous transactions are required and checked; v3's
existing sighash commits the value/script pairs. Neither proves current
unspentness offline. Network, next block height and absolute maximum fee are
explicit trusted caller inputs to signing/review, not assertions supplied by
the document. Existing activation checks reject v1 at hardening without
rewriting a partially signed transaction's version. The absolute fee ceiling
has no minimum-fee exception. Review also requires at least 10,000 satoshis
(`MIN_TX_FEE_SAT`) before invoking a signing callback. This floor does not
estimate witness size: finalization applies `core::check_min_fee` to the
actual finalized transaction and reviewed fee, so its required minimum may
be higher. Online signing additionally checks each UTXO against the configured
node and displays inputs, outputs, fee and change.

A creator builds the unsigned document; an updater adds missing public data;
a signer validates all inputs before invoking a signing callback; a combiner
requires the same transaction/context and rejects conflicting metadata or
signatures; a finalizer verifies the required signatures and final witness;
an extractor emits the finalized transaction. Signing builds a candidate and
validates the complete resulting document before replacing the original.
Callback or candidate-validation failure leaves the original document
unchanged; callbacks may already have run before candidate validation fails.

Finalization inherits `PolicySpend`'s restriction to the threshold
lowest-indexed signers common to **every** input. Separate threshold-sized
sets on different inputs do not suffice without that common signer set.
Static finalization does not establish current UTXO existence/unspentness,
coinbase maturity or relative input age, and does not guarantee mempool
admission. The format's 1,000,000-byte transaction limit and the node's default
400 KiB relay limit are distinct bounds; format acceptance is not relay
admission, and this package changes no relay rule.

Derivation paths/fingerprints are hints, not proofs of ownership or change.
There is no importable `verified` or `unspent` field. The Python reference
implements encoding, decoding and structural consistency only; it implements
none of these signing operations and never calls a PQ verifier.

## Equivalent JSON

All listed fields are required, including nullable fields. Unknown fields and
duplicate object fields are errors at every nesting level, including escaped
spellings of the same field. Object order and whitespace are insignificant;
the canonical serializer uses the order below and no insignificant spaces.
All hex is lowercase with an even number of characters. Null tree/previous
transaction means absent; an empty string is not an alternative representation.

```text
{
  "format": "gnb-pqpsbt",
  "version": 1,
  "network": "mainnet" or "testnet",
  "transaction": unsigned_transaction_hex,
  "policy": selected_policy_hex,
  "tree": full_tree_hex or null,
  "branch": zero_based_integer or null,
  "inputs": [{
    "value": canonical_decimal_string,
    "script": locking_script_hex,
    "previous_tx": complete_transaction_hex or null,
    "derivations": [{
      "key_index": integer,
      "fingerprint": eight_hex_characters,
      "path": [u32_integer, ...]
    }],
    "signatures": [{"key_index": integer, "signature": hex}]
  }]
}
```

A decimal value is `"0"` or a nonzero ASCII digit followed by ASCII digits,
within u64 (`18446744073709551615` maximum). Leading zeros, signs, exponents,
fractions, whitespace and JSON numeric amounts are errors. Numeric fields
use unsigned integer JSON tokens, never booleans, strings, fractions,
exponents or negative zero. Thus `0`, `"0"`, `"00"`, `false`, `0.0` and `-0`
are not aliases for key-index identity. Path elements are in 0–4,294,967,295;
bit 31 is carried as data and this format does not derive a key from a path.

## Independent vectors and bounded differential checks

The standard-library-only Python implementation was written from this byte
contract and existing transaction/policy encodings, without calling or copying
the new Rust PQ-PSBT codec. Public-key bodies and signatures in these fixtures
are synthetic bytes; accepted fixtures are **structurally accepted**, not
cryptographically signed transactions.

```sh
python3 reference/pqpsbt_test.py
python3 reference/pqpsbt_vectors.py --check
# Regenerate deliberately after a reviewed specification change:
python3 reference/pqpsbt_vectors.py
```

`reference/pqpsbt_vectors.json` contains 45 accepted documents with their exact
binary bytes, 95 rejected binary cases and 64 rejected JSON cases. This includes
64 deterministically seeded cases (32 accepted and 32 paired mutations) from
a fixed SHAKE-256 label. Rust and Python must check the same verdicts, and
accepted JSON and binary must agree exactly. The Rust integration test also runs 512 seeded binary mutations through the
Python JSONL oracle, retaining unmodified accepted controls. The initial local
run agreed on all 512 verdicts (95 accepted) and canonical bytes. This bounded
coverage is not a claim of ten million differential cases or comprehensive
consensus coverage.

The manifest has `schema: 1`, `seed`, `seeded_cases`, `scope`, `accepted`
(`name`, `binary`, `document`, `canonical_json`), `rejected_binary` (`name`, `binary`) and
`rejected_json` (`name`, `json`, containing the raw JSON text to preserve
malformations). Fixture regeneration is byte-for-byte reproducible.
The optional process oracle is `python3 reference/pqpsbt.py --jsonl`: each
line is `{"binary":"hex"}` or `{"json":"raw JSON text"}`. A success emits
`{"accepted":true,"binary":"canonical hex","document":...,"json":"canonical JSON text"}`.
Canonical JSON strings also check compact formatting and field order. Rejection
emits `{"accepted":false}`. Error wording is not part of the contract.
