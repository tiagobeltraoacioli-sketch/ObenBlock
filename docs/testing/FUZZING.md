# Fuzzing

ObenBlock fuzzes its untrusted-input parsers, its consensus encodings and its
block-acceptance pipeline with [cargo-fuzz] (libFuzzer, coverage-guided)
under AddressSanitizer. The crate is `node/fuzz`: its own workspace (excluded
from the root one, so nightly-only sanitizer flags never reach the consensus
build), one binary per target in `node/fuzz/fuzz_targets/`, one seed corpus
per target in `node/fuzz/corpus/<target>/`.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

Most targets do more than "never panics": they compare the library with an
independent implementation written from the specification in the target
(`fuzz_targets/common/mod.rs` and the targets themselves), or check a
round-trip, canonicality or sensitivity property. A property violation is an
assertion failure, which libFuzzer reports as a crash like any panic.

## Targets

| Target | Entry points | What it checks |
| --- | --- | --- |
| `tx_parse` | `Transaction::from_wire_bytes` | no panic; decode/encode is a fixed point; txid stable |
| `block_parse` | `Block::from_wire_bytes` | no panic; decode/encode is a fixed point |
| `header_parse` | `BlockHeader::from_wire_bytes` | no panic; fixed point; a trailing byte is refused |
| `netmsg_decode` | `network::decode_wire_message` (gossip frames) | no panic; an accepted frame obeys every field bound (restated in the target) and is the canonical encoding of its message (one frame per message: gossipsub message ids are SHA-256 of the frame) |
| `handshake_decode` | live `/gnb/pq/2.0.0` transport handshake `upgrade::Init` / `Resp` / `Finish` decode (until the re-audit, NET-17, it decoded the types of a never-used ML-DSA handshake, since removed) | no panic (`MAX_HANDSHAKE_MSG_SIZE` = 32 KiB limit, bincode standard configuration, as `read_msg`) |
| `pow_decode` | compact bits, chain work, ASERT (`gnb_smh::difficulty`) | no panic; bits round down and are stable; work monotone; ASERT equals an independent U512 implementation of aserti3-2d |
| `pow_verify` | GnB-SMH on small scratchpads, `crypto::verify` | no panic; strict `out < target`; malformed bits never validate; the hybrid verifier returns a bool on arbitrary keys and signatures |
| `merkle_path` | `coherence_core::verify_path` | no panic; wrong-length paths and indices above the tree depth never verify |
| `mempool_ops` | `Mempool` add / remove / remove_confirmed op stream | the `txs` / `spent` / rate-index invariant after every operation |
| `block_rules` | `core::block_rules` (VAL-2, VAL-10, VAL-12, CRY-1, B2-T10) | tagged Merkle root equals an RFC 6962-style recursive reference; legacy root equals Bitcoin's in-place `ComputeMerkleRoot`; coinbase branch folds back to the root and ignores position 0; a duplicated last id changes the tagged root; on blocks decoded from untrusted bytes: wire encoding and `wire_size` (the PoWit section included from `powit_height()`), txid, wtxid, header roots (the v2 body root over the transparent, shielded and PoWit sections from `powit_height()`), witness root, parents commitment and the 80-byte coinbase commitment equal the references; the 64-byte rule fires exactly on 64-byte txid preimages; the distinct-parents rule fires exactly on a repeated parent; the commitment verdict (which field fails) equals a reference parser, and the body verdict follows the specified order (parents, 64-byte, commitment); a block repaired to the specification (each parent once) is accepted, and altering any committed field (commitment byte, height, parent list, a witness, a truncated commitment, an extra transaction) is rejected while the miner's extra bytes are free |
| `sighash` | `Transaction::sighash`, `sighash_v2_checked`, `sighash_v3`, `SighashV3Precomputed` | no panic for any transaction, index or spent-output count; v2 equals an independent encoding of the specification (version byte 0x02 over the stripped transaction's wire encoding, `reference/gnb_sighash.py`), and the library's wire encoder produces the same body; v3 equals an independent 195-byte preimage; v3 errors exactly on a spent-output count mismatch or an out-of-range index; changing any single committed field (version, locktime, chain, suite, index, prevout, sequence, spent amount, spent script, output value or script) changes the v3 digest; no `script_sig` changes either digest |
| `witness_parse` | `parse_script_sig{,_borrowed,_exact}`, `build_script_sig`, `sighash::canonical_witness`, `check_input_witnesses` | the three parsers equal one exact reference parser (on this chain the framing is exact at every height, cc5c450); every accepted input is exactly `build_script_sig` of what it parsed to; trailing bytes are refused by every parser and by both witness rules; the canonical-witness and per-regime witness rules agree with the framing and `is_canonical_signature_encoding`; genuine canonical hybrid signatures altered by the input exercise the envelope and Falcon compact-encoding checks |
| `wire_roundtrip` | `Transaction` / `BlockHeader` / `Block` wire encoding, `admission::decode_tx_strict` | generated values: the encoding equals an independent encoder (whose PoWit-section framing applies from `powit_height()`), `wire_size` its length, `decode(encode(x)) == x` exactly when `x` is within the parser caps (values at and one past the script-length and parent caps are generated; the count and size caps need 100 KB to 10 MB values and are checked at and one past each cap by the unit test `core::limits::tests::count_and_size_caps_match_the_wire_parser` instead), every proper prefix and one extra byte are refused; untrusted bytes: the strict decoders are the exact inverse of the encoder (`decode(b) = x` implies `encode(x) == b`) |
| `undo_decode` | `UndoData::{from_bytes, to_bytes}` | no panic; decode/encode fixed point; a record without overwrites is byte-identical to the legacy six-field record; the legacy prefix decodes alone; an empty extension is normalised away; trailing garbage and a truncated extension are refused |
| `keystore_decode` | keyfile v1/v2 (`EncryptedKeyfile`, `Wallet::from_encrypted_bytes`), keystore v2/v3 (`Keypair::from_encrypted_bytes`), the spending unlock `Keypair::unlock_for_spending_bytes` (entry point of the keystore v2 -> v3 migration) | arbitrary JSON: no panic, decrypt driven to completion with cheap Argon2 parameters, parameters over the bounds refused before any KDF; the spending unlock never unlocks what the plain load refuses, never migrates without a stated network, and unlocks a keystore v3 only for its own network; library-written keyfiles (fast parameters) round-trip and refuse a wrong password and any altered AEAD-bound field; a keystore v3 written by an independent implementation of the format loads to the same key pair, unlocks for spending with no migration on its own network (or none stated) and not on the other, and refuses an altered network, address, version, ciphertext or KDF output length |
| `address_parse` | `Address::parse`, `parse_for_network`, `FromStr`, `Display` | verdict (value or error kind) equals a reference parser; the canonical form round-trips and differs only by hex case and the Bloch alias; `parse_for_network` accepts the own network only; a one-digit change is `BadChecksum`; a prefix swap keeps the hash (documented residual) |
| `sync_rr_codec` | `/gnb/sync/1` frames: `decode_request`, `decode_response`, `encode_frame`, `check_nonempty_frame`, and the libp2p codec `BlochSyncCodec` (`read_request` / `read_response` / `write_request` / `write_response`) over an in-memory stream | no panic; every refusal is `InvalidData` and an empty frame `UnexpectedEof` (not penalized); every response refusal is penalized except a Tips answer over `MAX_WIRE_TIPS` tips with a locator within its bound (refused without penalty: releases before the re-audit fix B2-T7 sent all their DAG leaves); accepted frames obey every bound and are canonical; both transports enforce the same bounds (a response accepted here passes the gossip decoder, a gossip pull accepted there is accepted here); generated messages round-trip exactly when within bounds; reading a response stream through the codec is exactly `check_nonempty_frame` + the decoder on its first 4 MiB; a request stream is read up to 64 bytes (`MAX_REQUEST_FRAME`): one that reaches 64 bytes, or a shorter frame `decode_request` refuses, reads as `SyncRequest::Malformed` (re-audit B1-T2: libp2p does not report a request that fails to decode, so the codec reports it as a request the network loop penalizes), an empty one is `UnexpectedEof`; every generated request encodes below 64 bytes; writing is `encode_frame` and reads back (`Malformed` for a request out of bounds); a stream past the read cap (a valid frame followed by padding: 64 bytes for a request, 4 MiB for a response) is refused (`Malformed` / a penalized response refusal) |
| `accept_dag` | the message processor's path for a gossiped block: `Block::from_wire_bytes`, then `ingress::BlockIngress::handle_block` (structure without proof of work, the orphan pool with its floor and proof check, the POW-3 work rule, `normalize_wire_metadata`, `accept::accept_block_tracking`, the drain of waiting orphans) and the periodic orphan sweep, on a RocksDB `Storage` in a temporary directory with a real `GhostDAG` | small arbitrary DAGs (up to 6 sealed blocks, PoW-cheap through the crate's `test-pow-limit` feature) with signed spends of funded outputs, conflicting spends, spend chains, version 1 and 3 transactions, broken signatures, missing inputs and deliberate faults (coinbase over-claim, wrong height, wrong difficulty bits sealed at their own easy target so that the difficulty rule is what refuses them, timestamp before a parent, duplicated transaction), under the hardening activation never / from genesis / inside the DAG; no panic, and two different arrival orders of the same block set (orphans buffered in the core's pool and drained when a parent is accepted or by the sweep) end with the same selected tip, applied tip, UTXO set digest and DAG block set; a block with a wrong height, a timestamp before a parent, wrong bits or a duplicated transaction is in neither node's DAG; optionally a reload from storage (`reconcile_on_startup`) keeps that state |

The relaunched mainnet line brought six more targets, smaller ones with no
reference implementation of their own:

| Target | Entry points | What it checks |
| --- | --- | --- |
| `sync_decode` | `network::sync_rr::{decode_request, decode_response}` | no panic |
| `pq_handshake_decode` | `transport::upgrade::{Init, Resp, Finish}` bincode decode, without `handshake_decode`'s size bound | no panic |
| `block_validate` | `Block::from_wire_bytes`, `validate_structure_cheap`, `blockval::validate_block_transactions` against an empty UTXO view | no panic |
| `tx_validate` | `Transaction::from_wire_bytes`, `blockval::validate_tx_inputs` at height 10,000,000 against a view paying every input (1,000 GNB) to the key or policy its witness reveals | no panic; the wire encoding round-trips |
| `policy_witness_decode` | `PolicyWitness::decode`, `SpendPolicy::decode` | no panic; an accepted witness or policy re-encodes to the same bytes; a witness fits `MAX_SCRIPT_SIG_LEN` |
| `script_sig_verify` | `Transaction::parse_script_sig`, `crypto::verify_canonical` | no panic; an accepted witness is exactly `build_script_sig` of its parts |

Round 5 adds `descriptor_json`, exercising the strict public descriptor JSON
parser and shared wallet API. Accepted descriptions must inspect identically;
pool export/import must preserve the complete result; another requested network
must be refused. Its twelve public JSON seeds (eight acceptance controls, four
rejections) are replayed on stable by `node/tests/descriptor_seed_corpus.rs`.
They are selected from `reference/descriptor_vectors.py`; no private keys are
included. The separate CI step `reference/descriptor_differential.py` compares
complete Rust/Python responses, including a deterministic generated campaign.
Round trips alone are not evidence of independent script or checksum equality.
The reusable fuzz workflow discovers this target from Cargo.toml; a configured
target does not establish that a campaign has completed.

The seed corpora of eight of the nine original targets are generated (and
replayed on stable Rust) by `node/tests/parser_corpus_floor.rs`; those of
`header_parse`, of the nine targets added in October 2026 and of the six
mainnet-line targets by `node/tests/fuzz_seed_corpus.rs`, which also
checks that every committed `seed_*` file is reproducible and replays every
corpus file (seeds and crash regressions `regress_*`) through the parsing
entry points on stable Rust (for the mainnet-line targets, through
everything the target does with its bytes). The mainnet-line seeds start on
the accepting paths (`mainnet_line_seeds_reach_their_entry_points`): the
`tx_validate` seeds are signed against the target's view and pass every
rule (one and two single-key inputs, a 1-of-2 policy with timelocks), the
`block_validate` seeds pass the structural checks on mainnet (below the
activation, with the suffix witness commitment, with the PoWit section,
and under the hardening rules). Each corpus stays below 200 KB.

## Defects found

Both are fixed at their root cause, with regression tests and the crashing
input committed to the target's corpus (`regress_*`).

1. **Non-minimal CompactSize varints accepted by the wire decoders; block
   transactions framed by their re-encoded length** (`wire_roundtrip`,
   strict-inverse property). `read_varint` accepted `FD 05 00` for 5 (and the
   5- and 9-byte forms of small values), so every block, header and
   transaction had many byte encodings although `Block::from_wire_bytes` is
   documented as the strict inverse of `to_wire_bytes`; each variant of a
   `NewBlock` payload was also a distinct gossip message. Worse,
   `Block::from_wire_bytes` advanced past each transaction by
   `tx.to_wire_bytes(true).len()`, fewer bytes than the transaction decoder
   had consumed for a non-minimal encoding, and parsed the rest of the block
   from inside that transaction (a crafted block with script length
   `FD 0C 00` and a locktime ending `FD 00` decoded "successfully" that way).
   Fixed in `core/mod.rs`: only minimal varints are accepted (Bitcoin Core's
   `ReadCompactSize` rule) and the block decoder frames each transaction by
   the bytes consumed (`Transaction::read_wire_bytes`). The encoders always
   wrote minimal varints, so nothing produced or stored changes; block ids,
   txids and roots commit to decoded values, so this is not a validity rule.
   It changes which bytes are accepted for a valid block id; the rule, its
   reasoning and the mixed-version consequence are specified in
   docs/CONSENSUS.md ("Wire encoding"), and the consensus vectors
   `decode/non-minimal-tx-count/post` and
   `decode/non-minimal-script-sig-length/pre` pin it for the Rust runners and
   the Python reference: the decoder before the fix (and the Python
   reference before it) accepts both byte strings, the second one (a
   coinbase whose locktime ends `FD 00`) only through the old framing. A
   widened copy relayed by an older node is dropped without a gossip penalty
   (`ingress::verdict_for_block_decode_error`; every byte string the old
   decoder accepts and the new one refuses fails on a non-minimal varint,
   `core::wire_canonical_tests::pre_fix_acceptances_fail_on_a_non_minimal_varint`).
   The reproducer came from a seed written to probe the property (a header
   with a `FD 01 00` parent count); a 200-second run without that seed did not
   rediscover it. Tests: `core::wire_canonical_tests`,
   `node/tests/fuzz_regressions.rs::header_with_a_non_minimal_parent_count_is_refused`.
2. **Non-canonical gossip and sync frames accepted (bincode non-minimal
   varints)** (`netmsg_decode`, canonical-frame property; found in about two
   seconds from the original seed corpus). bincode's decoder accepts a value
   in a longer varint form (`FC 1F 00 00 00` for 31), so one message had many
   byte encodings. Gossipsub message ids are SHA-256 of the frame, so each
   variant was a fresh message id: the de-duplication bypass that audit NET-7
   closed for trailing bytes, reopened through the varints. The `/gnb/sync/1`
   codec had the same gap. Fixed in `network/mod.rs` (`decode_wire_message`
   refuses a frame that is not the re-encoding of its message:
   `WireDecodeError::NonCanonical`, a penalized protocol violation except
   for `NewBlock` / `NewTransaction`, which older releases relay, see
   docs/CONSENSUS.md "Wire encoding") and
   `network/sync_rr.rs` (`decode_request` / `decode_response`, `InvalidData`).
   Tests: `node/tests/fuzz_regressions.rs`. On the integration branch the
   same check arrived first with the sanitizers package (commit `6492ebc`,
   the same hunks), which found it necessary on i686 as well: bincode reads
   declared lengths as `usize`, so a 32-bit node decoded a frame declaring
   2^32 + n bytes as one of n bytes (docs/testing/SANITIZERS.md, F5); there
   it sits next to the libp2p 0.57 codec and its 64-byte request cap.

Each fix was checked by mutation: disabling it makes its regression tests
fail.

The campaign also showed that `header_parse` had no seed corpus (its
directory did not exist: libFuzzer refused to start with it, and CI created
it empty); `fuzz_seed_corpus.rs` now generates one.

## Campaign results (October 2026)

Every target ran under ASan (`cargo +nightly fuzz build`: release, debug
assertions and overflow checks, LeakSanitizer on) for 600 s, `accept_dag` for
1,800 s, starting from its committed corpus (all of it; see below for the
first `accept_dag` run), with `nice -n 15 -jobs=1
-workers=1 -rss_limit_mb=2048 -timeout=120`, two targets at a time on a shared
4-core machine that was also running other builds and mutation tests (the
exec rates are lower bounds). Built with `nightly-2026-10-14` (rustc
1.101.0-nightly 822182db4 2026-10-13, cargo 2026-10-07; the toolchain CI
pins) and cargo-fuzz 0.13.2. The binaries were built from the tree
with both fixes above in place; the later runs (`header_parse`,
`undo_decode`, `address_parse`, `sync_rr_codec`) were rebuilt from the
committed tree (the library code did not change in between, only `#[cfg(test)]`
code). `accept_dag` was re-run on the final tree (below). After the other
runs the library gained only the `gnb::libp2p` re-export and a unit test;
all 18 targets were then rebuilt from the final tree and replayed their
committed corpora with exit status 0. `cov` / `ft` are libFuzzer's covered
edges and features at the end of the run (whole binary), `corpus` the
corpus it ended with.

| Target | Seconds | Executions | exec/s | cov | ft | Corpus (units) | Peak RSS (MB) | Findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `tx_parse` | 600 | 11,433,892 | 19,024 | 380 | 1,121 | 124 | 531 | none |
| `block_parse` | 600 | 14,014,853 | 23,319 | 561 | 1,865 | 225 | 478 | none |
| `header_parse` | 600 | 46,196,287 | 76,865 | 255 | 439 | 39 | 436 | none (first run: no corpus directory, see above) |
| `netmsg_decode` | 600 | 20,998,230 | 34,938 | 1,126 | 2,641 | 269 | 156 | none after fix 2 (found it in ~2 s before) |
| `handshake_decode` | 600 | 13,945,696 | 23,204 | 231 | 489 | 110 | 93 | none |
| `pow_decode` | 600 | 34,419,600 | 57,270 | 519 | 1,002 | 201 | 487 | none |
| `pow_verify` | 600 | 2,744,125 | 4,565 | 274 | 335 | 61 | 405 | none |
| `merkle_path` | 600 | 11,406,970 | 18,979 | 112 | 137 | 24 | 528 | none |
| `mempool_ops` | 600 | 290,038 | 482 | 1,151 | 6,188 | 548 | 514 | none |
| `block_rules` | 600 | 504,144 | 838 | 2,003 | 6,156 | 307 | 477 | none |
| `sighash` | 600 | 1,813,337 | 3,017 | 962 | 3,042 | 223 | 480 | none |
| `witness_parse` | 600 | 2,215,323 | 3,686 | 852 | 1,625 | 147 | 404 | none |
| `wire_roundtrip` | 600 | 500,821 | 833 | 1,548 | 4,886 | 480 | 432 | none after fix 1 |
| `undo_decode` | 600 | 2,074,054 | 3,451 | 1,389 | 4,037 | 395 | 334 | none |
| `keystore_decode` | 600 | 1,437,930 | 2,392 | 5,482 | 14,025 | 2,332 | 476 | none |
| `address_parse` | 600 | 4,318,981 | 7,186 | 626 | 1,151 | 88 | 555 | none |
| `sync_rr_codec` | 600 | 119,432 | 198 | 2,325 | 5,852 | 558 | 558 | none |
| `accept_dag` | 1,800 | 1,287 | 0.7 | 8,000 | 26,649 | 323 | 540 | none (no slow unit) |

No crash, leak, timeout or out-of-memory input after the two fixes.
`sync_rr_codec` also ran 600 s before it drove the libp2p codec (527,601
executions, 877 exec/s, cov 2,033, no finding); the codec checks raised its
coverage to 2,325 edges and lowered the rate (every frame is also read
through the codec, and the read-cap check builds 4 MiB streams). Rebuilt
with the codec trait taken from `gnb::libp2p`, it ran another 120 s (27,278
executions, cov 2,304, no finding).

`accept_dag` is slow by construction: every block it has not built before
costs one GnB-SMH evaluation (a 64 MiB scratchpad) to seal, which dominates
under ASan and coverage instrumentation (13 of 15 stack samples of a running
campaign were in `gnb_smh::hash_with`, the other two in RocksDB opening its
temporary databases). An input of up to six blocks took 1.4 s on average in
the run above (2.6 s, and up to 10 s, in the first run on a busier machine);
libFuzzer reports a unit of 10 s or more as `slow-unit` (the per-input
timeout is 120 s).

The row above is the second `accept_dag` campaign, a re-run of the target
after two corrections, from the whole committed corpus (12 seeds: the 6
original programs, the 4 DAG-1 scenarios and 2 wrong-bits programs). The first 1,800 s
run (703 executions, cov 8,080, no finding) is not a valid result for the
current target: it started from the 6 original seeds only (the 4 DAG-1
scenario seeds were committed nine minutes after it started, and were only
replayed, never fuzzed from), and its wrong-bits fault never reached the
difficulty rule. That fault gave the block the genesis bits (a target of
about 2^-12) and left it unsealed, so `validate_structure` refused it as an
invalid proof of work every time; the fault now uses a wrong target within
the pow limit that seals in one or two evaluations (`0x2100FFFE` or
`0x21008000`), and the target also asserts that a block with a wrong
height, a timestamp before a parent, wrong bits or a duplicated transaction
is never accepted.

Replaying the whole final corpus of the run above (318 inputs: the 12 seeds
and the 306 it added; activation never, from genesis, inside the DAG and at
the mainnet height) with `ACCEPT_DAG_LOG=1` shows the pipeline both
accepting and rejecting, for many different reasons: of 1,173 deliveries in
the first arrival order, 563 were accepted; the others were rejected in
their chain context for a missing UTXO (197), an invalid selected parent
(120), a coinbase over-claim (25), a double spend (6), descent from an
invalid block (3), BIP30 (an output that would overwrite an unspent coin,
2), a transaction version not allowed at the height (2) or an invalid
signature (2, and 1 body rejected without poisoning the block id); and
outside it for a duplicated transaction (94), a timestamp before a parent
(71), wrong difficulty bits (44: `invalid difficulty: block bits 0x2100fffe`
26 times, `0x21008000` 18 times) and a wrong height (43). No block was
refused as an invalid proof of work.

### After the merge into the integration branch

The package was written on `b6a2976` and merged after the mempool/relay
(P4), networking/storage (P5), block-ingress (P3), mutation-testing,
consensus-vector and sanitizer packages. Three targets were adapted to the
APIs those packages changed:

* `accept_dag` delivered blocks to `accept::accept_block` behind
  `validate_structure`, retrying orphans itself. P3 replaced the processor's
  `NewBlock` handling with `ingress::BlockIngress`, so the target now
  decodes each block from its wire bytes and hands it to
  `BlockIngress::handle_block` (structure without proof of work, the orphan
  pool, the POW-3 work rule, `normalize_wire_metadata`,
  `accept_block_tracking`, the orphan drain), then runs the processor's
  orphan sweep. The sweep matters: an orphan whose parent is stored but
  disqualified (an over-claiming coinbase) is not drained by that parent's
  own acceptance, only by the sweep. With the sweep removed from the harness
  the target stopped in 14 s with `arrival order changed the outcome`.
* `sync_rr_codec` modelled a 4 MiB read for requests too; P5's codec reads
  at most 64 bytes of a request stream (`MAX_REQUEST_FRAME`) and refuses one
  that reaches 64 bytes. The model now follows that, every generated request
  must encode below 64 bytes, and a request padded to the cap must be a
  penalized refusal.
* `keystore_decode` also drives P5's `Keypair::unlock_for_spending_bytes`
  (see the targets table).

Every target was rebuilt from the merged tree with `nightly-2026-10-14` and
cargo-fuzz 0.13.2, without a sanitizer (`-s none`; release, debug
assertions; disk space), and every committed corpus replayed with exit
status 0. Then each target except `pow_decode`, `pow_verify` and
`merkle_path` (library code unchanged; replayed only) ran from its committed
corpus, three at a time at `nice -n 10` on the shared 4-core machine:

| Target | Seconds | Executions | Findings |
| --- | ---: | ---: | --- |
| `accept_dag` | 900 | 1,186 | none |
| `sync_rr_codec` | 300 | 220,440 | none |
| `keystore_decode` | 300 | 8,738,026 | none |
| `wire_roundtrip` | 300 | 3,209,623 | none |
| `block_rules` | 120, then 300 | 456,781, then 7,103,962 | one harness defect (below), none after its fix |
| `sighash` | 120 | 3,482,523 | none |
| `netmsg_decode` | 120 | 40,152,150 | none |
| `witness_parse`, `undo_decode`, `address_parse`, `mempool_ops`, `block_parse`, `header_parse`, `tx_parse` | 60 each | 775,763; 3,143,813; 1,918,612; 312,448; 13,710,017; 39,930,910; 10,142,540 | none |
| `handshake_decode` | 30 | 23,366,454 | none |

The `block_rules` finding was in the target, not the library: its reference
treated activation `NEVER` as "legacy rules at every height", but
`activation::is_active_at` is `height >= activation` and `NEVER` is
u64::MAX, so a decoded block claiming height u64::MAX is under the hardening
rules even with `NEVER` (no block can reach that height: its parents would
be at u64::MAX - 1). The library has behaved this way since before the
package; the reference now uses the same predicate, and the input is in the
corpus as `regress_height_u64_max_under_never`.

Replaying the 12 `accept_dag` seeds with `ACCEPT_DAG_LOG=1` through the
ingress core: of the deliveries in the first arrival order, 16 were
accepted, 4 buffered as orphans (children of refused blocks), and the rest
refused for a missing UTXO (6), a timestamp before a parent (2), wrong
difficulty bits (2), an invalid selected parent (2), a coinbase over-claim
(2), a wrong height (1) and a duplicated transaction (1).

### The first CI run of the merged tree

The merge of the relaunched mainnet line had not been fuzzed in CI (the job
does not run on pushes). Its first run on the pull request (run
38873936215, at `c9fdb6d`) failed nine targets:

* `tx_validate`, `block_validate`, `policy_witness_decode`,
  `pq_handshake_decode`, `script_sig_verify` and `sync_decode`, the targets
  of the mainnet line, had no committed seed corpus. `fuzz_seed_corpus.rs`
  now generates one for each (above).
* `witness_parse`, `sighash` and `block_rules`, targets of the hardening
  branch, checked specifications the merge had changed. In each case the
  library follows the specification of the merged tree and the target was
  corrected:
  * `witness_parse` (crash after 76 executions): it asserted the historical
    lenient framing (`parse_script_sig_borrowed` ignoring bytes after the
    public key). This chain made the single-key `script_sig` exact at every
    height in cc5c450, so the three parsers are one exact parser and a tail
    is refused by each of them and by both witness rules.
  * `sighash` (every seed): its v2 reference was the hardening branch's
    digest, a bincode body under version byte 0x01. Sighash v2 here hashes
    the stripped transaction's wire encoding under version byte 0x02
    (`reference/gnb_sighash.py`); the reference is rewritten from that.
  * `block_rules`: its repair of a decoded block predated re-audit B2-T10
    (from the activation each parent is listed once), so a block whose
    header repeats a parent, repaired otherwise to the specification, was
    refused by the library and the target reported `a block repaired to the
    specification is rejected` (`64-byte transaction accepted` when the block
    also carries a 64-byte transaction: the parent rule runs first). The
    repair now lists each parent once, and the target checks the
    distinct-parents rule and the order of the body rules against
    references.

The job log the API returns holds only its last 5,000 lines (from the end of
`tx_parse` on), and the uploaded reproducers could not be downloaded from the
machine that did this work, so only the `witness_parse` input came from CI.
The others were reproduced on stable Rust: the target bodies, compiled into
a throwaway test, ran over the committed seeds and random mutations of them
(`sighash` failed on its first seed; `block_rules` failed once a seed's
parent was listed twice). Both crash inputs fail the old target bodies and
pass the corrected ones; they are in the corpora as
`witness_parse/regress_trailing_bytes_after_witness` and
`block_rules/regress_duplicate_parent`, and pinned with the specified
behaviour by `node/tests/fuzz_regressions.rs`.

`tx_validate` also had a defect no run could report: its view paid every
input `u64::MAX / 4`, more than `MAX_SUPPLY_SAT`, so `validate_tx_inputs`
stopped at the first input (`input overflow`) and no input reached the
witness, policy or signature checks the target is about. The view now pays
1,000 GNB per input, and the target's seeds are signed against it.

The corrected and the newly seeded targets then ran in the same stable
harness (debug build, so far fewer executions than libFuzzer) with no
finding: `block_rules` 200 s (73,976 executions) plus 180 s (36,731) of
structural mutations (parents repeated or dropped, heights at the
activation, PoWit and witness-commitment boundaries, transactions added,
removed and duplicated, shielded transactions, PoWit shares), `sighash`
200 s (1,292,820), `witness_parse` 200 s (1,440,562), `tx_validate` 300 s
(49,361,225), `block_validate` 200 s (27,637,996), `policy_witness_decode`
150 s (24,486,901), `script_sig_verify`, `pq_handshake_decode` and
`sync_decode` 60 s each (24,528,548; 2,363,068; 7,201,992).

### Do the targets detect what they are meant to detect?

Besides the two real defects (whose fixes were each checked by disabling
them: the regression tests then fail), each new target was rebuilt from a
scratch copy in which its independent reference or harness (the test side,
never the library) was altered, and run over its committed corpus. A
differential assertion that never ran, or compared values that do not depend
on the input, would not notice; each target stopped with the expected
assertion within seconds:

| Target | Test side altered | Detected after | Assertion |
| --- | --- | ---: | --- |
| `block_rules` | witness root over txids instead of wtxids | 1 s | `witness root` |
| `sighash` | v3 spent scripts hashed without their length prefix | 1 s | `sighash v3 differs from the specification` |
| `witness_parse` | reference claims the whole `script_sig` is consumed | < 1 s | `exact parser differs from the reference` |
| `wire_roundtrip` | CompactSize single-byte form ends at 0xFB | 3 s | `transaction encoding differs from the reference` |
| `undo_decode` | legacy record fields in another order | 1 s | legacy record equality |
| `keystore_decode` | independent v3 writer omits the network byte of the associated data | 1 s | `library refuses a keystore v3 written to the specification` |
| `address_parse` | reference checks 3 of the 4 checksum bytes | < 1 s | `parse differs from the reference` |
| `sync_rr_codec` | expected read result without `check_nonempty_frame` | 1 s | `read_request: error kinds differ` |
| `accept_dag` | arrival order B never retries a block whose parent is unknown (the harness before the merge, which retried orphans itself) | 9 s | `arrival order changed the outcome` |
| `accept_dag` | the wrong-bits fault silently builds a valid block (the expected bits) | 20 s | `b0 with wrong difficulty bits was accepted` |

## Known limits

* CI starts every run from the committed seeds: the corpus a run grows is
  not kept (only crash reproducers are uploaded), so the weekly campaign does
  not accumulate coverage from week to week.
* `accept_dag` executes one input every 1.4 to 2.6 s on average (above):
  the 60-second pull-request run sees a few dozen DAGs, the weekly 10-minute
  run a few hundred.
* `accept_dag` runs with gnb-crypto's `test-pow-limit` feature (one
  evaluation seals a block): the expected bits are always the
  pre-activation pow limit and `validate_pow` enforces that limit at every
  height. Neither the ASERT schedule nor the hardened pow limit of audit
  POW-3 (the genesis target from the activation on) is exercised by it, in
  any of its activation regimes. Both are covered only by gnb-crypto's own
  tests, run without the feature (`expected_bits_at`, `pow_limit_bits_at`,
  `validate_pow` at the hardened limit; CI job `consensus-crates`), and the
  ASERT arithmetic by `pow_decode` (with the pre-activation pow limit).
* `wire_roundtrip` reaches the script-length and parent caps only; the count
  and size caps (inputs, outputs, block and shielded transactions,
  nullifiers, shielded outputs, proof, binding signature) are checked by a
  unit test, not fuzzed.
* `accept_dag` drives the processor's ingress core, but on DAGs of at most
  six blocks its anti-DoS rules admit every block: the POW-3 work threshold
  is 0 below `ANTI_DOS_WINDOW_BLOCKS` (360) selected-chain blocks, no block
  is deep below the tip, and under `test-pow-limit` the orphan floor is the
  pow limit. `LowWork`, the deep-backfill budget and orphan-pool eviction
  are covered by the node's tests (`node/tests/fix_chain_selection.rs`,
  `node/tests/fix_net_ingress.rs`, `ingress` unit tests), not here. The
  orphan floor gate in `BlockIngress::handle_block` (`OrphanBelowFloor`)
  was covered by no test before Phase 4: under `test-pow-limit` the floor
  is the pow limit, so every test build admitted every decodable bits value
  there, and the tests named here checked only the floor's helper
  functions (re-audit, POW-4 residual). It is covered since Phase 4 by
  `node/tests/fix_ingress_dos.rs::pow4_floor_gate_refuses_before_the_proof`,
  which sets a stricter reference target through a test seam
  (`BlockIngress::with_reference_target`); the global orphan bound's
  arrival-order eviction by
  `fix_ingress_dos::pow4_global_orphan_bound_evicts_by_arrival_not_height`.
  Still not here: the orphan sweep runs once after the last delivery (in
  the node it runs every 30 s), and blocks arrive unsolicited from no peer.
* The async read of the sync codec is driven over an in-memory stream; the
  libp2p substream and muxer underneath are not fuzzed.
* `keystore_decode` drives the decryption to completion only for Argon2
  parameters up to 64 KiB / 2 passes / 2 lanes (larger ones are checked at
  the parsing and bounds layer only).

## Reproducing

Prerequisites: a nightly toolchain, `cargo install cargo-fuzz`, and clang /
libclang for `librocksdb-sys`.

```sh
cp Cargo.lock node/fuzz/Cargo.lock      # start from the audited lockfile
cd node/fuzz
cargo +nightly fuzz build               # every target, ASan, debug assertions
cargo +nightly fuzz list

# One target over its committed corpus (new inputs go to the first directory):
mkdir -p /tmp/new
cargo +nightly fuzz run sighash /tmp/new corpus/sighash -- \
    -max_total_time=600 -rss_limit_mb=2048 -timeout=120 -print_final_stats=1

# Replay one input (a CI artifact, or a corpus file):
cargo +nightly fuzz run wire_roundtrip corpus/wire_roundtrip/regress_nonminimal_parent_count

# accept_dag: print the verdict of every delivery (first arrival order):
ACCEPT_DAG_LOG=1 cargo +nightly fuzz run accept_dag corpus/accept_dag/seed_0010_38

# Minimize a crash, or the corpus:
cargo +nightly fuzz tmin <target> <crash file>
cargo +nightly fuzz cmin <target>
```

The campaign above ran each binary directly (`target/x86_64-unknown-linux-gnu/
release/<target>`) with `nice -n 15 <binary> -jobs=1 -workers=1
-rss_limit_mb=2048 -max_total_time=600 -timeout=120 -print_final_stats=1
-artifact_prefix=<dir>/ <scratch corpus> corpus/<target>`.

Regenerate the generated seeds after changing a generator:

```sh
GNB_WRITE_FUZZ_SEEDS=1 cargo test -p gnb --test fuzz_seed_corpus   # new targets
cargo test -p gnb --test parser_corpus_floor generate_seed_corpus  # original targets
```

## Continuous integration

`.github/workflows/fuzz.yml` builds every target with ASan on a pinned
nightly (`FUZZ_TOOLCHAIN`, `nightly-2026-10-14`, the toolchain of the
campaign above; bump it deliberately) and runs each one over its committed
corpus. `ci.yml` calls it on every pull request and in the nightly run with
60 seconds per target; its own weekly schedule (Sunday 06:23 UTC, not the
minute of mutants.yml's weekly run) runs 10 minutes per target, and a manual run takes the time as an input. A crash, leak, timeout
(120 s per input) or out-of-memory input (2 GB) fails the job, and every
reproducer libFuzzer wrote is uploaded as the `fuzz-artifacts` artifact. The
job also fails when `cargo fuzz list` fails or does not list every `[[bin]]`
of `node/fuzz/Cargo.toml` (it can never pass having fuzzed nothing), and when
a target has no committed seed corpus.

Only the downloaded crate sources are cached (key: toolchain and
lockfiles). The ASan target directory (measured locally: about 5 GB of
dependencies plus about 0.4 GB per target binary) is rebuilt on every run:
caching it would take most of the repository's 10 GB cache budget from the
other jobs, and any change to the node's code rebuilds the targets anyway.
