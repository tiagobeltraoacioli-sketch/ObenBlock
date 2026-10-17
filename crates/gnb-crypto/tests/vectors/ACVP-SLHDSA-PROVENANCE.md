# Official NIST ACVP SLH-DSA-SHAKE-128s vectors (FIPS 205)

Source: NIST's [ACVP-Server repository](https://github.com/usnistgov/ACVP-Server),
pinned commit `975de31eb83d87039ec88934fdc47d8c312b892d` (the commit the
ML-DSA fixtures use). Original files, downloaded without transformation:

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json` | 75,294 | `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920` |
| `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json` | 38,178,342 | `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba` |
| `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json` | 30,731,848 | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` |

(`internalProjection.json` is NIST's join of `prompt.json` and
`expectedResults.json` for each vector set.) URL form:
`https://raw.githubusercontent.com/usnistgov/ACVP-Server/<commit>/<path>`.

`extract-acvp-slhdsa.py <dir> acvp-slhdsa-shake128s.json` checks the three
digests and keeps the SLH-DSA-SHAKE-128s groups with the pure external or the
internal signature interface (GnB never pre-hashes, so the `preHash` groups
26 and 62 are left out):

| Mode | Groups (tgId) | Cases |
| --- | --- | --- |
| keyGen | 2 | 10 (tcId 11–20) |
| sigGen | 25 (pure, deterministic), 61 (pure, hedged), 34 (internal, deterministic), 70 (internal, hedged) | 28 |
| sigVer | 25 (pure), 34 (internal) | 28 (4 valid; 6 with a 7,855- or 7,857-byte signature) |

Hex is lower-cased. sigGen's expected signatures are replaced by their SHA-256
(`signatureSha256`, plus `signatureLen`); the test hashes the signature it
produces. sigVer drops the secret keys NIST includes; every set drops the
unused `deferred`, `hashAlg` and `reason` fields. No expected value is computed
by GnB code. Extracted fixture: `acvp-slhdsa-shake128s.json`, 890,119 bytes,
SHA-256 `fe1ee7daa6f985255e41735fb23afadfddd9cee473c4e3ab6df79ceb689dfd00`
(pinned by `tests/acvp_slhdsa.rs`).

## What the test proves

`tests/acvp_slhdsa.rs` checks, through the production wrapper
`gnb_crypto::crypto::slhdsa` and its pinned `fips205 =0.4.1` backend:

- key generation from the three seeds (FIPS 205 Algorithm 18) reproduces all
  10 official key pairs;
- pure signing (Algorithm 22) with the official context and `opt_rand`
  (`PK.seed` for the deterministic variant, `additionalRandomness` for the
  hedged one) reproduces all 14 official signatures;
- the internal signing function of the backend (Algorithm 19) reproduces the
  14 internal-interface signatures;
- pure verification (Algorithm 24) gives all 14 official verdicts (2 valid,
  12 invalid including the wrong lengths), and the backend's internal
  verification (Algorithm 20) the 14 internal ones;
- the consensus verifier `slhdsa::verify` (empty context) accepts the official
  valid empty-context cases (sigVer tcId 343; the signatures of sigGen tcId
  215 and 530) and rejects every valid case that carries a non-empty context.

This is conformance evidence for the parameter set and interfaces GnB uses on
the build that runs the test (x86_64 in CI). It is not ACVP certification or
FIPS validation, and it does not qualify other parameter sets or the pre-hash
interface. Determinism across platforms rests on SLH-DSA being integer-only
hashing (no floating point) and is cross-checked by the independent second
implementation (`tests/slhdsa_differential.rs`, RustCrypto `slh-dsa`).
