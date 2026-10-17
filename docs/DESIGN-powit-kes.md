# PoWit KES: forward-secure witness keys ("Proof of Context and Time")

Status: **implemented** (`crates/gnb-crypto/src/core/kes.rs`, commit 7feeb99) and
consensus from `core::powit_height()` (mainnet 10,000; testnet off unless
`--powit-height`). Tested by
unit tests and on a 3-node testnet, including signing with a stolen key file.

## Problem

Finality by signatures has one classic weakness: **long-range attacks.** Keys
that were witnesses a year ago may later leak, be sold, or be retired
carelessly. With them an attacker can sign an alternative history from that
time and present it to a node that is syncing from scratch. Old signing keys
are a liability for as long as they exist.

## Idea

A witness key **evolves once per PoWit epoch, and the previous epoch's secret
is erased.** A signature for a checkpoint in epoch `e` must use the leaf key
of epoch `e`. Once a witness has moved past `e`, nobody can produce such a
signature again, the witness included, so stolen keys cannot rewrite the past.

This is a key-evolving signature scheme (KES, as in Cardano's Ouroboros),
built from GnB's hybrid ML-DSA-65 ‖ Falcon-1024 signatures and a SHA3 Merkle
tree, so it stays post-quantum.

## Construction

```
seed_0              random 32 bytes (the only secret ever stored, encrypted)
seed_{i+1}        = SHA3("GNB-KES-v1/step" ‖ seed_i)            one-way
leaf_i            = hybrid keypair from SHA3("GNB-KES-v1/leaf" ‖ seed_i)
L_i               = SHA3("GNB-KES-v1/pk" ‖ pk_i)
root              = Merkle(L_0 … L_{2^depth − 1})
witness id        = SHA3("GNB-KES-v1/id" ‖ u8(depth) ‖ root)[0..20]
```

- **Key generation:** derive every leaf once, keep only the leaf hashes
  (2^depth × 32 bytes, public) and `seed_0`, encrypted with the witness
  password (Argon2id + AES-256-GCM, the wallet format).
- **Evolve to epoch `e`:** replace the stored seed with `seed_e` and write it
  to disk atomically **before** signing anything in `e`. Earlier seeds cannot
  be recomputed from `seed_e`. In memory (audit CRY-4) the seed lives in a
  locked, wiped `SecretBytes` region and each step overwrites it in place;
  the hash states that held earlier seeds and every leaf key (generated in
  secret memory for one signature) are wiped, and the stack is scrubbed
  after key generation, evolution and signing, so an earlier seed is not
  left in RAM, swap or a core dump (`docs/RUNNING.md`, "Secret key memory").
- **Sign in epoch `e`:** `(e, pk_e, Sign(leaf_e, msg), auth_path_e)`.
- **Verify:** `H(pk_e)` and the path must give `root`, `e` must equal the
  epoch of the attestation's target, and the hybrid signature must verify
  canonically.

| Parameter | Value |
| --- | --- |
| Depth | 12 (4,096 epochs: ~2.8 years at 6 h epochs on mainnet) |
| Keygen | 4,096 hybrid keypairs, a few minutes once (Falcon dominates) |
| Signature overhead | `pk_e` (~3.7 KB) + signature (~4.6 KB) + path 12 × 32 = 384 B + index |
| Stored secret | 32 bytes (`seed_e`), encrypted |

When a key runs out of epochs, the operator creates a new one. Witness weight
comes from share work over the last window, so a new identity only has to
mine shares again.

## Consensus changes (PoWit format v2)

1. **Attestation:** carries `(depth, root, KesSignature)` instead of a plain
   public key and signature. Its witness id is derived from `(depth, root)`.
2. **Epoch binding:** the KES index must equal `epoch(target.height)`. A link
   to a checkpoint can only ever be signed with that epoch's leaf.
3. **Witness shares name their witness:** a share gains a `witness` field (the
   KES witness id), bound into the share's PoW input. Weight goes to the
   witness id; the payout can be any valid script (a cold-wallet address).
   Identity is separate from money.
4. **Equivocation proofs:** unchanged in shape. Both attestations must verify
   under the same witness id.
5. **The signed message commits the key** (from the second hardening
   activation, for attestations whose target is at or above it; PoWit audit
   finding 1). `kes::verify` checks only that the leaf hash and the supplied
   path reach the root, so with a message that does not name the key, one
   leaf's signature re-rooted under any sibling hash verified as a signature
   by another key, one SHA3 per key: a single double vote gave an unlimited
   supply of valid equivocation proofs against keys nobody holds. The v2
   message adds `u8(depth) ‖ root` (docs/CONSENSUS.md, "PoWit", "Attestation
   messages"), so a signature is valid for exactly one key; from the same
   activation a block may carry a proof only against a witness of the
   evidence epochs.

## Context binding (transactions, optional, later)

The same idea for transactions: a sighash may commit to an **anchor**, a
recent block hash plus a validity window. The transaction is then valid only
on a chain that contains that block, and only until the window closes. This
gives replay protection across forks and expiry for stale transactions. It is
a separate, optional sighash flag and is not part of this change.

## What it does not solve

- **Ever-saved old seeds:** if an operator backs up `seed_0` and keeps the
  backup, forward security is lost for that operator. Rule: back up nothing
  but the current encrypted seed, and treat older backups as toxic.
- **Restoring an old backup** can make a node sign an earlier epoch again.
  The node keeps the highest source and target heights the key signed, in
  its vote record and beside the key file (`<key>.votes-highwater.json`, so
  it moves with the key onto a fresh data directory), and never signs a
  link with a lower source or a target not above them (EIP-3076's minimal
  slashing protection). The key file, the record and the high-water file
  are written durably (fsync of the file, rename, fsync of the directory)
  before a signature is released, and a record or high-water file that
  exists but cannot be read makes the witness refuse to start instead of
  reading as "no votes". Losing the record AND the high-water file together
  with an old backup can still produce a double vote, and the key would be
  barred.
- **A key compromised in the current epoch** can still sign the current and
  future epochs until the operator rotates. That is unchanged from today.

## Tests

- Sign and verify for every leaf at a small depth.
- A wrong index, a tampered path, or another root fails.
- After evolving to `e`, signing any `e' < e` is impossible.
- Old secrets are not derivable from the stored state.
- The PoWit state machine accepts KES attestations, rejects a mismatched
  epoch index, and proves equivocations across leaves.
- A live testnet repeats the three adversarial tests with KES keys.
