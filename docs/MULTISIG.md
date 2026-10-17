# Multisig and timelocks

GnB has no script language. A script interpreter is the largest consensus
attack surface Bitcoin has, so GnB instead defines exactly two output types
(`crates/gnb-crypto/src/core/policy.rs`):

| Output script | Address | Spent by |
| --- | --- | --- |
| 20 bytes: `SHA3-256(pubkey)[..20]` | `gnb1q…` / `gnb1t…` | one hybrid ML-DSA-65 ‖ Falcon-1024 signature |
| 33 bytes: `0x02 ‖ SHA3-256("GNB-POLICY-v1" ‖ policy)` | `gnb1m…` / `gnb1n…` | the policy plus `m` signatures |

Any other output script is invalid (it used to be an unspendable burn).

## Spend policies

A policy is:

- **m-of-n multisig**: 1 ≤ m ≤ n ≤ 7 distinct hybrid keys (each 3,749 bytes
  enveloped, or 3,745 bytes raw for a genesis carry-over key). From the
  second hardening height a key may also be a conservative suite-0x0003 key
  (SLH-DSA-SHAKE-128s AND Falcon-1024, 1,829 bytes, signatures up to 9,322
  bytes), mixed freely with hybrid keys; below it a policy listing one is
  invalid (`docs/CONSENSUS.md`, "Conservative suite 0x0003"). `policyaddress`,
  `policyspend` and `policysign` carry such keys; the PQ-PSBT format and the
  vault commands do not yet. Distinct means
  distinct keys, not distinct byte strings: the raw and the enveloped
  encoding of one key are the same signer (`core::policy::key_identity`,
  PF-4). `gnb-cli policyaddress`, `vaultcreate` and every other tool
  (`SpendPolicy::new`) refuse a policy that names one key twice at every
  height, and every vault command refuses a published vault file that does
  (`Vault::tree`); from the second hardening upgrade such a policy cannot be
  spent, and the spend tools (`policyspend --next-height`, `policysign`,
  the PQ-PSBT roles) refuse to build, sign or finalize a spend of it for a
  block at or above that height (`docs/CONSENSUS.md`, "Spend-policy key
  identity"). Below it the old rule holds (byte-wise distinct), under
  which, with sighash v3, one signer fills both slots of such a key;
- **`after`** (absolute timelock): spendable only by a transaction whose
  `locktime ≥ after`. `0` = none;
- **`older`** (relative timelock): spendable only `older` blocks after the
  output confirmed (counted in the depth measure of the spending block's
  regime, docs/CONSENSUS.md, "Coinbase maturity"; an output of the genesis
  ledger, such as a vesting tranche, is confirmed at the genesis). `0` = none.

The output commits only to the policy's hash. The spender reveals the policy
and exactly `m` signatures, tagged with strictly increasing key indices, in
the strict enveloped canonical form. Encodings are canonical, so one policy
has one hash.

## Transaction locktime

`locktime` is a block height: a transaction is valid only in a block at
height ≥ `locktime` (`0` is always valid). It applies to every transaction,
not only to policy spends.

## Validation

One implementation (`node/src/blockval.rs`) serves block validation, reorgs,
`sendrawtransaction`, gossip admission and block templates. Templates are
built only from transactions valid together at the template height, and
invalid mempool entries are evicted, so a time-locked or conflicting
transaction can never make a mined block invalid.

The txid excludes `script_sig`. The block id commits to every witness from
`WITNESS_COMMITMENT_HEIGHT` (5,000; the coinbase's `|wc:` suffix) and at/after
the hardening activation (the coinbase commitment), so there every failure
marks the block invalid. Only a block below both heights can be re-sent with
other witness bytes under the same id: there a failure that depends on the
revealed witness (the policy's framing, its hash, its timelocks and branch,
the signatures) rejects the copy received but never marks the block invalid
(docs/CONSENSUS.md, "Coinbase commitment").

The revealed policy (or policy-tree branch with its Merkle path) is checked
against the spent output first, before any of its fields is read; the
timelocks are those of the policy the output commits to. A made-up policy is
the same witness failure as a bad signature (audit F1: it used to be read
first, and a made-up `older` asked for the confirmation of an output that
has no transaction, such as a vesting tranche, which stopped the node).
Timelock failures are witness failures too, classified like the signatures
(another branch of a policy tree may satisfy them).

## Witness sizes

A policy witness carries the whole policy (every key) plus `m` signatures, so
it grows with both `n` and `m`. Measured (`node/tests/policy_spend_transport.rs`):

| Policy | Witness (`script_sig`) |
| --- | --- |
| 1-of-1 | 8,361 B |
| 1-of-2 | 12,112 B |
| 2-of-3 | 20,455 B |
| 3-of-5 | 32,547 B |
| 7-of-7 | 58,402 B |

The transaction decoder accepts a `script_sig` up to
`MAX_SCRIPT_SIG_LEN` = `policy::MAX_POLICY_WITNESS_LEN` (114,834 B), the
largest witness the policy parser can accept. Before this limit was tied to
the parser it was 10,000 B, so every policy with more than one key was valid
by consensus but could not be relayed, mined or stored. That test round-trips
each shape through the transaction and block wire formats, storage, the
mempool and block validation.

## Using it (`gnb-cli`)

```sh
# Each participant: export the public key.
gnb-cli pubkey alice.json > alice.pub

# Anyone: 2-of-3 address, each deposit locked for 144 blocks (~72 min).
gnb-cli policyaddress 2 alice.pub bob.pub carol.pub --older 144
#   address: gnb1m…   policy: 0102…   ← keep the policy hex

# Fund it like any address.
gnb-cli send wallet.json gnb1m… 10

# List its UTXOs.
gnb-cli getutxos gnb1m…

# Anyone: unsigned spend (change returns to the policy).
gnb-cli policyspend policy.hex gnb1q… 1.5 --utxo TXID:VOUT:SATS --out spend.json

# Each signer, on their own machine (the spend file travels, keys do not).
gnb-cli policysign spend.json alice.json
gnb-cli policysign spend.json carol.json

# Anyone: combine and broadcast.
gnb-cli policysend spend.json
```

`policysign` prints the outputs before asking for the password; check them.

## Policy trees (alternative branches)

From `core::powit_height()` (on in testnets, **off on mainnet**), a policy
output can commit to 2 to 4 alternative branches. Each branch is an ordinary
policy, m-of-n plus its own `after` and `older`:

```text
leaf_i     = SHA3("GNB-POLICY-v2/leaf" ‖ branch_i)       empty leaves pad to a power of two
node       = SHA3("GNB-POLICY-v2/node" ‖ left ‖ right)
commitment = 0x02 ‖ u8(n_branches) ‖ root
script     = 0x02 ‖ SHA3("GNB-POLICY-v1" ‖ commitment)    the same 33-byte output type
```

A spend reveals one branch, its index and its Merkle path (witness tag
`0x03`), then that branch's signatures. The branch's own timelocks apply, and
the other branches stay private. Before activation a branch witness is
invalid, so a tree output can be created but not spent.

## Bridge vault (`gnb-cli`)

The Bloch bridge vault is a two-branch tree: branch 0 is `k`-of-`n` signers
with no timelock, and branch 1 is `r`-of-`s` cold keys after a long `older`.
See [SIDECHAIN-BLOCH.md](SIDECHAIN-BLOCH.md).

```sh
# Deployment, once: write and publish the vault definition.
gnb-cli vaultcreate vault.json --testnet --release 3 s1.pub s2.pub s3.pub s4.pub s5.pub \
        --recovery 2 c1.pub c2.pub c3.pub --older 1051200

# User: lock GNB for an L2 address (vault in output 0, 20-byte destination marker in output 1).
gnb-cli vaultlock wallet.json vault.json 10 0xAbC…

# Signer: verify a lock on its own node (JSON verdict; --finalized uses PoWit finality).
gnb-cli vaultchecklock vault.json <txid> --min-conf 1000

# Release after a finalized burn: build, check on each signer, sign k times, send.
gnb-cli vaultrelease vault.json <burn_id> gnb1t… <burn_sats> --utxo TXID:VOUT:SATS --out rel.json
gnb-cli vaultcheckrelease vault.json rel.json <burn_id> gnb1t… <burn_sats>   # each signer
gnb-cli policysign rel.json signer.json                                     # k signers
gnb-cli policysend rel.json

# Disaster only: cold keys, valid `older` blocks after each deposit confirmed.
gnb-cli vaultrecover vault.json gnb1t… 10 --utxo TXID:VOUT:SATS --out rec.json
```

`GNB_WALLET_PASSWORD` replaces the password prompt, so signer programs can
run unattended.
