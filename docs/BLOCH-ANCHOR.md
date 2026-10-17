# Bloch checkpoint anchors

ObenBlock periodically records the latest **finalized checkpoint of Bloch**
(FFG `finalized.epoch`, `finalized.root`, `finalized_height`) in an ordinary
transaction. Once that transaction is buried under the chain's proof of work
(and PoWit finality), rewriting Bloch history behind the anchored checkpoint
also means contradicting a public, timestamped record on another chain.
Anyone can check an anchor against Bloch with read-only RPC calls. Until the
relaunch lands, the code does this on the GnB chain, under GnB-SMH proof of
work. This is the Bloch-to-ObenBlock half of the mutual anchoring; the other
half, ObenBlock's finalized checkpoints recorded in Bloch, is specified in
[DESIGN-obenblock.md](DESIGN-obenblock.md) §8 and not implemented yet.

Nothing here is a consensus rule on either chain. No node needs to upgrade.

## Transaction format (version 1)

An anchor is a payment from the anchoring wallet back to itself:

| output | script_pubkey | value |
|---|---|---|
| 0 | 33 bytes: `0x02 ‖ root` (Bloch finalized checkpoint root) | exactly 546 |
| 1 | 20 bytes: `"BLA1" ‖ epoch (u64 BE) ‖ finalized_height (u64 BE)` | exactly 546 |
| 2+ | change to the anchoring wallet | |

Both markers are valid output kinds (`core::policy::output_kind`): a policy
hash and a key hash. Nobody can spend them (that would need a policy tree
hashing to the Bloch root, or a key hashing to the epoch marker), so they
stay in the UTXO set and an anchor remains findable after nodes prune its
block body. 546 base units is the dust threshold, the same value as the
bridge markers (`bridge::MARKER_VALUE`); zero-value outputs are non-standard.

Parsing is exact (`bloch_anchor::parse_anchor`): order, lengths, tag, magic
and values must all match.

## Who to trust

An anchor proves that **its signer** saw the checkpoint as finalized no later
than the GnB-SMH block holding it. Verifiers decide whose anchors count:
`blochcheckanchor --anchorer gnb1…` accepts only anchors signed by that
address (the input public keys are hashed and compared). The anchoring
address is published with each deployment.

The anchoring program checks before it signs: every run reads `getchaininfo`
from at least two Bloch RPC sources and anchors only when all answers agree
on (epoch, root, height). It refuses a checkpoint older than, or conflicting
with, the last one it anchored, which would mean Bloch finality went
backwards (exit 3, an alarm for operators).

## Tools

```
gnb-cli blochanchor <wallet.json> <epoch> <finalized_height> <root hex> [--fee GNB] [--dry-run]
gnb-cli blochcheckanchor <txid> [--anchorer gnb1...] [--min-conf N] [--finalized]
scripts/bloch-anchor.py --bloch-rpc URL,URL[,...] --wallet W --state S [--every-epochs 4]
```

`blochanchor` pays the consensus minimum fee unless `--fee` is given. Its
password comes from `GNB_WALLET_PASSWORD_FILE`, then `GNB_WALLET_PASSWORD`,
then a prompt. `blochcheckanchor` prints JSON (`ok`, `epoch`, `root`,
`finalized_height`, `signer_hashes`, `block_height`, `confirmations`);
`--finalized` requires the anchor to be at or below the PoWit-finalized
height.

To verify an anchor against Bloch, compare its `root` with the block at that
epoch boundary on any Bloch node, or with `getchaininfo.finalized` while it
is still the latest.

## Deployment

`deploy/bloch-anchor/`: a oneshot service plus a timer (every 10 minutes).
A run anchors only when Bloch finality has advanced `BLOCH_ANCHOR_EVERY_EPOCHS`
epochs since the last anchor (default 4; one Bloch epoch is about 16 minutes,
so about one anchor an hour), and waits while the previous anchor is
unconfirmed.

1. Create a dedicated wallet (`gnb-cli newwallet`), fund it, and publish its
   address.
2. `useradd --system --no-create-home --shell /usr/sbin/nologin gnb-anchor`
3. Install `gnb-cli` and `scripts/bloch-anchor.py` in `/opt/gnb/bin/`,
   the keystore as `/etc/gnb/bloch-anchor/wallet.json` (owner `gnb-anchor`,
   mode 0600), its password as `/etc/gnb/bloch-anchor/wallet-password`
   (root, 0600; systemd passes it as a credential), and
   `bloch-anchor.env.example` as `/etc/gnb/bloch-anchor.env`.
4. `systemctl enable --now bloch-anchor.timer`; logs in
   `journalctl -u bloch-anchor`.

Cost per anchor with one input: about 8.6 kB, so a minimum fee of about
17,200 base units plus 1,092 locked in the two markers, about 0.00018 GSMH.
At one anchor an hour that is about 0.0045 GSMH a day and two permanent
UTXO-set entries per anchor. Keep the wallet consolidated: each extra input
adds about 8.5 kB.
