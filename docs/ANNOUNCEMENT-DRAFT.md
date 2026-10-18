# Announcement draft: ObenBlock mainnet

Status: DRAFT, not published. Fill every `[AT LAUNCH: …]` value and check
it against docs/LAUNCH.md §4 before anyone posts this. Do not post it
before block 1 is in and the launch nodes pass `verify`
(deploy/obenblock-launch/LAUNCH-RUNBOOK.md, step 7, branch
`obenblock/launch-kit`).

---

## ObenBlock mainnet is live

ObenBlock (OBB) mainnet started on `[AT LAUNCH: LAUNCH_TIME UTC]`.

ObenBlock is a new proof-of-work chain built from the GnB-SMH code base. It
starts from a clean genesis. Blocks are mined with SHA-256d on Bitcoin's
header layout, so stock Bitcoin ASICs can mine it. Finality comes from
PoWit witness votes weighted by share work, under the PoCI rules.

**Check before you use it**

- Genesis block id (display order): `[AT LAUNCH: GENESIS_HASH]`
- Release: 0.2.0, `[AT LAUNCH: GitHub release URL]`, checksums in
  `SHA256SUMS`
- Chain id: `0x4F420001`
- P2P port 18110, DNS seed `seed.obenblock.xyz`, peers
  `[AT LAUNCH: seed peer multiaddrs]`

Compare the genesis id from more than one source: your own node
(`getblockhash 0`, reversed to display order), the release notes, the
repository (`docs/OBENBLOCK-GENESIS.md`, `reference/obb_genesis.py
--check`) and obenblock.xyz. How: docs/LAUNCH.md §4.

**What is in it**

- SHA-256d proof of work with 30 s blocks, ASERT, and stall relief that
  eases a late block's target, so block production recovers when hashrate
  leaves.
- A slow start: the block subsidy ramps up over the first 5,760 blocks
  (about two days). Early blocks pay almost nothing.
- Supply cap 12,500,000 OBB: 9.0M mined, 1.0M Bloch Genesis-3 carry-over
  (paid to the same keys as in GnB's genesis), 1.25M team and 1.25M founder,
  both locked by consensus (a one-year cliff, then 36 monthly tranches).
- No balance from the GnB chain. GnB keeps running separately.
- `obb1…` addresses. Existing `gnb1…` and `bloch1…` keys work, and a
  Bloch carry-over holder spends with the same keystore.
- PoCI finality: one frozen voter set per epoch, a strict two-thirds
  quorum, finality certificates, evidence against double votes, and no
  inactivity leak, so a network partition cannot finalize on both sides.
- Built-in Stratum V1 (port 3333) and Stratum V2 (port 3334) servers in the
  node, solo mining to the address in the worker name.

**What to know first**

- **No finality before height 3,600** (about 30 hours if blocks keep
  schedule, longer if the hashrate at launch is low). Until then, treat
  every block as provisional. After that, credit deposits at "finalized"
  (`getfinalityinfo`), not at a number of blocks.
- **The first block can take hours.** The launch difficulty is set for
  1 EH/s. Below that, stall relief lowers the target over time. Median
  times are in docs/MINING-ASIC.md §7.
- **The Stratum servers are solo.** There is no pool payout and no fee
  split.
- **ASICs on Stratum V1 mine blocks, not witness shares.** Witness shares
  need header-only mining, and in this release they are mined by nodes
  that run a witness key.
- **Bloch anchors are advisory.** They raise alerts on a contradiction and
  never move a checkpoint.
- **Not tested on real ASIC hardware yet.** The Stratum path is tested in
  software. Connect one device first.
- There is no exchange listing, price or return implied by this
  announcement.

**Mining**

```text
V1:  stratum+tcp://[AT LAUNCH: STRATUM_ENDPOINT]:3333
     worker obb1<your address>[.label], password x
V2:  stratum2+tcp://[AT LAUNCH: STRATUM_ENDPOINT]:3334/[AT LAUNCH: STRATUM_V2_AUTHORITY_PUBKEY]
```

Or run your own node with `--stratum` and point your miners at it. Guide:
docs/MINING-ASIC.md.

**Links**

- Site: https://obenblock.xyz
- Code: https://github.com/gnb-smh/ObenBlock
- Node guide: docs/LAUNCH.md
- Release notes: docs/RELEASE-NOTES-0.2.0.md
- Issues: https://github.com/gnb-smh/ObenBlock/issues

---

## Short version (for a post with a character limit)

ObenBlock (OBB) mainnet is live. SHA-256d PoW on Bitcoin's header (stock
ASICs work), PoCI finality from height 3,600, 12.5M cap, slow start.
Genesis `[AT LAUNCH: first 16 hex of GENESIS_HASH]…`: verify it from
several sources before you use it. Release 0.2.0 and guide:
`[AT LAUNCH: GitHub release URL]`
