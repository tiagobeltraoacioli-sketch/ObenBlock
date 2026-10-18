# ObenBlock Improvement Proposals (OBIPs)

An OBIP proposes a **future** evolution of ObenBlock: a consensus rule, a peer
message, an RPC, an application convention or a process. The format and the
workflow are those of OBIP-1, adapted from Bitcoin's BIP-2.

What ObenBlock is today is the **base specification**, not a set of OBIPs.
It is implemented on branches and written in:

- `docs/DESIGN-obenblock.md`: chain identity and `obb` addresses (§2),
  genesis (§3), SHA-256d proof of work (§4), stall relief (§5.1), witness
  shares and the long window (§6.1, §6.2), growth cap on W (§6.3), advisory
  Bloch anchors (§8, phase 1);
- `docs/DESIGN-obenblock-poci.md`: PoCI strict finality, frozen
  configurations and handoff (§2–§4), absence pruning (§4.1), Proof of
  Corruption (§5), finality certificate (§6), signer protection (§8), launch
  (§9); exact encodings on branch `obenblock/o11a-poci-reference`;
- `docs/CONSENSUS.md`, "PoWit" (32 attestations per block, `ceil(K/32)`
  blocks of inclusion);
- `docs/DESIGN-witness-shares.md`;
- `docs/BLOCH-ANCHOR.md` (BLA1 anchors of Bloch in ObenBlock).

OBIPs cite that text by document and section. They never restate it.

"The technical note" in the OBIPs is "Votos sobre shares, provas compactas e
finalidade segura" (2026-10-18), with its P1/P2 items and references R1–R18.
"The partition simulator" is `reference/sim/partition_sim.py` and
`docs/research/obenblock-partition-sim.md` on branch
`obenblock/o11b-partition-sim`.

Every OBIP except OBIP-1 is a Draft. None has a reference implementation or
test vectors yet. Parameters marked `OPEN` are undecided. Nothing here claims
that a research question is solved.

## Index

| OBIP | Layer | Title | Type | Status | Requires | Main prerequisites |
| --- | --- | --- | --- | --- | --- | --- |
| [1](obip-0001.md) | Process | OBIP purpose and process | Process | Active | none | none |
| [2](obip-0002.md) | Peer Services | Compact post-quantum finality certificates | Standards Track | Draft | none | measured prototype of the proof relation (Groth16 baseline and hash-based track); size/time targets set from it |
| [3](obip-0003.md) | Consensus (hard fork) | Certified Bloch anchors | Standards Track | Draft | none | Bloch repository access; `cfg_commit` carrier decision and reference model; registry able to verify full certificates, or OBIP-2 Final with a PQ proof system; simulator open issues addressed |
| [4](obip-0004.md) | Applications | Bloch light client in the node | Standards Track | Draft | none | Bloch roster leaf (0x23) on Bloch mainnet; `getstateproof`/`getlcroster` served; Bloch anchor registry and proof format; frozen Bloch wire format |
| [5](obip-0005.md) | Consensus (hard fork) | Out-of-body PoCI vote aggregation | Standards Track | Draft | none | regtest measurements (propagation, reconstruction, verify time, latency at K = 64…1,920+); new `params_digest` version |
| [6](obip-0006.md) | Consensus (hard fork) | Commit-reveal votes in the vote window | Standards Track | Draft | none | regtest measurements per `commit_len`; owner decision that the gain justifies the cost |
| [7](obip-0007.md) | Consensus (hard fork) | Bloch-authorized finality recovery | Standards Track | Draft | 4 | OBIP-4 deployed; Bloch registry record kind; submitter policy and stall/round parameters; simulator with recovery and hidden partition |
| [8](obip-0008.md) | Consensus (hard fork) | Configuration floor and fast re-entry | Standards Track | Draft | none | owner decision on carry mode and floor; simulator extended with §4.1 pruning; base clarification of §4.1 across skipped epochs |
| [9](obip-0009.md) | Consensus (soft fork) | Data availability sampling | Standards Track | Draft | none | codec, chunk size and sampling parameters from a prototype; network simulation with selective disclosure |
| [10](obip-0010.md) | Consensus (soft fork) | Validity proofs of block execution | Standards Track | Draft | none | accumulator choice and benchmark; prototype circuit with measured proof size and times; differential tests |
| [11](obip-0011.md) | API/RPC | Operator-diversity metrics | Standards Track | Draft | none | default signals and privacy defaults; metric naming |
| [12](obip-0012.md) | Consensus (hard fork) | Committee-based fast finality | Informational | Draft | none | formal model of a fork-choice option with PoCI; PQ sortition; measured bandwidth (with OBIP-2, OBIP-5) |
| [13](obip-0013.md) | Consensus (hard fork) | Settlement layer with forced exits | Informational | Draft | 10 | OBIP-10 proof system chosen with an L1 verification cost bound; an L1 bridge primitive OBIP |

"Requires" lists technical dependencies only. OBIP-1 applies to all and is
not listed.

## Suggested order of work

Dependencies, including soft ones (an OBIP that is a prerequisite or a
better input for another, without being in its `Requires`):

```text
OBIP-11 ─────────────────────────────── informs every decision on concentration
OBIP-8  ──> OBIP-3, OBIP-7              (simulator open issues; recovery applies its rules)
OBIP-4  ──> OBIP-7                      (Requires)
OBIP-2  ──> OBIP-3 (compact option), OBIP-12 (bandwidth)
OBIP-5  ──> OBIP-6 (capacity), OBIP-12 (carriage)
OBIP-9, OBIP-10 ──> OBIP-13             (OBIP-10 Requires; DA for off-L1 data)
```

1. **OBIP-11** (API/RPC, no consensus effect). Cheap, and it gives the
   numbers (weight per effective operator) that the floor of OBIP-8 and every
   assumption of "less than a third Byzantine" need.
2. **OBIP-8**. It answers the two open issues of the partition simulator
   (thin configuration after a stall longer than the window; the losing side
   of a long partition leaving the configuration). OBIP-3 lists them as a
   prerequisite, and OBIP-7 applies the same handoff.
3. **OBIP-5**. Inclusion capacity becomes binding as the witness set grows
   (`ceil(K/32)` reaches a full checkpoint interval at K = 1,920). It is
   needed before OBIP-6 is practical above K = 960.
4. **OBIP-2** prototype (research, no consensus). Its measurements decide
   whether OBIP-3 uses compact certificates and set the scale for OBIP-12.
5. **OBIP-4**, as soon as the Bloch roster leaf is on Bloch mainnet.
6. **OBIP-3**, once Bloch repository access exists and the `cfg_commit`
   carrier is decided.
7. **OBIP-7**, after OBIP-4 is deployed and OBIP-8 is decided; it adds an
   explicit trust dependency on Bloch and needs the owner's decision on the
   submitter policy.
8. **OBIP-6**, only if OBIP-5 measurements and the commit-reveal
   measurements show a gain worth the latency.
9. Long-term research: **OBIP-9**, **OBIP-10**, then **OBIP-13**;
   **OBIP-12** stays Informational until a fork-choice option has a formal
   model.

## Post-quantum status, in one place

- Votes and certificates of the base use hybrid ML-DSA-65 + Falcon-1024 KES
  signatures (about 4.6 kB per signature; about 8.7 kB per vote with the
  public key and path).
- Pairing-based SNARKs (Groth16), KZG and BLS aggregation are **not**
  post-quantum. They appear in OBIPs only as laboratory baselines or as
  rejected options.
- Hash-based transparent proofs (STARK family) are conjectured post-quantum
  under hash assumptions; their proofs are tens to hundreds of kB, and none
  has been measured for an ObenBlock relation.

## Adding an OBIP

Follow OBIP-1: open a pull request with `docs/obip/obip-NNNN.md` (the editor
assigns the number), the fenced preamble and the required sections, and add a
row to the index above.
