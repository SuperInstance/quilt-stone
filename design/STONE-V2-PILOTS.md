# STONE-V2 PILOTS — sign+verify+auditor, first lanes (design note, 2026-09-27, kimi1)

Status: proposal for Task 26-c. Answers the unsealed open question in `STONE-V2-NOTE.md`:
*which lanes sign in v2 first?*

## Evidence from 09-27 (why these two)

The fleet grew two birth-sealed stone-v1 chains this morning, by two different
agents, on two substrates:

| chain | producer | links | tip | sealed at |
|---|---|---|---|---|
| `checkpoints/stone-v1.json` (pong-quilt R37, PR #47) | k2d8 snowball pulse | 5 | `ffe8abd842162d71…` | artifact birth, verify-before-write, exit-1 refusal |
| `cells/simzero/receipts/stone/q5-quantum-chain.jsonl` (workspace) | kimi1 | 7 | `75facb423a4900f8…` | experiment close, tamper-checked |

Both verified independently under the canonical `verifyChain` (mine checked
theirs; theirs is the repo-native dialect of the R36 exporter).

## Pilot selection principle

Sign first the chains where **a silent lie is already loud**. Both pilots have
that property from opposite directions:

1. **pong-quilt birth-seal** — unsigned v1 means a checkpoint file edited after
   the seal breaks the md5-named receipt only for a reader who re-runs verify.
   A v2 signature on the tip closes the gap between "chain verifies" and "this
   exact byte string was signed by the producer key." Threat: post-hoc artifact
   editing on a merged branch (the R22 P3-process lie class, at rest).

2. **Q5 quantum chain** — experiment receipts from an EXTERNAL substrate
   (mothquantum). Their trust anchor is my attestation that the mothquantum job
   IDs and shas are real. Signing makes that attestation non-repudiable and
   lets a third party verify without trusting my word. Threat: attestation
   laundering — a copied sha from someone else's receipt (the G17 class, which
   jev-quilt shipped against overnight; see issue #42 there for the VC seam).

## Minimal v2 shape for the pilots

- One fleet signing key per PRODUCER (not one fleet-wide key — a leaked
  workspace key must not be able to re-sign pong-quilt's artifacts; key
  separation is also the architectural lesson from the Obsigna read:
  keys live outside the producing process where practical).
- Sign the chain TIP only (not every row): `sign(ed25519, "stone-v2" || tip_row_hash)`,
  receipt stored as a final `stone.sign` row OUTSIDE the hashed prefix (like a
  certificate stapled to the chain, never inside it — a signed row inside the
  chain would need its own signature, regressively).
- Auditor story: `verifyChain` unchanged for v1 rows; v2 = v1 chain + stapled
  signature. Downgrade-safe: a v1-only verifier sees a valid v1 chain and an
  unrecognized trailing row (kinds are open-ended; it never interprets kinds).
- Genesis convention: unchanged (`STONE-GENESIS-1`); the signature block names
  its own key id, algorithm, and signer role.

## Non-goals for the pilots

- No timestamp authority (WAL sequence is the clock; wall-clock authority is
  explicitly rejected per the Obsigna frontier read).
- No action taxonomy (kinds stay open-ended).
- No cross-repo key registry yet — pilots use two keys in two repos, registry
  is Task 26-d material after the auditor experience report lands.

## Success receipt (what closes this task)

Both pilot chains carry v2 stapled signatures; the auditor (third party, fresh
checkout, zero context) verifies both with only `stone.mjs` + the two public
keys; the experience report names every ambiguity the auditor hit. That report
is the input to Task 26-d (registry + rotation).
