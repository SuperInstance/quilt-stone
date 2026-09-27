# quilt-stone

**THE STONE** — the canonical receipt-chain module for the SuperInstance
fleet. One verifier for every repo's chain. Zero dependencies, ESM,
Node ≥ 20 (fleet runs v24).

## Provenance

Born **Task 26** of the fleet's practice: seven repos — *quilt-murmur,
quilt-dba, quilt-fiction, exoj, quilt-raw, quilt-arch, quilt-silicon* — each
seal receipt chains with slightly different local implementations, all
transcribed from one ancestor (`quilt-cortex/cortex/receipts.mjs`, the fleet
toolkit idiom). The user's directive:

> "write and code their experiences into actual stone for the record to grow
> from" … "widen your constructions modularly for later building blocks from
> abstractions we don't yet have in full view."

The abstraction in partial view **is** the receipt chain. This repo makes it
ONE thing — without rewriting the record behind its authors: every legacy
chain verifies under its own dialect, matched semantically exactly.

House law: **a receipt without a chain is a rumor.**

## What's here

| file | role |
|------|------|
| `stone.mjs` | the canonical module: `fnv1a64`, `rowHash`, `sealChain`, `verifyChain`, `detectAlg`, `canonicalJSON`, `sha256Hex`, `stamp`, `ALGS` (6 dialects), `verifyChainFile` |
| `STONE-SPEC.md` | the format spec: row kinds, field normalization, genesis conventions, exact serialization per dialect, verification contract, writer's checklist |
| `verify_all.mjs` | THE CONFORMANCE RUN: discovers every chain in every sibling repo, verifies each with stone.mjs, cross-checks each verdict against the repo's OWN local verifier |
| `smoke.mjs` | stone self-checks — seal/verify/tamper per dialect, canonical-JSON stability, detection, zero-dep static check (58/58) |
| `experiments/e_st1_conform.mjs` | the receipted conformance experiment — rules sealed first, results dogfooded into a stone-v1 chain written by stone.mjs itself |

## Dialects (legacy, verified as-found)

| key | repos | hash |
|-----|-------|------|
| `fnv1a64-fleet` | murmur, dba, fiction, arch, silicon, cortex (origin) | fnv1a64 over insertion-order JSON, `0x`+16hex, genesis `GENESIS` |
| `sha256-canonical` | exoj | sha256 over canonical JSON (recursive sort), 64hex, genesis `EXOJ-RECEIPTS-GENESIS` |
| `fnv1a64-rawpipe` | quilt-raw | masked fnv over `prev + '|' + deepSorted(body)`, fields `prev`/`hash`, genesis `gen0` |
| `fnv1a64-quant` | quilt-quant | fnv over top-sorted JSON (seq inside), fields `prev_hash`/`row_hash`, 16hex, genesis 16 zeros |
| `fnv1a64-tidepool` | quilt-playtest (discovered 26-b) | quant's math but seq OUTSIDE the hash |
| `stone-v1` | **new chains** | sha256 over canonical JSON + mandatory `stone.header` row, genesis `STONE-GENESIS-1` |

## Forward-format adopters

- **pong-quilt** — Round 36 (`tools/wal-export.js` `toStoneV1()`) seals its
  receipt-panel WAL in stone-v1, produced live and cited in-repo at
  `SuperInstance/pong-quilt` PR #46 (merged 2026-09-27). Smoke section 12b
  pins the exporter's real output: verifies under `stone.mjs`, tamper and
  row-splice caught at the exact row. A receipt without a chain is a rumor;
  an export without a verifier is noise.

## Run it

```
node smoke.mjs          # 58/58 self-checks
node verify_all.mjs     # conformance run over ../ (the whole record)
```

Conformance at Task 26-b seal time: **42/42 chains verified under their own
semantics, 42/42 local-verifier agreement, 0 divergences** (11 repos, 53
jsonl files sniffed). Receipts: `experiments/outputs/receipts_e_st1.jsonl`.
