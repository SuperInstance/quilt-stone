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
| `stone.mjs` | the canonical module: `fnv1a64`, `rowHash`, `sealChain`, `verifyChain`, `detectAlg`, `canonicalJSON`, `sha256Hex`, `stamp`, `ALGS` (**14 dialects**), `RULE_FROM` (machine-checked provenance), `verifyChainFile`, `verifyChronoCustody`, `verifySignedReceiptEnvelope` |
| `STONE-SPEC.md` | the format spec: row kinds, field normalization, genesis conventions, exact serialization per dialect, verification contract, writer's checklist |
| `verify_all.mjs` | THE CONFORMANCE RUN: discovers every chain in every sibling repo, verifies each with stone.mjs, cross-checks each verdict against the repo's OWN local verifier |
| `smoke.mjs` | stone self-checks — seal/verify/tamper per dialect, canonical-JSON stability, detection, v2 annotation/signature staples, standards-draft tracking pins, zero-dep static check (85/85) |
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
| `fnv1a64-utf8-pyjson` | **AI-Writings** (`calculator-quilt`) | fnv1a-64 over **UTF-8 BYTES** of **Python's** `json.dumps` (sorted keys, compact, ensure_ascii, `0.0` not `0`), fields `prev`/`hash`, genesis `0x`+16 zeros |
| `witness-chain-v1` | **AI-Writings** (`labs/situation-recorder`), **witness-spec** | sha256 over RFC 8785 JCS, **RFC 6962 domain separation** (`0x00` leaf / `0x01` node), `hash` field, genesis `0x`+16 zeros — **the linkage is in RECORD ORDER: there is no `prev` field** |

### Census dialects (2026-10)

Read out of each owner's source, not guessed from a filename. Each entry's
`RULE FROM: <repo>/<path>` comment names the file it was read from, and
`RULE_FROM` in `stone.mjs` makes that provenance machine-checkable. Fixtures
live in `fixtures/` and their provenance is recorded in `fixtures/README.md`.

| key | owner | hash | canonical form | linkage | genesis | proof | negative control |
|---|---|---|---|---|---|---|---|
| `chrono-organ/1` | **quilt-chrono** | sha256 | `canonicalJSON` (JCS) of the OBJECT `{seq, op, prev}` | `seq` (0-based) + `prev` | `GENESIS` | tip = the owner's **Ed25519-signed** checkpoint `cf0fbce2…`; sig verifies under the key published in the owner's receipt | edit an `op` field → break at that row; re-point `prev`; renumber `seq` |
| `sha256-pyjson-probe` | **quilt-gpu-lab** | sha256 | Python `json.dumps(sort_keys=True)` with **DEFAULT separators** (`, ` / `: `), `ensure_ascii=True` | **none** — per-record seal, `genesis: null` | none | all **215** committed rows in `probes.jsonl` re-derive | edit one probe → that row fails; the compact-separator form does **not** verify |
| `quilt-cell-ledger/1` | **quilt-rust** | sha256 | **ryū / serde_json**: keys sorted by UTF-8 byte order, `40.0` stays `40.0` (JCS sends `40`) | `prev_hash` inside the hashed bytes | **per-cell commit** `sha256(canonical{kind,cell_id,genesis,genesis_ts})` | committed genesis commit `470bc527…` reproduces exactly; all 3 committed edge-provenance vectors reproduce | a JCS rendering of the same object does **not** reproduce; `ryuNum(40) !== JSON.stringify(40)` |
| `quilt-edge/1` | **quilt-rust** | sha256 | same ryū form (per-edge provenance seal) | `chain_i = sha256(chain_{i-1} + ":" + provenance_i)` — a **colon-joined string**, not an object | **per-cell commit** `sha256(canonical{kind,cell,genesis,genesis_ts})` | **all six** committed per-cell chains in `bindings/go/golden.json` reproduce from genesis to head | wrong per-cell genesis → break at 0; forged provenance seal → refused |
| `moth-ledger/1` | **moth-ledger** | fnv1a-64 over **UTF-8 bytes** | Python canonical, `ensure_ascii=False` (no `\uXXXX`) | **`chain_hash` = fnv1a(prev_digest_bytes ‖ row_digest_bytes)** — binary concatenation, no string step | `"0"*16` | chain written by moth-ledger's own `Ledger`, accepted by its own `verify_chain()` | hashing the two digests as TEXT does **not** reproduce; edit row 1 or 2 → that row fails |
| `quilt-doctor-wal` | **pong-quilt** | fnv1a-64 (full code units) | `canonical()` — **deep**-sorted, unlike quant's top-level-only | `prev_hash` (`"0"*16` at seq 0) | `"0"*16` | byte output of pong-quilt's own committed `node tools/wal-export.js`, identical across runs | a nested `args` object must separate it from `fnv1a64-quant` (it does); edit an arg → that row fails |

### Signed envelopes (not chains)

A chain that verifies is **attested**. These name the signer, which is a
different claim and gets its own verifier.

| law | owner | what is actually signed |
|---|---|---|
| `verifyChronoCheckpoint` / `verifyChronoCustody` | **quilt-chrono** | organ checkpoint v3: `Ed25519(canonicalJson{hash, manifestHash, seq})`, signer named by `sha256(SPKI PEM)` |
| `verifySignedReceiptEnvelope` | **jev-quilt** | receipts-v2: `Ed25519(canonical_bytes ‖ chain_head)` — see the note below |

> **jev-quilt does NOT use BLAKE3.** Both its module docstring and common
> assumption say `Ed25519(BLAKE3(canonical_bytes ‖ chain_head))`. The shipped
> `seal_bytes` calls `ed25519.sign(seed, message_bytes(...))` directly —
> BLAKE3 is vendored in the package and never called on this path. The
> owner's own published vectors settle it: `vectors/signed_receipt_vectors.json`
> says "byte-identity is the acceptance test", and the signature reproduces
> byte-for-byte under **plain** Ed25519. `canonical_bytes` is also not JSON at
> all — it is pipe-joined UTF-8.

### Candidates that are NOT new dialects

| candidate | finding |
|---|---|
| **quilt-arcade** | `shared/kit.mjs`'s `verifyChain` is **exactly `fnv1a64-quant`** — same fnv1a-64 (full code units, 16 hex, no `0x`), same top-level-only sorted `JSON.stringify`, same `"0"*16` genesis, same `prev_hash`/`row_hash` fields. The fleet has fewer dialects than it looks like. (It ships no committed chain file: the `row_hash` occurrences in its `*.sheet.json` are program-cell **source**, not data.) |
| **pong-quilt** (the `canonicalJSON` lineage chain) | is **`stone-v1`** — `tools/wal-export.js`'s `toStoneV1` seals a `stone.header` row naming `alg: "stone-v1"`, and `checkpoints/coev-stone-v1.json` verifies under it. Already in the registry. Its *other*, deep-canon doctor WAL was unlabelled by the census and is `quilt-doctor-wal` above. |
| **quilt-research-canons** `chain-lint.py` | **defines no chain at all.** It is a linter: `is_zero` / `classify` deciding whether a live `prev_hash` field holds a real link or 16 zeros. No hash, no canonical form, no genesis, no linkage. A candidate is not a dialect. |
| **quilt-crabbox** | **not a chain** — a single Ed25519-signed receipt document with length-prefixed framing (`"crabbox-terminal-receipt-v2\0"` + 4-byte big-endian lengths), signer = `sha256:` + sha256 of the raw key. No prev, no genesis, no rows to link. It also commits no signed receipt to use as a fixture. |
| **quilt-rust** full row seal | the rule is read and implemented, but **cannot be pinned**: `compat/golden.json` ships entries abridged to `{seq, prev_hash, hash}` while the seal covers the whole `LedgerEntry`. See `fixtures/README.md`. |

## Forward-format adopters

- **pong-quilt** — Round 36 (`tools/wal-export.js` `toStoneV1()`) seals its
  receipt-panel WAL in stone-v1, produced live and cited in-repo at
  `SuperInstance/pong-quilt` PR #46 (merged 2026-09-27). Smoke section 12b
  pins the exporter's real output: verifies under `stone.mjs`, tamper and
  row-splice caught at the exact row. A receipt without a chain is a rumor;
  an export without a verifier is noise.

## Standards interop tracking

STONE-SPEC §9 tracks the signed-agent-receipt ecosystem without claiming
conformance: `draft-marques-asqav-compliance-receipts-07` (JCS [RFC 8785];
Ed25519 mandatory, ES256, ML-DSA-65 [FIPS 204]), SCITT [RFC 9943] (formerly
`draft-ietf-scitt-architecture`), and the house rule that a future export must
not silently rename stone-v1 chain rows. Smoke pins make draft-number drift
loud.

## Run it

```
node smoke.mjs          # 85/85 self-checks
node verify_all.mjs     # conformance run over ../ (the whole record)
```

Conformance at Task 26-b seal time: **42/42 chains verified under their own
semantics, 42/42 local-verifier agreement, 0 divergences** (11 repos, 53
jsonl files sniffed). Receipts: `experiments/outputs/receipts_e_st1.jsonl`.
