# STONE-SPEC.md — the fleet receipt-chain format

Status: **Task 26-b, canonical**. This document fixes what every future
experiment writes into. The reference implementation is `stone.mjs`
(zero dependencies, ESM). The conformance run is `verify_all.mjs`; the
receipted conformance experiment is `experiments/e_st1_conform.mjs`.

---

## 0. Provenance

Born Task 26 of the SuperInstance fleet's practice. Seven repos —
**quilt-murmur, quilt-dba, quilt-fiction, exoj, quilt-raw, quilt-arch,
quilt-silicon** — each seal receipt chains with slightly different local
implementations, all transcribed from one ancestor
(`quilt-cortex/cortex/receipts.mjs`, the "fleet toolkit idiom"). The user's
directive: *"write and code their experiences into actual stone for the record
to grow from"* and *"widen your constructions modularly for later building
blocks from abstractions we don't yet have in full view."* The abstraction in
partial view **is** the receipt chain. This repo makes it ONE thing: one
verifier, one spec, every repo's chain — verified under its own semantics,
compatible with the existing record, nothing rewritten behind its authors.

The Task 26-b sweep also discovered an eighth chain dialect in
**quilt-quant** (`shared/kit.mjs`, ported from a `quilt-cloudflare ocean.ts`
line) and the cortex origin chain itself. Both are in scope.

**House law: a receipt without a chain is a rumor.** A claim row that cannot
be re-derived from its chain — genesis through tip, hash by hash — is not
evidence. Tamper-evidence is the point: seal first, mutate nothing, let the
verifier catch every divergence.

---

## 1. Row kinds (observed across the record)

Rows are JSON objects, one per line in a `.jsonl` file. Observed kinds (the
field is `kind`; quilt-silicon writes `type` — both accepted, `kind` is the
normalized name; the chain math never hashes the field NAME, only the values):

| kind                  | role |
|-----------------------|------|
| `run.config`          | charter of a run: task, seeds, arms, world, fixed-point conventions |
| `rules.R1`…`rules.Rn`, `decision_rules`, `poc_rules` | decision rules **sealed BEFORE the runs they govern** |
| `charter`             | repo/experiment charter + doctrine (quilt-raw, quilt-arch, quilt-fiction style) |
| `stage.*`, `probe.*`, `result.*`, `finding`, `honest_negative` | per-stage evidence and honest negatives |
| `summary`             | final verdicts, smokes, chain tip |
| `chain.seal`          | self-referential seal (rows count + digest of the prefix) |
| `stone.header`        | **new (stone-v1)**: first row of a chain, names its `alg` and `genesis` |

Kinds are open-ended — a chain may carry any kind. The verifier does not
interpret kinds; it only guarantees the links.

## 2. Field normalization

**Normalized (what all new chains write):**

- `row_hash` — this row's hash, hex string.
- `seq` — 1-based position (quilt-raw enforces `seq === index+1` at verify;
  exoj has used 0-based seq — seq is informational for fleet/exoj dialects).
- `kind` — row kind (silicon's `type` aliased at the reader's discretion; it
  is payload, not link).

**Aliases recognized by `stone.mjs` detection (legacy, read-only):**

| dialect | hash field | link field(s) | note |
|---------|-----------|----------------|------|
| fnv1a64-fleet | `row_hash` | (implicit — prev is the running tip) | |
| sha256-canonical | `row_hash` | (implicit) | |
| fnv1a64-rawpipe | `hash` | `prev` (explicit, stored per row) | quilt-raw |
| fnv1a64-quant | `row_hash` | `prev_hash` (explicit) | quilt-quant |
| fnv1a64-tidepool | `row_hash` | `prev_hash` (explicit) | quilt-playtest (discovered) |

`verifyChain` returns both `at` (the broken row's `seq`, fleet-compat) and
`firstBadIndex` (the 0-based array index — the canonical locator).

## 3. Genesis conventions

| dialect | default genesis (the value hashed before row 0) |
|---------|--------------------------------------------------|
| fnv1a64-fleet | `'GENESIS'` |
| sha256-canonical | `'EXOJ-RECEIPTS-GENESIS'` |
| fnv1a64-rawpipe | `'gen0'` |
| fnv1a64-quant | `'0000000000000000'` (16 zeros) |
| fnv1a64-tidepool | `'0000000000000000'` (16 zeros) |
| stone-v1 | `'STONE-GENESIS-1'` (or the header row's recorded `genesis`) |

The genesis is a **string hashed into row 0** — there is no separate genesis
object in the file. Repos that pass a custom genesis to `sealChain` must
record it in a `stone.header` row (stone-v1) or in the run.config payload so
the chain remains self-describing. The sibling repos all use their defaults.

## 4. Dialects — exact semantics (matched to the sibling implementations)

### 4.1 `fnv1a64-fleet` — murmur, dba, fiction, arch, silicon, cortex

Source of truth: `quilt-murmur/murmur/receipts.mjs` (byte-identical copies in
quilt-dba/shared, quilt-fiction/fiction; comment-differing but
semantics-identical in dba/dba, arch, silicon, cortex).

```
fnv1a64(input):
  s = (typeof input === 'string') ? input : JSON.stringify(input)
  h = 0xcbf29ce484222325
  for each UTF-16 code unit c of s:  h = (h XOR c) * 0x100000001b3  mod 2^64
  return '0x' + h as 16 lowercase hex

rowHash(row, prev):
  rest = row minus `row_hash`            # order-preserving rest-destructure
  return fnv1a64([prev, rest])           # JSON.stringify of the ARRAY:
                                         # INSERTION-ORDER serialization,
                                         # NOT key-sorted (see §5)

sealChain(rows, genesis='GENESIS'):
  prev = genesis; for each row: prev = rowHash(row, prev); row.row_hash = prev

verifyChain(rows, genesis='GENESIS'):
  same walk; first row whose recomputed hash ≠ row.row_hash fails:
    return { ok:false, at: row.seq ?? null, why:'hash mismatch' }
  else { ok:true, links: rows.length }
```

### 4.2 `sha256-canonical` — exoj

Source of truth: `exoj/receipts.mjs`. Same strip-`row_hash` shape as fleet,
but:

```
hash = sha256Hex(canonicalJSON([prev, rest]))   # UTF-8 bytes, recursive key
                                                # sort, undefined skipped (§5)
genesis default 'EXOJ-RECEIPTS-GENESIS'
row_hash is 64 hex, NO '0x' prefix
```

### 4.3 `fnv1a64-rawpipe` — quilt-raw

Source of truth: `quilt-raw/experiments/e_r1_line.mjs` (lines 32–73).

```
fnv1a64raw(s): FNV-1a 64 with each code unit MASKED & 0xff (differs from
               fleet on any code unit > 255 — e.g. γ, →, ≥)
canonDeep(o):  deep-sorted, no-whitespace JSON
hash = fnv1a64raw(prev + '|' + canonDeep(body))
  body = row minus {prev, hash}         # seq and kind INCLUDED in the hash
row fields: prev (explicit link) + hash
genesis 'gen0'
verify additionally enforces: row.seq === index+1  AND  row.prev === prev
```

### 4.4 `fnv1a64-quant` — quilt-quant

Source of truth: `quilt-quant/shared/kit.mjs` (§"witness receipt idiom").

```
fnv1a64q(s): FNV-1a 64, full code units, NO '0x' prefix (16 hex)
canonTop(o): rebuild o with TOP-LEVEL-ONLY sorted keys, then JSON.stringify
fields = row minus row_hash; fields.prev_hash = prev (forced)
hash = fnv1a64q(canonTop(fields))        # seq IS inside the hash
row fields: prev_hash (explicit) + row_hash
genesis '0000000000000000'
verify additionally enforces row.prev_hash === prev
(the sibling's verifyChain THROWS on tamper and RETURNS the tip string on
success; stone.mjs returns the verdict — the verdict is the normalized
contract, the throw/return-string is the dialect's accent)
```

### 4.5 `fnv1a64-tidepool` — quilt-playtest (DISCOVERED Task 26-b)

Source of truth: `quilt-playtest/examples/e10_tidepool_artifacts.mjs`
(lines 80–94), chain file `tidepool-artifacts.jsonl`. Same hash math as the
quant dialect — but **`seq` is NOT inside the hash**: at seal time the row was
built as `{ seq: i, ...fields, row_hash }` AFTER hashing, so the sealed
content never contained seq. On disk the rows carry seq (post-hash append);
a correct re-derivation strips `row_hash` AND `seq`.

```
fields = row minus {row_hash, seq}; fields.prev_hash = prev (forced)
hash = fnv1a64q(canonTop(fields))
genesis '0000000000000000'; row fields prev_hash + row_hash (16 hex, no 0x)
```

Structurally IDENTICAL to `fnv1a64-quant` (same fields, same hash form), so
detection is by **trial verification**: try quant first, then tidepool; a
chain failing under both reports under quant with its `firstBadIndex`.
This pair is the spec's cleanest lesson: two repos, one idiom, one field's
difference in hash content — invisible without a canonical verifier.

### 4.6 `stone-v1` — the forward format (NEW chains only)

New chains MUST write stone-v1:

- Row 0 is a header: `{ kind:'stone.header', alg:'stone-v1', genesis:'STONE-GENESIS-1', ... }` — itself hashed like any row.
- Hash = `sha256Hex(canonicalJSON([prev, row minus row_hash]))` — the same
  math as exoj's dialect, mandated together with the header so every new
  chain is self-describing and serialization-canonical by construction.
- `row_hash` (64 hex), implicit prev, genesis `STONE-GENESIS-1`.
- No wall-clock, no randomness, no floats inside hashed content (floats ARE
  permitted as receipted measurements when the payload records them as
  strings or as JSON numbers with receipted formatting — but exact integers
  are the house style).

#### 4.6.1 v2 annotation rows (STONE-V2-PILOTS resolution)

A row whose `kind` is `stone.*` but NOT `stone.header` (e.g. the stapled
`stone.sign` tip signature from STONE-V2-PILOTS) is an **annotation**:

- It carries a SELF-HASH computed exactly like a body row against the
  chain's current tip — but **prev never advances into it**. The annotation
  sits outside the hashed prefix while every byte of it stays
  tamper-evident (an edited annotation breaks `annotation hash mismatch`).
- Body rows never use `stone.*` kinds, so the split is unambiguous;
  `annotateTip(rows, {kind:'stone.sign', ...})` is the canonical stapler.
- Downgrade safety, verified by running: the design's literal "no row_hash"
  staple FAILED v1 verify (`missing row_hash`) — see the quilt-stone#2
  comment. Under this rule a v1-only verifier either accepts a trailing
  self-hashed staple (tip confusion only, never a silent lie) or, for
  mid-chain staples, rejects at the next body row — both loud, never quiet.
- Non-goal kept: hash-linking a signature like a normal row (signature on
  the inside) remains forbidden — that is the regressive case the design
  already forbids.

#### 4.6.2 v2 tip signatures — the first sign lane (STONE-V2-PILOTS)

`signTip(rows, privateKey, {key_id, signer_role})` staples an ed25519
signature on the chain's **body tip** as a `stone.sign` annotation row;
`verifyTipSignature(rows, publicKey)` is the auditor entry point.

- Signed message: the domain-separated `"stone-v2" || tip_row_hash` —
  pinned byte-level in smoke.
- The signature block names its own **key id, algorithm, and signer role**;
  genesis convention unchanged (`STONE-GENESIS-1`).
- The stored `tip` field binds the signature to the exact chain it
  staples. A chain edited after signing re-seals into self-consistent
  hashes (hash-verify PASSES — pinned in smoke as the laundering case),
  but the signature still names the OLD tip and
  `verifyTipSignature` refuses: `signed tip does not match the chain tip`.
  This closes the R22 P3-process gap at rest: "chain verifies" now
  implies "this exact byte string was signed by the producer key."
- **Key separation is per producer repo, never fleet-wide** (a leaked key
  elsewhere must not be able to re-sign this repo's artifacts). No
timestamp authority (WAL sequence is the clock), no key registry yet —
  the auditor experience report feeds Task 26-d.
- Node runtime note: one-shot `verify` arg order differs across fleet
  runtimes; `edVerify` tries the documented order and falls back on the
  arg-type error (detected by running, pinned in smoke).

## 5. THE SERIALIZATION — where cross-repo chains break

The single most fragile point of the whole record: **what byte string does
the hash digest?** Three different answers coexist in the fleet:

1. **fleet dialect: `JSON.stringify([prev, rest])`** — insertion order of
   keys, recursive objects unsorted, no whitespace, non-ASCII characters
   emitted literally (UTF-8 on disk). Stable ONLY because rows are written
   with `JSON.stringify` and re-read with `JSON.parse`, which preserves
   insertion order. Re-key a row (or rebuild it from different code paths)
   and the hash changes with no tamper. This is the known fleet weakness.
2. **exoj / stone-v1: `canonicalJSON`** — recursively sorted keys,
   undefined-valued keys skipped, arrays ordered, no whitespace, digested as
   UTF-8. Permutation-invariant: identical logical content always hashes
   identically. **This is THE canonical serialization from Task 26-b on.**
3. **raw dialect: deep-sorted canon over `prev + '|' + body`** — sorted, but
   a different input shape (pipe-joined string, seq/kind included) and a
   masked FNV (code units & 0xff).
4. **quant dialect: top-level-only sort** — nested objects ride on
   insertion order like the fleet dialect.

`stone.mjs` matches all of them exactly (receipted in
`experiments/outputs/receipts_e_st1.jsonl`) and documents them here so the
divergence can never be silently bridged. **Do not "fix" a legacy chain's
serialization; verify it under its own dialect. Write new chains in stone-v1.**

Number round-trip notes (all dialects): `-0` stringifies as `0`; `1e21`
round-trips as `1e21`; integers beyond 2^53 MUST be strings (house rule —
the repos already do this, e.g. quilt-raw's `S()` helper).

## 6. Verification contract

`verifyChain(rows, genesis?, opts?)` (stone.mjs) returns exactly:

```
{ ok: boolean,
  firstBadIndex: number|null,   # canonical locator of the first break
  at: seq|null,                 # fleet-compat locator (row.seq ?? null)
  why: string|null,             # 'hash mismatch' | 'missing row_hash' |
                                # 'seq break at i' | 'prev break at i' | ...
  alg: dialectKey|null,
  genesis: string|null,
  links: number,                # rows.length
  tip: string|null }            # last GOOD hash (null: empty chain or
                                # row 0 broke)
```

- An empty chain verifies `ok:true, links:0, tip:null` (vacuous — a chain of
  nothing is not a rumor, but it is not a record either).
- Rows that are not objects, undetectable dialects, and malformed JSONL lines
  are verdicts, not exceptions — the canonical verifier never throws.
- The local sibling verifiers keep their native shapes (fleet returns
  `{ok, links, at, why}`; raw returns `{ok, why, tip}`; quant throws). R2 of
  the conformance run proves stone.mjs reproduces each native verdict.

## 7. Tamper evidence (the whole point)

The chain's promise: **any edit to any sealed row, any deleted row, any
reordered row, any renamed field, and any dialect mismatch is caught with the
exact index of the first divergence.** Proven, not asserted — R3 of
`e_st1_conform.mjs` seals a chain, mutates one row, and shows the verifier
catch it; `smoke.mjs` does it per dialect (54/54).

## 8. Writer's checklist (every future experiment)

1. New chain? → stone-v1: `stone.header` row 0, `sealChain(rows, undefined, {alg:'stone-v1'})`.
2. Extending a legacy repo's existing chain? → keep that repo's dialect and genesis; stone.mjs verifies it as-is.
3. Seal decision rules BEFORE the runs they govern (receipts before verdicts).
4. No wall-clock, no `Math.random`, no BigInts, no floats inside hashed content.
5. Write `.jsonl` rows with `JSON.stringify` only; never pretty-print a chain file.
6. Record the chain tip in the summary artifact AND in the commit message — a tip nobody can find is a rumor with extra steps.
7. **Hash is the LAST write to a row.** The tidepool artifact ledger's `seq`
   was appended after hashing and so is invisible to its own hash — it works,
   but only because the reader was written to match. Fields added after the
   hash are a silent fork: any future reader that trusts the file layout over
   the seal-time layout derives different hashes. stone-v1 forbids it:
   `sealChain` is the last code that touches a row.
8. If you must extend a legacy dialect, name it: add it to `ALGS` in
   stone.mjs with its source-of-truth citation, exactly as fnv1a64-tidepool
   was. Never overload an existing dialect key with new semantics.
