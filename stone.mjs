// quilt-stone/stone.mjs — THE STONE: canonical receipt-chain module for the
// SuperInstance fleet. Zero dependencies (node:crypto builtin only). ESM.
//
// PROVENANCE: born Task 26 of the fleet's practice — seven repos (quilt-murmur,
// quilt-dba, quilt-fiction, exoj, quilt-raw, quilt-arch, quilt-silicon) each
// seal receipt chains with slightly different local implementations, all
// transcribed from the same ancestor (quilt-cortex/cortex/receipts.mjs, the
// "fleet toolkit"). The user's directive: "write and code their experiences
// into actual stone for the record to grow from" and "widen your constructions
// modularly for later building blocks from abstractions we don't yet have in
// full view." The abstraction in partial view IS the receipt chain — this
// module makes it ONE thing. Survey receipted in STONE-SPEC.md; every dialect
// here is matched SEMANTICALLY EXACTLY to its sibling implementation so the
// existing chains verify unmodified. Compatibility with the existing repos is
// the whole point. House law: a receipt without a chain is a rumor.
//
// DIALECTS (legacy, verified as-found — see STONE-SPEC.md for the full table):
//   fnv1a64-fleet    quilt-murmur, quilt-dba, quilt-fiction, quilt-arch,
//                    quilt-silicon, quilt-cortex (the toolkit origin)
//   sha256-canonical exoj
//   fnv1a64-rawpipe  quilt-raw
//   fnv1a64-quant    quilt-quant (discovered by the Task 26-b sweep)
//   stone-v1         NEW chains only: header row + canonical serialization.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

// ============================================================================
// 1. HASH PRIMITIVES
// ============================================================================

// Core FNV-1a 64 over a JS string, iterating UTF-16 code units.
// maskLow8: raw dialect masks each code unit with & 0xff (quilt-raw);
//           fleet/quant dialects use the full code unit. These DIFFER on
//           non-ASCII input — that is why they are separate dialects.
function fnv1a64Units(s, maskLow8) {
  let h = 0xcbf29ce484222325n;
  const p = 0x100000001b3n, m = 0xffffffffffffffffn;
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(maskLow8 ? (s.charCodeAt(i) & 0xff) : s.charCodeAt(i));
    h = (h * p) & m;
  }
  return h; // BigInt, un-prefixed
}

const hex16 = (h, prefix) => (prefix ? '0x' : '') + h.toString(16).padStart(16, '0');

// FLEET fnv1a64 (quilt-murmur/murmur/receipts.mjs et al., verbatim semantics):
// string input hashed directly; ANY other input is hashed over
// JSON.stringify(input) — note: NOT key-sorted (insertion-order serialization).
// Returns '0x' + 16 lowercase hex.
export function fnv1a64(input) {
  const s = typeof input === 'string' ? input : JSON.stringify(input);
  return hex16(fnv1a64Units(s, false), true);
}

// RAW fnv1a64 (quilt-raw/experiments/e_r1_line.mjs): string-only, each code
// unit masked & 0xff. Returns '0x' + 16 hex.
export function fnv1a64RawString(s) {
  return hex16(fnv1a64Units(s, true), true);
}

// QUANT fnv1a64 (quilt-quant/shared/kit.mjs): string-only, full code units,
// NO '0x' prefix. Returns 16 hex.
export function fnv1a64QuantString(s) {
  return hex16(fnv1a64Units(s, false), false);
}

// sha256 over the UTF-8 bytes of a string, plain hex (exoj dialect).
export function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

// CANONICAL JSON (THE serialization for new chains; exoj semantics verbatim):
//  - object keys sorted recursively (lexicographic by Unicode code unit, i.e.
//    Array.prototype.sort on the key strings);
//  - keys whose value is undefined are SKIPPED (matches JSON.stringify
//    round-trip semantics so chains re-verify identically from disk);
//  - arrays keep order; null is "null"; numbers use JSON.stringify number
//    formatting; strings use JSON.stringify escaping;
//  - output has NO whitespace; digested as UTF-8 bytes.
// This is where cross-repo chains break: the fleet dialect serializes with
// plain JSON.stringify (INSERTION order, nested objects unsorted), raw with
// deep-sorted canon, quant with TOP-LEVEL-ONLY sort. Three different orders.
export function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// Deep-sorted canon (quilt-raw dialect; payloads there are strings/numbers/
// bools only, but implemented generally). Undefined-valued keys skipped.
function canonDeep(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return '[' + value.map(canonDeep).join(',') + ']';
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonDeep(value[k])).join(',') + '}';
}

// Top-level-only sorted stringify (quilt-quant dialect): rebuilds the object
// with keys sorted at the TOP level, nested values left to JSON.stringify
// (their insertion order is preserved — stable only because the sibling
// always writes rows via JSON.stringify and re-reads with JSON.parse).
function canonTop(value) {
  const s = {};
  for (const k of Object.keys(value).sort()) s[k] = value[k];
  return JSON.stringify(s);
}

// Strip fields preserving key order (equivalent to the siblings'
// `const { x, ...rest } = row` rest-destructure, which preserves order).
function withoutKeys(row, drop) {
  const out = {};
  for (const k of Object.keys(row)) if (!drop.includes(k)) out[k] = row[k];
  return out;
}

// ============================================================================
// 2. DIALECT REGISTRY
// ============================================================================

export const ALGS = {
  'fnv1a64-fleet': {
    repos: ['quilt-murmur', 'quilt-dba', 'quilt-fiction', 'quilt-arch', 'quilt-silicon', 'quilt-cortex'],
    hashField: 'row_hash', prevField: null, genesis: 'GENESIS',
    hashForm: /^0x[0-9a-f]{16}$/,
    // hash = fnv1a64(JSON.stringify([prev, row-without-row_hash]))
    //       (JSON.stringify of the ARRAY -> insertion-order serialization)
    hashOf(row, prev) {
      return fnv1a64([prev, withoutKeys(row, ['row_hash'])]);
    },
    setLinks(row, prev, hash) { row.row_hash = hash; },
  },
  'sha256-canonical': {
    repos: ['exoj'],
    hashField: 'row_hash', prevField: null, genesis: 'EXOJ-RECEIPTS-GENESIS',
    hashForm: /^[0-9a-f]{64}$/,
    hashOf(row, prev) {
      return sha256Hex(canonicalJSON([prev, withoutKeys(row, ['row_hash'])]));
    },
    setLinks(row, prev, hash) { row.row_hash = hash; },
  },
  'fnv1a64-rawpipe': {
    repos: ['quilt-raw'],
    hashField: 'hash', prevField: 'prev', genesis: 'gen0',
    hashForm: /^0x[0-9a-f]{16}$/,
    // hash = fnv1a64raw(prev + '|' + canonDeep(body))
    // body = row minus {prev, hash} (seq/kind INCLUDED, deep-sorted)
    hashOf(row, prev) {
      return fnv1a64RawString(prev + '|' + canonDeep(withoutKeys(row, ['prev', 'hash'])));
    },
    setLinks(row, prev, hash) { row.prev = prev; row.hash = hash; },
    // extra link rules enforced on verify (matched to quilt-raw verbatim):
    checkLink(row, prev, i) {
      if (row.seq !== i + 1) return `seq break at ${i}`;
      if (row.prev !== prev) return `prev break at ${i}`;
      return null;
    },
  },
  'fnv1a64-quant': {
    repos: ['quilt-quant'],
    hashField: 'row_hash', prevField: 'prev_hash', genesis: '0000000000000000',
    hashForm: /^[0-9a-f]{16}$/,
    // hash = fnv1a64quant(JSON.stringify(topSorted({...row-row_hash, prev_hash: prev})))
    hashOf(row, prev) {
      const fields = withoutKeys(row, ['row_hash']);
      fields.prev_hash = prev; // overwrite/append LAST, then top-level sort
      return fnv1a64QuantString(canonTop(fields));
    },
    setLinks(row, prev, hash) { row.prev_hash = prev; row.row_hash = hash; },
    checkLink(row, prev /*, i*/) {
      if (row.prev_hash !== prev) return 'prev_hash mismatch';
      return null;
    },
  },
  'fnv1a64-tidepool': {
    // DISCOVERED Task 26-b: quilt-playtest/tidepool-artifacts.jsonl (written by
    // examples/e10_tidepool_artifacts.mjs). Same hash math as the quant dialect
    // (top-level-sorted canon, full-code-unit fnv1a64, no 0x prefix, genesis
    // 16 zeros) — but `seq` is EXCLUDED from the hash: at seal time the row was
    // built as { seq: i, ...fields, row_hash } AFTER hashing, so the sealed
    // content never contained seq. Structurally identical to fnv1a64-quant;
    // discriminated from it by trial verification (see detectAlg).
    repos: ['quilt-playtest'],
    hashField: 'row_hash', prevField: 'prev_hash', genesis: '0000000000000000',
    hashForm: /^[0-9a-f]{16}$/,
    hashOf(row, prev) {
      const fields = withoutKeys(row, ['row_hash', 'seq']);
      fields.prev_hash = prev;
      return fnv1a64QuantString(canonTop(fields));
    },
    setLinks(row, prev, hash) { row.prev_hash = prev; row.row_hash = hash; },
    checkLink(row, prev /*, i*/) {
      if (row.prev_hash !== prev) return 'prev_hash mismatch';
      return null;
    },
  },
  'stone-v1': {
    // THE FORWARD FORMAT for NEW chains (STONE-SPEC.md §stone-v1):
    // sha256 over canonicalJSON, row_hash field, mandatory stone.header row 0,
    // genesis 'STONE-GENESIS-1' (or the header's own recorded genesis).
    repos: ['quilt-stone'],
    hashField: 'row_hash', prevField: null, genesis: 'STONE-GENESIS-1',
    hashForm: /^[0-9a-f]{64}$/,
    hashOf(row, prev) {
      return sha256Hex(canonicalJSON([prev, withoutKeys(row, ['row_hash'])]));
    },
    setLinks(row, prev, hash) { row.row_hash = hash; },
    // v2 ANNOTATION ROWS (STONE-V2-PILOTS resolution, quilt-stone#2 comment):
    // a row whose kind is 'stone.*' but NOT 'stone.header' is an annotation
    // (e.g. the stapled 'stone.sign' tip signature). It carries a SELF-HASH
    // computed with the CURRENT tip as prev — but prev NEVER advances past
    // it, so the annotation sits OUTSIDE the hashed prefix while every byte
    // of it stays tamper-evident (an edited annotation breaks its own
    // self-hash). Body rows never use 'stone.*' kinds, so the split is
    // unambiguous. Downgrade-safe: a v1-only verifier sees a valid chain
    // plus trailing self-hashed rows it cannot explain — never a silent lie.
    isAnnotation(row) {
      return typeof row.kind === 'string' &&
        row.kind.startsWith('stone.') && row.kind !== 'stone.header';
    },
  },
};

// Detect the dialect of a row array. Order of tests is normative:
//  1. explicit stone.header row (kind === 'stone.header' with an alg field)
//  2. presence of prev_hash  -> fnv1a64-quant OR fnv1a64-tidepool (structurally
//     identical link fields; discriminated by trial verification — quant first,
//     then tidepool; a chain failing under both reports under quant)
//  3. presence of prev+hash  -> fnv1a64-rawpipe
//  4. row_hash format:  0x+16hex -> fleet; 64hex -> sha256-canonical;
//     16hex -> quant; 0x+64hex -> sha256 (future-proof alias)
// Returns the alg key or null if undetectable (empty rows / no hash fields).
function trialOk(rows, algKey) {
  let prev = ALGS[algKey].genesis;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (!r || typeof r !== 'object') return false;
    if (r[ALGS[algKey].hashField] === undefined) return false;
    if (ALGS[algKey].checkLink && ALGS[algKey].checkLink(r, prev, i)) return false;
    const want = ALGS[algKey].hashOf(r, prev);
    if (want !== r[ALGS[algKey].hashField]) return false;
    prev = r[ALGS[algKey].hashField];
  }
  return true;
}

export function detectAlg(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const h0 = rows[0];
  if (h0 && typeof h0 === 'object' && h0.kind === 'stone.header' &&
      typeof h0.alg === 'string' && ALGS[h0.alg]) return h0.alg;
  let hasPrevHash = false;
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    if (r.prev_hash !== undefined) { hasPrevHash = true; break; }
    if (r.prev !== undefined && r.hash !== undefined) return 'fnv1a64-rawpipe';
  }
  if (hasPrevHash) {
    if (trialOk(rows, 'fnv1a64-quant')) return 'fnv1a64-quant';
    if (trialOk(rows, 'fnv1a64-tidepool')) return 'fnv1a64-tidepool';
    return 'fnv1a64-quant'; // fail under the primary shape, verdict carries why
  }
  let rh = null;
  for (const r of rows) {
    if (r && typeof r.row_hash === 'string') { rh = r.row_hash; break; }
  }
  if (rh !== null) {
    if (/^0x[0-9a-f]{16}$/.test(rh)) return 'fnv1a64-fleet';
    if (/^[0-9a-f]{64}$/.test(rh)) return 'sha256-canonical';
    if (/^[0-9a-f]{16}$/.test(rh)) return 'fnv1a64-quant';
    if (/^0x[0-9a-f]{64}$/.test(rh)) return 'sha256-canonical';
  }
  return null;
}

// ============================================================================
// 3. ROW HASH / SEAL / VERIFY  (sibling-call-compatible signatures)
// ============================================================================

// rowHash(row, prevHash, opts?) -> hash string for ONE link.
// Default dialect fnv1a64-fleet: identical to every fleet repo's rowHash.
export function rowHash(row, prevHash, opts) {
  const alg = ALGS[opts?.alg ?? 'fnv1a64-fleet'];
  return alg.hashOf(row, prevHash);
}

// sealChain(rows, genesis?, opts?) -> rows (mutated in place, returned).
// opts.alg: dialect key (default 'fnv1a64-fleet'). genesis default per dialect.
// Idempotent on an already-sealed prefix (hash fields are stripped before
// re-derivation), exactly like the siblings' sealChain.
export function sealChain(rows, genesis, opts) {
  const o = (genesis && typeof genesis === 'object' && !Array.isArray(genesis))
    ? genesis : (opts ?? {});
  const algKey = o.alg ?? 'fnv1a64-fleet';
  const alg = ALGS[algKey];
  if (!alg) throw new Error(`stone: unknown alg '${algKey}'`);
  let prev = (typeof genesis === 'string' ? genesis : o.genesis) ?? alg.genesis;
  for (const r of rows) {
    const h = alg.hashOf(r, prev);
    alg.setLinks(r, prev, h);
    // Annotation rows are self-hashed against the current tip but the tip
    // does NOT advance — the chain's prev never points into an annotation.
    if (!alg.isAnnotation?.(r)) prev = h;
  }
  return rows;
}

// annotateTip(rows, annotation, opts?) -> rows (mutated, returned). Appends a
// v2 ANNOTATION row (STONE-SPEC §4.6, STONE-V2-PILOTS): the row is self-hashed
// against the chain's current tip and prev never advances into it. The
// annotation object must carry kind:'stone.*' (≠ 'stone.header') — e.g.
// { kind:'stone.sign', sig:'...' } for the stapled tip signature. Returns rows.
export function annotateTip(rows, annotation, opts) {
  const algKey = opts?.alg ?? 'stone-v1';
  const alg = ALGS[algKey];
  if (!alg) throw new Error(`stone: unknown alg '${algKey}'`);
  if (!alg.isAnnotation) throw new Error(`stone: alg '${algKey}' has no annotation rule`);
  if (!alg.isAnnotation(annotation)) {
    throw new Error("stone: annotation rows must have kind 'stone.*' (≠ 'stone.header')");
  }
  // Resolve the live tip WITHOUT trusting stored row_hash values: re-derive
  // by walking the chain, skipping annotations exactly like the verifier.
  let prev = opts?.genesis ?? alg.genesis;
  for (const r of rows) {
    if (alg.isAnnotation(r)) continue;
    prev = alg.hashOf(r, prev);
  }
  const row = { ...annotation };
  row[alg.hashField] = alg.hashOf(row, prev);
  rows.push(row);
  return rows;
}

// verifyChain(rows, genesis?, opts?) -> canonical verdict:
//   { ok, firstBadIndex, at, why, alg, genesis, links, tip }
//   ok:true  -> firstBadIndex/at/why null, links = rows.length, tip = last hash
//               (null for an empty chain), alg/genesis = resolved dialect.
//   ok:false -> firstBadIndex = row index of the first break; at = that row's
//               seq (fleet-compat: seq ?? null); why = reason string;
//               tip = last GOOD hash before the break (null if row 0 broke).
// Auto-detects the dialect when no genesis/alg is given; falls back to the
// fleet default so sibling calls verifyChain(rows, 'GENESIS') behave exactly
// like the local implementations.
export function verifyChain(rows, genesis, opts) {
  const o = (genesis && typeof genesis === 'object' && !Array.isArray(genesis))
    ? genesis : (opts ?? {});
  const explicitGenesis = typeof genesis === 'string' ? genesis : undefined;
  let algKey = o.alg ?? detectAlg(rows) ?? 'fnv1a64-fleet';
  let alg = ALGS[algKey];
  if (!alg) {
    return { ok: false, firstBadIndex: 0, at: null, why: 'undetectable dialect', alg: null, genesis: null, links: Array.isArray(rows) ? rows.length : 0, tip: null };
  }
  const g = explicitGenesis ?? o.genesis ?? alg.genesis;
  const base = { alg: algKey, genesis: g, links: rows.length };
  let prev = g;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (!r || typeof r !== 'object') {
      return { ok: false, firstBadIndex: i, at: null, why: 'row is not an object', ...base, tip: i > 0 ? prev : null };
    }
    if (alg.checkLink) {
      const linkBad = alg.checkLink(r, prev, i);
      if (linkBad) return { ok: false, firstBadIndex: i, at: r.seq ?? null, why: linkBad, ...base, tip: i > 0 ? prev : null };
    }
    const hf = alg.hashField;
    if (r[hf] === undefined) {
      return { ok: false, firstBadIndex: i, at: r.seq ?? null, why: `missing ${hf}`, ...base, tip: i > 0 ? prev : null };
    }
    const want = alg.hashOf(r, prev);
    if (want !== r[hf]) {
      const annotation = alg.isAnnotation?.(r) === true;
      return { ok: false, firstBadIndex: i, at: r.seq ?? null, why: annotation ? 'annotation hash mismatch' : 'hash mismatch', ...base, tip: i > 0 ? prev : null };
    }
    // Annotation rows verify but never advance the tip (see ALGS['stone-v1']).
    if (!alg.isAnnotation?.(r)) prev = r[hf];
  }
  return { ok: true, firstBadIndex: null, at: null, why: null, ...base, tip: rows.length > 0 ? prev : null };
}

// verifyChainFile(path, opts?) — read a JSONL chain file and verify it.
// Malformed JSON lines are themselves chain breaks (tamper evidence includes
// the disk format). Returns the canonical verdict plus { path, rows }.
export function verifyChainFile(path, opts) {
  try {
    return verifyChain(readJsonl(path), opts);
  } catch (e) {
    if (e.stoneMalformedLine !== undefined) {
      return { ok: false, firstBadIndex: e.stoneMalformedLine, at: null, why: e.message, alg: null, genesis: null, links: e.stoneMalformedLine, tip: null };
    }
    return { ok: false, firstBadIndex: null, at: null, why: `verifier error: ${e.message}`, alg: null, genesis: null, links: 0, tip: null };
  }
}

function readJsonl(path) {
  const text = readFileSync(path, 'utf8');
  const lines = text.split('\n');
  const rows = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') continue;
    try { rows.push(JSON.parse(line)); }
    catch (e) {
      const err = new Error(`malformed JSON at line ${i + 1}: ${e.message}`);
      err.stoneMalformedLine = i;
      throw err;
    }
  }
  return rows;
}

// ============================================================================
// 4. SEQUENCE-ID HELPER (fleet semantics verbatim)
// ============================================================================

// stamp(prefix?) -> `${prefix}_${Date.now().toString(36)}_${rand36}` —
// an id helper ONLY: stamp outputs are for run/file identity, never hashed
// content (the siblings never put wall-clock or randomness inside a hash).
export function stamp(prefix = 'ln') {
  return `${prefix}_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}
