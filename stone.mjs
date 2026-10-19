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

import { createHash, createPublicKey, createHmac, sign, verify } from 'node:crypto';
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
// 1b. PYTHON'S json.dumps -- the canonical form of the calculator-quilt flavor
// ============================================================================
//
// A FIFTH canonical form, and the only one that is not JSON-native.
//
//   json.dumps(obj, sort_keys=True, separators=(",", ":"))
//
// differs from every other dialect's canon in three ways that all MATTER:
//
//   1. ensure_ascii defaults to True, so non-ASCII is escaped as \uXXXX
//      (JCS and JSON.stringify do not);
//   2. a float prints with repr()'s rules -- `0.0` prints as `0.0`, not `0`;
//   3. an int prints EXACTLY, at any size, because Python's int is
//      arbitrary-precision.
//
// WHICH MEANS THE CANONICAL FORM DEPENDS ON THE LEXICAL FORM OF THE
// NUMBER, and JSON.parse throws that distinction away. So the numbers have
// to survive the parse, and that is what parsePreservingNumbers() is for.
//
// A CONSEQUENCE WORTH KNOWING: this flavor is IMMUNE to the 2^53+1 problem
// that witness-chain-v1 has, because the sentinel carries the original
// text and BigInt keeps an integer exact at any size. The two flavors
// disagree about numbers because they canonicalize them by DIFFERENT
// RULES, and each rule has its own edge.

const PY_RAW = '__PYRAW_NUM__';

// Python's repr() for a float: the shortest round-trip digits, with the
// exponent band Python uses (exponential below 1e-4, at or above 1e16)
// and a two-digit exponent.
export function pyNum(v) {
  if (Number.isInteger(v) && Math.abs(v) < 1e16) return String(v);
  if (!Number.isFinite(v)) return Number.isNaN(v) ? 'NaN' : (v > 0 ? 'Infinity' : '-Infinity');
  if (v === 0) return Object.is(v, -0) ? '-0.0' : '0.0';
  const s = String(v);
  const m = /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]\d+))?$/.exec(s);
  if (!m) return s;
  const neg = m[1] === '-' ? '-' : '';
  const intPart = m[2], fracPart = m[3] || '';
  const exp = m[4] ? parseInt(m[4], 10) : 0;
  const raw = intPart + fracPart;
  const leadZeros = raw.length - raw.replace(/^0+/, '').length;
  const digits = raw.replace(/^0+/, '').replace(/0+$/, '');
  if (!digits) return neg ? '-0.0' : '0.0';
  const decpt = intPart.length + exp - leadZeros;
  const n = digits.length;
  if (decpt > 0 && decpt <= 16) {
    if (decpt >= n) return neg + digits + '0'.repeat(decpt - n) + '.0';
    return neg + digits.slice(0, decpt) + '.' + digits.slice(decpt);
  }
  if (decpt <= 0 && decpt > -4) return neg + '0.' + '0'.repeat(-decpt) + digits;
  const e = decpt - 1;
  const es = (e >= 0 ? '+' : '-') + String(Math.abs(e)).padStart(2, '0');
  return neg + digits[0] + (n > 1 ? '.' + digits.slice(1) : '') + 'e' + es;
}

// Python's json.dumps for a number token: an int prints exactly, a float
// prints by repr(). The token's LEXICAL form decides which.
export function pyNumFromText(t) {
  if (/[.eE]/.test(t)) {
    const v = Number(t);
    if (Number.isInteger(v) && Math.abs(v) < 1e16) {
      return Object.is(v, -0) ? '-0.0' : v.toFixed(1);
    }
    return pyNum(v);
  }
  return String(BigInt(t));
}

// Python's json.dumps for a string: JSON escaping, PLUS ensure_ascii.
export function pyStr(s) {
  return JSON.stringify(s).replace(/[\u0080-\uffff]/g, (c) =>
    '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

// Python sorts str by CODE POINT; JavaScript's default sort is by UTF-16
// code UNIT. They disagree above the BMP, so this is not cosmetic.
export function pySortKeys(keys) {
  return keys.slice().sort((a, b) => {
    const A = Array.from(a), B = Array.from(b);
    const n = Math.min(A.length, B.length);
    for (let i = 0; i < n; i++) {
      const x = A[i].codePointAt(0), y = B[i].codePointAt(0);
      if (x !== y) return x - y;
    }
    return A.length - B.length;
  });
}

export function pyJsonDumps(v) {
  return pyDumps(v, true, true);
}

// THE THREE SEPARATORS IN PLAY. Python's json.dumps has TWO separator
// settings and the fleet uses BOTH, so "json.dumps(sort_keys=True)" is
// NOT one thing -- it is three, and they disagree on every nested
// object and array. Naming them is the only way to keep them apart:
//   compact  true  -> separators=(',',':')   quilt-arcade-adjacent pyjson
//   compact  false -> separators=(', ',': ')  quilt-gpu-lab's probe seal
// and ensure_ascii splits it again (True escapes \uXXXX, False does not).
export function pyJsonDumpsLoose(v) { return pyDumps(v, false, true); }  // gpu-lab
export function pyJsonDumpsUtf8(v) { return pyDumps(v, true, false); }    // moth-ledger

function pyDumps(v, compact, ensureAscii) {
  const c = compact ? ',' : ', ';
  const k = compact ? ':' : ': ';
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return pyNum(v);
  if (typeof v === 'string') {
    if (v.startsWith(PY_RAW)) return pyNumFromText(v.slice(PY_RAW.length));
    return ensureAscii ? pyStr(v) : JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map((e) => pyDumps(e, compact, ensureAscii)).join(c) + ']';
  return '{' + pySortKeys(Object.keys(v))
    .map((key) => (ensureAscii ? pyStr(key) : JSON.stringify(key)) + k +
      pyDumps(v[key], compact, ensureAscii)).join(c) + '}';
}

// FNV-1a-64 over UTF-8 BYTES. Every OTHER dialect in this file iterates
// UTF-16 CODE UNITS, which is what JavaScript's strings are made of. Python
// iterates UTF-8 bytes. The two disagree on any non-ASCII input, which is
// why this is a separate dialect and not a variant of the others.
export function fnv1a64Utf8(s) {
  const b = Buffer.from(s, 'utf8');
  let h = 0xcbf29ce484222325n, p = 0x100000001b3n, m = 0xffffffffffffffffn;
  for (const x of b) { h ^= BigInt(x); h = (h * p) & m; }
  return '0x' + h.toString(16).padStart(16, '0');
}

// FNV-1a-64 over RAW BYTES, 16 lowercase hex, NO '0x'. moth-ledger's
// chain_hash concatenates two 8-byte digests BYTEWISE before hashing --
// there is no string step anywhere in that law -- so this is the entry
// point it needs and the string wrapper above cannot express it.
export function fnv1a64Bytes(buf) {
  let h = 0xcbf29ce484222325n, p = 0x100000001b3n, m = 0xffffffffffffffffn;
  for (const x of buf) { h ^= BigInt(x); h = (h * p) & m; }
  return h.toString(16).padStart(16, '0');
}

// ---------------------------------------------------------------------------
// 1c. ryū / serde_json -- quilt-rust's canonical form (NOT JCS)
// ---------------------------------------------------------------------------
//
// THIRD number law in this file, and the one JCS actively gets wrong.
// RFC 8785 canonicalises `85.0` to `85`; serde_json's Number::to_string
// renders it `85.0`. They agree on every non-float and disagree on every
// float, which is why `quilt-cell-ledger/1` and `quilt-edge/1` cannot be
// verified by the witness-chain-v1 (JCS) dialect and why they get their
// own entries. quilt-rust's own docs name the hazard out loud:
// "JavaScript renders 40.0 as 40; ports must preserve float-vs-int
//  distinction to stay on-chain." The lexical token from
// parsePreservingNumbers is what tells the two apart; JSON.parse cannot.

// Rust sorts strings by UTF-8 BYTE order (String::cmp). JavaScript's
// default sort is by UTF-16 CODE UNIT, and the two disagree above the BMP.
export function utf8SortKeys(keys) {
  return keys.slice().sort((a, b) =>
    Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
}

// serde_json / ryū number rendering: integers as integers, floats as the
// shortest round-trip decimal that KEEPS THE FLOAT MARKER.
export function ryuNumFromText(t) {
  if (!/[.eE]/.test(t)) return String(BigInt(t));       // integer token
  const v = Number(t);
  if (!Number.isFinite(v)) return 'null';                // serde_json's pinned refusal
  const s = String(v);                                   // shortest round-trip
  return /[.eE]/.test(s) ? s : s + '.0';
}

// No lexical form available (a hand-built object, not a parsed row):
// assume the float marker, which is the conservative choice -- an extra
// `.0` is visible, a missing one silently lands on the JCS hash.
export function ryuNum(v) {
  const s = String(v);
  if (!Number.isInteger(v) || !Number.isFinite(v)) return s;
  return s + '.0';
}

// Compact, keys sorted by UTF-8 byte order, serde_json number rendering,
// serde_json string escaping (which -- unlike Python -- does NOT \uXXXX-escape
// non-ASCII; it emits UTF-8 directly).
export function ryuCanonicalJSON(value) {
  // The number-preserving sentinel is what makes this canonical form possible
  // at all: `1000` and `1000.0` are the SAME JavaScript number, and ryū
  // renders them differently. parsePreservingNumbers() keeps the lexical token
  // alive on the row; this is where it is finally spent.
  if (typeof value === 'string' && value.startsWith(PY_RAW)) {
    return ryuNumFromText(value.slice(PY_RAW.length));
  }
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return '[' + value.map(ryuCanonicalJSON).join(',') + ']';
  return '{' + utf8SortKeys(Object.keys(value).filter((k) => value[k] !== undefined))
    .map((k) => JSON.stringify(k) + ':' + ryuCanonicalJSON(value[k])).join(',') + '}';
}

// ryuCanonicalJSON over a number-preserving parse, when the row has one.
export function ryuCanonicalOf(row) {
  const src = row.__pyjson ?? row;
  return ryuCanonicalJSON(src);
}

// Parse JSON, but KEEP THE LEXICAL FORM OF EVERY NUMBER.
export function parsePreservingNumbers(text) {
  const out = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < n) { if (text[j] === '\\') { j += 2; continue; } if (text[j] === '"') break; j++; }
      out.push(text.slice(i, j + 1)); i = j + 1; continue;
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i;
      if (text[j] === '-') j++;
      while (j < n && text[j] >= '0' && text[j] <= '9') j++;
      if (text[j] === '.') { j++; while (j < n && text[j] >= '0' && text[j] <= '9') j++; }
      if (text[j] === 'e' || text[j] === 'E') {
        j++;
        if (text[j] === '+' || text[j] === '-') j++;
        while (j < n && text[j] >= '0' && text[j] <= '9') j++;
      }
      out.push('"' + PY_RAW + text.slice(i, j) + '"'); i = j; continue;
    }
    out.push(c); i++;
  }
  return JSON.parse(out.join(''));
}

// ---------------------------------------------------------------------------
// 1d. quilt-rust's TWO GENESIS COMMITS + the edge provenance seal
// ---------------------------------------------------------------------------
//
// Both are per-cell: they commit to the cell's identity and its declared
// initial state, which is why no constant genesis string can stand in for
// them. Exported so an auditor can recompute a root without rebuilding a
// chain.

// Both take the SPEC OBJECT rather than loose arguments, because their
// preimages contain numbers whose int-vs-float form is the whole point and
// cannot survive being passed through a JavaScript argument list. Hand them
// either a plain object or a parsePreservingNumbers() parse of one.
const specOf = (s) => (s && typeof s === 'object' && s.__pyjson) ? s.__pyjson : (s ?? {});

export function ryuGenesisCommit(spec) {
  const s = specOf(spec);
  return sha256Hex(ryuCanonicalJSON({
    kind: 'quilt-cell-ledger/1',
    cell_id: s.cell_id === undefined ? null : s.cell_id,
    genesis: s.genesis === undefined ? null : s.genesis,
    genesis_ts: s.genesis_ts === undefined ? null : s.genesis_ts,
  }));
}

export function ryuEdgeGenesis(spec) {
  const s = specOf(spec);
  return sha256Hex(ryuCanonicalJSON({
    kind: 'quilt-edge/1',
    cell: s.cell === undefined ? null : s.cell,
    genesis: s.genesis === undefined ? null : s.genesis,
    genesis_ts: s.genesis_ts === undefined ? null : s.genesis_ts,
  }));
}

// The edge provenance preimage, verbatim from
// quilt-rust/bindings/go/internal/ledger/ledger.go seal(). NOT enforced by
// ALGS['quilt-edge/1'] -- see that dialect's comment for why.
export function edgeProvenance(row) {
  return sha256Hex(ryuCanonicalJSON({
    v: row.v, cell: row.cell, ts: row.ts, before: row.before, after: row.after,
    delta: row.delta, imbalance: row.imbalance,
    origin: row.origin === undefined ? null : row.origin,
    caller: row.caller === undefined ? null : row.caller,
    trace: row.trace === undefined ? [] : row.trace,
  }));
}

// The genesis a dialect resolves to for these rows: a dialect may root at a
// per-chain COMMIT rather than a constant string, so this is the ONE place
// that question is asked. Every call site goes through it.
export function genesisOf(algKey, rows) {
  const alg = ALGS[algKey];
  if (!alg) return null;
  return alg.genesisFor ? alg.genesisFor(rows) : alg.genesis;
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
  'fnv1a64-utf8-pyjson': {
    // THE calculator-quilt flavor (SuperInstance/AI-Writings ->
    // labs/examples/calculator-quilt/calc_quilt.py), which the verifier
    // had never heard of and MISDIAGNOSED as fnv1a64-rawpipe.
    //
    //   hash = '0x%016x' % fnv1a64( json.dumps(env, sort_keys=True,
    //                                              separators=(',',':')) )
    //   env  = the record MINUS its `hash`, with `prev` OVERWRITTEN by the
    //          running tip
    //   GENESIS = '0x0000000000000000'
    //
    // AND THE SOURCE'S OWN DOCSTRING SAID "tamper-evident". IT WAS WRONG,
    // AND IT WAS WRONG IN A WAY THAT MATTERED: that docstring is where
    // this chain RULE comes from, so the dialect inherited a false claim
    // about itself. The source docstring is corrected in the same change
    // (SuperInstance/AI-Writings#90). The chain re-derives, which is LEG 1
    // of 3 -- a re-chained edit verifies perfectly and a truncated tail
    // still verifies -- and the head is neither signed nor published out
    // of band, so legs 2 and 3 do not exist. The honest word is
    // ATTESTABLE.
    //
    // THREE THINGS MAKE IT A DIALECT OF ITS OWN:
    //   * FNV over UTF-8 BYTES. Every other dialect here iterates UTF-16
    //     CODE UNITS, because that is what JavaScript strings are made of.
    //     Python iterates UTF-8 bytes. They disagree on non-ASCII.
    //   * a canonical form that is PYTHON's json.dumps, not JSON's: floats
    //     print as `0.0` and not `0`, and non-ASCII is \uXXXX-escaped.
    //   * `prev` is OVERWRITTEN before hashing rather than excluded, so
    //     the STORED `prev` field is not itself covered by the hash.
    //
    // AND THE CONSEQUENCE THAT MATTERS MOST: because the canonical form
    // depends on the LEXICAL form of a number, this flavor can only be
    // verified FROM THE RAW TEXT. JSON.parse throws the int/float
    // distinction away, and a verifier handed a pre-parsed structure
    // cannot re-derive these hashes. readJsonl() therefore keeps a
    // number-preserving parse alongside each row.
    repos: ['AI-Writings'],
    hashField: 'hash', prevField: 'prev',
    genesis: '0x0000000000000000',
    hashForm: /^0x[0-9a-f]{16}$/,
    hashOf(row, prev) {
      const src = row.__pyjson ?? row;
      const env = { ...src };
      delete env.hash;
      env.prev = prev;
      return fnv1a64Utf8(pyJsonDumps(env));
    },
    setLinks(row, prev, hash) { row.prev = prev; row.hash = hash; },
  },
  'witness-chain-v1': {
    // THE SPEC's chain rule, as published in witness-chain/1 and implemented
    // by SuperInstance/AI-Writings' labs/situation-recorder/recorder.py:
    //
    //   leaf(i) = SHA256(0x00 || JCS(record_i))   -- record_i MINUS its own
    //                                                   `hash` field
    //   hash(0) = GENESIS                         -- 0x0000000000000000
    //   hash(i) = SHA256(0x01 || hash(i-1) || leaf(i))
    //   head    = hash(n)
    //
    // The 0x00/0x01 domain separation is RFC 6962 2.1. It is what makes
    // this a DIFFERENT chain from `sha256-canonical` -- which hashes the
    // same canonical bytes with a different envelope -- so the two can
    // never be mistaken for one another.
    //
    // THE LINKAGE LIVES IN RECORD ORDER. A witness-chain/1 record carries
    // `hash` and NO `prev`; `prev` is a property of the CHAIN, not of the
    // row. `detectAlg`'s rawpipe branch requires prev AND hash together, so
    // the two dialects cannot be confused. (This is also why the fleet's
    // canonical verifier used to report ABSENCE where recorder.py stands:
    // it was looking for a `prev` field that this format deliberately
    // does not have.)
    //
    // The version field (`v: "witness-chain/1"`) is INSIDE the hashed bytes,
    // so it cannot be stripped or downgraded without breaking the chain.
    repos: ['AI-Writings', 'witness-spec'],
    hashField: 'hash', prevField: null,
    genesis: '0x0000000000000000',
    hashForm: /^0x[0-9a-f]{64}$/,
    hashOf(row, prev) {
      const leaf = '0x' + sha256Hex('\u0000' + canonicalJSON(withoutKeys(row, ['hash'])));
      return '0x' + sha256Hex('\u0001' + prev + leaf);
    },
    setLinks(row, prev, hash) { row.hash = hash; },
  },
  // ==========================================================================
  // THE CENSUS DIALECTS (2026-10). Every rule below was read out of the OWNER'S
  // OWN SOURCE -- never inferred from a filename, never from a docstring that
  // the code contradicts -- and every one carries the fixture that proves it.
  // ==========================================================================

  'chrono-organ/1': {
    // RULE FROM: quilt-chrono/src/seal.js (buildChain / entryLink / linkHash /
    //   verifyChainLinks) -- the organ-toolkit receipt shape chrono's chain
    //   sidecar (`<ledger>.chain.jsonl`) is built from.
    //
    //   link    = { seq, op, prev, hash }
    //   hash    = sha256_hex( canonicalJson({ seq, op, prev }) )
    //   prev    = the previous link's hash; seq is the 0-BASED INDEX
    //   GENESIS = the literal string 'GENESIS' (src/seal.js CHAIN_GENESIS)
    //
    // `canonicalJson` IS quilt-stone's canonicalJSON -- same function, sorted
    // keys, no whitespace (chrono cites quilt-jev-toolkit's organ manifest.mjs
    // as the upstream law, and the fleet's is already proven JCS-conformant).
    // What makes this a dialect is NOT the canonical form: it is that the
    // preimage is an OBJECT keyed {seq, op, prev}, the position is covered
    // explicitly, the `op` payload rides inside the hash, and the genesis is
    // chrono's own literal rather than a fleet one. sha256-canonical and
    // stone-v1 both hash the canonical form of an ARRAY and neither can
    // reproduce this.
    //
    // THE CHECKPOINT IS A SEPARATE, STRICTER LAYER -- see verifyChronoCheckpoint.
    // A verified sidecar is NOT a sealed prefix: the Ed25519 checkpoint is what
    // names a boundary tip, and without it the chain is attested, not signed.
    repos: ['quilt-chrono'],
    hashField: 'hash', prevField: 'prev', genesis: 'GENESIS',
    hashForm: /^[0-9a-f]{64}$/,
    hashOf(row, prev) {
      return sha256Hex(canonicalJSON({ seq: row.seq, op: row.op, prev }));
    },
    setLinks(row, prev, hash) { row.prev = prev; row.hash = hash; },
    // verifyChainLinks law: seq === 0-based index, prev === running tip.
    checkLink(row, prev, i) {
      if (row.seq !== i) return `seq break at ${i}`;
      if (row.prev !== prev) return `prev break at ${i}`;
      return null;
    },
  },

  'sha256-pyjson-probe': {
    // RULE FROM: quilt-gpu-lab/experiments/d21_perception_ledger.py
    //   (harbor_room(), lines ~165-171):
    //     seal = p.pop("sha256")
    //     ok   = hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest() == seal
    //
    // THIS IS NOT A CHAIN AND THE DIALECT SAYS SO: genesis is null and there
    // is no linkage at all. Every probe is an INDEPENDENT content address.
    // That is why the harness ships a whole-file seal check instead of a
    // walking verifier -- a row here cannot say anything about its neighbours.
    //
    // THE SEPARATORS ARE THE DIALECT. `json.dumps(p, sort_keys=True)` with
    // PYTHON'S DEFAULTS emits ', ' and ': ' -- NOT the compact (',',':') that
    // fnv1a64-utf8-pyjson uses, and not serde_json's form either. Three
    // "sorted-key Python JSON" forms now live in this file and they are not
    // interchangeable; pyJsonDumpsLoose is this one, by name.
    //
    // WHY THIS MUST NOT BE READ AS fnv1a64-utf8-pyjson: the canonical form is
    // a close cousin of that dialect's (both are Python json.dumps with
    // sorted keys) and the shapes are identical -- but the hash is SHA-256,
    // not fnv1a-64, and the separators differ. detectAlg trials this dialect
    // only where no prev/prev_hash/row_hash exists anywhere, and a pyjson
    // chain always carries `prev`, so the two can never be confused.
    repos: ['quilt-gpu-lab'],
    hashField: 'sha256', prevField: null, genesis: null,
    hashForm: /^[0-9a-f]{64}$/,
    hashOf(row) {
      const body = { ...(row.__pyjson ?? row) };
      delete body.sha256;
      return sha256Hex(pyJsonDumpsLoose(body));
    },
    setLinks(row, prev, hash) { row.sha256 = hash; },
  },

  'quilt-cell-ledger/1': {
    // RULE FROM: quilt-rust/packages/core/src/ledger.rs
    //   (LedgerEntry::seal, CellLedger::genesis_commit, verify_chain) and
    //   quilt-rust/docs/cell-ledger.md §4.
    //
    //   hash(e)          = sha256_hex( canonical_json( e minus its hash ) )
    //   e.prev_hash      = the previous entry's hash, or the GENESIS COMMIT
    //   genesis_commit   = sha256_hex( canonical_json({
    //                         "kind": "quilt-cell-ledger/1",
    //                         "cell_id": …, "genesis": …, "genesis_ts": … }) )
    //
    // THREE THINGS MAKE THIS ITS OWN ENTRY:
    //   1. THE GENESIS IS NOT A CONSTANT. Every other dialect in this registry
    //      roots at a fixed string; this one roots at a PER-CELL COMMIT HASH
    //      that binds the cell's identity and its declared initial state. Two
    //      cells' ledgers never share a root. genesisFor() reads it off the
    //      rows when they carry it, and callers that hold only entries pass the
    //      commit explicitly -- which is exactly what a real verifier must do.
    //   2. THE CANONICAL FORM IS ryū/serde, NOT JCS. `40.0` stays `40.0`;
    //      RFC 8785 would send `40`. Proven against the owner's own
    //      compat/golden.json genesis commit -- see the test suite.
    //   3. THE PREIMAGE IS THE WHOLE ENTRY, linkage included: prev_hash is
    //      INSIDE the hashed bytes, so a rewrite of the link breaks the seal.
    // genesisRequired: this dialect's root is a PER-CELL COMMIT HASH, and
    // the owner commits entries WITHOUT the cell identity they belong to --
    // cell_id/genesis/genesis_ts live on the CellLedger, not on its entries.
    // So the root cannot be recovered from the rows alone and a caller that
    // has only entries MUST supply it (ryuGenesisCommit) or the verdict says
    // exactly that instead of blaming a hash that was never wrong.
    genesisRequired: true,
    repos: ['quilt-rust'],
    hashField: 'hash', prevField: 'prev_hash',
    genesis: null,
    genesisFor(rows) {
      const r0 = (rows && rows[0]) || {};
      if (r0.cell_id === undefined && r0.genesis === undefined && r0.genesis_ts === undefined) return null;
      return ryuGenesisCommit(r0);
    },
    hashForm: /^[0-9a-f]{64}$/,
    hashOf(row) {
      return sha256Hex(ryuCanonicalOf(withoutKeys(row, ['hash'])));
    },
    setLinks(row, prev, hash) { row.prev_hash = prev; row.hash = hash; },
    checkLink(row, prev /*, i*/) {
      if (row.prev_hash !== prev) return 'prev_hash mismatch';
      return null;
    },
  },

  'quilt-edge/1': {
    // RULE FROM: quilt-rust/bindings/go/internal/ledger/ledger.go
    //   (GenesisCommit, ChainHash) and bindings/go/README.md -- the port that
    //   spells the two formulas out in full.
    //
    //   chain_0 = sha256_hex( canonical_json({ "kind":"quilt-edge/1",
    //                                          "cell":…, "genesis":…,
    //                                          "genesis_ts":… }) )
    //   chain_i = sha256_hex( chain_{i-1} + ":" + provenance_i )
    //
    // THE LINK IS NOT A HASH OF A ROW. chain_i is a plain SHA-256 over the
    // CONCATENATION of the previous chain hash, a literal colon, and the
    // edge's provenance seal -- no JSON, no object, no fields. Nothing else in
    // this registry links that way. Like the cell ledger the root is per-cell.
    //
    // HONEST LIMIT, STATED BECAUSE IT IS A LIMIT: the `provenance` sub-seal
    // (sha256 over {v,cell,ts,before,after,delta,imbalance,origin,caller,
    // trace}) is implemented as edgeProvenance() below and read verbatim from
    // the owner's source -- but it is NOT enforced in checkLink, because the
    // only committed edge chains (bindings/go/golden.json) do not carry
    // origin/caller/trace, so enforcing it would be verifying against an
    // invented row shape. The CHAIN law is enforced, and the chain law is
    // what the committed goldens prove.
    genesisRequired: true,   // per-cell root; see the cell-ledger note above
    repos: ['quilt-rust'],
    hashField: 'chain', prevField: null, genesis: null,
    genesisFor(rows) {
      const r0 = (rows && rows[0]) || {};
      if (r0.genesis === undefined && r0.genesis_ts === undefined) return null;
      return ryuEdgeGenesis(r0);
    },
    hashForm: /^[0-9a-f]{64}$/,
    // The law consumes the edge's provenance SEAL, which the row carries --
    // it does not re-seal the body and then chain the result. Whether that
    // seal is itself re-derivable is the sub-rule below.
    hashOf(row, prev) {
      return sha256Hex(prev + ':' + row.provenance);
    },
    setLinks(row, prev, hash) { row.chain = hash; },
    // The provenance sub-seal is enforced WHEN THE ROW CARRIES THE FIELDS IT
    // IS SEALED OVER. The committed golden edges do not (no origin/caller/
    // trace), and silently treating an absent field as null would re-seal
    // over a body the owner never wrote -- so there the check is skipped and
    // says so, rather than passing on a preimage nobody can produce.
    checkLink(row) {
      // `v` alone is not enough: the committed golden edges carry `v` but not
      // the three provenance fields, and re-sealing those over nulls the owner
      // never wrote would fail every honest chain. Enforced only when the row
      // carries the WHOLE provenance body.
      if (row.origin === undefined || row.caller === undefined ||
          row.trace === undefined || row.v === undefined) return null;
      const want = edgeProvenance(row);
      if (row.provenance !== want) return 'edge provenance mismatch';
      return null;
    },
  },

  'moth-ledger/1': {
    // RULE FROM: moth-ledger/src/moth_ledger/ledger.py (Ledger.append,
    //   verify_chain), canonical.py (canonical_dumps), hashes.py (fnv1a_64_hex),
    //   and the README's own two-line statement of the law.
    //
    //   row_hash   = fnv1a64_hex( canonical_dumps(row minus row_hash+chain_hash) )
    //   chain_hash = fnv1a64_hex( bytes.fromhex(prev_chain_hash)
    //                             + bytes.fromhex(row_hash) )      # GENESIS "0"*16
    //
    // THE LINK IS BINARY. The two digests are decoded to their 8 raw bytes and
    // concatenated; there is no string step, no separator, no canonical form.
    // Every other linkage in this file is a string or an object. Getting this
    // wrong in the STRING direction still "looks" like a plausible chain,
    // which is why it is a named dialect and not a variant of the fnv ones.
    //
    // TWO MORE THINGS THAT ARE NOT THE PYTHON DIALECTS ALREADY HERE:
    //   * canonical_dumps uses ensure_ascii=False -- non-ASCII is emitted as
    //     UTF-8, NOT \uXXXX-escaped like fnv1a64-utf8-pyjson;
    //   * the fnv1a-64 runs over UTF-8 BYTES (pyJsonDumps emits bytes), while
    //     every other dialect in this file walks UTF-16 code units.
    //
    // PROVENANCE NOTE: moth-ledger commits NO chain file -- its own tests build
    // ledgers in a tmpdir. fixtures/moth-ledger-chain.jsonl was produced by
    // RUNNING moth-ledger's own Ledger class (its verify_chain() returned true
    // on it), so it is the owner's implementation agreeing with this one, not
    // this one agreeing with itself. See fixtures/README.md.
    repos: ['moth-ledger'],
    hashField: 'chain_hash', prevField: null, genesis: '0'.repeat(16),
    hashForm: /^[0-9a-f]{16}$/,
    hashOf(row, prev) {
      const body = { ...(row.__pyjson ?? row) };
      delete body.row_hash; delete body.chain_hash;
      const rowHash = fnv1a64Bytes(Buffer.from(pyJsonDumpsUtf8(body), 'utf8'));
      const a = Buffer.from(prev, 'hex'), b = Buffer.from(rowHash, 'hex');
      return fnv1a64Bytes(Buffer.concat([a, b]));
    },
    setLinks(row, prev, hash) { row.chain_hash = hash; },
  },

  'quilt-doctor-wal': {
    // RULE FROM: pong-quilt/tools/wal-export.js (toQuiltWal, verifyQuiltWal,
    //   canonical) -- the {args, cell, hash, op, prev_hash, seq} WAL that
    //   quilt_doctor/substrate.py's QuiltSubstrate.verify() consumes, mirrored
    //   line-for-line so a pin can prove the export fails the doctor's checks
    //   exactly when tampered, in the doctor's own vocabulary.
    //
    //   hash      = fnv1a64( canonical( line minus its hash ) )
    //   prev_hash = the previous line's hash; GENESIS '0'*16 at seq 0
    //
    // CLOSE RELATIVES, AND THIS IS WHY IT IS NOT A VARIANT OF EITHER:
    //   * vs fnv1a64-quant -- quant sorts the TOP LEVEL ONLY; canonical()
    //     here recurses, so the two diverge the moment `args` is an object.
    //   * vs fnv1a64-rawpipe -- rawpipe masks every code unit & 0xff and
    //     hashes `prev + '|' + body`; this hashes the WHOLE line (prev_hash
    //     included) with full code units and no separator.
    //   * vs fnv1a64-fleet -- that is 0x-prefixed and insertion-ordered.
    //
    // PROVENANCE NOTE: pong-quilt commits no quilt-doctor WAL -- its
    // checkpoints/ are all stone-v1. fixtures/pong-quilt-doctor-wal.jsonl is
    // the byte output of `node tools/wal-export.js`, the repo's own committed
    // demo driver (fixed inputs, no RNG, verified byte-identical across runs).
    repos: ['pong-quilt'],
    hashField: 'hash', prevField: 'prev_hash', genesis: '0'.repeat(16),
    hashForm: /^[0-9a-f]{16}$/,
    hashOf(row) {
      return fnv1a64QuantString(canonDeep(withoutKeys(row, ['hash'])));
    },
    setLinks(row, prev, hash) { row.prev_hash = prev; row.hash = hash; },
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

// ---------------------------------------------------------------------------
// PROVENANCE, AS DATA. A dialect with no named source of truth is a dialect
// that will drift -- and prose alone drifts silently, because nobody greps a
// comment when a sibling repo changes its hash. Every census dialect therefore
// also registers its owner source file HERE, where a test can pin it and a
// reviewer can see the diff. `repos:` in ALGS names the OWNER; this names the
// FILE the rule was read out of. Keep the two in step.
// ---------------------------------------------------------------------------
export const RULE_FROM = {
  'chrono-organ/1': 'quilt-chrono/src/seal.js',
  'sha256-pyjson-probe': 'quilt-gpu-lab/experiments/d21_perception_ledger.py',
  'quilt-cell-ledger/1': 'quilt-rust/packages/core/src/ledger.rs',
  'quilt-edge/1': 'quilt-rust/bindings/go/internal/ledger/ledger.go',
  'moth-ledger/1': 'moth-ledger/src/moth_ledger/ledger.py',
  'quilt-doctor-wal': 'pong-quilt/tools/wal-export.js',
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
  let prev = genesisOf(algKey, rows);
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

  // One structural survey, then a TRIAL LADDER. Every rung below is either
  // a rule that was here before this file changed (in which case its position
  // is untouched) or a new census dialect, and every new rung is tried
  // AGAINST ITS OWN TRIAL and only claimed on a full re-derivation. A shape
  // guess is never a verdict: where the shape is ambiguous, the chain is
  // reported under the primary dialect and the verdict carries the `why`.
  let hasPrevHash = false, hasPlainHash = false, hasChainHash = false;
  let hasChain = false, hasSeal = false, hasOtherLink = false;
  let prevAndHash = false;
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    if (r.prev_hash !== undefined) hasPrevHash = true;
    if (r.chain_hash !== undefined) hasChainHash = true;
    if (r.chain !== undefined) hasChain = true;
    if (r.hash !== undefined) hasPlainHash = true;
    if (r.sha256 !== undefined) hasSeal = true;
    if (r.prev !== undefined && r.hash !== undefined) prevAndHash = true;
    // NOTE: `chain` is deliberately NOT in this list. It is quilt-edge/1's
    // linkage field and no other dialect in this registry has one, so
    // counting it here would make hasOtherLink true for a quilt-edge chain
    // and lock out its own rung below.
    if (r.prev !== undefined || r.prev_hash !== undefined ||
        r.row_hash !== undefined || r.chain_hash !== undefined) hasOtherLink = true;
  }

  // 2. `prev` + `hash` together: rawpipe, the calculator-quilt flavor, or a
  //    chrono organ sidecar. They are discriminated by TRIAL, not by a guess
  //    -- and the trials must come first, because the old code returned
  //    rawpipe UNVERIFIED and so reported "seq break at 0" for a chain that
  //    is perfectly valid under its own rule. Order within the branch is
  //    fnv1a64-utf8-pyjson, chrono-organ/1, then rawpipe UNCHANGED.
  if (prevAndHash) {
    if (trialOk(rows, 'fnv1a64-utf8-pyjson')) return 'fnv1a64-utf8-pyjson';
    if (trialOk(rows, 'chrono-organ/1')) return 'chrono-organ/1';
    // A BROKEN chain cannot be trial-identified -- that is what a broken chain
    // is. Falling straight to rawpipe would then blame a chain for "seq break
    // at 0" when the actual break is three rows in and rawpipe never applied
    // to it. The hash FORM settles it without a trial: rawpipe (and the
    // calculator-quilt flavor) carry `0x`+16hex, a chrono organ link carries
    // bare 64-hex sha256. Same discriminator the row_hash ladder below uses.
    const h = String(rows.find((r) => r && typeof r.hash === 'string')?.hash ?? '');
    return /^0x[0-9a-f]{16}$/.test(h) ? 'fnv1a64-rawpipe' : 'chrono-organ/1';
  }

  // 3. `prev_hash`: quant/tidepool first, exactly as before, then the two
  //    sha256 dialects that use the same field names with a DIFFERENT
  //    canonical form. quant and tidepool need `row_hash`, so a chain that
  //    carries only `hash` cannot be taken by them whatever the order.
  if (hasPrevHash) {
    if (trialOk(rows, 'fnv1a64-quant')) return 'fnv1a64-quant';
    if (trialOk(rows, 'fnv1a64-tidepool')) return 'fnv1a64-tidepool';
    if (trialOk(rows, 'quilt-cell-ledger/1')) return 'quilt-cell-ledger/1';
    if (trialOk(rows, 'quilt-doctor-wal')) return 'quilt-doctor-wal';
    // A `hash` + `prev_hash` row CANNOT be quant or tidepool -- both require
    // a `row_hash` field these rows do not carry, so their trials could only
    // ever fail. Reporting such a chain as fnv1a64-quant would name a rule
    // that cannot apply to it, and would do so with a reason ("prev_hash
    // mismatch at 0") that names the wrong dialect AND the wrong row. The
    // hash width picks the rule that fits, exactly as the row_hash ladder
    // below does: 64-hex is a sha256 cell-ledger chain, 16-hex is the
    // quilt-doctor WAL. This matters most for BROKEN chains, which by
    // definition cannot be trial-identified at all.
    const hp = String(rows.find((r) => r && typeof r.hash === 'string')?.hash ?? '');
    if (/^[0-9a-f]{64}$/.test(hp)) return 'quilt-cell-ledger/1';
    if (/^[0-9a-f]{16}$/.test(hp)) return 'quilt-doctor-wal';
    return 'fnv1a64-quant';
  }

  // 4. `chain_hash` (+ `row_hash`): moth-ledger. Its link is the BINARY
  //    concatenation of the previous chain digest and the row digest, so it
  //    cannot be mistaken for a string-linking dialect -- but only its own
  //    re-derivation proves that, hence the trial.
  if (hasChainHash) {
    if (trialOk(rows, 'moth-ledger/1')) return 'moth-ledger/1';
    return 'moth-ledger/1'; // verdict carries why
  }

  // 5. a `hash` field and NO prev / prev_hash / row_hash / chain_hash /
  //    chain anywhere -> witness-chain-v1. The SHAPE is a guess; the TRIAL is
  //    the proof, and a chain that fails the trial is still reported under
  //    this dialect so the verdict carries WHY rather than "undetectable".
  if (hasPlainHash && !hasOtherLink) {
    if (trialOk(rows, 'witness-chain-v1')) return 'witness-chain-v1';
    return 'witness-chain-v1';
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

  // 6. `chain` and nothing else: a quilt-edge/1 per-cell edge chain. Last,
  //    because it is the only dialect whose link lives in a field the other
  //    twelve never look at.
  if (hasChain && !hasOtherLink && rh === null) {
    if (trialOk(rows, 'quilt-edge/1')) return 'quilt-edge/1';
    return 'quilt-edge/1';
  }

  // 7. `sha256` and NO link field anywhere: a per-record content seal with
  //    no linkage at all (quilt-gpu-lab's probes). Gated on the ABSENCE of
  //    every link field so it cannot claim a chain that happens to carry an
  //    unrelated sha256 column.
  if (hasSeal && !hasOtherLink && !hasPlainHash) {
    if (trialOk(rows, 'sha256-pyjson-probe')) return 'sha256-pyjson-probe';
    return 'sha256-pyjson-probe';
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
  let prev = (typeof genesis === 'string' ? genesis : o.genesis) ??
    genesisOf(algKey, rows);
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
  let prev = opts?.genesis ?? (alg.genesisFor ? alg.genesisFor(rows) : alg.genesis);
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
  const g = explicitGenesis ?? o.genesis ?? genesisOf(algKey, rows);
  const base = { alg: algKey, genesis: g, links: rows.length };
  if (alg.genesisRequired && (g === null || g === undefined)) {
    // A dialect whose root is a per-chain COMMIT, verified against rows that
    // do not carry the parameters that commit is built from. This is not a
    // broken chain and must never be reported as one -- the honest verdict
    // names what is missing and how to supply it.
    return {
      ok: false, firstBadIndex: 0, at: null,
      why: `${algKey}: per-chain genesis commit not present in the rows — supply it `
        + `(ryuGenesisCommit / ryuEdgeGenesis) as opts.genesis`,
      ...base, tip: null,
    };
  }
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

// ============================================================================
// 3b. V2 TIP SIGNATURES (STONE-V2-PILOTS first sign lane)
// ============================================================================

// bodyTip(rows, alg): the hash of the last NON-ANNOTATION row, re-derived by
// walking the chain from genesis — never trusting a stored tip or row_hash.
function bodyTip(rows, alg) {
  let prev = alg.genesisFor ? alg.genesisFor(rows) : alg.genesis;
  let seen = false;
  for (const r of rows) {
    if (!r || typeof r !== 'object' || alg.isAnnotation(r)) continue;
    prev = alg.hashOf(r, prev);
    seen = true;
  }
  return seen ? prev : null;
}

// signTip(rows, privateKey, opts?) -> rows (mutated, returned). Staples an
// ed25519 signature on the chain's BODY tip as a 'stone.sign' ANNOTATION row
// (STONE-V2-PILOTS): the signed message is the domain-separated string
// "stone-v2" || tip_row_hash; the row itself carries
//   { kind:'stone.sign', alg:'ed25519', key_id?, signer_role?, tip, sig }
// — the signature block names its own key id, algorithm, and signer role
// (genesis convention unchanged: STONE-GENESIS-1), and the stored `tip` field
// binds the signature to the exact chain it staples. privateKey is a
// node:crypto ed25519 private KeyObject (or PEM/DER string). Keys live with
// the PRODUCER — one key per producer repo, never fleet-wide (a leaked key
// elsewhere must not be able to re-sign this repo's artifacts).
export function signTip(rows, privateKey, opts) {
  const algKey = opts?.alg ?? 'stone-v1';
  const alg = ALGS[algKey];
  if (!alg) throw new Error(`stone: unknown alg '${algKey}'`);
  if (!alg.isAnnotation) throw new Error(`stone: alg '${algKey}' has no annotation rule`);
  const tip = bodyTip(rows, alg);
  if (tip === null) throw new Error('stone: cannot sign an empty chain (no body rows)');
  const msg = Buffer.concat([Buffer.from('stone-v2', 'utf8'), Buffer.from(tip, 'utf8')]);
  const sig = sign(null, msg, privateKey).toString('hex');
  return annotateTip(rows, {
    kind: 'stone.sign',
    alg: 'ed25519',
    key_id: opts?.key_id,
    signer_role: opts?.signer_role,
    tip,
    sig,
  }, opts);
}

// edVerify(msg, sig, pub): one-shot ed25519 verify across runtime dialects.
// Node's documented order is verify(null, data, signature, key); some fleet
// runtimes bind verify(null, data, key, signature) — both are tried, the
// arg-type error is the discriminator (detected by running, pinned in smoke).
function edVerify(msg, sig, pub) {
  try { return verify(null, msg, sig, pub); }
  catch (e) {
    if (e && e.code === 'ERR_INVALID_ARG_TYPE') return verify(null, msg, pub, sig);
    throw e;
  }
}

// verifyTipSignature(rows, publicKey, opts?) -> { ok, why, tip, signer,
// identity, binding_only }. The auditor entry point (success receipt of
// STONE-V2-PILOTS): re-derives the body tip WITHOUT trusting stored hashes,
// binds the last stapled 'stone.sign' row to it (stored tip field must equal
// the derived tip), then verifies the ed25519 signature over '"stone-v2" ||
// tip'. This closes the gap between "chain verifies" and "this exact byte
// string was signed by the producer key": a chain edited after signing
// re-seals into self-consistent hashes, but the signature still names the
// OLD tip (R22 P3-process lie class, at rest). ok:false verdicts name why:
// no stapled row / unsupported alg / no body rows / signed-tip mismatch /
// signature invalid for this key.
//
// KEY PROVENANCE (AUDITOR-EXPERIENCE.md note 2 — binding != identity): an
// embedded public key establishes only BINDING (one key signed this tip
// continuously), never IDENTITY ("Casey signed it"). opts.trustedKeys is the
// auditor's out-of-band key-id registry (Map or object: key_id -> publicKey).
// When provided and the verifying key matches a registered entry, the result
// upgrades: identity = { key_id, signer_role }. When the sign row's CLAIMED
// key_id maps to a DIFFERENT key (identity laundering by label), or the key
// matches no registry entry, ok stays true (the binding IS valid) but
// identity is null and binding_only is true — the claimed label is NEVER
// promoted to identity on binding alone. Without a registry the result is
// binding_only by definition.
export function verifyTipSignature(rows, publicKey, opts) {
  const algKey = opts?.alg ?? 'stone-v1';
  const alg = ALGS[algKey];
  const fail = (why) => ({ ok: false, why, tip: null, signer: null, identity: null, binding_only: true });
  if (!alg) return fail(`unknown alg '${algKey}'`);
  if (!alg.isAnnotation) return fail(`alg '${algKey}' has no annotation rule`);
  let signIdx = -1;
  for (let i = rows.length - 1; i >= 0; i--) {
    if (alg.isAnnotation(rows[i]) && rows[i].kind === 'stone.sign') { signIdx = i; break; }
  }
  if (signIdx < 0) return fail('no stone.sign row stapled');
  const signRow = rows[signIdx];
  if (signRow.alg !== 'ed25519') return fail(`unsupported signature alg '${signRow.alg}'`);
  const tip = bodyTip(rows.slice(0, signIdx), alg);
  if (tip === null) return fail('no body rows before the stone.sign row');
  if (signRow.tip !== tip) return fail('signed tip does not match the chain tip (post-signature chain edit)');
  const msg = Buffer.concat([Buffer.from('stone-v2', 'utf8'), Buffer.from(tip, 'utf8')]);
  let good = false;
  try { good = edVerify(msg, Buffer.from(signRow.sig, 'hex'), publicKey); }
  catch { good = false; }
  if (!good) return fail('signature invalid for this tip and key');
  const signer = { alg: 'ed25519', key_id: signRow.key_id ?? null, signer_role: signRow.signer_role ?? null };
  // binding -> identity upgrade against the auditor's out-of-band registry.
  let identity = null;
  let binding_only = true;
  let identity_claim_conflict = false;
  const reg = opts?.trustedKeys;
  if (reg) {
    let verifiedKeyId = null;
    let pubDer = null;
    const derOf = (k) => {
      try {
        // node >= 22 rejects createPublicKey on an existing public KeyObject
        const pub = (k && k.type === 'public') ? k : createPublicKey(k);
        return pub.export({ format: 'der', type: 'spki' });
      } catch { return null; }
    };
    pubDer = derOf(publicKey);
    const entries = reg instanceof Map ? reg.entries() : Object.entries(reg);
    for (const [kid, regPub] of entries) {
      const regDer = derOf(regPub);
      if (pubDer && regDer && regDer.equals(pubDer)) { verifiedKeyId = kid; break; }
    }
    if (verifiedKeyId !== null) {
      identity = { key_id: verifiedKeyId, signer_role: signer.signer_role };
      binding_only = false;
      // the signature block's own key_id label must agree with the registry
      // match — a labeled key that ISN'T the registered key under that label
      // is identity laundering, caught even when the label text matches.
      if (signer.key_id !== null && signer.key_id !== verifiedKeyId) identity_claim_conflict = true;
    } else if (signer.key_id !== null) {
      // claimed key_id matched no registered key: the claim is unproven.
      // binding stays valid; the label is explicitly NOT promoted.
      identity_claim_conflict = true;
    }
  }
  return { ok: true, why: null, tip, signer, identity, binding_only, identity_claim_conflict };
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

// THE ONE JSONL PARSER. Everything that reads a chain file goes through
// this, because there is a flavor whose canonical form depends on the
// LEXICAL form of a number, and a second parser that forgets that will
// misdiagnose a valid chain -- which is exactly what the fleet scan was
// doing before this function existed.
export function parseJsonl(text) {
  const lines = text.split('\n');
  const rows = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') continue;
    try {
      const row = JSON.parse(line);
      // Keep the LEXICAL form of every number alongside the row, for the
      // one flavor whose canonical form depends on it (fnv1a64-utf8-pyjson:
      // Python's json.dumps prints `0.0` and not `0`, and JSON.parse cannot
      // tell them apart). NON-ENUMERABLE, so it does not show up in
      // Object.keys, JSON.stringify, or any other dialect's canon.
      try {
        Object.defineProperty(row, '__pyjson', {
          value: parsePreservingNumbers(line), enumerable: false,
        });
      } catch (e) { /* frozen row: fall back to the plain parse */ }
      rows.push(row);
    }
    catch (e) {
      const err = new Error(`malformed JSON at line ${i + 1}: ${e.message}`);
      err.stoneMalformedLine = i;
      throw err;
    }
  }
  return rows;
}

function readJsonl(path) {
  return parseJsonl(readFileSync(path, 'utf8'));
}

// ============================================================================
// 3c. SIGNED ENVELOPES — the layers that sit ON TOP OF a chain
// ============================================================================
//
// A chain that verifies is ATTESTED. A chain whose tip is covered by a
// signature from a named key is SIGNED. Those are different claims and the
// fleet currently conflates them, so both envelope laws get a verifier here
// rather than being left implicit in whichever repo minted them.

// hex64 / hex128 — the two widths every signed artefact in this file uses.
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const HEX16 = /^[0-9a-f]{16}$/;

// Ed25519 raw 32-byte public key -> SPKI DER (prefix from RFC 8410 §9).
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function ed25519PublicKeyFromRaw(pub32) {
  if (!pub32 || pub32.length !== 32) return null;
  try { return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, pub32]), format: 'der', type: 'spki',
  }); } catch { return null; }
}

// ---------------------------------------------------------------------------
// quilt-chrono's organ checkpoint (src/seal.js, v3 §10.1)
// ---------------------------------------------------------------------------
//   sig       = Ed25519(signer_sk, canonicalJson({hash, manifestHash, seq}))
//   fingerprint = sha256( the signer's SPKI PEM )   <- the shared identity law
//   manifestHash = sha256( canonicalJson(manifest minus its own manifestHash) )
//
// The CHECKPOINT is what makes a chrono chain signed rather than merely
// attested: it pins ONE boundary tip, so a fully re-hashed tail past `seq`
// is a different fork the signature does not cover. verifyChain never claims
// that; this function does, and only this one.
export function chronoCheckpointPayload(seal) {
  return canonicalJSON({ hash: seal.hash, manifestHash: seal.manifestHash, seq: seal.seq });
}

export function ed25519Fingerprint(publicKey) {
  const spki = createPublicKey(publicKey).export({ type: 'spki', format: 'pem' });
  return sha256Hex(spki.toString());
}

export function verifyChronoCheckpoint(cp, publicKey, opts = {}) {
  const fail = (why) => ({ ok: false, why, seq: null, chainTip: null, manifestHash: null,
                           signer: null, anchorChecked: false, shapeChecked: false });
  if (!cp || typeof cp !== 'object' || Array.isArray(cp)) return fail('CHECKPOINT_MALFORMED: not an object');
  // The schema fields are checked WHEN PRESENT and required to be right when
  // they are. quilt-chrono's committed proof receipt stores the seal block
  // abridged ({alg, seq, hash, manifestHash, publicKeyFingerprint, sig}) and
  // omits them, so demanding them would reject the owner's own evidence; but a
  // checkpoint that DOES declare a schema and declares the wrong one is
  // refused. shapeChecked says which happened -- a verdict that silently
  // skipped a check must not read like one that passed it.
  let shapeChecked = false;
  if (cp.schema !== undefined || cp.schemaVersion !== undefined) {
    shapeChecked = true;
    if (cp.schema !== 'quilt.organ.checkpoint' || cp.schemaVersion !== 1) {
      return fail(`CHECKPOINT_MALFORMED: schema ${cp.schema}/${cp.schemaVersion} not implemented`);
    }
  }
  if (!Number.isInteger(cp.seq) || cp.seq < 0) return fail('CHECKPOINT_MALFORMED: seq must be a non-negative integer');
  for (const f of ['hash', 'manifestHash']) {
    if (typeof cp[f] !== 'string' || !HEX64.test(cp[f])) return fail(`CHECKPOINT_MALFORMED: ${f} missing or not sha256 hex`);
  }
  const payload = chronoCheckpointPayload(cp);

  // The carried prefix manifest must re-hash to the SIGNED manifestHash, when
  // the checkpoint carries one at all (the committed proof receipt does not).
  let anchorChecked = false;
  if (cp.manifest && typeof cp.manifest === 'object') {
    const carried = { ...cp.manifest };
    const carriedHash = carried.manifestHash;
    delete carried.manifestHash;
    anchorChecked = true;
    if (carriedHash !== cp.manifestHash || sha256Hex(canonicalJSON(carried)) !== cp.manifestHash) {
      return fail('CHECKPOINT_ANCHOR_MISMATCH: prefix manifest does not re-hash to the signed manifestHash');
    }
  }

  if (cp.alg === 'Ed25519') {
    if (typeof cp.publicKeyFingerprint !== 'string' || !HEX64.test(cp.publicKeyFingerprint)) {
      return fail('CHECKPOINT_MALFORMED: ed25519 checkpoint carries no usable publicKeyFingerprint');
    }
    if (typeof cp.sig !== 'string' || !HEX128.test(cp.sig)) {
      return fail('CHECKPOINT_MALFORMED: checkpoint sig missing or not 128-hex');
    }
    let fp;
    try { fp = ed25519Fingerprint(publicKey); } catch { return fail('CHECKPOINT_SIGNATURE_INVALID: provided key is unusable Ed25519 key material'); }
    if (fp !== cp.publicKeyFingerprint) {
      return fail('CHECKPOINT_SIGNATURE_INVALID: checkpoint names a signer this key is not');
    }
    if (!edVerify(Buffer.from(payload, 'utf8'), Buffer.from(cp.sig, 'hex'), publicKey)) {
      return fail('CHECKPOINT_SIGNATURE_INVALID: Ed25519 signature does not verify under this key');
    }
    return { ok: true, why: null, seq: cp.seq, chainTip: cp.hash, manifestHash: cp.manifestHash,
             signer: { alg: 'Ed25519', publicKeyFingerprint: fp }, anchorChecked, shapeChecked };
  }

  if (cp.alg === 'HMAC-SHA256') {
    if (typeof cp.sig !== 'string' || !HEX64.test(cp.sig)) {
      return fail('CHECKPOINT_MALFORMED: checkpoint sig missing or not sha256 hex');
    }
    const k = typeof publicKey === 'string' ? Buffer.from(publicKey, 'utf8') : publicKey;
    const mac = createHmac('sha256', k).update(payload, 'utf8').digest('hex');
    if (mac !== cp.sig) return fail('CHECKPOINT_SIGNATURE_INVALID: HMAC does not verify under this key');
    return { ok: true, why: null, seq: cp.seq, chainTip: cp.hash, manifestHash: cp.manifestHash,
             signer: { alg: 'HMAC-SHA256', publicKeyFingerprint: null }, anchorChecked, shapeChecked };
  }

  return fail(`CHECKPOINT_MALFORMED: alg ${JSON.stringify(cp.alg)} not implemented (fail-closed)`);
}

// verifyChronoCustody(cp, publicKey, links) — the full courtroom: the
// checkpoint's signature must pin THIS chain's tip at THIS boundary. A chain
// that verifies on its own but whose tip is not the signed one has not been
// signed by anybody, and that is the difference this function exists for.
export function verifyChronoCustody(cp, publicKey, links) {
  const v = verifyChronoCheckpoint(cp, publicKey);
  if (!v.ok) return v;
  const chain = verifyChain(links, 'GENESIS', { alg: 'chrono-organ/1' });
  if (!chain.ok) return { ...v, ok: false, why: `chain broken at ${chain.firstBadIndex}: ${chain.why}` };
  if (cp.seq >= links.length) {
    return { ...v, ok: false, why: 'CHECKPOINT_SEQ_BEYOND_RECEIPTS: checkpoint anchors past the carried chain' };
  }
  const atBoundary = links[cp.seq][ALGS['chrono-organ/1'].hashField];
  if (atBoundary !== cp.hash) {
    return { ...v, ok: false, why: 'CHECKPOINT_ANCHOR_MISMATCH: the signed tip is not this chain\'s tip at the anchored seq' };
  }
  return { ...v, chainOk: true, chainTipAtSeq: atBoundary, chainHead: chain.tip };
}

// ---------------------------------------------------------------------------
// jev-quilt's receipts-v2 signed envelope
// (jev_quilt/signed_receipts.py -- canonical_bytes / chain_head_hex /
//  message_bytes / verify_bytes)
// ---------------------------------------------------------------------------
//
// THE SIGNATURE IS OVER A PIPE-JOINED PREIMAGE, NOT JSON. The module
// docstring says "BLAKE3(canonical_bytes || chain_head)" and the shape is
// easy to assume is json.dumps(sort_keys=True); NEITHER IS TRUE. seal_bytes
// calls ed25519.sign(seed, message_bytes(...)) directly -- BLAKE3 is vendored
// in the package and never called on this path. The owner's own published
// vectors (vectors/signed_receipt_vectors.json, "byte-identity is the
// acceptance test") settle it: the signature reproduces byte-for-byte over
// the plain Ed25519 of canonical_bytes || chain_head, and does not reproduce
// over anything else. That vector is the fixture for this function.
//
// canonical_bytes = `${tick}|${state_hash}|${delta_hash}|${decision_kind}|${payload_hash}`
//   where payload_hash is RE-DERIVED from the retained residue text whenever
//   the receipt carries one (`fnv1a64(residue.utf8)`, 16 hex), and only falls
//   back to the stored hash when the payload is empty -- so editing the
//   payload breaks the signature, not just a side field.
// The optional typed decision fields (G20a) extend the preimage with a
// further '|' and the \x1f-joined field block; empty when none were set.

const PIPE = '|', US = '\x1f';

export function jevCanonicalBytes(receipt) {
  const payloadHash = receipt.payload
    ? fnv1a64Bytes(Buffer.from(String(receipt.payload), 'utf8'))
    : receipt.payload_hash;
  let raw = `${receipt.tick}${PIPE}${receipt.state_hash}${PIPE}${receipt.delta_hash}`
          + `${PIPE}${receipt.decision_kind}${PIPE}${payloadHash}`;
  const typed = jevDecisionBytes(receipt);
  if (typed) raw += PIPE + typed;
  return Buffer.from(raw, 'utf8');
}

export function jevDecisionBytes(receipt) {
  const fields = [receipt.dispatch_id, receipt.runner, receipt.key, receipt.correct,
                  receipt.base_verdict, receipt.answer];
  if (fields.every((f) => f === undefined || f === null)) return '';
  const enc = (v) => {
    if (v === undefined || v === null) return '';
    if (typeof v === 'boolean') return v ? '1' : '0';
    return String(v);
  };
  return fields.map(enc).join(US);
}

// fnv1a-64 over the chain tip's HEX TEXT -- what makes the envelope
// substrate-neutral: any sibling that can name its tip can be sealed.
export function jevChainHead(chainTip) {
  return fnv1a64Bytes(Buffer.from(String(chainTip), 'utf8'));
}

export function jevMessageBytes(receipt, chainHead) {
  return Buffer.concat([jevCanonicalBytes(receipt), Buffer.from(chainHead, 'ascii')]);
}

// verifySignedReceiptEnvelope(signed, pubkeyHex) -> verdict.
// Refusal polarity is the owner's: never throw, always return reasons.
export function verifySignedReceiptEnvelope(signed, pubkeys) {
  const reasons = [];
  const r = signed && signed.receipt;
  if (!r || typeof signed.signature !== 'string' || !HEX128.test(signed.signature)) {
    return { ok: false, reasons: ['malformed:envelope'], signer: signed?.signer ?? null };
  }
  if (!HEX16.test(signed.chain_head || '')) {
    return { ok: false, reasons: ['malformed:chain_head'], signer: signed.signer ?? null };
  }
  const pkHex = pubkeys ? pubkeys[signed.signer] : null;
  if (!pkHex) return { ok: false, reasons: ['unknown_signer'], signer: signed.signer };
  const pub = ed25519PublicKeyFromRaw(Buffer.from(String(pkHex), 'hex'));
  if (!pub) return { ok: false, reasons: ['malformed:public_key'], signer: signed.signer };
  // The envelope's own chain_head must name the chain tip it claims to seal,
  // when the caller supplies one. This is the check that stops a signature
  // being lifted onto a different fork.
  const expectHead = signed.chain_tip === undefined ? null : jevChainHead(signed.chain_tip);
  if (expectHead !== null && expectHead !== signed.chain_head) {
    return { ok: false, reasons: ['wrong_chain_head'], signer: signed.signer };
  }
  if (!edVerify(jevMessageBytes(r, signed.chain_head), Buffer.from(signed.signature, 'hex'), pub)) {
    reasons.push('bad_signature');
  }
  return { ok: reasons.length === 0, reasons, signer: signed.signer };
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
