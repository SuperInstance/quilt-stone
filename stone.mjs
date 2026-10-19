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

import { createHash, createPublicKey, sign, verify } from 'node:crypto';
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
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return pyNum(v);
  if (typeof v === 'string') {
    if (v.startsWith(PY_RAW)) return pyNumFromText(v.slice(PY_RAW.length));
    return pyStr(v);
  }
  if (Array.isArray(v)) return '[' + v.map(pyJsonDumps).join(',') + ']';
  return '{' + pySortKeys(Object.keys(v))
    .map((k) => pyStr(k) + ':' + pyJsonDumps(v[k])).join(',') + '}';
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
    if (r.prev !== undefined && r.hash !== undefined) {
      // prev+hash together: rawpipe OR the calculator-quilt flavor. They are
      // discriminated by TRIAL, not by a guess -- and the trial must come
      // first, because the old code returned rawpipe UNVERIFIED and so
      // reported "seq break at 0" for a chain that is perfectly valid under
      // its own rule.
      if (trialOk(rows, 'fnv1a64-utf8-pyjson')) return 'fnv1a64-utf8-pyjson';
      return 'fnv1a64-rawpipe';
    }
  }
  if (hasPrevHash) {
    if (trialOk(rows, 'fnv1a64-quant')) return 'fnv1a64-quant';
    if (trialOk(rows, 'fnv1a64-tidepool')) return 'fnv1a64-tidepool';
    return 'fnv1a64-quant'; // fail under the primary shape, verdict carries why
  }
  // 3b. a `hash` field, and NO prev / prev_hash / row_hash anywhere ->
  //     witness-chain-v1. The SHAPE is a guess; the TRIAL is the proof, and
  //     a chain that fails the trial is still reported under this dialect
  //     so the verdict carries WHY rather than saying "undetectable".
  let hasPlainHash = false, hasOtherLink = false;
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    if (r.hash !== undefined) hasPlainHash = true;
    if (r.prev !== undefined || r.prev_hash !== undefined || r.row_hash !== undefined) {
      hasOtherLink = true; break;
    }
  }
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

// ============================================================================
// 3b. V2 TIP SIGNATURES (STONE-V2-PILOTS first sign lane)
// ============================================================================

// bodyTip(rows, alg): the hash of the last NON-ANNOTATION row, re-derived by
// walking the chain from genesis — never trusting a stored tip or row_hash.
function bodyTip(rows, alg) {
  let prev = alg.genesis;
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
// 4. SEQUENCE-ID HELPER (fleet semantics verbatim)
// ============================================================================

// stamp(prefix?) -> `${prefix}_${Date.now().toString(36)}_${rand36}` —
// an id helper ONLY: stamp outputs are for run/file identity, never hashed
// content (the siblings never put wall-clock or randomness inside a hash).
export function stamp(prefix = 'ln') {
  return `${prefix}_${Date.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}
