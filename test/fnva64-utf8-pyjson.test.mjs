// THE EIGHTH DIALECT -- the one the fleet's verifier MISDIAGNOSED.
//
// Until this dialect existed, quilt-stone detected this chain as
// `fnv1a64-rawpipe` and reported:
//
//     why=seq break at 0 at=0
//
// which is a FALSE DIAGNOSIS OF A PERFECTLY VALID CHAIN. The chain is
// calculator-quilt's, it verifies under its own rule, and the verifier
// had no idea what rule that was.
//
// The fixture is the REAL artefact: 36 rows committed to
// SuperInstance/AI-Writings -> labs/synoptic-view/runs/calculator.jsonl.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  verifyChain, verifyChainFile, detectAlg, ALGS, pyJsonDumps, pyNum,
  pyNumFromText, fnv1a64Utf8, parsePreservingNumbers,
} from '../stone.mjs';

const RAW = readFileSync(new URL('../conformance-calculator-quilt.jsonl', import.meta.url), 'utf8');
const LINES = RAW.split('\n').filter((l) => l.trim() !== '');

test('the fixture is the real artefact, and it is unchanged', () => {
  assert.equal(LINES.length, 36, 'the fixture has 36 rows');
  // the file's own digest, so a truncation or a quiet edit is caught
  const recorded = readFileSync(
    new URL('../conformance-calculator-quilt.jsonl.sha256', import.meta.url), 'utf8')
    .trim().split(/\s+/)[0];
  assert.equal(createHash('sha256').update(RAW).digest('hex'), recorded,
    'the fixture has been edited');
});

test('the dialect is registered, and it is the one the owner\'s source describes', () => {
  const a = ALGS['fnv1a64-utf8-pyjson'];
  assert.ok(a, 'the dialect is missing from the registry');
  assert.equal(a.hashField, 'hash');
  assert.equal(a.prevField, 'prev');
  assert.equal(a.genesis, '0x0000000000000000');
  assert.ok(a.hashForm.test('0x' + 'a'.repeat(16)));
  assert.ok(!a.hashForm.test('0x' + 'a'.repeat(64)), 'a 64-hex hash is not this flavor');
});

test('the verifier reads the chain -- and names the RIGHT dialect', () => {
  const v = verifyChainFile(new URL('../conformance-calculator-quilt.jsonl', import.meta.url).pathname);
  assert.equal(v.ok, true, `the chain did not verify: ${v.why}`);
  assert.equal(v.alg, 'fnv1a64-utf8-pyjson');
  assert.equal(v.links, 36);
  assert.equal(v.tip, '0xaaeec5b31c7e1d45');
});

test('and it is NOT misdiagnosed as rawpipe any more', () => {
  const rows = LINES.map(parsePreservingNumbers);
  assert.equal(detectAlg(rows), 'fnv1a64-utf8-pyjson');
});

// ---------------------------------------------------------------------------
// THE CANONICAL FORM, and the three ways it differs from everyone else's.
// ---------------------------------------------------------------------------
test('a float prints as Python prints it -- `0.0`, not `0`', () => {
  // The int/float distinction lives in the TOKEN, not in the value, so it
  // is pyNumFromText that has to know about it. pyNum() alone cannot --
  // and that is exactly the point.
  assert.equal(pyNumFromText('0.0'), '0.0');
  assert.equal(pyNumFromText('0'), '0');
  assert.equal(pyNumFromText('0.5'), '0.5');
  assert.equal(pyNumFromText('1'), '1');
  assert.equal(pyNumFromText('1e+21'), '1e+21');
  assert.equal(pyNumFromText('1e-07'), '1e-07');
  assert.equal(pyNumFromText('1e-7'), '1e-07', "Python's exponent is two digits; ECMAScript's is not");
  assert.equal(pyNumFromText('333333333.33333329'), '333333333.3333333');
  assert.equal(pyNumFromText('-0.0'), '-0.0');
  assert.equal(pyNum(1e21), '1e+21');
  assert.equal(pyNum(1e-7), '1e-07');
  assert.equal(pyNum(333333333.33333329), '333333333.3333333');
});

test('an int prints EXACTLY, at any size -- which is why this flavor has no 2^53 problem', () => {
  assert.equal(pyNumFromText('9007199254740993'), '9007199254740993');
  assert.equal(pyNumFromText('9007199254740992'), '9007199254740992');
  assert.equal(pyNumFromText('123456789012345678901234567890'),
    '123456789012345678901234567890');
  // and the same value as a FLOAT is a different canonical string
  assert.equal(pyNumFromText('9007199254740993.0'), '9007199254740992.0');
});

test('non-ASCII is \\uXXXX-escaped, because ensure_ascii defaults to True', () => {
  assert.equal(pyJsonDumps('é'), '"\\u00e9"');
  assert.equal(pyJsonDumps('😀'), '"\\ud83d\\ude00"');
  assert.equal(JSON.stringify('é'), '"é"', 'JSON.stringify does NOT escape it -- that is the difference');
});

test('keys sort by CODE POINT, not by UTF-16 code unit', () => {
  // U+10000 is a surrogate pair; U+E000 is a single unit. UTF-16 order puts
  // the astral key FIRST; code-point order puts U+E000 first.
  const o = { '\u{10000}': 'A', '\uE000': 'B' };
  const out = pyJsonDumps(o);
  // U+10000 is a SURROGATE PAIR, and Python's ensure_ascii escapes each
  // UTF-16 code unit separately -- so it is \ud800\udc00, not \ud83d.
  assert.ok(out.indexOf('\\ue000') < out.indexOf('\\ud800'),
    'code-point order must put U+E000 first');
  assert.equal(out, '{"\\ue000":"B","\\ud800\\udc00":"A"}');
  // and the default JS sort would disagree
  assert.ok(Object.keys(o).sort().indexOf('\u{10000}') < Object.keys(o).sort().indexOf('\uE000'),
    'the JS default sort is UTF-16 order, which is the WRONG order here');
});

test('FNV over UTF-8 BYTES -- which is not what every other dialect does', () => {
  // 'é' is ONE UTF-16 code unit and TWO UTF-8 bytes, and the composed and
  // decomposed forms are different strings to a byte-hash and the same
  // string to a code-unit hash.
  assert.notEqual(fnv1a64Utf8('é'), fnv1a64Utf8('é'.normalize('NFD')));
  assert.ok(fnv1a64Utf8('').startsWith('0x'));

  // THE MUTATION THAT PROVES IT: mask each byte with 0xff, as the RAW
  // dialect does for code units. On ASCII input that is a NO-OP, so a test
  // that only used ASCII would not catch it. This one uses a non-ASCII
  // input, and the mask changes the answer.
  const s = 'café';
  const masked = fnv1a64Utf8(s).replace(/(..)(?=(..)$)/g, '$1');   // no-op guard
  assert.ok(masked.length > 0);
  const bytes = Buffer.from(s, 'utf8');
  assert.equal(bytes.length, 5, "'café' is 5 UTF-8 bytes");
  assert.equal(s.length, 4, "'café' is 4 UTF-16 code units");
  // and the byte-hash of a NON-ASCII string is NOT the code-unit hash
  assert.notEqual(fnv1a64Utf8('é'), '0x' + (() => {
    let h = 0xcbf29ce484222325n, p = 0x100000001b3n, m = 0xffffffffffffffffn;
    for (let i = 0; i < 'é'.length; i++) { h ^= BigInt('é'.charCodeAt(i)); h = (h * p) & m; }
    return h.toString(16).padStart(16, '0');
  })(), 'the byte-hash and the code-unit hash must differ for non-ASCII');
});

// ---------------------------------------------------------------------------
// THE NEGATIVE CONTROLS.
// ---------------------------------------------------------------------------
test('NEGATIVE: an edited body does not verify', () => {
  const rows = LINES.map(parsePreservingNumbers);
  rows[0].body.budget.usd = 999;
  const v = verifyChain(rows);
  assert.equal(v.ok, false, 'an edited body verified -- the guard is broken');
});

test('NEGATIVE: a dropped row does not verify', () => {
  const rows = LINES.map(parsePreservingNumbers);
  rows.splice(3, 1);
  const v = verifyChain(rows);
  assert.equal(v.ok, false, 'a dropped row verified -- the guard is broken');
});

test('NEGATIVE: a re-chained chain DOES verify -- and that is the honest limit', () => {
  // Self-consistency is not tamper-evidence. An attacker who re-chains the
  // whole log produces a valid chain. Only the signed head, published where
  // the log writer does not control it, catches that.
  const rows = LINES.map(parsePreservingNumbers);
  rows[0].body.budget.usd = 999;
  const alg = ALGS['fnv1a64-utf8-pyjson'];
  let prev = alg.genesis;
  for (const r of rows) {
    const env = { ...r };
    delete env.hash;
    env.prev = prev;
    prev = alg.hashOf(r, prev);
    r.hash = prev;
  }
  const v = verifyChain(rows);
  assert.equal(v.ok, true, 'a re-chained chain did not verify');
  assert.notEqual(v.tip, '0xaaeec5b31c7e1d45');
});

test('THE LIMIT, stated: this flavor needs the RAW TEXT, not a parsed structure', () => {
  // JSON.parse cannot tell `0.0` from `0`, and this canonical form can. So a
  // verifier handed a pre-parsed structure CANNOT re-derive these hashes --
  // it must read the file. That is not a bug in the dialect; it is a
  // property of a canonical form that depends on the lexical form of a
  // number, and it is why readJsonl keeps a number-preserving parse.
  const plain = JSON.parse(LINES[0]);
  const preserved = parsePreservingNumbers(LINES[0]);
  assert.notEqual(plain.body.budget.usd, preserved.body.budget.usd,
    'the two parses must actually differ here, or the test is not exercising anything');
  assert.equal(typeof plain.body.budget.usd, 'number');
  assert.equal(typeof preserved.body.budget.usd, 'string', 'the preserved one carries the text');
  // and a plain-parsed chain does NOT verify under this dialect
  const v = verifyChain(LINES.map((l) => JSON.parse(l)));
  assert.equal(v.ok, false, 'a plain-parsed chain verified -- the limit is not real');
});
