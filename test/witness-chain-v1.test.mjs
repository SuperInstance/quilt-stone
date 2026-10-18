// THE DIALECT THAT LETS THE FLEET'S CANONICAL VERIFIER READ THE FLEET'S
// REFERENCE WITNESS.
//
// Until this dialect existed, SuperInstance/quilt-stone could not verify a
// witness-chain/1 log, because witness-chain/1 records carry `hash` and NO
// `prev` -- and the verifier's rawpipe dialect requires prev AND hash
// together. The verifier was reporting ABSENCE where the reference
// implementation stood.
//
// Every expected hash, head and CANONICAL BYTE STRING in the vectors file was
// produced by the PYTHON reference implementation
// (SuperInstance/AI-Writings -> labs/situation-recorder/recorder.py). This
// test makes the JavaScript reproduce them EXACTLY. Not "equivalently" --
// byte for byte, including the canonical form of the body, which is the part
// that actually differs between implementations.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { verifyChain, detectAlg, ALGS, canonicalJSON, sealChain } from '../stone.mjs';

const V = JSON.parse(readFileSync(new URL('../conformance-witness-chain-v1.json', import.meta.url), 'utf8'));

// ---------------------------------------------------------------------------
// THE VECTOR FILE IS A RECEIPT. Assert its COUNT and its DIGEST, so a
// truncation or a quiet edit breaks the build instead of hiding in it.
// (A conformance suite that lists only the cases it passes is decoration.)
// ---------------------------------------------------------------------------
test('the vector file is intact -- its count and its digest are asserted', () => {
  assert.equal(V.case_count, 7, 'the number of vector cases changed');
  assert.equal(V.cases.length, 7, 'the number of vector cases on disk differs from the recorded count');

  // A LANGUAGE-INDEPENDENT digest: over the semantic content (heads and
  // canonical bodies), not over this file's bytes -- because the two
  // languages format a float differently on the way to disk, and a digest
  // that depends on that would be a digest of the transport, not of the
  // content. It is computed the same way in Python and in JavaScript.
  const h = createHash('sha256');
  for (const c of V.cases) {
    h.update(c.head); h.update('\n');
    for (const cb of c.canonical_bodies) { h.update(cb, 'utf8'); h.update('\n'); }
  }
  assert.equal(h.digest('hex'), V.vectors_digest,
    'the vectors have been edited since the digest was taken -- a truncation or a quiet change');

  // AND the file's own bytes, so that even a whitespace edit is caught.
  // The digest lives in its OWN file, so there is no self-reference to
  // converge on and no way to make the file agree with itself.
  const raw = readFileSync(new URL('../conformance-witness-chain-v1.json', import.meta.url));
  const recorded = readFileSync(new URL('../conformance-witness-chain-v1.sha256', import.meta.url), 'utf8').trim().split(/\s+/)[0];
  assert.equal(createHash('sha256').update(raw).digest('hex'), recorded,
    'the vector FILE has been edited on disk -- including its whitespace');
});

// ---------------------------------------------------------------------------
// THE DIALECT EXISTS, and it is the one the spec describes.
// ---------------------------------------------------------------------------
test('the dialect exists, and it is the one the spec describes', () => {
  const a = ALGS['witness-chain-v1'];
  assert.ok(a, 'the witness-chain-v1 dialect is missing from the registry');
  assert.equal(a.hashField, 'hash');
  assert.equal(a.prevField, null, 'witness-chain/1 linkage lives in RECORD ORDER; there is no prev field');
  assert.equal(a.genesis, '0x0000000000000000');
  assert.ok(a.hashForm.test('0x' + 'a'.repeat(64)));
  assert.ok(!a.hashForm.test('0x' + 'a'.repeat(16)), 'a 16-hex hash is not a witness-chain hash');
});

// ---------------------------------------------------------------------------
// THE POSITIVE CASE: every vector verifies, and reproduces the head.
// ---------------------------------------------------------------------------
for (const c of V.cases) {
  test(`verifies -- ${c.name}`, () => {
    const v = verifyChain(c.records);
    assert.equal(v.ok, true, `chain did not verify: ${v.why}`);
    assert.equal(v.alg, 'witness-chain-v1');
    assert.equal(v.genesis, '0x0000000000000000');
    assert.equal(v.links, c.records.length);
    assert.equal(v.tip, c.head, 'the head does not match the reference implementation');
  });

  test(`detects the dialect -- ${c.name}`, () => {
    assert.equal(detectAlg(c.records), 'witness-chain-v1');
  });

  test(`reproduces the CANONICAL BYTES -- ${c.name}`, () => {
    // The part that actually differs between implementations. A hash can
    // agree by luck once; the canonical form of the body cannot.
    for (let i = 0; i < c.records.length; i++) {
      const body = { ...c.records[i] };
      delete body.hash;
      assert.equal(canonicalJSON(body), c.canonical_bodies[i],
        `the canonical form of record ${i} differs from the reference implementation`);
    }
  });
}

// ---------------------------------------------------------------------------
// THE NEGATIVE CONTROLS. A test that cannot fail is a comment.
// ---------------------------------------------------------------------------
test('NEGATIVE: an edited body does not verify', () => {
  const rows = structuredClone(V.cases[0].records);
  rows[1].body.result = 'tampered';
  const v = verifyChain(rows);
  assert.equal(v.ok, false, 'an edited body verified -- the guard is broken');
  assert.equal(v.firstBadIndex, 1);
});

test('NEGATIVE: a dropped record does not verify', () => {
  const rows = structuredClone(V.cases[0].records);
  rows.splice(1, 1);
  const v = verifyChain(rows);
  assert.equal(v.ok, false, 'a dropped record verified -- the guard is broken');
});

test('NEGATIVE: a reordered chain does not verify', () => {
  const rows = structuredClone(V.cases[0].records);
  [rows[0], rows[1]] = [rows[1], rows[0]];
  const v = verifyChain(rows);
  assert.equal(v.ok, false, 'a reordered chain verified -- the guard is broken');
});

test('NEGATIVE: a chain with a prev field is NOT detected as witness-chain-v1', () => {
  // The rawpipe dialect is prev+hash TOGETHER. A witness-chain/1 record has
  // no prev, so the two must not be confused -- and a record that HAS a prev
  // is not a witness-chain/1 record.
  const rows = structuredClone(V.cases[0].records);
  rows[0].prev = '0x0000000000000000';
  assert.notEqual(detectAlg(rows), 'witness-chain-v1');
});

test('NEGATIVE: a re-chained chain DOES verify -- and that is the honest limit', () => {
  // THE TRUTH, ASSERTED RATHER THAN HIDDEN. A chain is self-consistent, and
  // self-consistency is not tamper-evidence: an attacker who re-chains the
  // whole log produces a perfectly valid chain. Only the SIGNED TREE HEAD,
  // published where the log writer does not control it, catches that.
  // This test exists so nobody later claims the chain alone is tamper-proof.
  const rows = structuredClone(V.cases[0].records);
  rows[1].body.result = 'tampered';
  const resealed = sealChain(rows, undefined, { alg: 'witness-chain-v1' });
  const v = verifyChain(resealed);
  assert.equal(v.ok, true, 'a re-chained chain did not verify -- the dialect is stricter than the spec');
  assert.notEqual(v.tip, V.cases[0].head, 'the re-chained head is the SAME -- the test is not exercising anything');
});

test('the dialect seals a chain the reference implementation then agrees with', () => {
  const bodies = [
    { v: 'witness-chain/1', seq: 0, body: { a: 1 } },
    { v: 'witness-chain/1', seq: 1, body: { b: 2 } },
  ];
  const sealed = sealChain(structuredClone(bodies), undefined, { alg: 'witness-chain-v1' });
  assert.equal(verifyChain(sealed).ok, true);
  assert.equal(sealed[0].hash, ALGS['witness-chain-v1'].hashOf(bodies[0], '0x0000000000000000'));
  assert.equal(sealed.length, 2);
});
