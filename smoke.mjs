// quilt-stone/smoke.mjs — stone self-checks: seal/verify/tamper on every
// dialect, canonical-JSON stability, sibling-call compatibility, detection.
// GREEN only if every check passes; exits 1 on any failure. Honest verdicts.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import {
  fnv1a64, fnv1a64RawString, fnv1a64QuantString, sha256Hex, canonicalJSON,
  rowHash, sealChain, verifyChain, detectAlg, stamp, ALGS, annotateTip,
  signTip, verifyTipSignature,
} from './stone.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
let n = 0, bad = 0;
const ok = (cond, name) => {
  n++;
  if (cond) { console.log(`  ok ${n} ${name}`); }
  else { bad++; console.log(`  FAIL ${n} ${name}`); }
};

// ---------- 1. hash primitive vectors ----------
ok(fnv1a64('') === '0xcbf29ce484222325', 'fnv1a64 empty-string FNV offset basis');
ok(fnv1a64('a') === '0xaf63dc4c8601ec8c', 'fnv1a64("a") published FNV-1a 64 vector');
ok(fnv1a64('foobar') === '0x85944171f73967e8', 'fnv1a64("foobar") published FNV-1a 64 vector');
ok(fnv1a64({ a: 1 }) === fnv1a64(JSON.stringify({ a: 1 })), 'fnv1a64 object input = JSON.stringify path');
ok(fnv1a64RawString('\u00e9') !== fnv1a64('a').slice(0) || true, 'raw variant callable'); // placeholder-free guard below
ok(fnv1a64RawString('gen0|{}') === '0x' + (() => { // independent inline re-derivation (masked)
  let h = 0xcbf29ce484222325n;
  const s = 'gen0|{}';
  for (let i = 0; i < s.length; i++) { h ^= BigInt(s.charCodeAt(i) & 0xff); h = (h * 0x100000001b3n) & 0xffffffffffffffffn; }
  return h.toString(16).padStart(16, '0');
})(), 'fnv1a64RawString matches masked re-derivation');
ok(fnv1a64QuantString('a') === 'af63dc4c8601ec8c', 'quant variant: no 0x prefix');
ok(sha256Hex('abc') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256Hex published vector');
ok(fnv1a64('\u03b3') !== fnv1a64RawString('\u03b3'), 'fleet vs raw fnv DIFFER on non-ASCII (full code unit vs &0xff, γ=U+03B9-range probe) — documented dialect split');

// ---------- 2. canonical JSON stability ----------
ok(canonicalJSON({ b: 1, a: { d: 2, c: [3, 1] } }) === '{"a":{"c":[3,1],"d":2},"b":1}', 'canonicalJSON sorts recursively, arrays keep order');
ok(canonicalJSON({ x: undefined, a: 1 }) === '{"a":1}', 'canonicalJSON skips undefined-valued keys');
ok(canonicalJSON({ a: 1, b: 2 }) === canonicalJSON({ b: 2, a: 1 }), 'insertion order does not change canonicalJSON');
ok(canonicalJSON(null) === 'null' && canonicalJSON(undefined) === 'null', 'null/undefined top-level -> null');
ok(canonicalJSON([1, 'two', { z: true, y: null }]) === '[1,"two",{"y":null,"z":true}]', 'canonicalJSON arrays + nested sort');
const a1 = { seq: 1, kind: 't', payload: { m: 1, k: 2 } };
const a2 = { payload: { k: 2, m: 1 }, kind: 't', seq: 1 };
ok(canonicalJSON(a1) === canonicalJSON(a2), 'permutation-invariance (the canonical claim)');

// ---------- 3. fleet dialect: seal -> verify -> tamper ----------
const fleet = [
  { seq: 1, kind: 'charter', law: 'no hash, no truth' },
  { seq: 2, kind: 'rule.R1', text: 'chains before verdicts' },
  { seq: 3, kind: 'summary', verdict: 'PENDING' },
];
sealChain(fleet); // default fleet dialect, genesis 'GENESIS'
ok(fleet[0].row_hash === fnv1a64(['GENESIS', { seq: 1, kind: 'charter', law: 'no hash, no truth' }]),
  'fleet row 0 hash = fnv1a64(JSON.stringify([GENESIS, rest])) — exact sibling semantics');
const fleetV = verifyChain(fleet);
ok(fleetV.ok === true && fleetV.links === 3 && fleetV.alg === 'fnv1a64-fleet' && fleetV.firstBadIndex === null,
  'fleet seal->verify ok, links/alg/firstBadIndex canonical fields');
ok(fleetV.tip === fleet[2].row_hash, 'tip = last row hash');
// sibling-compat: stripping row_hash then rowHash(rest, prev) reproduces link 1
const { row_hash, ...rest1 } = fleet[1];
ok(rowHash(rest1, fleet[0].row_hash) === fleet[1].row_hash, 'rowHash(row, prev) sibling call-compatible');
// TAMPER: mutate row 1 payload
fleet[1].text = 'verdicts before chains'; // the lie
const fleetT = verifyChain(fleet);
ok(fleetT.ok === false && fleetT.firstBadIndex === 1 && fleetT.why === 'hash mismatch',
  'TAMPER-PROOF: payload mutation caught at exact index');
ok(fleetT.tip === fleet[0].row_hash, 'tip after tamper = last GOOD hash');
fleet[1].text = 'chains before verdicts';
ok(verifyChain(fleet).ok === true, 'restored row re-verifies');

// ---------- 4. exoj dialect (sha256-canonical) ----------
const exojRows = [
  { kind: 'run.config', task: 'smoke' },
  { kind: 'poc_rules', p1: 'conservation' },
];
sealChain(exojRows, 'EXOJ-RECEIPTS-GENESIS', { alg: 'sha256-canonical' });
ok(/^[0-9a-f]{64}$/.test(exojRows[0].row_hash) && !exojRows[0].row_hash.startsWith('0x'),
  'exoj dialect: 64-hex row_hash, no 0x prefix');
const exojV = verifyChain(exojRows);
ok(exojV.ok && exojV.alg === 'sha256-canonical' && exojV.genesis === 'EXOJ-RECEIPTS-GENESIS',
  'exoj seal->verify ok with its genesis default');
ok(exojRows[0].row_hash === sha256Hex(canonicalJSON(['EXOJ-RECEIPTS-GENESIS', { kind: 'run.config', task: 'smoke' }])),
  'exoj row hash = sha256(canonicalJSON([genesis, rest])) — exact sibling semantics');
exojRows[1].p1 = 'violated';
ok(verifyChain(exojRows).firstBadIndex === 1, 'exoj dialect tamper caught');

// ---------- 5. raw dialect (fnv1a64-rawpipe) ----------
const rawRows = [
  { seq: 1, kind: 'charter', note: 'v->L->G->v\'' },
  { seq: 2, kind: 'rule', honest: true },
];
sealChain(rawRows, 'gen0', { alg: 'fnv1a64-rawpipe' });
ok(rawRows[0].hash === fnv1a64RawString('gen0|' + '{"kind":"charter","note":"v->L->G->v\'","seq":1}'),
  'raw row hash = fnv1a64raw(prev + "|" + deepSorted(body)) — exact sibling semantics');
ok(rawRows[0].prev === 'gen0' && rawRows[1].prev === rawRows[0].hash, 'raw rows carry explicit prev links');
const rawV = verifyChain(rawRows);
ok(rawV.ok && rawV.alg === 'fnv1a64-rawpipe' && rawV.genesis === 'gen0', 'raw seal->verify ok');
rawRows[1].honest = false;
const rawT = verifyChain(rawRows);
ok(rawT.ok === false && rawT.firstBadIndex === 1, 'raw dialect tamper caught');
const rawNoSeq = [{ kind: 'x' }];
sealChain(rawNoSeq, 'gen0', { alg: 'fnv1a64-rawpipe' });
rawNoSeq[0].seq = 5; // seq/prev tamper — raw verifies linkage explicitly
ok(verifyChain(rawNoSeq).why !== null && !verifyChain(rawNoSeq).ok, 'raw dialect seq/prev linkage enforced');

// ---------- 6. quant dialect (fnv1a64-quant) ----------
const qRows = [{ seq: 1, prev_hash: '0000000000000000', kind: 'accept', score: 0.5 }];
sealChain(qRows, undefined, { alg: 'fnv1a64-quant' });
ok(/^[0-9a-f]{16}$/.test(qRows[0].row_hash) && qRows[0].prev_hash === '0000000000000000',
  'quant dialect: 16-hex no-prefix row_hash, genesis 16 zeros');
ok(qRows[0].row_hash === fnv1a64QuantString(JSON.stringify(
  Object.fromEntries(Object.entries({ seq: 1, kind: 'accept', score: 0.5, prev_hash: '0000000000000000' }).sort())
)), 'quant row hash = fnv1a64quant(topSorted(fields + prev_hash)) — exact sibling semantics');
ok(verifyChain(qRows).ok, 'quant seal->verify ok');
qRows[0].score = 0.9;
ok(verifyChain(qRows).firstBadIndex === 0, 'quant dialect tamper caught');
qRows[0].score = 0.5;
qRows[0].prev_hash = 'deadbeefdeadbeef';
ok(verifyChain(qRows).ok === false, 'quant prev_hash tamper caught');

// ---------- 6b. tidepool dialect (fnv1a64-tidepool, discovered 26-b) ----------
// Seal-time shape reproduced: hash over {rec fields, prev_hash} — seq added
// AFTER hashing (e10 line 93), so a sealed-from-scratch tidepool row carries
// no seq; the on-disk artifact rows have seq appended post-hash.
const tRows = [
  { kind: 'playtest', title: 'dissent', body: 'x'.repeat(10), prev_hash: '0000000000000000' },
];
sealChain(tRows, undefined, { alg: 'fnv1a64-tidepool' });
tRows[0].seq = 0; // post-hash append, exactly what e10 did
ok(/^[0-9a-f]{16}$/.test(tRows[0].row_hash) && tRows[0].prev_hash === '0000000000000000',
  'tidepool dialect: 16-hex row_hash, genesis 16 zeros');
const tDisk = [JSON.parse(JSON.stringify(tRows[0]))];
const tV = verifyChain(tDisk);
ok(tV.ok && tV.alg === 'fnv1a64-tidepool', 'tidepool: on-disk row (seq present post-hash) re-verifies');
ok(verifyChain(tDisk, undefined, { alg: 'fnv1a64-quant' }).ok === false,
  'tidepool chain does NOT verify under quant dialect (seq-in-hash would break) — the two are distinct');
tDisk[0].body = 'tampered';
ok(verifyChain(tDisk).firstBadIndex === 0, 'tidepool dialect tamper caught');

// ---------- 7. stone-v1 (forward format) ----------
const v1 = [
  { kind: 'stone.header', alg: 'stone-v1', opened: 'smoke' },
  { kind: 'entry', say: 'the record grows' },
];
sealChain(v1, undefined, { alg: 'stone-v1' });
const v1V = verifyChain(v1);
ok(v1V.ok && v1V.alg === 'stone-v1' && v1V.genesis === 'STONE-GENESIS-1', 'stone-v1 seal->verify ok, header-first');
ok(detectAlg(v1) === 'stone-v1', 'detectAlg honors stone.header hint');

// ---------- 8. detection ----------
ok(detectAlg([{ seq: 1, row_hash: '0x0123456789abcdef' }]) === 'fnv1a64-fleet', 'detect: 0x+16 -> fleet');
ok(detectAlg([{ row_hash: 'ab'.repeat(32) }]) === 'sha256-canonical', 'detect: 64-hex -> sha256');
ok(detectAlg([{ prev: 'gen0', hash: '0x0123456789abcdef' }]) === 'fnv1a64-rawpipe', 'detect: prev+hash -> rawpipe');
ok(detectAlg([{ prev_hash: '0'.repeat(16), row_hash: '0123456789abcdef' }]) === 'fnv1a64-quant', 'detect: prev_hash -> quant');
ok(detectAlg([]) === null && detectAlg([{ a: 1 }]) === null, 'detect: empty/foreign -> null');
ok(verifyChain([{ a: 1 }]).ok === false, 'undetectable rows do NOT silently pass');

// ---------- 9. cross-dialect isolation ----------
ok(verifyChain(fleet, undefined, { alg: 'sha256-canonical' }).ok === false,
  'fleet chain does NOT verify under sha256 dialect (dialects are not interchangeable)');

// ---------- 10. empty chain + idempotent re-seal ----------
ok(verifyChain([]).ok === true && verifyChain([]).links === 0 && verifyChain([]).tip === null, 'empty chain verifies vacuously');
const re = [{ seq: 1, kind: 'x' }];
sealChain(re); const h1 = re[0].row_hash;
sealChain(re); // idempotent on sealed prefix
ok(re[0].row_hash === h1, 're-seal of sealed prefix is idempotent');

// ---------- 11. disk round-trip: file bytes re-verify ----------
const line = JSON.stringify(fleet[0]);
ok(verifyChain([JSON.parse(line)]).ok === true, 'JSON.stringify -> parse round-trip re-verifies (insertion order preserved)');

// ---------- 12. stamp + ALGS registry ----------
const s = stamp('st');
ok(/^st_[0-9a-z]+_[0-9a-z]+$/.test(s), 'stamp(prefix) format');
ok(Object.keys(ALGS).length === 6 && ALGS['fnv1a64-fleet'].genesis === 'GENESIS', 'ALGS registry: 6 dialects, fleet genesis');

// ---------- 12b. forward-format adopter: pong-quilt R36 (SuperInstance/pong-quilt PR #46) ----------
// The first fleet sibling to WRITE stone-v1 from its own exporter:
// pong-quilt's tools/wal-export.js toStoneV1() seals its receipt-panel WAL
// in the forward format (sha256/canonical + mandatory stone.header row).
// Fixture below is the exporter's REAL output, generated live by requiring
// pong-quilt's tools/wal-export.js at PR #46's merge tip — not retyped.
// Weight-law citation: this in-repo cite names the producing repo + PR.
const PQ_FIXTURE = "[{\"kind\":\"stone.header\",\"alg\":\"stone-v1\",\"genesis\":\"STONE-GENESIS-1\",\"tool\":\"pong-quilt\",\"source\":\"quilt-stone smoke fixture — produced by pong-quilt R36 toStoneV1 (SuperInstance/pong-quilt PR #46)\",\"row_hash\":\"0901bfc431230fe7c3d57847a956f4770c1ff076000b33f3165e5b0fa333757a\"},{\"kind\":\"pq/wal-op\",\"seq\":1,\"op\":\"LINK\",\"cell\":\"pq/receipt\",\"args\":{\"kind\":\"L2\",\"move\":1,\"conf\":0.42,\"gen\":0},\"row_hash\":\"a4f4b006a2b4d8d6ad22446339d419475c2c68d1af7a7e2b462f73dc62cd0a6b\"},{\"kind\":\"pq/wal-op\",\"seq\":2,\"op\":\"LINK\",\"cell\":\"pq/receipt\",\"args\":{\"kind\":\"DEATH\",\"move\":0,\"conf\":0,\"gen\":3},\"row_hash\":\"f40d76a4207e3a5ff43e3091ef637b4043933fee7d8db18766753b3d22cd5027\"},{\"kind\":\"pq/wal-op\",\"seq\":3,\"op\":\"LINK\",\"cell\":\"pq/receipt\",\"args\":{\"kind\":\"QA-REFUSAL\",\"move\":0,\"conf\":0,\"gen\":3},\"row_hash\":\"377c6b54ee476855b6b03e1d45be75fbc86a261aeb141455af5850fa6b96b62f\"},{\"kind\":\"pq/wal-op\",\"seq\":4,\"op\":\"VIEW\",\"cell\":\"pq/projection/eviction\",\"args\":{\"shown\":3,\"evicted\":41},\"row_hash\":\"99b2d0a6c848feb429b39d0696212ebc5906603983c47f9b6b6bed3fec6dd5de\"}]"; // exact exporter bytes
const pqChain = JSON.parse(PQ_FIXTURE);
const pqV = verifyChain(pqChain);
ok(pqV.ok === true && pqV.alg === 'stone-v1' && pqV.genesis === 'STONE-GENESIS-1' && pqV.links === 5,
  'pong-quilt R36 exporter output verifies under stone-v1 (alg/genesis/links canonical)');
ok(pqChain[0].kind === 'stone.header' && pqChain[0].tool === 'pong-quilt',
  'fixture header row is the mandatory stone.header, tool=pong-quilt (producer named, not laundered)');
ok(pqV.tip === pqChain[pqChain.length - 1].row_hash,
  'tip = last exporter row hash');
const pqTampered = JSON.parse(PQ_FIXTURE);
pqTampered[4].args.evicted = 42; // post-seal content edit
const pqT = verifyChain(pqTampered);
ok(pqT.ok === false && pqT.firstBadIndex === 4 && pqT.why === 'hash mismatch',
  'tampered exporter chain caught: hash mismatch at the edited row, never fake green');
const pqSpliced = JSON.parse(PQ_FIXTURE);
pqSpliced[2] = pqSpliced[3]; // duplicate a row: chain continuity must break
ok(verifyChain(pqSpliced).ok === false, 'row-splice breaks the exporter chain (prev-link continuity enforced)');

// ---------- 13. v2 annotation rows (STONE-V2-PILOTS resolution, #2 comment) ----------
// Rule: 'stone.*' kind ≠ 'stone.header' = annotation — self-hashed vs the
// current tip, prev NEVER advances into it. Every byte stays tamper-evident.
{
  const rows = [
    { kind: 'stone.header', alg: 'stone-v1', genesis: 'STONE-GENESIS-1' },
    { kind: 'receipt', claim: 'a' },
    { kind: 'receipt', claim: 'b' },
  ];
  sealChain(rows, undefined, { alg: 'stone-v1' });
  const bodyTip = rows[2].row_hash;
  annotateTip(rows, { kind: 'stone.sign', sig: 'ed25519:deadbeef', tip: bodyTip });
  const v = verifyChain(rows);
  ok(v.ok === true && v.links === 4, 'stapled stone.sign row verifies (downgrade-safe resolution 2)');
  ok(v.tip === bodyTip, 'tip stays the BODY tip — prev never advances into an annotation');

  const tampered = JSON.parse(JSON.stringify(rows));
  tampered[3].sig = 'ed25519:cafeb0ba'; // post-seal edit of the annotation itself
  const vt = verifyChain(tampered);
  ok(vt.ok === false && vt.firstBadIndex === 3 && vt.why === 'annotation hash mismatch',
    'edited annotation caught: annotation hash mismatch at the stapled row');

  const mid = JSON.parse(JSON.stringify(rows.slice(0, 3)));
  annotateTip(mid, { kind: 'stone.sign', sig: 'x' });
  mid.push({ kind: 'receipt', claim: 'c' });
  sealChain(mid, undefined, { alg: 'stone-v1' });
  const vm = verifyChain(mid);
  ok(vm.ok === true && vm.links === 5 && mid[4].row_hash !== undefined,
    'mid-chain annotation: later body rows still link over it (prev skips the staple)');

  const dbl = JSON.parse(JSON.stringify(rows));
  annotateTip(dbl, { kind: 'stone.sign', sig: 'second staple' });
  ok(verifyChain(dbl).ok === true, 'multiple annotations on one tip all verify');

  const noHash = JSON.parse(JSON.stringify(rows));
  delete noHash[3].row_hash;
  const vnh = verifyChain(noHash);
  ok(vnh.ok === false && vnh.firstBadIndex === 3,
    'annotation without self-hash is a chain break (rows are never skipped)');

  let threw = false;
  try { annotateTip([{ kind: 'stone.header', alg: 'stone-v1' }], { kind: 'receipt', claim: 'not an annotation' }); }
  catch { threw = true; }
  ok(threw, 'annotateTip refuses non-stone.* kinds (body rows can never be laundered as annotations)');

  // regression guard: annotation-free stone-v1 chains verify byte-identically
  const plain = [
    { kind: 'stone.header', alg: 'stone-v1', genesis: 'STONE-GENESIS-1' },
    { kind: 'receipt', claim: 'a' },
  ];
  sealChain(plain, undefined, { alg: 'stone-v1' });
  ok(verifyChain(plain).ok === true && detectAlg(plain) === 'stone-v1',
    'annotation-free stone-v1 behavior unchanged (detection + verify)');
}

// ---------- 13b. v2 tip signatures: sign + auditor verify (STONE-V2-PILOTS) ----------
{
  const { generateKeyPairSync } = await import('node:crypto');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const body = [
    { kind: 'stone.header', alg: 'stone-v1', genesis: 'STONE-GENESIS-1' },
    { kind: 'receipt', claim: 'birth-seal class' },
    { kind: 'receipt', claim: 'pong-quilt R37 shape' },
  ];
  sealChain(body, undefined, { alg: 'stone-v1' });
  const bodyTip = body[2].row_hash;
  signTip(body, privateKey, { key_id: 'pq-prerun-smoke', signer_role: 'producer' });

  const v = verifyChain(body);
  ok(v.ok === true && v.links === 4 && v.tip === bodyTip,
    'signed chain still verifies; tip stays the BODY tip under the staple');
  const s = verifyTipSignature(body, publicKey);
  ok(s.ok === true && s.tip === bodyTip &&
     s.signer.alg === 'ed25519' && s.signer.key_id === 'pq-prerun-smoke' && s.signer.signer_role === 'producer',
    'auditor verifies: signature block names alg/key_id/signer_role, tip binds');

  // The R22 P3-process gap, closed: post-signature body edit, re-sealed into
  // a fully self-consistent chain, then the OLD signature re-stapled onto the
  // new tip (the at-rest laundering attack). Chain verify PASSES — the
  // signature is what catches it.
  const edited = body.slice(0, 3).map((r) => { const c = { ...r }; delete c.row_hash; return c; });
  edited[1].claim = 'edited after signing';
  sealChain(edited, undefined, { alg: 'stone-v1' });
  const laundered = [...edited, { ...body[3] }];
  delete laundered[3].row_hash;
  const newTip = edited[2].row_hash;
  laundered[3].row_hash = sha256Hex(canonicalJSON([newTip, (({ row_hash, ...rest }) => rest)(laundered[3])]));
  ok(verifyChain(laundered).ok === true,
    'laundered chain (post-edit re-seal + old signature re-stapled) still verifies — hashes alone cannot catch this');
  const sl = verifyTipSignature(laundered, publicKey);
  ok(sl.ok === false && sl.why === 'signed tip does not match the chain tip (post-signature chain edit)',
    'the signature catches it: signed tip names the pre-edit tip');

  const wrongKey = generateKeyPairSync('ed25519').publicKey;
  const sw = verifyTipSignature(body, wrongKey);
  ok(sw.ok === false && sw.why === 'signature invalid for this tip and key',
    'wrong public key refused');

  const unsigned = [
    { kind: 'stone.header', alg: 'stone-v1', genesis: 'STONE-GENESIS-1' },
    { kind: 'receipt', claim: 'x' },
  ];
  sealChain(unsigned, undefined, { alg: 'stone-v1' });
  const sn = verifyTipSignature(unsigned, publicKey);
  ok(sn.ok === false && sn.why === 'no stone.sign row stapled',
    'unsigned chain names its absence (never faked green)');

  let threwEmpty = false;
  try { signTip([{ kind: 'stone.header', alg: 'stone-v1' }].filter(() => false).concat([]), privateKey); }
  catch { threwEmpty = true; }
  ok(threwEmpty, 'signing an empty (body-less) chain throws');

  // byte-level: the signed message is exactly "stone-v2" || tip_row_hash
  const msg = Buffer.concat([Buffer.from('stone-v2', 'utf8'), Buffer.from(bodyTip, 'utf8')]);
  const { verify: nodeVerify } = await import('node:crypto');
  let rawOk = false;
  try { rawOk = nodeVerify(null, msg, Buffer.from(body[3].sig, 'hex'), publicKey); }
  catch (e) {
    if (e && e.code === 'ERR_INVALID_ARG_TYPE') rawOk = nodeVerify(null, msg, publicKey, Buffer.from(body[3].sig, 'hex'));
    else throw e;
  }
  ok(rawOk, 'signed message is exactly "stone-v2" || tip_row_hash (domain separation pinned)');
}


// ---------- 13c. sign-lane adopter: pong-quilt R39 (SuperInstance/pong-quilt PR #51) ----------
// The first fleet sibling to STAPLE a producer ed25519 signature on its own
// stone chain: pong-quilt's tools/prerun.js signs the birth-seal chain's tip
// (verifyTipSignature BEFORE write; unsigned stone-v1.json stays canonical;
// QUILT_STONE_SIGN_KEY names the producer PEM; SIGN/REFUSED exit 1).
// Fixture below is the producer's REAL output — tools/prerun.js at PR #52's
// merge tip (carries PR #51), QUILT_STONE_DIR naming this checkout, generated
// live, not retyped. The committed PEM is the producer-published verifying
// key carried in the pilot wrapper's key.public block.
const PQ_SIGN_FIXTURE = "[{\"kind\":\"stone.header\",\"alg\":\"stone-v1\",\"genesis\":\"STONE-GENESIS-1\",\"tool\":\"pong-quilt\",\"source\":\"tools/prerun.js canonical checkpoint seal (Round 37)\",\"row_hash\":\"e686dbef4a277915b6a94c4003b1717d8f555e30440c01ca91c037466bb8eb5f\"},{\"kind\":\"pq/wal-op\",\"seq\":1,\"op\":\"LINK\",\"cell\":\"pq/prerun-checkpoint\",\"args\":{\"file\":\"curve.json\",\"md5\":\"63617065d33068159e86e77da9181a61\"},\"row_hash\":\"048df9a91eed63b08d5984ad5541e848c46ee8ee82e202f98ffec1a109df67d8\"},{\"kind\":\"pq/wal-op\",\"seq\":2,\"op\":\"LINK\",\"cell\":\"pq/prerun-checkpoint\",\"args\":{\"file\":\"level0.js\",\"md5\":\"8a49b0f659b572d5ba6943bcabbbe082\"},\"row_hash\":\"f2a91475f63089d03ab68fad16d8de06d93e32948a868eb21e645398672b67f9\"},{\"kind\":\"pq/wal-op\",\"seq\":3,\"op\":\"LINK\",\"cell\":\"pq/prerun-checkpoint\",\"args\":{\"file\":\"level1.js\",\"md5\":\"643bd132d51f3fd2f08c0054b48967ae\"},\"row_hash\":\"332ff37beb9cf75f78a90ed763e2f4d7c2fdbb507cb37cceb49fa9b3d5e3234d\"},{\"kind\":\"pq/wal-op\",\"seq\":4,\"op\":\"LINK\",\"cell\":\"pq/prerun-checkpoint\",\"args\":{\"file\":\"level2.js\",\"md5\":\"454511548f9224f9302c106abd9313d0\"},\"row_hash\":\"ffe8abd842162d717ff274fdd3c21c58622df9ede534f6b540f2ae16b69f5503\"},{\"kind\":\"stone.sign\",\"alg\":\"ed25519\",\"key_id\":\"pq-prerun-sign-pilot\",\"signer_role\":\"producer\",\"tip\":\"ffe8abd842162d717ff274fdd3c21c58622df9ede534f6b540f2ae16b69f5503\",\"sig\":\"4c1e357b7ce73f267c2dd46e7428b129a928633f3d20b9f0ac321dae62ed13e944224b2a613d070a9803544fe7540e9d0eaf9603750e373b364a4b1176592909\",\"row_hash\":\"2b38e0678bfbb0c9fced9c67e6ba60af4a3a14c1c6e5c21c4a623ffba6f82a7d\"}]"; // exact producer bytes
const pqSignChain = JSON.parse(PQ_SIGN_FIXTURE);
const PQ_SIGN_PUB = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAd4utl4Ig8O35dABdbu6ddpDDsvc9XXOWinpQFCApoa4=
-----END PUBLIC KEY-----`;
const BODY_TIP = 'ffe8abd842162d717ff274fdd3c21c58622df9ede534f6b540f2ae16b69f5503';
{
  const v = verifyChain(pqSignChain);
  ok(v.ok === true && v.alg === 'stone-v1' && v.links === 6 && v.tip === BODY_TIP,
    'pong-quilt R39 signed chain verifies under stone-v1 (6 links, tip stays the BODY tip under the staple)');
  ok(pqSignChain[0].kind === 'stone.header' && pqSignChain[0].tool === 'pong-quilt',
    'producer named in its own header (not laundered through a verifier repo)');
  const s = verifyTipSignature(pqSignChain, PQ_SIGN_PUB);
  ok(s.ok === true && s.tip === BODY_TIP && s.signer.key_id === 'pq-prerun-sign-pilot' &&
     s.signer.signer_role === 'producer' && s.signer.alg === 'ed25519',
    'auditor verifies the producer staple: key_id/signer_role named, tip binds the exact chain');

  // the at-rest laundering attack against a REAL producer artifact: edit a
  // checkpoint md5 post-signature, re-seal into a self-consistent chain,
  // re-staple the OLD signature row re-hashed against the new tip
  const edited = pqSignChain.slice(0, 5).map((r) => { const c = { ...r, args: r.args ? { ...r.args } : undefined }; delete c.row_hash; return c; });
  edited[3].args.md5 = '643bd132d51f3fd2f08c005b48967ae0'; // level1.js content edit
  sealChain(edited, undefined, { alg: 'stone-v1' });
  const laundered = [...edited, { ...pqSignChain[5] }];
  delete laundered[5].row_hash;
  const newTip = edited[4].row_hash;
  laundered[5].row_hash = sha256Hex(canonicalJSON([newTip, (({ row_hash, ...rest }) => rest)(laundered[5])]));
  ok(verifyChain(laundered).ok === true,
    'laundered producer chain (post-edit re-seal + old sig re-stapled) still verifies — hashes alone cannot catch this');
  const sl = verifyTipSignature(laundered, PQ_SIGN_PUB);
  ok(sl.ok === false && sl.why === 'signed tip does not match the chain tip (post-signature chain edit)',
    'the producer signature catches it on the real artifact: signed tip names the pre-edit tip');

  const wrongKeyPem = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA3qWb2E9rE7mQlXyGNoB4yDa8dF02kKQ3SvLtkTDMfB8=\n-----END PUBLIC KEY-----';
  const sw = verifyTipSignature(pqSignChain, wrongKeyPem);
  ok(sw.ok === false && sw.why === 'signature invalid for this tip and key',
    'wrong public key refused against the producer staple');
}

// ---------- 14. zero-dependency + ESM static check ----------
const src = readFileSync(join(HERE, 'stone.mjs'), 'utf8');
const imports = [...src.matchAll(/(?:^|\n)\s*import\s+[^'"]*from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]);
ok(imports.length > 0 && imports.every((p) => p.startsWith('node:')),
  `stone.mjs imports only node: builtins (${imports.join(', ')})`);
ok(!imports.some((p) => p.startsWith('.') || p.startsWith('/')), 'no relative imports in stone.mjs (leaf module)');
const pkg = JSON.parse(readFileSync(join(HERE, 'package.json'), 'utf8'));
ok(pkg.type === 'module' && pkg.dependencies === undefined && pkg.devDependencies === undefined,
  'package.json: type=module, zero deps');
ok(/^\s*import\s/m.test(src) && /\bexport\s+(function|const)/.test(src), 'ESM syntax present (static import + export)');

console.log(bad === 0 ? `\nSMOKE GREEN: ${n}/${n} checks pass` : `\nSMOKE RED: ${bad}/${n} checks FAIL`);
process.exit(bad === 0 ? 0 : 1);
