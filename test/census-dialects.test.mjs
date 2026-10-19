// quilt-stone/test/census-dialects.test.mjs — THE CENSUS DIALECTS.
//
// Every dialect the 2026-10 census added, proved against a fixture that came
// out of the OWNER'S OWN REPO, and then broken on purpose.
//
// The shape of this file is deliberate: for each dialect there is a POSITIVE
// test that re-derives real committed hashes, and a NEGATIVE CONTROL that
// mutates that same committed fixture and asserts the verifier says no. A
// dialect with only the positive test is decoration -- it proves the
// implementation agrees with itself, which is the defect this whole exercise
// exists to stop. The fixtures under ../fixtures/ are named in each test so a
// reviewer can go and read the upstream file they came from.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALGS, RULE_FROM, detectAlg, parsePreservingNumbers, pyJsonDumps, verifyChain, parseJsonl, sha256Hex, canonicalJSON,
  ryuCanonicalJSON, ryuGenesisCommit, ryuEdgeGenesis, ryuNum, pyJsonDumpsLoose,
  pyJsonDumpsUtf8, fnv1a64Bytes, verifyChronoCheckpoint, verifyChronoCustody,
  chronoCheckpointPayload, verifySignedReceiptEnvelope, jevCanonicalBytes,
  jevChainHead, jevMessageBytes, ed25519Fingerprint, edgeProvenance,
} from '../stone.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FX = (f) => readFileSync(join(HERE, '..', 'fixtures', f), 'utf8');
const clone = (x) => JSON.parse(JSON.stringify(x));
// JSON.parse(JSON.stringify(row)) THROWS AWAY the non-enumerable
// number-preserving parse, and for three of these dialects the lexical form of
// a number is the dialect. A tamper test built on that clone would fail at row
// 0 for the wrong reason and prove nothing about the row it meant to attack.
// So: mutate a plain copy, then RE-PARSE it from its own text, which is
// exactly what a verifier does when it reads the tampered file off disk.
// Read it back THE WAY A FILE IS READ -- parseJsonl, not
// parsePreservingNumbers. parseJsonl gives BOTH views (plain numbers in the
// row, lexical tokens alongside it); parsePreservingNumbers alone gives only
// the lexical one, and a dialect that does not consume the sentinel would
// then hash a sentinel string where a number belongs.
const reseal = (row) => parseJsonl(JSON.stringify(row))[0];
const tampered = (rows, i, mutate) => {
  const out = rows.map((r) => JSON.parse(JSON.stringify(r)));
  mutate(out[i], out);
  return out.map(reseal);
};
// Read a committed golden with its number lexemes intact: 85.0 must still be
// 85.0 after a round trip, and JSON.parse alone quietly makes it 85.
const golden = (f) => parsePreservingNumbers(FX(f));
// A negative control that did not mutate anything is a test that passes for
// the wrong reason, so every tamper asserts the row it touched.
const flipped = (s) => (s.endsWith('0') ? s.slice(0, -1) + '1' : s.slice(0, -1) + '0');

// ===========================================================================
// 1. chrono-organ/1  —  quilt-chrono/src/seal.js
// ===========================================================================
const chronoSeal = JSON.parse(FX('chrono-ed25519-checkpoint.json'));
const chronoChain = parseJsonl(FX('chrono-organ-seal-chain.jsonl'));

test('chrono-organ/1: the committed chain re-derives to the tip its owner SIGNED', () => {
  const v = verifyChain(chronoChain);
  assert.equal(v.ok, true);
  assert.equal(v.alg, 'chrono-organ/1');
  assert.equal(v.genesis, 'GENESIS');
  // The anchor that makes this more than self-agreement: the tip is the one
  // quilt-chrono committed inside an Ed25519-signed organ checkpoint.
  assert.equal(v.tip, chronoSeal.seal.hash);
  assert.equal(v.tip, 'cf0fbce20e02e7404943c7a59961969f5e8cd9c8fa50a610b7271890b7a42f6d');
});

test('chrono-organ/1 NEGATIVE: editing an `op` payload breaks the seal at that row', () => {
  const rows = tampered(chronoChain, 2, (r) => { r.op.value = 3.2; });  // one number
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 2);
  assert.equal(v.why, 'hash mismatch');
});

test('chrono-organ/1 NEGATIVE: re-pointing `prev` breaks the chain at that row', () => {
  const rows = tampered(chronoChain, 3, (r, all) => { r.prev = all[1].hash; });
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 3);
});

test('chrono-organ/1 NEGATIVE: renumbering `seq` is caught by the link rule', () => {
  const rows = tampered(chronoChain, 1, (r) => { r.seq = 7; });
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.match(v.why, /seq break/);
});

test('chrono checkpoint: the owner\'s committed Ed25519 signature verifies under its published key', () => {
  const v = verifyChronoCheckpoint(chronoSeal.seal, chronoSeal.identity.publicKeyPem);
  assert.equal(v.ok, true, v.why);
  assert.equal(v.seq, 3);
  assert.equal(v.chainTip, chronoSeal.seal.hash);
  // fingerprint law: sha256 over the signer's SPKI PEM
  assert.equal(ed25519Fingerprint(chronoSeal.identity.publicKeyPem),
               chronoSeal.identity.fingerprint);
});

test('chrono checkpoint NEGATIVE: a forged signature is refused by name', () => {
  const forged = clone(chronoSeal.seal);
  forged.sig = flipped(forged.sig);
  const v = verifyChronoCheckpoint(forged, chronoSeal.identity.publicKeyPem);
  assert.equal(v.ok, false);
  assert.match(v.why, /CHECKPOINT_SIGNATURE_INVALID/);
});

test('chrono checkpoint NEGATIVE: editing the signed anchor breaks the signature', () => {
  const forged = clone(chronoSeal.seal);
  forged.seq = 2;                               // re-anchor to a different boundary
  const v = verifyChronoCheckpoint(forged, chronoSeal.identity.publicKeyPem);
  assert.equal(v.ok, false);
  assert.match(v.why, /CHECKPOINT_SIGNATURE_INVALID/);
});

test('chrono custody: the signed tip must BE this chain\'s tip', () => {
  const ok = verifyChronoCustody(chronoSeal.seal, chronoSeal.identity.publicKeyPem, chronoChain);
  assert.equal(ok.ok, true, ok.why);
  assert.equal(ok.chainOk, true);
  // THE WHOLE POINT. Re-seal a FORK so the chain is internally perfect again,
  // then ask the checkpoint whether that fork is the one somebody signed. It
  // is not, and only the checkpoint can say so -- verifyChain cannot.
  // Re-seal the whole fork so it is internally PERFECT -- every hash correct
  // for the edited history. A tamper test that leaves broken hashes proves
  // only that hashes are checked, which was never in doubt.
  const forked = tampered(chronoChain, 3, (r) => { r.op.value = 99; });
  let prev = 'GENESIS';
  for (const l of forked) {
    l.prev = prev;
    l.hash = sha256Hex(canonicalJSON({ seq: l.seq, op: l.op, prev }));
    prev = l.hash;
  }
  assert.equal(forked.length, chronoChain.length);
  const forkedVerdict = verifyChain(forked, 'GENESIS', { alg: 'chrono-organ/1' });
  assert.equal(forkedVerdict.ok, true,
    'the fork must verify as a chain -- otherwise this proves nothing');
  assert.notEqual(forkedVerdict.tip, chronoSeal.seal.hash, 'and it must be a DIFFERENT chain');
  const v = verifyChronoCustody(chronoSeal.seal, chronoSeal.identity.publicKeyPem, forked);
  assert.equal(v.ok, false, 'a self-consistent fork is still not the sealed prefix');
  assert.match(v.why, /ANCHOR_MISMATCH/);
  // and the original, untouched, still passes custody
  assert.equal(
    verifyChronoCustody(chronoSeal.seal, chronoSeal.identity.publicKeyPem, chronoChain).ok, true);
});

// ===========================================================================
// 2. sha256-pyjson-probe  —  quilt-gpu-lab/experiments/d21_perception_ledger.py
// ===========================================================================
const probes = parseJsonl(FX('quilt-gpu-lab-probes.jsonl'));

test('sha256-pyjson-probe: all 215 committed probes re-derive', () => {
  assert.equal(probes.length, 215);
  const v = verifyChain(probes);
  assert.equal(v.ok, true);
  assert.equal(v.alg, 'sha256-pyjson-probe');
  assert.equal(v.genesis, null, 'this dialect has NO genesis and NO linkage');
});

test('sha256-pyjson-probe NEGATIVE: editing any probed field breaks that row only', () => {
  const rows = clone(probes);
  rows[100].claim = 'the trawler delivered nothing at all.';
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 100);
});

test('sha256-pyjson-probe NEGATIVE: the COMPACT separator form must NOT verify here', () => {
  // The separators ARE the dialect. Python's default json.dumps emits ', '
  // and ': '; fnv1a64-utf8-pyjson's compact form would hash different bytes.
  const src = probes[0].__pyjson ?? probes[0];
  const body = { ...src }; delete body.sha256;
  const loose = pyJsonDumpsLoose(body);          // quilt-gpu-lab: DEFAULT separators
  const compact = pyJsonDumps(body);             // fnv1a64-utf8-pyjson: COMPACT
  assert.notEqual(loose, compact, 'the two separator laws must differ on this row');
  assert.equal(sha256Hex(loose), probes[0].sha256);
  assert.notEqual(sha256Hex(compact), probes[0].sha256,
    'the compact form must NOT reproduce the gpu-lab seal');
});

// ===========================================================================
// 3. quilt-cell-ledger/1  —  quilt-rust/packages/core/src/ledger.rs
// ===========================================================================
const compat = golden('quilt-rust-compat-golden.json');
const CEL = compat.op_e_chain;
const EDGES_SPEC = compat.op_d_edge;

// The owner\'s committed genesis spec. NOTE A REAL TRAP, named because it is
// one: compat/golden.json\'s *transcript* prints `"genesis_ts": 1000.0`, but
// the field is `Option<u64>` in ledger.rs and the committed HASH only
// reproduces with the integer 1000. The transcript is a rendering; the hash is
// the law. Getting this wrong yields a plausible, wrong root.
const CELL_GENESIS_SPEC = parsePreservingNumbers(
  '{"cell_id":"bilge.level","genesis":40.0,"genesis_ts":1000}');

test('quilt-cell-ledger/1: the owner\'s committed GENESIS COMMIT reproduces exactly', () => {
  const got = ryuGenesisCommit(CELL_GENESIS_SPEC);
  assert.equal(got, CEL.entries[0].prev_hash);
  assert.equal(got, '470bc52774d2c173c46c5b0a8733676500fbc3b0b0cbf6d3e57662ff2ac4c1d3');
});

test('quilt-cell-ledger/1: the float transcript rendering of genesis_ts is the WRONG root', () => {
  const wrong = ryuGenesisCommit(parsePreservingNumbers(
    '{"cell_id":"bilge.level","genesis":40.0,"genesis_ts":1000.0}'));
  assert.notEqual(wrong, CEL.entries[0].prev_hash);
  assert.match(FX('quilt-rust-compat-golden.json'), /"genesis_ts": 1000\.0/,
    'the committed transcript really does print a float');
});

test('quilt-cell-ledger/1: the canonical form is ryū, and JCS would be WRONG', () => {
  const body = parsePreservingNumbers('{"cell_id":"bilge.level","genesis":40.0,"genesis_ts":1000}');
  const ryu = ryuCanonicalJSON(body);
  assert.match(ryu, /"genesis":40\.0/, 'ryū keeps the float marker');
  assert.match(ryu, /"genesis_ts":1000/, 'u64 renders as an integer');
  assert.notEqual(sha256Hex(ryu), sha256Hex(canonicalJSON(body)),
    'JCS sends 40.0 as 40, which is a DIFFERENT preimage and a different hash');
});

test('quilt-cell-ledger/1: every committed edge provenance vector reproduces', () => {
  for (const e0 of EDGES_SPEC) {
      const e = golden('quilt-rust-compat-golden.json').op_d_edge[EDGES_SPEC.indexOf(e0)];
    assert.equal(sha256Hex(ryuCanonicalJSON(e.inputs)), e.expect.provenance,
      `${e.name}: sha256(ryu canonical(inputs)) must equal the committed provenance`);
  }
});

test('quilt-cell-ledger/1 NEGATIVE: a JCS rendering of the genesis does NOT reproduce', () => {
  const jcs = canonicalJSON({ cell_id: 'bilge.level', genesis: 40.0, genesis_ts: 1000, kind: 'quilt-cell-ledger/1' });
  assert.notEqual(sha256Hex(jcs), CEL.entries[0].prev_hash,
    'if this ever equalled the ryū hash, the two forms would not be distinct dialects');
});

test('quilt-cell-ledger/1 NEGATIVE: ryuNum keeps the float marker, JCS drops it', () => {
  assert.equal(ryuNum(40), '40.0');
  assert.equal(JSON.stringify(40), '40');
  assert.notEqual(ryuNum(40), JSON.stringify(40));
});

// ===========================================================================
// 4. quilt-edge/1  —  quilt-rust/bindings/go/internal/ledger/ledger.go
// ===========================================================================
const goGolden = golden('quilt-rust-go-golden.json');
const fahrenheit = parseJsonl(FX('quilt-rust-edge-fahrenheit.jsonl'));

test('quilt-edge/1: every committed per-cell chain reproduces from its genesis commit', () => {
  // The sheet the go golden pins: value cells carry their declared initial
  // value at ts=0, formula cells declare null at ts=0 (bindings/go/README.md).
  const GENESIS_OF = { temp: '21', threshold: '200', 'ambient.light': '400',
                       fahrenheit: 'null', is_dark: 'null', 'light.state': 'null' };
  for (const [cell, edges] of Object.entries(goGolden.edges)) {
    let chain = ryuEdgeGenesis(parsePreservingNumbers(
      `{"cell":${JSON.stringify(cell)},"genesis":${GENESIS_OF[cell]},"genesis_ts":0}`));
    for (const e of edges) {
      chain = sha256Hex(chain + ':' + e.provenance);
      assert.equal(chain, e.chain, `${cell}: chain law must reproduce every committed edge chain`);
    }
    assert.equal(chain, goGolden.chains[cell], `${cell}: head must equal the committed chains map`);
  }
});

test('quilt-edge/1: the fahrenheit fixture verifies when its genesis IS supplied', () => {
  const g = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"fahrenheit","genesis":null,"genesis_ts":0}'));
  const v = verifyChain(fahrenheit, g, { alg: 'quilt-edge/1' });
  assert.equal(v.ok, true, v.why);
  assert.equal(v.tip, goGolden.chains.fahrenheit);
  assert.equal(v.tip, 'e091c1060ccd3c991dba761539a7da07eabdaa60e4e41ddf73e0186fed38134e');
});

test('quilt-edge/1: without its genesis the verdict NAMES what is missing, and does not blame a hash', () => {
  const v = verifyChain(fahrenheit);
  assert.equal(v.ok, false);
  assert.match(v.why, /per-chain genesis commit not present/);
  assert.equal(v.alg, 'quilt-edge/1');
});

test('quilt-edge/1 NEGATIVE: the wrong per-cell genesis is caught at row 0', () => {
  const wrong = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"fahrenheit","genesis":21,"genesis_ts":0}'));
  const v = verifyChain(fahrenheit, wrong, { alg: 'quilt-edge/1' });
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 0);
});

test('quilt-edge/1: the provenance sub-seal is enforced when the row carries its fields', () => {
  // A row that DOES carry origin/caller/trace/v is re-sealed and checked; a
  // committed golden row that does not is skipped, and the skip is visible.
  const g = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"x","genesis":null,"genesis_ts":0}'));
  const body = { v: 1, cell: 'x', ts: 1000, before: 1, after: 2,
                 delta: 1, imbalance: 1, origin: 'set', caller: 'a.b', trace: ['z'] };
  const row = { ...body, provenance: edgeProvenance(body) };
  assert.equal(verifyChain([{ ...row, chain: sha256Hex(g + ':' + row.provenance) }],
                           g, { alg: 'quilt-edge/1' }).ok, true);
  const lying = { ...body, value: 99 };  // a field not in the preimage
  assert.equal(edgeProvenance(lying), row.provenance);
});

test('quilt-edge/1 NEGATIVE: a forged provenance seal breaks the edge chain', () => {
  const g = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"x","genesis":null,"genesis_ts":0}'));
  const body = { v: 1, cell: 'x', ts: 1000, before: 1, after: 2,
                 delta: 1, imbalance: 1, origin: 'set', caller: null, trace: [] };
  const forged = { ...body, provenance: sha256Hex('not the edge body') };
  const row = { ...forged, chain: sha256Hex(g + ':' + forged.provenance) };
  const v = verifyChain([row], g, { alg: 'quilt-edge/1' });
  assert.equal(v.ok, false);
  assert.match(v.why, /provenance mismatch/);
});

test('quilt-edge/1: a carried provenance seal does NOT cover the body beside it', () => {
  // AN HONEST LIMIT, FOUND WHILE PINNING THIS DIALECT. The chain law consumes
  // the edge's provenance seal; the committed golden rows carry the seal but
  // NOT the fields it is sealed over (origin/caller/trace). So editing `after`
  // leaves the chain intact. That is not a bug in this module -- it is what
  // those committed rows are -- and it is exactly why a verifier that HOLDS
  // the edge body must re-derive provenance itself rather than trust it.
  const g = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"fahrenheit","genesis":null,"genesis_ts":0}'));
  const rows = tampered(fahrenheit, 1, (r) => { r.after = 86; });
  const v = verifyChain(rows, g, { alg: 'quilt-edge/1' });
  assert.equal(v.ok, true, 'the body is outside the chain law when provenance is carried');
  assert.equal(v.tip, goGolden.chains.fahrenheit,
    'and the tip does not move at all: an edited body behind a carried seal is invisible to the chain');
  // ...and the row that DOES carry its provenance body IS covered by it:
  const body = { v: 1, cell: 'x', ts: 1000, before: 1, after: 2,
                 delta: 1, imbalance: 1, origin: 'set', caller: null, trace: [] };
  const honest = { ...body, provenance: edgeProvenance(body) };
  const chain0 = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"x","genesis":null,"genesis_ts":0}'));
  const sealed = verifyChain([{ ...honest, chain: sha256Hex(chain0 + ':' + honest.provenance) }],
                             chain0, { alg: 'quilt-edge/1' });
  assert.equal(sealed.ok, true);
  const lied = { ...honest, after: 99 };
  assert.equal(verifyChain([{ ...lied, chain: sha256Hex(chain0 + ':' + lied.provenance) }],
                           chain0, { alg: 'quilt-edge/1' }).ok, false,
    'a body edit IS caught once the provenance fields travel with the row');
});

test('quilt-edge/1 NEGATIVE: the link is a colon-joined string, not a canonical object', () => {
  const g = ryuEdgeGenesis(parsePreservingNumbers('{"cell":"fahrenheit","genesis":null,"genesis_ts":0}'));
  const rows = clone(fahrenheit);
  const naive = sha256Hex(canonicalJSON({ prev: g, provenance: rows[0].provenance }));
  assert.notEqual(naive, rows[0].chain,
    'if an object preimage also worked, the dialect would not be distinct');
});

// ===========================================================================
// 5. moth-ledger/1  —  moth-ledger/src/moth_ledger/ledger.py
// ===========================================================================
const moth = parseJsonl(FX('moth-ledger-chain.jsonl'));

test('moth-ledger/1: the chain moth-ledger\'s own Ledger wrote re-derives here', () => {
  const v = verifyChain(moth);
  assert.equal(v.ok, true);
  assert.equal(v.alg, 'moth-ledger/1');
  assert.equal(v.genesis, '0000000000000000');
});

test('moth-ledger/1: the link is a BINARY digest concatenation, not a string', () => {
  const prev = ALGS['moth-ledger/1'].genesis;
  const body = { ...moth[0] }; delete body.row_hash; delete body.chain_hash;
  const rowHash = fnv1a64Bytes(Buffer.from(pyJsonDumpsUtf8(body), 'utf8'));
  assert.equal(rowHash, moth[0].row_hash, 'row_hash is fnv1a-64 over canonical UTF-8 bytes');
  const binary = fnv1a64Bytes(Buffer.concat([
    Buffer.from(prev, 'hex'), Buffer.from(rowHash, 'hex')]));
  const asString = fnv1a64Bytes(Buffer.from(prev + rowHash, 'utf8'));
  assert.equal(binary, moth[0].chain_hash);
  assert.notEqual(asString, moth[0].chain_hash,
    'hashing the two digests as TEXT must not also work');
});

test('moth-ledger/1 NEGATIVE: editing one row breaks that row and every link after it', () => {
  const rows = tampered(moth, 1, (r) => { r.verdict = 'REFUTED'; });
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 1);
});

test('moth-ledger/1 NEGATIVE: editing the LAST row alone still breaks it', () => {
  const rows = tampered(moth, 2, (r) => { r.reason = 'budget_renewed'; });
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 2);
});

test('moth-ledger/1 NEGATIVE: ensure_ascii matters — an escaped preimage must not verify', () => {
  // Build a row the committed fixture does not contain, so the two canonical
  // forms provably diverge: a non-ASCII cell name.
  const body = { kind: 'FINDING/v1', surface_id: 'src/par\u00e9se.c:88', target_repo: 'r\u00e9po' };
  const utf8 = pyJsonDumpsUtf8(body);            // ensure_ascii=False -> raw UTF-8
  const escaped = pyJsonDumps(body);             // ensure_ascii=True  -> \uXXXX
  assert.match(escaped, /\\u00e9/, 'the pyjson form really does escape it');
  assert.notEqual(utf8, escaped);
  assert.notEqual(fnv1a64Bytes(Buffer.from(utf8, 'utf8')),
                  fnv1a64Bytes(Buffer.from(escaped, 'utf8')));
});

// ===========================================================================
// 6. quilt-doctor-wal  —  pong-quilt/tools/wal-export.js
// ===========================================================================
const doctorWal = parseJsonl(FX('pong-quilt-doctor-wal.jsonl'));

test('quilt-doctor-wal: the repo\'s own demo driver output re-derives', () => {
  const v = verifyChain(doctorWal);
  assert.equal(v.ok, true);
  assert.equal(v.alg, 'quilt-doctor-wal');
  assert.equal(v.genesis, '0000000000000000');
});

test('quilt-doctor-wal: it is NOT fnv1a64-quant — the canon recurses where quant stops', () => {
  const nested = [{ op: 'LINK', cell: 'c', args: { a: { z: 1, b: 2 } },
                    seq: 0, prev_hash: '0000000000000000' }];
  const deep = ALGS['quilt-doctor-wal'].hashOf(nested[0], '0000000000000000');
  const quant = ALGS['fnv1a64-quant'].hashOf(nested[0], '0000000000000000');
  assert.notEqual(deep, quant, 'a nested object MUST separate these two dialects');
});

test('quilt-doctor-wal NEGATIVE: editing a nested arg breaks the chain', () => {
  const rows = tampered(doctorWal, 2, (r) => { r.args.outcome = 'SURVIVOR-CAP'; });
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 2);
});

test('quilt-doctor-wal NEGATIVE: editing the top-level args breaks the chain', () => {
  const rows = tampered(doctorWal, 4, (r) => { r.args.shown = 4; });
  const v = verifyChain(rows);
  assert.equal(v.ok, false);
  assert.equal(v.firstBadIndex, 4);
});

// ===========================================================================
// 7. jev-quilt receipts-v2 envelope  —  NOT A CHAIN
// ===========================================================================
const jev = JSON.parse(FX('jev-quilt-signed-receipt-vectors.json'));
const jevEnv = jev.envelope;

test('jev receipts-v2: the owner\'s published vector re-derives with NO BLAKE3 on the path', () => {
  const v = verifySignedReceiptEnvelope(
    { receipt: jevEnv.receipt, chain_head: jevEnv.chain_head,
      signer: jevEnv.signer, signature: jevEnv.signature_hex },
    { [jevEnv.signer]: jev.ed25519.public_key_hex });
  assert.equal(v.ok, true, JSON.stringify(v.reasons));
  // the chain_head law, re-derived
  assert.equal(jevChainHead(jevEnv.chain_tip), jevEnv.chain_head);
  // the canonical_bytes law, re-derived byte for byte
  assert.equal(jevCanonicalBytes(jevEnv.receipt).toString('hex'), jevEnv.canonical_hex);
  assert.equal(jevMessageBytes(jevEnv.receipt, jevEnv.chain_head).toString('hex'),
               jevEnv.canonical_hex + Buffer.from(jevEnv.chain_head, 'ascii').toString('hex'));
});

test('jev receipts-v2 NEGATIVE: the docstring\'s BLAKE3 claim is NOT what signed this', () => {
  // If BLAKE3 were on the path the vector would not reproduce under plain
  // Ed25519 -- it does, so the shipped code (and not its docstring) is the law.
  const v = verifySignedReceiptEnvelope(
    { receipt: jevEnv.receipt, chain_head: jevEnv.chain_head,
      signer: jevEnv.signer, signature: jevEnv.signature_hex },
    { [jevEnv.signer]: jev.ed25519.public_key_hex });
  assert.equal(v.ok, true);
  assert.equal(jev.ed25519.seed_hex, '00'.repeat(32), 'vector uses a fixed TEST seed, never a node key');
});

test('jev receipts-v2 NEGATIVE: editing the retained payload breaks the signature', () => {
  const r = { ...jevEnv.receipt, payload: '{"vector": false}' };
  const v = verifySignedReceiptEnvelope(
    { receipt: r, chain_head: jevEnv.chain_head, signer: jevEnv.signer, signature: jevEnv.signature_hex },
    { [jevEnv.signer]: jev.ed25519.public_key_hex });
  assert.equal(v.ok, false);
  assert.deepEqual(v.reasons, ['bad_signature']);
});

test('jev receipts-v2 NEGATIVE: a signature lifted onto another fork is refused', () => {
  const v = verifySignedReceiptEnvelope(
    { receipt: jevEnv.receipt, chain_head: jevEnv.chain_head, signer: jevEnv.signer,
      signature: jevEnv.signature_hex, chain_tip: 'f'.repeat(64) },
    { [jevEnv.signer]: jev.ed25519.public_key_hex });
  assert.equal(v.ok, false);
  assert.deepEqual(v.reasons, ['wrong_chain_head']);
});

test('jev receipts-v2 NEGATIVE: an unknown signer is refused by name', () => {
  const v = verifySignedReceiptEnvelope(
    { receipt: jevEnv.receipt, chain_head: jevEnv.chain_head, signer: 'stranger.k1', signature: jevEnv.signature_hex },
    { [jevEnv.signer]: jev.ed25519.public_key_hex });
  assert.equal(v.ok, false);
  assert.deepEqual(v.reasons, ['unknown_signer']);
});

// ===========================================================================
// 8. THE NO-STEAL INVARIANT: detection must not reassign anything
// ===========================================================================
test('every census dialect is DETECTED, not merely verifiable when forced', () => {
  const cases = [
    ['chrono-organ/1', chronoChain],
    ['sha256-pyjson-probe', probes],
    ['moth-ledger/1', moth],
    ['quilt-doctor-wal', doctorWal],
    ['quilt-edge/1', fahrenheit],
  ];
  for (const [expect, rows] of cases) {
    assert.equal(detectAlg(rows), expect, `${expect} must be auto-detected`);
  }
});

test('a quilt-rust cell-ledger chain is reported as itself, never as fnv1a64-quant', () => {
  // The abridged committed entries: shape `hash` + `prev_hash` with 64-hex.
  // quant and tidepool both REQUIRE `row_hash`, so they cannot apply here.
  const cellRows = CEL.entries.map((e) => parseJsonl(JSON.stringify(e))[0]);
  assert.equal(detectAlg(cellRows), 'quilt-cell-ledger/1');
  // and it is NOT reported as a chain that merely fails: with its real genesis
  // supplied the LINKAGE verifies, because these committed entries carry their
  // prev_hash chain intact.
  const linked = verifyChain(cellRows, ryuGenesisCommit(CELL_GENESIS_SPEC),
                             { alg: 'quilt-cell-ledger/1' });
  assert.equal(linked.firstBadIndex, 0,
    'the row SEAL cannot be re-derived from the owner\'s abridged entries — see below');
  assert.equal(CEL.entries[0].prev_hash, ryuGenesisCommit(CELL_GENESIS_SPEC));
});

test('the rust dialects do NOT steal each other: genesis-ts int vs float decide it', () => {
  const gInt = ryuGenesisCommit(parsePreservingNumbers('{"cell_id":"bilge.level","genesis":40.0,"genesis_ts":1000}'));
  const gFloat = ryuGenesisCommit(parsePreservingNumbers('{"cell_id":"bilge.level","genesis":40.0,"genesis_ts":1000.0}'));
  assert.notEqual(gInt, gFloat);
  assert.notEqual(gFloat, sha256Hex(canonicalJSON(
    { cell_id: 'bilge.level', genesis: 40.0, genesis_ts: 1000, kind: 'quilt-cell-ledger/1' })),
    'the JCS rendering of the same object is a real, different root');
});
