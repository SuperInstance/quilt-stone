// quilt-stone/experiments/e_st1_conform.mjs — E-ST1: the receipted
// conformance run of the canonical verifier over the whole fleet record.
//
// HOUSE DISCIPLINE: receipts BEFORE verdicts — the run.config and the four
// decision rules are sealed into a stone-v1 chain (dogfood: written by
// stone.mjs itself) and written to disk BEFORE runConformance() executes.
// Results are appended after, the seal is idempotent, the file is re-read
// from disk and re-verified as the final act (the chain audits itself).
//
// Rules (sealed before the runs they govern):
//   R1 every discoverable sibling chain verifies under its OWN semantics
//      (count them) — PASS iff chainsVerified == chainsFound > 0.
//   R2 the canonical module reproduces each repo's local verify verdict
//      (exported functions or re-implemented) — PASS iff every chain has an
//      available local verdict and zero divergences; the divergence list is
//      receipted either way.
//   R3 stone.mjs self-test: seal -> mutate one row -> verify catches it with
//      the exact firstBadIndex. Tamper-evidence PROVEN, not asserted.
//   R4 zero-dependency + ESM static check on every quilt-stone module.
//
// NO wall-clock, no randomness, no floats inside hashed content.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  sealChain, verifyChain, verifyChainFile, ALGS,
} from '../stone.mjs';
import { runConformance } from '../verify_all.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'outputs');
mkdirSync(OUT, { recursive: true });
const CHAIN = join(OUT, 'receipts_e_st1.jsonl');
const SUMMARY = join(OUT, 'e_st1_summary.json');

const writeChain = (rows) => writeFileSync(CHAIN, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');

// =========================== PHASE A: SEAL THE RULES =========================
const rows = [
  {
    kind: 'stone.header',
    alg: 'stone-v1',
    genesis: ALGS['stone-v1'].genesis,
    experiment: 'E-ST1 canonical conformance over the fleet record',
    repo: 'quilt-stone', lane: 'Task 26-b', agent: 'CODE-WRITING + INFRASTRUCTURE',
  },
  {
    kind: 'run.config',
    task: 'verify EVERY discoverable sibling receipt chain with the canonical verifier; cross-check against each repo\'s own local verifier',
    scope: '/home/z/my-project/download/* (recursive, node_modules/.git excluded, .jsonl content-sniffed for chain link fields)',
    method: 'stone.verifyChain auto-dialect; local cross-check via imported sibling modules (murmur/dba/fiction/arch/silicon/cortex/exoj/quant) or verbatim transcriptions (raw e_r1_line.mjs:32-73; playtest e10_tidepool_artifacts.mjs:80-94)',
    siblings_do_not_modify: true,
  },
  {
    kind: 'rules',
    R1: 'every discoverable sibling chain verifies under its OWN semantics; PASS iff chainsVerified == chainsFound AND chainsFound >= 1; the count and any broken chains are receipted per file',
    R2: 'the canonical module reproduces each repo\'s local verify verdict (imported or re-implemented); PASS iff localCrossChecked == chainsFound AND divergences == 0; the divergence list (repo, file, stoneOk, localOk) is receipted either way',
    R3: 'stone self-test: seal a 3-row scratch chain under stone-v1, mutate one sealed row\'s payload, verifyChain must return ok:false with firstBadIndex == the mutated index; PASS iff caught (tamper-evidence PROVEN)',
    R4: 'zero-dependency + ESM static check: stone.mjs, verify_all.mjs, smoke.mjs, e_st1_conform.mjs import ONLY node: builtins or repo-relative paths; package.json has no dependencies/devDependencies and type=module; PASS iff all files clean',
  },
];
sealChain(rows, undefined, { alg: 'stone-v1' });
writeChain(rows); // RULES ON DISK BEFORE ANY RUN

// =========================== PHASE B: RUN + RECEIPT =========================
const { results, tally } = await runConformance();

for (const r of results) {
  rows.push({
    kind: 'chain.result',
    repo: r.repo, file: r.file, rows: r.rows, alg: r.alg,
    ok: r.ok, firstBadIndex: r.firstBadIndex, why: r.why,
    tip: r.tip, genesis: r.genesis,
    localAvailable: r.localAvailable, self: r.self, localOk: r.localOk, agree: r.agree,
  });
}

// The sealed R1/R2 scope is SIBLING chains ("every discoverable sibling");
// quilt-stone's own chain is receipted above (self:true) and audited
// separately by the final chain.seal disk recheck — its only local verifier
// is stone.mjs itself, so an independent cross-check is impossible by
// construction.
const siblingResults = results.filter((r) => r.repo !== 'quilt-stone');
const selfResults = results.filter((r) => r.repo === 'quilt-stone');

// R3 — tamper-evidence PROVEN on a scratch chain (never on this file itself).
// Spec-correct shape: row 0 is the stone.header (that header is exactly what
// makes auto-detection choose stone-v1 over the format-identical exoj dialect).
const scratch = [
  { kind: 'stone.header', alg: 'stone-v1', note: 'R3 scratch chain' },
  { kind: 'r3.scratch', i: 0, note: 'sealed honest' },
  { kind: 'r3.scratch', i: 1, verdict: 'PENDING' },
  { kind: 'r3.scratch', i: 2, note: 'tail' },
];
sealChain(scratch, undefined, { alg: 'stone-v1' });
const scratchDetected = verifyChain(scratch).alg; // must auto-detect stone-v1
const beforeTip = scratch[3].row_hash;
scratch[2].verdict = 'FORGED'; // the lie
const caught = verifyChain(scratch);
const r3Caught = caught.ok === false && caught.firstBadIndex === 2 && caught.why === 'hash mismatch';
scratch[2].verdict = 'PENDING'; // restore for the receipt below
const restored = verifyChain(scratch);
rows.push({
  kind: 'r3.evidence',
  alg: 'stone-v1', detectedAlg: scratchDetected, links: 4, beforeTip,
  mutated: 'scratch[2].verdict -> "FORGED"',
  observed: { ok: caught.ok, firstBadIndex: caught.firstBadIndex, why: caught.why },
  caught: r3Caught,
  restoredVerifies: restored.ok === true,
});

// R4 — static check over every quilt-stone module (line-scoped scanning:
// a 'from' specifier or a bare side-effect import string per LINE)
const FILES = ['stone.mjs', 'verify_all.mjs', 'smoke.mjs', 'experiments/e_st1_conform.mjs'];
const r4 = { files: {}, allClean: true };
for (const f of FILES) {
  const src = readFileSync(join(HERE, '..', f), 'utf8');
  const imports = [];
  for (const line of src.split('\n')) {
    const code = line.replace(/\/\/.*$/, ''); // strip line comments (no // inside import specifiers in this repo)
    const m1 = code.match(/\bfrom\s*['"]([^'"]+)['"]/);
    if (m1) imports.push(m1[1]);
    const m2 = code.match(/^\s*import\s*['"]([^'"]+)['"]/);
    if (m2) imports.push(m2[1]);
  }
  const bad = imports.filter((p) => !p.startsWith('node:') && !p.startsWith('./') && !p.startsWith('../'));
  r4.files[f] = { imports, foreignImports: bad, clean: bad.length === 0 };
  if (bad.length > 0) r4.allClean = false;
}
const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'));
r4.pkg = { type: pkg.type, dependencies: pkg.dependencies ?? null, devDependencies: pkg.devDependencies ?? null };
r4.pkgClean = pkg.type === 'module' && pkg.dependencies === undefined && pkg.devDependencies === undefined;
if (!r4.pkgClean) r4.allClean = false;
rows.push({ kind: 'r4.evidence', ...r4 });

// =========================== VERDICTS (after the runs) ======================
const broken = siblingResults.filter((r) => !r.ok).map((r) => ({ repo: r.repo, file: r.file, firstBadIndex: r.firstBadIndex, why: r.why }));
const R1 = siblingResults.length >= 1 && siblingResults.every((r) => r.ok);
const divergenceList = tally.divergences.filter((d) => d.repo !== 'quilt-stone').map((d) => ({ repo: d.repo, file: d.file, stoneOk: d.ok, localOk: d.localOk }));
const siblingCross = siblingResults.filter((r) => r.localAvailable);
const R2 = siblingCross.length === siblingResults.length && divergenceList.length === 0;
const R3 = r3Caught && restored.ok === true && scratchDetected === 'stone-v1';
const R4 = r4.allClean;

rows.push(
  { kind: 'verdict.R1', pass: R1, chainsFound: siblingResults.length, chainsVerified: siblingResults.filter((r) => r.ok).length, chainsBroken: broken.length, broken, selfChainScannedSeparately: selfResults.length },
  { kind: 'verdict.R2', pass: R2, localCrossChecked: siblingCross.length, chainsFound: siblingResults.length, divergences: divergenceList, localSources: 'murmur/dba/fiction/arch/silicon/cortex/exoj/quant imported; raw+playtest transcribed verbatim; quilt-stone self (excluded from independent scope by the sealed rule)' },
  { kind: 'verdict.R3', pass: R3, tamperEvidence: R3 ? 'PROVEN' : 'NOT PROVEN' },
  { kind: 'verdict.R4', pass: R4, check: r4 },
);

// Final act: re-read THIS chain from disk and verify it with the canonical verifier
sealChain(rows, undefined, { alg: 'stone-v1' }); // idempotent on the sealed prefix; seals the new links
writeChain(rows);
const fromDisk = verifyChainFile(CHAIN);
const tip = fromDisk.tip;
rows.push({ kind: 'chain.seal', rows: rows.length, recheck: 'verifyChainFile(receipts_e_st1.jsonl)', fromDiskOk: fromDisk.ok, fromDiskWhy: fromDisk.why, tip });
sealChain(rows, undefined, { alg: 'stone-v1' });
writeChain(rows);

const allPass = R1 && R2 && R3 && R4 && fromDisk.ok;
const finalTip = rows[rows.length - 1].row_hash; // tip INCLUDING the chain.seal row
const summary = {
  experiment: 'E-ST1', repo: 'quilt-stone', lane: '26-b',
  verdicts: { R1, R2, R3, R4, selfChainFromDisk: fromDisk.ok },
  tally, tip, finalTip, alg: 'stone-v1', genesis: ALGS['stone-v1'].genesis, links: rows.length,
};
writeFileSync(SUMMARY, JSON.stringify(summary, null, 2) + '\n');

console.log(`R1 ${R1 ? 'PASS' : 'FAIL'}: ${siblingResults.filter((r) => r.ok).length}/${siblingResults.length} sibling chains verified under their own semantics (broken: ${broken.length})`);
console.log(`R2 ${R2 ? 'PASS' : 'FAIL'}: local cross-check ${siblingCross.length}/${siblingResults.length}, divergences ${divergenceList.length}`);
console.log(`R3 ${R3 ? 'PASS' : 'FAIL'}: tamper-evidence ${R3 ? 'PROVEN' : 'NOT PROVEN'} (caught=${r3Caught}, restored=${restored.ok})`);
console.log(`R4 ${R4 ? 'PASS' : 'FAIL'}: zero-dep + ESM static check across ${FILES.length + 1} files (incl package.json)`);
console.log(`self-chain: ${fromDisk.ok ? 'VERIFIED' : 'BROKEN'} from disk | links ${rows.length} | recheck-tip ${tip} | final-tip ${finalTip}`);
console.log(allPass ? 'E-ST1 GREEN' : 'E-ST1 RED');
process.exit(allPass ? 0 : 1);
