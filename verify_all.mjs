// quilt-stone/verify_all.mjs — THE CONFORMANCE RUN.
// Scans every sibling repo for discoverable receipt chains and verifies each
// one with the canonical verifier (stone.mjs), then cross-checks the verdict
// against each repo's OWN local verifier (imported where exported,
// re-implemented verbatim for quilt-raw whose verifier is not exported).
//
// Output: one receipt per chain — repo, file, rows, dialect, ok/bad +
// firstBadIndex, tip — plus the tally. Exit 0 iff every discovered chain
// verifies under its own semantics AND stone agrees with every local verdict.
//
// THIS MODULE NEVER MODIFIES A SIBLING REPO. Read-only over the record.

import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { verifyChain, verifyChainFile, detectAlg } from './stone.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..'); // /home/z/my-project/download

// ---------------------------------------------------------------------------
// local verifiers: each repo's OWN chain semantics (R2 cross-check source)
// ---------------------------------------------------------------------------
// quilt-raw's verifier is embedded in experiments/e_r1_line.mjs (not exported)
// — transcribed VERBATIM from lines 32–73 of that file:
function rawFnv(s) {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(s.charCodeAt(i) & 0xff);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return '0x' + h.toString(16).padStart(16, '0');
}
function rawCanon(o) {
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(rawCanon).join(',') + ']';
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + rawCanon(o[k])).join(',') + '}';
}
function rawVerifyChain(rs) {
  let prev = 'gen0';
  for (let i = 0; i < rs.length; i++) {
    const r = rs[i];
    const body = { seq: r.seq, kind: r.kind };
    for (const k of Object.keys(r).sort()) {
      if (k === 'prev' || k === 'hash' || k === 'seq' || k === 'kind') continue;
      body[k] = r[k];
    }
    if (r.seq !== i + 1) return { ok: false, why: `seq break at ${i}` };
    if (r.prev !== prev) return { ok: false, why: `prev break at ${i}` };
    if (rawFnv(prev + '|' + rawCanon(body)) !== r.hash) return { ok: false, why: `hash break at ${i}` };
    prev = r.hash;
  }
  return { ok: true, why: `${rs.length} links`, tip: prev };
}

// quilt-playtest tidepool verifier — transcribed from
// examples/e10_tidepool_artifacts.mjs lines 80–94 (hash = fnv1a64 over
// top-sorted JSON of {rec fields, prev_hash}; seq is added AFTER hashing so
// the sealed content excludes it; from disk, strip row_hash AND seq):
function tidepoolCanon(o) {
  const s = {}; for (const k of Object.keys(o).sort()) s[k] = o[k];
  return JSON.stringify(s);
}
function tidepoolVerifyChain(rs) {
  const fnv = (s) => {
    let h = 0xcbf29ce484222325n; const prime = 0x100000001b3n, mask = 0xffffffffffffffffn;
    for (let j = 0; j < s.length; j++) { h ^= BigInt(s.charCodeAt(j)); h = (h * prime) & mask; }
    return h.toString(16).padStart(16, '0');
  };
  let prev = '0'.repeat(16);
  for (let i = 0; i < rs.length; i++) {
    const r = rs[i];
    const rec = { ...r }; delete rec.row_hash; delete rec.seq;
    const fields = { ...rec, prev_hash: prev };
    if (fnv(tidepoolCanon(fields)) !== r.row_hash) return { ok: false, why: `hash break at ${i}` };
    if (r.prev_hash !== prev) return { ok: false, why: `prev break at ${i}` };
    prev = r.row_hash;
  }
  return { ok: true, why: `${rs.length} links`, tip: prev };
}

const LOCALS = {
  'quilt-murmur': '../quilt-murmur/murmur/receipts.mjs',
  'quilt-dba': '../quilt-dba/dba/receipts.mjs',
  'quilt-fiction': '../quilt-fiction/fiction/receipts.mjs',
  'quilt-arch': '../quilt-arch/experiments/receipts.mjs',
  'quilt-silicon': '../quilt-silicon/experiments/receipts.mjs',
  'quilt-cortex': '../quilt-cortex/cortex/receipts.mjs',
  'exoj': '../exoj/receipts.mjs',
  'quilt-quant': '../quilt-quant/shared/kit.mjs', // verifyChain THROWS; wrapped. Called with the repo's own chainFieldsOf (quant/quant/play.mjs line 142)
  'quilt-playtest': null, // inline tidepool transcription above (e10 lines 80–94)
  'quilt-raw': null, // inline transcription above
};

// localVerify(repo, rows) -> { available, ok, tip, native } — normalized view
// of the repo's OWN verifier verdict on the same parsed rows.
export function localVerify(repo, rows) {
  if (repo === 'quilt-raw') {
    const v = rawVerifyChain(rows);
    return { available: true, ok: v.ok === true, tip: v.tip ?? null, native: v };
  }
  if (repo === 'quilt-playtest') {
    const v = tidepoolVerifyChain(rows);
    return { available: true, ok: v.ok === true, tip: v.tip ?? null, native: v };
  }
  const rel = LOCALS[repo];
  if (!rel) return { available: false, ok: null, tip: null, native: null };
  try {
    // synchronous dynamic import of a file URL
    const mod = modCache.get(rel) ?? null;
    if (mod) return runLocal(mod, rows);
    return { available: false, ok: null, tip: null, native: `not loaded: ${rel}` };
  } catch (e) {
    return { available: false, ok: null, tip: null, native: e.message };
  }
}
const modCache = new Map();
export async function loadLocals() {
  for (const [repo, rel] of Object.entries(LOCALS)) {
    if (!rel) continue;
    try {
      modCache.set(rel, await import(pathToFileURL(join(HERE, rel)).href));
    } catch (e) {
      modCache.set(rel, { __importError: e.message });
    }
  }
}
function runLocal(mod, rows) {
  if (mod.__importError) return { available: false, ok: null, tip: null, native: `import failed: ${mod.__importError}` };
  if (typeof mod.verifyChain !== 'function') return { available: false, ok: null, tip: null, native: 'no verifyChain export' };
  try {
    let v;
    if (mod.GENESIS_PREV !== undefined) {
      // quant dialect: the repo's own call form — chainFieldsOf strips
      // row_hash (+ ts) before re-derivation (quant/quant/play.mjs:141-142,683).
      // NOTE: quant's verifyChain RETURNS the tip string on success and
      // THROWS on tamper — normalize both shapes here.
      v = mod.verifyChain(rows, ({ row_hash, ts, ...fields }) => fields);
      return { available: true, ok: typeof v === 'string' ? true : v?.ok === true, tip: typeof v === 'string' ? v : v?.tip ?? null, native: v };
    }
    v = mod.verifyChain(rows); // fleet/exoj dialects
    return { available: true, ok: v?.ok === true, tip: v?.tip ?? null, native: v };
  } catch (e) {
    return { available: true, ok: false, tip: null, native: { threw: e.message } };
  }
}

// ---------------------------------------------------------------------------
// discovery: every .jsonl under ROOT/*/, content-sniffed for chain-ness
// ---------------------------------------------------------------------------
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);
const MAX_FILE_BYTES = 20 * 1024 * 1024;

function walkJsonl(dir, out, depth = 0) {
  if (depth > 8) return;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walkJsonl(p, out, depth + 1); continue; }
    if (!e.isFile() || !e.name.endsWith('.jsonl')) continue;
    try { if (statSync(p).size > MAX_FILE_BYTES) continue; } catch { continue; }
    out.push(p);
  }
}

// A file is a receipt chain iff its rows carry chain link fields.
function sniffChainFile(path) {
  let rows;
  try {
    rows = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l));
  } catch { return { chain: false, reason: 'not parseable as JSONL' }; }
  if (!Array.isArray(rows) || rows.length === 0) return { chain: false, reason: 'empty file' };
  const hasLinks = (r) => r && typeof r === 'object' &&
    (r.row_hash !== undefined || (r.hash !== undefined && r.prev !== undefined) ||
     (r.row_hash !== undefined && r.prev_hash !== undefined));
  if (!rows.some(hasLinks)) return { chain: false, reason: 'no link fields (not a chain)' };
  return { chain: true, rows };
}

export async function discoverChains(root = ROOT) {
  const files = [];
  for (const e of readdirSync(root, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    walkJsonl(join(root, e.name), files);
  }
  const found = [];
  for (const f of files.sort()) {
    const repo = relative(root, f).split('/')[0];
    const s = sniffChainFile(f);
    found.push({ repo, file: f, relFile: relative(root, f), ...s });
  }
  return found;
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------
export async function runConformance({ root = ROOT, log = () => {} } = {}) {
  await loadLocals();
  const discovered = await discoverChains(root);
  const chains = discovered.filter((d) => d.chain);
  const notChains = discovered.filter((d) => !d.chain);
  const results = [];
  for (const c of chains) {
    const alg = detectAlg(c.rows);
    const stone = verifyChain(c.rows);
    const local = localVerify(c.repo, c.rows);
    const agree = local.available ? (local.ok === stone.ok) : null;
    results.push({
      repo: c.repo,
      file: c.relFile,
      rows: c.rows.length,
      alg,
      ok: stone.ok,
      firstBadIndex: stone.firstBadIndex,
      at: stone.at,
      why: stone.why,
      tip: stone.tip,
      genesis: stone.genesis,
      localAvailable: local.available,
      localOk: local.ok,
      localTip: local.tip,
      agree,
    });
  }
  const tally = {
    reposScanned: new Set(discovered.map((d) => d.repo)).size,
    jsonlScanned: discovered.length,
    chainsFound: chains.length,
    chainsVerified: results.filter((r) => r.ok).length,
    chainsBroken: results.filter((r) => !r.ok).length,
    localCrossChecked: results.filter((r) => r.localAvailable).length,
    divergences: results.filter((r) => r.agree === false),
    nonChainJsonl: notChains.map((d) => ({ repo: d.repo, file: d.relFile, reason: d.reason })),
  };
  return { results, tally };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const { results, tally } = await runConformance({ log: console.log });
  const w = [4, 44, 5, 17, 5, 8, 10];
  const pad = (s, n) => String(s ?? '').slice(0, n - 1).padEnd(n);
  console.log('REPO          FILE' + ' '.repeat(40) + 'ROWS ALG               OK    BAD-IDX TIP');
  for (const r of results) {
    console.log(
      pad(r.repo, 14) + pad(r.file, 45) + pad(r.rows, 5) + pad(r.alg, 19) +
      pad(r.ok ? 'ok' : 'BAD', 6) + pad(r.ok ? '' : r.firstBadIndex, 8) + (r.tip ?? '')
    );
    if (!r.ok) console.log(`              ^^ why=${r.why} at=${r.at}`);
    if (r.agree === false) console.log(`              ^^ LOCAL DIVERGENCE: localOk=${r.localOk} localTip=${r.localTip}`);
    if (r.agree === null && r.localAvailable === false) console.log(`              ^^ local verifier unavailable (${r.localTip ?? ''}) — R2 cross-check skipped`);
  }
  console.log('\nnon-chain .jsonl scanned (excluded from tally):');
  for (const nc of tally.nonChainJsonl) console.log(`  ${nc.repo}: ${nc.file} — ${nc.reason}`);
  console.log(`\nTALLY: ${tally.chainsVerified}/${tally.chainsFound} chains verified under their own semantics` +
    ` | local cross-check ${tally.localCrossChecked}/${tally.chainsFound}` +
    ` | divergences ${tally.divergences.length} | repos scanned ${tally.reposScanned} | jsonl scanned ${tally.jsonlScanned}`);
  const allGood = tally.chainsBroken === 0 && tally.divergences.length === 0;
  console.log(allGood ? 'CONFORMANCE GREEN' : 'CONFORMANCE RED');
  process.exit(allGood ? 0 : 1);
}
