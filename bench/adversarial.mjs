/**
 * Adversarial harness — same corpora, different attacks.
 *
 *   node bench/adversarial.mjs
 *
 * bench/corpora.mjs scores detection quality with random chunking. This file
 * assumes the detectors are fine and goes after the ENGINE, using the corpus text
 * as raw material for seven methods that random chunking cannot reach:
 *
 *   A  exhaustive split      every single boundary position, not a sample
 *   B  unicode mutation      real corpus values rewritten with look-alikes
 *   C  cross-API agreement   sieveText vs async generator vs TransformStream
 *   D  idempotence           sieving twice must change nothing
 *   E  long concatenation    200 records as one stream, as a real reply arrives
 *   F  complexity            throughput vs length — catch super-linear blowup
 *   G  chaos chunking        pathological patterns: empties, 1s, one huge chunk
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { sieveText, sieve, createSieveTransform, Sieve } from '../dist/index.js';

// Point CORPORA_DIR at the downloaded corpora, e.g.
//   CORPORA_DIR=../corpora node bench/corpora.mjs
const CORPORA = process.env.CORPORA_DIR || '../corpora';
const PRESIDIO = join(CORPORA, '01-presidio', 'synth_dataset_v2.json');
const AI4P = join(CORPORA, '05-ai4privacy', 'openpii-1m-slice-2000.jsonl');

if (!existsSync(PRESIDIO)) {
  console.log('corpora not found — run the download step first');
  process.exit(1);
}

const records = JSON.parse(readFileSync(PRESIDIO, 'utf8'));
const multilingual = existsSync(AI4P)
  ? readFileSync(AI4P, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  : [];

/** Records that actually contain something we detect — the interesting ones. */
const loaded = records.filter((r) => sieveText(r.full_text).detections.length > 0);

const results = [];
function report(method, passed, total, note = '') {
  const ok = passed === total;
  results.push({ method, passed, total, ok });
  const pct = total ? ((passed / total) * 100).toFixed(1) : '—';
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${method.padEnd(24)} ${String(passed).padStart(7)}/${String(total).padEnd(7)} ${pct}%${note ? '  ' + note : ''}`);
}

function pushAll(text, chunks) {
  const engine = new Sieve();
  let out = '';
  for (const c of chunks) out += engine.push(c).text;
  return out + engine.flush().text;
}

// ─────────────────────────────────────── A. exhaustive split

console.log('\nA. EXHAUSTIVE SPLIT — every boundary position, one split each\n');
{
  const sample = loaded.slice(0, 400);
  let total = 0, pass = 0;
  const failures = [];
  for (const rec of sample) {
    const text = rec.full_text;
    const expect = sieveText(text).text;
    for (let k = 1; k < text.length; k++) {
      total++;
      const got = pushAll(text, [text.slice(0, k), text.slice(k)]);
      if (got === expect) pass++;
      else if (failures.length < 3) failures.push({ k, text: text.slice(0, 60), expect, got });
    }
  }
  report('single split, all k', pass, total, `${sample.length} records`);
  for (const f of failures) {
    console.log(`        split@${f.k} ${JSON.stringify(f.text)}`);
    console.log(`          expect ${JSON.stringify(f.expect.slice(0, 70))}`);
    console.log(`          got    ${JSON.stringify(f.got.slice(0, 70))}`);
  }
}

// ─────────────────────────────────────── B. unicode mutation

console.log('\nB. UNICODE MUTATION — real corpus values rewritten with look-alikes\n');
{
  const MUTATIONS = [
    ['NBSP', (s) => s.replace(/ /g, '\u00A0')],
    ['en-dash', (s) => s.replace(/-/g, '\u2013')],
    ['thin space', (s) => s.replace(/ /g, '\u2009')],
    ['zero-width', (s) => s.split('').join('\u200B')],
    ['fullwidth digits', (s) => s.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + (+d)))],
  ];
  const IN = new Set(['CREDIT_CARD', 'EMAIL_ADDRESS', 'US_SSN', 'IBAN_CODE']);

  for (const [name, fn] of MUTATIONS) {
    let total = 0, pass = 0;
    for (const rec of records) {
      for (const sp of rec.spans || []) {
        if (!IN.has(sp.entity_type)) continue;
        const original = sp.entity_value;
        // Only test values the library catches unmutated — otherwise we would be
        // measuring coverage, not resistance to evasion.
        if (sieveText(original).detections.length === 0) continue;
        const mutated = fn(original);
        if (mutated === original) continue;
        total++;
        if (sieveText(mutated).detections.length > 0) pass++;
      }
    }
    report(name, pass, total);
  }
}

// ─────────────────────────────────────── C. cross-API agreement

console.log('\nC. CROSS-API AGREEMENT — three public entry points, one answer\n');
{
  const sample = loaded.slice(0, 300);
  let genPass = 0, tsPass = 0;

  for (const rec of sample) {
    const text = rec.full_text;
    const expect = sieveText(text).text;

    async function* src() {
      for (let i = 0; i < text.length; i += 5) yield text.slice(i, i + 5);
    }
    let viaGen = '';
    for await (const piece of sieve(src())) viaGen += piece;
    if (viaGen === expect) genPass++;

    const readable = new ReadableStream({
      start(c) {
        for (let i = 0; i < text.length; i += 5) c.enqueue(text.slice(i, i + 5));
        c.close();
      },
    });
    let viaTs = '';
    const reader = readable.pipeThrough(createSieveTransform()).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      viaTs += value;
    }
    if (viaTs === expect) tsPass++;
  }
  report('async generator', genPass, sample.length);
  report('TransformStream', tsPass, sample.length);
}

// ─────────────────────────────────────── D. idempotence

console.log('\nD. IDEMPOTENCE — sieving the output again must change nothing\n');
{
  let pass = 0;
  const bad = [];
  for (const rec of records) {
    const once = sieveText(rec.full_text).text;
    const twice = sieveText(once).text;
    if (once === twice) pass++;
    else if (bad.length < 3) bad.push({ once: once.slice(0, 60), twice: twice.slice(0, 60) });
  }
  report('sieve(sieve(x)) == sieve(x)', pass, records.length);
  for (const b of bad) console.log(`        once  ${JSON.stringify(b.once)}\n        twice ${JSON.stringify(b.twice)}`);
}

// ─────────────────────────────────────── E. long concatenation

console.log('\nE. LONG CONCATENATION — 200 records as one continuous reply\n');
{
  let pass = 0, total = 0;
  for (let batch = 0; batch < 5; batch++) {
    const slice = records.slice(batch * 200, batch * 200 + 200);
    if (!slice.length) break;
    const joined = slice.map((r) => r.full_text).join('\n\n');
    const expect = sieveText(joined).text;
    for (const size of [1, 3, 17, 512]) {
      total++;
      const chunks = [];
      for (let i = 0; i < joined.length; i += size) chunks.push(joined.slice(i, i + size));
      if (pushAll(joined, chunks) === expect) pass++;
    }
  }
  report('joined-document stream', pass, total, 'docs up to ~17k chars');
}

// ─────────────────────────────────────── F. complexity

console.log('\nF. COMPLEXITY — throughput must not collapse as input grows\n');
{
  const unit = records.slice(0, 40).map((r) => r.full_text).join('\n');
  const rows = [];
  for (const mult of [1, 2, 4, 8, 16]) {
    const text = unit.repeat(mult);
    const t0 = process.hrtime.bigint();
    const engine = new Sieve();
    for (let i = 0; i < text.length; i += 16) engine.push(text.slice(i, i + 16));
    engine.flush();
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    rows.push({ chars: text.length, ms, kbs: text.length / 1024 / (ms / 1000) });
  }
  for (const r of rows) {
    console.log(`        ${String(r.chars).padStart(8)} chars  ${r.ms.toFixed(1).padStart(8)} ms  ${r.kbs.toFixed(0).padStart(6)} KB/s`);
  }
  // Linear would keep KB/s flat; quadratic halves it on every doubling.
  const first = rows[0].kbs, last = rows[rows.length - 1].kbs;
  const ratio = last / first;
  const linear = ratio > 0.4;
  report('throughput stays linear', linear ? 1 : 0, 1, `16x input keeps ${(ratio * 100).toFixed(0)}% of throughput`);
}

// ─────────────────────────────────────── G. chaos chunking

console.log('\nG. CHAOS CHUNKING — pathological arrival patterns\n');
{
  const PATTERNS = {
    'empties interleaved': (t) => {
      const out = [];
      for (let i = 0; i < t.length; i++) { out.push(''); out.push(t[i]); out.push(''); }
      return out;
    },
    'one huge then ones': (t) => [t.slice(0, Math.floor(t.length / 2)), ...t.slice(Math.floor(t.length / 2)).split('')],
    'ones then one huge': (t) => [...t.slice(0, Math.floor(t.length / 2)).split(''), t.slice(Math.floor(t.length / 2))],
    'whole then empty': (t) => [t, '', '', ''],
    'fibonacci sizes': (t) => {
      const out = []; let a = 1, b = 2, i = 0;
      while (i < t.length) { out.push(t.slice(i, i + a)); i += a; [a, b] = [b, a + b]; }
      return out;
    },
  };
  const sample = loaded.slice(0, 250);
  for (const [name, fn] of Object.entries(PATTERNS)) {
    let pass = 0;
    for (const rec of sample) {
      const text = rec.full_text;
      if (pushAll(text, fn(text)) === sieveText(text).text) pass++;
    }
    report(name, pass, sample.length);
  }
}

// ─────────────────────────────────────── multilingual bonus

if (multilingual.length) {
  console.log('\nH. NON-LATIN CHAOS — the same patterns on Cyrillic and Greek text\n');
  const byScript = {};
  for (const row of multilingual) {
    const sc = row.script || '?';
    if (sc === 'Latn') continue;
    byScript[sc] = byScript[sc] || { pass: 0, total: 0 };
    const text = row.source_text;
    const expect = sieveText(text).text;
    const chunks = [];
    for (let i = 0; i < text.length; i++) { chunks.push(''); chunks.push(text[i]); }
    byScript[sc].total++;
    if (pushAll(text, chunks) === expect) byScript[sc].pass++;
  }
  for (const [sc, s] of Object.entries(byScript)) report(`${sc} 1-char + empties`, s.pass, s.total);
}

console.log('\n' + '═'.repeat(60));
const failed = results.filter((r) => !r.ok);
const totalChecks = results.reduce((n, r) => n + r.total, 0);
const totalPass = results.reduce((n, r) => n + r.passed, 0);
console.log(`  ${results.length} methods, ${totalChecks.toLocaleString()} individual checks`);
console.log(`  ${totalPass.toLocaleString()} passed, ${(totalChecks - totalPass).toLocaleString()} failed`);
console.log(failed.length ? `  FAILING METHODS: ${failed.map((f) => f.method).join(', ')}` : '  ALL METHODS PASS');
console.log('═'.repeat(60) + '\n');
process.exit(failed.length ? 1 : 0);
