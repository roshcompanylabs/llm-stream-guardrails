/**
 * Third-party corpus benchmark — all downloaded corpora.
 *
 *   node bench/corpora.mjs
 *
 * Every sample is run twice: once whole (BATCH) and once replayed in randomly
 * sized 1-7 character pieces (CHUNKED). The chunked run is the point — no public
 * benchmark does it, and it is the only thing that tests what this library is for.
 *
 * Scoring is deliberately conservative:
 *   IN SCOPE      types this library actually claims to detect.
 *   OUT OF SCOPE  types it does not attempt (names, dates, addresses, cities).
 *                 A hit there is recorded but never counted as a win.
 *   FALSE POSITIVE a detection on text the corpus says is not sensitive.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { sieveText, Sieve } from '../dist/index.js';

// Point CORPORA_DIR at the downloaded corpora, e.g.
//   CORPORA_DIR=../corpora node bench/corpora.mjs
const CORPORA = process.env.CORPORA_DIR || '../corpora';

function lcg(seed) {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296);
}

function chunkedRun(text, rand, policy = {}) {
  const engine = new Sieve(policy);
  let out = '';
  let i = 0;
  while (i < text.length) {
    const n = 1 + Math.floor(rand() * 7);
    out += engine.push(text.slice(i, i + n)).text;
    i += n;
  }
  return out + engine.flush().text;
}

const overlaps = (a1, a2, b1, b2) => a1 < b2 && b1 < a2;
const pct = (n, d) => (d === 0 ? '  n/a' : ((n / d) * 100).toFixed(1).padStart(5) + '%');
const rule = (n = 60) => '═'.repeat(n);

function header(title) {
  console.log('\n' + rule());
  console.log('  ' + title);
  console.log(rule() + '\n');
}

function scopeTable(stats) {
  console.log('  ' + 'entity'.padEnd(22) + 'total'.padStart(7) + 'found'.padStart(7) + 'recall'.padStart(8));
  let tot = 0, hit = 0;
  for (const [type, s] of Object.entries(stats)) {
    tot += s.total; hit += s.hit;
    console.log('  ' + type.padEnd(22) + String(s.total).padStart(7) + String(s.hit).padStart(7) + pct(s.hit, s.total).padStart(8));
  }
  console.log('  ' + '─'.repeat(44));
  console.log('  ' + 'TOTAL'.padEnd(22) + String(tot).padStart(7) + String(hit).padStart(7) + pct(hit, tot).padStart(8));
  return { tot, hit };
}

const summary = [];

// ══════════════════════════════════════════════════ Presidio (spans)

function runPresidio() {
  const file = join(CORPORA, '01-presidio', 'synth_dataset_v2.json');
  if (!existsSync(file)) return console.log('  (not found — skipped)');

  const IN = { CREDIT_CARD: 1, EMAIL_ADDRESS: 1, PHONE_NUMBER: 1, US_SSN: 1, IBAN_CODE: 1 };
  const records = JSON.parse(readFileSync(file, 'utf8'));
  const rand = lcg(20260920);
  const stats = {};
  for (const t of Object.keys(IN)) stats[t] = { total: 0, hit: 0 };
  let fp = 0, detTotal = 0, mismatch = 0, outSpans = 0;
  const fpSamples = [];

  for (const rec of records) {
    const text = rec.full_text;
    const spans = rec.spans || [];
    const { detections, text: batch } = sieveText(text);
    detTotal += detections.length;
    if (batch !== chunkedRun(text, rand)) mismatch++;

    for (const sp of spans) {
      const covered = detections.some((d) => overlaps(d.index, d.index + d.length, sp.start_position, sp.end_position));
      if (IN[sp.entity_type]) {
        stats[sp.entity_type].total++;
        if (covered) stats[sp.entity_type].hit++;
      } else outSpans++;
    }
    for (const d of detections) {
      if (!spans.some((sp) => overlaps(d.index, d.index + d.length, sp.start_position, sp.end_position))) {
        fp++;
        if (fpSamples.length < 5) fpSamples.push(`${d.detector}: ${JSON.stringify(d.match.slice(0, 40))}`);
      }
    }
  }

  console.log(`  ${records.length} records   ${detTotal} detections made\n`);
  const { tot, hit } = scopeTable(stats);
  console.log(`\n  out of scope: ${outSpans} spans (names, addresses, orgs…) — not attempted`);
  console.log(`  FALSE POSITIVES: ${fp} of ${detTotal}  (${pct(fp, detTotal).trim()})`);
  for (const f of fpSamples) console.log(`      ${f}`);
  console.log(`  STREAMING: ${records.length - mismatch}/${records.length} byte-identical` + (mismatch ? `   ${mismatch} MISMATCH` : '   (perfect)'));
  summary.push({ corpus: 'Presidio', recall: pct(hit, tot).trim(), fp, mismatch, samples: records.length });
}

// ══════════════════════════════════════════════════ Gretel (entity values)

function pyLiteral(s) {
  // entities is a Python repr: [{'entity': "...", 'types': ['email']}]
  return JSON.parse(
    s.replace(/(^|[\s[{,])'((?:[^'\\]|\\.)*)'/g, (_, pre, body) =>
      pre + JSON.stringify(body.replace(/\\'/g, "'"))),
  );
}

function runGretel() {
  const file = join(CORPORA, '02-gretel', 'gretel-pii-masking-en-v1-test.ndjson');
  if (!existsSync(file)) return console.log('  (not found — skipped)');

  const IN = {
    email: 1, phone_number: 1, credit_card_number: 1, ssn: 1,
    bank_routing_number: 1, account_number: 1,
  };
  const lines = readFileSync(file, 'utf8').trim().split('\n');
  const rand = lcg(4242);
  const stats = {};
  for (const t of Object.keys(IN)) stats[t] = { total: 0, hit: 0 };
  let unparsed = 0, mismatch = 0, outEnt = 0, rows = 0;

  for (const line of lines) {
    const row = JSON.parse(line);
    let ents;
    try { ents = pyLiteral(row.entities); } catch { unparsed++; continue; }
    rows++;
    const text = row.text;
    const out = sieveText(text).text;
    if (out !== chunkedRun(text, rand)) mismatch++;

    for (const e of ents) {
      const types = e.types || [];
      const value = String(e.entity);
      // No character offsets in this corpus — an entity counts as caught when
      // its literal value no longer survives in the output.
      const caught = value.length > 0 && !out.includes(value);
      let scored = false;
      for (const t of types) {
        if (IN[t]) {
          stats[t].total++;
          if (caught) stats[t].hit++;
          scored = true;
        }
      }
      if (!scored) outEnt++;
    }
  }

  console.log(`  ${rows} rows scored   ${unparsed} unparsable (upstream Python-literal quirks)\n`);
  const { tot, hit } = scopeTable(stats);
  console.log(`\n  out of scope: ${outEnt} entities (names, dates, record numbers…) — not attempted`);
  console.log(`  STREAMING: ${rows - mismatch}/${rows} byte-identical` + (mismatch ? `   ${mismatch} MISMATCH` : '   (perfect)'));
  summary.push({ corpus: 'Gretel', recall: pct(hit, tot).trim(), fp: '—', mismatch, samples: rows });
}

// ══════════════════════════════════════════════════ ai4privacy (multilingual)

function runAi4Privacy() {
  const file = join(CORPORA, '05-ai4privacy', 'openpii-1m-slice-2000.jsonl');
  if (!existsSync(file)) return console.log('  (not found — skipped)');

  const IN = { EMAIL: 1, TELEPHONENUM: 1, CREDITCARDNUMBER: 1, SOCIALNUM: 1 };
  const lines = readFileSync(file, 'utf8').trim().split('\n');
  const rand = lcg(999);
  const stats = {};
  for (const t of Object.keys(IN)) stats[t] = { total: 0, hit: 0 };
  let mismatch = 0, outSpans = 0;
  const byScript = {};

  for (const line of lines) {
    const row = JSON.parse(line);
    const text = row.source_text;
    const masks = row.privacy_mask || [];
    const { detections, text: batch } = sieveText(text);

    const streamed = chunkedRun(text, rand);
    const ok = batch === streamed;
    if (!ok) mismatch++;
    const sc = row.script || '?';
    byScript[sc] = byScript[sc] || { n: 0, bad: 0 };
    byScript[sc].n++;
    if (!ok) byScript[sc].bad++;

    for (const mk of masks) {
      const covered = detections.some((d) => overlaps(d.index, d.index + d.length, mk.start, mk.end));
      if (IN[mk.label]) {
        stats[mk.label].total++;
        if (covered) stats[mk.label].hit++;
      } else outSpans++;
    }
  }

  console.log(`  ${lines.length} rows   scripts: ${Object.entries(byScript).map(([k, v]) => `${k} ${v.n}`).join(', ')}\n`);
  const { tot, hit } = scopeTable(stats);
  console.log(`\n  out of scope: ${outSpans} spans (names, dates, cities, IDs…) — not attempted`);
  console.log(`  STREAMING: ${lines.length - mismatch}/${lines.length} byte-identical` + (mismatch ? `   ${mismatch} MISMATCH` : '   (perfect)'));
  for (const [k, v] of Object.entries(byScript)) {
    console.log(`      ${k}: ${v.n - v.bad}/${v.n}` + (v.bad ? '  <<< non-Latin failure' : ''));
  }
  summary.push({ corpus: 'ai4privacy', recall: pct(hit, tot).trim(), fp: '—', mismatch, samples: lines.length });
}

// ══════════════════════════════════════════════════ gitleaks (secrets)

function runGitleaks() {
  const file = join(CORPORA, '03-gitleaks', 'gitleaks-cases.json');
  if (!existsSync(file)) return console.log('  (not found — skipped)');

  const rules = JSON.parse(readFileSync(file, 'utf8'));
  const rand = lcg(7);
  let tpTotal = 0, tpHit = 0, fpTotal = 0, fpClean = 0, mismatch = 0;
  const missed = new Set();
  const wrongly = [];

  for (const r of rules) {
    for (const tp of r.tps || []) {
      tpTotal++;
      const { detections, text: batch } = sieveText(tp);
      if (detections.length) tpHit++; else missed.add(r.rule);
      if (batch !== chunkedRun(tp, rand)) mismatch++;
    }
    for (const fp of r.fps || []) {
      fpTotal++;
      const d = sieveText(fp).detections;
      if (!d.length) fpClean++;
      else if (wrongly.length < 5) wrongly.push(`${r.rule}: ${JSON.stringify(fp.slice(0, 38))} -> ${d[0].detector}`);
    }
  }

  console.log(`  ${rules.length} credential families, ${rules.filter((r) => (r.tps || []).length || (r.fps || []).length).length} with literal cases\n`);
  console.log(`  RECALL      ${tpHit}/${tpTotal} caught  (${pct(tpHit, tpTotal).trim()})`);
  console.log(`              ${missed.size} families produced at least one miss`);
  console.log(`  SPECIFICITY ${fpClean}/${fpTotal} near-misses correctly ignored  (${pct(fpClean, fpTotal).trim()})`);
  for (const w of wrongly) console.log(`      wrongly flagged  ${w}`);
  console.log(`  STREAMING   ${tpTotal - mismatch}/${tpTotal} byte-identical` + (mismatch ? `   ${mismatch} MISMATCH` : '   (perfect)'));
  summary.push({ corpus: 'gitleaks', recall: pct(tpHit, tpTotal).trim(), fp: fpTotal - fpClean, mismatch, samples: tpTotal });
}

header('PRESIDIO  synth_dataset_v2  (MIT, Microsoft)');
runPresidio();
header('GRETEL  pii-masking-en-v1 test split  (Apache-2.0)');
runGretel();
header('AI4PRIVACY  OpenPII-1M slice  (CC-BY-4.0) — multilingual');
runAi4Privacy();
header('GITLEAKS  rule corpus  (MIT) — credentials');
runGitleaks();

header('SUMMARY');
console.log('  ' + 'corpus'.padEnd(14) + 'samples'.padStart(9) + 'in-scope recall'.padStart(17) + 'false pos'.padStart(11) + 'stream fails'.padStart(14));
for (const s of summary) {
  console.log('  ' + s.corpus.padEnd(14) + String(s.samples).padStart(9) + String(s.recall).padStart(17) +
    String(s.fp).padStart(11) + String(s.mismatch).padStart(14));
}
const totalSamples = summary.reduce((n, s) => n + s.samples, 0);
const totalMismatch = summary.reduce((n, s) => n + s.mismatch, 0);
console.log(`\n  STREAMING EQUIVALENCE OVERALL: ${totalSamples - totalMismatch}/${totalSamples} samples byte-identical to batch` +
  (totalMismatch ? `   ${totalMismatch} FAILURES` : '   — no failures'));
console.log();
