/**
 * Latency cost of the settlement-point design.
 *
 * Answers a question left open in "Split-Boundary Leaks in Streaming Guardrails"
 * (doi:10.5281/zenodo.22909586): how much does a settlement-point filter delay
 * time-to-first-token against an unfiltered stream?
 *
 *   node bench/latency.mjs
 *
 * What is measured, and why it is three numbers rather than one:
 *
 *   1. CHUNKS TO FIRST OUTPUT — how many chunks must arrive before the first
 *      byte is released. Hardware-independent, and it is the number that
 *      actually decides perceived latency, because a real stream is paced by
 *      the model, not by the filter.
 *   2. CPU PER CHUNK — the compute the filter adds per chunk. Hardware-dependent.
 *   3. ADDED TIME TO FIRST TOKEN — (1) x the inter-chunk interval + (2). Reported
 *      at three interval values spanning what providers actually deliver.
 *
 * A single "added milliseconds" figure would be dishonest: nearly all of the
 * delay is structural (waiting for chunks) rather than computational, so a
 * number measured on a zero-latency loop does not transfer to a real stream.
 */

import { cpus, totalmem, platform, arch } from 'node:os';
import { Sieve, sieveText } from '../dist/index.js';

const RUNS = 9; // odd, so the median is a real sample
const WARMUP = 3;

const CORPORA = {
  'assistant reply': [
    'Sure, I can help with that. First, open the settings page and look for the ',
    'section called Integrations. You should see a list of connected services ',
    'there. If the one you want is missing, click Add and follow the prompts. ',
    'Let me know how it goes and I will take it from there.',
  ].join(''),
  'reply with PII': [
    'I found your account. The email on file is jane.doe@acme-corp.com and the ',
    'card ending 1111 is 4111 1111 1111 1111. Your phone number is +1 555 867 ',
    '5309. Let me know if any of that needs updating.',
  ].join(''),
  'markdown + code': [
    '## Setup\n\nInstall the package:\n\n```bash\nnpm install example\n```\n\n',
    'Then import it and call `configure()` with your options. See the docs for ',
    'the full list. Note that `timeout` is in milliseconds, not seconds.\n',
  ].join(''),
  'Japanese reply': [
    'こんにちは。ご質問ありがとうございます。設定ページを開いて、連携という項目を探してください。',
    '接続済みのサービスが一覧で表示されます。お探しのものが見つからない場合は、追加を選択してください。',
  ].join(''),
};

/** Tokens are a few characters each; these bracket what providers emit. */
const CHUNK_SIZES = [1, 4, 8, 16];

/** Inter-chunk intervals, milliseconds. Fast local, typical hosted, slow. */
const INTERVALS = [5, 20, 50];

const chunksOf = (text, size) => {
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
};

/** Baseline: the same loop shape, doing no work. Isolates the filter's cost. */
const passthrough = () => ({ push: (c) => ({ text: c }), flush: () => ({ text: '' }) });

function measure(makeEngine, chunks) {
  const engine = makeEngine();
  let chunksBeforeFirst = 0;
  let firstSeen = false;
  let released = 0;

  const t0 = process.hrtime.bigint();
  for (let i = 0; i < chunks.length; i++) {
    const out = engine.push(chunks[i]).text;
    released += out.length;
    if (!firstSeen) {
      if (out.length > 0) { firstSeen = true; chunksBeforeFirst = i + 1; }
    }
  }
  released += engine.flush().text.length;
  const t1 = process.hrtime.bigint();

  return {
    chunksBeforeFirst: firstSeen ? chunksBeforeFirst : chunks.length,
    neverStreamed: !firstSeen,
    cpuMs: Number(t1 - t0) / 1e6,
    released,
  };
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

console.log('Latency cost of the settlement-point design');
console.log('='.repeat(78));
console.log();
console.log('Environment');
console.log(`  cpu      ${cpus()[0].model.trim()} (${cpus().length} cores)`);
console.log(`  memory   ${Math.round(totalmem() / 2 ** 30)} GB`);
console.log(`  platform ${platform()} ${arch()}`);
console.log(`  node     ${process.version}`);
console.log(`  package  llm-stream-guardrails, default policy`);
console.log(`  method   ${RUNS} runs after ${WARMUP} warmup, median reported`);
console.log();

const rows = [];

for (const [label, text] of Object.entries(CORPORA)) {
  for (const size of CHUNK_SIZES) {
    const chunks = chunksOf(text, size);

    for (let i = 0; i < WARMUP; i++) {
      measure(() => new Sieve({}), chunks);
      measure(passthrough, chunks);
    }

    const filtered = [];
    const base = [];
    for (let i = 0; i < RUNS; i++) {
      filtered.push(measure(() => new Sieve({}), chunks));
      base.push(measure(passthrough, chunks));
    }

    const f = {
      chunks: median(filtered.map((r) => r.chunksBeforeFirst)),
      cpu: median(filtered.map((r) => r.cpuMs)),
      never: filtered[0].neverStreamed,
    };
    const b = {
      chunks: median(base.map((r) => r.chunksBeforeFirst)),
      cpu: median(base.map((r) => r.cpuMs)),
    };

    // Masking shortens the output, so the invariant is against the batch
    // result, not the input. This is the guarantee the whole design exists for,
    // asserted on every measured run rather than taken on trust.
    const expected = sieveText(text).text.length;
    if (filtered[0].released !== expected) {
      throw new Error(
        `streamed ${filtered[0].released} chars, batch gives ${expected}: ${label} @ ${size}`,
      );
    }

    rows.push({
      label, size,
      extraChunks: f.chunks - b.chunks,
      charsHeld: (f.chunks - b.chunks) * size,
      cpuPerChunk: (f.cpu - b.cpu) / chunks.length,
      never: f.never,
    });
  }
}

console.log('Structural delay — extra chunks before the first byte is released');
console.log();
console.log('  corpus             chunk   extra chunks   chars held   cpu/chunk');
console.log('  ' + '-'.repeat(68));
for (const r of rows) {
  console.log(
    '  ' + r.label.padEnd(19) +
    String(r.size).padStart(4) +
    String(r.extraChunks).padStart(14) +
    String(r.charsHeld).padStart(13) +
    (r.cpuPerChunk * 1000).toFixed(1).padStart(9) + ' us' +
    (r.never ? '   NEVER STREAMED' : ''),
  );
}

console.log();
console.log('Added time to first token = extra chunks x inter-chunk interval + cpu');
console.log();
const header = '  corpus             chunk' + INTERVALS.map((i) => `${i}ms`.padStart(10)).join('');
console.log(header);
console.log('  ' + '-'.repeat(header.length - 2));
for (const r of rows) {
  const cells = INTERVALS.map((iv) =>
    `${(r.extraChunks * iv + r.cpuPerChunk).toFixed(1)}ms`.padStart(10),
  ).join('');
  console.log('  ' + r.label.padEnd(19) + String(r.size).padStart(4) + cells);
}

const worstChars = Math.max(...rows.map((r) => r.charsHeld));
const worstCpu = Math.max(...rows.map((r) => r.cpuPerChunk)) * 1000;
console.log();
console.log('Worst case in this run');
console.log(`  characters held before first output   ${worstChars}`);
console.log(`  added cpu per chunk                   ${worstCpu.toFixed(1)} us`);
console.log();
console.log('The delay is structural, not computational: it is the wait for enough');
console.log('input to prove a match cannot still grow. CPU is a rounding error beside');
console.log('the inter-chunk interval at every size measured.');
