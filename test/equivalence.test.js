/**
 * The equivalence guarantee — the spine of the library.
 *
 *   For any input, any policy and any chunking:
 *     1. the streamed output is byte-identical to the batch output, and
 *     2. every emitted chunk is independently well-formed.
 *
 * Property (2) is not academic. The previous engine cut the buffer by UTF-16
 * code unit, so it emitted lone surrogates; a consumer doing
 * `process.stdout.write(token)` per token — the README's own example — rendered
 * 📦🚚 as 📦��. String concatenation hid the damage, which is exactly why the
 * original suite could not see it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { sieveText, Sieve } from '../dist/index.js';

/** Deterministic PRNG so a failure is always reproducible. */
function lcg(seed) {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296);
}

function streamThrough(input, chunks, policy) {
  const engine = new Sieve(policy);
  const out = [];
  for (const c of chunks) {
    const r = engine.push(c);
    if (r.text) out.push(r.text);
    if (r.blocked) return out;
  }
  const f = engine.flush();
  if (f.text) out.push(f.text);
  return out;
}

function fixedChunks(input, size) {
  const chunks = [];
  for (let i = 0; i < input.length; i += size) chunks.push(input.slice(i, i + size));
  return chunks;
}

function randomChunks(input, rand) {
  const chunks = [];
  let i = 0;
  while (i < input.length) {
    const n = 1 + Math.floor(rand() * 9);
    chunks.push(input.slice(i, i + n));
    i += n;
  }
  return chunks;
}

const CARD = '4111 1111 1111 1111';
const KEY = 'sk-abcdefghijklmnopqrstuvwxyz123456';

const PEM = '-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END RSA PRIVATE KEY-----';

const CORPUS = [
  'plain prose with nothing sensitive in it at all',
  `a card ${CARD} mid sentence`,
  `key ${KEY} and mail a@b.co`,
  'Shipping update 📦🚚✅ order on the way 🎉',
  `emoji 🎉 then a card ${CARD} then more emoji 🚀🌟`,
  'CJK 日本語のテキストがここにあります',
  'accents: café naïve résumé Ünicode',
  `mixed 📦 ${KEY} 日本語 ${CARD} café`,
  'trailing digits 4111 1111 1111',
  'a'.repeat(300) + CARD + 'b'.repeat(300),
  'line one\r\nline two\nline three',
  '',
  '   ',
  CARD,
  KEY,
  // Each of the following exists so that a policy below actually fires on it.
  // Without these, the banned-word and label policies were being asserted
  // against text that could never trigger them — a no-op dressed as coverage.
  'this document is forbidden to share outside the company',
  'пометка: секрет и больше ничего',
  'この文書は機密です',
  'Password: hunter2\nCVV: 419\nDate of Birth: 1988-02-29',
  'Patient ID: PT-99120 admitted Tuesday',
  `here is the key:\n${PEM}\nand text after it`,
  `${PEM} at the very start`,
  'an unterminated -----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkq that never closes',
  `two cards ${CARD} and 5500-0000-0000-0004 together`,
  'iban GB82 WEST 1234 5698 7654 32 and ssn 123-45-6789',
];

const POLICIES = [
  {},
  { action: 'report' },
  { action: 'block' },
  { mask: '#' },
  { mask: (d) => `<${d.detector}>` },
  { bannedWords: ['forbidden', 'секрет', '機密'] },
  { sensitiveLabels: ['patient id'] },
  { normalize: false },
];

test('EQUIVALENCE: streamed output is byte-identical to batch, every input x policy x chunking', () => {
  for (const input of CORPUS) {
    for (const policy of POLICIES) {
      const batch = sieveText(input, policy).text;

      for (const size of [1, 2, 3, 5, 7, 13, 64, 1000]) {
        const streamed = streamThrough(input, fixedChunks(input, size), policy).join('');
        assert.equal(
          streamed,
          batch,
          `mismatch: size=${size} policy=${JSON.stringify(policy)} input=${JSON.stringify(input.slice(0, 60))}`,
        );
      }

      const rand = lcg(12345);
      for (let trial = 0; trial < 12; trial++) {
        const streamed = streamThrough(input, randomChunks(input, rand), policy).join('');
        assert.equal(
          streamed,
          batch,
          `mismatch on random chunking trial ${trial}, policy=${JSON.stringify(policy)}`,
        );
      }
    }
  }
});

test('WELL-FORMEDNESS: every emitted chunk survives an independent encode/decode', () => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  for (const input of CORPUS) {
    for (const size of [1, 2, 3, 5, 7, 64]) {
      const chunks = streamThrough(input, fixedChunks(input, size), {});

      for (const chunk of chunks) {
        assert.equal(
          chunk.isWellFormed(),
          true,
          `lone surrogate emitted at size ${size} in ${JSON.stringify(input.slice(0, 40))}`,
        );
      }

      // What a per-token byte sink (process.stdout.write) actually produces.
      const perChunk = chunks.map((c) => dec.decode(enc.encode(c))).join('');
      assert.equal(
        perChunk,
        chunks.join(''),
        `per-chunk encoding corrupted output at size ${size}`,
      );
      assert.equal(perChunk.includes('�'), false, 'U+FFFD introduced');
    }
  }
});

test('emoji-heavy clean text is never corrupted at any chunk size', () => {
  const input = 'Shipping 📦🚚✅ update 🎉 done 🚀🌟💡 finished';
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  for (let size = 1; size <= 12; size++) {
    const chunks = streamThrough(input, fixedChunks(input, size), {});
    const rebuilt = chunks.map((c) => dec.decode(enc.encode(c))).join('');
    assert.equal(rebuilt, input, `corrupted at chunk size ${size}`);
  }
});

test('detection indices point at the real input, and matches are complete', () => {
  const input = `hello a@b.co world ${CARD} end`;
  const { detections } = sieveText(input);

  for (const d of detections) {
    assert.equal(
      input.slice(d.index, d.index + d.length),
      d.match,
      `index/length do not locate the match for ${d.detector}`,
    );
  }
  assert.equal(detections.find((d) => d.detector === 'creditCard').match, CARD);
});

test('streaming fires onDetect exactly once per detection, with the full value', () => {
  const input = `key ${KEY} then mail a@b.co`;
  for (const size of [1, 3, 9]) {
    const seen = [];
    streamThrough(input, fixedChunks(input, size), { onDetect: (d) => seen.push(d.match) });
    assert.deepEqual(seen, [KEY, 'a@b.co'], `wrong reports at chunk size ${size}`);
  }
});
