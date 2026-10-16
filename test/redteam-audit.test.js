/**
 * Regression tests for the detector-bypass findings reproduced against v0.7.8.
 *
 * Finding 1 (a PEM private-key body reaching the reader in cleartext) is the
 * critical one; the rest are high/medium. Each test fails on the pre-fix build.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { sieveText, Sieve, notPlaceholder } from '../dist/index.js';

const SIZES = [1, 2, 3, 5, 7, 13, 29, 64];

function streamThrough(input, size, policy = {}) {
  const engine = new Sieve(policy);
  let out = '';
  for (let i = 0; i < input.length; i += size) out += engine.push(input.slice(i, i + size)).text;
  return out + engine.flush().text;
}

/** The headline guarantee: streamed output equals whole-string output at every size. */
function streamedEqualsWhole(input, policy = {}) {
  const whole = sieveText(input, policy).text;
  for (const s of SIZES) {
    const streamed = streamThrough(input, s, policy);
    if (streamed !== whole) return { ok: false, size: s, whole, streamed };
  }
  return { ok: true, whole };
}

// ------------------------------------------------------- Finding 1: PEM key body

const BODY = 'MIIEvQIBADANBgkqhkiG9w0SENTINELKEYBODYabcdefghijklmnopqrstuvwxyz0123456789';
const leaksBody = (out) => out.replace(/\s/g, '').includes('SENTINELKEYBODY');

test('F1: a PRIVATE KEY closed by END CERTIFICATE does not leak its body', () => {
  const input = `here:\n-----BEGIN PRIVATE KEY-----\n${BODY}\n-----END CERTIFICATE-----\ndone`;
  assert.equal(leaksBody(sieveText(input).text), false, 'whole-string leaked the key body');
  for (const s of SIZES) assert.equal(leaksBody(streamThrough(input, s)), false, `leaked at chunk size ${s}`);
});

test('F1: a PRIVATE KEY closed by an arbitrary END label does not leak', () => {
  const input = `-----BEGIN RSA PRIVATE KEY-----\n${BODY}\n-----END X-----`;
  assert.equal(leaksBody(sieveText(input).text), false);
  for (const s of SIZES) assert.equal(leaksBody(streamThrough(input, s)), false, `leaked at chunk size ${s}`);
});

test('F1: an unterminated key followed by a certificate block does not leak', () => {
  const input = `-----BEGIN PRIVATE KEY-----\n${BODY}\n-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----`;
  assert.equal(leaksBody(sieveText(input).text), false);
  for (const s of SIZES) assert.equal(leaksBody(streamThrough(input, s)), false, `leaked at chunk size ${s}`);
});

test('F1: two key headers do not leak the body between them', () => {
  const input = `-----BEGIN PRIVATE KEY-----\n${BODY}\n-----BEGIN PRIVATE KEY-----`;
  assert.equal(leaksBody(sieveText(input).text), false);
  for (const s of SIZES) assert.equal(leaksBody(streamThrough(input, s)), false, `leaked at chunk size ${s}`);
});

test('F1: a standalone certificate block still passes through untouched', () => {
  const input = 'see\n-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\nok';
  const out = sieveText(input).text;
  assert.equal(out.includes('-----BEGIN CERTIFICATE-----'), true);
  assert.equal(out.includes('QQ=='), true);
  assert.equal(out.includes('-----END CERTIFICATE-----'), true);
});

// ------------------------------------------------- Finding 2: IBAN under streaming

const IBAN = 'GB82 WEST 1234 5698 7654 32';

test('F2: an IBAN directly after punctuation is masked, streamed as whole', () => {
  for (const pre of ['"', '(', '[', ':', '=', '{"iban":"']) {
    const r = streamedEqualsWhole(`${pre}${IBAN}`);
    assert.equal(r.ok, true, `divergence at ${JSON.stringify(pre)}: whole=${JSON.stringify(r.whole)} streamed=${JSON.stringify(r.streamed)}`);
    assert.equal(r.whole.includes(IBAN), false, `IBAN leaked for prefix ${JSON.stringify(pre)}`);
  }
});

test('F2: the JSON case masks the account number at every chunking', () => {
  const r = streamedEqualsWhole('{"iban":"GB82 WEST 1234 5698 7654 32"}');
  assert.equal(r.ok, true);
  assert.equal(r.whole.includes(IBAN), false);
});

// --------------------------------------------- Finding 3: run heuristic false negative

test('F3: a real token with an incidental four-run is still masked', () => {
  // Assembled from fragments so the file carries no contiguous provider-token
  // literal for a secret scanner to flag — these are synthetic fixtures whose
  // only job is to exercise the run heuristic, and each embeds a run of four.
  for (const t of [
    'ghp_' + '0000' + 'BCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'AKIA' + 'AAAA' + '567890ABCDEF',
    'sk_' + 'live_' + '1111' + 'abcdefghijklmnopqrstuvwxyz',
  ]) {
    assert.equal(sieveText(`token ${t} end`).text.includes(t), false, `leaked ${t}`);
  }
});

test('F3: a filled-in documentation placeholder is still ignored', () => {
  assert.equal(sieveText('key = AKIAXXXXXXXXXXXXXXXX').detections.length, 0);
  assert.equal(notPlaceholder('AKIAXXXXXXXXXXXXXXXX'), false);
  assert.equal(notPlaceholder('AKIAIOSFODNN7EXAMPLE'), true);
});

// --------------------------------------------------- Finding 4: Unicode fold gaps

test('F4: newly-folded Unicode look-alikes no longer defeat a detector', () => {
  const cases = [
    '4111 1111 1111 1111', // ogham space between card groups
    'ghp_abcd⁣efghijklmnopqrstuvwxyz0123456789', // invisible separator inside a token
    'GB82⁃WEST⁃1234⁃5698⁃7654⁃32', // hyphen-bullet IBAN separators
  ];
  for (const input of cases) {
    assert.equal(sieveText(input).detections.length >= 1, true, `missed detection in ${JSON.stringify(input)}`);
  }
});

test('F4: a Greek-capital homoglyph label still masks its value', () => {
  const out = sieveText('Ρassword: hunter2two').text; // Greek capital Rho for P
  assert.equal(out.includes('hunter2two'), false);
});
