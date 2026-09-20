/**
 * Regression tests for every HIGH-severity finding the red team reproduced
 * against v0.1.0. Each one leaked real data or hung the process.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { sieveText, Sieve } from '../dist/index.js';

const CARD = '4111 1111 1111 1111';
const KEY = 'sk-abcdefghijklmnopqrstuvwxyz123456';

function streamThrough(input, size, policy = {}) {
  const engine = new Sieve(policy);
  let out = '';
  for (let i = 0; i < input.length; i += size) out += engine.push(input.slice(i, i + size)).text;
  return out + engine.flush().text;
}

// ---------------------------------------------------------------- Unicode

test('Unicode separators no longer defeat the card detector (13 of 15 used to leak)', () => {
  const separators = [
    [' ', 'NBSP'], [' ', 'EN SP'], [' ', 'EM SP'],
    [' ', 'FIGURE SP'], [' ', 'THIN SP'], [' ', 'NNBSP'],
    [' ', 'MMSP'], ['　', 'IDEO SP'], ['‐', 'HYPHEN'],
    ['‑', 'NB HYPHEN'], ['‒', 'FIG DASH'], ['–', 'EN DASH'],
    ['−', 'MINUS'], [' ', 'SPACE'], ['-', 'HYPHEN-MINUS'],
  ];

  for (const [sep, label] of separators) {
    const card = `4111${sep}1111${sep}1111${sep}1111`;
    const { text } = sieveText(`Your card ${card} was charged.`);
    assert.ok(!text.includes('4111'), `${label} still leaks the card`);
    assert.ok(text.includes('[redacted:creditCard]'), `${label} not detected`);
  }
});

test('zero-width and combining characters no longer hide a value', () => {
  for (const hidden of ['​', '‌', '‍', '﻿', '­', '́']) {
    const card = `4111${hidden} 1111 1111 1111`;
    const { text } = sieveText(`card ${card} ok`);
    assert.ok(!text.includes('4111'), `U+${hidden.charCodeAt(0).toString(16)} still hides the card`);
  }
});

test('fullwidth digits are folded and caught', () => {
  const { text } = sieveText('card ４１１１ １１１１ １１１１ １１１１ ok');
  assert.ok(text.includes('[redacted:creditCard]'));
  assert.ok(!text.includes('４１１１'));
});

test('a homoglyph domain no longer defeats the email detector', () => {
  // Cyrillic а (U+0430) in place of Latin a.
  const { text, detections } = sieveText('mail аdmin@corp.com now');
  assert.equal(detections.length, 1);
  assert.equal(detections[0].detector, 'email');
  assert.ok(!text.includes('dmin@corp.com'));
});

// ------------------------------------------------------------ banned words

test('bannedWords now work in non-ASCII scripts (all were silently inert)', () => {
  const cases = [
    ['секрет', 'это секрет здесь', 'Cyrillic'],
    ['μυστικό', 'αυτό μυστικό εδώ', 'Greek'],
    ['סוד', 'זה סוד כאן', 'Hebrew'],
    ['機密', 'これは機密です', 'CJK'],
  ];

  for (const [word, sentence, label] of cases) {
    const { text, detections } = sieveText(sentence, { bannedWords: [word] });
    assert.equal(detections.length, 1, `${label} block list did not fire`);
    assert.ok(!text.includes(word), `${label} word survived`);
  }
});

test('a banned word still does not match inside a longer word', () => {
  const { detections } = sieveText('my password is strong', { bannedWords: ['pass'] });
  assert.equal(detections.length, 0);
});

// ------------------------------------------------------- variable-length secrets

test('a variable-length secret is never truncated and never tail-leaks', () => {
  const input = `token ${KEY} end`;
  for (const size of [1, 2, 4, 7, 15]) {
    const out = streamThrough(input, size);
    assert.ok(!out.includes('sk-'), `key fragment leaked at chunk size ${size}: ${out}`);
    assert.ok(!out.includes('abcdefghij'), `key body leaked at chunk size ${size}`);
    assert.equal(out, 'token [redacted:secret] end', `wrong output at size ${size}`);
  }
});

test('onDetect reports the complete key once, not 17 truncated prefixes', () => {
  const seen = [];
  streamThrough(`token ${KEY} end`, 1, { onDetect: (d) => seen.push(d.match) });
  assert.deepEqual(seen, [KEY]);
});

// ------------------------------------------------------------------- PEM keys

test('a full PEM private key block is masked entirely, body included', () => {
  const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ' + 'A'.repeat(200);
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
  const { text } = sieveText(`here it is:\n${pem}\ndone`);

  assert.ok(!text.includes('MIIEvQIBADAN'), 'key body streamed in cleartext');
  assert.ok(!text.includes(body.slice(0, 40)), 'key body streamed in cleartext');
  assert.ok(text.includes('[redacted:secret]'));
});

test('an UNTERMINATED PEM key fails closed rather than leaking the body', () => {
  const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw' + 'B'.repeat(300);
  const input = `oops:\n-----BEGIN PRIVATE KEY-----\n${body}`;

  for (const size of [1, 8, 64]) {
    const out = streamThrough(input, size);
    assert.ok(!out.includes('MIIEvQIBADAN'), `body leaked at chunk size ${size}`);
    assert.ok(!out.includes('BBBBBBBBBB'), `body leaked at chunk size ${size}`);
  }
});

test('an unterminated key still fails closed under a tiny retention ceiling', () => {
  const input = '-----BEGIN PRIVATE KEY-----' + 'A'.repeat(600);
  const out = streamThrough(input, 4, { maxRetention: 64 });
  assert.ok(!out.includes('AAAAAAAAAA'), 'ceiling overflow released the secret run');
});

// -------------------------------------------------------- credential coverage

test('a realistic .env dump does not survive (7 of 8 used to leak)', () => {
  const creds = [
    'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789',
    'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789',
    'sk_live_abcdefghij0123456789',
    'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    'glpat-abcdefghijklmnopqrstuv',
    'AKIAIOSFODNN7EXAMPLE',
    'AIzaSyA1234567890abcdefghijklmnopqrstuvw',
    'npm_abcdefghijklmnopqrstuvwxyz0123456789',
    'SG.abcdefghijklmnop_1234.abcdefghijklmnop_5678',
    'xoxb-1234567890-abcdefghij',
  ];

  for (const cred of creds) {
    const { text, detections } = sieveText(`API_KEY=${cred}`);
    assert.equal(detections.length, 1, `not detected: ${cred}`);
    assert.ok(!text.includes(cred), `leaked: ${cred}`);
  }
});

test('newly covered sensitive formats', () => {
  assert.ok(sieveText('ssn 123-45-6789 here').text.includes('[redacted:ssn]'));
  // A checksum-valid IBAN.
  assert.ok(sieveText('iban GB82 WEST 1234 5698 7654 32 here').text.includes('[redacted:iban]'));
  // A structurally similar but checksum-invalid one is left alone.
  assert.equal(sieveText('ref GB82 WEST 1234 5698 7654 33 here').detections.length, 0);
});

// ----------------------------------------------------------------- robustness

test('the email detector no longer backtracks catastrophically', () => {
  const hostile = 'x'.repeat(4000) + '@' + 'a-'.repeat(3000) + '!';
  const started = process.hrtime.bigint();
  sieveText(hostile);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(ms < 1000, `email pattern took ${ms.toFixed(0)}ms — backtracking is back`);
});

test('a non-numeric retention ceiling cannot disable streaming', () => {
  for (const bad of [NaN, Infinity, -1, 0, undefined, null, 'lots']) {
    const out = streamThrough(`hello world ${CARD} goodbye`, 3, { maxRetention: bad });
    assert.ok(out.includes('[redacted:creditCard]'), `broke with maxRetention=${String(bad)}`);
    assert.ok(out.includes('goodbye'), `stopped emitting with maxRetention=${String(bad)}`);
  }
});

test('masking can no longer mint a new match, because raw text is never rewritten', () => {
  // A mask that is itself a valid card must not be re-scanned into a detection.
  const { text, detections } = sieveText(`a@b.co and ${CARD}`, { mask: '4111 1111 1111 1111' });
  assert.equal(detections.length, 2);
  assert.equal(text, '4111 1111 1111 1111 and 4111 1111 1111 1111');
});

test('a mask containing a detectable value does not nest or recurse', () => {
  const { text, detections } = sieveText('mail a@b.co ok', { mask: 'x@y.com' });
  assert.equal(detections.length, 1);
  assert.equal(text, 'mail x@y.com ok');
});

test('block mode leaks nothing before it fires, at any chunk size', () => {
  const input = `intro text ${KEY} trailing`;
  for (const size of [1, 5, 20]) {
    const out = streamThrough(input, size, { action: 'block' });
    assert.ok(!out.includes('sk-'), `leaked before block at size ${size}`);
    assert.ok(!out.includes('trailing'), `emitted after block at size ${size}`);
  }
});
