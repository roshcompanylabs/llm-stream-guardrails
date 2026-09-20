/**
 * Detection accuracy.
 *
 * False positives are the reason redaction libraries get uninstalled, so the
 * "must NOT match" cases here carry as much weight as the "must match" ones.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { sieveText, luhn } from '../dist/index.js';

const redactedBy = (input) => sieveText(input).detections.map((d) => d.detector);

test('luhn accepts real card numbers', () => {
  assert.equal(luhn('4111111111111111'), true); // Visa test
  assert.equal(luhn('5500 0000 0000 0004'), true); // Mastercard test
  assert.equal(luhn('3400 0000 0000 009'), true); // Amex test, 15 digits
});

test('luhn rejects numbers that merely look like cards', () => {
  assert.equal(luhn('4111111111111112'), false); // bad check digit
  assert.equal(luhn('1234567812345678'), false);
  assert.equal(luhn('123'), false); // too short
  assert.equal(luhn('12345678901234567890'), false); // too long
});

test('a 16-digit number that fails Luhn is NOT redacted', () => {
  const input = 'order reference 4111 1111 1111 1112 shipped';
  const { text, detections } = sieveText(input);
  assert.equal(text, input, 'false positive: non-card was redacted');
  assert.equal(detections.length, 0);
});

test('ordinary numbers are left alone', () => {
  for (const input of [
    'the year 2026 was fine',
    'version 1.2.3 released',
    'we shipped 1500 units',
    'call it 99 problems',
  ]) {
    assert.equal(sieveText(input).text, input, `false positive on: ${input}`);
  }
});

test('detects common credential formats', () => {
  assert.deepEqual(redactedBy('key sk-abcdefghijklmnopqrstuvwxyz123456'), ['secret']);
  assert.deepEqual(redactedBy('aws AKIAIOSFODNN7EXAMPLE here'), ['secret']);
  assert.deepEqual(
    redactedBy('token ghp_abcdefghijklmnopqrstuvwxyz0123456789'),
    ['secret'],
  );
  assert.deepEqual(
    redactedBy('google AIzaSyA1234567890abcdefghijklmnopqrstuvw here'),
    ['secret'],
  );
  assert.deepEqual(
    redactedBy(
      'jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk done',
    ),
    ['secret'],
  );
  assert.deepEqual(redactedBy('-----BEGIN RSA PRIVATE KEY----- blah'), ['secret']);
});

test('a short sk- string is not mistaken for a key', () => {
  const input = 'the sk-8 model';
  assert.equal(sieveText(input).text, input);
});

test('detects a variety of email shapes', () => {
  for (const addr of [
    'a@b.co',
    'john.doe@example.com',
    'first+tag@sub.domain.org',
    'user_name99@mail-server.net',
  ]) {
    const { text, detections } = sieveText(`send to ${addr} now`);
    assert.equal(detections.length, 1, `missed: ${addr}`);
    assert.equal(text, 'send to [redacted:email] now');
  }
});

test('detects phone numbers with separators but not bare digit runs', () => {
  assert.deepEqual(redactedBy('call 555-867-5309 now'), ['phone']);
  assert.deepEqual(redactedBy('call +1 555 867 5309 now'), ['phone']);
  // A bare run of digits with no separators is too ambiguous to claim.
  assert.deepEqual(redactedBy('id 5558675309 ok'), []);
});

test('multiple different secrets in one message are all caught', () => {
  const { text, detections } = sieveText(
    'mail a@b.co card 4111 1111 1111 1111 key sk-abcdefghijklmnopqrstuvwxyz123456',
  );
  assert.deepEqual(detections.map((d) => d.detector), [
    'email',
    'creditCard',
    'secret',
  ]);
  assert.ok(!text.includes('a@b.co'));
  assert.ok(!text.includes('4111'));
  assert.ok(!text.includes('sk-abc'));
});

test('the mask itself is never re-redacted', () => {
  const { text } = sieveText('mail a@b.co ok');
  assert.equal(text, 'mail [redacted:email] ok');
  // Second pass must be a no-op.
  assert.equal(sieveText(text).text, text);
});
