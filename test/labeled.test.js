/**
 * Label-aware detection.
 *
 * Value-shape matching alone leaves the most obvious case wide open: a model
 * writes `Password: <anything>` and no pattern recognises `<anything>`. These
 * tests cover the label path, including the streaming constraint that made a
 * lookbehind implementation impossible — the engine releases the label before
 * the value arrives, so the label must be part of the match and only the value
 * masked via a capture group.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { Sieve, sieveText } from '../dist/index.js';

function streamThrough(input, size, policy = {}) {
  const engine = new Sieve(policy);
  let out = '';
  for (let i = 0; i < input.length; i += size) out += engine.push(input.slice(i, i + size)).text;
  return out + engine.flush().text;
}

test('a labelled value is redacted whatever shape it has', () => {
  const cases = [
    ['Password: TEST_PASSWORD_0001', 'Password: [redacted:labeledSensitive]'],
    ['CVV: CVV-TEST-001', 'CVV: [redacted:labeledSensitive]'],
    ['Passport: PASSPORT-TEST-000001', 'Passport: [redacted:labeledSensitive]'],
    ['Account Number: ACCOUNT-TEST-000001', 'Account Number: [redacted:labeledSensitive]'],
    ['API Key: sk-test-0000000001', 'API Key: [redacted:labeledSensitive]'],
    ['Date of Birth: 1988-04-12', 'Date of Birth: [redacted:labeledSensitive]'],
    ['Government ID = ID-TEST-0021', 'Government ID = [redacted:labeledSensitive]'],
    ['2FA code: 000001', '2FA code: [redacted:labeledSensitive]'],
  ];
  for (const [input, expected] of cases) {
    assert.equal(sieveText(input).text, expected, `failed on: ${input}`);
  }
});

test('env-var style labels are caught even though `_` blocks a word boundary', () => {
  for (const line of [
    'SECRET_KEY=TEST_SECRET_KEY_0001',
    'PRIVATE_KEY=TEST_PRIVATE_KEY_0001',
    'ACCESS_TOKEN=TEST_ACCESS_TOKEN_0001',
    'CLIENT_SECRET=TEST_CLIENT_SECRET_0001',
    'DATABASE_PASSWORD=TEST_DATABASE_PASSWORD_0001',
    'ADMIN_PASSWORD=TEST_ADMIN_PASSWORD_0001',
  ]) {
    const { text, detections } = sieveText(line);
    assert.equal(detections.length, 1, `not detected: ${line}`);
    assert.ok(text.endsWith('[redacted:labeledSensitive]'), `value survived: ${text}`);
    assert.ok(text.includes('='), 'the label itself must be preserved');
  }
});

test('only the value is masked — the label stays readable', () => {
  const { text } = sieveText('Password: hunter2');
  assert.ok(text.startsWith('Password: '), 'label was destroyed');
  assert.ok(!text.includes('hunter2'));
});

test('STREAMING: a labelled value survives being split one character at a time', () => {
  const input = 'CVV: CVV-TEST-001 and Password: TEST_PASSWORD_0001 done';
  for (const size of [1, 2, 3, 7, 20]) {
    const out = streamThrough(input, size);
    assert.ok(!out.includes('CVV-TEST-001'), `CVV leaked at chunk size ${size}: ${out}`);
    assert.ok(!out.includes('TEST_PASSWORD_0001'), `password leaked at chunk size ${size}`);
    assert.equal(out, sieveText(input).text, `streaming differed from batch at size ${size}`);
  }
});

test('custom labels can be added for domain-specific records', () => {
  const policy = { sensitiveLabels: ['patient id', 'insurance id', 'salary'] };
  assert.ok(sieveText('Patient ID: PATIENT-TEST-001', policy).text.includes('[redacted'));
  assert.ok(sieveText('Insurance ID: INSURANCE-TEST-001', policy).text.includes('[redacted'));
  assert.ok(sieveText('Salary: 120000', policy).text.includes('[redacted'));
  // and the built-ins still work alongside them
  assert.ok(sieveText('Password: abc', policy).text.includes('[redacted'));
});

test('ambiguous labels are deliberately NOT in the defaults', () => {
  // These collide with ordinary code and prose, so they stay opt-in.
  assert.equal(sieveText('interface User { token: string }').detections.length, 0);
  assert.equal(sieveText('Product Name: Blue Widget').detections.length, 0);
  assert.equal(sieveText('IP Address: 192.0.2.1').detections.length, 0);
});
