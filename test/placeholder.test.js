/**
 * Placeholder rejection.
 *
 * Documentation and IaC templates are full of credential-shaped strings that
 * protect nobody. Redacting them corrupts a code sample for no benefit, and it
 * was measured: 38 of the false positives against the gitleaks corpus were
 * exactly this class.
 *
 * The rule is deliberately asymmetric, and that asymmetry is the design:
 *   - by VALUE shape (`secret`) the checks are strict, because the shape is the
 *     only evidence there is;
 *   - by LABEL (`labeledSensitive`) they are weak, because a field literally
 *     called `Password` makes its value sensitive whatever it looks like.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { sieveText, notPlaceholder, notTemplateRef } from '../dist/index.js';

test('documentation placeholders are not treated as secrets', () => {
  for (const line of [
    'key = AKIAXXXXXXXXXXXXXXXX',
    'token: xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx',
    'export HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  ]) {
    assert.equal(sieveText(line).detections.length, 0, `wrongly redacted: ${line}`);
  }
});

test('template references are not treated as secrets', () => {
  for (const line of [
    'password = var.db_password',
    'password = "${aws_db_instance.default.password}"',
    'api_key: {{ vault_api_key }}',
    'API_KEY=<your-api-key-here>',
  ]) {
    assert.equal(sieveText(line).detections.length, 0, `wrongly redacted: ${line}`);
  }
});

test('an empty value is never a detection', () => {
  assert.equal(sieveText('password: ""').detections.length, 0);
  assert.equal(sieveText("password: ''").detections.length, 0);
});

test('a real credential-shaped value still is one', () => {
  // Same shape as the placeholders above, but without the repeated run.
  assert.equal(sieveText('key = AKIAIOSFODNN7EXAMPLE').detections.length, 1);
  assert.equal(sieveText('slack: xoxb-2957384910-2935-abcdefghij123').detections.length, 1);
});

test('the label path stays aggressive where the value path is strict', () => {
  // `TEST_PASSWORD_0001` is placeholder-ish by shape, but the label settles it.
  const labelled = sieveText('Password: TEST_PASSWORD_0001');
  assert.equal(labelled.detections.length, 1);
  assert.ok(!labelled.text.includes('TEST_PASSWORD_0001'));

  // The same string with no label and no credential shape stays untouched.
  assert.equal(sieveText('the build tag is TEST_PASSWORD_0001').detections.length, 0);
});

test('the two validators are exported and behave as documented', () => {
  assert.equal(notPlaceholder('AKIAXXXXXXXXXXXXXXXX'), false);
  assert.equal(notPlaceholder('AKIAIOSFODNN7EXAMPLE'), true);
  assert.equal(notTemplateRef('TEST_PASSWORD_0001'), true, 'label path must keep this');
  assert.equal(notTemplateRef('${secrets.TOKEN}'), false);
  assert.equal(notTemplateRef('   '), false);
});

test('a credential prefix inside a longer word is not a credential', () => {
  // Found by the gitleaks corpus: `ASIA` + 16 uppercase letters matched inside
  // the sentence TODAYINASIAASACKOFRICEFELLOVER, and `hf_` matched inside an
  // Objective-C identifier. Every prefix now needs a word boundary in front.
  assert.equal(sieveText('TODAYINASIAASACKOFRICEFELLOVER').detections.length, 0);
  assert.equal(sieveText('desktop-rhf_SponsoredProductsRemoteRHFSearch').detections.length, 0);

  // …while the same prefixes at a real boundary still fire.
  assert.equal(sieveText('aws_access_key: ASIAIOSFODNN7EXAMPLE').detections.length, 1);
  assert.equal(sieveText('key = AKIAIOSFODNN7EXAMPLE').detections.length, 1);
});

test('IDEMPOTENCE: sieving already-sieved output changes nothing', () => {
  // Found by the adversarial harness, not by chunked testing: `SSN: 123-45-6789`
  // masks to `SSN: [redacted:ssn]`, and a second pass saw the familiar `SSN:`
  // label in front of a value and redacted the mask itself. Real pipelines do
  // run text through twice — a retry, a proxy, defence in depth.
  for (const input of [
    "Here's my SSN: 123-45-6789",
    'Password: hunter2',
    'CVV: 419 and mail a@b.co',
    'API Key: sk-abcdefghijklmnopqrstuvwxyz123456',
  ]) {
    const once = sieveText(input).text;
    const twice = sieveText(once).text;
    const thrice = sieveText(twice).text;
    assert.equal(twice, once, `drifted on second pass: ${input}`);
    assert.equal(thrice, once, `drifted on third pass: ${input}`);
  }
});

test('markers from other redaction tools are left alone', () => {
  // ai4privacy and Presidio both emit bracketed tokens; masking them again
  // would corrupt a corpus that has already been anonymised.
  for (const input of ['Name: [GIVENNAME_1]', 'Email: [EMAIL]', 'Password: ***']) {
    assert.equal(sieveText(input).detections.length, 0, `re-redacted: ${input}`);
  }
});
