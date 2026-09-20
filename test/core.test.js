/**
 * Streaming behaviour — the part that actually matters.
 *
 * Anyone can regex a finished string. The whole reason this library exists is
 * that a secret arrives split across chunk boundaries, so these tests feed data
 * in deliberately hostile ways: tiny chunks, splits mid-token, splits mid-digit.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  Sieve,
  sieveText,
  sieve,
  createSieveTransform,
} from '../dist/index.js';

const VALID_CARD = '4111 1111 1111 1111'; // Luhn-valid Visa test number
const PAD = 'The quick brown fox jumps over a lazy dog. '; // no digits, no @

/** Push a string through a Sieve in fixed-size chunks and return the full output. */
function streamThrough(input, chunkSize, policy = {}) {
  const engine = new Sieve(policy);
  let out = '';
  for (let i = 0; i < input.length; i += chunkSize) {
    out += engine.push(input.slice(i, i + chunkSize)).text;
  }
  out += engine.flush().text;
  return out;
}

test('clean text passes through completely unchanged', () => {
  const input = PAD.repeat(20) + 'Nothing to see here.';
  for (const size of [1, 3, 7, 64, 1000]) {
    assert.equal(streamThrough(input, size), input, `chunk size ${size}`);
  }
});

test('redacts an email in a single chunk', () => {
  const { text, detections } = sieveText('Write to john.doe@example.com today');
  assert.equal(text, 'Write to [redacted:email] today');
  assert.equal(detections.length, 1);
  assert.equal(detections[0].detector, 'email');
});

test('redacts an email split across two chunks', () => {
  const engine = new Sieve();
  let out = '';
  out += engine.push('Write to john.doe@exa').text;
  out += engine.push('mple.com today').text;
  out += engine.flush().text;
  assert.equal(out, 'Write to [redacted:email] today');
  assert.ok(!out.includes('example.com'));
});

test('FLAGSHIP: catches a credit card fed 7 characters at a time, mid-stream', () => {
  // Long enough that the sieve is actively releasing text before the card arrives.
  const input = PAD.repeat(10) + `My card is ${VALID_CARD}, charge it.` + PAD.repeat(3);
  const out = streamThrough(input, 7);

  assert.ok(out.includes('[redacted:creditCard]'), 'card was not redacted');
  assert.ok(!out.includes('4111'), 'card digits leaked into the output');
  // Everything else must survive intact.
  assert.ok(out.startsWith(PAD));
  assert.ok(out.endsWith(PAD.repeat(3)));
});

test('catches a card no matter where the chunk boundary falls', () => {
  const input = `Card: ${VALID_CARD} end`;
  for (let size = 1; size <= 12; size++) {
    const out = streamThrough(input, size);
    assert.ok(!out.includes('4111'), `leaked at chunk size ${size}: ${out}`);
    assert.ok(out.includes('[redacted:creditCard]'), `missed at chunk size ${size}`);
  }
});

test('character-by-character streaming still catches everything', () => {
  const input = `mail me at a@b.co or use ${VALID_CARD} ok`;
  const out = streamThrough(input, 1);
  assert.ok(!out.includes('a@b.co'));
  assert.ok(!out.includes('4111'));
  assert.equal(out, 'mail me at [redacted:email] or use [redacted:creditCard] ok');
});

test('block action stops the stream: no secret, nothing after it', () => {
  // Clean text that settled BEFORE the violation is still emitted, and that is
  // correct — in a real stream the reader saw it long before the secret arrived,
  // and a stream cannot un-send what it already sent. The guarantees that matter
  // are that the secret never appears and that nothing after the block does.
  const engine = new Sieve({ action: 'block' });
  let out = '';
  out += engine.push('here is a secret sk-abcdefghijklmnopqrstuvwxyz123456 ').text;
  out += engine.push('this must never appear').text;
  out += engine.flush().text;

  assert.equal(engine.isBlocked, true, 'stream should be blocked');
  assert.ok(!out.includes('sk-'), 'secret leaked');
  assert.ok(!out.includes('never appear'), 'text after the block leaked');
  // How much of the clean prefix escaped before the block is a settlement
  // detail, not a guarantee — assert the safety properties, not the offset.
  assert.ok('here is a secret '.startsWith(out), 'emitted text should be a clean prefix');
});

test('report action leaves text intact but still reports', () => {
  const seen = [];
  const { text, detections } = sieveText('ping ops@corp.io now', {
    action: 'report',
    onDetect: (d) => seen.push(d.detector),
  });
  assert.equal(text, 'ping ops@corp.io now');
  assert.deepEqual(seen, ['email']);
  assert.equal(detections.length, 1);
});

test('a single detection is reported once, not once per chunk', () => {
  const seen = [];
  const input = 'contact a@b.co ' + PAD.repeat(20);
  const engine = new Sieve({ action: 'report', onDetect: (d) => seen.push(d.match) });
  for (let i = 0; i < input.length; i += 2) engine.push(input.slice(i, i + 2));
  engine.flush();
  assert.deepEqual(seen, ['a@b.co']);
});

test('the same value appearing twice is reported twice', () => {
  const seen = [];
  sieveText('a@b.co and again a@b.co', {
    action: 'report',
    onDetect: (d) => seen.push(d.match),
  });
  assert.deepEqual(seen, ['a@b.co', 'a@b.co']);
});

test('custom mask is honoured', () => {
  const { text } = sieveText('card 4111 1111 1111 1111 here', { mask: '####' });
  assert.equal(text, 'card #### here');
});

test('bannedWords are caught case-insensitively across chunks', () => {
  const engine = new Sieve({ bannedWords: ['Classified'] });
  let out = '';
  out += engine.push('this is clas').text;
  out += engine.push('sified information').text;
  out += engine.flush().text;
  assert.equal(out, 'this is [redacted:bannedWord] information');
});

test('async generator API filters an AI-SDK-style stream', async () => {
  async function* source() {
    yield 'your key is sk-';
    yield 'abcdefghijklmnopqrstuvwxyz123456';
    yield ' keep it safe';
  }
  let out = '';
  for await (const piece of sieve(source())) out += piece;
  assert.equal(out, 'your key is [redacted:secret] keep it safe');
});

test('TransformStream API works in a Web Streams pipeline', async () => {
  const input = ['email ', 'me at bob', '@site.org ok'];
  const readable = new ReadableStream({
    start(controller) {
      for (const c of input) controller.enqueue(c);
      controller.close();
    },
  });

  let out = '';
  const reader = readable.pipeThrough(createSieveTransform()).getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out += value;
  }
  assert.equal(out, 'email me at [redacted:email] ok');
});

test('there is no safety dial to get wrong: the engine settles on its own', () => {
  // v0.1 made the user reason about a `holdBack` buffer. The settlement engine
  // works out what it must hold, so no configuration can make it leak.
  const input = `Card ${VALID_CARD} end`;
  for (const retention of [undefined, 1, 16, 64, 100000]) {
    const out = streamThrough(input, 1, { maxRetention: retention });
    assert.ok(!out.includes('4111'), `leaked with maxRetention=${String(retention)}`);
    assert.ok(out.includes('[redacted:creditCard]'));
  }
});

test('KNOWN LIMIT: a pattern glued to word characters is not matched', () => {
  // The detectors are word-boundary anchored. That buys precision — digits inside
  // a hash or an order id are left alone — at the cost of missing `x4111...x`.
  // Natural model output is delimited; deliberately evasive input is not.
  // Tracked as a hardening item for the red-team pass.
  const glued = `x${VALID_CARD}x`;
  assert.equal(sieveText(glued).detections.length, 0);
});

test('empty input is handled safely', () => {
  assert.equal(sieveText('').text, '');
  const engine = new Sieve();
  assert.equal(engine.push('').text, '');
  assert.equal(engine.flush().text, '');
});
