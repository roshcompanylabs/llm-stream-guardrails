/**
 * The equivalence guarantee, asserted by someone else's definition of it.
 *
 * `test/equivalence.test.js` already checks that streamed output is byte-identical
 * to batch output. This file checks the same property using `chunk-invariance`, a
 * third-party package that states the invariant independently and names the
 * smallest failing split when it breaks. It adds no coverage the suite did not
 * already have — what it adds is that the property is not graded by its own author.
 *
 * The last test is the control. A filter that redacts each chunk on its own MUST
 * fail this assertion; if it ever passes, the assertion has stopped discriminating
 * and every green above it is worthless.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { assertChunkInvariantAsync, fromTransformStream, allSplits, twoPartSplits } from 'chunk-invariance';

import { sieveText, createSieveTransform, email } from '../dist/index.js';

/** The whole-input side of the invariant. */
const whole = (policy) => (text) => sieveText(text, policy).text;

/** The streaming side. A fresh transform per split, which the adapter guarantees. */
const streaming = (policy) => fromTransformStream(() => createSieveTransform(policy));

const BODIES = [
  ['email',              'contact me at redouane@example.com please'],
  ['credit card, spaced', 'card 4111 1111 1111 1111 expires soon'],
  ['IBAN',               'IBAN MA64011519000001205000534921 ok'],
  ['SSN',                'ssn 123-45-6789 done'],
  ['secret token',       'token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 here'],
  ['two in one line',    'mail a@b.com and card 4111111111111111 both'],
  ['nothing to redact',  'a perfectly ordinary sentence with no secrets at all'],
  ['non-ASCII around it', 'التحويل إلى redouane@example.com تم بنجاح'],
  ['emoji around it',    'send 📦 to redouane@example.com 🚚 today'],
];

let totalSplits = 0;

for (const [label, body] of BODIES) {
  test(`chunk-invariance: ${label}`, async () => {
    const n = await assertChunkInvariantAsync(streaming(), whole(), body, {
      splits: allSplits(body, 3),
    });
    assert.ok(n > 0, 'the assertion must check at least one split');
    totalSplits += n;
  });
}

test('chunk-invariance: a long body, cut at every single point', async () => {
  const long =
    'Hello. Your account redouane@example.com is linked to card 4111 1111 1111 1111 ' +
    'and IBAN MA64011519000001205000534921. The API token is ' +
    'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789. Please do not share any of this.';
  const n = await assertChunkInvariantAsync(streaming(), whole(), long, {
    splits: twoPartSplits(long),
  });
  assert.ok(n > 0);
  totalSplits += n;
});

test('chunk-invariance: holds under a narrowed policy too', async () => {
  // Only the email detector, so the card below must survive untouched on both
  // sides — the invariant has to hold for what is *not* redacted as well.
  const policy = { detectors: [email] };
  const body = 'mail redouane@example.com and card 4111 1111 1111 1111 together';
  const n = await assertChunkInvariantAsync(streaming(policy), whole(policy), body, {
    splits: twoPartSplits(body),
  });
  assert.ok(n > 0);
  totalSplits += n;
});

test('CONTROL: a naive per-chunk filter fails the same assertion', async () => {
  // Redacting each chunk in isolation is the bug this library exists to avoid.
  // If this does not throw, the assertion cannot tell the two apart and nothing
  // above this line means anything.
  const naive = fromTransformStream(
    () =>
      new TransformStream({
        transform(chunk, controller) {
          controller.enqueue(sieveText(chunk).text);
        },
      }),
  );

  await assert.rejects(
    () =>
      assertChunkInvariantAsync(naive, whole(), 'contact me at redouane@example.com please', {
        splits: twoPartSplits('contact me at redouane@example.com please'),
      }),
    (err) => {
      assert.match(String(err.message), /not chunk-invariant/);
      // It must also name the split, which is the part that makes it useful.
      assert.match(String(err.message), /cut at \d+/);
      return true;
    },
    'the control must fail, otherwise this whole file is vacuous',
  );
});
