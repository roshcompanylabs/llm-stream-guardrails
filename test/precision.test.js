/**
 * Precision guard.
 *
 * "What does it wrongly destroy" is the first question any evaluator asks, so it
 * is a build failure here rather than a number in a README. Two real false
 * positives were found and fixed by this corpus:
 *
 *   - `AC` + 32 hex matched a Twilio SID rule, so any uppercase hex hash was
 *     flagged. That rule also protected nothing: a Twilio Account SID is a public
 *     identifier, not a credential. Removed.
 *   - A space-separated SSN pattern matched any `123 45 6789` grouping, so
 *     "Reference 100 20 3000" became a social security number. Hyphens only now.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { sieveText } from '../dist/index.js';
import { CLEAN, SENSITIVE } from '../bench/corpus.mjs';

test('PRECISION: clean text is never touched', () => {
  const failures = [];

  for (const [category, samples] of Object.entries(CLEAN)) {
    for (const text of samples) {
      const { text: out, detections } = sieveText(text);
      if (detections.length > 0) {
        failures.push(
          `[${category}] ${JSON.stringify(text.slice(0, 70))} -> ` +
            detections.map((d) => `${d.detector}:"${d.match}"`).join(', '),
        );
      }
      assert.equal(out, text, `clean text was altered: ${JSON.stringify(text.slice(0, 70))}`);
    }
  }

  assert.deepEqual(failures, [], 'false positives:\n  ' + failures.join('\n  '));
});

test('RECALL: every sensitive sample is caught by the expected detector', () => {
  const misses = [];

  for (const [expected, text] of SENSITIVE) {
    const { detections } = sieveText(text);
    const got = detections.map((d) => d.detector);
    if (!got.includes(expected)) {
      misses.push(`expected ${expected} in ${JSON.stringify(text.slice(0, 60))}, got [${got}]`);
    }
  }

  assert.deepEqual(misses, [], 'missed detections:\n  ' + misses.join('\n  '));
});

test('a Twilio Account SID rule is not reintroduced — it is a public id, not a secret', () => {
  const { detections } = sieveText('build AC1234567890ABCDEF1234567890ABCDEF12 ok');
  assert.equal(detections.length, 0);
});

test('SSN stays hyphen-only so ordinary digit groupings survive', () => {
  assert.equal(sieveText('Reference 100 20 3000 in the ledger').detections.length, 0);
  assert.equal(sieveText('ssn 123-45-6789 on file').detections.length, 1);
});
