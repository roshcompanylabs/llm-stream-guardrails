/**
 * The test count in CONTRIBUTING.md must be the test count the suite reports.
 *
 * That line is where the contribution policy sends people, so a stale number there
 * is the first thing a new contributor checks and the first thing that does not
 * match. It said 69 while the suite ran 79, and it was corrected by hand once
 * already. A number a human has to remember to update is a number that goes stale,
 * so this makes the release fail instead.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const DOC = 'CONTRIBUTING.md';
const PATTERN = /npm test\s+#\s*(\d+)\s+tests/;

const doc = readFileSync(DOC, 'utf8');
const claimed = doc.match(PATTERN);
if (!claimed) {
  console.error(`${DOC}: no "npm test  # N tests" line found. The gate cannot check a`);
  console.error('claim that is not stated; either restore the line or drop this gate.');
  process.exit(1);
}

// `node --test` reports the totals on stdout; a non-zero exit here would mean the
// suite itself is broken, which the test job already covers, so surface it plainly.
let out;
try {
  out = execFileSync('node', ['--test'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
} catch (err) {
  out = `${err.stdout ?? ''}${err.stderr ?? ''}`;
}

const actual = out.match(/^# pass (\d+)$/m);
if (!actual) {
  console.error('Could not read a "# pass N" line from the test output.');
  process.exit(1);
}

const stated = Number(claimed[1]);
const passing = Number(actual[1]);

if (stated !== passing) {
  console.error(`${DOC} says ${stated} tests; the suite reports ${passing}.`);
  console.error(`Fix the line: npm test        # ${passing} tests`);
  process.exit(1);
}

console.log(`${DOC} states ${stated} tests, and the suite reports ${passing}.`);
