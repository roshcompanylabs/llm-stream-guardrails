/**
 * Precision & recall report.
 *
 * Run with: npm run bench
 */
import { sieveText } from '../dist/index.js';
import { CLEAN, SENSITIVE, cleanCount } from './corpus.mjs';

let fp = 0;
const detail = [];

console.log('\n=== FALSE POSITIVES (clean text that must NOT be touched) ===\n');
for (const [category, samples] of Object.entries(CLEAN)) {
  let catFp = 0;
  for (const text of samples) {
    const { detections } = sieveText(text);
    if (detections.length > 0) {
      fp++;
      catFp++;
      detail.push({ category, text, hits: detections.map((d) => `${d.detector}:"${d.match}"`) });
    }
  }
  console.log(
    `  ${catFp === 0 ? 'OK ' : 'FP '} ${category.padEnd(26)} ${samples.length - catFp}/${samples.length} clean`,
  );
}

if (detail.length) {
  console.log('\n  --- wrongly flagged ---');
  for (const d of detail) {
    console.log(`  [${d.category}] ${JSON.stringify(d.text.slice(0, 68))}`);
    console.log(`       -> ${d.hits.join(', ')}`);
  }
}

let miss = 0;
console.log('\n=== RECALL (sensitive text that MUST be caught) ===\n');
for (const [expected, text] of SENSITIVE) {
  const got = sieveText(text).detections.map((d) => d.detector);
  if (!got.includes(expected)) {
    miss++;
    console.log(`  MISS ${expected} in ${JSON.stringify(text.slice(0, 60))} (got: ${got.join(',') || 'nothing'})`);
  }
}
console.log(`  caught ${SENSITIVE.length - miss}/${SENSITIVE.length}`);

console.log('\n=== RESULT ===');
console.log(`  clean samples    : ${cleanCount}`);
console.log(`  false positives  : ${fp}`);
console.log(`  specificity      : ${(((cleanCount - fp) / cleanCount) * 100).toFixed(1)}%`);
console.log(`  sensitive samples: ${SENSITIVE.length}`);
console.log(`  missed           : ${miss}`);
console.log(`  recall           : ${(((SENSITIVE.length - miss) / SENSITIVE.length) * 100).toFixed(1)}%\n`);

process.exit(fp === 0 && miss === 0 ? 0 : 1);
