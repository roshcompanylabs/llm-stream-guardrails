/**
 * Rebuild the playground page from dist/ + the HTML template.
 *   node playground/build.cjs
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dist = path.join(root, 'dist');
const order = ['types.js', 'canonical.js', 'detectors.js', 'core.js', 'index.js'];

let bundle = '';
for (const f of order) {
  let s = fs.readFileSync(path.join(dist, f), 'utf8');
  s = s.replace(/^\s*import\b[^;]*?from\s*['"][^'"]+['"]\s*;?\s*$/gm, '');
  s = s.replace(/^\s*export\s+\*\s+from\s*['"][^'"]+['"]\s*;?\s*$/gm, '');
  s = s.replace(/^\s*export\s*\{[^}]*\}\s*(?:from\s*['"][^'"]+['"]\s*)?;?\s*$/gm, '');
  s = s.replace(/^export\s+/gm, '');
  bundle += '\n// ===== ' + f + ' =====\n' + s;
}

const tpl = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
if (!tpl.includes('/*__STREAMSIEVE_BUNDLE__*/')) throw new Error('placeholder missing');
if (!tpl.includes('__SS_VERSION__')) throw new Error('version placeholder missing');

// The page states a version. Taking it from package.json rather than the
// template means it cannot drift from the code that was inlined beside it.
const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;

const out = tpl
  .replace('/*__STREAMSIEVE_BUNDLE__*/', bundle)
  .split('__SS_VERSION__').join(version);
if (out.includes('__SS_VERSION__')) throw new Error('version placeholder survived');

fs.writeFileSync(path.join(__dirname, 'index.html'), out);
console.log('playground/index.html rebuilt — ' + (out.length / 1024).toFixed(1) + ' KB, v' + version);
