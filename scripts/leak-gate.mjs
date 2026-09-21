/**
 * Fails the build if the packed tarball carries anything that identifies the
 * machine it was built on.
 *
 * A redaction library that ships its author's home directory has lost the
 * argument before anyone reads the README, so this runs in CI rather than
 * living in someone's memory.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir, homedir, hostname, userInfo } from 'node:os';
import { join, basename, sep } from 'node:path';

/** Shapes that should never appear in a published file. */
const PATTERNS = [
  [/[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]/i, 'a Windows user-profile path'],
  [/\/(?:home|Users)\/[A-Za-z0-9._-]+\//, 'a Unix home directory path'],
  [/sourceMappingURL/, 'a source-map reference (it can embed build paths)'],
  // Only a body long enough to actually be a key. The test corpus deliberately
  // contains a 16-character stub so the PEM detector has something to catch,
  // and failing the build on that would teach everyone to ignore this gate.
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{200,}?-----END/, 'a private key block'],
];

/**
 * Strings taken from the machine doing the build, matched literally rather than
 * as patterns — so this file never has to contain the values it guards against,
 * and nothing needs escaping.
 */
const GENERIC = new Set(['root', 'runner', 'user', 'node', 'admin', 'ubuntu', 'home', 'users']);
const LITERALS = [];
for (const [value, label] of [
  [userInfo().username, 'the build user name'],
  [basename(homedir()), 'the home directory name'],
  [hostname().split('.')[0], 'the machine host name'],
]) {
  const v = String(value || '').toLowerCase();
  if (v.length >= 4 && !GENERIC.has(v)) LITERALS.push([v, label]);
}

const SKIP = /\.(png|jpe?g|gif|webp|ico|woff2?|ttf|eot|zip|gz|tgz)$/i;

const work = mkdtempSync(join(tmpdir(), 'leak-gate-'));
let failures = 0;

const report = (rel, text, index, label) => {
  failures++;
  console.error(`FAIL  ${rel}:${text.slice(0, index).split('\n').length}  contains ${label}`);
};

try {
  const out = execFileSync('npm', ['pack', '--pack-destination', work], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  const tarball = out.trim().split('\n').pop().trim();
  // Run from inside the directory and pass a bare filename: GNU tar reads a
  // leading "C:" as a remote host, so an absolute Windows path fails here.
  execFileSync('tar', ['-xzf', tarball], { cwd: work, encoding: 'utf8' });

  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) { walk(full); continue; }
      if (SKIP.test(entry)) continue;

      let text;
      try { text = readFileSync(full, 'utf8'); } catch { continue; }

      const rel = full.slice(work.length + 1).split(sep).join('/');
      const lower = text.toLowerCase();

      for (const [re, label] of PATTERNS) {
        const hit = text.match(re);
        if (hit) report(rel, text, hit.index, label);
      }
      for (const [needle, label] of LITERALS) {
        const at = lower.indexOf(needle);
        if (at !== -1) report(rel, text, at, label);
      }
    }
  };

  walk(join(work, 'package'));

  if (failures) {
    console.error(`\n${failures} leak${failures === 1 ? '' : 's'} found in the tarball. Not publishable.`);
    process.exit(1);
  }
  console.log('leak gate: tarball is clean');
} finally {
  rmSync(work, { recursive: true, force: true });
}
