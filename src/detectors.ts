/**
 * Built-in detectors.
 *
 * Two rules govern everything here.
 *
 * 1. Every quantifier is bounded. An unbounded `+` sitting next to an optional
 *    separator with an overlapping character class is how a detector becomes a
 *    denial-of-service vector — the original `email` pattern could hang for
 *    minutes on ordinary text.
 * 2. Patterns run against the *canonical* form of the text, so they can stay
 *    plain ASCII. Non-breaking spaces, fullwidth digits, zero-width characters
 *    and homoglyphs are folded away before a pattern ever sees them.
 */

import { canonicalize } from './canonical.js';
import type { Detector, PendingRegion } from './types.js';

/** Luhn checksum — what separates a real card number from any 16 digits. */
export function luhn(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Reject values that are obviously not a real secret.
 *
 * Documentation and templates are full of credential-shaped strings that carry
 * nothing: `AKIAXXXXXXXXXXXXXXXX`, `hf_xxxxx`, `<your-api-key>`,
 * `${aws_db_instance.default.password}`, `var.db_password`. Redacting those is
 * pure noise — it corrupts a code sample while protecting nobody.
 *
 * The run-of-four test is the workhorse: a random token essentially never
 * repeats one character four times, while every placeholder convention does.
 */
export function notPlaceholder(value: string): boolean {
  if (!notTemplateRef(value)) return false;
  const s = unquote(value);
  if (/(.)\1{3,}/.test(s)) return false; // xxxx, 0000, ----, ####
  if (/^(?:your|my|some|changeme|placeholder|redacted|insert)[-_ ]/i.test(s)) return false;
  return true;
}

function unquote(value: string): string {
  return value.replace(/^["'`]+|["'`]+$/g, '').trim();
}

/**
 * The weaker check used by the label-aware detector.
 *
 * When a field is literally called `Password`, the value after it is sensitive
 * whatever it looks like — that is the entire point of reading labels, and
 * applying the strict placeholder rules here would discard `TEST_PASSWORD_0001`
 * and every other synthetic record a user tests with. Only things that are not
 * values at all are rejected: empty strings and template references, where the
 * real secret lives somewhere else entirely.
 */
export function notTemplateRef(value: string): boolean {
  const s = unquote(value);
  if (s.length === 0) return false;
  if (/^\$\{|^\{\{|^<%|^%\(|^\$\(|^var\.|^process\.env|^os\.environ/i.test(s)) return false;
  if (/^<[^>]*>$/.test(s)) return false; // <your-key-here>
  if (isRedactionMarker(s)) return false;
  return true;
}

/**
 * Text that is already a redaction.
 *
 * Without this the library is not idempotent: `SSN: 123-45-6789` masks to
 * `SSN: [redacted:ssn]`, and a second pass sees the familiar `SSN:` label in
 * front of a value and redacts the mask itself. Running output through twice
 * happens in real pipelines — defence in depth, a retry, a proxy chaining two
 * filters — and it must be a no-op.
 *
 * Covers this library's own default mask, the common conventions, and the
 * bracketed-token style other tools emit (`[EMAIL]`, `[GIVENNAME_1]`).
 */
export function isRedactionMarker(value: string): boolean {
  const s = unquote(value);
  if (/^\[?\s*(?:redacted|masked|removed|hidden|filtered)\b/i.test(s)) return true;
  if (/^\[[A-Za-z][A-Za-z0-9_]*\]$/.test(s)) return true; // [EMAIL], [TITLE_1]
  if (/^[*•x_#-]{3,}$/i.test(s)) return true; // ***, xxx, ---, ###
  return false;
}

/** IBAN mod-97 checksum, so a random uppercase token is not called a bank account. */
export function ibanCheck(value: string): boolean {
  const s = value.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;

  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    const piece =
      code >= 65 && code <= 90 ? String(code - 55) : String.fromCharCode(code);
    for (let j = 0; j < piece.length; j++) {
      remainder = (remainder * 10 + (piece.charCodeAt(j) - 48)) % 97;
    }
  }
  return remainder === 1;
}

export const email: Detector = {
  name: 'email',
  // The domain part deliberately excludes `.` from the label class and bounds
  // the label count. That removes the overlapping-quantifier backtracking that
  // made the previous pattern quadratic.
  pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,4}[A-Za-z]{2,24}\b/g,
};

export const creditCard: Detector = {
  name: 'creditCard',
  pattern: /\b\d(?:[ -]?\d){12,18}\b/g,
  validate: luhn,
};

export const phone: Detector = {
  name: 'phone',
  pattern: new RegExp(
    [
      '\\+\\d{1,3}[ -]?(?:\\d[ -]?){6,14}\\d', // international, country code required
      '\\b\\d{3}[ -]\\d{3}[ -]\\d{4}\\b', // NANP with separators
      '\\(\\d{3}\\)[ -]?\\d{3}[ -]?\\d{4}\\b', // (555) 867-5309
    ].join('|'),
    'g',
  ),
};

export const ssn: Detector = {
  name: 'ssn',
  // Hyphenated form only. Allowing a space separator matched any `123 45 6789`
  // digit grouping — ordinary reference and batch numbers — at a measured 2 false
  // positives per 39 clean samples. Unicode dashes still work: they fold to "-".
  // Excludes the ranges the SSA never issues.
  pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
};

export const iban: Detector = {
  name: 'iban',
  pattern: /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,3})?\b/g,
  validate: ibanCheck,
};

/** Opt-in: network identifiers show up constantly in technical output. */
export const ipAddress: Detector = {
  name: 'ipAddress',
  pattern:
    /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
};

/**
 * Credentials. Prefix-anchored and bounded, covering the formats a modern stack
 * actually emits — a `.env` dump should not survive this.
 */
export const secret: Detector = {
  name: 'secret',
  pattern: new RegExp(
    [
      'sk-ant-[A-Za-z0-9_-]{20,200}', // Anthropic (before the bare sk- rule)
      'sk-proj-[A-Za-z0-9_-]{20,200}', // OpenAI project key
      'sk-[A-Za-z0-9_-]{20,200}', // OpenAI classic
      '[sprk]k_(?:live|test)_[A-Za-z0-9]{10,200}', // Stripe
      'gh[pousr]_[A-Za-z0-9]{36,255}', // GitHub
      'github_pat_[A-Za-z0-9_]{20,255}', // GitHub fine-grained
      'glpat-[A-Za-z0-9_-]{20,64}', // GitLab
      'AKIA[0-9A-Z]{16}', // AWS access key id
      'ASIA[0-9A-Z]{16}', // AWS temporary key id
      'AIza[0-9A-Za-z_-]{35}', // Google
      'ya29\\.[A-Za-z0-9_-]{20,200}', // Google OAuth
      'xox[baprs]-[A-Za-z0-9-]{10,255}', // Slack
      'SG\\.[A-Za-z0-9_-]{16,64}\\.[A-Za-z0-9_-]{16,64}', // SendGrid
      'npm_[A-Za-z0-9]{36}', // npm
      'dop_v1_[a-f0-9]{64}', // DigitalOcean
      'hf_(?=[A-Za-z0-9]{0,40}\d)[A-Za-z0-9]{30,40}', // Hugging Face user token (must contain a digit)
      'api_org_(?=[A-Za-z0-9]{0,40}\d)[A-Za-z0-9]{28,40}', // HF org token (must contain a digit)
      'sgp_[A-Za-z0-9_]{40,80}', // Sourcegraph
      'ntn_[A-Za-z0-9]{35,60}', // Notion
      'xapp-\\d-[A-Za-z0-9]{8,}-\\d{10,}-[a-f0-9]{40,}', // Slack app-level token
      'ops_[A-Za-z0-9+/=_-]{40,200}', // 1Password service account
      'EAA[A-Za-z0-9]{60,200}', // Facebook / Meta page access token
      'glsa_[A-Za-z0-9]{32,64}', // Grafana service account
      'dckr_pat_[A-Za-z0-9_-]{20,64}', // Docker Hub PAT
      'shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}', // Shopify
      'lin_api_[A-Za-z0-9]{40,64}', // Linear
      'rubygems_[a-f0-9]{48}', // RubyGems
      'pypi-[A-Za-z0-9_-]{50,}', // PyPI upload token
      'hooks\\.slack\\.com/services/[A-Za-z0-9/]{20,}', // Slack incoming webhook
      'discord(?:app)?\\.com/api/webhooks/\\d{15,}/[A-Za-z0-9_-]{50,}', // Discord webhook
      // JWT. Each segment was bounded at 1024, which silently stopped matching
      // any token whose payload carried more than that — a realistic size once
      // scopes, roles and permissions are in the claims, and the failure was a
      // miss rather than an error. 2048 per segment puts the longest matchable
      // token at roughly 6,150 characters, comfortably inside the 8192 default
      // retention ceiling so settlement can still hold a whole one.
      //
      // The quantifiers stay bounded and the separator is not in the character
      // class, so there is no ambiguity for a backtracking engine to explore.
      'eyJ[A-Za-z0-9_-]{10,2048}\\.[A-Za-z0-9_-]{10,2048}\\.[A-Za-z0-9_-]{10,2048}', // JWT
    ]
      // A leading word boundary on every alternative. Without it `ASIA[A-Z]{16}`
      // matched inside the sentence TODAYINASIAASACKOFRICEFELLOVER, and `hf_`
      // matched inside `desktop-rhf_SponsoredProducts`. Every prefix here starts
      // with a word character, so one boundary in front of the group covers all.
      .map((p) => '(?:' + p + ')')
      .join('|'),
    'g',
  ),
  validate: notPlaceholder,
};

// Applied after construction so the boundary wraps the whole alternation.
secret.pattern = new RegExp('\\b(?:' + secret.pattern.source + ')', 'g');

/**
 * PEM private keys, kept out of `secret` because they legitimately contain long
 * runs of the same character in their base64 body — exactly what the placeholder
 * check rejects everywhere else.
 *
 * The complete block is listed first so it wins over the bare header at the same
 * position; without it only the header was masked and the body streamed on.
 */
export const pemKey: Detector = {
  name: 'secret',
  pattern: new RegExp(
    [
      '-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\\s\\S]{0,16384}?-----END [A-Z ]{0,40}PRIVATE KEY-----',
      '-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----',
    ].join('|'),
    'g',
  ),
};

/**
 * Labels that make whatever follows them sensitive, whatever shape it has.
 *
 * Every other detector recognises the *value*. This one recognises the *field
 * name*, which is how a language model actually formats data — `Password: …`,
 * `Passport: …`, `Account Number: …`. A human reading `CVV:` knows the next
 * token is a secret even when it looks like nothing in particular; pattern
 * matching alone never will.
 *
 * Only the value is masked, never the label, so the output still reads as a
 * record. `address` excludes `IP address`, which is a separate opt-in concern.
 */
export const DEFAULT_SENSITIVE_LABELS = [
  // credentials
  'passwords?',
  'passwd',
  'passphrase',
  'api[ _-]?keys?',
  'secret[ _-]?keys?',
  'client[ _-]?secret',
  'private[ _-]?key',
  'access[ _-]?token',
  'refresh[ _-]?token',
  'bearer[ _-]?token',
  'session[ _-]?token',
  'auth[ _-]?token',
  // payment
  'cvv',
  'cvc',
  'card[ _-]?verification[ _-]?(?:code|value)',
  'card[ _-]?number',
  'credit[ _-]?card',
  'payment[ _-]?card',
  'account[ _-]?number',
  'bank[ _-]?account',
  'routing[ _-]?number',
  // government / identity
  'passport(?:[ _-]?(?:number|no\\.?))?',
  'national[ _-]?id(?:entity)?(?:[ _-]?number)?',
  'government[ _-]?id',
  'social[ _-]?security(?:[ _-]?number)?',
  'ssn',
  'tax[ _-]?id',
  'date[ _-]?of[ _-]?birth',
  'dob',
  // access control
  'security[ _-]?(?:code|question|answer)',
  'access[ _-]?code',
  'pin(?:[ _-]?code)?',
  '2fa[ _-]?code',
  'otp',
  'verification[ _-]?code',
  'recovery[ _-]?(?:code|email)',
  // contact fields — unambiguous as labels, where the value alone is not.
  // International phone shapes vary too much to catch safely by value
  // (`042.433 8800`, `60-56-85-91`, `+46 (0)8 928 571 38`), and widening the
  // value pattern enough to reach them also matches dates, ISBNs and IPv4.
  'phone(?:[ _-]?number)?',
  'telephone(?:[ _-]?number)?',
  'mobile(?:[ _-]?number)?',
  'cell(?:[ _-]?phone)?',
  'fax(?:[ _-]?number)?',
  'contact[ _-]?(?:number|phone)',
  'work[ _-]?phone',
  'home[ _-]?phone',
];

/**
 * Build a detector that recognises sensitive data by the *label in front of it*
 * rather than by the shape of the value.
 *
 * Every other detector reads the value. This one reads the field name, which is
 * how a language model actually formats a record — `Password: hunter2`,
 * `CVV: 419`, `DATABASE_PASSWORD=…`. A human reading `Passport:` knows the next
 * token is sensitive even when it looks like nothing in particular; pattern
 * matching on the value alone never will.
 *
 * Two details make it work under streaming:
 *
 *  - The label is part of the match and the value is a capture group, so
 *    settlement holds the label until the value is complete. A lookbehind cannot
 *    do this: the engine would release the label first, and the pattern could
 *    then never match the value that followed it.
 *  - A leading `[A-Za-z0-9_]*` lets `DATABASE_PASSWORD` and `ADMIN_PASSWORD`
 *    match `password`, since `_` is a word character and `\b` does not break there.
 *
 * Deliberately excluded from the defaults: bare `token`, `secret`, `key`, `id`,
 * `name` and `address`. They collide with ordinary code and prose
 * (`token: string`, `Product Name:`, `IP Address:`). Pass them via
 * `sensitiveLabels` if your context warrants it.
 */
export function labeledSensitiveDetector(extraLabels: string[] = []): Detector {
  const labels = [...DEFAULT_SENSITIVE_LABELS, ...extraLabels.map(escapeRegExp)];
  return {
    name: 'labeledSensitive',
    pattern: new RegExp(
      // The value is a single token, optionally quoted — not "the rest of the
      // line". A greedy value made `CVV: x and Password: y` swallow everything
      // after the first label, including the second field's own label.
      // Markdown emphasis is allowed to sit between the separator and the value.
      // Models format records as `**Date of Birth:** 1959-03-13`, and without
      // this the "value" captured was the `**`.
      // Bounded, not `*`. Unbounded, the engine retried this prefix from every
      // position in an unbroken run and consumed the rest of the buffer each
      // time, which is quadratic: 8,000 characters with no whitespace took
      // 870 ms in one scan while ordinary prose of the same length took 0.3 ms.
      // A model emitting one long token was enough to trigger it.
      //
      // 64 is far past any real prefix — `DATABASE_`, `PRODUCTION_POSTGRES_`
      // and the like are well under 30 — and it caps the work per position.
      '[A-Za-z0-9_]{0,64}(?:' +
        labels.join('|') +
        // The emphasis skip must not fire when the "emphasis" IS the value:
        // `Password: ***` would otherwise consume `**` and redact a lone `*`.
        // Bounded, not `*`. Three unbounded whitespace runs made the longest
      // possible match unbounded too, which is the one property the retention
      // ceiling has to be able to cover: if a pattern can outgrow the tail, the
      // engine meets its ceiling with a match still open and has to choose
      // between releasing a possible secret and refusing. 32 is well past any
      // real alignment in a config file or a key-value dump.
      ')\\*{0,2}_{0,2}[ \\t]{0,32}[:=][ \\t]{0,32}(?:(?:\\*{1,2}|_{1,2}|`)(?![*_`]))?[ \\t]{0,32}' +
        '("[^"\\r\\n]{0,200}"|\'[^\'\\r\\n]{0,200}\'|\\S{1,200})',
      'gi',
    ),
    maskGroup: 1,
    validate: notTemplateRef,
  };
}

/** The default label-aware detector. */
export const labeledSensitive: Detector = labeledSensitiveDetector();

/** The default detector set. `ipAddress` is deliberately opt-in. */
export const builtinDetectors: Detector[] = [
  email,
  creditCard,
  phone,
  ssn,
  iban,
  secret,
  pemKey,
  labeledSensitive,
];

/**
 * A PEM private key block. The body is unremarkable base64 that no pattern can
 * safely claim on its own, so the opener alone makes everything after it unsafe
 * until the closer arrives. Without this, only the header was masked and the key
 * itself streamed to the reader in cleartext.
 */
export const pemPrivateKey: PendingRegion = {
  name: 'secret',
  openPrefix: '-----BEGIN ',
  open: /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/g,
  // Any END closes the region. A certificate block therefore closes cleanly and
  // passes through untouched, while an unterminated block is held and masked.
  close: /-----END [A-Z ]{0,40}-----/g,
};

export const defaultPendingRegions: PendingRegion[] = [pemPrivateKey];

/** Escape a literal string so it can be embedded in a RegExp. */
function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Scripts written without spaces between words. A word-boundary assertion is
 * meaningless inside them, so those entries match as plain substrings.
 */
const UNSPACED_SCRIPT =
  /[぀-ヿ㐀-䶿一-鿿豈-﫿가-힯฀-๿]/u;

/**
 * Build a detector from literal words or phrases, matched case-insensitively.
 *
 * Boundaries use Unicode property escapes rather than `\b`, which is ASCII-only —
 * with `\b`, a Cyrillic, Greek, Arabic or Hebrew block list silently never
 * matched anything at all.
 */
export function bannedWordsDetector(words: string[]): Detector {
  const alternatives: string[] = [];

  for (const raw of words) {
    if (!raw) continue;
    // Fold the word the same way the text is folded, or the two planes disagree:
    // a Cyrillic block-list entry would be compared against its own homoglyph-
    // folded text and never match. Folding both sides also means an attacker
    // cannot evade the list by spelling the word with look-alike characters.
    const word = canonicalize(raw).text || raw;
    const body = escapeRegExp(word);
    const first = word.charAt(0);
    const last = word.charAt(word.length - 1);

    const openBoundary =
      UNSPACED_SCRIPT.test(first) || !/[\p{L}\p{N}_]/u.test(first)
        ? ''
        : '(?<![\\p{L}\\p{N}_])';
    const closeBoundary =
      UNSPACED_SCRIPT.test(last) || !/[\p{L}\p{N}_]/u.test(last)
        ? ''
        : '(?![\\p{L}\\p{N}_])';

    alternatives.push(openBoundary + body + closeBoundary);
  }

  const source = alternatives.length > 0 ? alternatives.join('|') : '(?!)';
  return { name: 'bannedWord', pattern: new RegExp(source, 'giu') };
}
