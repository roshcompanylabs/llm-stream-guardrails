# Changelog

All notable changes to this project. Versions follow [semver](https://semver.org/).

## 0.7.6

Raised on a public thread, and the criticism landed: *a bounded tail that
releases on overflow is a fixed window wearing a better name, because an
adversary who knows the threshold can cross it.*

That was true here for one configuration. `maxRetention` was floored at 256,
while the longest pattern could match 6,149 characters, so a caller who set a
low ceiling got exactly the behaviour being described — the engine met its
limit with a match still open and released.

### Fixed

- **`maxRetention` is floored at the longest bounded pattern, not at 256.**
  The unsafe configuration is now unreachable rather than documented. A ceiling
  a match could outgrow cannot be requested.

- **Two unbounded quantifiers made the longest possible match unbounded.** The
  label detector allowed unlimited whitespace on both sides of the separator,
  so no ceiling could have covered it. Bounded at 32, which is well past any
  real alignment in a config file. The longest label match is 1,132 characters
  now, down from no limit at all.

### Unchanged, and worth stating

The genuinely unbounded case is a PEM block, and it is not a pattern — it is a
pending region. No ceiling can cover it, so the overflow decision is made
explicitly and it fails closed: an opener with no closer masks rather than
releases, at any ceiling. That is now asserted rather than assumed.

## 0.7.5

Both of these came out of a question about what a bounded buffer must do when
a variable-length pattern is still open at the ceiling. Chasing it found that
two of the patterns had the wrong bound, in opposite directions.

### Fixed

- **An unbroken run made the scan quadratic.** The label detector opened with
  an unbounded `[A-Za-z0-9_]*`, so `DATABASE_PASSWORD` would match on its
  prefix. On text with no whitespace the engine retried that from every
  position and consumed the rest of the buffer each time. One scan of 8,000
  unbroken characters took **870 ms**; ordinary prose of the same length took
  0.3 ms. A model emitting a single long token was enough to reach it.

  The prefix is bounded at 64 now, which is far past any real one —
  `PRODUCTION_POSTGRES_PRIMARY_PASSWORD` has a 28-character prefix. Same 8,000
  characters: **15.9 ms**, and the cost is linear again.

- **A JWT with a payload over 1,024 characters was not detected.** Each segment
  was bounded at 1,024 and the failure was a miss rather than an error, so
  nothing said so. Claims carrying scopes or role lists pass that size in
  ordinary use. Bounded at 2,048 per segment now, which puts the longest
  matchable token near 6,150 characters — inside the 8,192 default retention
  ceiling, so settlement can still hold a whole one.

### Added

- A test asserting one scan of 16,000 unbroken characters finishes in under a
  second. The old behaviour was roughly 3.5 s at that size.
- A test asserting JWTs with 40, 600, 1,400 and 2,000-character segments are
  caught, in batch and at three chunk sizes.

## 0.7.4

### Fixed

- **The cut guard only recognised Latin combining marks.** It enumerated
  U+0300–U+036F, so Arabic harakat, Hebrew niqqud, Devanagari matras, Thai
  vowel signs and Cyrillic combining marks — 1,238 code points — were not
  treated as marks, and a cut could land between a letter and the mark that
  belongs to it. It now tests the Unicode Mark property.

  For Latin the cost of that is a frame of a bare vowel before the accent
  lands. For Devanagari and Thai a matra is not decoration, and the consonant
  alone renders as a different syllable until the rest arrives.

  Prompted by a question on the write-up: does the surrogate-pair fix hold
  trailing combining marks too?

### Added

- A test asserting the filter never splits a grapheme cluster that arrived
  intact — across Arabic, Devanagari, Hebrew, Thai, Latin combining marks, a
  ZWJ emoji sequence and a variation selector, at five chunk sizes. A boundary
  counts only if the filter created it and a mark sits on the far side;
  boundaries the input already had are not the filter's doing.

  Measured before the change, 0 of 40 combinations introduced a split, because
  where a base and its mark arrive in different input chunks the filter passes
  that through unchanged and frequently coalesces rather than splits. So the
  fix above is defensive at the cut points rather than a leak repair, and the
  test says which of the two it is.

- `npm run latency`, the time-to-first-token benchmark.

## 0.7.3

### Fixed

- **Text in a language written without spaces did not stream.** The settlement
  walk crossed every character above code 32, because an unbroken run might be a
  long secret such as a JWT. Latin prose is full of spaces and settled
  constantly. Japanese, Chinese, Korean and Thai prose has none, so an entire
  paragraph was one unbroken token, nothing ever settled, and the engine held
  the whole text block and released it at flush. Nothing leaked and nothing was
  lost — it simply stopped being a streaming filter for those languages.

  No built-in detector can match an ideograph; every one of them is ASCII. So
  the walk now settles at a character no detector can match, the way it settles
  at a space. Banned words can be non-ASCII, so crossing is still allowed, but
  bounded by the length of the longest non-ASCII banned word rather than
  unbounded — and zero when there are none, which is the default.

  A 680-character Japanese reply now holds 0 characters and emits from the first
  one, against 680 held and nothing before flush in 0.7.2. English is unchanged
  at about 20.

  Found by measuring rather than by a test: two independent harnesses disagreed
  about the worst-case hold, and chasing the difference found that there was no
  worst case.

### Changed

- The README latency figures now say they were measured on text written with
  spaces, and give the space-less case separately. They read as a general claim
  about the engine while measuring only the case that worked.

## 0.7.2

### Fixed

- **The author link on the npm page pointed at a string that is not a URL.** npm
  normalises an author object into `name <email> (url)`, so the parentheses in
  `Redouane (ROSH Company Labs)` were read as the url delimiter: npm took
  `ROSH Company Labs` as the url and discarded the real one. The name no longer
  contains parentheses.
- Removed `RELEASE_NOTES_TMP.md`, a scratch file from cutting the 0.7.1 release
  that was committed by accident. It contained nothing but three shell lines.

No change to the library itself. 0.7.1 and 0.7.2 are identical in behaviour.

## 0.7.1

A leak found by making the equivalence test tell the truth.

### Fixed

- **A space-separated IBAN was released in cleartext when it arrived in small
  chunks.** The walk that decides how far back a match could still grow
  abandoned the grouped-value hypothesis the instant it met a letter — a
  shortcut that exists because `sk-...456 ` reads like a digit group when you
  only look at the tail. An IBAN's groups are alphanumeric (`GB82 WEST 1234`),
  so the walk hit `WEST`, concluded it had been wrong, and settled the account
  number as safe text. A single-chunk call masked it; any chunking that split it
  did not. Streamed and batch output disagreed, which is the one thing this
  library says cannot happen. The walk now carries an IBAN-shaped hypothesis
  alongside the digits-only one, bounded by the longest IBAN any country issues.
- **`action: 'block'` discarded the safe text preceding the detection.** A
  stream had already delivered that prefix and cannot take it back, so a batch
  call and a streamed call returned different things for the same input. The
  prefix is text the engine had already settled as safe; it is now released
  before the stream terminates, in both paths.
- **`Policy.detectors` documented a default set that was never the default.**
  The published types told every TypeScript user that `ipAddress` was on by
  default. It is not, deliberately, and `labeledSensitive` and PEM key blocks
  were missing from the list.

### Changed

- The equivalence test now exercises policies and inputs that actually fire.
  Its banned-word policy was being asserted against text containing none of the
  banned words, and `action: 'block'`, custom mask functions, `sensitiveLabels`
  and PEM blocks were not covered at all. Both bugs above were invisible until
  this changed; neither was introduced by it.
- README corrections: the Web Streams example piped bytes into a string
  transform, which would have quietly corrupted output rather than failing; the
  detector table advertised Twilio, which was removed in 0.6, and omitted about
  a dozen families that are implemented; the integration claim now says what is
  true, that the OpenAI and Anthropic SDKs need a one-line map; the corpora
  command does not claim to reproduce a table it cannot download; and the
  54-sample regression figures carry their denominators instead of reading as
  two independent 100% scores.

### Added

- CI on Node 18, 20 and 22, running the suite and the precision gate, plus a
  leak gate that unpacks the tarball and fails the build on any build-machine
  path, user name or host name.
- `SECURITY.md`, `CONTRIBUTING.md` and issue templates, so a detector bypass
  has somewhere private to go instead of a public issue.

## 0.7.0

Idempotence, plus the adversarial harness that found the bug.

### Fixed

- **The library was not idempotent.** `SSN: 123-45-6789` masked to
  `SSN: [redacted:ssn]`, and a second pass saw the familiar `SSN:` label in front
  of a value and redacted the mask itself. Running output through twice happens in
  real pipelines — a retry, a proxy chaining two filters, defence in depth — and
  it must be a no-op. Redaction markers are now recognised and left alone,
  including those emitted by other tools (`[EMAIL]`, `[GIVENNAME_1]`, `***`).
- `Password: ***` redacted a lone `*`, because the markdown-emphasis skip
  consumed the first two asterisks before the value was read.

### Added

- `bench/adversarial.mjs` (`npm run adversarial`) — 18 methods, 22,897 checks:
  exhaustive single-split at every boundary, Unicode mutation of real corpus
  values, cross-API agreement, idempotence, long concatenated documents,
  complexity/throughput, chaotic chunk patterns, and non-Latin scripts.
- `isRedactionMarker` is exported for callers with a custom mask.

## 0.6.1

### Fixed

- A credential prefix inside a longer word was treated as a credential:
  `ASIA` + 16 uppercase letters matched inside the sentence
  `TODAYINASIAASACKOFRICEFELLOVER`, and `hf_` matched inside an Objective-C
  identifier. Every prefix now requires a word boundary in front.

## 0.6.0

Scored against third-party corpora for the first time, which found three engine
bugs that self-written tests structurally could not see.

### Fixed

- **Parentheses were not treated as token characters**, so the engine released
  `(579)` of `(579)888-3058` before the rest arrived and the pattern could never
  match. Any non-whitespace character now continues a token run.
- **Multi-word labels were split.** `Fly access token:` released `Fly access `
  and left `token:`, which matches nothing. The same bug hit `Date of Birth:`
  across 636 Gretel documents.
- **Long values were truncated by the lookback window.** A JWT runs to hundreds
  of characters; an unbroken non-whitespace run is now bounded by the real
  retention ceiling rather than the speculative window.
- Aligned config (`password       = "x"`) exhausted the label budget one space at
  a time; whitespace runs are now crossed whole.
- Markdown-formatted records (`**Date of Birth:** 1959-03-13`) captured the `**`
  as the value.

### Added

- Placeholder rejection: `AKIAXXXXXXXXXXXXXXXX`, `hf_xxxxx`, `<your-api-key>`,
  `${var.password}` are no longer redacted. Deliberately asymmetric — strict when
  matching by value shape, weak when matching by field label, because a field
  called `Password` makes its value sensitive whatever it looks like.
- ~17 more credential families (Hugging Face, Sourcegraph, Notion, Shopify,
  Grafana, Docker Hub, Linear, RubyGems, PyPI, Slack and Discord webhooks).
- Contact-field labels (`Phone`, `Mobile`, `Fax`, `Contact Number`). International
  phone shapes vary too much to catch safely by value; the label is unambiguous.
- `bench/corpora.mjs` (`npm run corpora`) — scores against Presidio, Gretel,
  ai4privacy and the gitleaks rule corpus.

## 0.5.0

### Added

- Label-aware detection. Every other detector reads the value; this one reads the
  field name, which is how a model actually formats a record. A lookbehind cannot
  work here — the engine releases the label before the value arrives — so the
  label is part of the match and only the value is masked, via `maskGroup`.
- `sensitiveLabels` policy option for domain-specific records.

## 0.4.0

### Fixed

- Measured precision for the first time and found two real defects: a Twilio SID
  rule that flagged any uppercase hex hash (and protected nothing — an Account SID
  is a public identifier, not a credential), and a space-separated SSN pattern
  that read `Reference 100 20 3000` as a social security number.

### Added

- `bench/precision.mjs` (`npm run bench`) and a precision guard in the test suite.

## 0.2.0

Engine rewrite after an adversarial review reproduced 35 defects in 0.1.0,
15 of them high severity.

### Fixed

- PEM private key bodies streamed in cleartext; only the header was masked.
- Variable-length secrets were masked at the chunk boundary with the remainder
  emitted in clear.
- Non-breaking spaces and en-dashes defeated the credit-card detector entirely.
- Emoji were corrupted by cutting the buffer mid-surrogate-pair.
- Non-ASCII block lists were silently inert, because `\b` is ASCII-only.
- Polynomial backtracking in the email pattern could hang the process.

### Changed

- Settlement engine: never act on text that is not provably finished, never emit
  text not scanned in final form. The raw buffer stays pristine; masking happens
  only on output.
- The `holdBack` setting is gone. No configuration can make the engine leak.

## 0.1.0

Initial release.
