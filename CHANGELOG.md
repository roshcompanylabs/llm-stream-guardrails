# Changelog

All notable changes to this project. Versions follow [semver](https://semver.org/).

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
