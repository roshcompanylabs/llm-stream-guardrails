# Contributing

Contributions are welcome. The rules below exist because this library filters
sensitive data, which makes a few ordinary habits dangerous here.

## Never put a real value in the repository

No real credential, card number, key, phone number or personal address — not in a
test, not in a benchmark, not in an issue, not in a commit message. Use a
structurally identical fake. `4111 1111 1111 1111` is a card number that passes
Luhn and belongs to nobody; that is the pattern to follow.

The same goes for your machine. No absolute filesystem path, no username, no
hostname anywhere in a diff. A tool that exists to prevent leaks cannot ship one.

## Before opening a pull request

```bash
npm install
npm test        # 79 tests
npm run bench   # precision gate: 0 false positives required
```

Both must pass. The precision gate is a build gate, not a report — a change that
introduces a single false positive fails it.

## Changing a detector

A detector change needs a case in `bench/corpus.mjs`:

- catching something new → add it to `SENSITIVE` with the detector name
- fixing a false positive → add the harmless value to `CLEAN`

That file is read by both the benchmark and `test/precision.test.js`, so an accepted
case becomes a permanent regression test. This is how the two real defects found so
far — a rule that flagged any uppercase hex hash, and a pattern that read
`Reference 100 20 3000` as a social security number — are kept dead.

Precision matters more than recall here. A filter that destroys a legitimate order
number in a live support chat is worse than no filter at all, because people stop
trusting it and turn it off.

## Changing the engine

The core invariant is in `src/core.ts`: never act on a match that could still grow,
and never emit text that has not been scanned in final form. The equivalence test
enforces the visible consequence — streamed output must be byte-identical to
filtering the whole string at once, at every chunk size.

If you are adding a fixed-size buffer or a `holdBack` option, stop. That was the
original design and it leaked: a secret still being written gets masked in the part
you hold and streamed in cleartext for the rest.

## Found a way past a detector?

That is a security report, not a pull request. See [SECURITY.md](SECURITY.md) —
report it privately first.

## Style

Match the surrounding code. No new runtime dependencies; the zero-dependency
guarantee is part of what the package offers.
