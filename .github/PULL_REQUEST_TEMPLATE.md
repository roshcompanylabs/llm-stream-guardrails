## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem it solves. Link an issue if there is one. -->

## Checklist

- [ ] `npm test` passes
- [ ] A detector change adds a case to `bench/corpus.mjs` — a sensitive one to `SENSITIVE`,
      or a harmless one to `CLEAN` so a future regression fails the build
- [ ] No real secret, credential or personal value appears in the diff, the tests or the
      commit message — use structurally identical fakes
- [ ] No absolute filesystem path, machine name or username appears anywhere in the diff
