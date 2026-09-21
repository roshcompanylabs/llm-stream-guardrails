# llm-stream-guardrails — LLM guardrails for streaming responses

[![CI](https://github.com/roshcompanylabs/llm-stream-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/roshcompanylabs/llm-stream-guardrails/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/llm-stream-guardrails)](https://www.npmjs.com/package/llm-stream-guardrails)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Redact PII and secrets from an LLM stream without buffering the response.**

Most guardrails filter after the fact: you buffer the whole reply, then scan it.
This one filters in flight — PII, API keys, private keys and banned content —
and proves the result is identical to buffering. Zero runtime dependencies.

It takes any async iterable of strings: the Vercel AI SDK's `textStream` goes in
directly, and the OpenAI and Anthropic SDKs need a one-line map to pull the text
out of their event objects (shown [below](#with-the-openai-and-anthropic-sdks)).

```bash
npm install llm-stream-guardrails
```

ESM only (`import`, Node 18+). There is no CommonJS build.

```ts
import { sieve } from 'llm-stream-guardrails';

for await (const token of sieve(result.textStream)) {
  process.stdout.write(token);   // secrets already gone
}
```

---

## Why this exists

Filtering a streamed response is a known unsolved corner, and the vendors say so
in their own documentation:

- **OpenAI** — their guardrails guide notes that with streaming enabled,
  violative content may briefly appear before a guardrail trigger fires.
  ([openai-guardrails-js](https://github.com/openai/openai-guardrails-js))
- **Vercel AI SDK** — the middleware docs describe streaming guardrails as hard
  precisely because the full content isn't known until the stream finishes, and
  the `wrapStream` guardrail example is left unimplemented.
  ([ai-sdk middleware docs](https://ai-sdk.dev/docs/ai-sdk-core/middleware))
- **NVIDIA NeMo Guardrails** — documents that objectionable text may already have
  reached the user, and leaves handling that to the caller.
- **AWS Bedrock Guardrails** — does not mask sensitive information in
  asynchronous/streaming mode.

The usual workaround is to stop streaming: buffer the whole reply, filter it,
then send it. That trades away the only reason to stream in the first place.

llm-stream-guardrails takes the other path — it filters in flight, and proves the result is
the same as if you had buffered.

---

## The guarantee

> For **any** input, **any** policy and **any** chunking, the streamed output is
> **byte-identical** to filtering the whole string at once — and every emitted
> chunk is independently well-formed.

That is the whole product, and it is enforced by a property test across every
input × policy × chunk-size combination in CI, not by a promise in a README.

## The problem

Filtering a *finished* LLM response is easy. Filtering a **streaming** one is not.

Text arrives in chunks, and a secret does not respect chunk boundaries:

```
chunk 1:  "...your card is 4111 11"
chunk 2:  "11 1111 1111, charge it."
```

Scan each chunk alone and the card sails through to the user's screen. By the
time you have the full response, they have already read it.

Worse, the obvious fix — buffer a bit, then redact what you find — is subtly
broken. If a secret is still being written when you act on it, you mask the part
you have and stream the rest in cleartext.

## How it works

**Settlement.** The engine never acts on text that is not provably finished, and
never emits text it has not scanned in final form.

- The raw buffer stays **pristine** — masking happens only on the way out.
- Detection runs against a **canonical view** of the text, so a non-breaking
  space, a fullwidth digit, a zero-width character or a homoglyph cannot smuggle
  a value past an ASCII pattern.
- Each chunk computes a **settlement point**: the furthest position no match
  could still grow past. A match touching the end of the buffer is never final.
- On benign prose the engine holds back **a handful of characters**, not a fixed
  window — so there is no latency dial to tune and no way to configure a leak.

---

## Usage

### With any AI SDK text stream

```ts
import { sieve } from 'llm-stream-guardrails';

for await (const token of sieve(result.textStream)) {
  process.stdout.write(token);
}
```

### In a Web Streams pipeline (edge, browsers, `Response` bodies)

`createSieveTransform()` is a `TransformStream<string, string>`. A `Response`
body is a stream of bytes, so decode on the way in and encode on the way out:

```ts
import { createSieveTransform } from 'llm-stream-guardrails';

return new Response(
  upstream
    .pipeThrough(new TextDecoderStream())
    .pipeThrough(createSieveTransform())
    .pipeThrough(new TextEncoderStream()),
);
```

Piping a byte stream straight in would not throw — it would stringify each
chunk and quietly ruin the output, so the two wrappers are not optional.

### With the OpenAI and Anthropic SDKs

Both yield event objects rather than strings. Map the text out first:

```ts
async function* text(stream) {
  for await (const event of stream) {
    // OpenAI chat completions
    const delta = event.choices?.[0]?.delta?.content;
    if (delta) yield delta;
    // Anthropic messages
    if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
      yield event.delta.text;
    }
  }
}

for await (const token of sieve(text(stream))) process.stdout.write(token);
```

### On a complete string

```ts
import { sieveText } from 'llm-stream-guardrails';

const { text, detections } = sieveText('mail me at a@b.co');
// text       → 'mail me at [redacted:email]'
// detections → [{ detector: 'email', match: 'a@b.co', index: 11, length: 6 }]
```

`detections[i].index` and `.length` locate the match in the **original input**,
and `.match` is always the **complete** value — never a truncated prefix.

---

## Policy

```ts
sieve(stream, {
  action: 'mask',                 // 'mask' | 'block' | 'report'
  bannedWords: ['classified'],
  mask: (d) => `[${d.detector} removed]`,
  onDetect: (d) => logger.warn(d),
});
```

| Option | Default | Meaning |
| --- | --- | --- |
| `action` | `'mask'` | `mask` replaces the match · `block` kills the stream · `report` passes text through but fires `onDetect` |
| `detectors` | built-ins | Override the detector set entirely |
| `bannedWords` | `[]` | Literal words, case-insensitive, Unicode-aware |
| `mask` | `` `[redacted:${detector}]` `` | String, or a function of the detection |
| `normalize` | `true` | Fold Unicode look-alikes before detecting. Turning this off makes detectors trivially evadable |
| `maxRetention` | `8192` | Hard ceiling on held text. You should not need this |
| `onDetect` | — | Fires **exactly once** per detection, with the complete value |

There is deliberately **no buffer-size setting**. The engine works out what it
must hold; no configuration can make it leak.

---

## Built-in detectors

| Detector | Catches | Precision measure |
| --- | --- | --- |
| `email` | Standard addresses incl. `+tags`, subdomains | Bounded quantifiers — no catastrophic backtracking |
| `creditCard` | 13–19 digits, any Unicode space or dash separator | **Luhn checksum** |
| `phone` | International (`+cc`) and NANP with separators | Bare digit runs ignored |
| `ssn` | US SSNs in separated form | Excludes never-issued ranges |
| `iban` | International bank accounts | **mod-97 checksum** |
| `secret` | 35 credential shapes: OpenAI, Anthropic, Stripe, GitHub (PATs and fine-grained), GitLab, AWS, Google, Slack (tokens and webhooks), Discord webhooks, SendGrid, npm, DigitalOcean, Hugging Face, Notion, Linear, Grafana, Docker, Shopify, Meta, Sourcegraph, RubyGems, PyPI, JWTs, **and complete PEM private key blocks** | Prefix-anchored and bounded |

`ipAddress` is available but **opt-in** — IPs appear constantly in technical
output and redacting them by default would be noise.

### Label-aware detection

Every detector above reads the **value**. `labeledSensitive` reads the **field
name**, which is how a language model actually formats a record:

```
Password: TEST_PASSWORD_0001      ->  Password: [redacted:labeledSensitive]
CVV: CVV-TEST-001                 ->  CVV: [redacted:labeledSensitive]
DATABASE_PASSWORD=hunter2         ->  DATABASE_PASSWORD=[redacted:labeledSensitive]
```

None of those values looks like anything in particular — no pattern on the value
could ever catch them. A human reading `Passport:` knows the next token is
sensitive; this detector encodes that. Only the value is masked, so the record
stays readable.

Add your own labels for domain-specific records:

```ts
sieve(stream, { sensitiveLabels: ['patient id', 'insurance id', 'salary'] });
```

Bare `token`, `secret`, `key`, `name` and `address` are deliberately **not** in
the defaults — they collide with ordinary code and prose (`token: string`,
`Product Name:`, `IP Address:`). Add them explicitly if your context warrants it.

### Measured against third-party corpora

Scored on **8,795 samples nobody here wrote**, each run twice — whole, then
replayed in random 1–7 character chunks:

| Corpus | Licence | Samples | In-scope recall | False positives | Stream failures |
| --- | --- | ---: | ---: | ---: | ---: |
| Presidio `synth_dataset_v2` | MIT | 1,500 | 80.9% | **0** | **0** |
| Gretel `pii-masking-en-v1` test | Apache-2.0 | 5,000 | 74.2% | — | **0** |
| ai4privacy OpenPII-1M slice | CC-BY-4.0 | 2,000 | 51.0% | — | **0** |
| gitleaks rule corpus | MIT | 295 | 47.1% | 72 | **0** |

These four datasets are **not** vendored here — they carry their own licences,
and the gitleaks fixtures are secret-shaped strings that belong in nobody's
repository. Fetch them yourself, point `CORPORA_DIR` at them, then:

```bash
CORPORA_DIR=/path/to/corpora npm run corpora
```

Without that directory the command exits and reports what is missing rather than
producing a number. The table above is therefore evidence you can reproduce, not
evidence you can re-run in one command.

**Streamed output was byte-identical to batch output on all 8,795 samples.** That
column is the one worth reading: it is the library's actual claim, and no public
benchmark measures it, so the harness derives it by re-chunking every sample.

Read the recall numbers honestly:

- **In-scope only.** Names, addresses, cities, dates and organisations are not
  attempted — 30,845 such spans were skipped, never counted as wins or losses.
  This is a format detector, not a named-entity recogniser.
- **ai4privacy is low for a reason.** Its synthetic card numbers do not satisfy
  Luhn and its national IDs are bare non-US digit runs. Catching them means
  dropping the checksum that keeps false positives at zero. That trade was
  declined; `sensitiveLabels` is the supported way to catch them by field name.
- **gitleaks measures breadth.** It defines 225 credential families; this library
  implements about 30 of the most common. 47.1% is coverage, not correctness.
- Of the 72 gitleaks "false positives", most are near-miss strings that a
  *scanner* is right to ignore and a *redactor* is arguably right to mask —
  different threat models. Genuine placeholders (`AKIAXXXXXXXXXXXXXXXX`,
  `${var.password}`) are now rejected outright.

### Regression corpus (written here)

False positives are why redaction libraries get uninstalled, so precision is a
build gate rather than a claim. Run it yourself:

```bash
npm run bench
```

| Metric | Result |
| --- | --- |
| Clean samples (must not be touched) | 39 |
| False positives | 0 / 39 |
| Sensitive samples (must be caught) | 15 |
| Caught | 15 / 15 |

This corpus was written here, and 54 samples is a regression gate, not a
measurement. The third-party numbers in the table above — 47% to 81% recall on
8,795 samples nobody here wrote — are the honest estimate of how this performs on
text it has not seen.

The clean corpus is deliberately adversarial — UUIDs, git SHAs, hex colours,
version strings, order and batch numbers, tracking numbers, ISBNs, dates, and
near-miss values such as a 16-digit number that fails Luhn. It found and killed
two real defects:

- A Twilio SID rule flagged any uppercase hex hash. It also protected nothing —
  an Account SID is a public identifier, not a credential. **Removed.**

  GitHub's own push protection confirmed the collision the hard way: it blocked
  the first push of this repository, flagging the *test fixture* — a git SHA —
  as a Twilio Account String Identifier. The fixture is now assembled at runtime
  so the literal never appears in the source. Same string, same test, no false
  alarm — which is the whole point being made.
- A space-separated SSN pattern turned `Reference 100 20 3000` into a social
  security number. **Hyphenated form only now.**

Both are locked in `test/precision.test.js`, so a regression fails the build.

### Fail-closed containment

A PEM private key body is unremarkable base64 that no pattern can safely claim.
So the engine holds from the `-----BEGIN ` marker — even a **partial** one that
has not finished arriving — and if the block never closes, it **masks rather
than releases**. That run is exactly where a key would be.

---

## Known limits

Honest, tested, and encoded in the suite rather than hidden:

- **Word-boundary anchoring.** A pattern glued directly to word characters
  (`x4111111111111111x`) is not matched. This buys precision — digits inside a
  hash or an order reference are left alone.
- **Pattern-based, not semantic.** It catches *formats*. It does not understand
  that "my mother's maiden name is Rodriguez" is sensitive.
- **Canonicalisation is per-character,** not full NFKC, so the index map back to
  the raw text stays exact. Exotic compatibility forms are not folded.

---

## Testing

```bash
npm test
```

The suite covers the equivalence property across every input × policy × chunking, chunk
well-formedness under independent encoding, plus a regression test for every
high-severity finding from an adversarial review — Unicode separator evasion,
zero-width hiding, variable-length secret tail leaks, PEM body leaks, non-ASCII
block lists, ReDoS, and surrogate-pair corruption.

---

## Support and contact

| | |
| --- | --- |
| **A bug, or a false positive** | [Open an issue](https://github.com/roshcompanylabs/llm-stream-guardrails/issues) |
| **A detector bypass — a value that got through** | [Report it privately](https://github.com/roshcompanylabs/llm-stream-guardrails/security/advisories/new). Please do not open a public issue for this. See [SECURITY.md](SECURITY.md). |
| **Commercial or licensing enquiries** | roshcompanylabs@gmail.com |

Bypass reports are the most useful thing you can send. Every accepted case is added to
the corpus in `bench/corpus.mjs`, so the build fails if it ever regresses.

---

## License

MIT © Redouane (ROSH Company Labs)
