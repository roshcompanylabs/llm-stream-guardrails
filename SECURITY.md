# Security Policy

`llm-stream-guardrails` exists to stop sensitive values from reaching a user's screen.
A way around it is not an edge case — it is the bug that matters most here.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.7.x | Yes |
| < 0.7 | No |

Fixes land on the latest minor. There is no long-term support branch.

## Reporting a vulnerability

**Please do not open a public issue for anything that lets data through.**

Use GitHub's private reporting — the **Report a vulnerability** button under the
repository's **Security** tab. It is private between you and the maintainers, and it
keeps the details off a public thread while a fix is prepared.

If that is unavailable to you, write to **roshcompanylabs@gmail.com** instead.

Reports are read and answered on a best-effort basis by a small team. No response
window is promised here, because a promise that cannot always be kept is worse than
none. You will get an acknowledgement, and you will be told what is being done.

## What is worth reporting

A **detector bypass** is in scope and is the most valuable report you can send: any
input that puts a real credential, card number, key or other sensitive value in front
of the reader when the policy should have masked it. Particularly:

- A value split across chunk boundaries that survives the settlement logic
- Unicode folding, invisible characters or homoglyphs that defeat a detector
- A pattern whose tail keeps growing and is released before it is complete
- Any case where streamed output differs from filtering the whole string at once
- A policy or input that makes the engine hold text past its retention ceiling

Please include: the input, the policy, the chunking, what you expected, what happened.
Redact the real value — a structurally identical fake is enough to reproduce it.

## What is not a vulnerability

- **A missed format the library never claimed to detect.** This is a pattern and
  label detector, not a named-entity recogniser. Names, addresses and free-text
  disclosures are out of scope by design, and saying so is not a bypass.
- **A false positive.** Annoying, and worth a normal issue — but it fails closed.
- **Vulnerabilities in your own model, provider or application.** This library
  filters a stream; it does not secure what produced it.
- **A denial of service from an input you constructed and fed to yourself.**

## Disclosure

Coordinated disclosure, please: let a fix ship before publishing details. If you want
credit, say so and you will be named in the advisory and the release notes. If you
would rather not be, that is fine too.
