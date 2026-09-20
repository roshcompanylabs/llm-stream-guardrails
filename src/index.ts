/**
 * llm-stream-guardrails — filter PII, secrets and banned content out of an LLM stream
 * before it reaches the reader.
 *
 * The guarantee: for any input, any policy and any chunking, the streamed output
 * is byte-identical to what you would get filtering the whole string at once,
 * and every emitted chunk is independently well-formed.
 *
 * @packageDocumentation
 */

import { Sieve, resolvePolicy, scanCanonical } from './core.js';
import type { Detection, Policy } from './types.js';

export { Sieve, resolvePolicy, scanCanonical };
export { canonicalize } from './canonical.js';
export * from './types.js';
export {
  builtinDetectors,
  defaultPendingRegions,
  bannedWordsDetector,
  email,
  creditCard,
  phone,
  ssn,
  iban,
  ipAddress,
  secret,
  pemKey,
  notPlaceholder,
  notTemplateRef,
  isRedactionMarker,
  labeledSensitive,
  labeledSensitiveDetector,
  DEFAULT_SENSITIVE_LABELS,
  pemPrivateKey,
  luhn,
  ibanCheck,
} from './detectors.js';

/** Outcome of sieving a complete string. */
export interface SieveTextResult {
  /** The cleaned text. Empty if the policy blocked it. */
  text: string;
  /** Everything that was found, each with its complete matched value. */
  detections: Detection[];
  /** True if a `"block"` action fired. */
  blocked: boolean;
}

/**
 * Run a whole string through the sieve — the reference behaviour that the
 * streaming APIs are guaranteed to match exactly.
 */
export function sieveText(input: string, policy: Policy = {}): SieveTextResult {
  const engine = new Sieve(policy);
  const first = engine.push(input);
  const last = engine.flush();
  return {
    text: first.text + last.text,
    detections: [...first.detections, ...last.detections],
    blocked: first.blocked || last.blocked,
  };
}

/**
 * Wrap any async iterable of strings — which is what every major AI SDK gives
 * you for a text stream — and yield the filtered version.
 *
 * ```ts
 * for await (const token of sieve(result.textStream)) {
 *   process.stdout.write(token);
 * }
 * ```
 */
export async function* sieve(
  source: AsyncIterable<string>,
  policy: Policy = {},
): AsyncGenerator<string, void, unknown> {
  const engine = new Sieve(policy);

  for await (const chunk of source) {
    const { text, blocked } = engine.push(chunk);
    if (text) yield text;
    if (blocked) return;
  }

  const { text } = engine.flush();
  if (text) yield text;
}

/**
 * A `TransformStream` for Web Streams pipelines — edge runtimes, `Response`
 * bodies, browsers.
 */
export function createSieveTransform(
  policy: Policy = {},
): TransformStream<string, string> {
  const engine = new Sieve(policy);

  return new TransformStream<string, string>({
    transform(chunk, controller) {
      const { text, blocked } = engine.push(chunk);
      if (text) controller.enqueue(text);
      if (blocked) controller.terminate();
    },
    flush(controller) {
      const { text } = engine.flush();
      if (text) controller.enqueue(text);
    },
  });
}
