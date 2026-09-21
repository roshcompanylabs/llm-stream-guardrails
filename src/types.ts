/**
 * Public types for llm-stream-guardrails.
 */

/** What to do when a detector fires. */
export type Action =
  /** Replace the offending text with a mask, keep streaming. (default) */
  | 'mask'
  /** Stop the stream immediately and emit nothing further. */
  | 'block'
  /** Let the text through untouched, but report it via `onDetect`. */
  | 'report';

/** A single thing the sieve found. */
export interface Detection {
  /** Name of the detector that fired, e.g. `"email"` or `"creditCard"`. */
  detector: string;
  /** The exact raw text that matched — complete, never a truncated prefix. */
  match: string;
  /** Offset of the match in the original input, counting from the first character. */
  index: number;
  /** Length of the raw match in characters. */
  length: number;
}

/** A rule the sieve scans for. */
export interface Detector {
  /** Stable identifier, surfaced on every `Detection`. */
  name: string;
  /**
   * Pattern to search for, applied to the *canonical* form of the text.
   * The `g` flag is added automatically if missing.
   *
   * Bound every quantifier. An unbounded `+` next to an optional separator is
   * how a detector turns into a denial-of-service vector.
   */
  pattern: RegExp;
  /**
   * Optional second-stage check to kill false positives.
   * Return `false` to discard the match (e.g. digits that fail Luhn).
   */
  validate?: (match: string) => boolean;
  /**
   * Mask only this capture group instead of the whole match.
   *
   * This is what lets a detector recognise `Password: hunter2` by its label and
   * still redact only `hunter2`. It must be a capture group rather than a
   * lookbehind: the engine has to hold the label as part of the match, or the
   * label is released downstream first and the pattern can never match the value
   * that follows it.
   */
  maskGroup?: number;
}

/**
 * A region that must be held — and, if it never closes, masked — from the moment
 * its opener appears. This is how a PEM private key is contained: the body is not
 * matchable on its own, so the opener alone makes everything after it unsafe.
 */
export interface PendingRegion {
  /** Detector name reported if this region has to be masked. */
  name: string;
  /**
   * A literal marker that begins the region, e.g. `"-----BEGIN "`.
   *
   * This is what makes the region safe under streaming. The opener *pattern*
   * cannot match until the whole header has arrived, and at one character per
   * chunk the header is released long before that — so the engine holds as soon
   * as the tail looks like the start of this marker.
   */
  openPrefix: string;
  /** Pattern that opens the region. */
  open: RegExp;
  /** Pattern that closes it. */
  close: RegExp;
}

/** Configuration handed to the sieve. */
export interface Policy {
  /**
   * Detectors to run. Defaults to the built-in set: `email`, `creditCard`,
   * `phone`, `ssn`, `iban`, `secret` (credential families and complete PEM
   * private key blocks) and `labeledSensitive`.
   *
   * `ipAddress` is exported but is **not** on by default — addresses appear
   * constantly in technical output, so redacting them unasked is noise. Pass it
   * explicitly to enable it.
   */
  detectors?: Detector[];
  /** Open/close regions that must be held until closed. Defaults to PEM key blocks. */
  pendingRegions?: PendingRegion[];
  /** Extra literal words/phrases to catch, matched case-insensitively. */
  bannedWords?: string[];
  /**
   * Extra field labels whose value should be redacted whatever shape it has,
   * e.g. `['patient id', 'insurance id', 'salary']`.
   *
   * Added to the built-in label set. Use this for domain-specific records rather
   * than trying to describe every possible value format.
   */
  sensitiveLabels?: string[];
  /** What to do on a hit. Defaults to `"mask"`. */
  action?: Action;
  /**
   * Replacement text. Either a fixed string or a function of the detection.
   * Defaults to `` `[redacted:${detector}]` ``.
   */
  mask?: string | ((detection: Detection) => string);
  /**
   * Hard ceiling on how much text may be held while waiting for a match to
   * settle, in characters. Defaults to 8192.
   *
   * You should not need to touch this. The engine works out on its own how much
   * it must hold — normally only a handful of characters. This exists solely so
   * an unterminated credential cannot buffer without bound.
   *
   * On overflow the engine **fails closed**: the unsettled run is masked rather
   * than released, because that run is exactly where a variable-length secret
   * would be.
   */
  maxRetention?: number;
  /**
   * Fold Unicode look-alikes (non-breaking spaces, fullwidth digits, zero-width
   * characters, homoglyphs) before detecting. Defaults to `true`.
   *
   * Turning this off makes the detectors trivially evadable. It exists only for
   * callers who have already normalised upstream.
   */
  normalize?: boolean;
  /** Called once per detection, in stream order, with the complete match. */
  onDetect?: (detection: Detection) => void;
}

/** Result of pushing a chunk through the sieve. */
export interface SieveChunk {
  /** Text that is safe to release downstream. May be empty. */
  text: string;
  /** Detections finalised while processing this chunk. */
  detections: Detection[];
  /** True once the stream has been terminated by a `"block"` action. */
  blocked: boolean;
}

/** Policy with every optional field filled in and every pattern precompiled. */
export interface ResolvedPolicy {
  detectors: Detector[];
  pendingRegions: PendingRegion[];
  action: Action;
  mask: (detection: Detection) => string;
  maxRetention: number;
  normalize: boolean;
  onDetect: ((detection: Detection) => void) | undefined;
}
