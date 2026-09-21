/**
 * The settlement engine.
 *
 * The rule the whole design rests on:
 *
 *   **Never act on text that is not provably finished, and never emit text that
 *   has not been scanned in its final form.**
 *
 * The previous engine held back a fixed number of characters and then acted on
 * whatever it found, rewriting its own buffer with masked text as it went. Both
 * halves of that were wrong. A variable-length secret still being written would
 * be masked at the chunk boundary and the remainder streamed out in clear; and
 * because the buffer was rewritten, indices, dedupe keys and re-scans all drifted.
 *
 * Instead:
 *
 *  - The raw buffer stays pristine. Masking happens only on the way out.
 *  - Detection runs on a canonical view of the buffer, so Unicode look-alikes
 *    cannot smuggle a value past an ASCII pattern.
 *  - Each push computes a **settlement point**: the furthest position that no
 *    match could still grow past. Anything before it is final; anything after it
 *    is held. On benign prose this is a handful of characters, not 256.
 *  - A match touching the end of the buffer is never final — it might still grow.
 *  - A region that opens but has not closed (a PEM key block) holds from its
 *    opener, and fails **closed** if it never closes.
 *
 * Because only provably-final matches are acted on, every detection fires exactly
 * once, carries the complete matched text, and needs no deduplication.
 */

import { canonicalize, IDENTITY, toRaw } from './canonical.js';
import type {
  Detection,
  Detector,
  PendingRegion,
  Policy,
  ResolvedPolicy,
  SieveChunk,
} from './types.js';
import {
  bannedWordsDetector,
  builtinDetectors,
  defaultPendingRegions,
  labeledSensitiveDetector,
} from './detectors.js';

const DEFAULT_MAX_RETENTION = 8192;

/**
 * How far back the engine will look for a token that might still be growing.
 * Bounded so that a script written without spaces cannot make the tail unbounded;
 * a genuinely long pending value extends past this via a match or a pending region.
 */
const VIABLE_WINDOW = 256;

/** A match in canonical coordinates. */
interface RawHit {
  detector: string;
  /** Start of the region to mask. */
  start: number;
  /** End of the region to mask. */
  end: number;
  /**
   * Start of the *whole* match, which may sit before `start` when only a capture
   * group is masked. Settlement holds from here, so the context a pattern needs
   * (a `Password:` label, say) is never released ahead of the value it guards.
   */
  anchor: number;
}

function compilePattern(pattern: RegExp, needsIndices: boolean): RegExp {
  let flags = pattern.flags;
  if (!flags.includes('g')) flags += 'g';
  if (needsIndices && !flags.includes('d')) flags += 'd';
  return new RegExp(pattern.source, flags);
}

/** Fill in defaults and precompile every pattern exactly once. */
export function resolvePolicy(policy: Policy = {}): ResolvedPolicy {
  const chosen: Detector[] = [...(policy.detectors ?? builtinDetectors)];
  if (policy.bannedWords && policy.bannedWords.length > 0) {
    chosen.push(bannedWordsDetector(policy.bannedWords));
  }
  if (policy.sensitiveLabels && policy.sensitiveLabels.length > 0) {
    const widened = labeledSensitiveDetector(policy.sensitiveLabels);
    const existing = chosen.findIndex((d) => d.name === 'labeledSensitive');
    if (existing >= 0) chosen[existing] = widened;
    else chosen.push(widened);
  }

  // Compiling here rather than per push is worth roughly three orders of
  // magnitude — the previous engine rebuilt every RegExp on every chunk.
  const detectors = chosen.map((d) => ({
    name: d.name,
    pattern: compilePattern(d.pattern, d.maskGroup !== undefined),
    validate: d.validate,
    maskGroup: d.maskGroup,
  }));

  const pendingRegions = (policy.pendingRegions ?? defaultPendingRegions).map((r) => ({
    name: r.name,
    openPrefix: r.openPrefix,
    open: compilePattern(r.open, false),
    close: compilePattern(r.close, false),
  }));

  const mask = policy.mask ?? ((d: Detection) => `[redacted:${d.detector}]`);

  // Guard the ceiling: a NaN here previously disabled streaming entirely and
  // grew the buffer without bound until the process hung.
  // Floored at the viable window: this ceiling exists to bound a pathological
  // hold, not to throttle normal operation. Setting it below the window would
  // make the engine mask ordinary text instead of releasing it.
  const requested = policy.maxRetention;
  const maxRetention = Math.max(
    VIABLE_WINDOW,
    typeof requested === 'number' && Number.isFinite(requested) && requested > 0
      ? Math.floor(requested)
      : DEFAULT_MAX_RETENTION,
  );

  return {
    detectors,
    pendingRegions,
    action: policy.action ?? 'mask',
    mask: typeof mask === 'function' ? mask : () => mask,
    maxRetention,
    normalize: policy.normalize ?? true,
    onDetect: policy.onDetect,
  };
}

/** Run every detector over `text`, resolving overlaps. */
export function scanCanonical(text: string, detectors: Detector[]): RawHit[] {
  const hits: RawHit[] = [];

  for (const detector of detectors) {
    const re = detector.pattern;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const anchor = m.index;
      let start = m.index;
      let end = m.index + m[0].length;

      if (detector.maskGroup !== undefined) {
        // `d` flag gives us the group's own offsets, so a label can be part of
        // the match — and therefore held by settlement — while only the value
        // it guards is masked.
        const range = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> })
          .indices?.[detector.maskGroup];
        if (!range) continue;
        start = range[0];
        end = range[1];
      }

      // Validate what will actually be masked. For a label-aware detector that
      // is the value, not the whole `label: value` match — a placeholder check
      // on the label would be meaningless.
      if (detector.validate && !detector.validate(text.slice(start, end))) continue;

      hits.push({ detector: detector.name, start, end, anchor });
    }
  }

  hits.sort((a, b) => a.start - b.start || b.end - a.end);

  const resolved: RawHit[] = [];
  let coveredTo = -1;
  for (const hit of hits) {
    if (hit.start >= coveredTo) {
      resolved.push(hit);
      coveredTo = hit.end;
    }
  }
  return resolved;
}

const isDigit = (code: number) => code >= 48 && code <= 57;

/** A character that can appear inside a separated value group, e.g. an IBAN's `GB82` or `WEST`. */
const isGroupChar = (code: number) => isDigit(code) || (code >= 65 && code <= 90);

/** The longest IBAN any country issues, used to bound the grouped-value walk. */
const IBAN_MAX_LENGTH = 34;

/**
 * Characters that can sit inside some pattern, so a run of them may still grow.
 *
 * Any non-whitespace character qualifies. An enumerated list looks safer and is
 * not: it silently released `(579)` from `(579)888-3058` because parentheses
 * were missing, and the opening quote of `key = "d3d1..."` for the same reason,
 * after which neither pattern could ever match. The walk still stops at the
 * first whitespace, so on ordinary prose it holds a word, not a window.
 */
function isTokenChar(code: number): boolean {
  return code > 32;
}

/**
 * Walk back from the end over text that could still be part of a growing match.
 * Returns the canonical index where the unsettled tail begins.
 */
function viablePrefixStart(text: string, maxRetention: number): number {
  const n = text.length;
  // An unbroken run of non-whitespace may be a single long secret — a JWT runs
  // to hundreds of characters — so it is bounded only by the real ceiling.
  // Speculative whitespace crossings are the part that needs the tighter bound,
  // or text without spaces would never settle.
  const tokenLimit = Math.max(0, n - maxRetention);
  const crossLimit = Math.max(0, n - VIABLE_WINDOW);
  let i = n;
  /** No non-digit token character seen yet, so a digit-group is still plausible. */
  let digitsOnly = true;
  /** Where to fall back to if the digit-group hypothesis turns out to be wrong. */
  let lastSeparatorCross = -1;
  /** True once a `:` or `=` has been crossed, so we are inside a field label. */
  let inLabel = false;
  /** Words of label crossed so far, bounded so this cannot run away. */
  let labelWords = 0;
  /**
   * Speculative crossings before any separator is seen. A buffer ending
   * `Date of Birth` has no `:` yet, so nothing marks it as a label — releasing
   * it means the separator arrives to find its label already truncated. Three
   * covers the longest built-in labels (`Date of Birth`, `Social Security
   * Number`, `Bank Routing Number`) and costs a few words of latency.
   */
  let preLabelCross = 3;
  /**
   * An IBAN body is uppercase alphanumeric in groups — `GB82 WEST 1234 5698
   * 7654 32` — so a letter after a group separator does not on its own prove
   * this was never a grouped value. Without this, the walk reached `WEST`,
   * concluded the digit-group hypothesis was wrong and released the whole
   * account number in cleartext at any chunk size small enough to split it.
   * Bounded by the longest possible IBAN so it cannot run away.
   */
  let ibanShape = true;
  let alnumCrossed = 0;
  const groupedViable = () => digitsOnly || (ibanShape && alnumCrossed <= IBAN_MAX_LENGTH);

  while (i > tokenLimit) {
    const code = text.charCodeAt(i - 1);

    if (isDigit(code)) {
      alnumCrossed++;
      i--;
      continue;
    }

    if (isTokenChar(code)) {
      if (code >= 65 && code <= 90) alnumCrossed++; // 'A'-'Z'
      else ibanShape = false;
      // A letter after crossing a separator usually means this was never a digit
      // group (`sk-...456 ` reads like `4111 1111 ` from the tail alone) — so
      // undo the crossing rather than dragging the whole token back into the
      // held region. Uppercase alphanumeric runs are the exception above.
      if (lastSeparatorCross >= 0 && !groupedViable()) return lastSeparatorCross;
      if (code === 58 || code === 61) inLabel = true; // ':' or '='
      digitsOnly = false;
      i--;
      continue;
    }

    // Whitespace that follows a label separator belongs to the label/value pair.
    // Releasing it would hand `Password: ` downstream before its value arrived,
    // and the label-aware detector could then never match what follows.
    if (code === 32 || code === 9) {
      if (i <= crossLimit) break;
      let j = i - 1;
      while (j > 0 && (text.charCodeAt(j - 1) === 32 || text.charCodeAt(j - 1) === 9)) j--;
      const before = j > 0 ? text.charCodeAt(j - 1) : -1;
      if (before === 58 || before === 61) {
        // ':' or '=' — keep walking back through the label itself.
        inLabel = true;
        digitsOnly = false;
        lastSeparatorCross = -1;
        i = j;
        continue;
      }
      // A multi-word label such as `Fly access token:` or `Date of Birth:` must
      // be held whole. Splitting it released `Fly access ` and left `token:`,
      // which matches nothing.
      //
      // Skip the whole whitespace run, not one character: aligned config like
      // `password       = "x"` is a single gap, and counting it per-character
      // exhausted the budget before the label was reached.
      if (inLabel && labelWords < 4) {
        labelWords++;
        i = j;
        continue;
      }
      // No separator seen yet — hold one more word in case one is still coming.
      if (!inLabel && preLabelCross > 0) {
        preLabelCross--;
        i = j;
        continue;
      }
    }

    // A space or dash right after a digit — or after an uppercase alphanumeric
    // group, which is what an IBAN is made of — may be a group separator with
    // more of the value still to come.
    if (
      (code === 32 || code === 45) &&
      groupedViable() &&
      i >= 2 &&
      isGroupChar(text.charCodeAt(i - 2))
    ) {
      lastSeparatorCross = i;
      i--;
      continue;
    }

    break;
  }
  return i;
}

const isJoiner = (code: number) =>
  (code >= 0x0300 && code <= 0x036f) || // combining marks
  (code >= 0xfe00 && code <= 0xfe0f) || // variation selectors
  code === 0x200d; // zero-width joiner

/**
 * Never cut inside a surrogate pair or immediately before a combining character.
 * Cutting by UTF-16 code unit is what emitted a lone high surrogate at the cut
 * and a lone low surrogate after it, so an emoji pair rendered as mojibake for
 * any consumer that encoded each emitted chunk on its own.
 */
function clampCut(raw: string, index: number): number {
  let i = index;
  if (i <= 0 || i >= raw.length) return i;

  while (i > 0 && i < raw.length && isJoiner(raw.charCodeAt(i))) i--;

  if (i > 0 && i < raw.length) {
    const hi = raw.charCodeAt(i - 1);
    const lo = raw.charCodeAt(i);
    if (hi >= 0xd800 && hi <= 0xdbff && lo >= 0xdc00 && lo <= 0xdfff) i--;
  }
  return i < 0 ? 0 : i;
}

/**
 * Stateful sieve. Feed chunks with `push()`, then call `flush()` once.
 */
export class Sieve {
  private readonly policy: ResolvedPolicy;
  private raw = '';
  private consumed = 0;
  private blocked = false;
  /**
   * Set once a confirmed unterminated region has been masked at the ceiling.
   * Without this the marker is consumed along with the masked run, so the rest
   * of the key body arrives with no context and is released as ordinary text.
   */
  private suppressing: PendingRegion | null = null;

  constructor(policy: Policy = {}) {
    this.policy = resolvePolicy(policy);
  }

  /** True once a `"block"` action has terminated the stream. */
  get isBlocked(): boolean {
    return this.blocked;
  }

  push(chunk: string): SieveChunk {
    if (this.blocked) return { text: '', detections: [], blocked: true };
    if (chunk.length === 0) return { text: '', detections: [], blocked: false };
    this.raw += chunk;
    return this.drain(false);
  }

  /** Release everything still held. Call exactly once, after the last push. */
  flush(): SieveChunk {
    if (this.blocked) {
      this.raw = '';
      return { text: '', detections: [], blocked: true };
    }
    if (this.raw.length === 0) return { text: '', detections: [], blocked: false };
    return this.drain(true);
  }

  private drain(final: boolean): SieveChunk {
    const raw = this.raw;
    const canonical = this.policy.normalize
      ? canonicalize(raw)
      : { text: raw, map: IDENTITY };
    const text = canonical.text;

    // Still inside a region that already failed closed: swallow everything until
    // it closes. The mask was emitted when the region was first contained.
    if (this.suppressing) {
      const region = this.suppressing;
      region.close.lastIndex = 0;
      const closer = region.close.exec(text);
      const upTo = closer ? closer.index + closer[0].length : text.length;
      const rawUpTo = closer ? toRaw(canonical, upTo, raw.length) : raw.length;
      if (closer) this.suppressing = null;
      this.raw = raw.slice(rawUpTo);
      this.consumed += rawUpTo;
      return { text: '', detections: [], blocked: false };
    }

    const hits = scanCanonical(text, this.policy.detectors);

    // Where is it safe to stop holding?
    let settle = final ? text.length : viablePrefixStart(text, this.policy.maxRetention);

    // An unterminated pending region makes everything from its marker unsafe.
    // `confirmed` separates a real unterminated block (which must fail closed)
    // from a tail that merely looks like the start of one (which only delays).
    let pendingFrom = -1;
    let pendingName = '';
    let pendingConfirmed = false;
    let pendingRegion: PendingRegion | null = null;

    for (const region of this.policy.pendingRegions) {
      let from = -1;
      let confirmed = false;

      const marker = text.lastIndexOf(region.openPrefix);
      if (marker >= 0) {
        region.close.lastIndex = marker;
        if (region.close.exec(text) === null) {
          from = marker;
          confirmed = true;
        }
      }

      if (from < 0 && !final) {
        // The tail may be a partial marker that has not finished arriving.
        const longest = Math.min(region.openPrefix.length - 1, text.length);
        for (let len = longest; len > 0; len--) {
          if (text.endsWith(region.openPrefix.slice(0, len))) {
            from = text.length - len;
            break;
          }
        }
      }

      if (from >= 0 && (pendingFrom < 0 || from < pendingFrom)) {
        pendingFrom = from;
        pendingName = region.name;
        pendingConfirmed = confirmed;
        pendingRegion = region;
      }
    }
    if (pendingFrom >= 0 && !final) settle = Math.min(settle, pendingFrom);

    if (!final) {
      // A match that reaches the end may still grow; one that straddles the
      // settlement point pulls it back to the match's own start.
      for (const hit of hits) {
        if (hit.end >= text.length || hit.end > settle) {
          // Hold from the whole match, not just the masked span, or a label is
          // released ahead of its value and can never match again.
          if (hit.anchor < settle) settle = hit.anchor;
        }
      }
    }

    // Fail closed rather than release a run that has outgrown the ceiling — that
    // run is exactly where a variable-length credential would be.
    let forced: RawHit | null = null;
    if (!final && text.length - settle > this.policy.maxRetention) {
      forced = {
        detector: pendingConfirmed ? pendingName : 'unsettled',
        start: settle,
        end: text.length,
        anchor: settle,
      };
      settle = text.length;
      if (pendingConfirmed && pendingRegion) this.suppressing = pendingRegion;
    }
    if (final && pendingConfirmed && pendingFrom >= 0) {
      forced = {
        detector: pendingName,
        start: pendingFrom,
        end: text.length,
        anchor: pendingFrom,
      };
    }

    if (settle <= 0 && !final) {
      return { text: '', detections: [], blocked: false };
    }

    // Translate to raw coordinates and make sure the cut is a legal boundary.
    let rawSettle = final ? raw.length : toRaw(canonical, settle, raw.length);
    rawSettle = final ? raw.length : clampCut(raw, rawSettle);
    if (!final && rawSettle <= 0) {
      return { text: '', detections: [], blocked: false };
    }

    const finalHits = hits.filter((h) => h.end <= settle);
    if (forced) {
      const kept = finalHits.filter((h) => h.end <= forced.start);
      kept.push(forced);
      finalHits.length = 0;
      finalHits.push(...kept);
    }

    const detections: Detection[] = finalHits.map((hit) => {
      const start = toRaw(canonical, hit.start, raw.length);
      const end = Math.min(toRaw(canonical, hit.end, raw.length), rawSettle);
      return {
        detector: hit.detector,
        match: raw.slice(start, end),
        index: this.consumed + start,
        length: end - start,
      };
    });

    if (detections.length > 0 && this.policy.action === 'block') {
      for (const d of detections) this.policy.onDetect?.(d);
      this.blocked = true;
      // Release the text that precedes the first detection, then terminate.
      //
      // A stream has usually already delivered this prefix in earlier chunks and
      // cannot take it back, so discarding it here would make a batch call and a
      // streamed call disagree — which is the one thing this library promises
      // never happens. The prefix is text the engine already settled as safe, so
      // releasing it leaks nothing: everything from the detection onwards is
      // dropped and the stream is closed.
      const first = detections[0];
      const cut = first ? clampCut(raw, Math.max(0, first.index - this.consumed)) : 0;
      const safe = raw.slice(0, cut);
      this.raw = '';
      this.consumed += cut;
      return { text: safe, detections, blocked: true };
    }

    for (const d of detections) this.policy.onDetect?.(d);

    const head = raw.slice(0, rawSettle);
    let out: string;
    if (this.policy.action === 'mask' && detections.length > 0) {
      out = '';
      let cursor = 0;
      for (const d of detections) {
        const localStart = d.index - this.consumed;
        out += head.slice(cursor, localStart) + this.policy.mask(d);
        cursor = localStart + d.length;
      }
      out += head.slice(cursor);
    } else {
      out = head;
    }

    this.raw = raw.slice(rawSettle);
    this.consumed += rawSettle;
    return { text: out, detections, blocked: false };
  }
}
