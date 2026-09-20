/**
 * The canonical plane.
 *
 * Detection must not run on raw bytes. A credit card separated by non-breaking
 * spaces, an email with a zero-width space inside it, or fullwidth digits all
 * render identically to the reader while defeating an ASCII pattern completely.
 *
 * So we build a second view of the buffer — a canonical form — and run the
 * detectors against that, then map every match back to the raw text so the
 * original characters (never a rewritten version of them) are what gets masked.
 *
 * The mapping is exact because canonicalisation here is strictly per-character:
 * every raw character becomes either zero or one canonical character. That rules
 * out full NFKC (which can expand one character into several) in favour of a
 * targeted table covering the evasions that were actually reproduced.
 */

/** A canonical view of some raw text, plus the index map back to it. */
export interface Canonical {
  /** The canonical text detectors run against. */
  text: string;
  /**
   * `map[i]` is the raw index the canonical character `i` came from.
   * Has one extra trailing entry equal to the raw length, so the raw end of a
   * canonical range `[start, end)` is always `map[end]`.
   */
  map: number[];
}

/** Characters that carry no visible width and must never hide inside a match. */
function isInvisible(code: number): boolean {
  return (
    code === 0x00ad || // soft hyphen
    code === 0x200b || // zero-width space
    code === 0x200c || // zero-width non-joiner
    code === 0x200d || // zero-width joiner
    code === 0x2060 || // word joiner
    code === 0xfeff || // BOM / zero-width no-break space
    (code >= 0x200e && code <= 0x200f) || // LTR/RTL marks
    (code >= 0x202a && code <= 0x202e) || // bidi embedding/override
    (code >= 0x2066 && code <= 0x2069) || // bidi isolates
    (code >= 0x0300 && code <= 0x036f) || // combining diacriticals
    (code >= 0xfe00 && code <= 0xfe0f) // variation selectors
  );
}

/** Space-like characters that a locale or a PDF export may use between digits. */
function isUnicodeSpace(code: number): boolean {
  return (
    code === 0x00a0 || // no-break space
    (code >= 0x2000 && code <= 0x200a) || // en/em/thin/hair spaces
    code === 0x202f || // narrow no-break space
    code === 0x205f || // medium mathematical space
    code === 0x3000 // ideographic space
  );
}

/** Dash-like characters typography loves to substitute for a plain hyphen. */
function isUnicodeDash(code: number): boolean {
  return (
    (code >= 0x2010 && code <= 0x2015) || // hyphen .. horizontal bar
    code === 0x2212 || // minus sign
    code === 0xfe58 ||
    code === 0xfe63 ||
    code === 0xff0d // fullwidth hyphen-minus
  );
}

/**
 * Cyrillic and Greek letters that are visually indistinguishable from Latin.
 * Folding them is what stops `аdmin@corp.com` (Cyrillic а) from sailing past.
 */
const HOMOGLYPHS = new Map<number, string>([
  [0x0430, 'a'], [0x0435, 'e'], [0x043e, 'o'], [0x0440, 'p'],
  [0x0441, 'c'], [0x0443, 'y'], [0x0445, 'x'], [0x0456, 'i'],
  [0x0455, 's'], [0x0458, 'j'], [0x04bb, 'h'],
  [0x0410, 'A'], [0x0412, 'B'], [0x0415, 'E'], [0x041a, 'K'],
  [0x041c, 'M'], [0x041d, 'H'], [0x041e, 'O'], [0x0420, 'P'],
  [0x0421, 'C'], [0x0422, 'T'], [0x0425, 'X'],
  [0x03bf, 'o'], [0x03b1, 'a'], [0x03b5, 'e'], [0x03c1, 'p'],
  [0x0391, 'A'], [0x0392, 'B'], [0x0395, 'E'], [0x039f, 'O'],
]);

/**
 * Fold a single character to its canonical form.
 * Returns `''` to drop the character entirely.
 */
function foldChar(ch: string, code: number): string {
  if (isInvisible(code)) return '';
  if (isUnicodeSpace(code)) return ' ';
  if (isUnicodeDash(code)) return '-';

  // Fullwidth digits, uppercase and lowercase -> ASCII.
  if (code >= 0xff10 && code <= 0xff19) return String.fromCharCode(code - 0xff10 + 0x30);
  if (code >= 0xff21 && code <= 0xff3a) return String.fromCharCode(code - 0xff21 + 0x41);
  if (code >= 0xff41 && code <= 0xff5a) return String.fromCharCode(code - 0xff41 + 0x61);
  // Fullwidth @ . - _ + / :
  if (code === 0xff20) return '@';
  if (code === 0xff0e) return '.';
  if (code === 0xff3f) return '_';
  if (code === 0xff0b) return '+';
  if (code === 0xff0f) return '/';
  if (code === 0xff1a) return ':';

  const homoglyph = HOMOGLYPHS.get(code);
  if (homoglyph !== undefined) return homoglyph;

  return ch;
}

/**
 * Build the canonical view of `raw`.
 *
 * Fast path: pure-ASCII text (the overwhelming majority of model output) is
 * returned without allocating a per-character map.
 */
export function canonicalize(raw: string): Canonical {
  let needsFolding = false;
  for (let i = 0; i < raw.length; i++) {
    if (raw.charCodeAt(i) > 0x7f) {
      needsFolding = true;
      break;
    }
  }

  if (!needsFolding) {
    // Identity map, produced lazily by the caller via `identityRawIndex`.
    return { text: raw, map: IDENTITY };
  }

  let text = '';
  const map: number[] = [];
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charAt(i);
    const folded = foldChar(ch, raw.charCodeAt(i));
    if (folded === '') continue;
    text += folded;
    map.push(i);
  }
  map.push(raw.length);
  return { text, map };
}

/** Sentinel meaning "canonical index equals raw index". */
export const IDENTITY: number[] = [];

/** Translate a canonical index to a raw index for a given canonical view. */
export function toRaw(canonical: Canonical, canonicalIndex: number, rawLength: number): number {
  if (canonical.map === IDENTITY) return canonicalIndex;
  if (canonicalIndex >= canonical.map.length) return rawLength;
  return canonical.map[canonicalIndex]!;
}
