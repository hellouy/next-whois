/**
 * Minimal RFC 3492 punycode decoder for IDN TLD labels.
 *
 * Purpose: display help. The wire format (punycode, "xn--…") stays the
 * source of truth everywhere in the lookup pipeline; this module only
 * converts "xn--…" labels to their Unicode form for UI display.
 *
 * Zero dependencies so it runs in both the Node API runtime and the
 * browser bundle (the Node core `punycode` module is deprecated and not
 * available client-side).
 */

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = "-";

/** Maps an ASCII code point to its base-36 digit value, or BASE if invalid. */
function decodeDigit(cp: number): number {
  // "0"-"9" (0x30-0x39) → 26-35, "A"-"Z" (0x41-0x5A) → 0-25, "a"-"z" (0x61-0x7A) → 0-25
  return cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : BASE;
}

/** Bias adaptation (RFC 3492 section 6.1). */
function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
    delta = Math.floor(delta / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + SKEW));
}

/**
 * Decodes the body of a punycode label (the part after "xn--").
 * Returns null on any malformed input — callers must fall back to the
 * original label instead of guessing.
 */
export function decodePunycodeLabel(input: string): string | null {
  if (!input || /[^0-9a-z-]/.test(input)) return null;

  const output: number[] = [];
  const basicEnd = input.lastIndexOf(DELIMITER);
  const basic = basicEnd > 0 ? input.slice(0, basicEnd) : "";
  for (let j = 0; j < basic.length; j++) {
    const cp = input.charCodeAt(j);
    if (cp >= 0x80) return null;
    output.push(cp);
  }

  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  for (let index = basicEnd > 0 ? basicEnd + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) return null;
      const digit = decodeDigit(input.charCodeAt(index++));
      if (digit >= BASE) return null;
      i += digit * w;
      if (i > 0x10ffff * 100) return null; // overflow guard
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    if (n < 0x80 || n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    output.splice(i++, 0, n);
  }

  // Reject decodes that land on control characters (e.g. the degenerate
  // label "aa" decodes to U+0080 U+0080) — never valid IDNA output and
  // never something we want to render.
  if (/[\u0000-\u001f\u007f-\u009f]/.test(String.fromCodePoint(...output))) return null;
  return String.fromCodePoint(...output);
}

/**
 * Returns the Unicode display form of a TLD label when it is an IDN
 * ("xn--…") that decodes cleanly; otherwise returns the label unchanged.
 *
 * e.g. "xn--fiqs8s" → "中国", "com" → "com", "xn--invalid" → "xn--invalid"
 */
export function tldToUnicode(tld: string): string {
  if (!tld.startsWith("xn--")) return tld;
  const decoded = decodePunycodeLabel(tld.slice(4));
  return decoded && decoded !== tld ? decoded : tld;
}
