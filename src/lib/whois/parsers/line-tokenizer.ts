/**
 * Shared low-level line tokenizer for WHOIS text.
 *
 * Both parsers in this codebase need to turn raw WHOIS lines into key/value
 * pairs:
 *   - internal-whoiser.ts parseSimpleWhoisLines() builds a flat record for
 *     IP/ASN lookups.
 *   - common_parser.ts analyzeWhois() feeds a domain result object.
 *
 * The splitting rules (first-colon boundary, comment lines, the "Network:"
 * prefix some registries emit) live here so the two callers cannot drift.
 * Callers keep their own semantics — case normalisation, dedup-to-array,
 * field mapping — on top of these primitives.
 */

export interface WhoIsPair {
  /** Key as written, case preserved. Callers lowercase when they need to. */
  key: string;
  /** Value with surrounding whitespace removed. Never empty. */
  value: string;
}

/** True for WHOIS comment lines ("%" or "#" at the start). */
export function isCommentLine(line: string): boolean {
  const trimmed = line.trimStart();
  return trimmed.startsWith("%") || trimmed.startsWith("#");
}

/**
 * True when the colon at index i is a clock/offset separator inside a time
 * value ("07:57:05", "+08:00", the "10:20:30" in an ISO "…T10:20:30Z" stamp)
 * rather than the key/value boundary.
 *
 * The digit run before the colon must stand alone — start of line, preceded by
 * a non-alphanumeric char, or (for a 2-digit hour) by the ISO "T" separator —
 * so a label such as "Address1: 123" is not mistaken for a time.
 */
function isTimeColon(s: string, i: number): boolean {
  if (!/\d/.test(s[i - 1] ?? "") || !/\d/.test(s[i + 1] ?? "")) return false;
  let j = i - 1;
  while (j >= 0 && /\d/.test(s[j])) j--;
  const before = j >= 0 ? s[j] : "";
  if (before === "" || !/[0-9A-Za-z]/.test(before)) return true;
  const digitRun = i - 1 - j;
  return (before === "T" || before === "t") && digitRun === 2;
}

/**
 * Split a line into its key and value at the first colon that is not part of
 * a time value.
 *
 * Some registries (e.g. TWNIC) write dates as free text without a key:
 *   "Record created on 2022-07-30 07:57:05 (UTC+8)"
 * Splitting at the clock colon would yield key "…on 2022-07-30 07" and value
 * "57:05 (UTC+8)", which date parsers misread as year 2057. Skipping time
 * colons leaves such lines as free text so the date-keyword fallback handles
 * them correctly.
 *
 * Returns null for blank lines, lines without a usable colon, and lines where
 * the key or value is empty after trimming — callers treat those as free text.
 */
export function splitWhoisLine(line: string): WhoIsPair | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  let idx = -1;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] !== ":") continue;
    if (isTimeColon(trimmed, i)) continue;
    idx = i;
    break;
  }
  if (idx <= 0) return null;
  const key = trimmed.slice(0, idx).trim();
  const value = trimmed.slice(idx + 1).trim();
  if (!key || !value) return null;
  return { key, value };
}

/**
 * Strip a leading "Network:" label from a line that contains at least two
 * colons, e.g. "Network: Class C: 192.0.2.0 - 192.0.2.255".
 *
 * Registries use this to nest a second labelled value inside one line. The
 * one-colon form ("Network: 192.0.2.0") is left untouched because the
 * "Network" token is itself the field key there.
 */
export function stripNetworkPrefix(line: string): string {
  const segments = line.split(":");
  if (segments.length >= 3 && segments[0].toLowerCase() === "network") {
    return segments.slice(1).join(":");
  }
  return line;
}
