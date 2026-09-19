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
 * Split a line into its key and value at the first colon.
 *
 * Returns null for blank lines, lines without a colon, and lines where the
 * key or value is empty after trimming — callers treat those as free text.
 */
export function splitWhoisLine(line: string): WhoIsPair | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  const idx = trimmed.indexOf(":");
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
