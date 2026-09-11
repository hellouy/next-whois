/**
 * Pure helpers for the batch-check domain matrix (prefix × suffix).
 * Kept free of React/next imports so they are trivially unit-testable.
 */

/** Normalize a raw prefix/suffix token into a lowercase, dot-stripped label. */
export function normalizeDomainPart(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^\.+/, "")
    .replace(/\.+$/, "")
    .replace(/\s+/g, "");
}

/** Split a free-form multi-value input into normalized, de-duplicated parts. */
export function parseDomainParts(input: string): string[] {
  if (!input) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const token of input.split(/[\s,，]+/)) {
    const norm = normalizeDomainPart(token);
    if (!norm) continue;
    if (!seen.has(norm)) {
      seen.add(norm);
      out.push(norm);
    }
  }
  return out;
}

/**
 * Build the cartesian product of prefixes × TLDs as fully-qualified domains.
 * Inputs are normalized and de-duplicated; the output is stable-sorted.
 */
export function buildDomainMatrix(prefixes: string[], tlds: string[]): string[] {
  const p = Array.from(new Set(prefixes.map(normalizeDomainPart).filter(Boolean)));
  const t = Array.from(new Set(tlds.map(normalizeDomainPart).filter(Boolean)));
  if (p.length === 0 || t.length === 0) return [];
  const out = new Set<string>();
  for (const prefix of p) {
    for (const tld of t) {
      out.add(`${prefix}.${tld}`);
    }
  }
  return [...out].sort();
}
