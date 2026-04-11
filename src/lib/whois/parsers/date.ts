/**
 * Date-format parsing utilities for WHOIS field values.
 *
 * Handles the wide variety of date/time strings returned by registries
 * worldwide and normalises them to ISO-8601.
 *
 * Also exports applyParams(), which enriches a WhoisAnalyzeResult with
 * computed domain-age, remaining-days and pricing data.
 */

import moment from "moment";
import { WhoisAnalyzeResult } from "@/lib/whois/types";
import { getDomainPricing, getDomainTransferNegotiable } from "@/lib/pricing/client";

// ── Supported date formats (moment strict-mode list) ─────────────────────────

export const DATE_FORMATS = [
  "YYYY-MM-DDTHH:mm:ssZ",
  "YYYY-MM-DDTHH:mm:ss.SSSZ",
  "YYYY-MM-DDTHH:mm:ssZZ",
  "YYYY-MM-DD HH:mm:ss",
  "YYYY-MM-DD HH:mm:ssZ",
  "YYYY-MM-DD",
  "DD.MM.YYYY HH:mm:ss",
  "DD.MM.YYYY HH:mm",
  "DD.MM.YYYY",
  "DD-MM-YYYY HH:mm:ss",
  "DD-MM-YYYY",
  "MM/DD/YYYY HH:mm:ss",
  "MM/DD/YYYY",
  "YYYY/MM/DD HH:mm:ss",
  "YYYY/MM/DD",
  "YYYY.MM.DD HH:mm:ss",
  "YYYY.MM.DD",
  "DD MMM YYYY",
  "DD-MMM-YYYY",
  "MMM DD YYYY",
  "MMM DD, YYYY",
  "D-MMM-YYYY",
  "YYYYMMDD",
  "YYYY-MM-DDTHH:mm:ss.SSS[Z]",
  "ddd MMM DD HH:mm:ss [UTC] YYYY",
  "ddd, DD MMM YYYY HH:mm:ss ZZ",
  "DD/MM/YYYY HH:mm:ss",
  "DD/MM/YYYY",
  "D MMM YYYY",
  "D MMMM YYYY HH:mm:ss",
  "D MMMM YYYY HH:mm",
  "D MMMM YYYY",
  "YYYY-MM-DD HH:mm:ss UTC",
  "YYYY-MM-DDZ",
  "MM-DD-YYYY",
  "YYYY MM DD",
  "D/M/YYYY",
  "D.M.YYYY",
];

export const DATE_REGEX =
  /\b(\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)?|\d{2}[.\/\-]\d{2}[.\/\-]\d{4}(?:\s+\d{2}:\d{2}(?::\d{2})?)?|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4}|\d{4}[.\/]\d{2}[.\/]\d{2})\b/i;

// ── Core parsing ─────────────────────────────────────────────────────────────

/**
 * Scan a raw WHOIS text for a date near one of the given keywords.
 * Returns the first ISO-8601 date found on a matching line, or "".
 */
export function extractDateNearKeyword(raw: string, keywords: string[]): string {
  const lines = raw.split("\n");
  for (const line of lines) {
    const lower = line.toLowerCase();
    const hasKeyword = keywords.some((kw) => lower.includes(kw));
    if (!hasKeyword) continue;
    const m = line.match(DATE_REGEX);
    if (m) {
      const parsed = analyzeTime(m[1]);
      if (parsed && parsed !== m[1]) return parsed;
    }
  }
  return "";
}

/**
 * Parse a single date/time string into ISO-8601.
 * Returns the original string if parsing fails.
 */
export function analyzeTime(time: string): string {
  if (!time || time.length === 0) return time;
  try {
    let cleaned = time
      .replace(/<|>/g, "")
      .replace(/\[.*?\]/g, "")
      .trim();

    const beforePrefix = cleaned.match(/^before\s+(.+)$/i);
    if (beforePrefix) cleaned = beforePrefix[1].trim();

    const parenMatch = cleaned.match(/^(.+?)\s*\(.*?\)\s*$/);
    if (parenMatch) cleaned = parenMatch[1].trim();

    const m = moment(cleaned, DATE_FORMATS, true);
    if (m.isValid()) return m.toISOString();

    const mLenient = moment(cleaned, DATE_FORMATS, false);
    if (mLenient.isValid()) return mLenient.toISOString();

    const native = new Date(cleaned);
    if (!isNaN(native.getTime())) return native.toISOString();

    return time;
  } catch {
    return time;
  }
}

// ── Domain age / expiry calculations ────────────────────────────────────────

export function calculateDomainAge(creationDate: string): number {
  if (creationDate === "Unknown") return 0;
  return moment().diff(moment(creationDate), "years");
}

export function calculateRemainingDays(expirationDate: string): number {
  if (expirationDate === "Unknown") return 0;
  return Math.max(0, moment(expirationDate).diff(moment(), "days"));
}

// ── Post-parse enrichment ────────────────────────────────────────────────────

/**
 * Enrich a WhoisAnalyzeResult with computed age/remaining-days and
 * pricing data fetched from the pricing client.
 */
export async function applyParams(result: WhoisAnalyzeResult): Promise<WhoisAnalyzeResult> {
  result.domainAge =
    !result.creationDate || result.creationDate === "Unknown"
      ? null
      : calculateDomainAge(result.creationDate);
  result.remainingDays =
    !result.expirationDate || result.expirationDate === "Unknown"
      ? null
      : calculateRemainingDays(result.expirationDate);

  const [registerPrice, renewPrice, negotiable] = await Promise.all([
    getDomainPricing(result.domain, "new"),
    getDomainPricing(result.domain, "renew"),
    getDomainTransferNegotiable(result.domain),
  ]);
  result.registerPrice = registerPrice;
  result.renewPrice = renewPrice;
  result.negotiable = negotiable;

  return result;
}
