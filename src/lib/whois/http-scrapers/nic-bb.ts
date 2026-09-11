/**
 * HTTP WHOIS scraper for .bb ccTLD (Barbados)
 * Registry: Telecommunications Unit, Government of Barbados
 *
 * Technical situation:
 * - No TCP WHOIS (port 43) server for .bb
 * - No RDAP endpoint in the IANA bootstrap
 * - Web WHOIS available at https://www.whois.telecoms.gov.bb/status/<domain>
 *   → GET the domain as a URL path segment (case-insensitive)
 *   → Registered domain → a <pre> block containing standard WHOIS text:
 *       Domain Name: BB.BB / Creation Date / Registrar / Domain Status /
 *       Registrant / Admin / Tech contacts / Name Server / DNSSEC / ...
 *   → Unregistered domain → <pre> contains only a legal disclaimer
 *     (no "Domain Name:" line)
 *
 * The extracted WHOIS text is standard-enough for the generic parser
 * (analyzeWhois) to consume directly.
 */

import { load } from "cheerio";

const BB_WHOIS = "https://www.whois.telecoms.gov.bb/status/";
const TIMEOUT_MS = 9_000;

export type NicBbResult =
  | { success: true; domain: string; rawWhoisContent: string }
  | { success: false; blocked: boolean; reason: string };

function makeSignal(): AbortSignal {
  if (typeof AbortSignal !== "undefined" && "timeout" in AbortSignal) {
    return (AbortSignal as any).timeout(TIMEOUT_MS);
  }
  const ac = new AbortController();
  setTimeout(() => ac.abort(), TIMEOUT_MS);
  return ac.signal;
}

export async function lookupNicBb(domain: string): Promise<NicBbResult> {
  const cleanDomain = domain
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .replace(/\.+$/, "")
    .trim();

  if (!cleanDomain) {
    return { success: false, blocked: false, reason: "Invalid domain name" };
  }

  let html: string;
  try {
    const res = await fetch(`${BB_WHOIS}${encodeURIComponent(cleanDomain)}`, {
      method: "GET",
      signal: makeSignal(),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
    if (!res.ok) {
      return {
        success: false,
        blocked: res.status === 403 || res.status === 429,
        reason: `HTTP ${res.status}`,
      };
    }
    html = await res.text();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      blocked: /timeout|aborted|timed out/i.test(msg),
      reason: msg,
    };
  }

  const $ = load(html);
  const preText = $("pre").first().text().replace(/\r/g, "").trim();

  // Registered responses carry a "Domain Name:" line; the availability page
  // only contains the legal disclaimer text.
  if (!/^Domain Name:/im.test(preText)) {
    return { success: false, blocked: false, reason: "Domain not found or not registered" };
  }

  return { success: true, domain: cleanDomain, rawWhoisContent: preText };
}
