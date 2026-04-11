/**
 * HTTP WHOIS scraper for .ph ccTLD (Philippines)
 * Registry: Dot PH (dotPH) — https://whois.dot.ph/
 *
 * Technical situation:
 * - TCP WHOIS (port 43) to whois.dot.ph times out from non-PH cloud IPs
 * - RDAP: no public RDAP endpoint in the IANA bootstrap
 * - HTTP WHOIS available at https://whois.dot.ph/whois?search=<domain>
 *   → server-rendered HTML; domain data is in a <pre> block inside #result-whois
 *   → dates are injected by JavaScript: var createDate = moment('ISO_DATE')
 *     so they must be extracted from the <script> source, not from the DOM text
 *
 * "Domain is available." in #alert-message  → domain not registered
 */

import { load } from "cheerio";

const DOTPH_WHOIS = "https://whois.dot.ph/whois";
const TIMEOUT_MS = 9_000;

export type NicPhResult =
  | {
      success: true;
      domain: string;
      status: string[];
      registrant: string;
      registrantOrg: string;
      registrar: string;
      createdDate: string;
      updatedDate: string;
      expiresDate: string;
      nameservers: string[];
      rawWhoisContent: string;
    }
  | { success: false; blocked: boolean; reason: string };

function makeSignal(): AbortSignal {
  if (typeof AbortSignal !== "undefined" && "timeout" in AbortSignal) {
    return (AbortSignal as any).timeout(TIMEOUT_MS);
  }
  const ac = new AbortController();
  setTimeout(() => ac.abort(), TIMEOUT_MS);
  return ac.signal;
}

/** Extract ISO date string from: var <varName> = moment('ISO_DATE').format(...) */
function extractMomentDate(scripts: string, varName: string): string {
  const re = new RegExp(`var\\s+${varName}\\s*=\\s*moment\\('([^']+)'\\)`);
  const m = re.exec(scripts);
  return m ? m[1] : "";
}

/** Parse the first value for a key like "Registrar: Value" */
function parseLine(lines: string[], key: string): string {
  const prefix = key.toLowerCase() + ":";
  for (const line of lines) {
    const t = line.trim();
    if (t.toLowerCase().startsWith(prefix)) {
      return t.slice(prefix.length).trim();
    }
  }
  return "";
}

/** Parse all values for a repeating key like "Name Server: ns1.example.com" */
function parseAllLines(lines: string[], key: string): string[] {
  const prefix = key.toLowerCase() + ":";
  return lines
    .map(l => l.trim())
    .filter(l => l.toLowerCase().startsWith(prefix))
    .map(l => l.slice(prefix.length).trim())
    .filter(Boolean);
}

export async function lookupNicPh(domain: string): Promise<NicPhResult> {
  const cleanDomain = domain.toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .trim();

  let html: string;
  try {
    const url = `${DOTPH_WHOIS}?search=${encodeURIComponent(cleanDomain)}`;
    const res = await fetch(url, {
      signal: makeSignal(),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        Referer: "https://whois.dot.ph/",
      },
      redirect: "follow",
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

  // Cloudflare / rate-limit check
  if (
    html.toLowerCase().includes("captcha") ||
    html.toLowerCase().includes("too many requests") ||
    html.toLowerCase().includes("access denied")
  ) {
    return { success: false, blocked: true, reason: "Rate limited or CAPTCHA required" };
  }

  // "Domain is available." in #alert-message → not registered
  const alertText = $("#alert-message").text().trim().toLowerCase();
  if (
    alertText.includes("available") ||
    alertText.includes("not found") ||
    alertText.includes("does not exist")
  ) {
    return { success: false, blocked: false, reason: "Domain not found or not registered" };
  }

  // Grab the <pre> inside #result-whois
  const preHtml = $("#result-whois pre").html() || "";
  if (!preHtml) {
    return {
      success: false,
      blocked: false,
      reason: alertText.length > 0 ? alertText : "Unexpected response from whois.dot.ph",
    };
  }

  // Convert <br> to newlines, strip remaining tags, decode HTML entities
  const preText = preHtml
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x2F;/g, "/")
    .replace(/&nbsp;/g, " ");

  const lines = preText.split("\n").map(l => l.trim()).filter(l => l.length > 0);

  // Dates are NOT in the visible HTML — they are injected by client-side JS:
  //   var createDate = moment('2016-08-16T07:43:22Z').format(...)
  // Extract the ISO timestamp directly from the <script> source.
  const allScripts = $("script")
    .map((_, el) => $(el).html() || "")
    .get()
    .join("\n");
  const createdDate = extractMomentDate(allScripts, "createDate");
  const expiresDate = extractMomentDate(allScripts, "expiryDate");
  const updatedDate = extractMomentDate(allScripts, "updateDate");

  // Parse key fields from the <pre> lines
  const statusRaw    = parseLine(lines, "Status");
  const statuses: string[] = statusRaw
    ? statusRaw.split(",").map(s => s.trim()).filter(Boolean)
    : ["Active"];

  const registrar       = parseLine(lines, "Registrar");
  const registrantName  = parseLine(lines, "Registrant Name");
  const registrantOrg   = parseLine(lines, "Registrant Organization");
  const nameservers     = parseAllLines(lines, "Name Server");

  // Build a clean raw text with real dates filled in
  const rawLines: string[] = [];
  for (const line of lines) {
    const t = line.toLowerCase();
    if (t.startsWith("creation date:") && createdDate) {
      rawLines.push(`Creation Date: ${createdDate}`);
    } else if (t.startsWith("expiration date:") && expiresDate) {
      rawLines.push(`Expiration Date: ${expiresDate}`);
    } else if (t.startsWith("updated date:") && updatedDate) {
      rawLines.push(`Updated Date: ${updatedDate}`);
    } else if (t.startsWith("whois info for")) {
      // skip header line
    } else {
      rawLines.push(line);
    }
  }
  const rawWhoisContent = rawLines.join("\n").trim();

  if (!registrar && nameservers.length === 0 && !statusRaw) {
    return {
      success: false,
      blocked: false,
      reason: "Could not parse WHOIS data from whois.dot.ph",
    };
  }

  return {
    success: true,
    domain: cleanDomain,
    status: statuses,
    registrant: registrantName || registrantOrg || "Unknown",
    registrantOrg: registrantOrg || registrantName || "Unknown",
    registrar,
    createdDate,
    updatedDate,
    expiresDate,
    nameservers,
    rawWhoisContent,
  };
}
