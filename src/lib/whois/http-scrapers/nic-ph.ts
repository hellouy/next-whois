/**
 * HTTP WHOIS scraper for .ph ccTLD (Philippines)
 * Registry: Dot PH / Domain Administration Inc.
 * Website: https://www.nic.ph
 *
 * Technical situation:
 * - TCP WHOIS (port 43) to whois.dot.ph may time out from non-PH cloud IPs
 * - RDAP: no public RDAP endpoint in IANA bootstrap
 * - HTTP WHOIS interface available at https://www.whois.ph/
 *   → returns HTML page with domain registration information
 */

const NIC_PH_WHOIS = "https://www.whois.ph/";
const TIMEOUT_MS = 9_000;

export type NicPhResult =
  | {
      success: true;
      status: string;
      registrant: string;
      registrar: string;
      createdDate: string;
      updatedDate: string;
      expiresDate: string;
      nameservers: string[];
      raw: string;
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

function extractText(html: string, pattern: RegExp): string {
  const m = html.match(pattern);
  return m ? m[1].trim() : "";
}

function extractAll(html: string, pattern: RegExp): string[] {
  const results: string[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(pattern.source, pattern.flags + (pattern.flags.includes("g") ? "" : "g"));
  while ((m = re.exec(html)) !== null) {
    if (m[1]) results.push(m[1].trim());
  }
  return results;
}

export async function lookupNicPh(domain: string): Promise<NicPhResult> {
  const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//i, "").split("/")[0];

  let html: string;
  try {
    const url = `${NIC_PH_WHOIS}?d=${encodeURIComponent(cleanDomain)}`;
    const res = await fetch(url, {
      signal: makeSignal(),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; WhoisBot/1.0; +https://github.com/IANA-WHOIS/bot)",
        Accept: "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
      },
      redirect: "follow",
    });
    if (!res.ok) {
      return { success: false, blocked: res.status === 403, reason: `HTTP ${res.status}` };
    }
    html = await res.text();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const isTimeout = /timeout|aborted/i.test(msg);
    return { success: false, blocked: isTimeout, reason: msg };
  }

  const lower = html.toLowerCase();

  // Check if domain is not found / available
  if (
    lower.includes("not found") ||
    lower.includes("no match") ||
    lower.includes("domain name not registered") ||
    lower.includes("no information available") ||
    lower.includes("available for registration")
  ) {
    return { success: false, blocked: false, reason: "Domain not found or not registered" };
  }

  // Check for CAPTCHA / rate-limiting
  if (lower.includes("captcha") || lower.includes("too many requests") || lower.includes("rate limit")) {
    return { success: false, blocked: true, reason: "Rate limited or CAPTCHA required" };
  }

  // Try to extract WHOIS data from the HTML

  // Status — look for common patterns like "Status: Active" or "Domain Status:"
  const status =
    extractText(html, /Status[:\s]+<[^>]*>([^<]+)<\/[^>]+>/i) ||
    extractText(html, /Status[:\s]+([A-Za-z][A-Za-z0-9 _-]*?)(?:<|\n|\r)/i) ||
    extractText(html, /Domain\s+Status[:\s]+([A-Za-z][A-Za-z0-9 _-]*?)(?:<|\n|\r)/i) ||
    "";

  const registrant =
    extractText(html, /Registrant[:\s]+<[^>]*>([^<]+)<\/[^>]+>/i) ||
    extractText(html, /Registrant\s+Name[:\s]+([^\n<\r]+)/i) ||
    "";

  const registrar =
    extractText(html, /Registrar[:\s]+<[^>]*>([^<]+)<\/[^>]+>/i) ||
    extractText(html, /Registrar[:\s]+([^\n<\r]+)/i) ||
    "";

  const createdDate =
    extractText(html, /Created?\s+Date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2}[^\n<\r]*)/i) ||
    extractText(html, /Registration\s+Date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2}[^\n<\r]*)/i) ||
    "";

  const updatedDate =
    extractText(html, /Updated?\s+Date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2}[^\n<\r]*)/i) ||
    "";

  const expiresDate =
    extractText(html, /Expir(?:y|ation)\s+Date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2}[^\n<\r]*)/i) ||
    extractText(html, /Expires?[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2}[^\n<\r]*)/i) ||
    "";

  // Nameservers
  const nameservers =
    extractAll(html, /Name\s*Server[:\s]+([a-z0-9][\w.-]+\.[a-z]{2,})/i).filter(Boolean) ||
    [];

  // If we got at least some data, consider it a success
  if (!registrant && !registrar && !status && nameservers.length === 0) {
    return { success: false, blocked: false, reason: "Could not parse WHOIS response from NIC.PH" };
  }

  // Extract a text representation of the relevant section
  const raw = html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/\s{3,}/g, "\n")
    .trim()
    .slice(0, 4000);

  return {
    success: true,
    status: status || "Active",
    registrant,
    registrar,
    createdDate,
    updatedDate,
    expiresDate,
    nameservers,
    raw,
  };
}
