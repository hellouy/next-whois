/**
 * HTTP WHOIS scraper for .tt ccTLD (Trinidad and Tobago)
 * Registry: TTNIC — Trinidad and Tobago Network Information Centre
 *
 * Technical situation:
 * - No TCP WHOIS (port 43) server for .tt (whois.nic.tt does not resolve)
 * - No RDAP endpoint in the IANA bootstrap (rdap.nic.tt ENOTFOUND)
 * - Web WHOIS available at https://www.nic.tt/cgi-bin/search.pl
 *   → HTML form POST with field `name` (domain) + `Search`
 *   → Registered domain → 200 with a <table class="data"> of key/value rows:
 *       Domain Name / Registrant Name / Registrant Address / DNS Hostnames /
 *       DNS IP Addresses / Registration Date / Expiration Date (+ ACTIVE) /
 *       Administrative / Technical / Billing Contact (redacted)
 *   → Unregistered domain → 200 with "This Domain Name is available."
 *
 * Dates are "Oct 15, 2006" (English month) and are converted to ISO
 * (YYYY-MM-DD) so the generic WHOIS parser can read them.
 */

import { load } from "cheerio";

const NIC_TT_WHOIS = "https://www.nic.tt/cgi-bin/search.pl";
const TIMEOUT_MS = 9_000;

const MONTHS: Record<string, string> = {
  Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
  Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
};

export type NicTtResult =
  | {
      success: true;
      domain: string;
      registrant: string;
      registrantAddress: string;
      nameservers: string[];
      createdDate: string;
      expiresDate: string;
      status: string[];
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

/** Convert "Oct 15, 2006" → "2006-10-15"; pass through anything else. */
function toIsoDate(value: string): string {
  const m = /^([A-Za-z]{3})\s+(\d{1,2}),\s+(\d{4})/.exec(value.trim());
  if (!m) return value.trim();
  const mon = MONTHS[m[1]];
  if (!mon) return value.trim();
  return `${m[3]}-${mon}-${m[2].padStart(2, "0")}`;
}

/** Parse the <table class="data"> key/value rows into a flat map. */
function parseDataTable(html: string): Record<string, string> {
  const $ = load(html);
  const fields: Record<string, string> = {};
  $("table.data tr").each((_, tr) => {
    const tds = $(tr)
      .find("td")
      .map((__, td) => $(td).text().replace(/\s+/g, " ").trim())
      .get();
    if (tds.length >= 2 && tds[0]) {
      fields[tds[0].replace(/:\s*$/, "")] = tds[1];
    }
  });
  return fields;
}

export async function lookupNicTt(domain: string): Promise<NicTtResult> {
  const cleanDomain = domain
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .replace(/\.+$/, "")
    .trim();

  let html: string;
  try {
    const res = await fetch(NIC_TT_WHOIS, {
      method: "POST",
      signal: makeSignal(),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded",
        Referer: NIC_TT_WHOIS,
      },
      body: `name=${encodeURIComponent(cleanDomain)}&Search=Search`,
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

  // "This Domain Name is available." → not registered
  if (/This Domain Name is available/i.test(html)) {
    return { success: false, blocked: false, reason: "Domain not found or not registered" };
  }

  const fields = parseDataTable(html);
  if (!fields["Domain Name"]) {
    return {
      success: false,
      blocked: false,
      reason: "Unexpected response from nic.tt",
    };
  }

  const domainName = fields["Domain Name"] || cleanDomain;
  const nameservers = (fields["DNS Hostnames"] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const createdDate = toIsoDate(fields["Registration Date"] || "");
  const expiresDate = toIsoDate(fields["Expiration Date"] || "");

  // Build normalized WHOIS text using keys the generic parser understands
  const lines: string[] = [`Domain Name: ${domainName}`];
  if (fields["Registrant Name"]) {
    lines.push(`Registrar: TTNIC — Trinidad and Tobago Network Information Centre (.tt Registry)`);
    lines.push(`Registrant Name: ${fields["Registrant Name"]}`);
  }
  if (fields["Registrant Address"] && !/redacted/i.test(fields["Registrant Address"])) {
    lines.push(`Registrant Street: ${fields["Registrant Address"]}`);
  }
  if (nameservers.length > 0) {
    lines.push(`Name Server: ${nameservers.join(", ")}`);
  }
  if (createdDate) {
    lines.push(`Creation Date: ${createdDate}`);
  }
  if (expiresDate) {
    lines.push(`Registry Expiry Date: ${expiresDate}`);
  }
  lines.push(`Status: Active`);
  lines.push(`>>> Source: nic.tt web WHOIS <<<`);

  const rawWhoisContent = lines.filter((l) => l || true).join("\n").trim();

  return {
    success: true,
    domain: domainName,
    registrant: fields["Registrant Name"] || "",
    registrantAddress: fields["Registrant Address"] || "",
    nameservers,
    createdDate,
    expiresDate,
    status: ["Active"],
    rawWhoisContent,
  };
}
