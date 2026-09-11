/**
 * HTTP WHOIS scraper for .gm ccTLD (Gambia)
 * Registry: GM-NIC (managed by CYPDOM)
 *
 * Technical situation:
 * - TCP WHOIS (port 43) on nic.gm accepts connections but never responds
 * - whois.nic.gm / whois.gm do not resolve; no RDAP endpoint in IANA bootstrap
 * - Web WHOIS available at https://www.nic.gm/NIC2/search.html
 *   → form GET to /NIC2/scripts/checkdom.aspx?dname=<sld>
 *   → The server answers with a 302 redirect whose Location encodes the result:
 *       /NIC2/whois-details.html?dname=x   → domain is REGISTERED
 *       /NIC2/whois-available.html?dname=x → domain is AVAILABLE
 *       /NIC2/whois-reserved.html?dname=x  → domain is RESERVED/PREMIUM
 *   → The details page renders a <table> whose cells (registrar, dates, name
 *     servers) are normally empty — the server only reliably exposes the
 *     registered/available/reserved tri-state, so we treat an empty details
 *     page as "registered" with unknown extra fields.
 */

import { load } from "cheerio";

const GM_CHECK_WHOIS = "https://www.nic.gm/NIC2/scripts/checkdom.aspx";
const TIMEOUT_MS = 9_000;

export type NicGmResult =
  | {
      success: true;
      domain: string;
      reserved: boolean;
      registrar: string;
      registrationDate: string;
      nameservers: string[];
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

function extractField(html: string, id: string): string {
  const $ = load(html);
  return $(`#${id}`).text().replace(/\s+/g, " ").trim();
}

function extractNameServers(html: string): string[] {
  const $ = load(html);
  const ns: string[] = [];
  for (let i = 1; i <= 4; i++) {
    const value = $(`#name-server-${i}`).text().replace(/\s+/g, " ").trim();
    if (value) ns.push(value);
  }
  return ns;
}

async function getHtml(url: string, ua: string): Promise<string> {
  const res = await fetch(url, {
    method: "GET",
    signal: makeSignal(),
    headers: {
      "User-Agent": ua,
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      Referer: "https://www.nic.gm/NIC2/search.html",
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

export async function lookupNicGm(domain: string): Promise<NicGmResult> {
  const sld = domain
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .replace(/\.gm$/i, "")
    .replace(/\.+$/, "")
    .replace(/[^a-z0-9-]/g, "")
    .trim();

  if (!sld) {
    return { success: false, blocked: false, reason: "Invalid domain name" };
  }

  const ua =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
  const checkUrl = `${GM_CHECK_WHOIS}?dname=${encodeURIComponent(sld)}`;
  const fullDomain = `${sld}.gm`;

  // ── Step 1: hit checkdom.aspx and read the 302 Location (the tri-state) ─────
  let location = "";
  try {
    const res = await fetch(checkUrl, {
      method: "GET",
      redirect: "manual",
      signal: makeSignal(),
      headers: {
        "User-Agent": ua,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        Referer: "https://www.nic.gm/NIC2/search.html",
      },
    });
    location = res.headers.get("location") || "";
    if (!location && res.ok) {
      // No redirect — parse the body directly as a fallback.
      const html = await res.text();
      if (/whois-available|is available/i.test(html)) {
        return { success: false, blocked: false, reason: "Domain not found or not registered" };
      }
      if (/whois-reserved|reserved\/premium/i.test(html)) {
        return {
          success: true, domain: fullDomain, reserved: true,
          registrar: "", registrationDate: "", nameservers: [],
          status: ["registry-reserved"],
          rawWhoisContent: `Domain Name: ${fullDomain}\nStatus: registry-reserved\n>>> Source: nic.gm web WHOIS <<<`,
        };
      }
      if (/whois-details|is registered/i.test(html)) {
        return {
          success: true, domain: fullDomain, reserved: false,
          registrar: "", registrationDate: "", nameservers: [],
          status: ["Active"],
          rawWhoisContent: `Domain Name: ${fullDomain}\nStatus: Active\n>>> Source: nic.gm web WHOIS <<<`,
        };
      }
      return { success: false, blocked: false, reason: "Unexpected response from nic.gm" };
    }
    if (!location) {
      return { success: false, blocked: false, reason: "Unexpected response from nic.gm" };
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      blocked: /timeout|aborted|timed out|HTTP 4|HTTP 5/i.test(msg),
      reason: msg,
    };
  }

  // ── Step 2: interpret the redirect target ────────────────────────────────────
  if (location.includes("whois-available")) {
    return { success: false, blocked: false, reason: "Domain not found or not registered" };
  }

  if (location.includes("whois-reserved")) {
    return {
      success: true, domain: fullDomain, reserved: true,
      registrar: "", registrationDate: "", nameservers: [],
      status: ["registry-reserved"],
      rawWhoisContent: `Domain Name: ${fullDomain}\nStatus: registry-reserved\n>>> Source: nic.gm web WHOIS <<<`,
    };
  }

  if (location.includes("whois-details")) {
    // Registered. Try to pull whatever extra fields the details page exposes
    // (usually empty — the registry does not render them server-side).
    let registrar = "";
    let registrationDate = "";
    let nameservers: string[] = [];
    try {
      const detailsUrl = new URL(location, "https://www.nic.gm").toString();
      const html = await getHtml(detailsUrl, ua);
      registrar = extractField(html, "registrar-name");
      registrationDate = extractField(html, "registration-date");
      nameservers = extractNameServers(html);
    } catch {
      /* details page unavailable — registration state alone is still valid */
    }
    const lines = [`Domain Name: ${fullDomain}`];
    if (registrar) lines.push(`Registrar: ${registrar}`);
    if (registrationDate) lines.push(`Creation Date: ${registrationDate}`);
    if (nameservers.length > 0) lines.push(`Name Server: ${nameservers.join(", ")}`);
    lines.push("Status: Active");
    lines.push(">>> Source: nic.gm web WHOIS <<<");
    return {
      success: true, domain: fullDomain, reserved: false,
      registrar, registrationDate, nameservers,
      status: ["Active"],
      rawWhoisContent: lines.join("\n"),
    };
  }

  return { success: false, blocked: false, reason: "Unexpected response from nic.gm" };
}
