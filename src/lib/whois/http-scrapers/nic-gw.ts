/**
 * HTTP WHOIS scraper for .gw ccTLD (Guinea-Bissau)
 * Registry: ARN – Autoridade Reguladora Nacional — https://registar.nic.gw/
 *
 * Technical situation:
 * - No TCP WHOIS (port 43) server for .gw (whois.nic.gw does not resolve)
 * - No RDAP endpoint in the IANA bootstrap
 * - Web WHOIS available at https://registar.nic.gw/en/whois/<domain>/
 *   → WordPress-rendered HTML; data lives in <fieldset> blocks:
 *     <span>Section</span> + <label>Key:</label> followed by a bare text node
 *     or an <a> element holding the value
 *   - Registered domain → 200 with fieldsets (General data / Registrant /
 *     Administrative Contact)
 *   - Unregistered domain → HTTP 404 (WordPress 404 page)
 *
 * Dates are DD/MM/YYYY on the site and are converted to ISO (YYYY-MM-DD)
 * so the generic WHOIS parser can read them.
 */

import { load } from "cheerio";

const NIC_GW_WHOIS = "https://registar.nic.gw/en/whois";
const TIMEOUT_MS = 9_000;

export type NicGwResult =
  | { success: true; rawWhoisContent: string }
  | { success: false; blocked: boolean; reason: string };

function makeSignal(): AbortSignal {
  if (typeof AbortSignal !== "undefined" && "timeout" in AbortSignal) {
    return (AbortSignal as any).timeout(TIMEOUT_MS);
  }
  const ac = new AbortController();
  setTimeout(() => ac.abort(), TIMEOUT_MS);
  return ac.signal;
}

/** Convert "29/07/2014" → "2014-07-29"; pass through anything else. */
function toIsoDate(value: string): string {
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(value.trim());
  return m ? `${m[3]}-${m[2]}-${m[1]}` : value.trim();
}

/**
 * Parse all <fieldset> blocks inside the whois <article> into
 * { "Section Name": { "Key": "Value" } }.
 * Keys are <label> elements; values are the following text node or <a>.
 */
function parseFieldsets(html: string): Record<string, Record<string, string>> {
  const $ = load(html);
  const sections: Record<string, Record<string, string>> = {};

  $("article fieldset").each((_, fs) => {
    const $fs = $(fs);
    let section = "";
    let currentKey: string | null = null;
    const fields: Record<string, string> = {};

    $fs.contents().each((__, node) => {
      if (node.type === "text") {
        const text = (node.data || "").trim();
        if (text && currentKey) {
          fields[currentKey] = text;
          currentKey = null;
        }
        return;
      }
      if (node.type !== "tag") return;

      const el = $(node);
      const tag = (node as any).tagName?.toLowerCase() ?? (node as any).name;

      if (tag === "span") {
        section = el.text().trim();
        return;
      }
      if (tag === "label") {
        currentKey = el.text().replace(/:\s*$/, "").trim();
        return;
      }
      if (tag === "a" && currentKey) {
        const value = el.text().trim();
        if (value) {
          fields[currentKey] = value;
          currentKey = null;
        }
        return;
      }
      // <form> (anonymous contact form) and everything else: ignore
    });

    if (section && Object.keys(fields).length > 0) {
      sections[section] = fields;
    }
  });

  return sections;
}

export async function lookupNicGw(domain: string): Promise<NicGwResult> {
  const cleanDomain = domain
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .split("/")[0]
    .replace(/\.+$/, "")
    .trim();

  let html: string;
  try {
    const res = await fetch(`${NIC_GW_WHOIS}/${encodeURIComponent(cleanDomain)}/`, {
      signal: makeSignal(),
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
      },
      redirect: "follow",
    });
    if (res.status === 404) {
      // Unregistered .gw domains get the WordPress 404 page
      return { success: false, blocked: false, reason: "Domain not found or not registered" };
    }
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

  // Sanity check: registered-domain pages contain the fieldset structure
  if (!/<fieldset/i.test(html)) {
    return {
      success: false,
      blocked: false,
      reason: "Unexpected response from registar.nic.gw",
    };
  }

  const sections = parseFieldsets(html);
  const general = sections["General data"] || {};
  const registrant = sections["Registrant"] || {};
  const admin = sections["Administrative Contact"] || {};

  // <header class="title"><h2>nic.gw</h2> — fall back to the query domain
  const headerTitle = load(html)("header.title h2").first().text().trim();
  const domainName = headerTitle || cleanDomain;

  // Build normalized WHOIS text using keys the generic parser understands
  const lines: string[] = [`Domain Name: ${domainName}`];

  if (general["Submission Date"]) {
    lines.push(`Creation Date: ${toIsoDate(general["Submission Date"])}`);
  }
  if (general["Expiration Date"]) {
    lines.push(`Registry Expiry Date: ${toIsoDate(general["Expiration Date"])}`);
  }
  if (general["Status"]) {
    lines.push(`Status: ${general["Status"]}`);
  }
  if (registrant["Name"]) {
    lines.push(`Registrar: ARN - Autoridade Reguladora Nacional (.gw Registry)`);
    lines.push(`Registrant Name: ${registrant["Name"]}`);
  }
  if (registrant["Address"]) {
    lines.push(`Registrant Street: ${registrant["Address"]}`);
  }
  if (registrant["Phone"]) {
    lines.push(`Registrant Phone: ${registrant["Phone"]}`);
  }
  if (registrant["E-mail"]) {
    lines.push(`Registrant Email: ${registrant["E-mail"]}`);
  }
  if (admin["Name"]) {
    lines.push(`Admin Name: ${admin["Name"]}`);
  }
  if (admin["Address"]) {
    lines.push(`Admin Street: ${admin["Address"]}`);
  }
  if (admin["Phone"]) {
    lines.push(`Admin Phone: ${admin["Phone"]}`);
  }
  if (admin["E-mail"]) {
    lines.push(`Admin Email: ${admin["E-mail"]}`);
  }
  lines.push(`>>> Source: registar.nic.gw web WHOIS <<<`);

  const rawWhoisContent = lines.filter((l, i) => l || i === 0).join("\n").trim();

  if (rawWhoisContent.split("\n").length < 3) {
    return {
      success: false,
      blocked: false,
      reason: "Could not parse WHOIS data from registar.nic.gw",
    };
  }

  return { success: true, rawWhoisContent };
}
