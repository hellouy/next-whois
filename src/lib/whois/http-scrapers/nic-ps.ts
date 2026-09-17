/**
 * HTTP WHOIS scraper for .ps ccTLD (Palestine)
 * Registry: PNINA — Palestinian National Internet Naming Authority
 *            https://www.pnina.ps/
 *
 * Technical situation:
 * - TCP WHOIS (port 43) whois.pnina.ps resolves (65.21.199.175) but silently
 *   drops cloud/datacenter connections — connects, returns 0 bytes.
 * - No RDAP endpoint (rdap.nic.ps ENOTFOUND).
 * - Web WHOIS available at https://www.pnina.ps/whois/?domain=<domain>
 *   → WordPress + Cloudflare-rendered HTML with two tabs:
 *     "Pretty" (#whois-pretty): <dl class="row"> with <dt>/<dd> pairs
 *     "Raw"    (#whois-raw):    <pre> containing standard WHOIS text
 *       (Domain Name / Creation Date / Registry Expiry Date / Domain Status /
 *        Name Server / Registrar / Registrant / DNSSEC / ...)
 *   → Registered domain → 200 with the tab structure + <pre> data
 *   → Unregistered domain → may return the same page structure with no
 *     "Domain Name:" line in the <pre>, OR may trigger Cloudflare bot challenge
 *
 * Cloudflare bot protection:
 *   The site sits behind Cloudflare bot management. The first request from a
 *   given datacenter IP typically succeeds; subsequent rapid requests receive
 *   a JavaScript challenge page ("Please wait while your request is being
 *   verified..."). On Vercel, each Lambda invocation may use a different
 *   egress IP, giving the scraper a chance to succeed. When challenged, the
 *   scraper returns blocked=true so the lookup engine surfaces a link to the
 *   registry's web WHOIS for manual verification.
 *
 * The extracted <pre> text is standard "Key: Value" WHOIS format, directly
 * consumable by the generic parser (analyzeWhois).
 *
 * Note: registrar email values are Cloudflare-email-obfuscated inside the
 * <pre> (visible as "[email protected]" placeholder). Registrant contact
 * data is GDPR-redacted by the registry itself ("Redacted | EU Registrar").
 */

import { load } from "cheerio";

const PNINA_WHOIS = "https://www.pnina.ps/whois/";
const TIMEOUT_MS = 9_000;

export type NicPsResult =
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

/**
 * Detect Cloudflare bot-protection challenge pages.
 * The challenge page contains a verification message and heavy obfuscated JS,
 * but none of the WHOIS result structure (#whois-raw, <pre>, <dl class="row">).
 */
function isCloudflareChallenge(html: string): boolean {
  if (/Please wait while your request is being verified/i.test(html)) {
    return true;
  }
  if (/id="text"[^>]*>\s*Please/i.test(html)) {
    return true;
  }
  return false;
}

export async function lookupNicPs(domain: string): Promise<NicPsResult> {
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
    const res = await fetch(
      `${PNINA_WHOIS}?domain=${encodeURIComponent(cleanDomain)}`,
      {
        method: "GET",
        signal: makeSignal(),
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
        },
        redirect: "follow",
      },
    );
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

  if (isCloudflareChallenge(html)) {
    return {
      success: false,
      blocked: true,
      reason: "Cloudflare bot protection challenge — automated WHOIS lookup is temporarily unavailable, please check the registry directly",
    };
  }

  const $ = load(html);
  const preText = $("#whois-raw pre").first().text().replace(/\r/g, "").trim();

  if (!preText) {
    const prettyExists = $("#whois-pretty").length > 0;
    return {
      success: false,
      blocked: false,
      reason: prettyExists
        ? "Domain not found or not registered"
        : "Unexpected response from pnina.ps",
    };
  }

  if (!/^Domain Name:/im.test(preText)) {
    return { success: false, blocked: false, reason: "Domain not found or not registered" };
  }

  return { success: true, rawWhoisContent: preText };
}
