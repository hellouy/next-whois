/**
 * WHOIS handler for .bb ccTLD (Barbados)
 * Registry: Barbados Telecommunications Unit
 * Website:  https://www.telecoms.gov.bb/
 *
 * Technical situation:
 * - WHOIS server: whois.telecoms.gov.bb (IP: 3.99.77.191, AWS ca-central-1)
 * - Port 43 TCP is firewalled for cloud/commercial IP ranges (AWS, Vercel, GCP, Azure).
 *   It responds only from residential / non-cloud IPs.
 * - No public RDAP endpoint.
 * - No accessible HTTP/HTTPS WHOIS query API (www.whois.telecoms.gov.bb is also blocked).
 *
 * This module does a short TCP probe (3 s). If it succeeds (non-cloud environment)
 * the raw WHOIS text is returned. If it times out (cloud infrastructure) the caller
 * receives a structured result so the UI can render a "manual lookup" card instead
 * of a generic timeout error.
 */

import { queryWhoisTcp } from "@/lib/whois/whois-transport";

export const BB_WHOIS_HOST = "whois.telecoms.gov.bb";
export const BB_REGISTRY_URL = "https://www.telecoms.gov.bb/";

const BB_CLOUD_BLOCK_NOTE =
  "The .bb WHOIS server restricts access to residential/ISP IPs — " +
  "cloud infrastructure (Vercel, AWS, GCP, Azure) is blocked at the network level. " +
  "Use the registry website link below to look up .bb domains manually.";

export type TelecomsBbResult =
  | { success: true; raw: string }
  | { success: false; blocked: boolean; reason: string };

export async function lookupTelecomsBb(
  domain: string,
  timeoutMs = 3_000,
): Promise<TelecomsBbResult> {
  try {
    const raw = await queryWhoisTcp(BB_WHOIS_HOST, 43, domain, timeoutMs);
    if (!raw || !raw.trim()) {
      return { success: false, blocked: false, reason: "WHOIS server connected but returned no data" };
    }
    return { success: true, raw };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const isTimeout = /timeout|timed.?out|ETIMEDOUT|EHOSTUNREACH/i.test(msg);
    const isRefused = /ECONNREFUSED|ECONNRESET/i.test(msg);
    return {
      success: false,
      blocked: isTimeout,
      reason: isTimeout
        ? BB_CLOUD_BLOCK_NOTE
        : isRefused
        ? "Connection refused by .bb WHOIS server"
        : `Connection error: ${msg.slice(0, 120)}`,
    };
  }
}
