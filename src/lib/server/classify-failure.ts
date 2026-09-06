/**
 * Failure reason classification for the TLD failure events pipeline.
 *
 * Maps low-level query errors onto a stable, aggregatable enum so the admin
 * failure dashboard can bucket reasons across suffixes. Legacy string reasons
 * (from the old tld_fallback_stats counter) are preserved for backward
 * compatibility during the transition.
 */

export const FAILURE_REASONS = [
  "no_server",          // no public WHOIS/RDAP server sources configured
  "dns_failure",        // hostname resolution failure (ENOTFOUND/EAI_AGAIN)
  "connect_timeout",    // TCP connect / overall query timed out
  "socket_error",       // refused / reset / aborted / hang-up / EPIPE
  "http_blocked",       // 403 / Cloudflare challenge / bot detection
  "http_not_found",     // 404
  "http_server_error",  // 5xx
  "rdap_error",         // RDAP HTTP / parse failure
  "empty_response",     // server answered with no recognizable payload
  "parse_error",        // payload present but no fields could be parsed
  "rate_limited",       // 429 / local rate limit
  "third_party_failed", // third-party lookup API fallback also failed
  "iana_fallback",      // routed to IANA fallback path
  "unknown",
] as const;

export type FailureReason = (typeof FAILURE_REASONS)[number];

export function isFailureReason(v: string): v is FailureReason {
  return (FAILURE_REASONS as readonly string[]).includes(v);
}

/**
 * Normalize a legacy reason string or classify an error message into a stable
 * FailureReason. Explicit user-supplied reasons (from call sites that already
 * know the category) win over message heuristics.
 */
export function classifyFailure(
  errorMsg: string | undefined,
  legacyReason?: string,
): FailureReason {
  if (legacyReason) {
    // Reason already expressed in the new enum → use it directly.
    if (isFailureReason(legacyReason)) return legacyReason;
    // Legacy values from the old tld_fallback_stats counter.
    if (legacyReason === "timeout") return "connect_timeout";
  }

  const m = (errorMsg ?? "").toLowerCase();
  if (!m) return legacyReason === "no_server" ? "no_server" : "unknown";

  // DNS detection first: resolution failures that also mention timeouts are DNS
  // (e.g. "DNS request timed out"), distinct from a connect timeout on the socket.
  if (/enotfound|eai_again|getaddrinfo|nxdomain| EAI_ /i.test(m)) return "dns_failure";
  if (/dns/i.test(m) && /timed out|timeout/i.test(m)) return "dns_failure";
  if (/etimedout|timed out|timeout/i.test(m)) return "connect_timeout";
  if (/econnrefused|econnreset|econnaborted|socket hang up|epipe|broken pipe/i.test(m)) {
    return "socket_error";
  }
  if (/forbidden|cloudflare|challenge|captcha|access denied|blocked/i.test(m) || /\b403\b/.test(m)) {
    return "http_blocked";
  }
  if (/not found|404/i.test(m)) return "http_not_found";
  if (/(^|\D)[5]\d\d(\D|$)/.test(m)) return "http_server_error";
  if (/rate|429|too many/i.test(m)) return "rate_limited";
  if (/empty response|empty whois|zero bytes|no content|returned no data|nothing to parse/i.test(m)) {
    return "empty_response";
  }
  if (/parse|unparseable|unrecognized|invalid json/i.test(m)) return "parse_error";
  return "unknown";
}