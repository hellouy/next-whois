const WHOIS_ERROR_PATTERNS = [
  /no match/i,
  /not found/i,
  /no data found/i,
  /no entries found/i,
  /no object found/i,
  /nothing found/i,
  /invalid query/i,
  /^error:/im,
  /malformed/i,
  /object does not exist/i,
  /domain not found/i,
  /status:\s*free/i,
  /status:\s*available/i,
  /is available for/i,
  /no whois information/i,
  /tld is not supported/i,
  /not registered/i,
  /domain is available/i,
  /domain available/i,
  /available for registration/i,
  /available for purchase/i,
  /this domain is free/i,
];

const WHOIS_RATE_LIMIT_PATTERNS = [
  /rate.?limit/i,
  /too many (?:requests|queries)/i,
  /query.?rate.*exceeded/i,
  /exceeded.*query.?limit/i,
  /access denied/i,
  /connection refused/i,
  /temporarily.?blocked/i,
  /please.{0,20}try again later/i,
];

const WHOIS_NOT_REGISTERED_PATTERNS = [
  /no match/i,
  /not found/i,
  /no data found/i,
  /no entries found/i,
  /no object found/i,
  /nothing found/i,
  /object does not exist/i,
  /domain not found/i,
  /status:\s*free/i,
  /status:\s*available/i,
  /is available for/i,
  /not registered/i,
  /domain is available/i,
  /domain available/i,
  /available for registration/i,
  /available for purchase/i,
  /this domain is free/i,
];

export function isWhoisRateLimited(raw: string): boolean {
  const allLines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  // Check the full response (including % comment lines) — servers like
  // whois.nic.hu put access-restriction messages inside % comment lines.
  // Scan first 30 lines of the raw response for rate-limit signals.
  const allContent = allLines.slice(0, 30).join("\n");

  // Also check only non-boilerplate content lines for other servers.
  const filteredLines = allLines.filter(
    (l) =>
      !l.startsWith("%") &&
      !l.startsWith("#") &&
      !l.startsWith(">>>") &&
      !l.startsWith("NOTICE") &&
      !l.startsWith("TERMS OF USE") &&
      !l.startsWith("Terms of Use") &&
      !l.startsWith("By submitting") &&
      !l.startsWith("This service") &&
      !l.startsWith("Access to") &&
      !l.startsWith("You agree"),
  );
  const filtered = filteredLines.slice(0, 20).join("\n");

  return WHOIS_RATE_LIMIT_PATTERNS.some((p) => p.test(filtered) || p.test(allContent));
}

export function isNotRegisteredWhoisResponse(whoisError: string): boolean {
  return WHOIS_NOT_REGISTERED_PATTERNS.some((p) => p.test(whoisError));
}

export function isIanaFallback(raw: string): boolean {
  return raw.includes("% IANA WHOIS server");
}

export function detectWhoisError(raw: string): string | null {
  const allLines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith(">>>"));

  // RFC 3912 comment lines (% / #). Some registries ONLY report the empty /
  // not-registered state inside comments — e.g. whois.nic.sn answers with
  // "%% NOT FOUND" — so comment lines must participate in the pattern scan
  // instead of being discarded outright.
  const commentLines = allLines.filter(
    (l) => l.startsWith("%") || l.startsWith("#"),
  );
  const lines = allLines.filter(
    (l) =>
      !l.startsWith("%") &&
      !l.startsWith("#") &&
      !l.startsWith("NOTICE") &&
      !l.startsWith("TERMS OF USE") &&
      !l.startsWith("Terms of Use") &&
      !l.startsWith("By submitting") &&
      !l.startsWith("This service") &&
      !l.startsWith("Access to") &&
      !l.startsWith("You agree"),
  );
  if (lines.length === 0 && commentLines.length === 0) return "Empty WHOIS response";

  const scan = (candidates: string[]): string | null => {
    const filtered = candidates.slice(0, 30).join("\n");
    for (const pattern of WHOIS_ERROR_PATTERNS) {
      const match = filtered.match(pattern);
      if (match) {
        const matchLine = candidates.find((l) => pattern.test(l));
        return matchLine?.trim() || match[0];
      }
    }
    return null;
  };

  // Content lines take precedence; fall back to comment lines so responses
  // whose payload is comments-only (or whose not-found marker is a comment,
  // as with .sn) are still classified correctly.
  return scan(lines) ?? scan(commentLines);
}

export function isEmptyResult(result: {
  domain: string;
  registrar: string;
  creationDate: string;
  expirationDate: string;
  nameServers: string[];
  cidr: string;
  netRange: string;
  netName: string;
  originAS: string;
  inetNum: string;
  inet6Num: string;
}): boolean {
  const hasIpData =
    (result.cidr && result.cidr !== "Unknown") ||
    (result.netRange && result.netRange !== "Unknown") ||
    (result.netName && result.netName !== "Unknown") ||
    (result.originAS && result.originAS !== "Unknown") ||
    (result.inetNum && result.inetNum !== "Unknown") ||
    (result.inet6Num && result.inet6Num !== "Unknown");
  if (hasIpData) return false;
  return (
    (!result.domain || result.domain === "") &&
    result.registrar === "Unknown" &&
    result.creationDate === "Unknown" &&
    result.expirationDate === "Unknown" &&
    result.nameServers.length === 0
  );
}

export function isIPAddress(query: string): boolean {
  const bare = query.replace(/\/\d{1,3}$/, "");
  return (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(bare) ||
    /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(bare)
  );
}

export function isASNumber(query: string): boolean {
  // Match "AS12345" (with prefix) or bare numeric strings like "12345".
  // Bare numbers are treated as AS numbers to match the behaviour in
  // rdap_client.ts which also accepts plain digit strings for autnum lookups.
  return /^AS\d+$/i.test(query) || /^\d+$/.test(query);
}

export function toAsciiDomain(domain: string): string {
  if (!/[^\x00-\x7F]/.test(domain)) return domain;
  try {
    const { domainToASCII } = require("url") as typeof import("url");
    const ascii = domainToASCII(domain.toLowerCase());
    if (ascii && ascii !== domain.toLowerCase() && !ascii.includes("\u0000")) {
      return ascii;
    }
  } catch {}
  return domain;
}
