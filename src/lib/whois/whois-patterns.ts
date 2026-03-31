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
];

export function isWhoisRateLimited(raw: string): boolean {
  return WHOIS_RATE_LIMIT_PATTERNS.some((p) => p.test(raw));
}

export function isNotRegisteredWhoisResponse(whoisError: string): boolean {
  return WHOIS_NOT_REGISTERED_PATTERNS.some((p) => p.test(whoisError));
}

export function isIanaFallback(raw: string): boolean {
  return raw.includes("% IANA WHOIS server");
}

export function detectWhoisError(raw: string): string | null {
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(
      (l) =>
        l.length > 0 &&
        !l.startsWith("%") &&
        !l.startsWith("#") &&
        !l.startsWith(">>>") &&
        !l.startsWith("NOTICE") &&
        !l.startsWith("TERMS OF USE"),
    );
  if (lines.length === 0) return "Empty WHOIS response";
  for (const pattern of WHOIS_ERROR_PATTERNS) {
    const match = raw.match(pattern);
    if (match) {
      const matchLine = raw.split("\n").find((l) => pattern.test(l));
      return matchLine?.trim() || match[0];
    }
  }
  return null;
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
  return /^AS\d+$/i.test(query);
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
