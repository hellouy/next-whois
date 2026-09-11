// HTTP check pure helpers: timing mapping and cookie analysis.

export type HttpTiming = {
  dnsMs: number | null;
  connectMs: number | null;
  tlsMs: number | null;
  ttfbMs: number;
  totalMs: number;
};

export type HttpTimingMarks = {
  start: number;
  dnsEnd: number | null;
  connectEnd: number | null;
  tlsEnd: number | null;
  headersEnd: number | null;
  end: number;
};

export function computeTiming(marks: HttpTimingMarks): HttpTiming {
  const { start, dnsEnd, connectEnd, tlsEnd, headersEnd, end } = marks;
  const dnsMs = dnsEnd != null ? dnsEnd - start : null;
  const base = connectEnd ?? dnsEnd ?? start;
  const connectMs = connectEnd != null
    ? dnsEnd != null ? connectEnd - dnsEnd : connectEnd - start
    : null;
  const tlsMs = tlsEnd != null
    ? connectEnd != null ? tlsEnd - connectEnd : tlsEnd - (dnsEnd ?? start)
    : null;
  const ttfbMs = headersEnd != null ? headersEnd - start : end - start;
  const totalMs = end - start;
  return { dnsMs, connectMs, tlsMs, ttfbMs, totalMs };
}

export type CookieInfo = {
  name: string;
  domain: string | null;
  path: string | null;
  expires: string | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  issues: string[];
};

export function parseCookieHeader(header: string): CookieInfo {
  const parts = header.split(";").map(s => s.trim());
  const first = parts[0] ?? "";
  const eq = first.indexOf("=");
  const name = eq > 0 ? first.slice(0, eq) : first;
  const info: CookieInfo = {
    name,
    domain: null,
    path: null,
    expires: null,
    secure: false,
    httpOnly: false,
    sameSite: null,
    issues: [],
  };
  for (const p of parts.slice(1)) {
    if (!p) continue;
    const lower = p.toLowerCase();
    if (lower.startsWith("domain=")) info.domain = p.slice(7).trim() || null;
    else if (lower.startsWith("path=")) info.path = p.slice(5).trim() || null;
    else if (lower.startsWith("expires=")) info.expires = p.slice(8).trim() || null;
    else if (lower.startsWith("samesite=")) info.sameSite = p.slice(9).trim().toLowerCase() || null;
    else if (lower === "secure") info.secure = true;
    else if (lower === "httponly") info.httpOnly = true;
  }
  return info;
}

export function analyzeCookie(info: CookieInfo): CookieInfo {
  const issues: string[] = [];
  if (!info.secure) issues.push("no_secure");
  if (!info.httpOnly) issues.push("no_httponly");
  if (!info.sameSite) issues.push("no_samesite");
  info.issues = issues;
  return info;
}

export function computeCookieRating(cookies: CookieInfo[]): "secure" | "needs_attention" | "insecure" {
  if (cookies.length === 0) return "secure";
  let hasInsecure = false;
  let hasAttention = false;
  for (const c of cookies) {
    if (!c.secure && !c.httpOnly) hasInsecure = true;
    else if (!c.secure || !c.httpOnly || !c.sameSite) hasAttention = true;
  }
  if (hasInsecure) return "insecure";
  if (hasAttention) return "needs_attention";
  return "secure";
}
