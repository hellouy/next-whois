import type { NextApiRequest, NextApiResponse } from "next";
import http from "http";
import https from "https";
import tls from "tls";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { isBlockedHost } from "@/lib/ssrf-guard";
import { computeTiming, parseCookieHeader, analyzeCookie, computeCookieRating, type HttpTiming, type CookieInfo } from "@/lib/http-timing";

export const config = { maxDuration: 15 };

const RL_LIMIT  = 20;
const RL_WINDOW = 60_000;

export type SecurityHeader = {
  name: string;
  key: string;
  value: string | null;
  present: boolean;
  severity: "critical" | "high" | "medium" | "info";
  description: string;
};

export type HttpTlsSummary = {
  protocol: string | null;
  cipher: string | null;
  certificate: {
    cn: string | null;
    sans: string[];
    validTo: string | null;
    expired: boolean | null;
    trusted: boolean;
  } | null;
};

export type HttpCheckResult = {
  ok: boolean;
  url: string;
  finalUrl: string;
  statusCode: number | null;
  statusText: string | null;
  latencyMs: number | null;
  server: string | null;
  contentType: string | null;
  contentLength: number | null;
  xPoweredBy: string | null;
  cacheControl: string | null;
  via: string | null;
  redirectChain: { url: string; status: number }[];
  // Security headers
  hsts: string | null;
  csp: string | null;
  xFrameOptions: string | null;
  xContentTypeOptions: string | null;
  referrerPolicy: string | null;
  permissionsPolicy: string | null;
  xXssProtection: string | null;
  securityScore: number;
  securityHeaders: SecurityHeader[];
  // Enhanced (optional)
  timing?: HttpTiming;
  cookies?: CookieInfo[];
  cookieRating?: "secure" | "needs_attention" | "insecure";
  tls?: HttpTlsSummary | null;
  error?: string;
};

function isValidUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function computeSecurityHeaders(headers: Headers, isHttps: boolean): { score: number; headers: SecurityHeader[]; parsed: Record<string, string | null> } {
  const get = (name: string) => headers.get(name);

  const hsts              = get("strict-transport-security");
  const csp               = get("content-security-policy");
  const xFrame            = get("x-frame-options");
  const xContentType      = get("x-content-type-options");
  const referrer          = get("referrer-policy");
  const permissions       = get("permissions-policy");
  const xXss              = get("x-xss-protection");

  const items: SecurityHeader[] = [
    {
      name: "Strict-Transport-Security",
      key: "hsts",
      value: hsts,
      present: isHttps && !!hsts,
      severity: "critical",
      description: "HSTS",
    },
    {
      name: "Content-Security-Policy",
      key: "csp",
      value: csp,
      present: !!csp,
      severity: "high",
      description: "CSP",
    },
    {
      name: "X-Frame-Options",
      key: "x-frame-options",
      value: xFrame,
      present: !!xFrame,
      severity: "high",
      description: "Clickjacking",
    },
    {
      name: "X-Content-Type-Options",
      key: "x-content-type-options",
      value: xContentType,
      present: !!xContentType,
      severity: "medium",
      description: "MIME sniff",
    },
    {
      name: "Referrer-Policy",
      key: "referrer-policy",
      value: referrer,
      present: !!referrer,
      severity: "medium",
      description: "Referrer",
    },
    {
      name: "Permissions-Policy",
      key: "permissions-policy",
      value: permissions,
      present: !!permissions,
      severity: "medium",
      description: "Permissions",
    },
    {
      name: "X-XSS-Protection",
      key: "x-xss-protection",
      value: xXss,
      present: !!xXss,
      severity: "info",
      description: "XSS (legacy)",
    },
  ];

  // Weight: critical=30, high=25, medium=10, info=5
  const weights = { critical: 30, high: 25, medium: 10, info: 5 };
  const totalWeight = items.reduce((s, h) => s + weights[h.severity], 0);
  const earnedWeight = items.filter(h => h.present).reduce((s, h) => s + weights[h.severity], 0);
  const score = Math.round((earnedWeight / totalWeight) * 100);

  return {
    score,
    headers: items,
    parsed: { hsts, csp, xFrameOptions: xFrame, xContentTypeOptions: xContentType, referrerPolicy: referrer, permissionsPolicy: permissions, xXssProtection: xXss },
  };
}

type RawHopResult = {
  statusCode: number | null;
  statusText: string;
  headers: http.IncomingHttpHeaders;
  marks: { start: number; dnsEnd: number | null; connectEnd: number | null; tlsEnd: number | null; headersEnd: number | null };
};

// Manual http/https request that records per-phase timing via socket events.
function rawRequest(url: string, ua: string, timeoutMs: number): Promise<RawHopResult> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const marks = { start: Date.now(), dnsEnd: null as number | null, connectEnd: null as number | null, tlsEnd: null as number | null, headersEnd: null as number | null };
    const req = lib.request(u, {
      method: "GET",
      headers: { "User-Agent": ua, Accept: "text/html,*/*" },
      timeout: timeoutMs,
    });
    req.on("socket", socket => {
      socket.on("lookup", () => { marks.dnsEnd = Date.now(); });
      socket.on("connect", () => { marks.connectEnd = Date.now(); });
      socket.on("secureConnect", () => { marks.tlsEnd = Date.now(); });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("response", res => {
      marks.headersEnd = Date.now();
      // We only need headers — destroy the stream to release the connection.
      res.destroy();
      resolve({
        statusCode: res.statusCode ?? null,
        statusText: res.statusMessage ?? "",
        headers: res.headers,
        marks,
      });
    });
    req.on("error", err => reject(err));
    req.end();
  });
}

function parseCookies(headers: http.IncomingHttpHeaders): CookieInfo[] {
  const raw = headers["set-cookie"];
  if (!raw) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  return list.filter(Boolean).map(h => analyzeCookie(parseCookieHeader(h)));
}

function hdr(headers: http.IncomingHttpHeaders, name: string): string | null {
  const v = headers[name];
  if (v === undefined || v === null) return null;
  return Array.isArray(v) ? (v[0] ?? null) : v;
}

function getTlsSummary(hostname: string, port: number, timeoutMs: number): Promise<HttpTlsSummary | null> {
  return new Promise(resolve => {
    let settled = false;
    const done = (v: HttpTlsSummary | null) => { if (!settled) { settled = true; resolve(v); } };
    const timer = setTimeout(() => { socket.destroy(); done(null); }, timeoutMs);
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false });
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = (socket as any).getCipher?.();
      const trusted = socket.authorized;
      socket.end();
      const validTo = cert.valid_to ? String(cert.valid_to) : null;
      const sans = (cert.subjectaltname ?? "").split(", ").map(s => s.replace(/^DNS:/, "")).filter(Boolean);
      const cnRaw = cert.subject?.CN;
      const cn = cnRaw ? (Array.isArray(cnRaw) ? cnRaw.join(", ") : String(cnRaw)) : null;
      const expired = validTo ? new Date(validTo).getTime() < Date.now() : null;
      clearTimeout(timer);
      done({
        protocol: protocol ?? null,
        cipher: typeof cipher === "object" && cipher ? (cipher.name ?? null) : null,
        certificate: { cn, sans, validTo, expired, trusted },
      });
    });
    socket.once("error", () => { clearTimeout(timer); done(null); });
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse<HttpCheckResult>) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      ok: false, url: "", finalUrl: "", statusCode: null, statusText: null,
      latencyMs: null, server: null, contentType: null, contentLength: null,
      xPoweredBy: null, cacheControl: null, via: null,
      redirectChain: [], hsts: null, csp: null, xFrameOptions: null,
      xContentTypeOptions: null, referrerPolicy: null, permissionsPolicy: null,
      xXssProtection: null, securityScore: 0, securityHeaders: [],
      error: "Method not allowed",
    });
  }

  const { ok: allowed } = await checkRateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) {
    return res.status(429).json({
      ok: false, url: "", finalUrl: "", statusCode: null, statusText: null,
      latencyMs: null, server: null, contentType: null, contentLength: null,
      xPoweredBy: null, cacheControl: null, via: null,
      redirectChain: [], hsts: null, csp: null, xFrameOptions: null,
      xContentTypeOptions: null, referrerPolicy: null, permissionsPolicy: null,
      xXssProtection: null, securityScore: 0, securityHeaders: [],
      error: "Too many requests, please try again later",
    });
  }

  const rawUrl = ((req.query.url as string) || "").trim();
  if (!rawUrl || !isValidUrl(rawUrl)) {
    return res.status(400).json({
      ok: false, url: rawUrl, finalUrl: rawUrl, statusCode: null, statusText: null,
      latencyMs: null, server: null, contentType: null, contentLength: null,
      xPoweredBy: null, cacheControl: null, via: null,
      redirectChain: [], hsts: null, csp: null, xFrameOptions: null,
      xContentTypeOptions: null, referrerPolicy: null, permissionsPolicy: null,
      xXssProtection: null, securityScore: 0, securityHeaders: [],
      error: "Invalid URL (must start with http:// or https://)",
    });
  }

  try {
    const parsed = new URL(rawUrl);
    if (await isBlockedHost(parsed.hostname)) {
      return res.status(400).json({
        ok: false, url: rawUrl, finalUrl: rawUrl, statusCode: null, statusText: null,
        latencyMs: null, server: null, contentType: null, contentLength: null,
        xPoweredBy: null, cacheControl: null, via: null,
        redirectChain: [], hsts: null, csp: null, xFrameOptions: null,
        xContentTypeOptions: null, referrerPolicy: null, permissionsPolicy: null,
        xXssProtection: null, securityScore: 0, securityHeaders: [],
        error: "Private or internal addresses are not allowed",
      });
    }
  } catch {}

  const MAX_REDIRECTS = 8;
  const TIMEOUT_MS    = 10000;
  const UA = "Mozilla/5.0 (compatible; WHOIS-HTTPChecker/1.0; +https://example.com)";

  const redirectChain: { url: string; status: number }[] = [];
  let currentUrl = rawUrl;
  let lastHop: RawHopResult | null = null;
  const t0 = Date.now();

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const hop = await rawRequest(currentUrl, UA, TIMEOUT_MS);

      lastHop = hop;

      if (hop.statusCode !== null && hop.statusCode >= 300 && hop.statusCode < 400) {
        const location = hdr(hop.headers, "location") || "";
        redirectChain.push({ url: currentUrl, status: hop.statusCode });
        if (!location) break;
        try { currentUrl = new URL(location, currentUrl).href; } catch { break; }
        // Re-check every redirect hop: a public URL redirecting into private
        // space must be blocked, not followed.
        let nextHost: string;
        try { nextHost = new URL(currentUrl).hostname; } catch { break; }
        if (await isBlockedHost(nextHost)) {
          return res.status(400).json({
            ok: false, url: rawUrl, finalUrl: currentUrl, statusCode: null, statusText: null,
            latencyMs: null, server: null, contentType: null, contentLength: null,
            xPoweredBy: null, cacheControl: null, via: null,
            redirectChain, hsts: null, csp: null, xFrameOptions: null,
            xContentTypeOptions: null, referrerPolicy: null, permissionsPolicy: null,
            xXssProtection: null, securityScore: 0, securityHeaders: [],
            error: "Redirect to private or internal address blocked",
          });
        }
        continue;
      }
      break;
    }

    const latencyMs = Date.now() - t0;
    if (!lastHop) throw new Error("No response received");

    // Loop above only exits early on a non-redirect status; if the final hop
    // is still a redirect we exhausted MAX_REDIRECTS and must not report it
    // as a success (a redirect is never the terminal response).
    if (lastHop.statusCode !== null && lastHop.statusCode >= 300 && lastHop.statusCode < 400) {
      res.setHeader("Cache-Control", "no-store");
      return res.status(200).json({
        ok: false,
        url: rawUrl,
        finalUrl: currentUrl,
        statusCode: lastHop.statusCode,
        statusText: lastHop.statusText || null,
        latencyMs: Date.now() - t0,
        server: null, contentType: null, contentLength: null,
        xPoweredBy: null, cacheControl: null, via: null,
        redirectChain, hsts: null, csp: null, xFrameOptions: null,
        xContentTypeOptions: null, referrerPolicy: null, permissionsPolicy: null,
        xXssProtection: null, securityScore: 0, securityHeaders: [],
        error: `Too many redirects (exceeded ${MAX_REDIRECTS})`,
      });
    }

    const statusCode = lastHop.statusCode;
    const isOk = statusCode !== null && statusCode >= 200 && statusCode < 400;
    const isHttps = currentUrl.startsWith("https://");

    // Timing breakdown from socket events
    const timing = computeTiming({
      start: lastHop.marks.start,
      dnsEnd: lastHop.marks.dnsEnd,
      connectEnd: lastHop.marks.connectEnd,
      tlsEnd: lastHop.marks.tlsEnd,
      headersEnd: lastHop.marks.headersEnd,
      end: lastHop.marks.headersEnd ?? Date.now(),
    });

    // Cookie analysis
    const cookies = parseCookies(lastHop.headers);
    const cookieRating = computeCookieRating(cookies);

    // TLS / certificate summary for HTTPS targets
    let tlsSummary: HttpTlsSummary | null = null;
    if (isHttps) {
      const u = new URL(currentUrl);
      tlsSummary = await getTlsSummary(u.hostname, u.port ? parseInt(u.port) : 443, 5000);
    }

    const h = lastHop.headers;
    const { score, headers: secHeaders, parsed: secParsed } = computeSecurityHeaders(new Headers({
      ...Object.fromEntries(Object.entries(h).filter(([, v]) => v !== undefined).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : v as string])),
    }), isHttps);

    const clRaw = hdr(h, "content-length");
    const contentLength = clRaw ? parseInt(clRaw) : null;

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      ok: isOk,
      url: rawUrl,
      finalUrl: currentUrl,
      statusCode,
      statusText: lastHop.statusText || null,
      latencyMs,
      server: hdr(h, "server"),
      contentType: hdr(h, "content-type")?.split(";")[0].trim() || null,
      contentLength: Number.isFinite(contentLength) ? contentLength : null,
      xPoweredBy: hdr(h, "x-powered-by"),
      cacheControl: hdr(h, "cache-control"),
      via: hdr(h, "via"),
      redirectChain,
      hsts: secParsed.hsts,
      csp: secParsed.csp,
      xFrameOptions: secParsed.xFrameOptions,
      xContentTypeOptions: secParsed.xContentTypeOptions,
      referrerPolicy: secParsed.referrerPolicy,
      permissionsPolicy: secParsed.permissionsPolicy,
      xXssProtection: secParsed.xXssProtection,
      securityScore: score,
      securityHeaders: secHeaders,
      timing,
      cookies,
      cookieRating,
      tls: tlsSummary,
    });
  } catch (err: unknown) {
    const latencyMs = Date.now() - t0;
    const msg = err instanceof Error ? err.message : "unknown";
    const isTimeout = msg.includes("abort") || msg.includes("timeout") || msg.includes("TimeoutError") || msg.includes("timed out");
    const isNoConn = msg.includes("ENOTFOUND") || msg.includes("ECONNREFUSED") || msg.includes("ENETUNREACH") || msg.includes("EHOSTUNREACH") || msg.includes("network");

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      ok: false,
      url: rawUrl,
      finalUrl: currentUrl,
      statusCode: null,
      statusText: null,
      latencyMs: isTimeout ? null : latencyMs,
      server: null,
      contentType: null,
      contentLength: null,
      xPoweredBy: null,
      cacheControl: null,
      via: null,
      redirectChain,
      hsts: null,
      csp: null,
      xFrameOptions: null,
      xContentTypeOptions: null,
      referrerPolicy: null,
      permissionsPolicy: null,
      xXssProtection: null,
      securityScore: 0,
      securityHeaders: [],
      error: isTimeout ? "Connection timed out" : isNoConn ? "Cannot reach target server" : msg.slice(0, 120),
    });
  }
}
