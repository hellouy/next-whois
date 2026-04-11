import type { NextApiRequest, NextApiResponse } from "next";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 15 };

const RL_LIMIT  = 20;
const RL_WINDOW = 60_000;

function isPrivateHost(host: string): boolean {
  if (/^(localhost|127\.|0\.0\.0\.0|::1|0:0:0:0:0:0:0:1)$/i.test(host)) return true;
  if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (/^192\.168\.\d+\.\d+$/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)) return true;
  if (/^169\.254\.\d+\.\d+$/.test(host)) return true;
  if (/^fe80:/i.test(host)) return true;
  if (host === "169.254.169.254") return true;
  if (/\.local$/i.test(host)) return true;
  return false;
}

export type SecurityHeader = {
  name: string;
  key: string;
  value: string | null;
  present: boolean;
  severity: "critical" | "high" | "medium" | "info";
  description: string;
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

  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
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
    if (isPrivateHost(parsed.hostname)) {
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
  let lastRes: Response | null = null;
  const t0 = Date.now();

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

      let r: Response;
      try {
        // Use GET (not HEAD) so security headers injected by middleware are always returned.
        // We abort the body stream immediately after headers arrive to keep it cheap.
        r = await fetch(currentUrl, {
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
          headers: { "User-Agent": UA, Accept: "text/html,*/*" },
        });
      } finally {
        clearTimeout(timer);
      }

      // Abort body download immediately — we only need headers
      try { r.body?.cancel(); } catch {}

      lastRes = r;

      if (r.status >= 300 && r.status < 400) {
        const location = r.headers.get("location") || "";
        redirectChain.push({ url: currentUrl, status: r.status });
        if (!location) break;
        try { currentUrl = new URL(location, currentUrl).href; } catch { break; }
        continue;
      }
      break;
    }

    const latencyMs = Date.now() - t0;
    if (!lastRes) throw new Error("No response received");

    const statusCode = lastRes.status;
    const isOk = statusCode >= 200 && statusCode < 400;
    const isHttps = currentUrl.startsWith("https://");

    const { score, headers: secHeaders, parsed: secParsed } = computeSecurityHeaders(lastRes.headers, isHttps);

    const clRaw = lastRes.headers.get("content-length");
    const contentLength = clRaw ? parseInt(clRaw) : null;

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      ok: isOk,
      url: rawUrl,
      finalUrl: currentUrl,
      statusCode,
      statusText: lastRes.statusText || null,
      latencyMs,
      server: lastRes.headers.get("server") || null,
      contentType: lastRes.headers.get("content-type")?.split(";")[0].trim() || null,
      contentLength: Number.isFinite(contentLength) ? contentLength : null,
      xPoweredBy: lastRes.headers.get("x-powered-by") || null,
      cacheControl: lastRes.headers.get("cache-control") || null,
      via: lastRes.headers.get("via") || null,
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
    });
  } catch (err: unknown) {
    const latencyMs = Date.now() - t0;
    const msg = err instanceof Error ? err.message : "unknown";
    const isTimeout = msg.includes("abort") || msg.includes("timeout") || msg.includes("AbortError");
    const isNoConn = msg.includes("ENOTFOUND") || msg.includes("ECONNREFUSED") || msg.includes("fetch failed") || msg.includes("network");

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
