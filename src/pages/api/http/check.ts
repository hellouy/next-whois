import type { NextApiRequest, NextApiResponse } from "next";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 15 };

const RL_LIMIT  = 20;
const RL_WINDOW = 60_000;

/** Returns true if the hostname resolves to a private / loopback / link-local address */
function isPrivateHost(host: string): boolean {
  // Reject obvious loopback / localhost
  if (/^(localhost|127\.|0\.0\.0\.0|::1|0:0:0:0:0:0:0:1)$/i.test(host)) return true;
  // Reject RFC-1918 private ranges
  if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (/^192\.168\.\d+\.\d+$/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)) return true;
  // Reject link-local
  if (/^169\.254\.\d+\.\d+$/.test(host)) return true;
  if (/^fe80:/i.test(host)) return true;
  // Reject metadata / cloud-provider IPs
  if (host === "169.254.169.254") return true;
  // Reject .local mDNS domains
  if (/\.local$/i.test(host)) return true;
  return false;
}

export type HttpCheckResult = {
  ok: boolean;
  url: string;
  finalUrl: string;
  statusCode: number | null;
  statusText: string | null;
  latencyMs: number | null;
  server: string | null;
  contentType: string | null;
  redirectChain: { url: string; status: number }[];
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

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<HttpCheckResult>,
) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      ok: false, url: "", finalUrl: "", statusCode: null, statusText: null,
      latencyMs: null, server: null, contentType: null, redirectChain: [],
      error: "Method not allowed",
    });
  }

  // Rate limiting: 20 requests per minute per IP
  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) {
    return res.status(429).json({
      ok: false, url: "", finalUrl: "", statusCode: null, statusText: null,
      latencyMs: null, server: null, contentType: null, redirectChain: [],
      error: "请求过于频繁，请稍后再试",
    });
  }

  const rawUrl = ((req.query.url as string) || "").trim();

  if (!rawUrl || !isValidUrl(rawUrl)) {
    return res.status(400).json({
      ok: false, url: rawUrl, finalUrl: rawUrl, statusCode: null, statusText: null,
      latencyMs: null, server: null, contentType: null, redirectChain: [],
      error: "请输入合法的 URL（http:// 或 https://）",
    });
  }

  // SSRF protection: block requests to private / internal hosts
  try {
    const parsed = new URL(rawUrl);
    if (isPrivateHost(parsed.hostname)) {
      return res.status(400).json({
        ok: false, url: rawUrl, finalUrl: rawUrl, statusCode: null, statusText: null,
        latencyMs: null, server: null, contentType: null, redirectChain: [],
        error: "不允许访问私有或内网地址",
      });
    }
  } catch {
    // URL parse already validated above
  }

  const MAX_REDIRECTS = 8;
  const TIMEOUT_MS = 10000;

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
        r = await fetch(currentUrl, {
          method: "HEAD",
          redirect: "manual",
          signal: controller.signal,
          headers: {
            "User-Agent":
              "Mozilla/5.0 (compatible; X.RW-HTTPChecker/1.0; +https://x.rw)",
            Accept: "text/html,application/xhtml+xml,*/*",
          },
        });
      } finally {
        clearTimeout(timer);
      }

      lastRes = r;

      if (r.status >= 300 && r.status < 400) {
        const location = r.headers.get("location") || "";
        redirectChain.push({ url: currentUrl, status: r.status });

        if (!location) break;
        try {
          currentUrl = new URL(location, currentUrl).href;
        } catch {
          break;
        }
        continue;
      }

      break;
    }

    const latencyMs = Date.now() - t0;

    if (!lastRes) throw new Error("No response received");

    const statusCode = lastRes.status;
    const isOk = statusCode >= 200 && statusCode < 400;

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
      redirectChain,
    });
  } catch (err: unknown) {
    const latencyMs = Date.now() - t0;
    const msg = err instanceof Error ? err.message : "unknown";
    const isTimeout = msg.includes("abort") || msg.includes("timeout");
    const isNoConn =
      msg.includes("ENOTFOUND") ||
      msg.includes("ECONNREFUSED") ||
      msg.includes("fetch failed") ||
      msg.includes("network");

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
      redirectChain,
      error: isTimeout
        ? "连接超时"
        : isNoConn
        ? "无法连接到目标服务器"
        : msg.slice(0, 100),
    });
  }
}
