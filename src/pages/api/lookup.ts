import type { NextApiRequest, NextApiResponse } from "next";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
import { DnsProbeResult } from "@/lib/whois/dns-check";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { enforceApiKey } from "@/lib/access-key";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { saveSearchRecord } from "@/lib/server/save-search-record";
import { getSetting } from "@/lib/server/site-settings-server";

export const config = {
  maxDuration: 30,
};

// Rate limit: 40 requests per 60 s per IP
const RATE_LIMIT        = 40;
const RATE_WINDOW_MS    = 60_000;
// Maximum accepted query length (domain names: 253 chars per RFC 1035)
const MAX_QUERY_LENGTH  = 300;

type Data = {
  status: boolean;
  time: number;
  cached?: boolean;
  cachedAt?: number;
  cacheTtl?: number;
  source?: "rdap" | "whois";
  result?: WhoisAnalyzeResult;
  error?: string;
  dnsProbe?: DnsProbeResult;
  registryUrl?: string;
};


export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>,
) {
  // Only allow GET and HEAD
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("Allow", "GET, HEAD");
    return res.status(405).json({ time: -1, status: false, error: "Method not allowed" });
  }

  // Rate limiting
  const ip = getClientIp(req);
  const { allowed, remaining, resetMs } = rateLimit(ip, RATE_LIMIT, RATE_WINDOW_MS);
  res.setHeader("X-RateLimit-Limit", String(RATE_LIMIT));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetMs / 1_000)));
  if (!allowed) {
    return res.status(429).json({ time: -1, status: false, error: "Too many requests — please slow down" });
  }

  // API key enforcement (when enabled in admin)
  const keyOk = await enforceApiKey(req, res, "api");
  if (!keyOk) return;

  // Input validation
  const query = req.query.query || req.query.q;
  if (!query || typeof query !== "string" || query.trim().length === 0) {
    return res.status(400).json({ time: -1, status: false, error: "Query is required" });
  }
  const trimmed = query.trim();
  if (trimmed.length > MAX_QUERY_LENGTH) {
    return res
      .status(400)
      .json({ time: -1, status: false, error: `Query too long (max ${MAX_QUERY_LENGTH} chars)` });
  }
  // Reject obviously non-sensical characters (null bytes, control chars)
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(trimmed)) {
    return res.status(400).json({ time: -1, status: false, error: "Invalid characters in query" });
  }

  // Fetch session once — used for require_login check and search record tracking
  let userId: string | null = null;
  let userEmail: string | null = null;
  try {
    const session = await getServerSession(req, res, authOptions);
    userId    = (session?.user as any)?.id    ?? null;
    userEmail = session?.user?.email ?? null;
  } catch {}

  // require_login: if enabled, deny anonymous lookups
  const requireLogin = await getSetting("require_login");
  if (requireLogin === "1" && !userEmail) {
    return res.status(401).json({ time: -1, status: false, error: "请先登录后再进行查询" });
  }

  // ── CN Reserved SLD short-circuit ─────────────────────────────────────────
  // Province, functional, and system-reserved .cn second-level domains are
  // managed by CNNIC and are never directly registerable. Skip the WHOIS/RDAP
  // network query and return a synthetic "registry-reserved" result instantly.
  const cnReserved = getCnReservedSldInfo(trimmed);
  if (cnReserved) {
    const syntheticResult: WhoisAnalyzeResult = {
      ...initialWhoisAnalyzeResult,
      domain: trimmed,
      status: [{ status: "registry-reserved", url: "" }],
      rawWhoisContent: `[CN Reserved] ${cnReserved.descZh}`,
    };
    saveSearchRecord(trimmed, syntheticResult, undefined, userId, userEmail).catch(() => {});
    res.setHeader("Cache-Control", "s-maxage=43200, stale-while-revalidate=86400");
    return res.status(200).json({
      time: 0,
      status: true,
      cached: false,
      cacheTtl: 43_200,
      source: "whois" as const,
      result: syntheticResult,
    });
  }

  const nocache = req.query.nocache === "1";
  const { time, status, result, error, cached, cachedAt, cacheTtl, source, dnsProbe, registryUrl } =
    await lookupWhoisWithCache(trimmed, { nocache });
  if (!status) {
    return res.status(500).json({ time, status, error, dnsProbe, registryUrl });
  }

  // Always save the search record — including cached results — so every query
  // (anonymous or logged-in, first-time or repeat) is recorded in the backend.
  if (result) {
    saveSearchRecord(trimmed, result, dnsProbe, userId, userEmail).catch(() => {});
  }

  // Set Cache-Control header to match the actual smart TTL so Vercel's
  // CDN edge cache also honours the same expiry windows as Redis.
  const sMaxAge = cacheTtl && cacheTtl > 0 ? cacheTtl : 3600;
  const swr     = Math.min(sMaxAge * 4, 86_400);
  res.setHeader("Cache-Control", `s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`);
  return res.status(200).json({ time, status, result, cached, cachedAt, cacheTtl, source, dnsProbe, registryUrl });
}
