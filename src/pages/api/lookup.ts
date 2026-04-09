import type { NextApiRequest, NextApiResponse } from "next";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
import { DnsProbeResult } from "@/lib/whois/dns-check";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { enforceApiKey, isSameOriginRequest } from "@/lib/access-key";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { saveSearchRecord } from "@/lib/server/save-search-record";
import { getSetting } from "@/lib/server/site-settings-server";
import { logQuery } from "@/lib/db";

export const config = {
  maxDuration: 30,
};

// Tiered rate limits per 60 s per IP.
// Subscribed users get the highest quota; anonymous the lowest.
const RATE_LIMIT_ANON   = 40;   // unauthenticated / API-key users
const RATE_LIMIT_AUTHED = 120;  // logged-in free accounts
const RATE_LIMIT_SUB    = 300;  // active subscription holders
const RATE_WINDOW_MS    = 60_000;
// Maximum accepted query length (domain names: 253 chars per RFC 1035)
const MAX_QUERY_LENGTH  = 300;

type Data = {
  status: boolean;
  time: number;
  cached?: boolean;
  cachedAt?: number;
  cacheTtl?: number;
  source?: "rdap" | "whois" | "tian.hu" | "YISI.YUN";
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

  // Input validation (sync — run before any async work)
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
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(trimmed)) {
    return res.status(400).json({ time: -1, status: false, error: "Invalid characters in query" });
  }

  // Fetch session + require_login in parallel before rate-limiting so we can
  // apply the correct tier (getServerSession is a fast in-process JWT decode).
  const [session, requireLogin] = await Promise.all([
    getServerSession(req, res, authOptions).catch(() => null),
    getSetting("require_login"),
  ]);
  const userId    = (session?.user as any)?.id             ?? null;
  const userEmail = session?.user?.email                    ?? null;
  const isSubscribed = !!((session?.user as any)?.subscriptionAccess);

  // Tiered rate limiting — same-origin (the site itself) is always exempt.
  // Tier key includes auth state so each tier has its own independent bucket.
  const ip         = getClientIp(req);
  const sameOrigin = isSameOriginRequest(req);
  const tierLimit  = sameOrigin  ? RATE_LIMIT_SUB
                   : isSubscribed ? RATE_LIMIT_SUB
                   : userEmail    ? RATE_LIMIT_AUTHED
                   :                RATE_LIMIT_ANON;
  const tierKey    = sameOrigin  ? `${ip}:origin`
                   : isSubscribed ? `${ip}:sub`
                   : userEmail    ? `${ip}:auth`
                   :                `${ip}:anon`;

  const { allowed, remaining, resetMs } = sameOrigin
    ? { allowed: true, remaining: tierLimit, resetMs: 0 }
    : rateLimit(tierKey, tierLimit, RATE_WINDOW_MS);

  res.setHeader("X-RateLimit-Limit", String(tierLimit));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetMs / 1_000)));
  if (!allowed) {
    return res.status(429).json({ time: -1, status: false, error: "Too many requests — please slow down" });
  }

  // API key enforcement (when enabled in admin)
  const keyOk = await enforceApiKey(req, res, "api");
  if (!keyOk) return;

  // require_login: if enabled, deny anonymous lookups
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

  // Extract the TLD (last dot-separated label) for log grouping
  const tldParts = trimmed.toLowerCase().split(".");
  const tld = tldParts.length >= 2 ? tldParts[tldParts.length - 1] : trimmed;

  if (!status) {
    logQuery({ domain: trimmed, tld, success: false, cached: false, durationMs: time * 1000, errorCode: error?.slice(0, 60) ?? null, source: source ?? null }).catch(() => {});
    return res.status(500).json({ time, status, error, dnsProbe, registryUrl });
  }

  // Record every successful lookup — logged-in or anonymous, cached or fresh.
  saveSearchRecord(trimmed, result ?? { ...initialWhoisAnalyzeResult }, dnsProbe, userId, userEmail).catch(() => {});
  logQuery({ domain: trimmed, tld, success: true, cached: cached ?? false, durationMs: time * 1000, errorCode: null, source: source ?? null }).catch(() => {});

  // Set Cache-Control header to match the actual smart TTL so Vercel's
  // CDN edge cache also honours the same expiry windows as Redis.
  const sMaxAge = cacheTtl && cacheTtl > 0 ? cacheTtl : 3600;
  const swr     = Math.min(sMaxAge * 4, 86_400);
  res.setHeader("Cache-Control", `s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`);
  return res.status(200).json({ time, status, result, cached, cachedAt, cacheTtl, source, dnsProbe, registryUrl });
}
