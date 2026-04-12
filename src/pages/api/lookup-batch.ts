import type { NextApiRequest, NextApiResponse } from "next";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { WhoisAnalyzeResult } from "@/lib/whois/types";
import { DnsProbeResult } from "@/lib/whois/dns-check";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";
import { enforceApiKey, isSameOriginRequest } from "@/lib/access-key";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";

export const config = {
  maxDuration: 60,
};

// Concurrency limit per batch to avoid hammering upstream WHOIS servers
const CONCURRENCY = 5;

// Rate limits apply only to external (non-same-origin) callers
const RATE_LIMIT_ANON   = 5;
const RATE_LIMIT_AUTHED = 15;
const RATE_LIMIT_SUB    = 40;
const RATE_WINDOW_MS    = 60_000;

// Max batch sizes: logged-in users are unlimited within a single request
// (capped at ANON_MAX for anonymous), authenticated users get higher caps.
const MAX_ANON_SIZE    = 10;
const MAX_AUTHED_SIZE  = 500;  // effectively unlimited for UI use

export type BatchItem = {
  domain: string;
  status: boolean;
  time: number;
  cached?: boolean;
  cachedAt?: number;
  cacheTtl?: number;
  source?: "rdap" | "whois" | "tian.hu" | "YISI.YUN" | "whois.ph";
  result?: WhoisAnalyzeResult;
  error?: string;
  dnsProbe?: DnsProbeResult;
};

type Data =
  | { items: BatchItem[]; elapsed: number }
  | { error: string };

async function runWithConcurrency<T>(
  tasks: (() => Promise<T>)[],
  concurrency: number,
): Promise<PromiseSettledResult<T>[]> {
  const results: PromiseSettledResult<T>[] = new Array(tasks.length);
  let idx = 0;

  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      try {
        results[i] = { status: "fulfilled", value: await tasks[i]() };
      } catch (reason) {
        results[i] = { status: "rejected", reason };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker));
  return results;
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>,
) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  // ── Session ──────────────────────────────────────────────────────────────
  const session = await getServerSession(req, res, authOptions).catch(() => null);
  const userEmail    = session?.user?.email ?? null;
  const isSubscribed = !!((session?.user as any)?.subscriptionAccess);
  const sameOrigin   = isSameOriginRequest(req);
  const isLoggedIn   = !!userEmail;

  // ── Rate limiting (external callers only) ────────────────────────────────
  const ip        = getClientIp(req);
  const tierLimit = sameOrigin    ? RATE_LIMIT_SUB
                  : isSubscribed  ? RATE_LIMIT_SUB
                  : isLoggedIn    ? RATE_LIMIT_AUTHED
                  :                 RATE_LIMIT_ANON;
  const tierKey   = sameOrigin    ? `${ip}:origin:batch`
                  : isSubscribed  ? `${ip}:sub:batch`
                  : isLoggedIn    ? `${ip}:auth:batch`
                  :                 `${ip}:anon:batch`;

  if (!sameOrigin) {
    const { allowed, remaining, resetMs } = rateLimit(tierKey, tierLimit, RATE_WINDOW_MS);
    res.setHeader("X-RateLimit-Limit", String(tierLimit));
    res.setHeader("X-RateLimit-Remaining", String(remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetMs / 1_000)));
    if (!allowed) {
      return res.status(429).json({ error: "Rate limit exceeded — please slow down" });
    }
  }

  // ── API key enforcement ──────────────────────────────────────────────────
  const keyOk = await enforceApiKey(req, res, "api");
  if (!keyOk) return;

  // ── Validate request body ────────────────────────────────────────────────
  let domains: unknown;
  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    domains = body?.domains;
  } catch {
    return res.status(400).json({ error: "Invalid JSON body" });
  }

  if (!Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: "Request body must include a non-empty \"domains\" array" });
  }

  const maxBatch = isLoggedIn ? MAX_AUTHED_SIZE : MAX_ANON_SIZE;
  if ((domains as unknown[]).length > maxBatch) {
    return res.status(400).json({ error: `Batch size exceeds maximum of ${maxBatch}` });
  }

  const queryList = (domains as unknown[])
    .map(d => (typeof d === "string" ? d.trim().toLowerCase() : ""))
    .filter(Boolean);

  if (queryList.length === 0) {
    return res.status(400).json({ error: "No valid domain strings in \"domains\" array" });
  }

  // ── Execute lookups with controlled concurrency ───────────────────────────
  // This avoids hammering upstream WHOIS servers while still being fast.
  // Cache hits are returned instantly, so effective throughput is much higher.
  const batchStart = Date.now();
  const tasks = queryList.map(domain => () => lookupWhoisWithCache(domain));
  const settled = await runWithConcurrency(tasks, CONCURRENCY);

  const items: BatchItem[] = settled.map((result, i) => {
    const domain = queryList[i];
    if (result.status === "fulfilled") {
      const { status, time, cached, cachedAt, cacheTtl, source, result: r, error, dnsProbe } = result.value;
      return { domain, status, time, cached, cachedAt, cacheTtl, source, result: r, error, dnsProbe };
    }
    return {
      domain,
      status: false,
      time: 0,
      error: result.reason instanceof Error ? result.reason.message : "Unknown error",
    };
  });

  const elapsed = (Date.now() - batchStart) / 1000;
  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ items, elapsed });
}
