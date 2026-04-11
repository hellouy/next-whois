import type { NextApiRequest, NextApiResponse } from "next";
import { lookupWhoisCacheStreaming } from "@/lib/whois/lookup";
import { WhoisResult, WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
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

// Tiered rate limits per 60 s per IP — mirrors /api/lookup.ts tiers so
// authenticated and subscribed users get the same higher quotas on both endpoints.
const RATE_LIMIT_ANON   = 40;   // unauthenticated / external API-key users
const RATE_LIMIT_AUTHED = 120;  // logged-in free accounts
const RATE_LIMIT_SUB    = 300;  // active subscription holders
const RATE_WINDOW_MS    = 60_000;
const MAX_QUERY_LENGTH  = 300;

/**
 * Streaming WHOIS lookup endpoint — returns NDJSON (newline-delimited JSON).
 *
 * For cache-miss RDAP-supported domains, the response arrives in two lines:
 *   Line 1  (sent immediately when RDAP resolves, ~1-2 s):
 *     { ...WhoisResult, streaming: true, partial: true }
 *   Line 2  (sent when WHOIS enrichment finishes, ~0.4-5 s later):
 *     { ...WhoisResult, streaming: true, partial: false }
 *
 * For cache hits or WHOIS-only TLDs, a single line is sent and the
 * connection closes immediately (behaves identically to /api/lookup).
 *
 * Latency optimization: the WHOIS/RDAP lookup is started immediately after
 * input validation — before awaiting the session/settings check.  The
 * session check runs in parallel with the first RDAP round-trip, saving
 * 50-300 ms on every request.  If auth fails, the lookup is abandoned.
 *
 * CN reserved SLDs are detected synchronously before the lookup starts so
 * no network request is wasted.  Rate limiting is applied after auth so the
 * correct tier (anon/authed/subscribed) is used, matching /api/lookup.ts.
 */
export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("Allow", "GET, HEAD");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const query = req.query.query || req.query.q;
  if (!query || typeof query !== "string" || !query.trim()) {
    return res.status(400).json({ error: "Query is required" });
  }
  const trimmed = query.trim();
  if (trimmed.length > MAX_QUERY_LENGTH) {
    return res.status(400).json({ error: `Query too long (max ${MAX_QUERY_LENGTH} chars)` });
  }
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(trimmed)) {
    return res.status(400).json({ error: "Invalid characters in query" });
  }

  const nocache = req.query.nocache === "1";
  const ip = getClientIp(req);
  const sameOrigin = isSameOriginRequest(req);

  // ── CN reserved SLD check — synchronous, zero network cost ───────────────
  // Province, functional, and system-reserved .cn SLDs never need a WHOIS
  // lookup.  Detecting them here (before starting the lookup) avoids wasting
  // a network request and keeps latency near-zero for these queries.
  const cnReserved = getCnReservedSldInfo(trimmed);

  // ── Earliest possible lookup start ───────────────────────────────────────
  // Begin the WHOIS/RDAP lookup immediately after input validation — before
  // the API-key check and session check — so those auth round-trips run in
  // parallel with the first RDAP/WHOIS network requests.
  // Skip for CN reserved domains (synthetic result, no lookup needed).
  let _lookupAborted = false;
  let _bufferedPartial: WhoisResult | null = null;
  let _onPartial: (p: WhoisResult) => void = (p) => { _bufferedPartial = p; };

  const lookupPromise = cnReserved ? null : lookupWhoisCacheStreaming(
    trimmed,
    { nocache },
    (partial) => { if (!_lookupAborted) _onPartial(partial); },
  );

  // ── API-key check + auth check (runs in parallel with the lookup above) ──
  const keyOk = await enforceApiKey(req, res, "api");
  if (!keyOk) { _lookupAborted = true; return; }

  const [session, requireLogin] = await Promise.all([
    getServerSession(req, res, authOptions).catch(() => null),
    getSetting("require_login"),
  ]);
  const userId       = (session?.user as any)?.id    ?? null;
  const userEmail    = session?.user?.email           ?? null;
  const isSubscribed = !!((session?.user as any)?.subscriptionAccess);

  // ── Tiered rate limiting — applied after auth so the correct quota applies ─
  // Same-origin (the site itself) is always exempt.
  const tierLimit = sameOrigin    ? RATE_LIMIT_SUB
                  : isSubscribed  ? RATE_LIMIT_SUB
                  : userEmail     ? RATE_LIMIT_AUTHED
                  :                 RATE_LIMIT_ANON;
  const tierKey   = sameOrigin    ? `${ip}:origin`
                  : isSubscribed  ? `${ip}:sub`
                  : userEmail     ? `${ip}:auth`
                  :                 `${ip}:anon`;

  const { allowed, remaining, resetMs } = sameOrigin
    ? { allowed: true, remaining: tierLimit, resetMs: 0 }
    : rateLimit(tierKey, tierLimit, RATE_WINDOW_MS);

  res.setHeader("X-RateLimit-Limit", String(tierLimit));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetMs / 1_000)));

  if (!allowed) {
    _lookupAborted = true;
    return res.status(429).json({ error: "Too many requests — please slow down" });
  }

  if (requireLogin === "1" && !userEmail) {
    _lookupAborted = true;
    return res.status(401).json({ error: "Please log in to perform queries" });
  }

  // ── CN reserved SLD — return synthetic NDJSON result without streaming ────
  if (cnReserved) {
    const tldParts = trimmed.toLowerCase().split(".");
    const tld = tldParts.length >= 2 ? tldParts[tldParts.length - 1] : trimmed;
    const syntheticResult: WhoisAnalyzeResult = {
      ...initialWhoisAnalyzeResult,
      domain: trimmed,
      status: [{ status: "registry-reserved", url: "" }],
      rawWhoisContent: `[CN Reserved] ${cnReserved.descZh}`,
    };
    saveSearchRecord(trimmed, syntheticResult, undefined, userId, userEmail).catch(() => {});
    logQuery({ domain: trimmed, tld, success: true, cached: false, durationMs: 0, errorCode: null, source: "whois" }).catch(() => {});
    res.setHeader("Content-Type", "application/x-ndjson");
    res.setHeader("Cache-Control", "s-maxage=43200, stale-while-revalidate=86400");
    res.write(JSON.stringify({
      time: 0, status: true, cached: false, cacheTtl: 43200, source: "whois",
      result: syntheticResult, partial: false,
    }) + "\n");
    return res.end();
  }

  // ── Set up NDJSON streaming response ─────────────────────────────────────
  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Transfer-Encoding", "chunked");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  let partialSent = false;
  let finalSent   = false;

  function writeChunk(data: WhoisResult & { partial: boolean }) {
    try {
      res.write(JSON.stringify(data) + "\n");
    } catch {
      // Client disconnected
    }
  }

  // Upgrade the partial callback so future partial results write directly.
  _onPartial = (p) => {
    if (!partialSent && !finalSent) {
      partialSent = true;
      writeChunk({ ...p, result: p.result ?? { ...initialWhoisAnalyzeResult }, partial: true });
    }
  };

  // If a partial result arrived during the session check, send it now.
  // TypeScript 5.9's narrowing is too aggressive here: after _onPartial is
  // reassigned (above) it concludes _bufferedPartial can never be non-null,
  // even though the original closure ran before the reassignment.  The double
  // cast bypasses that over-eager narrowing while keeping the runtime guard.
  const bufferedPartial = _bufferedPartial as unknown as WhoisResult | null;
  if (bufferedPartial !== null && !partialSent && !finalSent) {
    partialSent = true;
    writeChunk({ ...bufferedPartial, result: bufferedPartial.result ?? { ...initialWhoisAnalyzeResult }, partial: true });
  }

  const tldParts = trimmed.toLowerCase().split(".");
  const tld = tldParts.length >= 2 ? tldParts[tldParts.length - 1] : trimmed;

  try {
    const finalResult = await lookupPromise!;

    finalSent = true;

    const sMaxAge = finalResult.cacheTtl && finalResult.cacheTtl > 0 ? finalResult.cacheTtl : 3600;
    const swr     = Math.min(sMaxAge * 4, 86_400);
    res.setHeader("Cache-Control", `s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`);

    writeChunk({
      ...finalResult,
      result: finalResult.result ?? { ...initialWhoisAnalyzeResult },
      partial: false,
    });

    logQuery({
      domain: trimmed, tld,
      success: finalResult.status,
      cached: finalResult.cached ?? false,
      durationMs: (finalResult.time ?? 0) * 1000,
      errorCode: finalResult.status ? null : (finalResult.error?.slice(0, 60) ?? null),
      source: finalResult.source ?? null,
    }).catch(() => {});

    if (finalResult.status) {
      saveSearchRecord(
        trimmed,
        finalResult.result ?? { ...initialWhoisAnalyzeResult },
        finalResult.dnsProbe,
        userId,
        userEmail,
      ).catch(() => {});
    }
  } catch (err) {
    if (!finalSent) {
      const errMsg = err instanceof Error ? err.message : "Unknown error";
      writeChunk({
        time: 0,
        status: false,
        cached: false,
        error: errMsg,
        partial: false,
        result: { ...initialWhoisAnalyzeResult },
      });
      logQuery({
        domain: trimmed, tld, success: false, cached: false,
        durationMs: 0, errorCode: errMsg.slice(0, 60), source: null,
      }).catch(() => {});
    }
  } finally {
    res.end();
  }
}
