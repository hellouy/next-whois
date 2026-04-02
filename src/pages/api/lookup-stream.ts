import type { NextApiRequest, NextApiResponse } from "next";
import { lookupWhoisCacheStreaming } from "@/lib/whois/lookup";
import { WhoisResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { enforceApiKey, isSameOriginRequest } from "@/lib/access-key";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { saveSearchRecord } from "@/lib/server/save-search-record";
import { getSetting } from "@/lib/server/site-settings-server";
import { cleanDomain } from "@/lib/utils";

export const config = {
  maxDuration: 30,
};

const RATE_LIMIT      = 40;
const RATE_WINDOW_MS  = 60_000;
const MAX_QUERY_LENGTH = 300;

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
 * The client should use response.body ReadableStream + TextDecoder to
 * consume each newline-delimited JSON object as it arrives.
 */
export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("Allow", "GET, HEAD");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const ip = getClientIp(req);
  const sameOrigin = isSameOriginRequest(req);
  const { allowed, remaining, resetMs } = sameOrigin
    ? { allowed: true, remaining: RATE_LIMIT, resetMs: 0 }
    : rateLimit(ip, RATE_LIMIT, RATE_WINDOW_MS);
  res.setHeader("X-RateLimit-Limit", String(RATE_LIMIT));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetMs / 1_000)));
  if (!allowed) {
    return res.status(429).json({ error: "Too many requests — please slow down" });
  }

  const keyOk = await enforceApiKey(req, res, "api");
  if (!keyOk) return;

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

  const [session, requireLogin] = await Promise.all([
    getServerSession(req, res, authOptions).catch(() => null),
    getSetting("require_login"),
  ]);
  const userId    = (session?.user as any)?.id    ?? null;
  const userEmail = session?.user?.email           ?? null;

  if (requireLogin === "1" && !userEmail) {
    return res.status(401).json({ error: "请先登录后再进行查询" });
  }

  // Set up NDJSON streaming response
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

  const nocache = req.query.nocache === "1";

  try {
    const finalResult = await lookupWhoisCacheStreaming(
      trimmed,
      { nocache },
      (partial) => {
        if (!partialSent && !finalSent) {
          partialSent = true;
          writeChunk({ ...partial, result: partial.result ?? { ...initialWhoisAnalyzeResult }, partial: true });
        }
      },
    );

    finalSent = true;

    // Only send the final line if it differs from the partial (i.e., WHOIS
    // enrichment added something) or if no partial was sent (cache hit /
    // WHOIS-first path).
    const sMaxAge = finalResult.cacheTtl && finalResult.cacheTtl > 0 ? finalResult.cacheTtl : 3600;
    const swr     = Math.min(sMaxAge * 4, 86_400);
    res.setHeader("Cache-Control", `s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`);

    writeChunk({
      ...finalResult,
      result: finalResult.result ?? { ...initialWhoisAnalyzeResult },
      partial: false,
    });

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
      writeChunk({
        time: 0,
        status: false,
        cached: false,
        error: err instanceof Error ? err.message : "Unknown error",
        partial: false,
        result: { ...initialWhoisAnalyzeResult },
      });
    }
  } finally {
    res.end();
  }
}
