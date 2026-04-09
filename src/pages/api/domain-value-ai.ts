/**
 * POST /api/domain-value-ai
 * AI-powered domain value deep analysis with Redis caching.
 *
 * Body: { domain: string }
 * Returns: DomainAiAnalysis | { error: string }
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth";
import { authOptions } from "./auth/[...nextauth]";
import { analyzeDomainWithAi } from "@/lib/server/domain-value-ai";
import { scoreDomain } from "@/lib/domain-value";
import { checkRateLimit } from "@/lib/rate-limit";

// Rate limit: 5 AI calls per IP per minute, backed by Redis so it survives
// lambda cold starts and is consistent across multiple function instances.
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // Auth required
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) {
    return res.status(401).json({ error: "Authentication required to use AI analysis" });
  }

  const { domain } = req.body ?? {};
  if (!domain || typeof domain !== "string" || domain.length > 100) {
    return res.status(400).json({ error: "Invalid domain" });
  }

  const cleanDomain = domain.toLowerCase().trim();

  // Only analyze domains (must have at least one dot)
  const dotIdx = cleanDomain.indexOf(".");
  if (dotIdx < 1) {
    return res.status(400).json({ error: "Please enter a complete domain name (with TLD)" });
  }

  // Quick score check — only worth analyzing domains with some value
  const scoreResult = scoreDomain(cleanDomain, "domain");
  if (!scoreResult || scoreResult.score < 10) {
    return res.status(400).json({ error: "Domain value is too low for AI deep analysis" });
  }

  // Redis-backed rate limit — persists across lambda restarts and instances.
  // Key includes user email so each user has their own independent limit.
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    ?? req.socket.remoteAddress
    ?? "unknown";
  const rateLimitKey = `domain-value-ai:${session.user.email}:${ip}`;
  const rl = await checkRateLimit(rateLimitKey, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);
  if (!rl.ok) {
    return res.status(429).json({ error: "Too many requests, please try again later" });
  }

  try {
    const analysis = await analyzeDomainWithAi(cleanDomain);
    if (!analysis) {
      return res.status(503).json({ error: "AI analysis service is temporarily unavailable, please try again" });
    }
    return res.status(200).json(analysis);
  } catch (e) {
    console.error("[api/domain-value-ai]", e);
    return res.status(500).json({ error: "AI analysis failed, please try again" });
  }
}
