import type { NextApiRequest, NextApiResponse } from "next";
import { getActivePlans } from "@/lib/payment";
import { isDbReady } from "@/lib/db-query";
import { getRedisValue, setRedisValue } from "@/lib/server/redis";

const CACHE_KEY = "payment:active_plans";
const CACHE_TTL = 5 * 60; // 5 minutes

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  res.setHeader("Cache-Control", "public, max-age=120, stale-while-revalidate=300");

  // L2: Redis cache
  try {
    const cached = await getRedisValue(CACHE_KEY);
    if (cached) {
      return res.status(200).json(JSON.parse(cached));
    }
  } catch { /* ignore redis errors */ }

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  try {
    const plans = await getActivePlans();
    const payload = { plans };

    // Store in Redis
    try {
      await setRedisValue(CACHE_KEY, JSON.stringify(payload), CACHE_TTL);
    } catch { /* ignore */ }

    return res.status(200).json(payload);
  } catch (err: any) {
    console.error("[payment/plans] error:", err.message);
    return res.status(500).json({ error: "Failed to retrieve plans, please try again" });
  }
}
