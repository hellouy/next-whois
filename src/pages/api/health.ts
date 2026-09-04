import type { NextApiRequest, NextApiResponse } from "next";
import { isDbReady } from "@/lib/db-query";
import { isRedisAvailable } from "@/lib/server/redis";

/**
 * Public, unauthenticated health endpoint for uptime monitoring.
 * Returns component status; always 200 with body (degraded states included)
 * so monitors can alert on the payload rather than on HTTP status.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const started = Date.now();
  const db = await isDbReady().catch(() => false);
  const redis = isRedisAvailable();

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({
    ok: true,
    status: db ? (redis ? "healthy" : "degraded") : "unhealthy",
    components: { db: db ? "up" : "down", redis: redis ? "up" : "down" },
    latencyMs: Date.now() - started,
    ts: new Date().toISOString(),
  });
}
