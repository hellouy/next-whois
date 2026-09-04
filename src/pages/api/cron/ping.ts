import type { NextApiRequest, NextApiResponse } from "next";
import { isDbReady } from "@/lib/db-query";
import { getDbReady } from "@/lib/db";
import { isRedisAvailable, getRedisValue } from "@/lib/server/redis";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/cron/ping");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  // Auth is fail-closed: when CRON_SECRET is not configured, only an admin
  // session may trigger the endpoint (never anonymous access).
  const secret = process.env.CRON_SECRET;
  if (secret) {
    const authHeader = req.headers.authorization;
    if (authHeader !== `Bearer ${secret}`) {
      return res.status(401).json({ error: "unauthorized" });
    }
  } else {
    const { requireAdmin } = await import("@/lib/admin");
    const session = await requireAdmin(req, res);
    if (!session) return;
  }

  const dbReady = await isDbReady();
  if (!dbReady) {
    return res.status(503).json({ ok: false, error: "db unavailable", ts: new Date().toISOString() });
  }

  const db = await getDbReady();
  const dbStart = Date.now();
  let dbLatencyMs: number | null = null;
  let dbError: string | null = null;
  try {
    await db!.query("SELECT 1");
    dbLatencyMs = Date.now() - dbStart;
    logger.info(`[cron/ping] db alive (${dbLatencyMs}ms)`);
  } catch (err: any) {
    dbError = err.message;
    logger.error("[cron/ping] db query failed:", err.message);
  }

  let redisOk = false;
  let redisLatencyMs: number | null = null;
  if (isRedisAvailable()) {
    const redisStart = Date.now();
    try {
      await getRedisValue("ping:probe");
      redisLatencyMs = Date.now() - redisStart;
      redisOk = true;
      logger.info(`[cron/ping] redis alive (${redisLatencyMs}ms)`);
    } catch (err: any) {
      logger.error("[cron/ping] redis probe failed:", err.message);
    }
  }

  const ok = !dbError;
  const status = ok ? 200 : 500;
  return res.status(status).json({
    ok,
    db: dbError ? { ok: false, error: dbError } : { ok: true, latencyMs: dbLatencyMs },
    redis: redisOk ? { ok: true, latencyMs: redisLatencyMs } : { ok: false },
    ts: new Date().toISOString(),
  });
}
