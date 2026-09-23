/**
 * Vercel Cron — Domain drop-calendar ingestion.
 *
 * Runs every configured drop source through collect → enrich → score → upsert,
 * records per-source status and invalidates the query cache. Authentication
 * reuses the shared CRON_SECRET bearer / admin-session pattern.
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { isDbReady } from "@/lib/db-query";
import { verifySecretTimingSafe } from "@/lib/admin";
import { runDropPipeline } from "@/lib/drop-pipeline";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/cron/drop-sources");

export const config = { maxDuration: 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).end();
  }

  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const auth = req.headers.authorization;
    const legacy = req.headers["x-cron-secret"] as string | undefined;
    const provided = auth?.startsWith("Bearer ") ? auth.slice(7) : legacy;
    if (!verifySecretTimingSafe(provided, cronSecret)) {
      return res.status(401).json({ error: "unauthorized" });
    }
  } else {
    // Fail-closed: without CRON_SECRET only an admin session may run ingestion.
    const { requireAdmin } = await import("@/lib/admin");
    const session = await requireAdmin(req, res);
    if (!session) return;
  }

  if (!(await isDbReady())) {
    return res.status(503).json({ error: "DB unavailable" });
  }

  try {
    const result = await runDropPipeline();
    logger.info(
      `[cron/drop-sources] upserted=${result.upserted} skipped=${result.skipped} sources=${result.sources.length}`,
    );
    return res.json({ ok: true, ...result, ts: new Date().toISOString() });
  } catch (e: any) {
    const message = e?.message ?? String(e);
    logger.error(`[cron/drop-sources] pipeline failed: ${message}`);
    return res.status(500).json({ ok: false, error: message });
  }
}
