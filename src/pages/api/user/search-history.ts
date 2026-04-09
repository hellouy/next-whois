import type { NextApiRequest, NextApiResponse } from "next";
import { getSession } from "@/lib/auth";
import { randomBytes } from "crypto";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { computeValueTier, maybeSendHighValueAlert } from "@/lib/server/save-search-record";

const MAX_HISTORY   = 100;
const PAGE_SIZE     = 20;

/** Delete records that have exceeded their tier-based retention period. */
async function pruneExpired(userId: string) {
  await run(
    `DELETE FROM search_history WHERE user_id = $1 AND (
       (value_tier = 'high'     AND created_at < NOW() - INTERVAL '50 days') OR
       (value_tier = 'valuable' AND created_at < NOW() - INTERVAL '20 days') OR
       ((value_tier = 'normal' OR value_tier IS NULL)
                                AND created_at < NOW() - INTERVAL '10 days')
     )`,
    [userId],
  );
}

/** Keep only the newest MAX_HISTORY records for this user. */
async function trimToLimit(userId: string) {
  await run(
    `DELETE FROM search_history WHERE user_id = $1
     AND id NOT IN (
       SELECT id FROM search_history WHERE user_id = $1
       ORDER BY created_at DESC LIMIT $2
     )`,
    [userId, MAX_HISTORY],
  );
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res);
  const userId = (session?.user as any)?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "db unavailable" });

  const userEmail = (session?.user as any)?.email as string | undefined;

  // ── GET: paginated history ────────────────────────────────────────────────
  if (req.method === "GET") {
    const page  = Math.max(1, parseInt((req.query.page as string) || "1") || 1);
    const limit = PAGE_SIZE;
    const offset = (page - 1) * limit;

    const [rows, countRow] = await Promise.all([
      many(
        `SELECT id, query, query_type, created_at, reg_status, expiration_date,
                remaining_days, value_tier
         FROM (
           SELECT DISTINCT ON (LOWER(query)) id, query, query_type, created_at,
                  reg_status, expiration_date, remaining_days, value_tier
           FROM search_history WHERE user_id = $1
           ORDER BY LOWER(query), created_at DESC
         ) sub
         ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
        [userId, limit, offset],
      ),
      one<{ count: string }>(
        "SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history WHERE user_id = $1",
        [userId],
      ),
    ]);

    const total = parseInt(countRow?.count ?? "0");
    const pages = Math.max(1, Math.ceil(total / limit));

    return res.status(200).json({
      history: rows.map((r) => ({
        id: r.id,
        query: r.query,
        queryType: r.query_type,
        timestamp: new Date(r.created_at).getTime(),
        regStatus: r.reg_status ?? "unknown",
        expirationDate: r.expiration_date ?? null,
        remainingDays: r.remaining_days ?? null,
        valueTier: r.value_tier ?? "normal",
      })),
      total,
      page,
      pages,
    });
  }

  // ── POST: insert one or bulk-sync ─────────────────────────────────────────
  if (req.method === "POST") {
    const { query, queryType, regStatus, expirationDate, remainingDays } = req.body;

    // Bulk sync from localStorage
    if (Array.isArray(req.body.records)) {
      const records: Array<{
        query: string;
        queryType: string;
        regStatus?: string;
        expirationDate?: string | null;
        remainingDays?: number | null;
        timestamp?: number;
      }> = req.body.records.slice(0, MAX_HISTORY);

      for (const rec of records) {
        const clean = (rec.query || "").trim().slice(0, 255);
        if (!clean) continue;
        const tier = computeValueTier(clean, rec.queryType ?? "domain", rec.regStatus ?? null);
        await run("DELETE FROM search_history WHERE user_id = $1 AND LOWER(query) = LOWER($2)", [userId, clean]);
        const id = randomBytes(8).toString("hex");
        const createdAt = rec.timestamp ? new Date(rec.timestamp).toISOString() : new Date().toISOString();
        await run(
          `INSERT INTO search_history
             (id, user_id, query, query_type, reg_status, expiration_date, remaining_days, value_tier, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT DO NOTHING`,
          [id, userId, clean, rec.queryType ?? "domain", rec.regStatus ?? null,
           rec.expirationDate ?? null, rec.remainingDays ?? null, tier, createdAt],
        );
      }

      await pruneExpired(userId);
      await trimToLimit(userId);
      return res.status(200).json({ ok: true, synced: records.length });
    }

    // Single insert
    if (!query || typeof query !== "string") return res.status(400).json({ error: "query required" });
    const clean = query.trim().slice(0, 255);
    if (!clean) return res.status(400).json({ error: "query empty" });

    const qt = queryType ?? "domain";
    const rs = regStatus ?? null;
    const tier = computeValueTier(clean, qt, rs);

    if (rs === "unregistered") {
      maybeSendHighValueAlert(clean, qt, rs, userEmail).catch(() => {});
    }

    await run("DELETE FROM search_history WHERE user_id = $1 AND LOWER(query) = LOWER($2)", [userId, clean]);

    const id = randomBytes(8).toString("hex");
    await run(
      `INSERT INTO search_history
         (id, user_id, query, query_type, reg_status, expiration_date, remaining_days, value_tier)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [id, userId, clean, qt, rs,
       expirationDate ?? null, typeof remainingDays === "number" ? remainingDays : null, tier],
    );

    await pruneExpired(userId);
    await trimToLimit(userId);

    return res.status(200).json({ ok: true });
  }

  // ── DELETE ────────────────────────────────────────────────────────────────
  if (req.method === "DELETE") {
    const { id } = req.query;
    if (id === "all") {
      await run("DELETE FROM search_history WHERE user_id = $1", [userId]);
      return res.status(200).json({ ok: true });
    }
    if (typeof id === "string" && id) {
      await run("DELETE FROM search_history WHERE id = $1 AND user_id = $2", [id, userId]);
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: "missing id" });
  }

  return res.status(405).end();
}
