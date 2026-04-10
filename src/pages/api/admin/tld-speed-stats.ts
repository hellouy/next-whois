import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export type TldSpeedRow = {
  tld: string;
  total: number;
  successes: number;
  failures: number;
  fail_pct: number;
  avg_ms: number;
  p50_ms: number;
  p95_ms: number;
  max_ms: number;
  cached_pct: number;
  last_seen: string;
};

export type TldSpeedStats = {
  period_hours: number;
  total_queries: number;
  total_success: number;
  total_fail: number;
  overall_avg_ms: number;
  rows: TldSpeedRow[];
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  const hours   = Math.min(parseInt(String(req.query.hours ?? "24"), 10), 720) || 24;
  const minQry  = Math.max(parseInt(String(req.query.min_queries ?? "1"), 10), 1);
  const sort    = ["avg_ms", "fail_pct", "total", "p95_ms"].includes(String(req.query.sort))
    ? String(req.query.sort) : "avg_ms";
  const limit   = Math.min(parseInt(String(req.query.limit ?? "100"), 10), 500) || 100;

  const client = await db.connect();
  try {
    const { rows } = await client.query<TldSpeedRow>(`
      SELECT
        tld,
        COUNT(*)::int                                                          AS total,
        COUNT(*) FILTER (WHERE success)::int                                   AS successes,
        COUNT(*) FILTER (WHERE NOT success)::int                               AS failures,
        ROUND(COUNT(*) FILTER (WHERE NOT success)::numeric / COUNT(*) * 100, 1)::float AS fail_pct,
        ROUND(AVG(duration_ms))::int                                           AS avg_ms,
        ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration_ms))::int  AS p50_ms,
        ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms))::int AS p95_ms,
        MAX(duration_ms)                                                       AS max_ms,
        ROUND(COUNT(*) FILTER (WHERE cached)::numeric / COUNT(*) * 100, 1)::float AS cached_pct,
        MAX(created_at)::text                                                  AS last_seen
      FROM query_logs
      WHERE created_at > NOW() - ($1 || ' hours')::interval
        AND tld <> ''
      GROUP BY tld
      HAVING COUNT(*) >= $2
      ORDER BY ${sort} DESC NULLS LAST
      LIMIT $3
    `, [hours, minQry, limit]);

    const agg = await client.query<{
      total: string; success: string; fail: string; avg_ms: string;
    }>(`
      SELECT
        COUNT(*)::text           AS total,
        COUNT(*) FILTER (WHERE success)::text  AS success,
        COUNT(*) FILTER (WHERE NOT success)::text AS fail,
        ROUND(AVG(duration_ms))::text AS avg_ms
      FROM query_logs
      WHERE created_at > NOW() - ($1 || ' hours')::interval
    `, [hours]);

    const a = agg.rows[0];
    const result: TldSpeedStats = {
      period_hours: hours,
      total_queries:  parseInt(a.total   ?? "0"),
      total_success:  parseInt(a.success ?? "0"),
      total_fail:     parseInt(a.fail    ?? "0"),
      overall_avg_ms: parseInt(a.avg_ms  ?? "0"),
      rows,
    };

    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json(result);
  } finally {
    client.release();
  }
}
