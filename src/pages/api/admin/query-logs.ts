import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { getDbReady } from "@/lib/db";

export type QueryLogRow = {
  id: string;
  domain: string;
  tld: string;
  success: boolean;
  cached: boolean;
  duration_ms: number;
  error_code: string | null;
  source: string | null;
  created_at: string;
};

export type QueryLogStats = {
  total: number;
  errors: number;
  cached: number;
  avg_duration_ms: number;
  error_rate: number;
};

export type QueryLogResponse = {
  rows: QueryLogRow[];
  stats: QueryLogStats;
  total_count: number;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const session = await getServerSession(req, res, authOptions).catch(() => null);
  const isAdmin = !!(session?.user as any)?.isAdmin;
  if (!isAdmin) return res.status(403).json({ error: "Forbidden" });

  const db = await getDbReady().catch(() => null);
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  const {
    tld = "",
    status = "all",
    hours = "24",
    page = "1",
    limit = "100",
  } = req.query as Record<string, string>;

  const pageNum  = Math.max(1, parseInt(page, 10) || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10) || 100));
  const offset   = (pageNum - 1) * limitNum;
  const hoursNum = Math.min(720, Math.max(1, parseInt(hours, 10) || 24));

  const conditions: string[] = [`created_at > NOW() - INTERVAL '${hoursNum} hours'`];
  const params: unknown[]    = [];

  if (tld.trim()) {
    params.push(tld.trim().toLowerCase());
    conditions.push(`tld = $${params.length}`);
  }
  if (status === "ok")   conditions.push("success = true");
  if (status === "fail") conditions.push("success = false");

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const client = await db.connect().catch(() => null);
  if (!client) return res.status(503).json({ error: "DB connection failed" });

  try {
    const [rowsResult, statsResult, countResult] = await Promise.all([
      client.query<QueryLogRow>(
        `SELECT id, domain, tld, success, cached, duration_ms, error_code, source, created_at
         FROM query_logs ${where}
         ORDER BY created_at DESC
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        [...params, limitNum, offset],
      ),
      client.query<{ total: string; errors: string; cached: string; avg_ms: string }>(
        `SELECT
           COUNT(*)                              AS total,
           COUNT(*) FILTER (WHERE NOT success)   AS errors,
           COUNT(*) FILTER (WHERE cached)        AS cached,
           COALESCE(AVG(duration_ms), 0)::int    AS avg_ms
         FROM query_logs ${where}`,
        params,
      ),
      client.query<{ count: string }>(
        `SELECT COUNT(*) FROM query_logs ${where}`,
        params,
      ),
    ]);

    const s = statsResult.rows[0];
    const total      = parseInt(s?.total ?? "0", 10);
    const errors     = parseInt(s?.errors ?? "0", 10);
    const cached_cnt = parseInt(s?.cached ?? "0", 10);
    const avg_ms     = parseInt(s?.avg_ms ?? "0", 10);

    const stats: QueryLogStats = {
      total,
      errors,
      cached: cached_cnt,
      avg_duration_ms: avg_ms,
      error_rate: total > 0 ? Math.round((errors / total) * 1000) / 10 : 0,
    };

    return res.status(200).json({
      rows: rowsResult.rows,
      stats,
      total_count: parseInt(countResult.rows[0]?.count ?? "0", 10),
    } satisfies QueryLogResponse);
  } finally {
    client.release();
  }
}
