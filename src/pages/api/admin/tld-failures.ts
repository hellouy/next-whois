import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export type TldFailureRow = {
  tld: string;
  fail_count: number;
  fail_reason: string | null;
  last_domain: string | null;
  sample_error: string | null;
  last_fail_at: string | null;
  has_custom_server: boolean;
  custom_server_source: string | null;
  repair_status: string | null;
  found_server: string | null;
  admin_notes: string | null;
  repaired_at: string | null;
  whoiser_bypass: boolean;
  this_week_count?: number;
  prev_week_count?: number;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  // ── GET: paginated list ───────────────────────────────────────────────────
  if (req.method === "GET") {
    const minFails   = Math.max(1, parseInt(String(req.query.min_fails ?? "1"), 10));
    const reason     = req.query.reason as string | undefined;
    const search     = req.query.search as string | undefined;
    const hideManual = req.query.hide_manual === "1";
    const page       = Math.max(1, parseInt(String(req.query.page ?? "1"), 10));
    const perPage    = Math.min(200, Math.max(10, parseInt(String(req.query.per_page ?? "50"), 10)));
    const offset     = (page - 1) * perPage;

    const client = await db.connect();
    try {
      const params: (string | number | string[])[] = [minFails];
      let where =
        `WHERE f.fail_count >= $1
         AND char_length(f.tld) BETWEEN 2 AND 24
         AND f.tld ~ '^[a-zA-Z]'
         AND f.tld NOT LIKE '%.%'`;

      if (reason) {
        params.push(reason);
        where += ` AND f.fail_reason = $${params.length}`;
      }
      if (search) {
        params.push(`%${search}%`);
        where += ` AND f.tld ILIKE $${params.length}`;
      }
      if (hideManual) {
        where += ` AND (c.tld IS NULL OR c.source <> 'manual')`;
      }

      // Total count (cheap — no period comparison)
      const countParams = [...params];
      const countResult = await client.query<{ total: string }>(
        `SELECT COUNT(*)::text AS total
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         ${where}`,
        countParams,
      );
      const total = parseInt(countResult.rows[0]?.total ?? "0");

      // Paged rows
      const dataParams = [...params, perPage, offset];
      const { rows } = await client.query<TldFailureRow>(
        `SELECT
           f.tld,
           f.fail_count,
           f.fail_reason,
           f.last_domain,
           f.sample_error,
           f.last_fail_at::text,
           f.repair_status,
           f.found_server,
           f.admin_notes,
           f.repaired_at::text,
           COALESCE(f.whoiser_bypass, false) AS whoiser_bypass,
           (c.tld IS NOT NULL) AS has_custom_server,
           c.source AS custom_server_source
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         ${where}
         ORDER BY f.fail_count DESC, f.last_fail_at DESC NULLS LAST
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        dataParams,
      );

      // Summary (not paginated)
      const summary = await client.query<{ reason: string | null; count: string }>(
        `SELECT fail_reason AS reason, COUNT(*) AS count
         FROM tld_fallback_stats WHERE fail_count > 0
         GROUP BY fail_reason ORDER BY count DESC`,
      );

      // Period comparison only for current page (small set → fast)
      const tldList = rows.map(r => r.tld);
      let periodMap: Record<string, { this_week: number; prev_week: number }> = {};
      if (tldList.length > 0 && req.query.period_compare !== "0") {
        const periodRows = await client.query<{ tld: string; this_week: string; prev_week: string }>(
          `SELECT
             f.tld,
             COALESCE(SUM(CASE WHEN h.created_at >= NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END), 0)::text AS this_week,
             COALESCE(SUM(CASE WHEN h.created_at >= NOW() - INTERVAL '14 days'
                               AND h.created_at <  NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END), 0)::text AS prev_week
           FROM tld_fallback_stats f
           LEFT JOIN search_history h
             ON LOWER(REVERSE(SPLIT_PART(REVERSE(h.query), '.', 1))) = f.tld
             AND h.query_type = 'domain'
             AND h.reg_status IS NULL
             AND h.created_at >= NOW() - INTERVAL '14 days'
           WHERE f.tld = ANY($1::text[])
           GROUP BY f.tld`,
          [tldList],
        ).catch(() => ({ rows: [] as { tld: string; this_week: string; prev_week: string }[] }));
        for (const pr of periodRows.rows) {
          periodMap[pr.tld] = { this_week: parseInt(pr.this_week), prev_week: parseInt(pr.prev_week) };
        }
      }

      const rowsWithPeriod = rows.map(r => ({
        ...r,
        this_week_count: periodMap[r.tld]?.this_week ?? 0,
        prev_week_count: periodMap[r.tld]?.prev_week ?? 0,
      }));

      return res.status(200).json({
        rows: rowsWithPeriod,
        summary: summary.rows,
        total,
        page,
        per_page: perPage,
        total_pages: Math.ceil(total / perPage),
      });
    } finally {
      client.release();
    }
  }

  // ── DELETE: clear counts ─────────────────────────────────────────────────
  if (req.method === "DELETE") {
    const { tld, clear_all, reason, tlds } = req.body as {
      tld?: string;
      tlds?: string[];
      clear_all?: boolean;
      reason?: string;
    };
    const client = await db.connect();
    try {
      // Bulk delete specific list
      if (tlds && tlds.length > 0) {
        const { rowCount } = await client.query(
          `UPDATE tld_fallback_stats
           SET fail_count = 0, fail_reason = NULL, sample_error = NULL, last_fail_at = NULL
           WHERE tld = ANY($1::text[])`,
          [tlds],
        );
        return res.status(200).json({ ok: true, cleared: rowCount ?? 0 });
      }

      // Clear all (optionally filtered by reason)
      if (clear_all) {
        let where = `WHERE fail_count > 0`;
        const params: any[] = [];
        if (reason) { params.push(reason); where += ` AND fail_reason = $${params.length}`; }
        const { rowCount } = await client.query(
          `UPDATE tld_fallback_stats
           SET fail_count = 0, fail_reason = NULL, sample_error = NULL, last_fail_at = NULL
           ${where}`,
          params,
        );
        return res.status(200).json({ ok: true, cleared: rowCount ?? 0 });
      }

      // Single TLD
      if (!tld) return res.status(400).json({ error: "tld, tlds, or clear_all required" });
      await client.query(
        `UPDATE tld_fallback_stats
         SET fail_count = 0, fail_reason = NULL, sample_error = NULL, last_fail_at = NULL
         WHERE tld = $1`,
        [tld],
      );
      return res.status(200).json({ ok: true });
    } finally {
      client.release();
    }
  }

  // ── PATCH: update repair_status / admin_notes / found_server ────────────
  if (req.method === "PATCH") {
    const { tld, repair_status, admin_notes, found_server } = req.body as {
      tld?: string;
      repair_status?: string;
      admin_notes?: string;
      found_server?: string;
    };
    if (!tld) return res.status(400).json({ error: "tld required" });
    const client = await db.connect();
    try {
      await client.query(
        `UPDATE tld_fallback_stats
         SET repair_status = COALESCE($2, repair_status),
             admin_notes   = COALESCE($3, admin_notes),
             found_server  = COALESCE($4, found_server),
             repaired_at   = CASE WHEN $2 = 'fixed' THEN NOW() ELSE repaired_at END
         WHERE tld = $1`,
        [tld, repair_status ?? null, admin_notes ?? null, found_server ?? null],
      );
      return res.status(200).json({ ok: true });
    } finally {
      client.release();
    }
  }

  return res.status(405).json({ error: "Method not allowed" });
}
