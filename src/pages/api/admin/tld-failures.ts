import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export type TldFailureEventRow = {
  id: string;
  tld: string;
  fail_reason: string;
  reason_detail: string | null;
  domain: string | null;
  context: string | null;
  created_at: string;
};

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
  tld_api_source: string | null;
  this_week_count?: number;
  prev_week_count?: number;
  window_events?: number;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  // ── GET: paginated config/repair list + windowed dashboard ──────────────
  if (req.method === "GET") {
    // ── Optional: recent failure events for a single TLD ───────────────────
    const eventsFor = (req.query.events_for as string | undefined)?.trim();
    if (eventsFor) {
      const client = await db.connect();
      try {
        const { rows } = await client.query<TldFailureEventRow>(
          `SELECT id::text, tld, fail_reason, reason_detail, domain, context,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at
           FROM tld_failure_events
           WHERE tld = $1
           ORDER BY created_at DESC, id DESC
           LIMIT 50`,
          [eventsFor.toLowerCase().replace(/^\./, "")],
        );
        return res.status(200).json({ events: rows });
      } finally {
        client.release();
      }
    }

    // fail_count is frozen at 0 since R5 (metric source = query_logs + events).
    // min_fails kept only for backward compat; 0 = no counter filter.
    const minFails   = Math.max(0, parseInt(String(req.query.min_fails ?? "0"), 10));
    const reason     = req.query.reason as string | undefined;
    const search     = req.query.search as string | undefined;
    const hideManual = req.query.hide_manual === "1";
    const repair     = req.query.repair as string | undefined;
    const page       = Math.max(1, parseInt(String(req.query.page ?? "1"), 10));
    const perPage    = Math.min(200, Math.max(10, parseInt(String(req.query.per_page ?? "50"), 10)));
    const offset     = (page - 1) * perPage;
    // Dashboard window in days (7 or 30; clamped defensively)
    const windowDays = Math.min(Math.max(parseInt(String(req.query.window ?? "7"), 10) || 7, 1), 30);

    const client = await db.connect();
    try {
      const params: (string | number | string[])[] = [];
      let where =
        `WHERE char_length(f.tld) BETWEEN 2 AND 24
         AND f.tld ~ '^[a-zA-Z]'
         AND f.tld NOT LIKE '%.%'`;

      if (minFails > 0) {
        params.push(minFails);
        where += ` AND f.fail_count >= $${params.length}`;
      }
      if (reason) {
        params.push(reason);
        where += ` AND f.fail_reason = $${params.length}`;
      }
      if (repair && repair !== "all") {
        if (repair === "pending") {
          where += ` AND (f.repair_status IS NULL OR f.repair_status = 'pending')`;
        } else {
          params.push(repair);
          where += ` AND f.repair_status = $${params.length}`;
        }
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
           f.tld_api_source,
           (c.tld IS NOT NULL) AS has_custom_server,
           c.source AS custom_server_source
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         ${where}
         ORDER BY
           CASE WHEN f.repair_status IS NULL OR f.repair_status = 'pending' THEN 0
                WHEN f.repair_status = 'in_progress' THEN 1
                WHEN f.repair_status = 'wont_fix' THEN 2
                ELSE 3 END,
           f.last_fail_at DESC NULLS LAST,
           f.tld
         LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
        dataParams,
      );

      // Summary pills: group by repair status (counter columns are frozen — R5)
      const summary = await client.query<{ reason: string | null; count: string }>(
        `SELECT COALESCE(NULLIF(repair_status, ''), 'pending') AS reason, COUNT(*)::text AS count
         FROM tld_fallback_stats
         WHERE char_length(tld) BETWEEN 2 AND 24
           AND tld ~ '^[a-zA-Z]'
           AND tld NOT LIKE '%.%'
         GROUP BY 1 ORDER BY count DESC`,
      );

      // Period comparison only for current page (small set → fast)
      // Metric fact source is query_logs (search_history records successes only,
      // so joining it for failures always returned 0 — fixed).
      const tldList = rows.map(r => r.tld);
      let periodMap: Record<string, { this_week: number; prev_week: number }> = {};
      if (tldList.length > 0 && req.query.period_compare !== "0") {
        const periodRows = await client.query<{ tld: string; this_week: string; prev_week: string }>(
          `SELECT
             f.tld,
             COALESCE(SUM(CASE WHEN q.created_at >= NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END), 0)::text AS this_week,
             COALESCE(SUM(CASE WHEN q.created_at >= NOW() - INTERVAL '14 days'
                               AND q.created_at <  NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END), 0)::text AS prev_week
           FROM tld_fallback_stats f
           LEFT JOIN query_logs q
             ON q.tld = f.tld
             AND NOT q.success
             AND q.created_at >= NOW() - INTERVAL '14 days'
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

      // Diagnostic events per TLD within the dashboard window — lets the
      // config/repair list show how many failures each suffix actually
      // produced in the window (fact source = tld_failure_events).
      const evCountArg = [windowDays, tldList] as (string | number | string[])[];
      const evCountRows = await client.query<{ tld: string; count: string }>(
        `SELECT tld, COUNT(*)::text AS count
         FROM tld_failure_events
         WHERE created_at > NOW() - make_interval(days => $1)
           AND tld = ANY($2::text[])
         GROUP BY tld`,
        evCountArg,
      );
      const evCountMap: Record<string, number> = {};
      for (const r of evCountRows.rows) evCountMap[r.tld] = parseInt(r.count, 10);
      rowsWithPeriod.forEach(r => { r.window_events = evCountMap[r.tld] ?? 0; });

      // ── Windowed dashboard aggregates ─────────────────────────────────────
      // Metrics (totals / success rate / delta) come from query_logs — the
      // metric fact source. reason_dist / trend / top_failed come from the
      // diagnostic fact source tld_failure_events (R1/R2/R4).
      const wArg = [windowDays] as (string | number)[];
      const m = await client.query<{ total: string; success: string; fail: string }>(
        `SELECT COUNT(*)::text AS total,
                COUNT(*) FILTER (WHERE success)::text AS success,
                COUNT(*) FILTER (WHERE NOT success)::text AS fail
         FROM query_logs
         WHERE created_at > NOW() - make_interval(days => $1)`,
        wArg,
      );
      const prevAgg = await client.query<{ fail: string }>(
        `SELECT COUNT(*) FILTER (WHERE NOT success)::text AS fail
         FROM query_logs
         WHERE created_at >= NOW() - make_interval(days => $1 * 2)
           AND created_at <  NOW() - make_interval(days => $1)`,
        [windowDays],
      );
      const mrow  = m.rows[0];
      const qTotal = parseInt(mrow?.total  ?? "0");
      const qOk    = parseInt(mrow?.success ?? "0");
      const qFail  = parseInt(mrow?.fail    ?? "0");
      const prevFail = parseInt(prevAgg.rows[0]?.fail ?? "0");
      const metrics = {
        window_days: windowDays,
        total_queries: qTotal,
        success: qOk,
        fail: qFail,
        success_rate: qTotal > 0 ? Math.round((qOk / qTotal) * 1000) / 10 : null,
        prev_fail: prevFail,
        fail_delta_pct:
          prevFail > 0
            ? Math.round(((qFail - prevFail) / prevFail) * 1000) / 10
            : (qFail > 0 ? 100 : 0),
      };

      const evArg = [windowDays] as (string | number)[];
      const reasonDist = await client.query<{ reason: string; count: string }>(
        `SELECT fail_reason AS reason, COUNT(*)::text AS count
         FROM tld_failure_events
         WHERE created_at > NOW() - make_interval(days => $1)
         GROUP BY fail_reason ORDER BY count DESC`,
        evArg,
      );
      const trend = await client.query<{ date: string; count: string }>(
        `SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS date, COUNT(*)::text AS count
         FROM tld_failure_events
         WHERE created_at > NOW() - make_interval(days => $1)
         GROUP BY date_trunc('day', created_at) ORDER BY date`,
        evArg,
      );
      const topFailed = await client.query<{
        tld: string; fail_count: string; last_domain: string | null;
        sample_error: string | null; last_fail_at: string | null;
        last_reason: string | null;
        total: string; success: string; success_rate: string | null;
      }>(
        `WITH ev AS (
           SELECT tld, COUNT(*)::int AS fail_count,
                  MAX(created_at) AS last_fail_ts,
                  (ARRAY_AGG(domain ORDER BY created_at DESC))[1] AS last_domain,
                  (ARRAY_AGG(reason_detail ORDER BY created_at DESC))[1] AS sample_error,
                  (ARRAY_AGG(fail_reason ORDER BY created_at DESC))[1] AS last_reason
           FROM tld_failure_events
           WHERE created_at > NOW() - make_interval(days => $1)
           GROUP BY tld
         )
         SELECT ev.tld, ev.fail_count::text,
                ev.last_domain, ev.sample_error, ev.last_fail_ts::text, ev.last_reason,
                COALESCE(q.total, 0)::text  AS total,
                COALESCE(q.success, 0)::text AS success,
                (CASE WHEN q.total > 0 THEN ROUND(q.success::numeric / q.total * 100, 1)::text ELSE NULL END) AS success_rate
         FROM ev
         LEFT JOIN (
           SELECT tld, COUNT(*)::int AS total, COUNT(*) FILTER (WHERE success)::int AS success
           FROM query_logs
           WHERE created_at > NOW() - make_interval(days => $1)
           GROUP BY tld
         ) q ON q.tld = ev.tld
         ORDER BY ev.fail_count DESC, ev.last_fail_ts DESC
         LIMIT 50`,
        evArg,
      );

      return res.status(200).json({
        rows: rowsWithPeriod,
        summary: summary.rows,
        total,
        page,
        per_page: perPage,
        total_pages: Math.ceil(total / perPage),
        window_days: windowDays,
        metrics,
        reason_dist: reasonDist.rows,
        trend: trend.rows,
        top_failed: topFailed.rows,
      });
    } finally {
      client.release();
    }
  }

  // ── DELETE: clear diagnostic statistics (events table, R5) ──────────────
  // Config/repair state in tld_fallback_stats is untouched — counters there
  // are frozen. Clearing now removes tld_failure_events rows.
  if (req.method === "DELETE") {
    const { tld, clear_all, tlds } = req.body as {
      tld?: string;
      tlds?: string[];
      clear_all?: boolean;
    };
    const client = await db.connect();
    try {
      // Bulk delete specific list
      if (tlds && tlds.length > 0) {
        const { rowCount } = await client.query(
          `DELETE FROM tld_failure_events WHERE tld = ANY($1::text[])`,
          [tlds],
        );
        return res.status(200).json({ ok: true, cleared: rowCount ?? 0 });
      }

      // Clear all events
      if (clear_all) {
        const { rowCount } = await client.query(`DELETE FROM tld_failure_events`);
        return res.status(200).json({ ok: true, cleared: rowCount ?? 0 });
      }

      // Single TLD
      if (!tld) return res.status(400).json({ error: "tld, tlds, or clear_all required" });
      const { rowCount } = await client.query(
        `DELETE FROM tld_failure_events WHERE tld = $1`,
        [tld],
      );
      return res.status(200).json({ ok: true, cleared: rowCount ?? 0 });
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
