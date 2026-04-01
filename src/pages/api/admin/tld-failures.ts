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
  repair_status: string | null;
  found_server: string | null;
  admin_notes: string | null;
  repaired_at: string | null;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  if (req.method === "GET") {
    const minFails = parseInt(String(req.query.min_fails ?? "1"), 10);
    const reason   = req.query.reason as string | undefined;
    const search   = req.query.search as string | undefined;
    const client = await db.connect();
    try {
      let where = `WHERE f.fail_count >= $1`;
      const params: any[] = [minFails];
      if (reason) { params.push(reason); where += ` AND f.fail_reason = $${params.length}`; }
      if (search) { params.push(`%${search}%`); where += ` AND f.tld ILIKE $${params.length}`; }
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
           (c.tld IS NOT NULL) AS has_custom_server
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         ${where}
         ORDER BY f.fail_count DESC, f.last_fail_at DESC
         LIMIT 500`,
        params,
      );
      const summary = await client.query<{ reason: string | null; count: string }>(
        `SELECT fail_reason AS reason, COUNT(*) AS count
         FROM tld_fallback_stats WHERE fail_count > 0
         GROUP BY fail_reason ORDER BY count DESC`
      );
      return res.status(200).json({ rows, summary: summary.rows });
    } finally {
      client.release();
    }
  }

  if (req.method === "DELETE") {
    const { tld } = req.body as { tld?: string };
    if (!tld) return res.status(400).json({ error: "tld required" });
    const client = await db.connect();
    try {
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
