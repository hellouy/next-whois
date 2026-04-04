import type { NextApiRequest, NextApiResponse } from "next";
import { many, one } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  const session = await requireAdmin(req, res);
  if (!session) return;

  try {
    const [
      totalRow,
      activeRow,
      tldRows,
      recentRows,
      logsRow,
      noTldRow,
    ] = await Promise.all([
      one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = true"),
      many<{ tld: string; count: string }>(
        `SELECT LOWER(REVERSE(SPLIT_PART(REVERSE(domain), '.', 1))) AS tld,
                COUNT(*) AS count
         FROM reminders
         GROUP BY tld
         ORDER BY count DESC
         LIMIT 20`
      ),
      many<{ domain: string; email: string; active: boolean; created_at: string }>(
        `SELECT domain, email, active, created_at::text
         FROM reminders
         ORDER BY created_at DESC
         LIMIT 10`
      ),
      one<{ count: string }>(
        "SELECT COUNT(*) AS count FROM reminder_logs WHERE sent_at > NOW() - INTERVAL '30 days'"
      ),
      one<{ count: string }>(
        `SELECT COUNT(*) AS count
         FROM reminders r
         LEFT JOIN tld_rules tr ON tr.tld = LOWER(REVERSE(SPLIT_PART(REVERSE(r.domain), '.', 1)))
         WHERE tr.tld IS NULL`
      ),
    ]);

    return res.json({
      total: parseInt(totalRow?.count || "0"),
      active: parseInt(activeRow?.count || "0"),
      tlds: tldRows.map(r => ({ tld: r.tld, count: parseInt(r.count) })),
      recent: recentRows,
      logs30d: parseInt(logsRow?.count || "0"),
      noTldRules: parseInt(noTldRow?.count || "0"),
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: msg });
  }
}
