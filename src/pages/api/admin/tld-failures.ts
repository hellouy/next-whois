import type { NextApiRequest, NextApiResponse } from "next";
import { getSession } from "next-auth/react";
import { getDbReady } from "@/lib/db";

export type TldFailureRow = {
  tld: string;
  fail_count: number;
  fail_reason: string | null;
  last_domain: string | null;
  sample_error: string | null;
  last_fail_at: string | null;
  has_custom_server: boolean;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession({ req });
  if (!session?.user) return res.status(401).json({ error: "Unauthorized" });

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  if (req.method === "GET") {
    const client = await db.connect();
    try {
      const { rows } = await client.query<TldFailureRow>(
        `SELECT
           f.tld,
           f.fail_count,
           f.fail_reason,
           f.last_domain,
           f.sample_error,
           f.last_fail_at::text,
           (c.tld IS NOT NULL) AS has_custom_server
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         WHERE f.fail_count > 0
         ORDER BY f.fail_count DESC, f.last_fail_at DESC
         LIMIT 200`,
      );
      return res.status(200).json({ rows });
    } finally {
      client.release();
    }
  }

  if (req.method === "DELETE") {
    // Reset a single TLD's failure count
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

  return res.status(405).json({ error: "Method not allowed" });
}
