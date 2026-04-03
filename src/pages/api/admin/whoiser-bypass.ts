import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";
import {
  resetWhoiserBypass,
  resetAllWhoiserBypasses,
  markWhoiserBypassed,
} from "@/lib/whois/whoiser-bypass";

export type WhoiserBypassRow = {
  tld: string;
  whoiser_bypass: boolean;
  fail_count: number;
  last_fail_at: string | null;
  has_manual_server: boolean;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  if (req.method === "GET") {
    const client = await db.connect();
    try {
      const { rows } = await client.query<WhoiserBypassRow>(
        `SELECT
           f.tld,
           f.whoiser_bypass,
           f.fail_count,
           f.last_fail_at::text,
           (c.tld IS NOT NULL AND c.source = 'manual') AS has_manual_server
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         WHERE f.whoiser_bypass = true
         ORDER BY f.fail_count DESC, f.tld`,
      );
      return res.status(200).json({ rows });
    } finally {
      client.release();
    }
  }

  if (req.method === "DELETE") {
    const { tld, clear_all } = req.body as { tld?: string; clear_all?: boolean };
    if (clear_all) {
      await resetAllWhoiserBypasses();
      return res.status(200).json({ ok: true });
    }
    if (!tld) return res.status(400).json({ error: "tld or clear_all required" });
    await resetWhoiserBypass(tld.toLowerCase().replace(/^\./, ""));
    return res.status(200).json({ ok: true });
  }

  if (req.method === "POST") {
    const { tld } = req.body as { tld?: string };
    if (!tld) return res.status(400).json({ error: "tld required" });
    await markWhoiserBypassed(tld.toLowerCase().replace(/^\./, ""));
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
