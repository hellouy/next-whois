import type { NextApiRequest, NextApiResponse } from "next";
import { many, run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (!(await isDbReady())) {
    return res.status(503).json({ error: "数据库未就绪" });
  }

  if (req.method === "GET") {
    try {
      const rows = await many<{
        tld: string;
        fail_count: number;
        use_fallback: boolean;
        last_fail_at: string | null;
      }>(
        `SELECT tld, fail_count, use_fallback, last_fail_at
         FROM tld_fallback_stats
         ORDER BY use_fallback DESC, fail_count DESC, last_fail_at DESC
         LIMIT 200`,
      );
      return res.json({ rows });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  // POST: manually create or upsert a TLD entry
  if (req.method === "POST") {
    const { tld, fail_count, use_fallback } = req.body as {
      tld?: string;
      fail_count?: number;
      use_fallback?: boolean;
    };
    if (!tld || !/^[a-z0-9-]{1,63}$/.test(tld.toLowerCase().replace(/^\./, ""))) {
      return res.status(400).json({ error: "无效的 TLD（仅支持小写字母、数字、连字符）" });
    }
    const normalized = tld.toLowerCase().replace(/^\./, "");
    const fc = typeof fail_count === "number" ? Math.max(0, Math.floor(fail_count)) : 0;
    const uf = typeof use_fallback === "boolean" ? use_fallback : fc >= 3;
    try {
      await run(
        `INSERT INTO tld_fallback_stats (tld, fail_count, use_fallback, last_fail_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (tld) DO UPDATE
           SET fail_count   = $2,
               use_fallback = $3,
               last_fail_at = NOW()`,
        [normalized, fc, uf],
      );
      const rows = await many<{
        tld: string; fail_count: number; use_fallback: boolean; last_fail_at: string | null;
      }>(`SELECT tld, fail_count, use_fallback, last_fail_at FROM tld_fallback_stats WHERE tld = $1`, [normalized]);
      return res.json({ ok: true, row: rows[0] });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const { tld } = req.body as { tld?: string };
    try {
      if (tld) {
        await run(`DELETE FROM tld_fallback_stats WHERE tld = $1`, [tld]);
      } else {
        await run(`DELETE FROM tld_fallback_stats`);
      }
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PATCH") {
    const { tld, use_fallback, fail_count } = req.body as {
      tld: string;
      use_fallback?: boolean;
      fail_count?: number;
    };
    if (!tld) return res.status(400).json({ error: "缺少 tld 参数" });
    try {
      if (typeof fail_count === "number") {
        const fc = Math.max(0, Math.floor(fail_count));
        // Auto-set use_fallback based on threshold if not explicitly provided
        const uf = typeof use_fallback === "boolean" ? use_fallback : fc >= 3;
        await run(
          `UPDATE tld_fallback_stats SET fail_count = $2, use_fallback = $3 WHERE tld = $1`,
          [tld, fc, uf],
        );
      } else if (typeof use_fallback === "boolean") {
        await run(
          `UPDATE tld_fallback_stats SET use_fallback = $2 WHERE tld = $1`,
          [tld, use_fallback],
        );
      } else {
        return res.status(400).json({ error: "缺少 use_fallback 或 fail_count 参数" });
      }
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, POST, DELETE, PATCH");
  return res.status(405).json({ error: "Method not allowed" });
}
