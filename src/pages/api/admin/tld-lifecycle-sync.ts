import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { requireAdmin } from "@/lib/admin";
import { many, run, isDbReady } from "@/lib/db-query";
import { invalidateLifecycleOverridesCache } from "@/lib/server/lifecycle-overrides";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const admin = await requireAdmin(req, res);
  if (!admin) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  if (req.method === "GET") {
    try {
      const [rules, overrides] = await Promise.all([
        many<{ tld: string }>(
          `SELECT tld FROM tld_rules WHERE scrape_status = 'ok' ORDER BY tld`
        ).catch(() => []),
        many<{ tld: string }>(
          `SELECT tld FROM tld_lifecycle_overrides ORDER BY tld`
        ).catch(() => []),
      ]);
      const overrideTlds = new Set(overrides.map(r => r.tld));
      const newCount = rules.filter(r => !overrideTlds.has(r.tld)).length;
      return res.json({
        ai_ok: rules.length,
        already_overridden: overrides.length,
        would_import: newCount,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "POST") {
    const { tld } = req.body ?? {};
    try {
      const whereClause = tld
        ? `AND tld = $1`
        : "";
      const params = tld ? [tld] : [];

      const rules = await many<{
        tld: string;
        grace_period_days: number;
        redemption_period_days: number;
        pending_delete_days: number;
        confidence: string;
      }>(
        `SELECT tld, grace_period_days, redemption_period_days, pending_delete_days, confidence
         FROM tld_rules
         WHERE scrape_status = 'ok' ${whereClause}
         ORDER BY tld`,
        params
      ).catch(() => []);

      if (rules.length === 0) {
        return res.json({ imported: 0, skipped: 0, message: "没有可导入的 AI 抓取记录" });
      }

      const existing = await many<{ tld: string }>(
        `SELECT tld FROM tld_lifecycle_overrides`
      ).catch(() => []);
      const existingSet = new Set(existing.map(r => r.tld));

      let imported = 0;
      let skipped = 0;
      for (const rule of rules) {
        if (existingSet.has(rule.tld)) { skipped++; continue; }
        const id = randomBytes(8).toString("hex");
        await run(
          `INSERT INTO tld_lifecycle_overrides (id, tld, grace, redemption, pending_delete, registry, notes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            id,
            rule.tld,
            rule.grace_period_days,
            rule.redemption_period_days,
            rule.pending_delete_days,
            null,
            `AI 自动抓取导入 (confidence: ${rule.confidence})`,
          ]
        ).catch(() => { skipped++; imported--; });
        imported++;
      }

      invalidateLifecycleOverridesCache();
      return res.json({
        imported,
        skipped,
        message: `已导入 ${imported} 条 AI 抓取数据到生命周期规则库，跳过 ${skipped} 条（已有记录）`,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).end();
}
