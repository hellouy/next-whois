import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export const config = { maxDuration: 120 };

const TABLES: { name: string; label: string; ephemeral?: boolean }[] = [
  { name: "users",                   label: "用户" },
  { name: "search_history",          label: "查询记录" },
  { name: "stamps",                  label: "品牌认领" },
  { name: "reminders",               label: "到期提醒" },
  { name: "reminder_logs",           label: "提醒日志" },
  { name: "feedback",                label: "问题反馈" },
  { name: "sponsors",                label: "赞助者" },
  { name: "invite_codes",            label: "邀请码" },
  { name: "activation_codes",        label: "激活码" },
  { name: "access_keys",             label: "访问密钥" },
  { name: "friendly_links",          label: "友情链接" },
  { name: "payment_plans",           label: "套餐" },
  { name: "payment_orders",          label: "支付订单" },
  { name: "balance_transactions",    label: "余额流水" },
  { name: "site_settings",           label: "站点设置" },
  { name: "changelog_entries",       label: "更新日志" },
  { name: "tld_rules",               label: "TLD 规则" },
  { name: "tld_fallback_stats",      label: "TLD 兜底统计" },
  { name: "tld_lifecycle_overrides", label: "TLD 生命周期覆盖" },
  { name: "tld_lifecycle_feedback",  label: "TLD 规则纠错" },
  { name: "custom_whois_servers",    label: "自定义 WHOIS 服务器" },
  { name: "hot_prefixes",            label: "热门前缀" },
  { name: "tool_clicks",             label: "工具点击统计" },
  { name: "user_tool_clicks",        label: "用户工具点击" },
  { name: "tld_registry_info",       label: "注册局数据库" },
  { name: "tld_server_failures",     label: "TLD 服务器修复队列" },
  { name: "whois_cache",             label: "WHOIS 缓存", ephemeral: true },
  { name: "password_reset_tokens",   label: "密码重置令牌", ephemeral: true },
  { name: "rate_limit_records",      label: "频率限制记录", ephemeral: true },
];

const PAGE_SIZE = 1_000;

export async function getTableStats(db: Awaited<ReturnType<typeof getDbReady>>) {
  if (!db) return [];
  return Promise.all(
    TABLES.map(async (t) => {
      try {
        const r = await db.query(`SELECT COUNT(*)::int AS n FROM ${t.name}`);
        return { name: t.name, label: t.label, count: r.rows[0]?.n ?? 0, ephemeral: t.ephemeral };
      } catch {
        return { name: t.name, label: t.label, count: -1, ephemeral: t.ephemeral };
      }
    })
  );
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "GET") return res.status(405).end();

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "数据库不可用" });

  const isDownload = req.query.download === "1";
  const skipEphemeral = req.query.skip_ephemeral !== "0";

  if (!isDownload) {
    const stats = await getTableStats(db);
    return res.json({ tables: stats });
  }

  const exportTables = skipEphemeral ? TABLES.filter(t => !t.ephemeral) : TABLES;
  const filename = `db-export-${new Date().toISOString().slice(0, 10)}.json`;

  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Transfer-Encoding", "chunked");

  const exportedAt = new Date().toISOString();
  const exportedBy = (session.user as any)?.email ?? "admin";

  // Collect table metadata first (just counts — no row data in memory)
  const meta: Record<string, { count: number; error?: string }> = {};
  for (const t of exportTables) {
    try {
      const r = await db.query(`SELECT COUNT(*)::int AS n FROM ${t.name}`);
      meta[t.name] = { count: r.rows[0]?.n ?? 0 };
    } catch (err) {
      meta[t.name] = { count: 0, error: err instanceof Error ? err.message : String(err) };
    }
  }

  // Stream the JSON body in chunks — never accumulate all rows in memory.
  res.write(`{"exported_at":${JSON.stringify(exportedAt)},"schema_version":"1.0","exported_by":${JSON.stringify(exportedBy)},"meta":${JSON.stringify(meta)},"tables":{`);

  let firstTable = true;
  for (const t of exportTables) {
    if (!firstTable) res.write(",");
    firstTable = false;

    res.write(`${JSON.stringify(t.name)}:[`);

    // Skip tables that had errors during count
    if (meta[t.name]?.error) {
      res.write("]");
      continue;
    }

    let offset = 0;
    let firstRow = true;
    let done = false;
    let readError: string | undefined;

    while (!done) {
      try {
        const r = await db.query(
          `SELECT * FROM ${t.name} ORDER BY 1 LIMIT $1 OFFSET $2`,
          [PAGE_SIZE, offset],
        );

        for (const row of r.rows) {
          if (!firstRow) res.write(",");
          firstRow = false;
          res.write(JSON.stringify(row));
        }

        if (r.rows.length < PAGE_SIZE) {
          done = true;
        } else {
          offset += PAGE_SIZE;
        }
      } catch (e: any) {
        readError = (e as Error).message;
        done = true;
      }
    }

    // Record any mid-pagination error so the admin can see partial exports.
    if (readError && !meta[t.name]?.error) {
      meta[t.name] = { ...meta[t.name], error: `read error at offset ${offset}: ${readError}` };
    }

    res.write("]");
  }

  res.write("}}");
  res.end();
}
