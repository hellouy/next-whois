import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export const config = { maxDuration: 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const session = await requireAdmin(req, res);
  if (!session) return;

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  const filter = (req.query.filter as string) ?? "all";
  const search = ((req.query.search as string) ?? "").trim().toLowerCase();

  const HIGH_VALUE_LATEST = `(
    l.query_type = 'domain' AND l.reg_status = 'unregistered' AND (
      length(split_part(l.query, '.', 1)) <= 4
      OR regexp_replace(l.query, '\\.[^.]+$', '') ~ '^[0-9]+$'
      OR (
        length(split_part(l.query, '.', 1)) <= 6
        AND split_part(l.query, '.', -1) IN ('com','net','org','io','ai','app','dev','co','me')
      )
      OR split_part(l.query, '.', 1) IN (
        'ai','api','bot','gpt','llm','pay','web3','nft','dao','defi',
        'www','domain','whois','dns','cloud','data','code','dev',
        'shop','store','trade','market','crypto','chain','wallet',
        'tech','app','hub','lab','pro','go','me','my','one'
      )
    )
  )`;

  let filterClause = "1=1";
  if (filter === "available") {
    filterClause = "l.query_type = 'domain' AND l.reg_status = 'unregistered'";
  } else if (filter === "expiring") {
    filterClause = "l.query_type = 'domain' AND l.reg_status = 'registered' AND l.remaining_days IS NOT NULL AND l.remaining_days >= 0 AND l.remaining_days <= 90";
  } else if (filter === "high_value") {
    filterClause = HIGH_VALUE_LATEST;
  } else if (filter === "anonymous") {
    filterClause = "l.user_id IS NULL";
  } else if (filter === "logged") {
    filterClause = "l.user_id IS NOT NULL";
  }

  const searchClause = search ? "AND LOWER(l.query) LIKE $1" : "";
  const searchParam = search ? [`%${search}%`] : [];

  const cte = `
    WITH latest AS (
      SELECT DISTINCT ON (LOWER(query))
        query, query_type, reg_status, expiration_date, remaining_days, value_tier, created_at, user_id
      FROM search_history
      ORDER BY LOWER(query), created_at DESC
    ),
    totals AS (
      SELECT
        LOWER(query) AS qkey,
        COUNT(*) AS search_count,
        COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) AS unique_logged_users
      FROM search_history
      GROUP BY LOWER(query)
    )
  `;

  const client = await db.connect();
  try {
    const filename = `search-records_${filter}_${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Transfer-Encoding", "chunked");
    res.setHeader("Cache-Control", "no-store");

    const BOM = "\uFEFF";
    const headers = ["域名", "类型", "注册状态", "到期日", "剩余天数", "价值级别", "最后搜索时间", "搜索次数", "独立登录用户", "最近用户邮箱"].join(",");
    res.write(BOM + headers + "\r\n");

    const PAGE = 500;
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const params: any[] = [...searchParam, PAGE, offset];
      const searchIdx = search ? 1 : 0;
      const pageIdx = searchIdx + 1;
      const offsetIdx = pageIdx + 1;

      const rowsResult = await client.query(
        `${cte}
         SELECT
           l.query, l.query_type, l.reg_status, l.expiration_date,
           l.remaining_days, l.value_tier, l.created_at AS last_searched_at,
           t.search_count, t.unique_logged_users,
           u.email AS last_user_email
         FROM latest l
         JOIN totals t ON t.qkey = LOWER(l.query)
         LEFT JOIN users u ON l.user_id = u.id
         WHERE ${filterClause} ${searchClause}
         ORDER BY l.created_at DESC
         LIMIT $${pageIdx} OFFSET $${offsetIdx}`,
        params
      );

      if (rowsResult.rows.length === 0) {
        hasMore = false;
        break;
      }

      const chunk = rowsResult.rows.map((r: any) => {
        const fields = [
          r.query ?? "",
          r.query_type ?? "",
          r.reg_status ?? "",
          r.expiration_date ? new Date(r.expiration_date).toLocaleDateString("zh-CN") : "",
          r.remaining_days ?? "",
          r.value_tier ?? "",
          r.last_searched_at ? new Date(r.last_searched_at).toLocaleString("zh-CN") : "",
          r.search_count ?? 0,
          r.unique_logged_users ?? 0,
          r.last_user_email ?? "",
        ];
        return fields.map((v: any) => `"${String(v).replace(/"/g, '""')}"`).join(",");
      }).join("\r\n");

      res.write(chunk + "\r\n");
      offset += rowsResult.rows.length;
      if (rowsResult.rows.length < PAGE) hasMore = false;
    }

    res.end();
  } catch (err: any) {
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    } else {
      res.end();
    }
  } finally {
    client.release();
  }
}
