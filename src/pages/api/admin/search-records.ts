import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

const PAGE_SIZE = 50;

// High-value domain detection (applied to the latest record per domain)
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

// Same conditions applied to raw table (for stats queries)
const HIGH_VALUE_RAW = `(
  query_type = 'domain' AND reg_status = 'unregistered' AND (
    length(split_part(query, '.', 1)) <= 4
    OR regexp_replace(query, '\\.[^.]+$', '') ~ '^[0-9]+$'
    OR (
      length(split_part(query, '.', 1)) <= 6
      AND split_part(query, '.', -1) IN ('com','net','org','io','ai','app','dev','co','me')
    )
    OR split_part(query, '.', 1) IN (
      'ai','api','bot','gpt','llm','pay','web3','nft','dao','defi',
      'www','domain','whois','dns','cloud','data','code','dev',
      'shop','store','trade','market','crypto','chain','wallet',
      'tech','app','hub','lab','pro','go','me','my','one'
    )
  )
)`;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  // ── DELETE ────────────────────────────────────────────────────────────────
  if (req.method === "DELETE") {
    const { id, query: queryParam } = req.query;

    // Delete all records for a specific domain/query (used by grouped view)
    if (queryParam && typeof queryParam === "string") {
      try {
        const deleted = await run(
          `DELETE FROM search_history WHERE LOWER(query) = LOWER($1)`,
          [queryParam],
        );
        return res.status(200).json({ ok: true, deleted });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }

    // Delete single record by id (legacy)
    if (id && typeof id === "string") {
      try {
        await run(`DELETE FROM search_history WHERE id = $1`, [id]);
        return res.status(200).json({ ok: true });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }

    const body = (req.body ?? {}) as { period?: string; user_id?: string | null };

    if (body.user_id === null) {
      try {
        const deleted = await run(`DELETE FROM search_history WHERE user_id IS NULL`);
        return res.status(200).json({ ok: true, deleted });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }

    if (body.user_id) {
      try {
        const deleted = await run(`DELETE FROM search_history WHERE user_id = $1`, [body.user_id]);
        return res.status(200).json({ ok: true, deleted });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }

    const periodMap: Record<string, string> = {
      yesterday:   "created_at >= NOW() - INTERVAL '2 days' AND created_at < NOW() - INTERVAL '1 day'",
      day_before:  "created_at >= NOW() - INTERVAL '3 days' AND created_at < NOW() - INTERVAL '2 days'",
      week:        "created_at < NOW() - INTERVAL '7 days'",
      month:       "created_at < NOW() - INTERVAL '30 days'",
      all:         "1=1",
      anonymous:   "user_id IS NULL",
    };
    const condition = body.period ? periodMap[body.period] : undefined;
    if (!condition) return res.status(400).json({ error: "无效的时间段或参数" });

    try {
      const deleted = await run(`DELETE FROM search_history WHERE ${condition}`);
      return res.status(200).json({ ok: true, deleted });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, DELETE");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const page   = Math.max(1, parseInt((req.query.page   as string) ?? "1"));
    const filter = (req.query.filter  as string) ?? "all";
    const search = ((req.query.search as string) ?? "").trim().toLowerCase();
    const offset = (page - 1) * PAGE_SIZE;

    // ── Filter clause applied to the `latest` CTE (one row per unique domain) ──
    // The CTE gives: query, query_type, reg_status, remaining_days, user_id
    // aliased as `l`, joined to `users` as `u`.
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

    // Search by domain name
    const searchClause = search ? "AND LOWER(l.query) LIKE $3" : "";
    const searchParam  = search ? [`%${search}%`] : [];

    // ── CTE: one row per unique domain (using most recent record) ─────────────
    // `latest` = most recent record per domain
    // `totals` = search count + unique user count per domain
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
          COUNT(*)              AS search_count,
          COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) AS unique_logged_users
        FROM search_history
        GROUP BY LOWER(query)
      )
    `;

    const baseSelect = `
      FROM latest l
      JOIN totals t ON t.qkey = LOWER(l.query)
      LEFT JOIN users u ON l.user_id = u.id
      WHERE ${filterClause} ${searchClause}
    `;

    const [totalRow, rows] = await Promise.all([
      one<{ count: string }>(
        `${cte} SELECT COUNT(*) AS count ${baseSelect}`,
        searchParam,
      ),
      many(
        `${cte}
         SELECT
           l.query, l.query_type, l.reg_status, l.expiration_date,
           l.remaining_days, l.value_tier, l.created_at AS last_searched_at,
           l.user_id IS NULL AS last_was_anon,
           t.search_count, t.unique_logged_users,
           u.email AS last_user_email, u.name AS last_user_name
         ${baseSelect}
         ORDER BY l.created_at DESC
         LIMIT $1 OFFSET $2`,
        [PAGE_SIZE, offset, ...searchParam],
      ),
    ]);

    // ── Stats + chart data — all queries run in parallel ─────────────────────
    const [
      allCount, todayCount, availableCount, expiringCount,
      highValueCount, registeredCount, totalEventsCount,
      uniqueUsersCount, anonCount, loggedCount,
      dailyStats, topQueries, topByType, topUsers, topTlds,
    ] = await Promise.all([
      one<{ count: string }>("SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history"),
      one<{ count: string }>("SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '1 day'"),
      one<{ count: string }>("SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history WHERE query_type = 'domain' AND reg_status = 'unregistered'"),
      one<{ count: string }>("SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history WHERE query_type = 'domain' AND reg_status = 'registered' AND remaining_days IS NOT NULL AND remaining_days >= 0 AND remaining_days <= 90"),
      one<{ count: string }>(`SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history WHERE ${HIGH_VALUE_RAW}`),
      one<{ count: string }>("SELECT COUNT(DISTINCT LOWER(query)) AS count FROM search_history WHERE query_type = 'domain' AND reg_status = 'registered'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history"),
      one<{ count: string }>("SELECT COUNT(DISTINCT user_id) AS count FROM search_history WHERE user_id IS NOT NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE user_id IS NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE user_id IS NOT NULL"),
      many<{ day: string; count: string; available: string; registered: string; anon: string; logged: string }>(
        `SELECT DATE(created_at) AS day, COUNT(*) AS count,
           COUNT(*) FILTER (WHERE reg_status = 'unregistered') AS available,
           COUNT(*) FILTER (WHERE reg_status = 'registered')   AS registered,
           COUNT(*) FILTER (WHERE user_id IS NULL)             AS anon,
           COUNT(*) FILTER (WHERE user_id IS NOT NULL)         AS logged
         FROM search_history
         WHERE created_at >= NOW() - INTERVAL '30 days'
         GROUP BY day ORDER BY day ASC`,
      ),
      many<{ query: string; query_type: string; count: string }>(
        `SELECT query, query_type, COUNT(*) AS count
         FROM search_history
         WHERE created_at >= NOW() - INTERVAL '30 days'
         GROUP BY query, query_type ORDER BY count DESC LIMIT 10`,
      ),
      many<{ query_type: string; count: string }>(
        `SELECT query_type, COUNT(DISTINCT LOWER(query)) AS count
         FROM search_history GROUP BY query_type ORDER BY count DESC`,
      ),
      many<{ user_email: string; user_name: string | null; count: string }>(
        `SELECT u.email AS user_email, u.name AS user_name, COUNT(*) AS count
         FROM search_history sh
         JOIN users u ON sh.user_id = u.id
         WHERE sh.created_at >= NOW() - INTERVAL '30 days'
         GROUP BY u.email, u.name ORDER BY count DESC LIMIT 10`,
      ),
      many<{ tld: string; count: string }>(
        `SELECT split_part(query, '.', -1) AS tld, COUNT(*) AS count
         FROM search_history
         WHERE query_type = 'domain'
           AND char_length(split_part(query, '.', -1)) >= 2
           AND split_part(query, '.', -1) ~ '^[a-zA-Z]'
         GROUP BY tld ORDER BY count DESC LIMIT 12`,
      ),
    ]);

    const records = rows.map(r => ({
      query:            r.query as string,
      queryType:        r.query_type as string,
      regStatus:        (r.reg_status as string) ?? "unknown",
      expirationDate:   r.expiration_date ?? null,
      remainingDays:    r.remaining_days ?? null,
      valueTier:        (r.value_tier as string) ?? "normal",
      lastSearchedAt:   r.last_searched_at as string,
      searchCount:      parseInt(r.search_count as string),
      uniqueLoggedUsers: parseInt(r.unique_logged_users as string),
      lastWasAnon:      r.last_was_anon as boolean,
      lastUserEmail:    r.last_user_email ?? null,
      lastUserName:     r.last_user_name  ?? null,
    }));

    const total = parseInt(totalRow?.count ?? "0");
    return res.json({
      records,
      pagination: {
        page,
        pageSize: PAGE_SIZE,
        total,
        totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
      },
      stats: {
        all:           parseInt(allCount?.count          ?? "0"),
        today:         parseInt(todayCount?.count        ?? "0"),
        totalEvents:   parseInt(totalEventsCount?.count  ?? "0"),
        available:     parseInt(availableCount?.count    ?? "0"),
        expiring:      parseInt(expiringCount?.count     ?? "0"),
        highValue:     parseInt(highValueCount?.count    ?? "0"),
        registered:    parseInt(registeredCount?.count   ?? "0"),
        anonymous:     parseInt(anonCount?.count         ?? "0"),
        logged:        parseInt(loggedCount?.count       ?? "0"),
        uniqueUsers:   parseInt(uniqueUsersCount?.count  ?? "0"),
      },
      dailyStats: dailyStats.map(r => ({
        day:        r.day,
        count:      parseInt(r.count),
        available:  parseInt(r.available),
        registered: parseInt(r.registered),
        anon:       parseInt(r.anon),
        logged:     parseInt(r.logged),
      })),
      topByType:  topByType.map(r  => ({ type: r.query_type, count: parseInt(r.count) })),
      topQueries: topQueries.map(r => ({ query: r.query, type: r.query_type, count: parseInt(r.count) })),
      topUsers:   topUsers.map(r   => ({ email: r.user_email, name: r.user_name ?? null, count: parseInt(r.count) })),
      topTlds:    topTlds.map(r    => ({ tld: r.tld, count: parseInt(r.count) })),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
}
