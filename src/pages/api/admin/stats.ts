import type { NextApiRequest, NextApiResponse } from "next";
import { many, one } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

// ── In-process cache (3 minutes) ──────────────────────────────────────────────
// Stats are expensive: 30+ queries. Cache the full result for 3 min to make
// repeated visits to the admin overview instant.
let _cache: { data: any; ts: number } | null = null;
const CACHE_TTL = 3 * 60_000;

function zeroFillDays<T extends Record<string, any>>(
  rows: T[],
  valueKey: string,
  days = 7,
): T[] {
  const map = new Map<string, T>();
  for (const row of rows) map.set(row.day, row);
  const result: T[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date();
    d.setUTCDate(d.getUTCDate() - i);
    const day = d.toISOString().slice(0, 10);
    result.push(map.get(day) ?? ({ day, [valueKey]: 0 } as unknown as T));
  }
  return result;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const session = await requireAdmin(req, res);
  if (!session) return;

  // Bust cache when ?refresh=1
  if (req.query.refresh === "1") _cache = null;

  // Return cached result if still fresh
  if (_cache && Date.now() - _cache.ts < CACHE_TTL) {
    res.setHeader("X-Cache", "HIT");
    res.setHeader("Cache-Control", "private, max-age=60, stale-while-revalidate=120");
    return res.json(_cache.data);
  }

  try {
    // ── Aggregate all search_history stats in ONE query ────────────────────
    const [searchAgg, userAgg, paymentAgg, misc] = await Promise.all([
      one<{
        total: string; anon: string; logged: string;
        today: string; today_anon: string; today_logged: string;
        domain_cnt: string; ip_cnt: string; asn_cnt: string; cidr_cnt: string;
        available_cnt: string; registered_cnt: string; high_value_cnt: string;
        failed_all: string; failed_today: string; weekly: string;
      }>(`
        SELECT
          COUNT(*)::text                                                                                           AS total,
          COUNT(*) FILTER (WHERE user_id IS NULL)::text                                                           AS anon,
          COUNT(*) FILTER (WHERE user_id IS NOT NULL)::text                                                       AS logged,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day')::text                                    AS today,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day' AND user_id IS NULL)::text                AS today_anon,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day' AND user_id IS NOT NULL)::text            AS today_logged,
          COUNT(*) FILTER (WHERE query_type = 'domain')::text                                                     AS domain_cnt,
          COUNT(*) FILTER (WHERE query_type IN ('ipv4','ipv6'))::text                                             AS ip_cnt,
          COUNT(*) FILTER (WHERE query_type = 'asn')::text                                                        AS asn_cnt,
          COUNT(*) FILTER (WHERE query_type = 'cidr')::text                                                       AS cidr_cnt,
          COUNT(*) FILTER (WHERE reg_status = 'unregistered')::text                                               AS available_cnt,
          COUNT(*) FILTER (WHERE reg_status = 'registered')::text                                                 AS registered_cnt,
          COUNT(*) FILTER (WHERE value_tier = 'high')::text                                                       AS high_value_cnt,
          COUNT(*) FILTER (WHERE query_type = 'domain' AND reg_status IS NULL
                            AND created_at < NOW() - INTERVAL '10 minutes')::text                                  AS failed_all,
          COUNT(*) FILTER (WHERE query_type = 'domain' AND reg_status IS NULL
                            AND created_at >= NOW() - INTERVAL '1 day'
                            AND created_at < NOW() - INTERVAL '10 minutes')::text                                  AS failed_today,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')::text                                   AS weekly
        FROM search_history
      `),

      // ── All user stats in ONE query ──────────────────────────────────────
      one<{ total: string; disabled_cnt: string; today_cnt: string; subscribed_cnt: string }>(`
        SELECT
          COUNT(*)::text                                                                                           AS total,
          COUNT(*) FILTER (WHERE disabled = true)::text                                                           AS disabled_cnt,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day')::text                                    AS today_cnt,
          COUNT(*) FILTER (WHERE subscription_access = true
                            AND (subscription_expires_at IS NULL
                              OR subscription_expires_at > NOW()))::text                                           AS subscribed_cnt
        FROM users
      `),

      // ── All payment stats in ONE query ───────────────────────────────────
      one<{ total_orders: string; paid_orders: string; paid_revenue: string | null }>(`
        SELECT
          COUNT(*)::text                                                    AS total_orders,
          COUNT(*) FILTER (WHERE status = 'paid')::text                    AS paid_orders,
          SUM(amount) FILTER (WHERE status = 'paid')::text                 AS paid_revenue
        FROM payment_orders
      `).catch(() => ({ total_orders: "0", paid_orders: "0", paid_revenue: null })),

      // ── Quick scalar counts for stamps, reminders, feedback, tld failures ─
      one<{ stamps: string; verified_stamps: string; reminders: string; feedback: string; tld_failures: string }>(`
        SELECT
          (SELECT COUNT(*) FROM stamps)::text                                              AS stamps,
          (SELECT COUNT(*) FROM stamps WHERE verified = true)::text                       AS verified_stamps,
          (SELECT COUNT(*) FROM reminders WHERE active = true)::text                      AS reminders,
          (SELECT COUNT(*) FROM feedback)::text                                           AS feedback,
          (SELECT COUNT(*) FROM tld_fallback_stats WHERE fail_count > 3)::text            AS tld_failures
      `).catch(() => ({ stamps: "0", verified_stamps: "0", reminders: "0", feedback: "0", tld_failures: "0" })),
    ]);

    // ── List queries (small result sets) ──────────────────────────────────
    const [recentUsers, recentSearches, topFailingTlds, dailyTrend, dailySignups, dailyRevenue] = await Promise.all([
      many<{ id: string; email: string; name: string | null; created_at: string; disabled: boolean }>(
        "SELECT id, email, name, created_at, disabled FROM users ORDER BY created_at DESC LIMIT 5",
      ),
      many<{ id: string; query: string; query_type: string; created_at: string; user_id: string | null; reg_status: string | null }>(
        "SELECT id, query, query_type, created_at, user_id, reg_status FROM search_history ORDER BY created_at DESC LIMIT 10",
      ),
      many<{ tld: string; fail_count: number; fail_reason: string | null; last_fail_at: string | null; has_custom_server: boolean }>(
        `SELECT f.tld, f.fail_count, f.fail_reason, f.last_fail_at::text,
                (c.tld IS NOT NULL) AS has_custom_server
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         WHERE f.fail_count > 3
         ORDER BY f.fail_count DESC LIMIT 8`,
      ).catch(() => [] as any[]),
      many<{ day: string; count: string }>(
        `SELECT DATE(created_at)::text AS day, COUNT(*) AS count
         FROM search_history WHERE created_at >= NOW() - INTERVAL '7 days'
         GROUP BY DATE(created_at) ORDER BY day`,
      ).catch(() => [] as any[]),
      many<{ day: string; count: string }>(
        `SELECT DATE(created_at)::text AS day, COUNT(*) AS count
         FROM users WHERE created_at >= NOW() - INTERVAL '7 days'
         GROUP BY DATE(created_at) ORDER BY day`,
      ).catch(() => [] as any[]),
      many<{ day: string; revenue: string }>(
        `SELECT DATE(created_at)::text AS day, SUM(amount)::text AS revenue
         FROM payment_orders
         WHERE status = 'paid' AND created_at >= NOW() - INTERVAL '7 days'
         GROUP BY DATE(created_at) ORDER BY day`,
      ).catch(() => [] as any[]),
    ]);

    const domainInt  = parseInt(searchAgg?.domain_cnt  ?? "0");
    const failedInt  = parseInt(searchAgg?.failed_all  ?? "0");
    const failureRate = domainInt > 0 ? Math.round((failedInt / domainInt) * 1000) / 10 : 0;

    const data = {
      users:               parseInt(userAgg?.total         ?? "0"),
      disabledUsers:       parseInt(userAgg?.disabled_cnt  ?? "0"),
      stamps:              parseInt(misc?.stamps            ?? "0"),
      verifiedStamps:      parseInt(misc?.verified_stamps  ?? "0"),
      activeReminders:     parseInt(misc?.reminders        ?? "0"),
      searches:            parseInt(searchAgg?.total        ?? "0"),
      feedback:            parseInt(misc?.feedback          ?? "0"),
      anonSearches:        parseInt(searchAgg?.anon         ?? "0"),
      loggedSearches:      parseInt(searchAgg?.logged       ?? "0"),
      todaySearches:       parseInt(searchAgg?.today        ?? "0"),
      todayAnonSearches:   parseInt(searchAgg?.today_anon  ?? "0"),
      todayLoggedSearches: parseInt(searchAgg?.today_logged ?? "0"),
      todayUsers:          parseInt(userAgg?.today_cnt      ?? "0"),
      subscribedUsers:     parseInt(userAgg?.subscribed_cnt ?? "0"),
      totalOrders:         parseInt(paymentAgg?.total_orders ?? "0"),
      paidOrders:          parseInt(paymentAgg?.paid_orders  ?? "0"),
      paidRevenue:         parseFloat(paymentAgg?.paid_revenue ?? "0") || 0,
      tldFailures:         parseInt(misc?.tld_failures      ?? "0"),
      weeklySearches:      parseInt(searchAgg?.weekly        ?? "0"),
      failedDomainSearches: failedInt,
      todayFailedSearches: parseInt(searchAgg?.failed_today ?? "0"),
      failureRate,
      queryTypeBreakdown: {
        domain: domainInt,
        ip:     parseInt(searchAgg?.ip_cnt   ?? "0"),
        asn:    parseInt(searchAgg?.asn_cnt  ?? "0"),
        cidr:   parseInt(searchAgg?.cidr_cnt ?? "0"),
      },
      regStatusBreakdown: {
        available:  parseInt(searchAgg?.available_cnt  ?? "0"),
        registered: parseInt(searchAgg?.registered_cnt ?? "0"),
        highValue:  parseInt(searchAgg?.high_value_cnt ?? "0"),
      },
      topFailingTlds,
      dailyTrend:    zeroFillDays(dailyTrend.map(d => ({ day: d.day, count: parseInt(d.count) })), "count"),
      dailySignups:  zeroFillDays(dailySignups.map(d => ({ day: d.day, count: parseInt(d.count) })), "count"),
      dailyRevenue:  zeroFillDays(dailyRevenue.map(d => ({ day: d.day, revenue: parseFloat(d.revenue ?? "0") || 0 })), "revenue"),
      recentUsers,
      recentSearches,
    };

    _cache = { data, ts: Date.now() };
    res.setHeader("X-Cache", "MISS");
    res.setHeader("Cache-Control", "private, max-age=60, stale-while-revalidate=120");
    return res.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: msg });
  }
}
