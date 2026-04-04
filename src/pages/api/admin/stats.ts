import type { NextApiRequest, NextApiResponse } from "next";
import { many, one } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const session = await requireAdmin(req, res);
  if (!session) return;

  try {
    const [
      users, disabledUsers, stamps, verifiedStamps, reminders, history, feedback,
      anonSearches, loggedSearches, todaySearches, todayAnonSearches, todayLoggedSearches, todayUsers, subscribedUsers,
      totalOrders, paidOrders, paidRevenue,
      tldFailures, weeklySearches, domainSearches, ipSearches, asnSearches, cidrSearches,
      availableSearches, registeredSearches, highValueSearches,
      failedDomainSearches, todayFailedSearches,
    ] = await Promise.all([
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE disabled = true"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM stamps"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM stamps WHERE verified = true"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = true"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM feedback").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE user_id IS NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE user_id IS NOT NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '1 day'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '1 day' AND user_id IS NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '1 day' AND user_id IS NOT NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE created_at >= NOW() - INTERVAL '1 day'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE subscription_access = true AND (subscription_expires_at IS NULL OR subscription_expires_at > NOW())").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM payment_orders").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM payment_orders WHERE status = 'paid'").catch(() => ({ count: "0" })),
      one<{ sum: string | null }>("SELECT SUM(amount)::text AS sum FROM payment_orders WHERE status = 'paid'").catch(() => ({ sum: null })),
      // TLD failures stats
      one<{ count: string }>("SELECT COUNT(*) AS count FROM tld_fallback_stats WHERE fail_count > 3").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '7 days'"),
      // query type breakdown
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE query_type = 'domain'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE query_type IN ('ipv4','ipv6')"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE query_type = 'asn'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE query_type = 'cidr'"),
      // reg status breakdown
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE reg_status = 'unregistered'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE reg_status = 'registered'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE value_tier = 'high'").catch(() => ({ count: "0" })),
      // Failed domain queries: domain type with no reg_status resolved (older than 10 min, so lookup has settled)
      one<{ count: string }>(
        "SELECT COUNT(*) AS count FROM search_history WHERE query_type = 'domain' AND reg_status IS NULL AND created_at < NOW() - INTERVAL '10 minutes'"
      ).catch(() => ({ count: "0" })),
      // Today's failed domain queries
      one<{ count: string }>(
        "SELECT COUNT(*) AS count FROM search_history WHERE query_type = 'domain' AND reg_status IS NULL AND created_at >= NOW() - INTERVAL '1 day' AND created_at < NOW() - INTERVAL '10 minutes'"
      ).catch(() => ({ count: "0" })),
    ]);

    const [recentUsers, recentSearches, topFailingTlds, dailyTrend] = await Promise.all([
      many<{ id: string; email: string; name: string | null; created_at: string; disabled: boolean }>(
        "SELECT id, email, name, created_at, disabled FROM users ORDER BY created_at DESC LIMIT 5"
      ),
      many<{ id: string; query: string; query_type: string; created_at: string; user_id: string | null; reg_status: string | null }>(
        "SELECT id, query, query_type, created_at, user_id, reg_status FROM search_history ORDER BY created_at DESC LIMIT 10"
      ),
      many<{ tld: string; fail_count: number; fail_reason: string | null; last_fail_at: string | null; has_custom_server: boolean }>(
        `SELECT f.tld, f.fail_count, f.fail_reason, f.last_fail_at::text,
                (c.tld IS NOT NULL) AS has_custom_server
         FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         WHERE f.fail_count > 3
         ORDER BY f.fail_count DESC LIMIT 8`
      ).catch(() => [] as any[]),
      many<{ day: string; count: string }>(
        `SELECT DATE(created_at)::text AS day, COUNT(*) AS count
         FROM search_history
         WHERE created_at >= NOW() - INTERVAL '7 days'
         GROUP BY DATE(created_at) ORDER BY day`
      ).catch(() => [] as any[]),
    ]);

    const totalSearchesInt = parseInt(history?.count ?? "0");
    const failedInt = parseInt(failedDomainSearches?.count ?? "0");
    const domainInt = parseInt(domainSearches?.count ?? "0");
    const failureRate = domainInt > 0 ? Math.round((failedInt / domainInt) * 1000) / 10 : 0;

    return res.json({
      users: parseInt(users?.count ?? "0"),
      disabledUsers: parseInt(disabledUsers?.count ?? "0"),
      stamps: parseInt(stamps?.count ?? "0"),
      verifiedStamps: parseInt(verifiedStamps?.count ?? "0"),
      activeReminders: parseInt(reminders?.count ?? "0"),
      searches: totalSearchesInt,
      feedback: parseInt(feedback?.count ?? "0"),
      anonSearches: parseInt(anonSearches?.count ?? "0"),
      loggedSearches: parseInt(loggedSearches?.count ?? "0"),
      todaySearches: parseInt(todaySearches?.count ?? "0"),
      todayAnonSearches: parseInt(todayAnonSearches?.count ?? "0"),
      todayLoggedSearches: parseInt(todayLoggedSearches?.count ?? "0"),
      todayUsers: parseInt(todayUsers?.count ?? "0"),
      subscribedUsers: parseInt(subscribedUsers?.count ?? "0"),
      totalOrders: parseInt(totalOrders?.count ?? "0"),
      paidOrders: parseInt(paidOrders?.count ?? "0"),
      paidRevenue: parseFloat(paidRevenue?.sum ?? "0") || 0,
      tldFailures: parseInt(tldFailures?.count ?? "0"),
      weeklySearches: parseInt(weeklySearches?.count ?? "0"),
      failedDomainSearches: failedInt,
      todayFailedSearches: parseInt(todayFailedSearches?.count ?? "0"),
      failureRate,
      queryTypeBreakdown: {
        domain: domainInt,
        ip: parseInt(ipSearches?.count ?? "0"),
        asn: parseInt(asnSearches?.count ?? "0"),
        cidr: parseInt(cidrSearches?.count ?? "0"),
      },
      regStatusBreakdown: {
        available: parseInt(availableSearches?.count ?? "0"),
        registered: parseInt(registeredSearches?.count ?? "0"),
        highValue: parseInt(highValueSearches?.count ?? "0"),
      },
      topFailingTlds,
      dailyTrend: dailyTrend.map(d => ({ day: d.day, count: parseInt(d.count) })),
      recentUsers,
      recentSearches,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return res.status(500).json({ error: msg });
  }
}
