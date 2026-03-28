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
      anonSearches, todaySearches, todayUsers, subscribedUsers,
      totalOrders, paidOrders, paidRevenue,
    ] = await Promise.all([
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE disabled = true"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM stamps"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM stamps WHERE verified = true"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = true"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM feedback").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE user_id IS NULL"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '1 day'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE created_at >= NOW() - INTERVAL '1 day'"),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE subscription_access = true AND (subscription_expires_at IS NULL OR subscription_expires_at > NOW())").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM payment_orders").catch(() => ({ count: "0" })),
      one<{ count: string }>("SELECT COUNT(*) AS count FROM payment_orders WHERE status = 'paid'").catch(() => ({ count: "0" })),
      one<{ sum: string | null }>("SELECT SUM(amount)::text AS sum FROM payment_orders WHERE status = 'paid'").catch(() => ({ sum: null })),
    ]);

    const [recentUsers, recentSearches] = await Promise.all([
      many<{ id: string; email: string; name: string | null; created_at: string; disabled: boolean }>(
        "SELECT id, email, name, created_at, disabled FROM users ORDER BY created_at DESC LIMIT 5"
      ),
      many<{ id: string; query: string; query_type: string; created_at: string; user_id: string | null }>(
        "SELECT id, query, query_type, created_at, user_id FROM search_history ORDER BY created_at DESC LIMIT 10"
      ),
    ]);

    return res.json({
      users: parseInt(users?.count ?? "0"),
      disabledUsers: parseInt(disabledUsers?.count ?? "0"),
      stamps: parseInt(stamps?.count ?? "0"),
      verifiedStamps: parseInt(verifiedStamps?.count ?? "0"),
      activeReminders: parseInt(reminders?.count ?? "0"),
      searches: parseInt(history?.count ?? "0"),
      feedback: parseInt(feedback?.count ?? "0"),
      anonSearches: parseInt(anonSearches?.count ?? "0"),
      todaySearches: parseInt(todaySearches?.count ?? "0"),
      todayUsers: parseInt(todayUsers?.count ?? "0"),
      subscribedUsers: parseInt(subscribedUsers?.count ?? "0"),
      totalOrders: parseInt(totalOrders?.count ?? "0"),
      paidOrders: parseInt(paidOrders?.count ?? "0"),
      paidRevenue: parseFloat(paidRevenue?.sum ?? "0") || 0,
      recentUsers,
      recentSearches,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
}
