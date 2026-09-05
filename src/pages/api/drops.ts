import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, isDbReady } from "@/lib/db-query";
import { computeLifecycle } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { getSetting } from "@/lib/server/site-settings-server";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/drops");

const PUBLIC_GROUP_LIMIT = 500;

type DomainRow = { domain: string; tld: string };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const days = Math.min(Math.max(parseInt(String(req.query.days ?? "30"), 10) || 30, 1), 90);
  const session = await getServerSession(req, res, authOptions);
  const email = session?.user?.email ?? null;

  const publicEnabled = (await getSetting("drop_calendar_public", "1").catch(() => "1")) !== "0";

  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);
  const endStr = new Date(today.getTime() + days * 86_400_000).toISOString().slice(0, 10);

  // ── Public part: crawled expiring-drop leads ───────────────────────────────
  let publicLocked = false;
  let drops: { date: string; domains: DomainRow[] }[] = [];
  if (publicEnabled || email) {
    try {
      const rows = await many<{
        domain: string; tld: string; available_date: string | null;
      }>(
        `SELECT domain, tld, available_date
         FROM expired_domain_leads
         WHERE status = 'available'
           AND available_date IS NOT NULL
           AND available_date >= $1
           AND available_date <= $2
         ORDER BY available_date ASC, domain ASC
         LIMIT $3`,
        [todayStr, endStr, PUBLIC_GROUP_LIMIT],
      );
      const byDate = new Map<string, DomainRow[]>();
      for (const r of rows) {
        const key = r.available_date!;
        if (!byDate.has(key)) byDate.set(key, []);
        byDate.get(key)!.push({ domain: r.domain, tld: r.tld });
      }
      drops = [...byDate.entries()].map(([date, domains]) => ({ date, domains }));
    } catch (err) {
      logger.error("[drops] public query error:", err instanceof Error ? err.message : String(err));
      drops = [];
    }
  } else {
    publicLocked = true;
  }

  // ── Private part: the user's own subscriptions with an upcoming drop ──────
  let userDrops: { date: string; domains: { domain: string; reminder_id: string }[] }[] = [];
  if (email) {
    try {
      const rows = await many<{
        id: string; domain: string; whois_expiry_date: string | null; expiration_date: string | null;
      }>(
        `SELECT id, domain, whois_expiry_date, expiration_date
         FROM reminders WHERE email = $1 AND active = true`,
        [email],
      );
      const overrides = await loadLifecycleOverrides().catch(() => ({}));
      const byDate = new Map<string, { domain: string; reminder_id: string }[]>();
      for (const r of rows) {
        const effectiveExpiry = r.whois_expiry_date ?? r.expiration_date;
        if (!effectiveExpiry) continue;
        const lc = computeLifecycle(r.domain, effectiveExpiry, undefined, overrides);
        if (!lc || lc.phase === "dropped") continue;
        const dropStr = lc.dropDate.toISOString().slice(0, 10);
        if (dropStr < todayStr || dropStr > endStr) continue;
        if (!byDate.has(dropStr)) byDate.set(dropStr, []);
        byDate.get(dropStr)!.push({ domain: r.domain, reminder_id: r.id });
      }
      userDrops = [...byDate.entries()].map(([date, domains]) => ({ date, domains }));
    } catch (err) {
      logger.error("[drops] user query error:", err instanceof Error ? err.message : String(err));
      userDrops = [];
    }
  }

  res.setHeader("Cache-Control", "public, max-age=300, stale-while-revalidate=600");
  return res.json({
    today: todayStr,
    days,
    public_locked: publicLocked,
    drops,
    user_drops: userDrops,
  });
}
