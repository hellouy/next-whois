import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, isDbReady } from "@/lib/db-query";
import { computeLifecycle } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { buildIcs } from "@/lib/ics";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/subscriptions/ics");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  try {
    const rows = await many<{
      id: string; domain: string; expiration_date: string | null;
      whois_expiry_date: string | null;
    }>(
      `SELECT id, domain, expiration_date, whois_expiry_date
       FROM reminders WHERE email = $1 AND active = true`,
      [session.user.email],
    );

    const overrides = await loadLifecycleOverrides();
    const baseUrl = `${req.headers["x-forwarded-proto"] || "https"}://${req.headers.host || "localhost"}`;

    const events = rows.map((r) => {
      const effectiveExpiry = r.whois_expiry_date ?? r.expiration_date;
      const eventsForDomain: { uid: string; summary: string; start: string; end?: string; description?: string; url?: string }[] = [];
      if (effectiveExpiry) {
        const lc = computeLifecycle(r.domain, effectiveExpiry, undefined, overrides);
        if (lc) {
          eventsForDomain.push({
            uid: `${r.id}@expiry`,
            summary: `${r.domain} expires`,
            start: effectiveExpiry,
            description: `Domain ${r.domain} is expected to expire.`,
            url: `${baseUrl}/${r.domain}`,
          });
          if (lc.graceEnd) eventsForDomain.push({
            uid: `${r.id}@grace`,
            summary: `${r.domain} grace period ends`,
            start: lc.graceEnd.toISOString().slice(0, 10),
            url: `${baseUrl}/${r.domain}`,
          });
          if (lc.redemptionEnd) eventsForDomain.push({
            uid: `${r.id}@redemption`,
            summary: `${r.domain} redemption period ends`,
            start: lc.redemptionEnd.toISOString().slice(0, 10),
            url: `${baseUrl}/${r.domain}`,
          });
          if (lc.dropDate) eventsForDomain.push({
            uid: `${r.id}@drop`,
            summary: `${r.domain} estimated drop date`,
            start: lc.dropDate.toISOString().slice(0, 10),
            url: `${baseUrl}/${r.domain}`,
          });
        }
      }
      return eventsForDomain;
    }).flat();

    const ics = buildIcs(events, { calendarName: "Domain Expiry Reminders" });
    res.setHeader("Content-Type", "text/calendar; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="domain-reminders.ics"`);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(ics);
  } catch (err) {
    logger.error("[subscriptions/ics] error:", err instanceof Error ? err.message : String(err));
    return res.status(500).json({ error: "Failed to export calendar" });
  }
}
