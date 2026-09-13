import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, isDbReady } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/snipe-targets");

export type UserSnipeTargetDto = {
  id: string;
  domain: string;
  tld: string;
  status: string;
  serviceCents: number | null;
  frozenCents: number;
  failReason: string | null;
  dropEta: string | null;
  huntStart: string | null;
  huntEnd: string | null;
  registeredAt: string | null;
  createdAt: string;
  hasSubscription: boolean;
};

const ACTIVE_STATUSES = ["armed", "blocked_balance", "sniping"];
const ENDED_STATUSES = ["succeeded", "failed", "cancelled"];

export function normalizeSnipeFilter(status: string | undefined): string | null {
  if (!status || status === "all") return null;
  if (status === "ended") return "ended";
  return ACTIVE_STATUSES.includes(status) ? status : null;
}

/**
 * GET /api/user/snipe-targets?status=all|armed|blocked_balance|sniping|ended&q=<domain>
 *
 * Returns the signed-in user's preorder targets. Pricing/status come straight
 * from snipe_targets rows owned by this user (user_email = session). The
 * `hasSubscription` flag is a left join hint against `reminders` and is purely
 * informational — the snipe list is intentionally decoupled from the reminder
 * list endpoint so a subscription missing its row never hides a target.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  if (req.method === "GET") {
    const filter = normalizeSnipeFilter(req.query.status as string | undefined);
    const q = String(req.query.q ?? "").trim().toLowerCase();

    const conditions: string[] = ["st.user_email = $1"];
    const params: unknown[] = [session.user.email];

    if (filter === "ended") {
      conditions.push(`st.status = ANY($${params.length + 1}::varchar[])`);
      params.push(ENDED_STATUSES);
    } else if (filter) {
      conditions.push(`st.status = $${params.length + 1}`);
      params.push(filter);
    }

    if (q) {
      conditions.push(`st.domain ILIKE $${params.length + 1}`);
      params.push(`%${q}%`);
    }

    try {
      const rows = await many<{
        id: string; domain: string; tld: string; status: string;
        service_price_cents: number | null; frozen_cents: number; fail_reason: string | null;
        drop_eta: string | null; hunt_start: string | null; hunt_end: string | null;
        registered_at: string | null; created_at: string; has_sub: boolean | null;
      }>(
        `SELECT st.id, st.domain, st.tld, st.status,
                st.service_price_cents, st.frozen_cents, st.fail_reason,
                st.drop_eta, st.hunt_start, st.hunt_end, st.registered_at,
                st.created_at,
                (EXISTS (
                   SELECT 1 FROM reminders r
                   WHERE r.email = $1 AND r.domain = st.domain
                 )) AS has_sub
         FROM snipe_targets st
         WHERE ${conditions.join(" AND ")}
         ORDER BY
           CASE WHEN st.status IN ('armed','blocked_balance','sniping')
                THEN 0 ELSE 1 END,
           st.created_at DESC`,
        params,
      );

      const targets: UserSnipeTargetDto[] = rows.map((r) => ({
        id: r.id,
        domain: r.domain,
        tld: r.tld,
        status: r.status,
        serviceCents: r.service_price_cents,
        frozenCents: r.frozen_cents,
        failReason: r.fail_reason,
        dropEta: r.drop_eta,
        huntStart: r.hunt_start,
        huntEnd: r.hunt_end,
        registeredAt: r.registered_at,
        createdAt: r.created_at,
        hasSubscription: !!r.has_sub,
      }));

      return res.status(200).json({ targets });
    } catch (err) {
      logger.error("[snipe-targets] GET error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "Failed to load snipe targets" });
    }
  }

  return res.status(405).end();
}