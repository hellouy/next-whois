import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, run, withTransaction, isDbReady } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";
import { snipeServicePrice } from "@/lib/server/snipe-pricing";
import {
  createUserSnipeTarget,
  freezeForSnipe,
  cancelUserSnipeTarget,
  SnipeTakenError,
} from "@/lib/server/snipe-balance";

const logger = createLogger("api/user/snipe-targets/[domain]");

/**
 * GET /api/user/snipe-targets/[domain]
 * PATCH /api/user/snipe-targets/[domain]  body: { action: 'enable' | 'disable' }
 *
 * Single-target read + enable/disable mirroring the subscriptions.ts snipe_action
 * flow. Ownership is enforced twice: the 404 on lookup (user_email match) and
 * every mutation re-scoped by user_email inside the balance helpers.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const userEmail = session.user.email;
  const domain = String(req.query.domain ?? "").toLowerCase();
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  const loadTarget = () =>
    one<{
      id: string; domain: string; tld: string; status: string;
      service_price_cents: number | null; frozen_cents: number; fail_reason: string | null;
      notes: string | null; drop_eta: string | null; hunt_start: string | null;
      hunt_end: string | null; registered_at: string | null; created_at: string;
      updated_at: string; has_sub: boolean | null; reminder_id: string | null;
    }>(
      `SELECT t.id, t.domain, t.tld, t.status,
              t.service_price_cents, t.frozen_cents, t.fail_reason,
              t.notes, t.drop_eta, t.hunt_start, t.hunt_end, t.registered_at,
              t.created_at, t.updated_at,
              (EXISTS (SELECT 1 FROM reminders r
                       WHERE r.email = $1 AND r.domain = t.domain)) AS has_sub,
              (SELECT r.id FROM reminders r
               WHERE r.email = $1 AND r.domain = t.domain) AS reminder_id
       FROM snipe_targets t
       WHERE t.domain = $2 AND t.user_email = $1`,
      [userEmail, domain],
    );

  if (req.method === "GET") {
    try {
      const row = await loadTarget();
      if (!row) return res.status(404).json({ error: "Snipe target not found" });

      const user = await one<{ balance_cents: number }>(
        "SELECT balance_cents FROM users WHERE email = $1",
        [userEmail],
      );

      return res.status(200).json({
        target: {
          id: row.id,
          domain: row.domain,
          tld: row.tld,
          status: row.status,
          serviceCents: row.service_price_cents,
          frozenCents: row.frozen_cents,
          failReason: row.fail_reason,
          notes: row.notes,
          dropEta: row.drop_eta,
          huntStart: row.hunt_start,
          huntEnd: row.hunt_end,
          registeredAt: row.registered_at,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          hasSubscription: !!row.has_sub,
          linkedReminderId: row.reminder_id,
        },
        balanceCents: user?.balance_cents ?? 0,
      });
    } catch (err) {
      logger.error("[snipe-targets] GET error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "Failed to load snipe target" });
    }
  }

  if (req.method === "PATCH") {
    const { action } = (req.body ?? {}) as { action?: string };

    if (action === "disable") {
      const existing = await loadTarget();
      if (!existing) return res.status(404).json({ error: "Snipe target not found" });
      try {
        const released = await withTransaction((tx) =>
          cancelUserSnipeTarget(tx, { domain, userEmail }),
        );
        return res.status(200).json({ ok: true, snipe: { status: "cancelled", releasedCents: released } });
      } catch (err) {
        logger.error("[snipe-targets] PATCH disable error:", err instanceof Error ? err.message : String(err));
        return res.status(500).json({ error: "停用失败，请稍后重试" });
      }
    }

    if (action !== "enable") {
      return res.status(400).json({ error: "action must be 'enable' or 'disable'" });
    }

    // enable: no pre-existing target required — createUserSnipeTarget creates
    // when absent and throws SnipeTakenError when another user holds the domain.

    try {
      const quote = await snipeServicePrice(domain);
      if (!quote || quote.serviceCents == null || quote.serviceCents <= 0) {
        return res.status(502).json({ error: "无法获取注册报价，抢注暂不可用" });
      }
      const serviceCents = quote.serviceCents as number;

      const result = await withTransaction(async (tx) => {
        const targetId = await createUserSnipeTarget(tx, {
          domain,
          tld: (() => {
            const labels = domain.split(".");
            return labels[labels.length - 1] ?? "";
          })(),
          userEmail,
          serviceCents,
          expirationDate: null,
        });
        const hold = await freezeForSnipe(tx, targetId, userEmail, serviceCents);
        return { targetId, hold };
      });

      if (result.hold.insufficient) {
        await runStatusUpdate(result.targetId, "blocked_balance");
        return res.status(200).json({
          ok: true,
          snipe: {
            status: "blocked_balance",
            serviceCents,
            balanceCents: result.hold.balanceCents,
            neededCents: serviceCents - Math.max(0, result.hold.balanceCents),
          },
        });
      }

      await runStatusUpdate(result.targetId, "armed");
      return res.status(200).json({ ok: true, snipe: { status: "armed", serviceCents } });
    } catch (err) {
      if (err instanceof SnipeTakenError) {
        return res.status(409).json({ error: "该域名已被其他用户预定抢注", code: "SNIPE_TAKEN" });
      }
      logger.error("[snipe-targets] PATCH enable error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "抢注操作失败，请稍后重试" });
    }
  }

  return res.status(405).end();
}

async function runStatusUpdate(targetId: string, status: string) {
  await run("UPDATE snipe_targets SET status = $2, updated_at = NOW() WHERE id = $1", [targetId, status]);
}