import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, run, isDbReady } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";

type ClaimedCode = {
  id: number;
  plan_name: string;
  duration_days: number | null;
  grants_subscription: boolean;
  balance_grant_cents: number;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  // Rate-limit activation code redemptions: 10 per hour per IP (prevents brute-force)
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`redeem:${ip}`, 10, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many attempts, please try again later" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  const code = String(req.body?.code ?? "").trim().toUpperCase();
  if (!code) return res.status(400).json({ error: "Please enter an activation code" });

  try {
    const dbUser = await one<{ id: string; balance_cents: number }>(
      `SELECT id, balance_cents FROM users WHERE email = $1`,
      [session.user.email]
    );
    if (!dbUser) return res.status(404).json({ error: "User not found" });

    // Pre-flight check to give specific error messages before attempting atomic claim
    const preview = await one<{ id: number; used: boolean; used_by: string | null; expires_at: string | null }>(
      `SELECT id, used, used_by, expires_at FROM activation_codes WHERE code = $1`,
      [code]
    );
    if (!preview) return res.status(404).json({ error: "Activation code not found, please double-check and try again" });
    if (preview.used) {
      if (preview.used_by === dbUser.id)
        return res.status(409).json({ error: "You have already used this activation code" });
      return res.status(409).json({ error: "This activation code has already been used" });
    }
    if (preview.expires_at && new Date(preview.expires_at) < new Date())
      return res.status(410).json({ error: "Activation code has expired" });

    // Atomically claim the code — only ONE concurrent request can win.
    // WHERE used = false ensures a second concurrent request returns zero rows.
    const ac = await one<ClaimedCode>(
      `UPDATE activation_codes
          SET used = true, used_by = $1, used_at = NOW()
        WHERE id = $2
          AND used = false
          AND (expires_at IS NULL OR expires_at > NOW())
        RETURNING id, plan_name, duration_days, grants_subscription, balance_grant_cents`,
      [dbUser.id, preview.id]
    );

    if (!ac) {
      // Race lost — another request claimed it between our SELECT and UPDATE
      return res.status(409).json({ error: "This activation code has already been used" });
    }

    const results: string[] = [];

    // Grant subscription access
    if (ac.grants_subscription) {
      if (ac.duration_days) {
        await run(
          `UPDATE users
           SET subscription_access = TRUE,
               membership_plan = $2,
               updated_at = NOW(),
               subscription_expires_at = GREATEST(COALESCE(subscription_expires_at, NOW()), NOW())
                 + ($3 || ' days')::INTERVAL
           WHERE id = $1`,
          [dbUser.id, ac.plan_name, ac.duration_days]
        );
        results.push(`Membership extended by ${ac.duration_days} days (${ac.plan_name})`);
      } else {
        await run(
          `UPDATE users
           SET subscription_access = TRUE,
               membership_plan = $2,
               updated_at = NOW(),
               subscription_expires_at = NULL
           WHERE id = $1`,
          [dbUser.id, ac.plan_name]
        );
        results.push(`Lifetime membership activated (${ac.plan_name})`);
      }
    }

    // Grant balance
    if (ac.balance_grant_cents > 0) {
      await run(
        `UPDATE users SET balance_cents = balance_cents + $2 WHERE id = $1`,
        [dbUser.id, ac.balance_grant_cents]
      );
      await run(
        `INSERT INTO balance_transactions (user_id, amount_cents, type, description)
         VALUES ($1, $2, 'recharge', $3)`,
        [dbUser.id, ac.balance_grant_cents, `Activation code recharge: ${code}`]
      );
      results.push(`Balance increased by ¥${(ac.balance_grant_cents / 100).toFixed(2)}`);
    }

    const updated = await one<{
      subscription_access: boolean;
      subscription_expires_at: string | null;
      balance_cents: number;
      membership_plan: string | null;
    }>(
      `SELECT subscription_access, subscription_expires_at, balance_cents, membership_plan FROM users WHERE id = $1`,
      [dbUser.id]
    );

    return res.json({
      ok: true,
      message: results.join("；"),
      subscriptionAccess: updated?.subscription_access ?? false,
      subscriptionExpiresAt: updated?.subscription_expires_at ?? null,
      membershipPlan: updated?.membership_plan ?? null,
      balanceCents: updated?.balance_cents ?? 0,
    });
  } catch (err: any) {
    console.error("[user/redeem-code]", err.message);
    return res.status(500).json({ error: "Redemption failed, please try again" });
  }
}
