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
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  // Rate-limit activation code redemptions: 10 per hour per IP (prevents brute-force)
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`redeem:${ip}`, 10, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many attempts, please try again later" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "请先登录" });

  const code = String(req.body?.code ?? "").trim().toUpperCase();
  if (!code) return res.status(400).json({ error: "请输入激活码" });

  try {
    const dbUser = await one<{ id: string; balance_cents: number }>(
      `SELECT id, balance_cents FROM users WHERE email = $1`,
      [session.user.email]
    );
    if (!dbUser) return res.status(404).json({ error: "用户不存在" });

    // Pre-flight check to give specific error messages before attempting atomic claim
    const preview = await one<{ id: number; used: boolean; used_by: string | null; expires_at: string | null }>(
      `SELECT id, used, used_by, expires_at FROM activation_codes WHERE code = $1`,
      [code]
    );
    if (!preview) return res.status(404).json({ error: "激活码不存在，请检查后重试" });
    if (preview.used) {
      if (preview.used_by === dbUser.id)
        return res.status(409).json({ error: "您已使用过该激活码" });
      return res.status(409).json({ error: "该激活码已被使用" });
    }
    if (preview.expires_at && new Date(preview.expires_at) < new Date())
      return res.status(410).json({ error: "激活码已过期" });

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
      return res.status(409).json({ error: "该激活码已被使用" });
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
        results.push(`会员已延长 ${ac.duration_days} 天（${ac.plan_name}）`);
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
        results.push(`已开通永久会员（${ac.plan_name}）`);
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
        [dbUser.id, ac.balance_grant_cents, `激活码充值：${code}`]
      );
      results.push(`余额增加 ¥${(ac.balance_grant_cents / 100).toFixed(2)}`);
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
    return res.status(500).json({ error: "兑换失败，请稍后重试" });
  }
}
