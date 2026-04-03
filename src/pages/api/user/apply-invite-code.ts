import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, run, isDbReady } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // Rate-limit invite code attempts: 10 per hour per IP (prevents enumeration)
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`invite:apply:${ip}`, 10, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many attempts, please try again later" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user) return res.status(401).json({ error: "请先登录" });

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库不可用" });

  const userEmail = (session.user as any).email as string;
  const user = await one<{ id: string; subscription_access: boolean; subscription_expires_at: string | null }>(
    "SELECT id, subscription_access, subscription_expires_at FROM users WHERE email = $1",
    [userEmail]
  );
  if (!user) return res.status(404).json({ error: "用户不存在" });
  // Only block if subscription is still active (not expired)
  const isActiveSubscriber = user.subscription_access && (
    !user.subscription_expires_at || new Date(user.subscription_expires_at) > new Date()
  );
  if (isActiveSubscriber) return res.status(400).json({ error: "你已拥有订阅权限", code: "ALREADY_HAS_ACCESS" });

  const { inviteCode } = req.body;
  if (!inviteCode?.trim()) return res.status(400).json({ error: "请输入邀请码" });

  const code = String(inviteCode).trim().toUpperCase();
  const codeRow = await one<{
    id: string; is_active: boolean; use_count: number; max_uses: number; expires_at: string | null;
  }>(
    "SELECT id, is_active, use_count, max_uses, expires_at FROM invite_codes WHERE code = $1",
    [code]
  );
  if (!codeRow) return res.status(400).json({ error: "邀请码无效" });
  if (!codeRow.is_active) return res.status(400).json({ error: "邀请码已停用" });
  if (codeRow.expires_at && new Date(codeRow.expires_at) < new Date())
    return res.status(400).json({ error: "邀请码已过期" });
  if (codeRow.use_count >= codeRow.max_uses) return res.status(400).json({ error: "邀请码已达使用上限" });

  await run("UPDATE users SET subscription_access = TRUE, invite_code_used = $1, updated_at = NOW() WHERE id = $2", [code, user.id]);
  await run("UPDATE invite_codes SET use_count = use_count + 1 WHERE id = $1", [codeRow.id]);

  return res.status(200).json({ ok: true });
}
