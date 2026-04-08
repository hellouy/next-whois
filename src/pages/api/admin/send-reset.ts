import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { requireAdmin } from "@/lib/admin";
import { one, run, isDbReady } from "@/lib/db-query";
import { sendEmail, passwordResetHtml, getSiteLabel } from "@/lib/email";
import { isAdminEmail } from "@/lib/admin-server";

const RESET_EXPIRES_MINUTES = 60;
const SITE_URL =
  process.env.NEXT_PUBLIC_BASE_URL ||
  process.env.NEXTAUTH_URL ||
  "https://x.rw";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await requireAdmin(req, res);
  if (!session) return;

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  const { userId, email } = req.body as { userId?: string; email?: string };

  let targetEmail: string | null = null;
  let targetId: string | null = null;

  if (userId) {
    const row = await one<{ id: string; email: string; disabled: boolean }>(
      "SELECT id, email, disabled FROM users WHERE id = $1",
      [userId]
    );
    if (!row) return res.status(404).json({ error: "用户不存在" });
    if (await isAdminEmail(row.email)) return res.status(403).json({ error: "无法操作创始人账户" });
    targetEmail = row.email;
    targetId = row.id;
  } else if (email) {
    const cleanEmail = email.toLowerCase().trim();
    const row = await one<{ id: string; email: string }>(
      "SELECT id, email FROM users WHERE email = $1",
      [cleanEmail]
    );
    if (!row) return res.status(404).json({ error: "该邮箱对应用户不存在" });
    targetEmail = row.email;
    targetId = row.id;
  } else {
    return res.status(400).json({ error: "请提供 userId 或 email" });
  }

  await run(
    "UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false",
    [targetId]
  );

  const tokenId = randomBytes(8).toString("hex");
  const rawToken = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + RESET_EXPIRES_MINUTES * 60 * 1000).toISOString();

  try {
    await run(
      "INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)",
      [tokenId, targetId, rawToken, expiresAt]
    );
  } catch (err: any) {
    return res.status(500).json({ error: "生成重置令牌失败" });
  }

  const resetUrl = `${SITE_URL}/reset-password?token=${rawToken}`;
  const siteName = await getSiteLabel().catch(() => "X.RW");

  try {
    await sendEmail({
      to: targetEmail,
      subject: `重置你的 ${siteName} 密码（管理员触发）`,
      html: passwordResetHtml({ resetUrl, siteName }),
    });
  } catch (e) {
    return res.status(500).json({ error: "邮件发送失败，请检查邮件服务配置" });
  }

  return res.status(200).json({ ok: true, email: targetEmail });
}
