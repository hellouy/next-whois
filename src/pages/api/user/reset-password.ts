import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { one, run, isDbReady } from "@/lib/db-query";
import { sendEmail, passwordChangedHtml, getSiteLabel } from "@/lib/email";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { token, password } = req.body;
  if (!token || typeof token !== "string")
    return res.status(400).json({ error: "无效的重置链接" });
  if (!password || String(password).length < 8)
    return res.status(400).json({ error: "密码至少 8 位" });
  if (String(password).length > 128)
    return res.status(400).json({ error: "密码最长 128 位" });

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  const record = await one<{ id: string; user_id: string; expires_at: string; used: boolean }>(
    "SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token = $1",
    [token],
  );

  if (!record) return res.status(400).json({ error: "重置链接无效或已过期" });
  if (record.used) return res.status(400).json({ error: "该重置链接已被使用，请重新申请" });
  if (new Date(record.expires_at) < new Date())
    return res.status(400).json({ error: "重置链接已过期，请重新申请" });

  const newHash = await hash(String(password), 12);

  try {
    await run("UPDATE users SET password_hash = $1 WHERE id = $2", [newHash, record.user_id]);
  } catch (err: any) {
    console.error("[reset-password] update error:", err.message);
    return res.status(500).json({ error: "重置失败，请稍后重试" });
  }

  await run("UPDATE password_reset_tokens SET used = true WHERE id = $1", [record.id]);

  const userRow = await one<{ email: string; name: string | null }>(
    "SELECT email, name FROM users WHERE id = $1",
    [record.user_id]
  );
  if (userRow) {
    getSiteLabel().then(siteName =>
      sendEmail({
        to: userRow.email,
        subject: `账号密码已重置 — 安全提醒 | ${siteName}`,
        html: passwordChangedHtml({ name: userRow.name ?? null, email: userRow.email, siteName }),
      }).catch(e => console.error("[reset-password] email error:", e))
    );
  }

  return res.status(200).json({ ok: true });
}
