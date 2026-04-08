import type { NextApiRequest, NextApiResponse } from "next";
import { setRedisValue, getRedisValue, deleteRedisValue, isRedisAvailable } from "@/lib/server/redis";
import { sendEmailDirect, verifyCodeHtml, getSiteLabel } from "@/lib/email";
import { isDbReady, one } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email)))
    return res.status(400).json({ error: "邮箱格式不正确" });

  const cleanEmail = String(email).toLowerCase().trim();

  if (await isDbReady()) {
    const regSetting = await one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'allow_registration'");
    const allowReg = !regSetting || regSetting.value === "1";
    if (!allowReg) return res.status(403).json({ error: "注册已暂停，请联系管理员" });

    const existing = await one("SELECT id FROM users WHERE email = $1", [cleanEmail]);
    if (existing) return res.status(409).json({ error: "该邮箱已注册" });
  }

  if (!isRedisAvailable()) {
    return res.status(503).json({ error: "验证码服务暂不可用，请稍后重试" });
  }

  const rateLimitKey = `verify:rate:${cleanEmail}`;
  const recentlySent = await getRedisValue(rateLimitKey);
  if (recentlySent) return res.status(429).json({ error: "请稍等 60 秒后再重新发送" });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const storeKey = `verify:register:${cleanEmail}`;
  const stored = await setRedisValue(storeKey, code, 600);
  if (!stored) return res.status(503).json({ error: "验证码服务暂不可用，请稍后重试" });

  const siteName = await getSiteLabel().catch(() => "X.RW");
  try {
    await sendEmailDirect(
      cleanEmail,
      `${code} 是你的 ${siteName} 注册验证码`,
      verifyCodeHtml({ code, email: cleanEmail, siteName }),
    );
  } catch (err: any) {
    await deleteRedisValue(storeKey);
    console.error("[send-verify-code] email send failed:", err.message);
    return res.status(500).json({ error: "邮件发送失败，请检查邮件配置或稍后重试" });
  }

  await setRedisValue(rateLimitKey, "1", 60);
  return res.status(200).json({ ok: true });
}
