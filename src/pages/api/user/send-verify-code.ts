import type { NextApiRequest, NextApiResponse } from "next";
import {
  setRedisValue,
  getRedisValue,
  deleteRedisValue,
  isRedisAvailable,
} from "@/lib/server/redis";
import { sendEmailDirect, verifyCodeHtml, getSiteLabel } from "@/lib/email";
import { isDbReady, one, run } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";

/** Store a verification code in the DB as a Redis-independent fallback.
 *  Uses an UPSERT so one row per (email, scope) — old code is simply replaced. */
async function storeCodeInDb(email: string, code: string): Promise<void> {
  if (!(await isDbReady())) return;
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await run(
    `INSERT INTO verify_codes (email, scope, code, expires_at)
     VALUES ($1, 'register', $2, $3)
     ON CONFLICT (email, scope) DO UPDATE
       SET code = $2, expires_at = $3, created_at = NOW()`,
    [email, code, expiresAt],
  );
}

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

  // Rate limit: max 1 code per 60 s (Redis-preferred, DB fallback via checkRateLimit)
  if (isRedisAvailable()) {
    const rateLimitKey = `verify:rate:${cleanEmail}`;
    const recentlySent = await getRedisValue(rateLimitKey);
    if (recentlySent) return res.status(429).json({ error: "请稍等 60 秒后再重新发送" });
  } else if (await isDbReady()) {
    const rl = await checkRateLimit(`verify:rate:${cleanEmail}`, 1, 60_000);
    if (!rl.ok) return res.status(429).json({ error: "请稍等 60 秒后再重新发送" });
  } else {
    return res.status(503).json({ error: "验证码服务暂不可用，请稍后重试" });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));

  // Persist the code (Redis preferred, DB fallback — both may succeed simultaneously)
  let stored = false;
  if (isRedisAvailable()) {
    const ok = await setRedisValue(`verify:register:${cleanEmail}`, code, 600);
    if (ok) stored = true;
  }
  // Always write to DB as a fallback so registration works when Redis is down
  try {
    await storeCodeInDb(cleanEmail, code);
    stored = true;
  } catch {
    // DB write failed — that is acceptable if Redis succeeded
  }

  if (!stored) {
    return res.status(503).json({ error: "验证码服务暂不可用，请稍后重试" });
  }

  const siteName = await getSiteLabel().catch(() => "X.RW");
  try {
    await sendEmailDirect(
      cleanEmail,
      `${code} 是你的 ${siteName} 注册验证码`,
      verifyCodeHtml({ code, email: cleanEmail, siteName }),
    );
  } catch (err: any) {
    // Roll back stored codes on email failure
    if (isRedisAvailable()) await deleteRedisValue(`verify:register:${cleanEmail}`).catch(() => {});
    if (await isDbReady())
      await run("DELETE FROM verify_codes WHERE email = $1 AND scope = 'register'", [cleanEmail]).catch(() => {});
    console.error("[send-verify-code] email send failed:", err.message);
    return res.status(500).json({ error: "邮件发送失败，请检查邮件配置或稍后重试" });
  }

  // Set Redis rate-limit key (best-effort; DB rate-limit already recorded above when Redis was down)
  if (isRedisAvailable()) {
    await setRedisValue(`verify:rate:${cleanEmail}`, "1", 60).catch(() => {});
  }

  return res.status(200).json({ ok: true });
}
