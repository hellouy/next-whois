import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { randomBytes } from "crypto";
import { one, run, isDbReady, withTransaction } from "@/lib/db-query";
import { sendEmail, welcomeHtml, getSiteLabel } from "@/lib/email";
import { localeFromCookieHeader, localeFromAcceptHeader, getEmailStrings } from "@/lib/email-strings";
import { getRedisValue, deleteRedisValue } from "@/lib/server/redis";
import { getCaptchaConfig, verifyCaptchaToken } from "@/lib/server/captcha";
import { checkRateLimit } from "@/lib/rate-limit";

type CodeRow = { id: string; is_active: boolean; use_count: number; max_uses: number; expires_at: string | null };

async function validateInviteCode(code: string): Promise<{ codeRow: CodeRow | null; error: string | null }> {
  const codeRow = await one<CodeRow>(
    "SELECT id, is_active, use_count, max_uses, expires_at FROM invite_codes WHERE code = $1",
    [code.trim().toUpperCase()]
  );
  if (!codeRow) return { codeRow: null, error: "邀请码无效" };
  if (!codeRow.is_active) return { codeRow: null, error: "邀请码已停用" };
  if (codeRow.expires_at && new Date(codeRow.expires_at) < new Date())
    return { codeRow: null, error: "邀请码已过期" };
  if (codeRow.use_count >= codeRow.max_uses) return { codeRow: null, error: "邀请码已达使用上限" };
  return { codeRow, error: null };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(`${ip}:register`, 10, 60 * 60_000);
  if (!rl.ok) return res.status(429).json({ error: "注册请求过于频繁，请1小时后再试" });

  const { email, password, name, inviteCode, verifyCode, captchaToken } = req.body;
  if (!email || !password) return res.status(400).json({ error: "邮箱和密码不能为空" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "邮箱格式不正确" });
  if (String(password).length < 8)
    return res.status(400).json({ error: "密码至少 8 位" });
  if (String(password).length > 128)
    return res.status(400).json({ error: "密码最长 128 位" });

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用，请稍后重试" });

  const regSetting = await one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'allow_registration'");
  const allowReg = !regSetting || regSetting.value === "1";
  if (!allowReg) return res.status(403).json({ error: "注册已暂停，请联系管理员" });

  const captchaConfig = await getCaptchaConfig("register");
  if (captchaConfig.provider && captchaConfig.secretKey) {
    if (!captchaToken?.trim()) return res.status(400).json({ error: "请完成人机验证" });
    const captchaOk = await verifyCaptchaToken(String(captchaToken), captchaConfig.provider, captchaConfig.secretKey);
    if (!captchaOk) return res.status(400).json({ error: "人机验证失败，请重试" });
  }

  const requireInvite = await one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'require_invite_code'");
  const needsInvite = requireInvite?.value === "1";

  let codeRow: CodeRow | null = null;
  const cleanInviteCode = inviteCode?.trim() ? String(inviteCode).trim().toUpperCase() : null;

  if (needsInvite) {
    if (!cleanInviteCode) return res.status(400).json({ error: "注册需要邀请码" });
    const { codeRow: cr, error } = await validateInviteCode(cleanInviteCode);
    if (error) return res.status(400).json({ error });
    codeRow = cr;
  } else if (cleanInviteCode) {
    const { codeRow: cr } = await validateInviteCode(cleanInviteCode);
    codeRow = cr;
  }

  const cleanEmail = String(email).toLowerCase().trim();
  const existing = await one("SELECT id FROM users WHERE email = $1", [cleanEmail]);
  if (existing) return res.status(409).json({ error: "该邮箱已注册" });

  const storedCode = await getRedisValue(`verify:register:${cleanEmail}`);
  if (storedCode !== null) {
    if (!verifyCode?.trim()) return res.status(400).json({ error: "请填写邮箱验证码" });
    if (String(verifyCode).trim() !== storedCode)
      return res.status(400).json({ error: "验证码错误或已过期" });
  }

  const id = randomBytes(8).toString("hex");
  const passwordHash = await hash(String(password), 12);
  const cleanName = name ? String(name).trim().slice(0, 50) || null : null;
  const subscriptionAccess = codeRow !== null;

  const locale = localeFromCookieHeader(req.headers.cookie) ||
                 localeFromAcceptHeader(req.headers["accept-language"]);

  try {
    // Wrap user insert + invite-code update in a single transaction so a
    // mid-flight failure never leaves an orphaned user or over-used invite code.
    await withTransaction(async (tx) => {
      await tx.run(
        "INSERT INTO users (id, email, password_hash, name, subscription_access, invite_code_used, locale) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        [id, cleanEmail, passwordHash, cleanName, subscriptionAccess, cleanInviteCode ?? null, locale],
      );

      if (codeRow) {
        const updated = await tx.run(
          "UPDATE invite_codes SET use_count = use_count + 1 WHERE id = $1 AND use_count < max_uses",
          [codeRow.id],
        );
        if (updated === 0) {
          throw Object.assign(new Error("邀请码已达使用上限，注册失败"), { code: "INVITE_EXHAUSTED" });
        }
      }
    });
  } catch (err: any) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "该邮箱已注册" });
    }
    if (err.code === "INVITE_EXHAUSTED") {
      return res.status(400).json({ error: err.message });
    }
    console.error("[register] transaction error:", err.message);
    return res.status(500).json({ error: "注册失败，请稍后重试" });
  }

  if (storedCode !== null) {
    await deleteRedisValue(`verify:register:${cleanEmail}`);
  }

  getSiteLabel().then((siteName) => {
    const s = getEmailStrings(locale);
    sendEmail({
      to: cleanEmail,
      subject: s.subj_welcome(siteName),
      html: welcomeHtml({ name: cleanName, email: cleanEmail, siteName, locale }),
    });
  }).catch((e) => console.error("[register] welcome email error:", e));

  return res.status(201).json({ ok: true });
}
