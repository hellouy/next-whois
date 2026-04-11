import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { randomBytes } from "crypto";
import { one, run, isDbReady, withTransaction } from "@/lib/db-query";
import { sendEmail, welcomeHtml, getSiteLabel } from "@/lib/email";
import { localeFromCookieHeader, localeFromAcceptHeader, getEmailStrings } from "@/lib/email-strings";
import { getRedisValue, deleteRedisValue, isRedisAvailable } from "@/lib/server/redis";
import { getCaptchaConfig, verifyCaptchaToken } from "@/lib/server/captcha";
import { checkRateLimit } from "@/lib/rate-limit";

type CodeRow = { id: string; is_active: boolean; use_count: number; max_uses: number; expires_at: string | null };

async function validateInviteCode(code: string): Promise<{ codeRow: CodeRow | null; error: string | null }> {
  const codeRow = await one<CodeRow>(
    "SELECT id, is_active, use_count, max_uses, expires_at FROM invite_codes WHERE code = $1",
    [code.trim().toUpperCase()]
  );
  if (!codeRow) return { codeRow: null, error: "Invalid invite code" };
  if (!codeRow.is_active) return { codeRow: null, error: "Invite code has been deactivated" };
  if (codeRow.expires_at && new Date(codeRow.expires_at) < new Date())
    return { codeRow: null, error: "Invite code has expired" };
  if (codeRow.use_count >= codeRow.max_uses) return { codeRow: null, error: "Invite code usage limit reached" };
  return { codeRow, error: null };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(`${ip}:register`, 10, 60 * 60_000);
  if (!rl.ok) return res.status(429).json({ error: "Too many registration attempts, please try again in 1 hour" });

  const { email, password, name, inviteCode, verifyCode, captchaToken } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Invalid email format" });
  if (String(password).length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (String(password).length > 128)
    return res.status(400).json({ error: "Password must not exceed 128 characters" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable, please try again" });

  const regSetting = await one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'allow_registration'");
  const allowReg = !regSetting || regSetting.value === "1";
  if (!allowReg) return res.status(403).json({ error: "Registration is currently disabled, please contact the administrator" });

  const captchaConfig = await getCaptchaConfig("register");
  if (captchaConfig.provider && captchaConfig.secretKey) {
    if (!captchaToken?.trim()) return res.status(400).json({ error: "Please complete the CAPTCHA verification" });
    const captchaOk = await verifyCaptchaToken(String(captchaToken), captchaConfig.provider, captchaConfig.secretKey);
    if (!captchaOk) return res.status(400).json({ error: "CAPTCHA verification failed, please try again" });
  }

  const requireInvite = await one<{ value: string }>("SELECT value FROM site_settings WHERE key = 'require_invite_code'");
  const needsInvite = requireInvite?.value === "1";

  let codeRow: CodeRow | null = null;
  const cleanInviteCode = inviteCode?.trim() ? String(inviteCode).trim().toUpperCase() : null;

  if (needsInvite) {
    if (!cleanInviteCode) return res.status(400).json({ error: "An invite code is required to register" });
    const { codeRow: cr, error } = await validateInviteCode(cleanInviteCode);
    if (error) return res.status(400).json({ error });
    codeRow = cr;
  } else if (cleanInviteCode) {
    const { codeRow: cr } = await validateInviteCode(cleanInviteCode);
    codeRow = cr;
  }

  const cleanEmail = String(email).toLowerCase().trim();

  // Resolve and validate the verification code BEFORE checking email existence.
  // This ordering matters for security: if we checked email existence first, an
  // attacker could probe whether any address is registered by submitting with no
  // code and reading the error message (409 = registered, 400 = not registered).
  // By checking the code first, probing requires possessing a valid code — which
  // requires access to the inbox — making enumeration practically infeasible.
  let storedCode: string | null = null;
  if (isRedisAvailable()) {
    storedCode = await getRedisValue(`verify:register:${cleanEmail}`);
  }
  if (storedCode === null && (await isDbReady())) {
    const dbCode = await one<{ code: string; expires_at: string }>(
      "SELECT code, expires_at FROM verify_codes WHERE email = $1 AND scope = 'register'",
      [cleanEmail],
    );
    if (dbCode && new Date(dbCode.expires_at) > new Date()) {
      storedCode = dbCode.code;
    }
  }
  // Enforce: code is always required
  if (storedCode === null) {
    return res.status(400).json({ error: "Please send a verification code first, or the code has expired — please request a new one" });
  }
  if (!verifyCode?.trim()) return res.status(400).json({ error: "Please enter the email verification code" });
  if (String(verifyCode).trim() !== storedCode)
    return res.status(400).json({ error: "Incorrect or expired verification code" });

  // Code is valid — now check for duplicate email.
  const existing = await one("SELECT id FROM users WHERE email = $1", [cleanEmail]);
  if (existing) return res.status(409).json({ error: "This email is already registered" });

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
          throw Object.assign(new Error("Invite code usage limit reached, registration failed"), { code: "INVITE_EXHAUSTED" });
        }
      }
    });
  } catch (err: any) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "This email is already registered" });
    }
    if (err.code === "INVITE_EXHAUSTED") {
      return res.status(400).json({ error: err.message });
    }
    console.error("[register] transaction error:", err.message);
    return res.status(500).json({ error: "Registration failed, please try again" });
  }

  // Clean up verification codes (both stores) after successful registration
  if (isRedisAvailable()) {
    await deleteRedisValue(`verify:register:${cleanEmail}`).catch(() => {});
  }
  if (await isDbReady()) {
    await run("DELETE FROM verify_codes WHERE email = $1 AND scope = 'register'", [cleanEmail]).catch(() => {});
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
