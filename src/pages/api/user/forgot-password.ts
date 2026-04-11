import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { one, run, isDbReady } from "@/lib/db-query";
import { sendEmail, passwordResetHtml, getSiteLabel } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";
import { localeFromCookieHeader, getEmailStrings } from "@/lib/email-strings";

const RESET_EXPIRES_MINUTES = 60;
const SITE_URL =
  process.env.NEXT_PUBLIC_BASE_URL ||
  process.env.NEXTAUTH_URL ||
  "https://example.com";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(`${ip}:forgot`, 3, 10 * 60_000);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again in 10 minutes" });

  const { email } = req.body;
  if (!email || typeof email !== "string")
    return res.status(400).json({ error: "Please enter your email address" });

  const cleanEmail = email.toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail))
    return res.status(400).json({ error: "Invalid email format" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const user = await one<{ id: string; locale: string | null }>(
    "SELECT id, locale FROM users WHERE email = $1",
    [cleanEmail],
  );
  // Always return ok to prevent email enumeration
  if (!user) return res.status(200).json({ ok: true });

  const locale = user.locale || localeFromCookieHeader(req.headers.cookie) || "zh";

  await run(
    "UPDATE password_reset_tokens SET used = true WHERE user_id = $1 AND used = false",
    [user.id],
  );

  const tokenId = randomBytes(8).toString("hex");
  const rawToken = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + RESET_EXPIRES_MINUTES * 60 * 1000).toISOString();

  try {
    await run(
      "INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES ($1, $2, $3, $4)",
      [tokenId, user.id, rawToken, expiresAt],
    );
  } catch (err: any) {
    console.error("[forgot-password] token insert error:", err.message);
    return res.status(500).json({ error: "Operation failed, please try again later" });
  }

  const resetUrl = `${SITE_URL}/reset-password?token=${rawToken}`;
  const siteName = await getSiteLabel().catch(() => "WHOIS");
  const s = getEmailStrings(locale);
  try {
    await sendEmail({
      to: cleanEmail,
      subject: s.subj_password_reset(siteName),
      html: passwordResetHtml({ resetUrl, siteName, locale }),
    });
  } catch (e) {
    console.error("[forgot-password] Failed to send email:", e);
    return res.status(500).json({ error: "Failed to send email, please try again later" });
  }

  return res.status(200).json({ ok: true });
}
