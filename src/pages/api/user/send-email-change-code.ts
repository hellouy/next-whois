import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { setRedisValue, getRedisValue, deleteRedisValue } from "@/lib/server/redis";
import { sendEmail, verifyCodeHtml, getSiteLabel } from "@/lib/email";
import { isDbReady, one } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/send-email-change-code");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  const { newEmail } = req.body;
  if (!newEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(newEmail))) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  const cleanNew = String(newEmail).toLowerCase().trim();
  const currentEmail = session.user.email;

  if (cleanNew === currentEmail.toLowerCase()) {
    return res.status(400).json({ error: "New email is the same as the current email" });
  }

  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`email-change-code:${ip}`, 5, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again later" });

  if (await isDbReady()) {
    const existing = await one("SELECT id FROM users WHERE email = $1", [cleanNew]);
    if (existing) return res.status(409).json({ error: "This email is already used by another account" });
  }

  const rateLimitKey = `email-change-rate:${currentEmail}`;
  const recentlySent = await getRedisValue(rateLimitKey);
  if (recentlySent) return res.status(429).json({ error: "Please wait 60 seconds before requesting a new code" });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const storeKey = `email-change:${currentEmail}:${cleanNew}`;

  await setRedisValue(storeKey, code, 600);
  await setRedisValue(rateLimitKey, "1", 60);

  const siteName = await getSiteLabel().catch(() => "WHOIS");
  try {
    await sendEmail({
      to: cleanNew,
      subject: `${code} 是你的 ${siteName} 邮箱更换验证码`,
      html: verifyCodeHtml({ code, email: cleanNew, siteName }),
    });
  } catch (e: any) {
    // Roll back stored code and rate-limit key so the user can retry immediately
    await deleteRedisValue(storeKey).catch(() => {});
    await deleteRedisValue(rateLimitKey).catch(() => {});
    logger.error("[send-email-change-code] sendEmail failed:", e.message);
    return res.status(500).json({ error: "Failed to send verification code, please check the email address and try again" });
  }

  return res.status(200).json({ ok: true });
}
