import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { one, run, isDbReady } from "@/lib/db-query";
import { sendEmail, passwordChangedHtml, getSiteLabel } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`reset-pwd:${ip}`, 5, 15 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again later" });

  const { token, password } = req.body;
  if (!token || typeof token !== "string")
    return res.status(400).json({ error: "Invalid reset link" });
  if (!password || String(password).length < 8)
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (String(password).length > 128)
    return res.status(400).json({ error: "Password must not exceed 128 characters" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  // Hash password first so the atomic claim is instant (not slowed by bcrypt)
  const newHash = await hash(String(password), 12);

  // Atomically claim the token — only one concurrent request can succeed.
  // If used = true OR expires_at is past, zero rows are returned → fail.
  const claimed = await one<{ id: string; user_id: string }>(
    `UPDATE password_reset_tokens
        SET used = true
      WHERE token = $1
        AND used = false
        AND expires_at > NOW()
      RETURNING id, user_id`,
    [token],
  );

  if (!claimed) {
    // Distinguish "never existed" from "already used / expired" for UX,
    // without leaking timing information about valid tokens.
    const exists = await one<{ used: boolean; expires_at: string }>(
      "SELECT used, expires_at FROM password_reset_tokens WHERE token = $1",
      [token],
    );
    if (!exists) return res.status(400).json({ error: "Invalid or expired reset link" });
    if (exists.used) return res.status(400).json({ error: "This reset link has already been used, please request a new one" });
    return res.status(400).json({ error: "Reset link has expired, please request a new one" });
  }

  try {
    await run("UPDATE users SET password_hash = $1 WHERE id = $2", [newHash, claimed.user_id]);
  } catch (err: any) {
    // Roll back the token claim so the user can retry
    await run("UPDATE password_reset_tokens SET used = false WHERE id = $1", [claimed.id]).catch(() => {});
    console.error("[reset-password] update error:", err.message);
    return res.status(500).json({ error: "Reset failed, please try again" });
  }

  const userRow = await one<{ email: string; name: string | null }>(
    "SELECT email, name FROM users WHERE id = $1",
    [claimed.user_id]
  );
  if (userRow) {
    getSiteLabel().then(siteName =>
      sendEmail({
        to: userRow.email,
        subject: `Password Reset Successful — Security Notice | ${siteName}`,
        html: passwordChangedHtml({ name: userRow.name ?? null, email: userRow.email, siteName }),
      }).catch(e => console.error("[reset-password] email error:", e))
    );
  }

  return res.status(200).json({ ok: true });
}
