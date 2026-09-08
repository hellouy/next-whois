import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { createHash } from "crypto";
import { one, isDbReady, withTransaction } from "@/lib/db-query";
import { sendEmail, passwordChangedHtml, getSiteLabel } from "@/lib/email";
import { checkRateLimit } from "@/lib/rate-limit";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/reset-password");

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

  // SECURITY: tokens are stored hashed (see forgot-password), so claims must
  // hash the submitted token before matching — never compare plaintext.
  const tokenHash = createHash("sha256").update(token).digest("hex");

  // Atomic claim + password update in ONE transaction. The token is marked used
  // in the same transaction that writes the new hash, so a replayed submission
  // cannot double-apply. Bump session_version so every previously issued JWT is
  // invalidated (the jwt session callback enforces it) — a stolen session from
  // before the reset no longer works.
  let claimedUserId: string | null = null;
  try {
    claimedUserId = await withTransaction(async (tx) => {
      const row = await tx.one<{ id: string; user_id: string }>(
        `UPDATE password_reset_tokens
            SET used = true
          WHERE token = $1
            AND used = false
            AND expires_at > NOW()
          RETURNING id, user_id`,
        [tokenHash],
      );
      if (!row) return null;
      await tx.run(
        "UPDATE users SET password_hash = $1, session_version = session_version + 1, updated_at = NOW() WHERE id = $2",
        [newHash, row.user_id],
      );
      return row.user_id;
    });
  } catch (err: any) {
    logger.error("[reset-password] transaction error:", err.message);
    return res.status(500).json({ error: "Reset failed, please try again" });
  }

  if (!claimedUserId) {
    // Distinguish "never existed" from "already used / expired" for UX.
    const exists = await one<{ used: boolean; expires_at: string }>(
      "SELECT used, expires_at FROM password_reset_tokens WHERE token = $1",
      [tokenHash],
    );
    if (!exists) return res.status(400).json({ error: "Invalid or expired reset link" });
    if (exists.used) return res.status(400).json({ error: "This reset link has already been used, please request a new one" });
    return res.status(400).json({ error: "Reset link has expired, please request a new one" });
  }

  const userRow = await one<{ email: string; name: string | null }>(
    "SELECT email, name FROM users WHERE id = $1",
    [claimedUserId]
  );
  if (userRow) {
    getSiteLabel().then(siteName =>
      sendEmail({
        to: userRow.email,
        subject: `Password Reset Successful — Security Notice | ${siteName}`,
        html: passwordChangedHtml({ name: userRow.name ?? null, email: userRow.email, siteName }),
      }).catch(e => logger.error("[reset-password] email error:", e))
    );
  }

  return res.status(200).json({ ok: true });
}
