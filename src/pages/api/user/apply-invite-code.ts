import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, isDbReady, withTransaction } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/apply-invite-code");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // Rate-limit invite code attempts: 10 per hour per IP (prevents enumeration)
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`invite:apply:${ip}`, 10, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many attempts, please try again later" });

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const userEmail = (session.user as any).email as string;
  const user = await one<{ id: string; subscription_access: boolean; subscription_expires_at: string | null }>(
    "SELECT id, subscription_access, subscription_expires_at FROM users WHERE email = $1",
    [userEmail]
  );
  if (!user) return res.status(404).json({ error: "User not found" });

  const isActiveSubscriber = user.subscription_access && (
    !user.subscription_expires_at || new Date(user.subscription_expires_at) > new Date()
  );
  if (isActiveSubscriber) return res.status(400).json({ error: "You already have subscription access", code: "ALREADY_HAS_ACCESS" });

  const { inviteCode } = req.body;
  if (!inviteCode?.trim()) return res.status(400).json({ error: "Please enter an invite code" });

  const code = String(inviteCode).trim().toUpperCase();

  // Pre-flight SELECT for specific error messages
  const preview = await one<{
    id: string; is_active: boolean; use_count: number; max_uses: number; expires_at: string | null;
  }>(
    "SELECT id, is_active, use_count, max_uses, expires_at FROM invite_codes WHERE code = $1",
    [code]
  );
  if (!preview) return res.status(400).json({ error: "Invalid invite code" });
  if (!preview.is_active) return res.status(400).json({ error: "Invite code has been deactivated" });
  if (preview.expires_at && new Date(preview.expires_at) < new Date())
    return res.status(400).json({ error: "Invite code has expired" });
  if (preview.use_count >= preview.max_uses) return res.status(400).json({ error: "Invite code usage limit reached" });

  // Claim the code and grant access in ONE transaction so a failure mid-way
  // never consumes the code without granting access (or vice versa).
  const granted = await withTransaction(async (tx) => {
    // Atomically increment use_count only when still within limit.
    // Concurrent requests: only one wins; the rest get null back.
    const claimed = await tx.one<{ id: string }>(
      `UPDATE invite_codes
          SET use_count = use_count + 1
        WHERE id = $1
          AND is_active = true
          AND use_count < max_uses
          AND (expires_at IS NULL OR expires_at > NOW())
        RETURNING id`,
      [preview.id]
    );
    if (!claimed) return false;

    const updated = await tx.run(
      "UPDATE users SET subscription_access = TRUE, invite_code_used = $1, updated_at = NOW() WHERE id = $2",
      [code, user.id]
    );
    return updated === 1;
  }).catch((err: any) => {
    logger.error("[apply-invite-code] transaction error:", err?.message);
    return null;
  });

  if (granted === null) {
    return res.status(500).json({ error: "Failed to apply invite code, please try again" });
  }
  if (!granted) {
    // Race lost — concurrently exhausted/deactivated between SELECT and UPDATE,
    // or the user row vanished mid-transaction (rolled back the consume).
    return res.status(400).json({ error: "Invite code limit reached or deactivated" });
  }

  return res.status(200).json({ ok: true });
}
