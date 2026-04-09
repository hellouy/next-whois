import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, run, isDbReady } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { getRedisValue, deleteRedisValue } from "@/lib/server/redis";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  // Rate-limit write operations
  if (req.method === "PATCH") {
    const ip = String(
      req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
    ).split(",")[0].trim();
    const rl = await checkRateLimit(`profile:update:${ip}`, 10, 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "Too many requests" });
  }

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  if (req.method === "GET") {
    const user = await one<{
      id: string; name: string | null; email: string;
      avatar_color: string | null; email_verified: boolean; created_at: string;
    }>(
      "SELECT id, name, email, avatar_color, email_verified, created_at FROM users WHERE email = $1",
      [session.user.email],
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.status(200).json({ user });
  }

  if (req.method === "PATCH") {
    const { name, avatar_color, email, emailChangeCode } = req.body;
    const updates: string[] = [];
    const params: (string | null)[] = [];
    let emailChangeCodeKey: string | null = null;

    if (name !== undefined) {
      const trimmed = String(name).trim().slice(0, 50);
      updates.push(`name = $${params.length + 1}`);
      params.push(trimmed || null);
    }

    if (avatar_color !== undefined) {
      const validColors = ["violet", "blue", "emerald", "orange", "pink", "red", "yellow", "slate"];
      const color = validColors.includes(avatar_color) ? avatar_color : "violet";
      updates.push(`avatar_color = $${params.length + 1}`);
      params.push(color);
    }

    if (email !== undefined) {
      const newEmail = String(email).toLowerCase().trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail))
        return res.status(400).json({ error: "Invalid email format" });
      if (newEmail !== session.user.email) {
        // Require verification code sent to the new email address
        if (!emailChangeCode?.trim()) {
          return res.status(400).json({ error: "Please send a verification code to the new email first", code: "NEED_CODE" });
        }
        const storeKey = `email-change:${session.user.email}:${newEmail}`;
        const storedCode = await getRedisValue(storeKey);
        if (!storedCode) {
          return res.status(400).json({ error: "Verification code expired, please request a new one", code: "CODE_EXPIRED" });
        }
        if (String(emailChangeCode).trim() !== storedCode) {
          return res.status(400).json({ error: "Incorrect verification code", code: "CODE_WRONG" });
        }
        const existing = await one("SELECT id FROM users WHERE email = $1", [newEmail]);
        if (existing) return res.status(409).json({ error: "This email is already in use" });
        updates.push(`email = $${params.length + 1}`);
        params.push(newEmail);
        // Track key for deletion AFTER successful DB update
        emailChangeCodeKey = storeKey;
      }
    }

    if (updates.length === 0) return res.status(400).json({ error: "No fields to update" });

    updates.push(`updated_at = NOW()`);
    params.push(session.user.email);

    try {
      await run(
        `UPDATE users SET ${updates.join(", ")} WHERE email = $${params.length}`,
        params,
      );
    } catch (err: any) {
      console.error("[profile] PATCH error:", err.message);
      return res.status(500).json({ error: "Update failed, please try again" });
    }

    // Consume the email change code only after the DB update succeeds
    if (emailChangeCodeKey) {
      await deleteRedisValue(emailChangeCodeKey).catch(() => {});
    }

    const updatedUser = await one<{ id: string; name: string | null; email: string; avatar_color: string | null }>(
      "SELECT id, name, email, avatar_color FROM users WHERE email = $1",
      [email !== undefined ? String(email).toLowerCase().trim() : session.user.email],
    );

    return res.status(200).json({ ok: true, user: updatedUser });
  }

  return res.status(405).end();
}
