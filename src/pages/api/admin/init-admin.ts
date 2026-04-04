/**
 * POST /api/admin/init-admin
 *
 * Emergency admin account setup / password reset.
 *
 * Security model:
 *   - If SETUP_SECRET env var is set, the request body must include
 *     { secret, password } where secret === SETUP_SECRET.
 *   - If SETUP_SECRET is NOT set AND no admin account exists, this endpoint
 *     allows first-run bootstrap (one-time creation only). A server-side
 *     warning is logged to alert operators of the open state.
 *   - Once an admin account exists AND no SETUP_SECRET is configured,
 *     this endpoint returns 403 to prevent abuse.
 *
 * Use cases:
 *   1. First-time setup — admin never registered, no account in DB.
 *   2. Emergency password reset — admin forgot password, SMTP unavailable.
 *
 * Body: { password: string, secret?: string }
 * Returns: { ok: true } | { error: string }
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { randomBytes } from "crypto";
import { one, run, isDbReady } from "@/lib/db-query";
import { getAdminEmail } from "@/lib/admin-server";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { password, secret } = req.body as { password?: string; secret?: string };

  if (!password || typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "密码不能为空且至少 8 位" });
  }

  if (!(await isDbReady())) {
    return res.status(503).json({ error: "数据库暂不可用" });
  }

  const setupSecret = process.env.SETUP_SECRET || "";
  const adminEmail  = await getAdminEmail();

  // Check whether the admin account already exists
  const existing = await one<{ id: string }>(
    "SELECT id FROM users WHERE email = $1",
    [adminEmail],
  ).catch(() => null);

  if (existing) {
    // Admin account already exists — require SETUP_SECRET to reset password
    if (!setupSecret) {
      return res.status(403).json({
        error: "管理员账号已存在。如需重置密码，请在服务器环境变量中配置 SETUP_SECRET 并在请求中提供。",
      });
    }
    if (secret !== setupSecret) {
      return res.status(403).json({ error: "SETUP_SECRET 不匹配，拒绝访问。" });
    }
    // Reset password
    const passwordHash = await hash(password, 12);
    await run("UPDATE users SET password_hash = $1 WHERE email = $2", [passwordHash, adminEmail]);
    return res.json({ ok: true, action: "password_reset", email: adminEmail });
  }

  // Admin account does not exist — allow creation (first-run or with SETUP_SECRET)
  if (setupSecret && secret !== setupSecret) {
    return res.status(403).json({ error: "SETUP_SECRET 不匹配，拒绝访问。" });
  }

  // Warn operators when the endpoint is used without SETUP_SECRET protection.
  // This is intentional for first-run bootstrap, but should be secured afterward.
  if (!setupSecret) {
    console.warn(
      "[init-admin] WARNING: Creating admin account without SETUP_SECRET protection. " +
      "Set the SETUP_SECRET environment variable to secure this endpoint after setup."
    );
  }

  const id           = randomBytes(8).toString("hex");
  const passwordHash = await hash(password, 12);

  try {
    await run(
      `INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, $3, $4)`,
      [id, adminEmail, passwordHash, "管理员"],
    );
    return res.json({ ok: true, action: "created", email: adminEmail });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
}
