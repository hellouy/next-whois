/**
 * POST /api/admin/init-admin
 *
 * Emergency admin account setup / password reset.
 *
 * Security model:
 *   - SETUP_SECRET env var MUST be set. If it is absent this endpoint always
 *     returns 403, even if no admin account exists yet. This prevents
 *     open-admin hijack on misconfigured deployments.
 *   - The request body must include { secret, password } where
 *     secret === SETUP_SECRET.
 *
 * Use cases:
 *   1. First-time setup — set SETUP_SECRET in env, then call this endpoint.
 *   2. Emergency password reset — admin forgot password, SMTP unavailable.
 *
 * Body: { password: string, secret: string }
 * Returns: { ok: true } | { error: string }
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { hash } from "bcryptjs";
import { randomBytes } from "crypto";
import { one, run, isDbReady } from "@/lib/db-query";
import { getAdminEmail } from "@/lib/admin-server";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // SETUP_SECRET must always be configured. Reject unconditionally when absent
  // to prevent hijacking on misconfigured production deployments.
  const setupSecret = process.env.SETUP_SECRET;
  if (!setupSecret) {
    console.warn(
      "[init-admin] Blocked request: SETUP_SECRET environment variable is not set. " +
      "Configure it before using this endpoint."
    );
    return res.status(403).json({
      error: "此端点需要配置 SETUP_SECRET 环境变量才能使用。请在服务器设置中配置后重试。",
    });
  }

  const { password, secret } = req.body as { password?: string; secret?: string };

  if (secret !== setupSecret) {
    return res.status(403).json({ error: "SETUP_SECRET 不匹配，拒绝访问。" });
  }

  if (!password || typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "密码不能为空且至少 8 位" });
  }

  if (!(await isDbReady())) {
    return res.status(503).json({ error: "数据库暂不可用" });
  }

  const adminEmail = await getAdminEmail();

  // Check whether the admin account already exists
  const existing = await one<{ id: string }>(
    "SELECT id FROM users WHERE email = $1",
    [adminEmail],
  ).catch(() => null);

  if (existing) {
    // Admin account exists — reset password
    const passwordHash = await hash(password, 12);
    await run("UPDATE users SET password_hash = $1 WHERE email = $2", [passwordHash, adminEmail]);
    return res.json({ ok: true, action: "password_reset", email: adminEmail });
  }

  // Admin account does not exist — create it
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
