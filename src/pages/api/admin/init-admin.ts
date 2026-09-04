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
 *   - Brute-force protection: max 5 failed attempts per IP in 15 minutes.
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
import { randomBytes, timingSafeEqual } from "crypto";
import { one, run, isDbReady } from "@/lib/db-query";
import { getAdminEmail } from "@/lib/admin-server";

// ── In-process brute-force rate limiter ───────────────────────────────────────
const RATE_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_FAILURES   = 5;
const _failures = new Map<string, { count: number; since: number }>();

function getClientIp(req: NextApiRequest): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  return req.socket?.remoteAddress ?? "unknown";
}

function checkRateLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const rec = _failures.get(ip);
  if (!rec || now - rec.since > RATE_WINDOW_MS) {
    return { allowed: true, remaining: MAX_FAILURES };
  }
  const remaining = MAX_FAILURES - rec.count;
  return { allowed: remaining > 0, remaining: Math.max(0, remaining) };
}

function recordFailure(ip: string) {
  const now = Date.now();
  const rec = _failures.get(ip);
  if (!rec || now - rec.since > RATE_WINDOW_MS) {
    _failures.set(ip, { count: 1, since: now });
  } else {
    rec.count++;
  }
}

function clearFailures(ip: string) {
  _failures.delete(ip);
}

// Constant-time secret comparison to prevent timing attacks
function safeCompare(a: string, b: string): boolean {
  try {
    const aBuf = Buffer.from(a);
    const bBuf = Buffer.from(b);
    if (aBuf.length !== bBuf.length) {
      // Still run timingSafeEqual on equal-length buffers to avoid timing leak
      timingSafeEqual(aBuf, aBuf);
      return false;
    }
    return timingSafeEqual(aBuf, bBuf);
  } catch {
    return false;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // SETUP_SECRET must always be configured
  const setupSecret = process.env.SETUP_SECRET;
  if (!setupSecret) {
    console.warn(
      "[init-admin] Blocked request: SETUP_SECRET environment variable is not set."
    );
    return res.status(403).json({
      error: "此端点需要配置 SETUP_SECRET 环境变量才能使用。请在服务器设置中配置后重试。",
    });
  }

  const ip = getClientIp(req);
  const { allowed, remaining } = checkRateLimit(ip);
  if (!allowed) {
    console.warn(`[init-admin] Rate limit exceeded for IP ${ip}`);
    return res.status(429).json({
      error: "请求过于频繁，请 15 分钟后再试。",
    });
  }

  const { password, secret } = req.body as { password?: string; secret?: string };

  if (!secret || !safeCompare(secret, setupSecret)) {
    recordFailure(ip);
    const left = MAX_FAILURES - (_failures.get(ip)?.count ?? 0);
    console.warn(`[init-admin] Secret mismatch from IP ${ip}, ${left} attempts remaining`);
    return res.status(403).json({
      error: `SETUP_SECRET 不匹配，拒绝访问。剩余尝试次数：${Math.max(0, left)}`,
    });
  }

  if (!password || typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ error: "密码不能为空且至少 8 位" });
  }

  if (password.length > 128) {
    return res.status(400).json({ error: "密码不能超过 128 位" });
  }

  if (!(await isDbReady())) {
    return res.status(503).json({ error: "数据库暂不可用" });
  }

  const adminEmail = await getAdminEmail();

  const existing = await one<{ id: string }>(
    "SELECT id FROM users WHERE email = $1",
    [adminEmail],
  ).catch(() => null);

  clearFailures(ip);

  if (existing) {
    const passwordHash = await hash(password, 12);
    await run("UPDATE users SET password_hash = $1 WHERE email = $2", [passwordHash, adminEmail]);
    console.log(`[init-admin] Password reset for admin ${adminEmail} from IP ${ip}`);
    return res.json({ ok: true, action: "password_reset", email: adminEmail });
  }

  const id           = randomBytes(8).toString("hex");
  const passwordHash = await hash(password, 12);

  try {
    await run(
      `INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, $3, $4)`,
      [id, adminEmail, passwordHash, "管理员"],
    );
    console.log(`[init-admin] Admin account created for ${adminEmail} from IP ${ip}`);
    return res.json({ ok: true, action: "created", email: adminEmail });
  } catch (err: any) {
    console.error("[init-admin]", err);
    return res.status(500).json({ error: "Initialization failed" });
  }
}
