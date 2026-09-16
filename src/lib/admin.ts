import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { timingSafeEqual } from "crypto";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { getAdminEmail, isAdminEmail } from "@/lib/admin-server";
import { checkRateLimit } from "@/lib/rate-limit";

export { ADMIN_EMAIL, getAdminEmail };

/**
 * Timing-safe comparison of a Bearer token against an expected secret.
 * Prevents timing side-channel attacks on CRON_SECRET verification.
 */
export function verifyCronSecret(
  authHeader: string | undefined,
  secret: string,
): boolean {
  if (!authHeader || !secret) return false;
  const expected = `Bearer ${secret}`;
  const a = Buffer.from(authHeader);
  const b = Buffer.from(expected);
  if (a.length !== b.length) {
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Timing-safe comparison of two secret strings (e.g. extracted bearer token
 * or legacy header value against the expected CRON_SECRET).
 */
export function verifySecretTimingSafe(
  provided: string | undefined,
  secret: string,
): boolean {
  if (!provided || !secret) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(secret);
  if (a.length !== b.length) {
    timingSafeEqual(b, b);
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Synchronous admin check — compares against the compile-time ADMIN_EMAIL
 * constant. Use `isAdminEmail()` (async) for the DB-backed check.
 */
export function isAdmin(email?: string | null): boolean {
  if (!email) return false;
  return email.toLowerCase().trim() === ADMIN_EMAIL.toLowerCase().trim();
}

export async function requireAdmin(
  req: NextApiRequest,
  res: NextApiResponse,
): Promise<any> {
  // Rate-limit admin API access by IP — limits scanning/enumeration attempts
  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`admin:api:${ip}`, 60, 60 * 1000);
  if (!rl.ok) {
    res.status(429).json({ error: "Too many requests" });
    return null;
  }

  const session = await getServerSession(req, res, authOptions);
  const email = (session?.user as any)?.email;
  if (!(await isAdminEmail(email))) {
    res.status(403).json({ error: "Forbidden" });
    return null;
  }
  return session;
}
