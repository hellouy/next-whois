import NextAuth, { type NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { compare } from "bcryptjs";
import { one } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { getSetting } from "@/lib/server/site-settings-server";
import {
  isRedisAvailable,
  incrRedisValue,
  setRedisValue,
  deleteRedisValue,
  getRedisValue,
} from "@/lib/server/redis";

// ── Brute-force tracking: Redis-backed (survives serverless cold starts) ────────
// Falls back to in-process Map when Redis is unavailable.
const MAX_FAILED_ATTEMPTS = 10;
const FAILED_WINDOW_MS    = 15 * 60 * 1000; // 15 minutes
const LOCKOUT_MS          = 30 * 60 * 1000; // 30-minute lockout after exceeding threshold

const _localBf = new Map<string, { count: number; resetAt: number }>();

async function isLockedOut(key: string): Promise<boolean> {
  if (isRedisAvailable()) {
    try {
      const locked = await getRedisValue(`bf:lock:${key}`);
      if (locked) return true;
    } catch {}
  }
  const entry = _localBf.get(key);
  if (!entry) return false;
  if (Date.now() > entry.resetAt) { _localBf.delete(key); return false; }
  return entry.count >= MAX_FAILED_ATTEMPTS;
}

async function recordFailedAttempt(key: string) {
  if (isRedisAvailable()) {
    try {
      const windowSecs  = Math.ceil(FAILED_WINDOW_MS / 1000);
      const lockoutSecs = Math.ceil(LOCKOUT_MS / 1000);
      const count = await incrRedisValue(`bf:count:${key}`, windowSecs);
      if (count !== null && count >= MAX_FAILED_ATTEMPTS) {
        await setRedisValue(`bf:lock:${key}`, "1", lockoutSecs);
      }
      return;
    } catch {}
  }
  const now = Date.now();
  const entry = _localBf.get(key);
  if (!entry || now > entry.resetAt) {
    _localBf.set(key, { count: 1, resetAt: now + FAILED_WINDOW_MS });
  } else {
    entry.count += 1;
    if (entry.count >= MAX_FAILED_ATTEMPTS) entry.resetAt = now + LOCKOUT_MS;
  }
}

async function clearFailedAttempts(key: string) {
  if (isRedisAvailable()) {
    try {
      await Promise.all([
        deleteRedisValue(`bf:count:${key}`),
        deleteRedisValue(`bf:lock:${key}`),
      ]);
    } catch {}
  }
  _localBf.delete(key);
}

// Housekeeping — purge expired in-process fallback entries every 10 minutes
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    _localBf.forEach((entry, key) => {
      if (now > entry.resetAt) _localBf.delete(key);
    });
  }, 10 * 60 * 1000).unref?.();
}

export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt" },
  secret: process.env.NEXTAUTH_SECRET,
  pages: {
    signIn: "/login",
    error: "/login",
  },
  providers: [
    CredentialsProvider({
      name: "Email",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        rememberMe: { label: "Remember Me", type: "text" },
      },
      async authorize(credentials, req) {
        if (!credentials?.email || !credentials?.password) return null;

        // If disable_login is enabled, block all credential logins
        const disableLogin = await getSetting("disable_login");
        if (disableLogin === "1") return null;

        const email = credentials.email.toLowerCase().trim();
        const ip = String(
          (req as any)?.headers?.["x-forwarded-for"] ||
          (req as any)?.socket?.remoteAddress ||
          "unknown"
        ).split(",")[0].trim();

        // ── Rate-limit by IP (global) ───────────────────────────────────────
        const ipRl = await checkRateLimit(`login:ip:${ip}`, 20, 10 * 60 * 1000);
        if (!ipRl.ok) return null; // silently reject — caller sees "CredentialsSignin"

        // ── Rate-limit by email (per-account brute-force, Redis-backed) ───────
        const emailKey = `login:email:${email}`;
        if (await isLockedOut(emailKey)) return null;

        const user = await one<{
          id: string;
          email: string;
          name: string | null;
          password_hash: string;
          disabled: boolean;
          subscription_access: boolean;
          subscription_expires_at: string | null;
        }>(
          "SELECT id, email, name, password_hash, disabled, subscription_access, subscription_expires_at FROM users WHERE email = $1",
          [email],
        );

        if (!user) {
          await recordFailedAttempt(emailKey);
          return null;
        }
        if (user.disabled) return null;

        const valid = await compare(credentials.password, user.password_hash);
        if (!valid) {
          await recordFailedAttempt(emailKey);
          return null;
        }

        // Successful login — clear any brute-force counters
        await clearFailedAttempts(emailKey);

        // Respect subscription expiry at login time
        const expired = user.subscription_expires_at
          ? new Date(user.subscription_expires_at) < new Date()
          : false;
        const subscriptionAccess = user.subscription_access && !expired;

        return {
          id: user.id,
          email: user.email,
          name: user.name ?? null,
          subscriptionAccess,
          rememberMe: credentials.rememberMe !== "0",
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger, session }) {
      // Initial sign-in: populate token from user object
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.subscriptionAccess = (user as any).subscriptionAccess ?? false;
        const rememberMe = (user as any).rememberMe !== false;
        if (!rememberMe) {
          // Session-only: expire in 24h
          token.exp = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
        }
        // Default NextAuth maxAge (30 days) applies when rememberMe=true
      }

      if (trigger === "update") {
        // Allow updating display name from client
        if (session?.name !== undefined) token.name = session.name;

        // SECURITY: Never trust client-provided subscriptionAccess.
        // Use the `refreshSubscription` signal to re-read from DB.
        if (session?.refreshSubscription === true && token.email) {
          try {
            const row = await one<{
              subscription_access: boolean;
              subscription_expires_at: string | null;
            }>(
              "SELECT subscription_access, subscription_expires_at FROM users WHERE email = $1",
              [token.email as string],
            );
            const expired = row?.subscription_expires_at
              ? new Date(row.subscription_expires_at) < new Date()
              : false;
            token.subscriptionAccess = !!(row?.subscription_access && !expired);
          } catch {
            // Keep existing token value on DB error — fail safe
          }
        }
      }

      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        (session.user as any).id = token.id as string;
        session.user.email = token.email as string;
        session.user.name = token.name as string | null;
        (session.user as any).subscriptionAccess = (token.subscriptionAccess as boolean) ?? false;
      }
      return session;
    },
  },
};

export default NextAuth(authOptions);
