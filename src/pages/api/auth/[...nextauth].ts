import NextAuth, { type NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { compare } from "bcryptjs";
import { one } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { getSetting } from "@/lib/server/site-settings-server";

// ── Brute-force tracking: failed attempts per email (in-process, single server) ─
const failedAttempts = new Map<string, { count: number; resetAt: number }>();
const MAX_FAILED_ATTEMPTS = 10;
const FAILED_WINDOW_MS    = 15 * 60 * 1000; // 15 minutes
const LOCKOUT_MS          = 30 * 60 * 1000; // 30-minute lockout after exceeding threshold

function isLockedOut(key: string): boolean {
  const entry = failedAttempts.get(key);
  if (!entry) return false;
  if (Date.now() > entry.resetAt) {
    failedAttempts.delete(key);
    return false;
  }
  return entry.count >= MAX_FAILED_ATTEMPTS;
}

function recordFailedAttempt(key: string) {
  const entry = failedAttempts.get(key);
  const now = Date.now();
  if (!entry || now > entry.resetAt) {
    failedAttempts.set(key, { count: 1, resetAt: now + FAILED_WINDOW_MS });
  } else {
    entry.count += 1;
    // Extend lockout window on each additional failure once threshold reached
    if (entry.count >= MAX_FAILED_ATTEMPTS) {
      entry.resetAt = now + LOCKOUT_MS;
    }
  }
}

function clearFailedAttempts(key: string) {
  failedAttempts.delete(key);
}

// Housekeeping — purge expired entries every 10 minutes
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    failedAttempts.forEach((entry, key) => {
      if (now > entry.resetAt) failedAttempts.delete(key);
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

        // ── Rate-limit by email (per-account brute-force) ──────────────────
        const emailKey = `login:email:${email}`;
        if (isLockedOut(emailKey)) return null;

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
          recordFailedAttempt(emailKey);
          return null;
        }
        if (user.disabled) return null;

        const valid = await compare(credentials.password, user.password_hash);
        if (!valid) {
          recordFailedAttempt(emailKey);
          return null;
        }

        // Successful login — clear any brute-force counters
        clearFailedAttempts(emailKey);

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
