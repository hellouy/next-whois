import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { checkRateLimit } from "@/lib/rate-limit";
import { one, many, run, isDbReady } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/subscriptions/bulk");

const FREE_TIER_LIMIT = 5;
const BULK_MAX = 50;
const DEFAULT_THRESHOLDS = [60, 30, 1];

const DEFAULT_FLAGS = {
  grace: true,
  redemption: true,
  pendingDelete: true,
  dropSoon: true,
  dropped: true,
};

function isValidDomain(d: string): boolean {
  if (!d || d.length > 253) return false;
  if (!d.includes(".")) return false;
  if (d.startsWith(".") || d.endsWith(".")) return false;
  if (d.includes("..")) return false;
  const labels = d.split(".");
  const tld = labels[labels.length - 1];
  if (tld.length < 2) return false;
  return labels.every(l =>
    l.length > 0 && l.length <= 63 &&
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(l)
  );
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(ip, 10);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again later" });

  const { domains, expirationDates } = req.body ?? {};

  let rawDomains: string[] = [];
  if (Array.isArray(domains)) {
    rawDomains = domains;
  } else if (typeof domains === "string") {
    rawDomains = domains.split(/[\n,;]+/);
  }
  if (rawDomains.length === 0) return res.status(400).json({ error: "No domains provided" });
  if (rawDomains.length > BULK_MAX) {
    return res.status(400).json({ error: `At most ${BULK_MAX} domains per batch` });
  }

  const email = session.user.email;
  const flags = JSON.stringify(DEFAULT_FLAGS);
  const thresholds = JSON.stringify(DEFAULT_THRESHOLDS);

  // Optional per-domain expiration dates (YYYY-MM-DD), keyed by raw index
  const dateMap: Record<number, string | null> = {};
  if (expirationDates && typeof expirationDates === "object") {
    for (const [k, v] of Object.entries(expirationDates)) {
      if (typeof v === "string") {
        const d = new Date(v);
        if (!isNaN(d.getTime())) dateMap[Number(k)] = d.toISOString().slice(0, 10);
      }
    }
  }

  const cleanDomainSet = new Map<string, string>(); // cleaned -> original
  const invalid: string[] = [];
  for (const d of rawDomains) {
    const cleaned = String(d).toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/$/, "").replace(/\/.*$/, "");
    if (!cleaned) continue;
    if (!isValidDomain(cleaned)) { invalid.push(String(d).trim()); continue; }
    cleanDomainSet.set(cleaned, String(d).trim());
  }
  const cleanDomains = [...cleanDomainSet.keys()];
  if (cleanDomains.length === 0) {
    return res.status(400).json({ error: "No valid domains found in input" });
  }

  // Reject duplicates against this user's existing (non-cancelled) subscriptions
  const existingRows = await many<{ domain: string }>(
    `SELECT domain FROM reminders WHERE email = $1 AND active = true`,
    [email],
  );
  const existingSet = new Set(existingRows.map(r => r.domain));
  const toAdd = cleanDomains.filter(d => !existingSet.has(d));
  const skipped = cleanDomains.length - toAdd.length;

  // Enforce free-tier limit (count toward total active after adding this batch)
  const userRow = await one<{ subscription_access: boolean; subscription_expires_at: string | null }>(
    "SELECT subscription_access, subscription_expires_at FROM users WHERE email = $1",
    [email],
  ).catch(() => null);
  const expired = userRow?.subscription_expires_at
    ? new Date(userRow.subscription_expires_at) < new Date()
    : false;
  const isMember = !!(userRow?.subscription_access && !expired);

  let activeCount = existingRows.length;
  if (!isMember && activeCount + toAdd.length > FREE_TIER_LIMIT) {
    const headroom = Math.max(0, FREE_TIER_LIMIT - activeCount);
    if (headroom === 0) {
      return res.status(403).json({
        error: `Free users can subscribe to at most ${FREE_TIER_LIMIT} domains. Upgrade to membership for unlimited subscriptions.`,
        code: "LIMIT_EXCEEDED",
        limit: FREE_TIER_LIMIT,
        current: activeCount,
      });
    }
    const trimmed = toAdd.slice(0, headroom);
    // Record which domains were dropped for limit reasons
    const overLimit = toAdd.length - headroom;
    const created: { domain: string; id: string; skipped: boolean }[] = [];
    try {
      for (const d of trimmed) {
        const id = randomBytes(8).toString("hex");
        const cancelToken = randomBytes(20).toString("hex");
        await run(
          `INSERT INTO reminders (id, domain, email, expiration_date, active, cancel_token, phase_flags, thresholds_json)
           VALUES ($1, $2, $3, $4, true, $5, $6, $7)`,
          [id, d, email, dateMap[cleanDomains.indexOf(d)] ?? null, cancelToken, flags, thresholds],
        );
        created.push({ domain: d, id, skipped: false });
      }
      return res.status(201).json({
        created,
        skipped,
        overLimit,
        limit: FREE_TIER_LIMIT,
        current: activeCount + created.length,
        truncated: overLimit > 0,
      });
    } catch (err) {
      logger.error("[bulk] INSERT (truncated) error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "Batch import failed" });
    }
  }

  const created: { domain: string; id: string; skipped: boolean }[] = [];
  const failed: string[] = [];
  try {
    for (const d of toAdd) {
      try {
        const id = randomBytes(8).toString("hex");
        const cancelToken = randomBytes(20).toString("hex");
        await run(
          `INSERT INTO reminders (id, domain, email, expiration_date, active, cancel_token, phase_flags, thresholds_json)
           VALUES ($1, $2, $3, $4, true, $5, $6, $7)`,
          [id, d, email, dateMap[cleanDomains.indexOf(d)] ?? null, cancelToken, flags, thresholds],
        );
        created.push({ domain: d, id, skipped: false });
      } catch (rowErr) {
        logger.error("[bulk] row error:", rowErr instanceof Error ? rowErr.message : String(rowErr));
        failed.push(d);
      }
    }
  } catch (err) {
    logger.error("[bulk] error:", err instanceof Error ? err.message : String(err));
    return res.status(500).json({ error: "Batch import failed" });
  }

  return res.status(201).json({ created, skipped, overLimit: 0, failed });
}
