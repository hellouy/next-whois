import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { checkRateLimit } from "@/lib/rate-limit";
import { sendEmail, subscriptionConfirmHtml, getSiteLabel } from "@/lib/email";
import { localeFromCookieHeader, getEmailStrings } from "@/lib/email-strings";
import { computeLifecycle, fmtDate } from "@/lib/lifecycle";
import { one, run, isDbReady } from "@/lib/db-query";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";

type WhoisFetchResult = {
  date: string;
  eppStatus: string[];
  registrar: string | null;
  creationDate: string | null;
  nameservers: string[];
};

/**
 * Try to get the domain's real expiration date and other WHOIS fields.
 * Returns null if unavailable or if the lookup takes too long.
 */
async function fetchWhoisExpiry(domain: string): Promise<WhoisFetchResult | null> {
  try {
    const result = await Promise.race([
      lookupWhoisWithCache(domain),
      new Promise<null>(resolve => setTimeout(() => resolve(null), 8000)),
    ]);
    if (!result || !result.result) return null;
    const r = result.result;
    const expiry = r.expirationDate;
    const epp: string[] = Array.isArray(r.status)
      ? r.status.map((s: { status?: string }) => s.status ?? "").filter(Boolean)
      : [];
    if (!expiry || expiry === "Unknown") return null;
    const d = new Date(expiry);
    if (isNaN(d.getTime())) return null;

    const clean = (v: any) => (v && v !== "Unknown" && v !== "N/A" ? String(v) : null);
    const registrar = clean(r.registrar);
    const creationDate = (() => {
      const raw = clean(r.creationDate);
      if (!raw) return null;
      const cd = new Date(raw);
      return isNaN(cd.getTime()) ? null : cd.toISOString().slice(0, 10);
    })();
    const nameservers: string[] = Array.isArray(r.nameServers)
      ? r.nameServers.map((ns: any) => String(ns).toLowerCase().trim()).filter((ns: string) => ns && ns !== "unknown").slice(0, 6)
      : [];

    return { date: d.toISOString().slice(0, 10), eppStatus: epp, registrar, creationDate, nameservers };
  } catch {
    return null;
  }
}

const FREE_TIER_LIMIT = 5;

const ALL_THRESHOLDS   = [60, 30, 10, 5, 1];
const DEFAULT_THRESHOLDS = [60, 30, 1];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(ip, 5);
  if (!rl.ok) return res.status(429).json({ error: "Too many requests, please try again later" });

  const { domain, email, expirationDate, phaseAlerts, thresholds, regStatusType } = req.body;
  if (!domain || !email) return res.status(400).json({ error: "Missing required fields" });

  const flags = {
    grace:         phaseAlerts?.grace         !== false,
    redemption:    phaseAlerts?.redemption    !== false,
    pendingDelete: phaseAlerts?.pendingDelete !== false,
    dropSoon:      phaseAlerts?.dropSoon      !== false,
    dropped:       phaseAlerts?.dropped       !== false,
  };

  // Validate & deduplicate thresholds (only allow known values)
  const selectedThresholds: number[] = Array.isArray(thresholds)
    ? [...new Set(thresholds.filter((t: any) => ALL_THRESHOLDS.includes(Number(t))).map(Number))].sort((a, b) => b - a)
    : DEFAULT_THRESHOLDS;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).json({ error: "Invalid email format" });

  if (!(await isDbReady())) return res.status(500).json({ error: "Database unavailable" });

  const cleanDomain  = String(domain).toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/$/, "").replace(/\/.*$/, "");

  // Basic domain format validation
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
  if (!isValidDomain(cleanDomain)) {
    return res.status(400).json({ error: "Invalid domain format, please enter a valid domain (e.g. example.com)" });
  }

  // ── Enforce free-tier subscription limit (re-validate from DB, not JWT) ─────
  const session = await getServerSession(req, res, authOptions);
  let isMember = false;
  if (session?.user?.email) {
    const userRow = await one<{ subscription_access: boolean; subscription_expires_at: string | null }>(
      "SELECT subscription_access, subscription_expires_at FROM users WHERE email = $1",
      [session.user.email],
    ).catch(() => null);
    const expired = userRow?.subscription_expires_at
      ? new Date(userRow.subscription_expires_at) < new Date()
      : false;
    isMember = !!(userRow?.subscription_access && !expired);
  }
  if (!isMember) {
    const countRow = await one<{ count: string }>(
      "SELECT COUNT(*) as count FROM reminders WHERE email = $1 AND active = true",
      [String(email).trim()],
    ).catch(() => null);
    const activeCount = parseInt(countRow?.count ?? "0", 10);
    // Allow updating existing subscription without counting toward limit
    const existing = await one<{ id: string }>(
      "SELECT id FROM reminders WHERE domain = $1 AND email = $2",
      [cleanDomain, String(email).trim()],
    ).catch(() => null);
    if (!existing && activeCount >= FREE_TIER_LIMIT) {
      return res.status(403).json({
        error: `Free users can subscribe to at most ${FREE_TIER_LIMIT} domains. Upgrade to membership for unlimited subscriptions.`,
        code: "LIMIT_EXCEEDED",
        limit: FREE_TIER_LIMIT,
        current: activeCount,
      });
    }
  }
  const cleanEmail   = String(email).trim();
  const userExpDate  = expirationDate ? String(expirationDate) : null;
  const cancelToken  = randomBytes(20).toString("hex");
  const id           = randomBytes(8).toString("hex");

  let reminderId: string;
  let cancelTok: string;

  try {
    const existing = await one<{ id: string; cancel_token: string; active: boolean }>(
      "SELECT id, cancel_token, active FROM reminders WHERE domain = $1 AND email = $2",
      [cleanDomain, cleanEmail],
    );

    if (existing) {
      reminderId = existing.id;
      cancelTok  = existing.cancel_token || cancelToken;
      await run(
        `UPDATE reminders
         SET expiration_date = $1, active = true, cancelled_at = NULL,
             cancel_reason = NULL, cancel_token = $2, phase_flags = $3, thresholds_json = $4,
             whois_synced_at = NULL, whois_expiry_date = NULL
         WHERE id = $5`,
        [userExpDate, cancelTok, JSON.stringify(flags), JSON.stringify(selectedThresholds), reminderId],
      );
      await run("DELETE FROM reminder_logs WHERE reminder_id = $1", [reminderId]);
    } else {
      reminderId = id;
      cancelTok  = cancelToken;
      await run(
        `INSERT INTO reminders (id, domain, email, expiration_date, active, cancel_token, phase_flags, thresholds_json)
         VALUES ($1, $2, $3, $4, true, $5, $6, $7)`,
        [reminderId, cleanDomain, cleanEmail, userExpDate, cancelTok, JSON.stringify(flags), JSON.stringify(selectedThresholds)],
      );
    }
  } catch (dbErr: any) {
    console.error("[remind/submit] DB error:", dbErr);
    return res.status(500).json({ error: "Database write failed, please try again" });
  }

  // ── WHOIS sync: verify expiry date against live registry data ──────────────
  // Runs after DB save; result updates stored expiry if WHOIS provides one.
  let verifiedExpDate = userExpDate;
  let eppStatuses: string[] = [];
  let whoisRegistrar: string | null = null;
  let whoisCreationDate: string | null = null;
  let whoisNameservers: string[] = [];
  const whoisData = await fetchWhoisExpiry(cleanDomain);
  if (whoisData) {
    eppStatuses = whoisData.eppStatus;
    whoisRegistrar = whoisData.registrar;
    whoisCreationDate = whoisData.creationDate;
    whoisNameservers = whoisData.nameservers;
    const whoisDate = whoisData.date;
    // Accept WHOIS date as authoritative unless user-provided date is much newer
    // (user might have manually renewed and WHOIS not yet updated)
    const useDateFromWhois = !userExpDate || (() => {
      const ud = new Date(userExpDate).getTime();
      const wd = new Date(whoisDate).getTime();
      const diffDays = Math.abs(ud - wd) / 86_400_000;
      // If WHOIS date is within 7 days of user date or WHOIS is later → use WHOIS
      return diffDays <= 7 || wd > ud;
    })();
    if (useDateFromWhois) {
      verifiedExpDate = whoisDate;
      await run(
        `UPDATE reminders
         SET expiration_date = $1, whois_expiry_date = $2, whois_synced_at = NOW(),
             registrar = $3, creation_date = $4, nameservers_json = $5
         WHERE id = $6`,
        [whoisDate, whoisDate, whoisRegistrar, whoisCreationDate,
         whoisNameservers.length ? JSON.stringify(whoisNameservers) : null, reminderId],
      ).catch((e: Error) => console.warn("[remind/submit] WHOIS date update failed:", e.message));
    }
  }

  // Use admin-curated and AI-scraped lifecycle overrides for accurate email info
  const overrides = await loadLifecycleOverrides().catch(() => ({}));
  const lc = computeLifecycle(cleanDomain, verifiedExpDate, eppStatuses.length ? eppStatuses : undefined, overrides);
  const lifecycleInfo = lc ? {
    phase:           lc.phase,
    graceEnd:        fmtDate(lc.graceEnd),
    redemptionEnd:   fmtDate(lc.redemptionEnd),
    dropDate:        fmtDate(lc.dropDate),
    hasGrace:        lc.cfg.grace > 0,
    hasRedemption:   lc.cfg.redemption > 0,
    hasPendingDelete: lc.cfg.pendingDelete > 0,
    registry:        lc.cfg.registry,
  } : undefined;

  const siteName = await getSiteLabel().catch(() => "WHOIS");
  const isRestricted = regStatusType === "prohibited" || regStatusType === "reserved";
  const locale = localeFromCookieHeader(req.headers.cookie) || "zh";
  const s = getEmailStrings(locale);
  await sendEmail({
    to: cleanEmail,
    subject: isRestricted
      ? s.subj_sub_restricted(cleanDomain)
      : s.subj_sub_confirm(cleanDomain),
    html: subscriptionConfirmHtml({
      domain: cleanDomain,
      expirationDate: verifiedExpDate,
      cancelToken: cancelTok,
      thresholds: selectedThresholds,
      regStatusType: regStatusType ? String(regStatusType) : undefined,
      lifecycle: lifecycleInfo,
      siteName,
      locale,
    }),
  });

  return res.status(200).json({ id: reminderId, thresholds: selectedThresholds });
}
