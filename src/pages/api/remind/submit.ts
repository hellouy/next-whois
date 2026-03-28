import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { checkRateLimit } from "@/lib/rate-limit";
import { sendEmail, subscriptionConfirmHtml, getSiteLabel } from "@/lib/email";
import { computeLifecycle, fmtDate } from "@/lib/lifecycle";
import { one, run, isDbReady } from "@/lib/db-query";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";

const FREE_TIER_LIMIT = 5;

const ALL_THRESHOLDS   = [60, 30, 10, 5, 1];
const DEFAULT_THRESHOLDS = [60, 30, 1];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown").split(",")[0].trim();
  const rl = await checkRateLimit(ip, 5);
  if (!rl.ok) return res.status(429).json({ error: "请求过于频繁，请稍后再试" });

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
  if (!emailRegex.test(email)) return res.status(400).json({ error: "邮箱格式不正确" });

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
    return res.status(400).json({ error: "域名格式不正确，请输入有效的域名（如 example.com）" });
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
        error: `普通用户最多订阅 ${FREE_TIER_LIMIT} 个域名，请升级会员解锁无限订阅`,
        code: "LIMIT_EXCEEDED",
        limit: FREE_TIER_LIMIT,
        current: activeCount,
      });
    }
  }
  const cleanEmail   = String(email).trim();
  const expDate      = expirationDate ? String(expirationDate) : null;
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
             cancel_reason = NULL, cancel_token = $2, phase_flags = $3, thresholds_json = $4
         WHERE id = $5`,
        [expDate, cancelTok, JSON.stringify(flags), JSON.stringify(selectedThresholds), reminderId],
      );
      await run("DELETE FROM reminder_logs WHERE reminder_id = $1", [reminderId]);
    } else {
      reminderId = id;
      cancelTok  = cancelToken;
      await run(
        `INSERT INTO reminders (id, domain, email, expiration_date, active, cancel_token, phase_flags, thresholds_json)
         VALUES ($1, $2, $3, $4, true, $5, $6, $7)`,
        [reminderId, cleanDomain, cleanEmail, expDate, cancelTok, JSON.stringify(flags), JSON.stringify(selectedThresholds)],
      );
    }
  } catch (dbErr: any) {
    console.error("[remind/submit] DB error:", dbErr);
    return res.status(500).json({ error: "数据库写入失败，请稍后重试" });
  }

  // Use admin-curated and AI-scraped lifecycle overrides for accurate email info
  const overrides = await loadLifecycleOverrides().catch(() => ({}));
  const lc = computeLifecycle(cleanDomain, expDate, undefined, overrides);
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

  const siteName = await getSiteLabel().catch(() => "X.RW");
  const isRestricted = regStatusType === "prohibited" || regStatusType === "reserved";
  await sendEmail({
    to: cleanEmail,
    subject: isRestricted
      ? `✅ 域名状态变化订阅已设置 · ${cleanDomain}`
      : `✅ 域名订阅已设置 · ${cleanDomain}`,
    html: subscriptionConfirmHtml({
      domain: cleanDomain,
      expirationDate: expDate,
      cancelToken: cancelTok,
      thresholds: selectedThresholds,
      regStatusType: regStatusType ? String(regStatusType) : undefined,
      lifecycle: lifecycleInfo,
      siteName,
    }),
  });

  return res.status(200).json({ id: reminderId, thresholds: selectedThresholds });
}

export { sendEmail };
