import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import {
  sendEmail, reminderHtml, phaseEventHtml,
  dropApproachingHtml, domainDroppedHtml, getSiteLabel,
} from "@/lib/email";
import {
  computeLifecycle,
  fmtDate,
  GRACE_KEY,
  REDEMPTION_KEY,
  PENDING_KEY,
} from "@/lib/lifecycle";
import { many, run, isDbReady } from "@/lib/db-query";
import { getEmailStrings } from "@/lib/email-strings";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { isAdminEmail } from "@/lib/admin-server";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";

/** Stale thresholds: refresh WHOIS more frequently as expiry approaches */
const WHOIS_STALE_CRITICAL_DAYS = 1;   // within 7 days of expiry → refresh every day
const WHOIS_STALE_URGENT_DAYS = 2;     // within 30 days of expiry → refresh every 2 days
const WHOIS_STALE_NORMAL_DAYS = 5;     // within 90 days of expiry → refresh every 5 days
/** Only sync WHOIS for reminders within this many days of expiry */
const WHOIS_SYNC_WINDOW_DAYS = 90;
/** Max WHOIS lookups per cron run to avoid rate limits */
const WHOIS_SYNC_LIMIT = 20;

/**
 * Refresh WHOIS expiry date for reminders that are approaching expiry and have
 * stale WHOIS data. Updates DB in-place and returns a map of reminderId → new date.
 */
async function refreshStaleWhoisDates(
  reminders: Array<{ id: string; domain: string; expiration_date: string | null; whois_synced_at: string | null }>,
): Promise<Map<string, { date: string; eppStatus: string[]; registrar: string | null; creationDate: string | null; nameservers: string[] }>> {
  const now = Date.now();
  const msPerDay = 86_400_000;

  // Pick candidates: within sync window, stale or never synced
  // Stale threshold varies by urgency: critical (<7d) = 1d, urgent (<30d) = 2d, normal (<90d) = 5d
  const candidates = reminders.filter((r) => {
    if (!r.expiration_date) return false;
    const expMs = new Date(r.expiration_date).getTime();
    const daysToExpiry = (expMs - now) / msPerDay;
    if (daysToExpiry < -30 || daysToExpiry > WHOIS_SYNC_WINDOW_DAYS) return false;
    const lastSync = r.whois_synced_at ? new Date(r.whois_synced_at).getTime() : 0;
    const staleDays = daysToExpiry <= 7
      ? WHOIS_STALE_CRITICAL_DAYS
      : daysToExpiry <= 30
        ? WHOIS_STALE_URGENT_DAYS
        : WHOIS_STALE_NORMAL_DAYS;
    return now - lastSync > staleDays * msPerDay;
  }).slice(0, WHOIS_SYNC_LIMIT);

  const updated = new Map<string, { date: string; eppStatus: string[]; registrar: string | null; creationDate: string | null; nameservers: string[] }>();
  await Promise.all(candidates.map(async (r) => {
    try {
      const res = await Promise.race([
        lookupWhoisWithCache(r.domain),
        new Promise<null>(resolve => setTimeout(() => resolve(null), 8000)),
      ]);
      if (!res?.result) return;
      const rv = res.result;
      const expiry = rv.expirationDate;
      const epp: string[] = Array.isArray(rv.status)
        ? rv.status.map((s: { status?: string }) => s.status ?? "").filter(Boolean)
        : [];
      if (!expiry || expiry === "Unknown") return;
      const d = new Date(expiry);
      if (isNaN(d.getTime())) return;
      const dateStr = d.toISOString().slice(0, 10);

      const clean = (v: any) => (v && v !== "Unknown" && v !== "N/A" ? String(v) : null);
      const registrar = clean(rv.registrar);
      const creationDate = (() => {
        const raw = clean(rv.creationDate);
        if (!raw) return null;
        const cd = new Date(raw);
        return isNaN(cd.getTime()) ? null : cd.toISOString().slice(0, 10);
      })();
      const nameservers: string[] = Array.isArray(rv.nameServers)
        ? rv.nameServers.map((ns: any) => String(ns).toLowerCase().trim()).filter((ns: string) => ns && ns !== "unknown").slice(0, 6)
        : [];

      await run(
        `UPDATE reminders
         SET expiration_date = $1, whois_expiry_date = $2, whois_synced_at = NOW(),
             registrar = $3, creation_date = $4, nameservers_json = $5
         WHERE id = $6`,
        [dateStr, dateStr, registrar, creationDate, nameservers.length ? JSON.stringify(nameservers) : null, r.id],
      );
      updated.set(r.id, { date: dateStr, eppStatus: epp, registrar, creationDate, nameservers });
      console.log(`[process] WHOIS refreshed ${r.domain} → ${dateStr}`);
    } catch (err) {
      console.warn(`[process] WHOIS refresh failed for ${r.domain}:`, err instanceof Error ? err.message : String(err));
    }
  }));
  return updated;
}

const DEFAULT_THRESHOLDS = [60, 30, 10, 5, 1];
const DROP_SOON_KEY = -4;   // 7 days before drop date
const DROPPED_KEY   = -5;   // domain just became available

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") return res.status(405).end();

  // Auth: accept CRON_SECRET (from Vercel cron) OR an admin session (from the dashboard UI)
  const cronSecret = process.env.CRON_SECRET;
  let authed = false;
  if (cronSecret) {
    const authHeader = req.headers.authorization;
    const legacyHeader = req.headers["x-cron-secret"] as string | undefined;
    // Note: query string secret removed for security (secrets can leak into server logs)
    const bearerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    const provided = bearerToken || legacyHeader;
    if (provided === cronSecret) authed = true;
  }
  if (!authed) {
    // Fall back to admin session auth (always required when cron secret not matched)
    const session = await getServerSession(req, res, authOptions);
    if (!session?.user?.email || !(await isAdminEmail(session.user.email))) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  if (!(await isDbReady())) return res.status(500).json({ error: "Database unavailable" });

  const siteName = await getSiteLabel().catch(() => "X.RW");

  try {
    // Load admin-configured TLD lifecycle overrides once for the whole batch
    const overrides = await loadLifecycleOverrides();

    const remindersRaw = await many<{
      id: string; domain: string; email: string;
      expiration_date: string | null; cancel_token: string; phase_flags: string | null;
      thresholds_json: string | null; whois_synced_at: string | null; whois_expiry_date: string | null;
      registrar: string | null; creation_date: string | null; nameservers_json: string | null;
    }>(
      `SELECT id, domain, email, expiration_date, cancel_token, phase_flags, thresholds_json,
              whois_synced_at, whois_expiry_date, registrar, creation_date, nameservers_json
       FROM reminders WHERE active = true AND expiration_date IS NOT NULL`,
    );

    // Batch-fetch user locales so each email can be sent in the user's language
    const uniqueEmails = [...new Set(remindersRaw.map((r) => r.email))];
    const userLocaleRows = uniqueEmails.length > 0
      ? await many<{ email: string; locale: string }>(
          `SELECT email, locale FROM users WHERE email = ANY($1::text[])`,
          [uniqueEmails],
        ).catch(() => [] as { email: string; locale: string }[])
      : [];
    const localeMap = new Map<string, string>(userLocaleRows.map((r) => [r.email, r.locale]));

    // Refresh WHOIS data for near-expiry domains with stale sync dates (non-blocking batch)
    const whoisRefreshed = await refreshStaleWhoisDates(remindersRaw).catch((e) => {
      console.warn("[process] WHOIS batch refresh error:", e?.message ?? e);
      return new Map<string, { date: string; eppStatus: string[]; registrar: string | null; creationDate: string | null; nameservers: string[] }>();
    });

    const reminderIds = remindersRaw.map((r) => r.id);
    const logsRaw = reminderIds.length > 0
      ? await many<{ reminder_id: string; days_before: number }>(
          `SELECT reminder_id, days_before FROM reminder_logs WHERE reminder_id = ANY($1::varchar[])`,
          [reminderIds],
        )
      : [];

    const logsByReminder: Record<string, number[]> = {};
    for (const log of logsRaw) {
      if (!logsByReminder[log.reminder_id]) logsByReminder[log.reminder_id] = [];
      logsByReminder[log.reminder_id].push(log.days_before);
    }

    const reminders = remindersRaw.map((r) => {
      const fresh = whoisRefreshed.get(r.id);
      let nameservers: string[] = [];
      try { if (r.nameservers_json) nameservers = JSON.parse(r.nameservers_json); } catch { /* ignore */ }
      return {
        ...r,
        // Prefer WHOIS-refreshed data from this run, then stored fields, then user-entered
        effective_expiry: fresh?.date ?? r.whois_expiry_date ?? r.expiration_date,
        epp_status:       fresh?.eppStatus ?? [],
        registrar:        fresh?.registrar ?? r.registrar ?? null,
        creation_date:    fresh?.creationDate ?? r.creation_date ?? null,
        nameservers:      fresh?.nameservers ?? nameservers,
        sent_keys:        logsByReminder[r.id] ?? [],
      };
    });

    const results = { sent: 0, expired: 0, skipped: 0, whois_refreshed: whoisRefreshed.size };

    for (const reminder of reminders) {
      try {
        const lc = computeLifecycle(
          reminder.domain,
          reminder.effective_expiry,
          reminder.epp_status.length ? reminder.epp_status : undefined,
          overrides,
        );
        if (!lc) { results.skipped++; continue; }

        const now = new Date();
        const { phase, expiry, graceEnd, redemptionEnd, dropDate, cfg } = lc;
        const msPerDay = 86_400_000;
        const daysToExpiry = Math.ceil((expiry.getTime() - now.getTime()) / msPerDay);
        const daysToDropDate = Math.ceil((dropDate.getTime() - now.getTime()) / msPerDay);
        const sentKeys: number[] = reminder.sent_keys;

        // Parse phase flags and thresholds early (needed by all branches below)
        let phaseFlags = { grace: true, redemption: true, pendingDelete: true, dropSoon: true, dropped: true };
        try {
          if (reminder.phase_flags) phaseFlags = { ...phaseFlags, ...JSON.parse(reminder.phase_flags) };
        } catch { /* keep defaults */ }

        let thresholds = DEFAULT_THRESHOLDS;
        try {
          if (reminder.thresholds_json) {
            const parsed = JSON.parse(reminder.thresholds_json);
            if (Array.isArray(parsed) && parsed.length > 0) thresholds = parsed;
          }
        } catch { /* keep defaults */ }

        const upsertLog = async (daysKey: number) => {
          const logId = randomBytes(8).toString("hex");
          await run(
            `INSERT INTO reminder_logs (id, reminder_id, days_before)
             VALUES ($1, $2, $3)
             ON CONFLICT (reminder_id, days_before) DO NOTHING`,
            [logId, reminder.id, daysKey],
          );
        };

        // ── Domain dropped: send notification then deactivate ─────────────────
        const locale = localeMap.get(reminder.email) || "zh";
        const ls = getEmailStrings(locale);
        if (phase === "dropped") {
          if (phaseFlags.dropped && !sentKeys.includes(DROPPED_KEY)) {
            await sendEmail({
              to: reminder.email,
              subject: ls.subj_dropped(reminder.domain),
              html: domainDroppedHtml({
                domain: reminder.domain,
                expirationDate: reminder.expiration_date,
                cancelToken: reminder.cancel_token,
                siteName,
                locale,
              }),
            });
            await upsertLog(DROPPED_KEY);
            results.sent++;
          }
          // Deactivate after notifying
          await run(
            `UPDATE reminders
             SET active = false, cancelled_at = $1, cancel_reason = 'domain_dropped_or_expired'
             WHERE id = $2`,
            [now.toISOString(), reminder.id],
          );
          results.expired++;
          continue;
        }

        // ── Past full recovery window (safety fallback) ───────────────────────
        const totalPostExpiry = cfg.grace + cfg.redemption + cfg.pendingDelete;
        const pastRecovery = (now.getTime() - expiry.getTime()) / msPerDay > (totalPostExpiry + 30);
        if (pastRecovery) {
          await run(
            `UPDATE reminders
             SET active = false, cancelled_at = $1, cancel_reason = 'domain_dropped_or_expired'
             WHERE id = $2`,
            [now.toISOString(), reminder.id],
          );
          results.expired++;
          continue;
        }

        let didSend = false;

        // ── Grace phase notification ──────────────────────────────────────────
        if (phaseFlags.grace && phase === "grace" && cfg.grace > 0 && !sentKeys.includes(GRACE_KEY)) {
          await sendEmail({
            to: reminder.email,
            subject: ls.subj_grace(reminder.domain),
            html: phaseEventHtml({
              domain: reminder.domain,
              phase: "grace",
              expirationDate: reminder.expiration_date,
              graceEnd: fmtDate(graceEnd),
              cancelToken: reminder.cancel_token,
              registrar: reminder.registrar,
              creationDate: reminder.creation_date,
              siteName,
              locale,
            }),
          });
          await upsertLog(GRACE_KEY);
          results.sent++;
          didSend = true;
        }

        // ── Redemption phase notification ─────────────────────────────────────
        if (!didSend && phaseFlags.redemption && phase === "redemption" && cfg.redemption > 0 && !sentKeys.includes(REDEMPTION_KEY)) {
          await sendEmail({
            to: reminder.email,
            subject: ls.subj_redemption(reminder.domain),
            html: phaseEventHtml({
              domain: reminder.domain,
              phase: "redemption",
              expirationDate: reminder.expiration_date,
              redemptionEnd: fmtDate(redemptionEnd),
              dropDate: fmtDate(dropDate),
              cancelToken: reminder.cancel_token,
              registrar: reminder.registrar,
              creationDate: reminder.creation_date,
              siteName,
              locale,
            }),
          });
          await upsertLog(REDEMPTION_KEY);
          results.sent++;
          didSend = true;
        }

        // ── Pending-delete phase notification ─────────────────────────────────
        if (!didSend && phaseFlags.pendingDelete && phase === "pendingDelete" && cfg.pendingDelete > 0 && !sentKeys.includes(PENDING_KEY)) {
          await sendEmail({
            to: reminder.email,
            subject: ls.subj_pending(reminder.domain),
            html: phaseEventHtml({
              domain: reminder.domain,
              phase: "pendingDelete",
              expirationDate: reminder.expiration_date,
              dropDate: fmtDate(dropDate),
              cancelToken: reminder.cancel_token,
              registrar: reminder.registrar,
              creationDate: reminder.creation_date,
              siteName,
              locale,
            }),
          });
          await upsertLog(PENDING_KEY);
          results.sent++;
          didSend = true;
        }

        // ── Drop approaching: 7 days before drop date ─────────────────────────
        if (!didSend && phaseFlags.dropSoon && phase === "pendingDelete" && daysToDropDate <= 7 && !sentKeys.includes(DROP_SOON_KEY)) {
          await sendEmail({
            to: reminder.email,
            subject: ls.subj_drop_soon(reminder.domain, daysToDropDate),
            html: dropApproachingHtml({
              domain: reminder.domain,
              expirationDate: reminder.expiration_date,
              dropDate: fmtDate(dropDate),
              daysToDropDate,
              cancelToken: reminder.cancel_token,
              siteName,
              locale,
            }),
          });
          await upsertLog(DROP_SOON_KEY);
          results.sent++;
          didSend = true;
        }

        // ── Active phase: days-to-expiry thresholds ───────────────────────────
        if (!didSend && phase === "active") {
          for (const threshold of thresholds) {
            if (daysToExpiry <= threshold && !sentKeys.includes(threshold)) {
              const subject =
                daysToExpiry <= 5  ? ls.subj_reminder_urgent(reminder.domain, daysToExpiry) :
                daysToExpiry <= 10 ? ls.subj_reminder_warn(reminder.domain, daysToExpiry)   :
                                     ls.subj_reminder(reminder.domain, daysToExpiry);

              await sendEmail({
                to: reminder.email,
                subject,
                html: reminderHtml({
                  domain: reminder.domain,
                  expirationDate: reminder.expiration_date,
                  daysLeft: daysToExpiry,
                  cancelToken: reminder.cancel_token,
                  registrar: reminder.registrar,
                  creationDate: reminder.creation_date,
                  nameservers: reminder.nameservers,
                  siteName,
                  locale,
                }),
              });
              await upsertLog(threshold);
              results.sent++;
              break;
            }
          }
        }
      } catch (reminderErr: any) {
        console.error("[remind/process] Error processing reminder", reminder.id, reminderErr.message);
        results.skipped++;
      }
    }

    return res.status(200).json({ ok: true, processed: reminders.length, ...results });
  } catch (err: any) {
    console.error("[remind/process] Fatal error:", err);
    return res.status(500).json({ error: "处理失败，请稍后重试" });
  }
}
