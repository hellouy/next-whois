/**
 * GET /api/user/dashboard
 * Combined endpoint: subscriptions + stamps in one round-trip.
 *
 * Optimizations vs. two separate endpoints:
 *  • Single serverless function cold-start
 *  • Single session validation
 *  • reminders + stamps + lifecycle_overrides all fetched in parallel
 *  • Then reminder_logs fetched once (depends on reminder IDs)
 *  • Cache-Control: private so browser serves stale instantly & refreshes behind the scenes
 */
import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { computeLifecycle, nextReminderFiring } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/dashboard");

const THRESHOLDS = [60, 30, 10, 5, 1];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const email = session.user.email;

  try {
    const userId = (session.user as any)?.id ?? null;

    // ── Phase 1: all DB queries in parallel, reminders+logs merged into one round-trip ──
    // The reminders query uses LEFT JOIN + JSON_AGG to embed reminder_logs inline,
    // eliminating Phase 2's serial wait (~400 ms saved per request).
    const [rows, stampsRows, overrides, userRow, searchStats, recentSearchRows] = await Promise.all([
      many<{
        id: string; domain: string; expiration_date: string | null;
        whois_expiry_date: string | null; whois_synced_at: string | null;
        active: boolean; cancel_token: string | null; created_at: string;
        days_before: number | null; thresholds_json: string | null;
        phase_flags: string | null; registrar: string | null;
        creation_date: string | null; nameservers_json: string | null;
        logs_json: string;
      }>(
        `SELECT r.id, r.domain, r.expiration_date, r.whois_expiry_date, r.whois_synced_at,
                r.active, r.cancel_token, r.created_at, r.days_before,
                r.thresholds_json, r.phase_flags, r.registrar, r.creation_date, r.nameservers_json,
                COALESCE(
                  JSON_AGG(
                    JSON_BUILD_OBJECT(
                      'reminder_id', rl.reminder_id,
                      'days_before', rl.days_before,
                      'sent_at',     rl.sent_at
                    ) ORDER BY rl.days_before
                  ) FILTER (WHERE rl.reminder_id IS NOT NULL),
                  '[]'
                ) AS logs_json
         FROM reminders r
         LEFT JOIN reminder_logs rl ON rl.reminder_id = r.id
         WHERE r.email = $1
         GROUP BY r.id, r.domain, r.expiration_date, r.whois_expiry_date, r.whois_synced_at,
                  r.active, r.cancel_token, r.created_at, r.days_before,
                  r.thresholds_json, r.phase_flags, r.registrar, r.creation_date, r.nameservers_json
         ORDER BY r.created_at DESC`,
        [email],
      ),
      many<{
        id: string; domain: string; tag_name: string; tag_style: string;
        link: string; description: string; nickname: string;
        verified: boolean; verified_at: string | null; created_at: string;
      }>(
        `SELECT id, domain, tag_name, tag_style, link, description, nickname,
                verified, verified_at, created_at
         FROM stamps WHERE email = $1 ORDER BY created_at DESC`,
        [email],
      ),
      loadLifecycleOverrides(),
      // DB-authoritative access flag — heals stale JWTs without re-login
      one<{ subscription_access: boolean; subscription_expires_at: string | null; balance_cents: number; membership_plan: string | null }>(
        "SELECT subscription_access, subscription_expires_at, balance_cents, membership_plan FROM users WHERE email = $1",
        [email],
      ),
      // Search history stats for the user
      userId ? one<{
        total: string; today: string; this_week: string;
        available: string; high_value: string;
        top_type: string | null;
      }>(
        `SELECT
           COUNT(*)::text                                                                                       AS total,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 day')::text                                AS today,
           COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days')::text                               AS this_week,
           COUNT(*) FILTER (WHERE reg_status = 'unregistered')::text                                           AS available,
           COUNT(*) FILTER (WHERE value_tier = 'high')::text                                                   AS high_value,
           (SELECT query_type FROM search_history WHERE user_id = $1
            GROUP BY query_type ORDER BY COUNT(*) DESC LIMIT 1)                                                AS top_type
         FROM search_history WHERE user_id = $1`,
        [userId],
      ).catch(() => null) : Promise.resolve(null),
      // Recent searches for user dashboard
      userId ? many<{ query: string; query_type: string; reg_status: string | null; created_at: string }>(
        `SELECT query, query_type, reg_status, created_at
         FROM search_history WHERE user_id = $1
         ORDER BY created_at DESC LIMIT 5`,
        [userId],
      ).catch(() => []) : Promise.resolve([]),
    ]);

    // ── Phase 2 (eliminated): reminder_logs now embedded via logs_json ────────

    // ── Phase 3: pure JS processing ─────────────────────────────────────────
    // Build logsByReminder from the inline JSON_AGG column instead of a second DB query.
    const logsByReminder: Record<string, { days_before: number; sent_at: string }[]> = {};
    for (const row of rows) {
      let parsed: { reminder_id: string; days_before: number; sent_at: string }[] = [];
      try { parsed = typeof row.logs_json === 'string' ? JSON.parse(row.logs_json) : (row.logs_json as any) ?? []; } catch { parsed = []; }
      logsByReminder[row.id] = parsed.map(l => ({ days_before: l.days_before, sent_at: l.sent_at }));
    }

    const nowMs = Date.now();
    const subscriptions = rows.map((r) => {
      // whois_expiry_date is the WHOIS-verified expiry (authoritative when present),
      // falling back to the user-provided expiration_date
      const effectiveExpiry = r.whois_expiry_date ?? r.expiration_date;
      const lc = effectiveExpiry
        ? computeLifecycle(r.domain, effectiveExpiry, undefined, overrides)
        : null;

      const reminderLogs = logsByReminder[r.id] ?? [];
      const sentKeys = reminderLogs.map(l => l.days_before);
      const lastLog = reminderLogs.length > 0
        ? reminderLogs.sort((a, b) => new Date(b.sent_at).getTime() - new Date(a.sent_at).getTime())[0]
        : null;

      // Parse JSON fields
      let thresholds: number[] = [];
      try { if (r.thresholds_json) thresholds = JSON.parse(r.thresholds_json); } catch { /* ignore */ }
      let phaseFlags: Record<string, boolean> = {};
      try { if (r.phase_flags) phaseFlags = JSON.parse(r.phase_flags); } catch { /* ignore */ }
      let nameservers: string[] = [];
      try { if (r.nameservers_json) nameservers = JSON.parse(r.nameservers_json); } catch { /* ignore */ }

      const daysToExpiry = lc?.daysToExpiry ?? null;
      const thresholdsToUse = thresholds.length > 0 ? thresholds : THRESHOLDS;
      let nextReminderAt: string | null = null;
      let nextReminderDays: number | null = null;
      if (effectiveExpiry && daysToExpiry !== null && daysToExpiry > 0) {
        // Interval semantics — mirrors the process.ts engine exactly
        const firing = nextReminderFiring(thresholdsToUse, daysToExpiry, new Date(effectiveExpiry), sentKeys);
        if (firing) {
          nextReminderAt = firing.at.toISOString();
          nextReminderDays = firing.days;
        }
      }

      return {
        id: r.id,
        domain: r.domain,
        // Always expose the effective (WHOIS-authoritative) expiry to the UI
        expiration_date: effectiveExpiry,
        active: r.active,
        cancel_token: r.cancel_token,
        created_at: r.created_at,
        days_before: r.days_before,
        whois_synced_at: r.whois_synced_at,
        registrar: r.registrar,
        creation_date: r.creation_date,
        nameservers,
        thresholds: thresholdsToUse,
        phase_flags: phaseFlags,
        drop_date: lc ? lc.dropDate.toISOString() : null,
        grace_end: lc ? lc.graceEnd.toISOString() : null,
        redemption_end: lc ? lc.redemptionEnd.toISOString() : null,
        phase: lc?.phase ?? null,
        days_to_expiry: lc?.daysToExpiry ?? null,
        days_to_drop: lc ? Math.ceil((lc.dropDate.getTime() - nowMs) / 86_400_000) : null,
        tld_confidence: lc?.cfg.confidence ?? null,
        sent_keys: sentKeys,
        last_reminded_at: lastLog?.sent_at ?? null,
        next_reminder_at: nextReminderAt,
        next_reminder_days: nextReminderDays,
      };
    });

    // DB-authoritative access flag — always trust DB over stale JWT
    // Auto-revoke if a time-limited subscription has expired
    let subscriptionAccess = userRow?.subscription_access ?? false;
    let subscriptionExpiresAt = userRow?.subscription_expires_at ?? null;
    if (subscriptionAccess && subscriptionExpiresAt && new Date(subscriptionExpiresAt) < new Date()) {
      // Subscription has expired; revoke in DB (fire-and-forget, don't block response)
      run(
        "UPDATE users SET subscription_access = FALSE, subscription_expires_at = NULL, updated_at = NOW() WHERE email = $1",
        [email]
      ).catch(e => logger.error("[dashboard] expiry revoke error:", e));
      subscriptionAccess = false;
      subscriptionExpiresAt = null;
    }

    // User-specific; allow browser to serve stale while quietly revalidating
    res.setHeader("Cache-Control", "private, max-age=0, stale-while-revalidate=60");
    return res.status(200).json({
      subscriptions,
      stamps: stampsRows,
      subscriptionAccess,
      subscriptionExpiresAt,
      balanceCents: userRow?.balance_cents ?? 0,
      membershipPlan: userRow?.membership_plan ?? null,
      searchStats: searchStats ? {
        total: parseInt(searchStats.total ?? "0"),
        today: parseInt(searchStats.today ?? "0"),
        thisWeek: parseInt(searchStats.this_week ?? "0"),
        available: parseInt(searchStats.available ?? "0"),
        highValue: parseInt(searchStats.high_value ?? "0"),
        topType: searchStats.top_type,
      } : null,
      recentSearches: recentSearchRows ?? [],
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error("[dashboard] GET error:", msg);
    return res.status(500).json({ error: "Failed to retrieve data" });
  }
}
