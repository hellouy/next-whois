import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, run, isDbReady } from "@/lib/db-query";
import { computeLifecycle } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";

const DEFAULT_THRESHOLDS = [60, 30, 10, 5, 1];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "请先登录" });

  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  if (req.method === "GET") {
    try {
      const rows = await many<{
        id: string; domain: string; expiration_date: string | null;
        whois_expiry_date: string | null; whois_synced_at: string | null;
        active: boolean; cancel_token: string | null; created_at: string;
        days_before: number | null;
        thresholds_json: string | null;
        phase_flags: string | null;
        registrar: string | null;
        creation_date: string | null;
        nameservers_json: string | null;
      }>(
        `SELECT id, domain, expiration_date, whois_expiry_date, whois_synced_at,
                active, cancel_token, created_at, days_before,
                thresholds_json, phase_flags, registrar, creation_date, nameservers_json
         FROM reminders WHERE email = $1 ORDER BY created_at DESC`,
        [session.user.email],
      );

      // Fetch all reminder_logs for these subscriptions in one query
      const ids = rows.map(r => r.id);
      const logs = ids.length > 0
        ? await many<{ reminder_id: string; days_before: number; sent_at: string }>(
            `SELECT reminder_id, days_before, sent_at FROM reminder_logs
             WHERE reminder_id = ANY($1::varchar[])`,
            [ids],
          )
        : [];

      // Index logs by reminder_id
      const logsByReminder: Record<string, { days_before: number; sent_at: string }[]> = {};
      for (const log of logs) {
        if (!logsByReminder[log.reminder_id]) logsByReminder[log.reminder_id] = [];
        logsByReminder[log.reminder_id].push(log);
      }

      // Compute lifecycle for each subscription using admin overrides
      const overrides = await loadLifecycleOverrides();
      const nowMs = Date.now();

      const subscriptions = rows.map((r) => {
        // Use WHOIS-verified date as authoritative source (same as dashboard.ts)
        const effectiveExpiry = r.whois_expiry_date ?? r.expiration_date;
        const lc = effectiveExpiry
          ? computeLifecycle(r.domain, effectiveExpiry, undefined, overrides)
          : null;

        // Reminder logs for this subscription
        const reminderLogs = logsByReminder[r.id] ?? [];
        const sentKeys = reminderLogs.map(l => l.days_before);
        const lastLog = reminderLogs.length > 0
          ? reminderLogs.sort((a, b) => new Date(b.sent_at).getTime() - new Date(a.sent_at).getTime())[0]
          : null;

        // Parse stored thresholds (use sub-specific config if available)
        let subThresholds = DEFAULT_THRESHOLDS;
        try {
          if (r.thresholds_json) {
            const parsed = JSON.parse(r.thresholds_json);
            if (Array.isArray(parsed) && parsed.length > 0) subThresholds = parsed.sort((a: number, b: number) => b - a);
          }
        } catch { /* keep defaults */ }

        // Parse phase flags
        let phaseFlags: Record<string, boolean> = { grace: true, redemption: true, pendingDelete: true, dropSoon: true, dropped: true };
        try {
          if (r.phase_flags) phaseFlags = { ...phaseFlags, ...JSON.parse(r.phase_flags) };
        } catch { /* keep defaults */ }

        // Parse nameservers
        let nameservers: string[] = [];
        try {
          if (r.nameservers_json) nameservers = JSON.parse(r.nameservers_json);
        } catch { /* ignore */ }

        // Compute when the next reminder threshold will fire
        const daysToExpiry = lc?.daysToExpiry ?? null;
        let nextReminderAt: string | null = null;
        let nextReminderDays: number | null = null;
        if (r.expiration_date && daysToExpiry !== null && daysToExpiry > 0) {
          for (const t of subThresholds) {
            // Threshold fires when daysToExpiry reaches t; only relevant if we haven't sent it
            if (daysToExpiry > t && !sentKeys.includes(t)) {
              const d = new Date(r.expiration_date);
              d.setDate(d.getDate() - t);
              nextReminderAt = d.toISOString();
              nextReminderDays = t;
              break;
            }
          }
        }

        return {
          id: r.id,
          domain: r.domain,
          expiration_date: effectiveExpiry,  // expose WHOIS-authoritative date to UI
          active: r.active,
          cancel_token: r.cancel_token,
          created_at: r.created_at,
          days_before: r.days_before,
          whois_synced_at: r.whois_synced_at,
          registrar: r.registrar,
          creation_date: r.creation_date,
          nameservers,
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
          thresholds: subThresholds,
          phase_flags: phaseFlags,
        };
      });

      return res.status(200).json({ subscriptions });
    } catch (err) {
      console.error("[subscriptions] GET error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "获取数据失败" });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "Missing id" });

    const { expiration_date, days_before, active, whois_sync } = req.body ?? {};

    // Full WHOIS sync: update expiry date + all WHOIS metadata atomically
    if (whois_sync && typeof whois_sync === "object") {
      const { expiry, registrar, creation_date, nameservers } = whois_sync as {
        expiry: string; registrar?: string | null; creation_date?: string | null; nameservers?: string[];
      };
      const parsed = new Date(expiry);
      if (isNaN(parsed.getTime())) return res.status(400).json({ error: "Invalid WHOIS date" });
      const dateStr = parsed.toISOString().slice(0, 10);
      const ns = Array.isArray(nameservers) && nameservers.length > 0 ? JSON.stringify(nameservers) : null;
      try {
        await run(
          `UPDATE reminders
           SET expiration_date = $1, whois_expiry_date = $2, whois_synced_at = NOW(),
               registrar = $3, creation_date = $4, nameservers_json = $5
           WHERE id = $6 AND email = $7`,
          [dateStr, dateStr, registrar ?? null, creation_date ?? null, ns, id as string, session.user.email],
        );
        return res.status(200).json({ ok: true, whois_synced_at: new Date().toISOString(), expiration_date: dateStr });
      } catch (err) {
        console.error("[subscriptions] PATCH whois_sync error:", err instanceof Error ? err.message : String(err));
        return res.status(500).json({ error: "WHOIS 同步失败" });
      }
    }

    // Manual expiry date update (user typed a date — does NOT update whois_synced_at)
    if (expiration_date !== undefined) {
      const parsed = new Date(expiration_date);
      if (isNaN(parsed.getTime())) return res.status(400).json({ error: "Invalid date" });
      try {
        await run(
          "UPDATE reminders SET expiration_date = $1 WHERE id = $2 AND email = $3",
          [parsed.toISOString().slice(0, 10), id as string, session.user.email],
        );
      } catch (err) {
        console.error("[subscriptions] PATCH expiration_date error:", err instanceof Error ? err.message : String(err));
        return res.status(500).json({ error: "更新到期日期失败" });
      }
    }

    if (days_before !== undefined) {
      const db = parseInt(days_before);
      if (isNaN(db) || db < 1 || db > 365) return res.status(400).json({ error: "提前提醒天数需在 1–365 之间" });
      try {
        await run(
          "UPDATE reminders SET days_before = $1 WHERE id = $2 AND email = $3",
          [db, id as string, session.user.email],
        );
      } catch (err) {
        console.error("[subscriptions] PATCH days_before error:", err instanceof Error ? err.message : String(err));
        return res.status(500).json({ error: "更新提醒设置失败" });
      }
    }

    if (active !== undefined) {
      const activeVal = Boolean(active);
      try {
        await run(
          "UPDATE reminders SET active = $1 WHERE id = $2 AND email = $3",
          [activeVal, id as string, session.user.email],
        );
      } catch (err) {
        console.error("[subscriptions] PATCH active error:", err instanceof Error ? err.message : String(err));
        return res.status(500).json({ error: "更新状态失败" });
      }
    }

    return res.status(200).json({ ok: true });
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "Missing id" });

    try {
      await run(
        `UPDATE reminders
         SET active = false, cancelled_at = $1, cancel_reason = 'user_dashboard'
         WHERE id = $2 AND email = $3`,
        [new Date().toISOString(), id as string, session.user.email],
      );
    } catch (err) {
      console.error("[subscriptions] DELETE error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "取消失败" });
    }
    return res.status(200).json({ ok: true });
  }

  return res.status(405).end();
}
