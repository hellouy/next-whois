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
        active: boolean; cancel_token: string | null; created_at: string;
        days_before: number | null;
        thresholds_json: string | null;
        phase_flags: string | null;
        whois_synced_at: string | null;
        registrar: string | null;
        creation_date: string | null;
        nameservers_json: string | null;
      }>(
        `SELECT id, domain, expiration_date, active, cancel_token, created_at, days_before,
                thresholds_json, phase_flags, whois_synced_at, registrar, creation_date, nameservers_json
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
        const lc = r.expiration_date
          ? computeLifecycle(r.domain, r.expiration_date, undefined, overrides)
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
          ...r,
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
          nameservers,
        };
      });

      return res.status(200).json({ subscriptions });
    } catch (err: any) {
      console.error("[subscriptions] GET error:", err.message);
      return res.status(500).json({ error: "获取数据失败" });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "Missing id" });

    const { expiration_date, days_before, active } = req.body ?? {};

    if (expiration_date !== undefined) {
      const parsed = new Date(expiration_date);
      if (isNaN(parsed.getTime())) return res.status(400).json({ error: "Invalid date" });
      try {
        await run(
          "UPDATE reminders SET expiration_date = $1 WHERE id = $2 AND email = $3",
          [parsed.toISOString(), id as string, session.user.email],
        );
      } catch (err: any) {
        console.error("[subscriptions] PATCH expiration_date error:", err.message);
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
      } catch (err: any) {
        console.error("[subscriptions] PATCH days_before error:", err.message);
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
      } catch (err: any) {
        console.error("[subscriptions] PATCH active error:", err.message);
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
    } catch (err: any) {
      console.error("[subscriptions] DELETE error:", err.message);
      return res.status(500).json({ error: "取消失败" });
    }
    return res.status(200).json({ ok: true });
  }

  return res.status(405).end();
}
