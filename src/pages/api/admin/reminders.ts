import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { sendEmail, reminderHtml, getSiteLabel } from "@/lib/email";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    try {
      const search = typeof req.query.search === "string" ? req.query.search : "";
      const filter = typeof req.query.filter === "string" ? req.query.filter : "all";
      const limit = Math.min(parseInt(String(req.query.limit || "50")), 200);
      const offset = parseInt(String(req.query.offset || "0"));

      const conditions: string[] = [];
      const params: any[] = [];

      if (search) {
        params.push(`%${search}%`);
        conditions.push(`(r.domain ILIKE $${params.length} OR r.email ILIKE $${params.length})`);
      }
      if (filter === "active") conditions.push("r.active = true");
      if (filter === "inactive") conditions.push("r.active = false");
      if (filter === "review") {
        // Reminders whose TLD data quality is uncertain: no record, pending, failed, warn_defaults, or no_data
        conditions.push(`(tr.tld IS NULL OR tr.needs_admin_review = true OR tr.scrape_status IN ('pending','failed','warn_defaults','no_data'))`);
      }

      const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
      const q = `SELECT r.id, r.domain, r.email, r.expiration_date, r.whois_expiry_date, r.whois_synced_at,
                        r.active, r.days_before, r.cancel_reason, r.cancelled_at, r.phase_flags, r.created_at,
                        tr.confidence             AS tld_confidence,
                        tr.scrape_status          AS tld_scrape_status,
                        tr.needs_admin_review     AS tld_needs_review,
                        tr.manually_edited        AS tld_manually_edited,
                        tr.scrape_attempts        AS tld_scrape_attempts
                 FROM reminders r
                 LEFT JOIN tld_rules tr ON tr.tld = LOWER(REVERSE(SPLIT_PART(REVERSE(r.domain), '.', 1)))${where}
                 ORDER BY r.created_at DESC
                 LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
      params.push(limit, offset);
      const reminders = await many(q, params);

      const countParams = params.slice(0, params.length - 2);
      const countRow = await one<{ count: string }>(
        `SELECT COUNT(*) AS count FROM reminders r LEFT JOIN tld_rules tr ON tr.tld = LOWER(REVERSE(SPLIT_PART(REVERSE(r.domain), '.', 1)))${where}`,
        countParams.length ? countParams : undefined
      );
      const total = parseInt(countRow?.count ?? "0");

      const [activeCount, inactiveCount, reviewCount] = await Promise.all([
        one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = true"),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = false"),
        one<{ count: string }>(
          `SELECT COUNT(*) AS count FROM reminders r
           LEFT JOIN tld_rules tr ON tr.tld = LOWER(REVERSE(SPLIT_PART(REVERSE(r.domain), '.', 1)))
           WHERE tr.tld IS NULL OR tr.needs_admin_review = true
              OR tr.scrape_status IN ('pending','failed','warn_defaults','no_data')`
        ),
      ]);

      return res.json({
        reminders, total,
        activeCount:   parseInt(activeCount?.count   ?? "0"),
        inactiveCount: parseInt(inactiveCount?.count ?? "0"),
        reviewCount:   parseInt(reviewCount?.count   ?? "0"),
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "POST") {
    const { id, action } = req.query;
    if (action === "send-email") {
      if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });

      const resendKey = process.env.RESEND_API_KEY;
      if (!resendKey) return res.status(503).json({ error: "RESEND_API_KEY 未配置，无法发送邮件" });

      try {
        const reminder = await one<{
          id: string; domain: string; email: string;
          expiration_date: string | null; cancel_token: string | null; active: boolean;
        }>(
          "SELECT id, domain, email, expiration_date, cancel_token, active FROM reminders WHERE id = $1",
          [id]
        );
        if (!reminder) return res.status(404).json({ error: "未找到该订阅记录" });

        const siteName = await getSiteLabel().catch(() => "X.RW");
        const daysLeft = reminder.expiration_date
          ? Math.ceil((new Date(reminder.expiration_date).getTime() - Date.now()) / 86_400_000)
          : 0;

        await sendEmail({
          to: reminder.email,
          subject: `[手动提醒] ${reminder.domain} 域名到期提醒 · ${siteName}`,
          html: reminderHtml({
            domain: reminder.domain,
            expirationDate: reminder.expiration_date,
            daysLeft,
            cancelToken: reminder.cancel_token ?? "manual",
            siteName,
          }),
        });

        return res.json({ ok: true, to: reminder.email });
      } catch (err: any) {
        return res.status(500).json({ error: err.message || "发送失败" });
      }
    }
    return res.status(400).json({ error: "Unknown action" });
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });

    const body = req.body as {
      active?: boolean;
      domain?: string;
      email?: string;
      expiration_date?: string | null;
      days_before?: number | null;
    };

    try {
      const setClauses: string[] = [];
      const params: any[] = [];

      if (body.active === false) {
        setClauses.push(`active = false`, `cancelled_at = NOW()`, `cancel_reason = '管理员停用'`);
      } else if (body.active === true) {
        setClauses.push(`active = true`, `cancelled_at = NULL`, `cancel_reason = NULL`);
      }

      if (body.domain !== undefined) {
        params.push(body.domain.trim().toLowerCase());
        setClauses.push(`domain = $${params.length}`);
      }
      if (body.email !== undefined) {
        params.push(body.email.trim().toLowerCase());
        setClauses.push(`email = $${params.length}`);
      }
      if (body.expiration_date !== undefined) {
        params.push(body.expiration_date ? new Date(body.expiration_date).toISOString() : null);
        setClauses.push(`expiration_date = $${params.length}`);
      }
      if (body.days_before !== undefined) {
        params.push(body.days_before ?? null);
        setClauses.push(`days_before = $${params.length}`);
      }

      if (setClauses.length === 0) return res.status(400).json({ error: "Nothing to update" });

      params.push(id);
      await run(
        `UPDATE reminders SET ${setClauses.join(", ")} WHERE id = $${params.length}`,
        params
      );
      const updated = await one("SELECT * FROM reminders WHERE id = $1", [id]);
      return res.json({ ok: true, reminder: updated });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    try {
      await run("DELETE FROM reminders WHERE id = $1", [id]);
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, POST, PATCH, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
