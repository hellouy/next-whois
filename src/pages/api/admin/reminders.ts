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
        conditions.push(`(domain ILIKE $${params.length} OR email ILIKE $${params.length})`);
      }
      if (filter === "active") conditions.push("active = true");
      if (filter === "inactive") conditions.push("active = false");

      const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
      const q = `SELECT id, domain, email, expiration_date, whois_expiry_date, whois_synced_at,
                        active, days_before, cancel_reason, cancelled_at, phase_flags, created_at
                 FROM reminders${where}
                 ORDER BY created_at DESC
                 LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
      params.push(limit, offset);
      const reminders = await many(q, params);

      const countParams = params.slice(0, params.length - 2);
      const countRow = await one<{ count: string }>(
        `SELECT COUNT(*) AS count FROM reminders${where}`,
        countParams.length ? countParams : undefined
      );
      const total = parseInt(countRow?.count ?? "0");

      const [activeCount, inactiveCount] = await Promise.all([
        one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = true"),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM reminders WHERE active = false"),
      ]);

      return res.json({
        reminders, total,
        activeCount: parseInt(activeCount?.count ?? "0"),
        inactiveCount: parseInt(inactiveCount?.count ?? "0"),
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
