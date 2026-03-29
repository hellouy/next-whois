import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { ADMIN_EMAIL } from "@/lib/admin-shared";

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
        conditions.push(`(u.email ILIKE $${params.length} OR u.name ILIKE $${params.length})`);
      }
      if (filter === "active") conditions.push("u.disabled = false");
      if (filter === "disabled") conditions.push("u.disabled = true");
      if (filter === "subscribed") conditions.push("u.subscription_access = true");
      if (filter === "verified") conditions.push("u.email_verified = true");

      const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
      const q = `
        SELECT
          u.id, u.email, u.name, u.created_at, u.updated_at,
          u.disabled, u.admin_notes, u.subscription_access, u.subscription_expires_at, u.email_verified, u.balance_cents,
          (SELECT COUNT(*) FROM search_history sh WHERE sh.user_id = u.id)::int AS search_count,
          (SELECT COUNT(*) FROM stamps s WHERE s.email = u.email)::int AS stamp_count,
          (SELECT COUNT(*) FROM reminders r WHERE r.email = u.email AND r.active = true)::int AS reminder_count
        FROM users u${where}
        ORDER BY u.created_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;
      params.push(limit, offset);
      const countParams = params.slice(0, params.length - 2);

      const [users, countRow, disabledRow, activeRow, subscribedRow, verifiedRow] = await Promise.all([
        many(q, params),
        one<{ count: string }>(
          `SELECT COUNT(*) AS count FROM users u${where}`,
          countParams.length ? countParams : undefined
        ),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE disabled = true"),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE disabled = false"),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE subscription_access = true"),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM users WHERE email_verified = true"),
      ]);
      const total = parseInt(countRow?.count ?? "0");

      return res.json({
        users,
        total,
        disabled: parseInt(disabledRow?.count ?? "0"),
        activeCount: parseInt(activeRow?.count ?? "0"),
        subscribedCount: parseInt(subscribedRow?.count ?? "0"),
        verifiedCount: parseInt(verifiedRow?.count ?? "0"),
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });

    const { name, email, admin_notes, disabled, subscription_access, email_verified, subscription_expires_at, balance_adjustment, balance_note } = req.body as {
      name?: string;
      email?: string;
      admin_notes?: string;
      disabled?: boolean;
      subscription_access?: boolean;
      email_verified?: boolean;
      subscription_expires_at?: string | null;
      balance_adjustment?: number;
      balance_note?: string;
    };

    try {
      const existing = await one<{ email: string }>("SELECT email FROM users WHERE id = $1", [id]);
      if (!existing) return res.status(404).json({ error: "用户不存在" });
      if (existing.email === ADMIN_EMAIL) return res.status(403).json({ error: "无法修改创始人账户" });

      const updates: string[] = [];
      const params: any[] = [];

      if (name !== undefined) { params.push(name || null); updates.push(`name = $${params.length}`); }
      if (email !== undefined) { params.push(email.toLowerCase().trim()); updates.push(`email = $${params.length}`); }
      if (admin_notes !== undefined) { params.push(admin_notes || null); updates.push(`admin_notes = $${params.length}`); }
      if (disabled !== undefined) { params.push(Boolean(disabled)); updates.push(`disabled = $${params.length}`); }
      if (subscription_access !== undefined) {
        params.push(Boolean(subscription_access));
        updates.push(`subscription_access = $${params.length}`);
        // Clear expiry whenever subscription is explicitly revoked
        if (!subscription_access) {
          updates.push(`subscription_expires_at = NULL`);
        }
      }
      // Allow admin to set a specific subscription expiry date (or null for lifetime)
      if (subscription_expires_at !== undefined) {
        if (subscription_expires_at === null || subscription_expires_at === "") {
          updates.push(`subscription_expires_at = NULL`);
        } else {
          const parsedDate = new Date(subscription_expires_at);
          if (isNaN(parsedDate.getTime())) {
            return res.status(400).json({ error: "到期日期格式不正确" });
          }
          params.push(parsedDate.toISOString());
          updates.push(`subscription_expires_at = $${params.length}`);
        }
      }
      if (email_verified !== undefined) { params.push(Boolean(email_verified)); updates.push(`email_verified = $${params.length}`); }

      if (updates.length === 0 && balance_adjustment === undefined) return res.status(400).json({ error: "无可更新字段" });

      if (updates.length > 0) {
        updates.push(`updated_at = NOW()`);
        params.push(id);
        await run(`UPDATE users SET ${updates.join(", ")} WHERE id = $${params.length}`, params);
      }

      // Handle balance adjustment separately to also create a transaction record
      if (balance_adjustment !== undefined && balance_adjustment !== 0) {
        const adjCents = Math.round(Number(balance_adjustment));
        if (!isNaN(adjCents)) {
          await run(
            "UPDATE users SET balance_cents = GREATEST(0, balance_cents + $1), updated_at = NOW() WHERE id = $2",
            [adjCents, id]
          );
          await run(
            `INSERT INTO balance_transactions (user_id, amount_cents, type, description)
             VALUES ($1, $2, $3, $4)`,
            [id, Math.abs(adjCents), adjCents > 0 ? "recharge" : "deduct", balance_note?.trim() || (adjCents > 0 ? "管理员充值" : "管理员扣款")]
          );
        }
      }

      const updated = await one(
        `SELECT id, email, name, created_at, updated_at, disabled, admin_notes,
                subscription_access, subscription_expires_at, email_verified, balance_cents,
                (SELECT COUNT(*) FROM search_history sh WHERE sh.user_id = u.id)::int AS search_count,
                (SELECT COUNT(*) FROM stamps s WHERE s.email = u.email)::int AS stamp_count,
                (SELECT COUNT(*) FROM reminders r WHERE r.email = u.email AND r.active = true)::int AS reminder_count
         FROM users u WHERE id = $1`,
        [id]
      );
      return res.json({ ok: true, user: updated });
    } catch (err: any) {
      if (err.code === "23505") return res.status(409).json({ error: "该邮箱已被其他账户使用" });
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    try {
      const existing = await one<{ email: string }>("SELECT email FROM users WHERE id = $1", [id]);
      if (existing?.email === ADMIN_EMAIL) return res.status(403).json({ error: "无法删除创始人账户" });
      await run("DELETE FROM users WHERE id = $1", [id]);
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, PATCH, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
