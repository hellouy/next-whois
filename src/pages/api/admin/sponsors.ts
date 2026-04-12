import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { randomBytes } from "crypto";

function genId() {
  return randomBytes(8).toString("hex");
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const { visible_only } = req.query;

    // Public endpoint: only visible sponsors, no auth required
    if (visible_only === "1") {
      try {
        const rows = await many<{
          id: string;
          name: string;
          avatar_url: string | null;
          amount: string | null;
          currency: string;
          message: string | null;
          sponsor_date: string | null;
          is_anonymous: boolean;
          is_visible: boolean;
          platform: string | null;
          created_at: string;
        }>(`SELECT * FROM sponsors WHERE is_visible = true ORDER BY sponsor_date DESC NULLS LAST, created_at DESC`);
        res.setHeader("Cache-Control", "public, max-age=60, stale-while-revalidate=120");
        return res.json({ sponsors: rows });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }

    // Admin-only: full list including hidden entries
    const session = await requireAdmin(req, res);
    if (!session) return;

    try {
      const rows = await many<{
        id: string;
        name: string;
        avatar_url: string | null;
        amount: string | null;
        currency: string;
        message: string | null;
        sponsor_date: string | null;
        is_anonymous: boolean;
        is_visible: boolean;
        platform: string | null;
        created_at: string;
      }>(`SELECT * FROM sponsors ORDER BY sponsor_date DESC NULLS LAST, created_at DESC`);
      res.setHeader("Cache-Control", "private, no-store");
      return res.json({ sponsors: rows });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "POST") {
    const { name, avatar_url, amount, currency, message, sponsor_date, is_anonymous, is_visible, platform } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "赞助者姓名不能为空" });
    try {
      const id = genId();
      await run(
        `INSERT INTO sponsors (id, name, avatar_url, amount, currency, message, sponsor_date, is_anonymous, is_visible, platform)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [id, name.trim(), avatar_url || null, amount ? parseFloat(amount) : null,
         currency || "CNY", message || null, sponsor_date || null,
         !!is_anonymous, is_visible !== false, platform || null]
      );
      const row = await one<{ id: string }>(`SELECT * FROM sponsors WHERE id = $1`, [id]);
      return res.json({ ok: true, sponsor: row });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PUT") {
    const { id, name, avatar_url, amount, currency, message, sponsor_date, is_anonymous, is_visible, platform } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    if (!name?.trim()) return res.status(400).json({ error: "赞助者姓名不能为空" });
    try {
      await run(
        `UPDATE sponsors SET name=$2, avatar_url=$3, amount=$4, currency=$5, message=$6,
         sponsor_date=$7, is_anonymous=$8, is_visible=$9, platform=$10
         WHERE id=$1`,
        [id, name.trim(), avatar_url || null, amount ? parseFloat(amount) : null,
         currency || "CNY", message || null, sponsor_date || null,
         !!is_anonymous, is_visible !== false, platform || null]
      );
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    try {
      await run(`DELETE FROM sponsors WHERE id=$1`, [id]);
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, POST, PUT, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
