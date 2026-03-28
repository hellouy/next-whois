import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { requireAdmin } from "@/lib/admin";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { invalidateLifecycleOverridesCache } from "@/lib/server/lifecycle-overrides";

let _tableReady = false;
async function ensureTable() {
  if (_tableReady) return;
  await run(`
    CREATE TABLE IF NOT EXISTS tld_lifecycle_feedback (
      id                       VARCHAR(16) PRIMARY KEY,
      tld                      VARCHAR(20) NOT NULL,
      current_grace            INTEGER,
      current_redemption       INTEGER,
      current_pending_delete   INTEGER,
      suggested_grace          INTEGER NOT NULL,
      suggested_redemption     INTEGER NOT NULL,
      suggested_pending_delete INTEGER NOT NULL,
      source_url               TEXT,
      notes                    TEXT,
      submitter_email          VARCHAR(255),
      status                   VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at              TIMESTAMPTZ,
      reviewed_by              VARCHAR(255)
    )
  `);
  _tableReady = true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const admin = await requireAdmin(req, res);
  if (!admin) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  await ensureTable();

  if (req.method === "GET") {
    const status = (req.query.status as string) || "pending";
    try {
      const where = status === "all" ? "" : "WHERE status = $1";
      const params = status === "all" ? [] : [status];
      const rows = await many(
        `SELECT id, tld, current_grace, current_redemption, current_pending_delete,
                suggested_grace, suggested_redemption, suggested_pending_delete,
                source_url, notes, submitter_email, status, created_at, reviewed_at, reviewed_by
         FROM tld_lifecycle_feedback ${where}
         ORDER BY created_at DESC`,
        params,
      );
      return res.status(200).json({ items: rows, total: rows.length });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    const { action } = req.body;
    if (!id || !action) return res.status(400).json({ error: "id 和 action 必须提供" });

    try {
      const item = await one<{
        id: string; tld: string;
        suggested_grace: number; suggested_redemption: number; suggested_pending_delete: number;
        source_url: string | null; notes: string | null;
      }>(
        `SELECT * FROM tld_lifecycle_feedback WHERE id = $1`,
        [id as string],
      );
      if (!item) return res.status(404).json({ error: "记录不存在" });

      if (action === "approve") {
        const ovId = randomBytes(8).toString("hex");
        const noteStr = [item.notes, item.source_url ? `来源：${item.source_url}` : null]
          .filter(Boolean).join(" | ") || null;

        await run(
          `INSERT INTO tld_lifecycle_overrides (id, tld, grace, redemption, pending_delete, registry, notes)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (tld) DO UPDATE
             SET grace = EXCLUDED.grace,
                 redemption = EXCLUDED.redemption,
                 pending_delete = EXCLUDED.pending_delete,
                 notes = EXCLUDED.notes,
                 updated_at = NOW()`,
          [ovId, item.tld, item.suggested_grace, item.suggested_redemption,
           item.suggested_pending_delete, null, noteStr],
        );
        invalidateLifecycleOverridesCache();

        await run(
          `UPDATE tld_lifecycle_feedback
           SET status = 'approved', reviewed_at = NOW(), reviewed_by = $1
           WHERE id = $2`,
          [admin.email, id as string],
        );
        return res.status(200).json({ ok: true, action: "approved" });
      }

      if (action === "reject") {
        await run(
          `UPDATE tld_lifecycle_feedback
           SET status = 'rejected', reviewed_at = NOW(), reviewed_by = $1
           WHERE id = $2`,
          [admin.email, id as string],
        );
        return res.status(200).json({ ok: true, action: "rejected" });
      }

      return res.status(400).json({ error: "action 必须为 approve 或 reject" });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "id 必须提供" });
    try {
      await run(`DELETE FROM tld_lifecycle_feedback WHERE id = $1`, [id as string]);
      return res.status(200).json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).end();
}
