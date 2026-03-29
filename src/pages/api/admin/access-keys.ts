import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { generateKey, generateId, invalidateKeyRequireCache } from "@/lib/access-key";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const session = await requireAdmin(req, res);
    if (!session) return;
    try {
      const keys = await many(
        "SELECT * FROM access_keys ORDER BY created_at DESC",
      );
      const setting = await one<{ value: string }>(
        "SELECT value FROM site_settings WHERE key = 'require_api_key'",
      );
      return res.json({ keys, require_api_key: setting?.value === "1" });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "POST") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const { action } = req.body as { action?: string };

    if (action === "toggle_require") {
      const { enabled } = req.body as { enabled: boolean };
      try {
        await run(
          `INSERT INTO site_settings (key, value, updated_at) VALUES ('require_api_key', $1, NOW())
           ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
          [enabled ? "1" : "0"],
        );
        invalidateKeyRequireCache();
        return res.json({ ok: true });
      } catch (err: any) {
        return res.status(500).json({ error: err.message });
      }
    }

    const { label, scope, expires_at, count } = req.body as {
      label?: string;
      scope?: string;
      expires_at?: string;
      count?: number;
    };

    const batchCount = Math.min(Math.max(1, parseInt(String(count)) || 1), 50);

    try {
      const created = [];
      for (let i = 0; i < batchCount; i++) {
        const id = generateId();
        const key = generateKey();
        await run(
          `INSERT INTO access_keys (id, key, label, scope, is_active, expires_at)
           VALUES ($1, $2, $3, $4, true, $5)`,
          [id, key, label?.trim() || null, scope || "api", expires_at || null],
        );
        const row = await one("SELECT * FROM access_keys WHERE id = $1", [id]);
        if (row) created.push(row);
      }
      return res.status(201).json({ ok: true, key: created[0], keys: created, count: created.length });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PATCH") {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const { id, is_active, label, scope } = req.body as {
      id: string;
      is_active?: boolean;
      label?: string;
      scope?: string;
    };
    try {
      if (is_active !== undefined) {
        await run("UPDATE access_keys SET is_active = $1 WHERE id = $2", [is_active, id]);
      }
      if (label !== undefined) {
        await run("UPDATE access_keys SET label = $1 WHERE id = $2", [label || null, id]);
      }
      if (scope !== undefined) {
        await run("UPDATE access_keys SET scope = $1 WHERE id = $2", [scope, id]);
      }
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const { id } = req.body as { id: string };
    try {
      await run("DELETE FROM access_keys WHERE id = $1", [id]);
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, POST, PATCH, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
