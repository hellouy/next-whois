import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { randomBytes } from "crypto";

function genCode(): string {
  const seg = () => randomBytes(3).toString("hex").toUpperCase();
  return `${seg()}-${seg()}-${seg()}`;
}

function parseExpiresAt(duration: string | undefined): string | null {
  if (!duration || duration === "permanent") return null;
  const now = new Date();
  const map: Record<string, number> = {
    "1d":  1,
    "7d":  7,
    "30d": 30,
    "365d": 365,
  };
  const days = map[duration];
  if (!days) return null;
  now.setDate(now.getDate() + days);
  return now.toISOString();
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库不可用" });

  if (req.method === "GET") {
    const data = await many<{
      id: string; code: string; description: string | null;
      is_active: boolean; max_uses: number; use_count: number;
      created_at: string; expires_at: string | null;
    }>("SELECT id, code, description, is_active, max_uses, use_count, created_at, expires_at FROM invite_codes ORDER BY created_at DESC");
    return res.json({ codes: data });
  }

  if (req.method === "POST") {
    const count = Math.min(Math.max(1, parseInt(req.body.count) || 1), 50);
    const max_uses = Math.max(1, parseInt(req.body.max_uses) || 1);
    const description = String(req.body.description || "").trim().slice(0, 100) || null;
    const expires_at = parseExpiresAt(req.body.expires_in);
    const adminUser = await one<{ id: string }>("SELECT id FROM users WHERE email = $1", [(session.user as any).email]);
    const creatorId = adminUser?.id ?? null;
    const records = Array.from({ length: count }, () => ({
      id: randomBytes(8).toString("hex"),
      code: genCode(),
    }));
    await Promise.all(records.map(({ id, code }) =>
      run(
        "INSERT INTO invite_codes (id, code, description, max_uses, created_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
        [id, code, description, max_uses, creatorId, expires_at]
      )
    ));
    return res.json({ created: records.map(r => r.code) });
  }

  if (req.method === "PATCH") {
    const { id, is_active } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    await run("UPDATE invite_codes SET is_active = $1 WHERE id = $2", [Boolean(is_active), id]);
    return res.json({ ok: true });
  }

  if (req.method === "DELETE") {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    await run("DELETE FROM invite_codes WHERE id = $1", [id]);
    return res.json({ ok: true });
  }

  return res.status(405).end();
}
