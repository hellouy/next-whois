import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { randomBytes } from "crypto";

function genActivationCode(): string {
  const seg = () => randomBytes(3).toString("hex").toUpperCase();
  return `${seg()}-${seg()}-${seg()}`;
}

function parseExpiresAt(duration: string | undefined): string | null {
  if (!duration || duration === "permanent") return null;
  const now = new Date();
  const map: Record<string, number> = { "1d": 1, "7d": 7, "30d": 30, "365d": 365 };
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
    const codes = await many(
      `SELECT ac.id, ac.code, ac.plan_name, ac.duration_days, ac.grants_subscription,
              ac.balance_grant_cents, ac.used, ac.used_at, ac.note, ac.expires_at,
              ac.created_at, u.email AS used_by_email
       FROM activation_codes ac
       LEFT JOIN users u ON ac.used_by = u.id
       ORDER BY ac.created_at DESC
       LIMIT 500`
    );
    return res.json({ codes });
  }

  if (req.method === "POST") {
    const count = Math.min(Math.max(1, parseInt(req.body.count) || 1), 100);
    const planName = String(req.body.plan_name || "会员套餐").trim().slice(0, 100);
    const durationDays = req.body.duration_days ? parseInt(req.body.duration_days) : null;
    const grantsSubscription = req.body.grants_subscription !== false;
    const balanceGrantCents = Math.max(0, parseInt(req.body.balance_grant_cents) || 0);
    const note = String(req.body.note || "").trim().slice(0, 200) || null;
    const expiresAt = parseExpiresAt(req.body.expires_in);

    const adminUser = await one<{ id: string }>(
      "SELECT id FROM users WHERE email = $1",
      [(session.user as any).email]
    );
    const creatorId = adminUser?.id ?? null;

    const created = Array.from({ length: count }, () => genActivationCode());
    await Promise.all(created.map(code =>
      run(
        `INSERT INTO activation_codes
           (code, plan_name, duration_days, grants_subscription, balance_grant_cents, note, created_by, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [code, planName, durationDays, grantsSubscription, balanceGrantCents, note, creatorId, expiresAt]
      )
    ));
    return res.json({ created });
  }

  if (req.method === "DELETE") {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    const ac = await one<{ used: boolean }>("SELECT used FROM activation_codes WHERE id = $1", [id]);
    if (!ac) return res.status(404).json({ error: "激活码不存在" });
    if (ac.used) return res.status(409).json({ error: "已使用的激活码无法删除" });
    await run("DELETE FROM activation_codes WHERE id = $1", [id]);
    return res.json({ ok: true });
  }

  return res.status(405).end();
}
