import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { randomBytes } from "crypto";

function genId() { return randomBytes(8).toString("hex"); }

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  if (req.method === "GET") {
    const plans = await many(
      `SELECT id, name, description, price::float AS price, currency,
              duration_days, is_recurring, grants_subscription,
              COALESCE(balance_grant_cents, 0) AS balance_grant_cents,
              is_active, sort_order, created_at
       FROM payment_plans ORDER BY sort_order ASC, price ASC`
    );
    return res.json({ plans });
  }

  if (req.method === "POST") {
    const { name, description, price, currency, duration_days, is_recurring, grants_subscription, sort_order, balance_grant_cents } = req.body;
    if (!name?.trim() || price === undefined || price === null)
      return res.status(400).json({ error: "名称和价格为必填项" });

    const id = genId();
    await run(
      `INSERT INTO payment_plans (id, name, description, price, currency, duration_days, is_recurring, grants_subscription, is_active, sort_order, balance_grant_cents)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,$10)`,
      [id, name.trim(), description?.trim() || null, parseFloat(price),
       currency || "CNY", duration_days || null, !!is_recurring,
       grants_subscription !== false, parseInt(sort_order) || 0,
       parseInt(balance_grant_cents) || 0]
    );
    const plan = await one(`SELECT * FROM payment_plans WHERE id=$1`, [id]);
    return res.status(201).json({ ok: true, plan });
  }

  if (req.method === "PUT") {
    const { id, name, description, price, currency, duration_days, is_recurring, grants_subscription, is_active, sort_order, balance_grant_cents } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    await run(
      `UPDATE payment_plans SET name=$2, description=$3, price=$4, currency=$5, duration_days=$6,
              is_recurring=$7, grants_subscription=$8, is_active=$9, sort_order=$10,
              balance_grant_cents=$11
       WHERE id=$1`,
      [id, name?.trim(), description?.trim() || null, parseFloat(price),
       currency || "CNY", duration_days || null, !!is_recurring,
       grants_subscription !== false, !!is_active, parseInt(sort_order) || 0,
       parseInt(balance_grant_cents) || 0]
    );
    const plan = await one(`SELECT * FROM payment_plans WHERE id=$1`, [id]);
    return res.json({ ok: true, plan });
  }

  if (req.method === "DELETE") {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    const used = await one<{ count: string }>(
      `SELECT COUNT(*) AS count FROM payment_orders WHERE plan_id=$1 AND status='paid'`, [id]
    );
    if (parseInt(used?.count || "0") > 0)
      return res.status(400).json({ error: "该套餐已有付费订单，不可删除（可下线）" });
    await run(`DELETE FROM payment_plans WHERE id=$1`, [id]);
    return res.json({ ok: true });
  }

  res.setHeader("Allow", "GET,POST,PUT,DELETE");
  return res.status(405).end();
}
