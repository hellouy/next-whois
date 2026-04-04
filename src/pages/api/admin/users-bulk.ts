import type { NextApiRequest, NextApiResponse } from "next";
import { run } from "@/lib/db-query";
import { requireAdmin, ADMIN_EMAIL } from "@/lib/admin";

type Action = "disable" | "enable" | "grant_subscription" | "revoke_subscription" | "delete";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { ids, action } = req.body as { ids: string[]; action: Action };

  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: "ids 不能为空" });
  }
  if (!["disable", "enable", "grant_subscription", "revoke_subscription", "delete"].includes(action)) {
    return res.status(400).json({ error: "无效操作" });
  }
  if (ids.length > 200) {
    return res.status(400).json({ error: "单次最多处理 200 条" });
  }

  const placeholders = ids.map((_, i) => `$${i + 1}`).join(",");

  try {
    let affected = 0;
    switch (action) {
      case "disable":
        affected = await run(
          `UPDATE users SET disabled = true WHERE id IN (${placeholders}) AND email != $${ids.length + 1}`,
          [...ids, ADMIN_EMAIL],
        );
        break;
      case "enable":
        affected = await run(
          `UPDATE users SET disabled = false WHERE id IN (${placeholders})`,
          ids,
        );
        break;
      case "grant_subscription":
        affected = await run(
          `UPDATE users SET subscription_access = true WHERE id IN (${placeholders})`,
          ids,
        );
        break;
      case "revoke_subscription":
        affected = await run(
          `UPDATE users SET subscription_access = false WHERE id IN (${placeholders})`,
          ids,
        );
        break;
      case "delete":
        affected = await run(
          `DELETE FROM users WHERE id IN (${placeholders}) AND email != $${ids.length + 1}`,
          [...ids, ADMIN_EMAIL],
        );
        break;
    }
    return res.status(200).json({ ok: true, affected });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
}
