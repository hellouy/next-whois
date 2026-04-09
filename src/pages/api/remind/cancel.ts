import type { NextApiRequest, NextApiResponse } from "next";
import { one, run, isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const token = String(req.query.token || "").trim();
  if (!token) return res.status(400).json({ error: "Missing token" });

  if (!(await isDbReady())) return res.status(500).json({ error: "Database unavailable" });

  try {
    const existing = await one<{ id: string; domain: string; email: string }>(
      "SELECT id, domain, email FROM reminders WHERE cancel_token = $1 AND active = true",
      [token],
    );
    if (!existing) return res.status(404).json({ error: "not_found" });

    await run(
      `UPDATE reminders
       SET active = false, cancelled_at = $1, cancel_reason = 'user_cancel'
       WHERE id = $2`,
      [new Date().toISOString(), existing.id],
    );

    return res.status(200).json({ ok: true, domain: existing.domain, email: existing.email });
  } catch (err: any) {
    console.error("[remind/cancel] DB error:", err);
    return res.status(500).json({ error: "Cancellation failed, please try again" });
  }
}
