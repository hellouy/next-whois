import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { getDbReady, getConnectionHost, getConnectionSource } from "@/lib/db";
import { one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  const steps: { step: string; ok: boolean; detail?: string }[] = [];

  const connSource = getConnectionSource();
  const connHost   = getConnectionHost();
  steps.push({
    step: "Database config",
    ok:   connSource !== "none",
    detail: connSource !== "none"
      ? `${connSource} → ${connHost}`
      : "Missing POSTGRES_URL_NON_POOLING secret",
  });

  if (connSource === "none") return res.status(500).json({ ok: false, steps });

  const db = await getDbReady();
  steps.push({ step: "Pool created & schema ready", ok: !!db });
  if (!db) return res.status(500).json({ ok: false, steps });

  const tables = ["stamps", "reminders", "reminder_logs", "users", "search_history", "tool_clicks"];
  for (const table of tables) {
    try {
      await db.query(`SELECT 1 FROM ${table} LIMIT 1`);
      steps.push({ step: `Table: ${table}`, ok: true, detail: "exists" });
    } catch (err: any) {
      steps.push({ step: `Table: ${table}`, ok: false, detail: err.message });
    }
  }

  // Write-read-delete round-trip on stamps
  const testId = `test_${randomBytes(4).toString("hex")}`;
  try {
    await run(
      `INSERT INTO stamps (id, domain, tag_name, tag_style, nickname, email, verify_token, verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
      [testId, "setup-test.example", "Setup Test", "personal", "setup-bot", "setup@test.internal", "test-token"],
    );
    steps.push({ step: "Write test (INSERT)", ok: true });

    const readRow = await one("SELECT id FROM stamps WHERE id = $1", [testId]);
    steps.push({ step: "Read test (SELECT)", ok: !!readRow, detail: readRow ? "round-trip OK" : "record not found" });

    await run("DELETE FROM stamps WHERE id = $1", [testId]);
    steps.push({ step: "Cleanup (DELETE)", ok: true });
  } catch (err: any) {
    steps.push({ step: "Write/Read/Delete test", ok: false, detail: err.message });
  }

  const allOk = steps.every((s) => s.ok);
  return res.status(allOk ? 200 : 500).json({ ok: allOk, steps });
}
