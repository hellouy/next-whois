import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { run, isDbReady } from "@/lib/db-query";

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
  if (req.method !== "POST") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  const {
    tld,
    current_grace, current_redemption, current_pending_delete,
    suggested_grace, suggested_redemption, suggested_pending_delete,
    source_url, notes, submitter_email,
  } = req.body;

  if (!tld || typeof tld !== "string") {
    return res.status(400).json({ error: "tld 必须提供" });
  }

  const sg = Number(suggested_grace);
  const sr = Number(suggested_redemption);
  const sp = Number(suggested_pending_delete);

  if (isNaN(sg) || sg < 0 || isNaN(sr) || sr < 0 || isNaN(sp) || sp < 0) {
    return res.status(400).json({ error: "建议天数必须为非负整数" });
  }

  if (submitter_email && typeof submitter_email === "string" && !submitter_email.includes("@")) {
    return res.status(400).json({ error: "邮箱格式不正确" });
  }

  try {
    await ensureTable();
    const id = randomBytes(8).toString("hex");
    await run(
      `INSERT INTO tld_lifecycle_feedback
         (id, tld, current_grace, current_redemption, current_pending_delete,
          suggested_grace, suggested_redemption, suggested_pending_delete,
          source_url, notes, submitter_email)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        id, tld.toLowerCase().trim(),
        current_grace ?? null, current_redemption ?? null, current_pending_delete ?? null,
        sg, sr, sp,
        source_url || null, notes || null, submitter_email || null,
      ],
    );
    return res.status(201).json({ ok: true, id });
  } catch (err: any) {
    console.error("[tld-lifecycle-feedback] error:", err.message);
    return res.status(500).json({ error: "提交失败，请稍后重试" });
  }
}
