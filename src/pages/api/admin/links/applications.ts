import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { one, many, run } from "@/lib/db-query";
import { getSiteLabel, sendEmail, linkApplyResultHtml } from "@/lib/email";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/admin/links/applications");

function parseBacklink(raw: string | null): unknown {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    const rows = await many<Record<string, unknown>>(
      `SELECT id, name, url, description, category, email, status, auto_approved,
              backlink_pages, admin_note, link_id, created_at, reviewed_at
       FROM friendly_link_applications
       ORDER BY created_at DESC`
    ).catch(err => {
      logger.error("[admin/links/applications] list failed:", err instanceof Error ? err.message : err);
      return [];
    });
    const applications = rows.map(r => ({ ...r, backlink_pages: parseBacklink(String(r.backlink_pages ?? null)) }));
    return res.json({ applications });
  }

  if (req.method === "PUT") {
    const { id, action, note } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    if (action !== "approve" && action !== "reject") {
      return res.status(400).json({ error: "action 只能为 approve 或 reject" });
    }

    const app = await one<Record<string, unknown>>(
      "SELECT id, name, url, description, category, email, status FROM friendly_link_applications WHERE id=$1",
      [id],
    );
    if (!app || String(app.status) === "approved") {
      return res.status(404).json({ error: "申请不存在或已处理" });
    }

    const siteName = await getSiteLabel().catch(() => "WHOIS");

    if (action === "approve") {
      const created = await one<{ id: number }>(
        `INSERT INTO friendly_links (name, url, description, category)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [String(app.name), String(app.url), app.description ? String(app.description) : null, app.category ? String(app.category) : null],
      ).catch(err => {
        logger.error("[admin/links/applications] insert friendly_links failed:", err instanceof Error ? err.message : err);
        return null;
      });
      if (!created) return res.status(500).json({ error: "上链写入失败" });

      await run(
        `UPDATE friendly_link_applications
         SET status='approved', admin_note=$2, link_id=$3, reviewed_at=NOW()
         WHERE id=$1`,
        [id, note ? String(note).slice(0, 200) : null, created.id],
      ).catch(() => {});

      if (app.email) {
        await sendEmail({
          to: String(app.email),
          subject: `[${siteName}] 友链申请已通过`,
          html: linkApplyResultHtml({ name: String(app.name), approved: true, siteName, locale: "zh" }),
        }).catch(err => {
          logger.error("[admin/links/applications] approve email failed:", err instanceof Error ? err.message : err);
        });
      }
      return res.json({ ok: true, id, linkId: created.id });
    }

    // reject
    await run(
      `UPDATE friendly_link_applications
       SET status='rejected', admin_note=$2, reviewed_at=NOW()
       WHERE id=$1`,
      [id, note ? String(note).slice(0, 200) : null],
    ).catch(() => {});

    if (app.email) {
      await sendEmail({
        to: String(app.email),
        subject: `[${siteName}] 友链申请未通过`,
        html: linkApplyResultHtml({ name: String(app.name), rejected: true, reason: note ? String(note) : undefined, siteName, locale: "zh" }),
      }).catch(err => {
        logger.error("[admin/links/applications] reject email failed:", err instanceof Error ? err.message : err);
      });
    }
    return res.json({ ok: true, id });
  }

  if (req.method === "DELETE") {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    await run("DELETE FROM friendly_link_applications WHERE id=$1", [id]).catch(() => {});
    return res.json({ ok: true });
  }

  return res.status(405).end();
}