import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { recordNotification } from "@/lib/notifications";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    try {
      const search = typeof req.query.search === "string" ? req.query.search : "";
      const issueType = typeof req.query.issue_type === "string" ? req.query.issue_type : "";
      const handledFilter = typeof req.query.handled === "string" ? req.query.handled : "";
      const limit = Math.min(parseInt(String(req.query.limit || "50")), 200);
      const offset = parseInt(String(req.query.offset || "0"));

      const params: any[] = [];
      const conditions: string[] = [];

      if (search) {
        params.push(`%${search}%`);
        conditions.push(`(query ILIKE $${params.length} OR email ILIKE $${params.length} OR description ILIKE $${params.length})`);
      }
      if (issueType) {
        params.push(`%"${issueType}"%`);
        conditions.push(`issue_types ILIKE $${params.length}`);
      }
      if (handledFilter === "false") {
        conditions.push(`(handled = false OR handled IS NULL)`);
      } else if (handledFilter === "true") {
        conditions.push(`handled = true`);
      }

      const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
      const q = `SELECT id, query, query_type, issue_types, description, email, created_at, handled, handled_at, reply, replied_at FROM feedback${where} ORDER BY handled ASC, created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
      params.push(limit, offset);

      const rows = await many(q, params);

      const countQ = `SELECT COUNT(*) AS count FROM feedback${where}`;
      const countParams = params.slice(0, params.length - 2);
      const countRows = await many<{ count: string }>(countQ, countParams);
      const total = parseInt(countRows[0]?.count ?? "0");

      const typeCounts: Record<string, number> = {};
      try {
        const typeCountRows = await many<{ issue_type: string; cnt: string }>(
          `SELECT unnested AS issue_type, COUNT(*) AS cnt
           FROM (
             SELECT jsonb_array_elements_text(issue_types::jsonb) AS unnested
             FROM feedback
             WHERE issue_types IS NOT NULL
               AND issue_types != ''
               AND issue_types != '[]'
               AND issue_types ~ '^\\s*\\['
           ) sub
           GROUP BY unnested
           ORDER BY cnt DESC`,
          []
        );
        for (const row of typeCountRows) {
          typeCounts[row.issue_type] = parseInt(row.cnt);
        }
      } catch {
        // issue_types column contains non-JSON rows — skip type aggregation gracefully
      }

      return res.json({ feedback: rows, total, typeCounts });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    const { handled } = req.body as { handled?: boolean };
    if (typeof handled !== "boolean") return res.status(400).json({ error: "handled 必须是 boolean" });
    try {
      await run(
        "UPDATE feedback SET handled = $1, handled_at = $2 WHERE id = $3",
        [handled, handled ? new Date().toISOString() : null, id]
      );
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  // Inline reply: persist the admin's answer, mark handled, and push a station
  // notification to the submitter when they hold an account (R1.1-R1.5).
  if (req.method === "POST") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    const { reply } = req.body as { reply?: string };
    const cleanReply = typeof reply === "string" ? reply.trim() : "";
    if (!cleanReply) return res.status(400).json({ error: "回复内容不能为空" });
    if (cleanReply.length > 2000) return res.status(400).json({ error: "回复内容不能超过 2000 个字符" });
    try {
      const fb = await one<{ email: string | null; query: string }>(
        "SELECT email, query FROM feedback WHERE id = $1",
        [id]
      );
      if (!fb) return res.status(404).json({ error: "反馈不存在" });

      const now = new Date().toISOString();
      await run(
        "UPDATE feedback SET reply = $1, replied_at = $2, handled = true, handled_at = $3 WHERE id = $4",
        [cleanReply, now, now, id]
      );

      if (fb.email) {
        const user = await one<{ id: string }>("SELECT id FROM users WHERE email = $1", [fb.email]).catch(() => null);
        if (user) {
          await recordNotification({
            email: fb.email,
            type: "feedback_reply",
            title: `您的反馈已回复：${fb.query}`,
            body: cleanReply,
            domain: fb.query,
          });
        }
      }
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    try {
      await run("DELETE FROM feedback WHERE id = $1", [id]);
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, PATCH, POST, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
