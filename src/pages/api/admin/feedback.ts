import type { NextApiRequest, NextApiResponse } from "next";
import { many, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    try {
      const search = typeof req.query.search === "string" ? req.query.search : "";
      const issueType = typeof req.query.issue_type === "string" ? req.query.issue_type : "";
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

      const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
      const q = `SELECT id, query, query_type, issue_types, description, email, created_at, handled, handled_at FROM feedback${where} ORDER BY handled ASC, created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
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

  res.setHeader("Allow", "GET, PATCH, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
