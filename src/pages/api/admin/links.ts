import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { many, one, run } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    const links = await many<{
      id: number; name: string; url: string; description: string | null;
      category: string | null; sort_order: number; active: boolean; created_at: string;
    }>("SELECT id, name, url, description, category, sort_order, active, created_at FROM friendly_links ORDER BY sort_order ASC, created_at DESC");
    return res.json({ links });
  }

  if (req.method === "POST") {
    const { name, url, description, category, sort_order } = req.body;
    if (!name?.trim() || !url?.trim()) return res.status(400).json({ error: "名称和链接不能为空" });
    try { new URL(url.trim()); } catch { return res.status(400).json({ error: "URL 格式不正确" }); }
    const link = await one<{ id: number }>(
      "INSERT INTO friendly_links (name, url, description, category, sort_order) VALUES ($1,$2,$3,$4,$5) RETURNING id",
      [name.trim(), url.trim(), description?.trim() || null, category?.trim() || null, Number(sort_order) || 0]
    );
    return res.status(201).json({ id: link?.id });
  }

  if (req.method === "PUT") {
    const { id, name, url, description, category, sort_order, active } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    if (name !== undefined || url !== undefined) {
      if (!name?.trim() || !url?.trim()) return res.status(400).json({ error: "名称和链接不能为空" });
      try { new URL(url.trim()); } catch { return res.status(400).json({ error: "URL 格式不正确" }); }
      await run(
        "UPDATE friendly_links SET name=$1, url=$2, description=$3, category=$4, sort_order=$5, active=$6 WHERE id=$7",
        [name.trim(), url.trim(), description?.trim() || null, category?.trim() || null, Number(sort_order) || 0, active !== false, id]
      );
    } else if (active !== undefined) {
      await run("UPDATE friendly_links SET active=$1 WHERE id=$2", [Boolean(active), id]);
    }
    return res.json({ ok: true });
  }

  if (req.method === "DELETE") {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "缺少 id" });
    await run("DELETE FROM friendly_links WHERE id=$1", [id]);
    return res.json({ ok: true });
  }

  return res.status(405).end();
}
