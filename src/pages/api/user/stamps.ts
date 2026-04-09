import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { invalidateStampCache } from "@/lib/stamp-cache";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  if (req.method === "GET") {
    try {
      const rows = await many(
        `SELECT id, domain, tag_name, tag_style, card_theme, link, description, nickname,
                verified, verified_at, created_at
         FROM stamps WHERE email = $1 ORDER BY created_at DESC`,
        [session.user.email],
      );
      return res.status(200).json({ stamps: rows });
    } catch (err: any) {
      console.error("[stamps] GET error:", err.message);
      return res.status(500).json({ error: "Failed to retrieve data" });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "Missing id" });

    const existing = await one(
      "SELECT id, domain FROM stamps WHERE id = $1 AND email = $2",
      [id as string, session.user.email],
    );
    if (!existing) return res.status(404).json({ error: "Stamp not found" });

    const ALLOWED_TAG_STYLES  = ["personal","official","brand","verified","partner","dev","warning","premium"];
    const ALLOWED_CARD_THEMES = ["app","official","aurora","emerald","solar","dev","warning","premium","gradient","celebrate","split","flash","neon"];

    const { tagName, tagStyle, cardTheme, link, description, nickname } = req.body;
    const setClauses: string[] = [];
    const values: any[] = [];
    let idx = 1;

    if (tagName !== undefined) { setClauses.push(`tag_name = $${idx++}`); values.push(String(tagName).trim().slice(0, 32)); }
    if (tagStyle !== undefined) {
      const safe = ALLOWED_TAG_STYLES.includes(String(tagStyle)) ? String(tagStyle) : "personal";
      setClauses.push(`tag_style = $${idx++}`); values.push(safe);
    }
    if (cardTheme !== undefined) {
      const safe = ALLOWED_CARD_THEMES.includes(String(cardTheme)) ? String(cardTheme) : "app";
      setClauses.push(`card_theme = $${idx++}`); values.push(safe);
    }
    if (link !== undefined) { setClauses.push(`link = $${idx++}`); values.push(String(link).trim().slice(0, 200)); }
    if (description !== undefined) { setClauses.push(`description = $${idx++}`); values.push(String(description).trim().slice(0, 200)); }
    if (nickname !== undefined) { setClauses.push(`nickname = $${idx++}`); values.push(String(nickname).trim().slice(0, 50)); }

    if (setClauses.length === 0) return res.status(400).json({ error: "No fields to update" });

    values.push(id as string, session.user.email);
    try {
      await run(
        `UPDATE stamps SET ${setClauses.join(", ")} WHERE id = $${idx++} AND email = $${idx++}`,
        values,
      );
      invalidateStampCache(String(existing.domain).toLowerCase());
    } catch (err: any) {
      console.error("[stamps] PATCH error:", err.message);
      return res.status(500).json({ error: "Update failed, please try again" });
    }
    return res.status(200).json({ ok: true });
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "Missing id" });

    try {
      const existing = await one(
        "SELECT domain FROM stamps WHERE id = $1 AND email = $2",
        [id as string, session.user.email],
      );
      await run(
        "DELETE FROM stamps WHERE id = $1 AND email = $2",
        [id as string, session.user.email],
      );
      if (existing?.domain) invalidateStampCache(String(existing.domain).toLowerCase());
    } catch (err: any) {
      console.error("[stamps] DELETE error:", err.message);
      return res.status(500).json({ error: "Deletion failed, please try again" });
    }
    return res.status(200).json({ ok: true });
  }

  return res.status(405).end();
}
