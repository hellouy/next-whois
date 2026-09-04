import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "crypto";
import { many, one, run } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { invalidateStampCache } from "@/lib/stamp-cache";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/admin/stamps");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    try {
      const search = typeof req.query.search === "string" ? req.query.search : "";
      const filter = typeof req.query.filter === "string" ? req.query.filter : "all";
      const styleFilter = typeof req.query.style === "string" ? req.query.style : "all";
      const limit = Math.min(parseInt(String(req.query.limit || "50")), 200);
      const offset = parseInt(String(req.query.offset || "0"));

      const conditions: string[] = [];
      const params: any[] = [];

      if (search) {
        params.push(`%${search}%`);
        conditions.push(`(domain ILIKE $${params.length} OR tag_name ILIKE $${params.length} OR email ILIKE $${params.length} OR nickname ILIKE $${params.length})`);
      }
      if (filter === "verified") conditions.push("verified = true");
      if (filter === "pending") conditions.push("verified = false");
      if (styleFilter !== "all") {
        params.push(styleFilter);
        conditions.push(`tag_style = $${params.length}`);
      }

      const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
      const q = `SELECT id, domain, tag_name, tag_style, card_theme, link, description, nickname, email, verified, verified_at, created_at
                 FROM stamps${where}
                 ORDER BY created_at DESC
                 LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
      params.push(limit, offset);
      const stamps = await many(q, params);

      const countParams = params.slice(0, params.length - 2);
      const countRow = await one<{ count: string }>(
        `SELECT COUNT(*) AS count FROM stamps${where}`,
        countParams.length ? countParams : undefined
      );
      const total = parseInt(countRow?.count ?? "0");

      const [verifiedCount, pendingCount] = await Promise.all([
        one<{ count: string }>("SELECT COUNT(*) AS count FROM stamps WHERE verified = true"),
        one<{ count: string }>("SELECT COUNT(*) AS count FROM stamps WHERE verified = false"),
      ]);

      const styleCounts = await many<{ tag_style: string; count: string }>(
        "SELECT tag_style, COUNT(*) AS count FROM stamps GROUP BY tag_style ORDER BY count DESC"
      );

      return res.json({
        stamps, total,
        verifiedCount: parseInt(verifiedCount?.count ?? "0"),
        pendingCount: parseInt(pendingCount?.count ?? "0"),
        styleCounts,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "POST") {
    const { domain, tag_name, tag_style, card_theme, link, description, nickname, email, verified } = req.body;
    if (!domain || !tag_name || !nickname || !email)
      return res.status(400).json({ error: "domain / tag_name / nickname / email 不能为空" });

    const cleanDomain    = String(domain).toLowerCase().trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
    const cleanTagName   = String(tag_name).trim().slice(0, 30);
    const cleanTagStyle  = String(tag_style  || "official");
    const cleanCardTheme = String(card_theme || "app");
    const cleanLink      = String(link || "").trim() || null;
    const cleanDesc      = String(description || "").trim().slice(0, 300) || null;
    const cleanNickname  = String(nickname).trim().slice(0, 30);
    const cleanEmail     = String(email).trim();
    const isVerified     = verified === true || verified === "true";

    const token = randomBytes(16).toString("hex");
    const id    = randomBytes(8).toString("hex");

    try {
      await run(
        `INSERT INTO stamps
           (id, domain, tag_name, tag_style, card_theme, link, description, nickname, email, verify_token, verified, verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [id, cleanDomain, cleanTagName, cleanTagStyle, cleanCardTheme, cleanLink, cleanDesc,
         cleanNickname, cleanEmail, token, isVerified, isVerified ? new Date() : null],
      );
      const created = await one("SELECT * FROM stamps WHERE id = $1", [id]);
      return res.status(201).json({ ok: true, stamp: created });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  if (req.method === "PATCH") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    const { verified, tag_name, tag_style, card_theme, link, description } = req.body;

    const ALLOWED_TAG_STYLES  = ["personal","official","brand","verified","partner","dev","warning","premium"];
    const ALLOWED_CARD_THEMES = ["app","official","aurora","emerald","solar","dev","warning","premium","celebrate","neon","gradient","split","flash"];

    try {
      if (verified === true) {
        await run(`UPDATE stamps SET verified = true, verified_at = NOW() WHERE id = $1`, [id]);
      } else if (verified === false) {
        await run(`UPDATE stamps SET verified = false, verified_at = NULL WHERE id = $1`, [id]);
      }
      const sets: string[] = [];
      const params: any[] = [];
      if (tag_name !== undefined)   { params.push(tag_name || null);   sets.push(`tag_name = $${params.length}`); }
      if (tag_style !== undefined)  {
        const safe = ALLOWED_TAG_STYLES.includes(String(tag_style)) ? String(tag_style) : null;
        params.push(safe);
        sets.push(`tag_style = $${params.length}`);
      }
      if (card_theme !== undefined) {
        const safe = ALLOWED_CARD_THEMES.includes(String(card_theme)) ? String(card_theme) : null;
        params.push(safe);
        sets.push(`card_theme = $${params.length}`);
      }
      if (link !== undefined)       { params.push(link || null);       sets.push(`link = $${params.length}`); }
      if (description !== undefined){ params.push(description || null);sets.push(`description = $${params.length}`); }
      if (sets.length) {
        params.push(id);
        await run(`UPDATE stamps SET ${sets.join(", ")} WHERE id = $${params.length}`, params);
      }
      const updated = await one<{ domain: string }>("SELECT * FROM stamps WHERE id = $1", [id]);
      if (updated?.domain) invalidateStampCache(updated.domain);
      return res.json({ ok: true, stamp: updated });
    } catch (err: any) {
      logger.error("[admin/stamps] PATCH error:", err.message);
      return res.status(500).json({ error: "更新失败，请稍后重试" });
    }
  }

  if (req.method === "DELETE") {
    const { id } = req.query;
    if (!id || typeof id !== "string") return res.status(400).json({ error: "Missing id" });
    try {
      await run("DELETE FROM stamps WHERE id = $1", [id]);
      return res.json({ ok: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }

  res.setHeader("Allow", "GET, POST, PATCH, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
