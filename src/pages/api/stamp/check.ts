import type { NextApiRequest, NextApiResponse } from "next";
import { many, isDbReady } from "@/lib/db-query";
import { getStampCache, setStampCache, STAMP_CACHE_TTL } from "@/lib/stamp-cache";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const domain = String(req.query.domain || "").toLowerCase().trim();
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  const cached = getStampCache(domain);
  if (cached && Date.now() - cached.ts < STAMP_CACHE_TTL) {
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({ stamps: cached.stamps });
  }

  if (!(await isDbReady())) return res.status(200).json({ stamps: [] });

  try {
    const rows = await many(
      `SELECT id, tag_name, tag_style, card_theme, link, nickname, description, verified_at
       FROM stamps WHERE domain = $1 AND verified = true
       ORDER BY verified_at DESC`,
      [domain],
    );
    const stamps = rows.map((r) => ({
      id: r.id, tagName: r.tag_name, tagStyle: r.tag_style,
      cardTheme: r.card_theme || "app",
      link: r.link, nickname: r.nickname, description: r.description,
      verifiedAt: r.verified_at,
    }));
    setStampCache(domain, stamps);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({ stamps });
  } catch (err: any) {
    console.error("[stamp/check] error:", err);
    return res.status(500).json({ error: "查询失败，请稍后重试", stamps: [] });
  }
}
