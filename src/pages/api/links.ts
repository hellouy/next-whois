import type { NextApiRequest, NextApiResponse } from "next";
import { many } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=300");
  try {
    const links = await many<{
      id: number; name: string; url: string; description: string | null;
      category: string | null; sort_order: number; logo_url: string | null;
    }>("SELECT id, name, url, description, category, sort_order, logo_url FROM friendly_links WHERE active = true ORDER BY sort_order ASC, id ASC");
    return res.json({ links });
  } catch {
    return res.json({ links: [] });
  }
}
