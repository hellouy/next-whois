import type { NextApiRequest, NextApiResponse } from "next";
import { getSession } from "@/lib/auth";
import { many, isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  if (!(await isDbReady())) return res.status(503).json({ error: "db unavailable" });

  const session = await getSession(req, res);
  const userId = (session?.user as any)?.id as string | undefined;

  if (userId) {
    const rows = await many<{ url: string; click_count: number }>(
      "SELECT url, click_count FROM user_tool_clicks WHERE user_id = $1",
      [userId],
    );
    const clicks: Record<string, number> = {};
    for (const row of rows) clicks[row.url] = row.click_count;
    res.setHeader("Cache-Control", "private, max-age=30, stale-while-revalidate=60");
    return res.status(200).json({ clicks, source: "user" });
  }

  const rows = await many<{ url: string; total_clicks: number }>(
    "SELECT url, total_clicks FROM tool_clicks",
  );
  const clicks: Record<string, number> = {};
  for (const row of rows) clicks[row.url] = row.total_clicks;
  res.setHeader("Cache-Control", "public, max-age=30, stale-while-revalidate=60");
  return res.status(200).json({ clicks, source: "global" });
}
