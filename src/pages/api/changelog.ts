import type { NextApiRequest, NextApiResponse } from "next";
import { many, isDbReady } from "@/lib/db-query";
import { getRedisValue, setRedisValue } from "@/lib/server/redis";

const CACHE_KEY = "changelog:entries";
const CACHE_TTL = 10 * 60; // 10 minutes

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  res.setHeader("Cache-Control", "public, s-maxage=120, stale-while-revalidate=600");

  // L2: Redis cache
  try {
    const cached = await getRedisValue(CACHE_KEY);
    if (cached) {
      return res.status(200).json(JSON.parse(cached));
    }
  } catch { /* ignore redis errors */ }

  if (!(await isDbReady())) return res.status(200).json({ entries: [] });

  try {
    const entries = await many(
      `SELECT id, entry_date::text as entry_date, type, zh, en, version
       FROM changelog_entries ORDER BY entry_date DESC, created_at DESC`,
    );
    const payload = { entries };

    // Store in Redis
    try {
      await setRedisValue(CACHE_KEY, JSON.stringify(payload), CACHE_TTL);
    } catch { /* ignore */ }

    return res.status(200).json(payload);
  } catch {
    return res.status(200).json({ entries: [] });
  }
}
