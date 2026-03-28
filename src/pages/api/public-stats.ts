import type { NextApiRequest, NextApiResponse } from "next";
import { one } from "@/lib/db-query";
import { getSetting } from "@/lib/server/site-settings-server";
import {
  isRedisAvailable,
  getRedisValue,
  setRedisValue,
} from "@/lib/server/redis";

const CACHE_KEY = "public_stats:v1";
const CACHE_TTL_S = 300; // 5 minutes

interface PublicStats {
  totalSearches: number;
  todaySearches: number;
  enabled: boolean;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const showStats = await getSetting("home_show_stats");
  if (showStats !== "1") {
    return res.json({ enabled: false, totalSearches: 0, todaySearches: 0 } satisfies PublicStats);
  }

  // Try Redis cache first
  if (isRedisAvailable()) {
    try {
      const cached = await getRedisValue(CACHE_KEY);
      if (cached) {
        const data = JSON.parse(cached) as Omit<PublicStats, "enabled">;
        res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=300");
        return res.json({ ...data, enabled: true } satisfies PublicStats);
      }
    } catch { /* ignore */ }
  }

  try {
    const [total, today] = await Promise.all([
      one<{ count: string }>("SELECT COUNT(*) AS count FROM search_history"),
      one<{ count: string }>(
        "SELECT COUNT(*) AS count FROM search_history WHERE created_at >= NOW() - INTERVAL '1 day'"
      ),
    ]);

    const result: Omit<PublicStats, "enabled"> = {
      totalSearches: parseInt(total?.count ?? "0"),
      todaySearches: parseInt(today?.count ?? "0"),
    };

    // Cache in Redis
    if (isRedisAvailable()) {
      try { await setRedisValue(CACHE_KEY, JSON.stringify(result), CACHE_TTL_S); } catch { /* ignore */ }
    }

    res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=300");
    return res.json({ ...result, enabled: true } satisfies PublicStats);
  } catch {
    return res.status(500).json({ error: "Failed to fetch stats" });
  }
}
