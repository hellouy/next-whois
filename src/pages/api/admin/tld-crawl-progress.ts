import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { one, many } from "@/lib/db-query";
import { isRedisAvailable, getRedisValue, setRedisValue } from "@/lib/server/redis";

const IANA_CACHE_KEY = "iana:root_zone_total_v1";
const IANA_FETCH_MS = 8_000;

/** Fetch runtime IANA root-zone non-IDN TLD count (cached 24h). */
async function fetchIanaTotal(): Promise<number | null> {
  if (isRedisAvailable()) {
    const cached = await getRedisValue(IANA_CACHE_KEY);
    if (cached) {
      const n = parseInt(cached, 10);
      if (!Number.isNaN(n) && n > 1000) return n;
    }
  }
  try {
    const resp = await fetch("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", {
      headers: { "User-Agent": "next-whois-ui/1.0 (domain lifecycle tool)" },
      signal: AbortSignal.timeout(IANA_FETCH_MS),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    const all = text
      .split(/\r?\n/)
      .map((l) => l.trim().toLowerCase())
      .filter((t) => t && !t.startsWith("#"));
    const nonIdn = all.filter((t) => !t.startsWith("xn--"));
    if (isRedisAvailable()) {
      await setRedisValue(IANA_CACHE_KEY, String(nonIdn.length), 24 * 60 * 60);
    }
    return nonIdn.length;
  } catch {
    return null;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const session = await requireAdmin(req, res);
  if (!session) return;

  try {
    // Latest crawl progress row (prefer the full-zone iana run)
    const progressRow = await one<any>(`
      SELECT run_key, status, done, total, ok, skipped, errors, default_only,
             iana_total, current_tld, pid, started_at, updated_at
      FROM tld_crawl_progress
      ORDER BY (run_key = 'iana') DESC, updated_at DESC
      LIMIT 1
    `);

    // tld_rules coverage
    const rules = await many<any>(`SELECT scrape_status, manually_edited FROM tld_rules`);
    const statusCount = {
      total: rules.length,
      ok: rules.filter((r) => r.scrape_status === "ok" || r.manually_edited).length,
      warn_defaults: rules.filter((r) => r.scrape_status === "warn_defaults" && !r.manually_edited).length,
      failed: rules.filter((r) => r.scrape_status === "failed" && !r.manually_edited).length,
      pending: rules.filter((r) => r.scrape_status === "pending" && !r.manually_edited).length,
      no_data: rules.filter((r) => r.scrape_status === "no_data" && !r.manually_edited).length,
      manually_edited: rules.filter((r) => r.manually_edited).length,
    };

    // Prefer the progress row's live count, else fetch IANA live, else null (cache).
    let ianaTotal = progressRow?.iana_total ?? null;
    let ianaStale = false;
    if (!ianaTotal) {
      ianaTotal = await fetchIanaTotal();
      ianaStale = ianaTotal == null;
      if (ianaTotal == null) ianaTotal = progressRow?.total ?? null; // fallback to run total
    }
    const iana = ianaTotal ?? statusCount.total; // last resort: DB rows

    return res.json({
      progress: progressRow
        ? {
            status: progressRow.status,
            done: progressRow.done,
            total: progressRow.total,
            ok: progressRow.ok,
            skipped: progressRow.skipped,
            errors: progressRow.errors,
            default_only: progressRow.default_only,
            current_tld: progressRow.current_tld,
            pid: progressRow.pid,
            started_at: progressRow.started_at,
            updated_at: progressRow.updated_at,
          }
        : null,
      coverage: {
        iana,
        ianaStale,
        ...statusCount,
        remaining: Math.max(0, iana - statusCount.total),
      },
    });
  } catch (e: any) {
    return res.status(500).json({ error: `Progress query failed: ${e.message}` });
  }
}