/**
 * whoisds.com daily drop-list adapter.
 *
 * whoisds publishes plain-text daily lists (one domain per line). The list URLs
 * are admin-configured via the `whoisds_list_urls` setting (comma separated);
 * the stage is inferred from each URL so a single source can feed several
 * phases. When no URL is configured the adapter is a no-op rather than an error.
 */

import { getSettings } from "@/lib/server/site-settings-server";
import type { DropStage } from "@/lib/drop-types";
import { EXPIREDDOMAINS_UA } from "./expireddomains-auth";
import type { AdapterResult, DropSourceAdapter, RawDropRow } from "./types";

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/** Infer the drop stage from a list URL's path. */
export function stageFromUrl(url: string): DropStage {
  const u = url.toLowerCase();
  if (/pending|pre-?release/.test(u)) return "pending_delete";
  if (/expir/.test(u)) return "expiring";
  return "deleted";
}

/** Parse a plain-text domain list into normalized rows. */
export function parseWhoisdsText(text: string, stage: DropStage, today: string): AdapterResult {
  const rows: RawDropRow[] = [];
  const seen = new Set<string>();
  let skipped = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim().toLowerCase();
    if (!line || line.startsWith("#")) continue;
    if (!DOMAIN_RE.test(line)) {
      skipped++;
      continue;
    }
    if (seen.has(line)) continue;
    seen.add(line);
    rows.push({
      domain: line,
      stage,
      dropDate: stage === "deleted" ? today : null,
      expiryDate: null,
      bl: null,
      dp: null,
      sourceDateType: stage === "deleted" ? "source" : "derived",
    });
  }

  return { rows, skipped };
}

export const whoisdsAdapter: DropSourceAdapter = {
  id: "whoisds",
  stages: ["deleted", "expiring", "pending_delete"],
  async fetch(): Promise<AdapterResult> {
    const settings = await getSettings(["whoisds_list_urls"]);
    const urls = String(settings.whoisds_list_urls ?? "")
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!urls.length) return { rows: [], skipped: 0 };

    const today = new Date().toISOString().slice(0, 10);
    const rows: RawDropRow[] = [];
    let skipped = 0;

    for (const url of urls) {
      const res = await fetch(url, {
        headers: { "User-Agent": EXPIREDDOMAINS_UA },
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`whoisds list returned HTTP ${res.status}`);
      const text = await res.text();
      const parsed = parseWhoisdsText(text, stageFromUrl(url), today);
      rows.push(...parsed.rows);
      skipped += parsed.skipped;
    }

    return { rows, skipped };
  },
};
