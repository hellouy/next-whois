/**
 * expireddomains.net public-listing adapter (no login required).
 *
 * The site exposes two anonymous listings that are perfect for a drop calendar:
 *
 *   /deleted-domains/  → names deleted from the registry (the drop already
 *                        happened; the listing carries the exact drop date)
 *   /expired-domains/  → names whose registration expired and are heading to
 *                        the drop; the listing carries the expiry date, from
 *                        which the drop date is derived via lifecycle rules
 *
 * Both listings are paginated 25 rows at a time via `?start=`. This adapter
 * needs no credentials, so it works on a fresh install where the authenticated
 * pending-delete adapter is not yet configured.
 */

import * as cheerio from "cheerio";
import { getSettings } from "@/lib/server/site-settings-server";
import { parseDropDate } from "@/lib/drop-normalize";
import type { DropStage } from "@/lib/drop-types";
import { EXPIREDDOMAINS_UA } from "./expireddomains-auth";
import type { AdapterResult, DropSourceAdapter, RawDropRow } from "./types";

export const EXPIREDDOMAINS_WWW = "https://www.expireddomains.net";
export const DELETED_PATH = "/deleted-domains/";
export const EXPIRED_PATH = "/expired-domains/";
const PAGE_SIZE = 25;
const PAGE_DELAY_MS = 1200;
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

/** Parse a human/compact metric such as "3.7 K", "1.2M" or "354" into a number. */
export function parseMetric(raw: string | null | undefined): number | null {
  const s = String(raw ?? "").trim().replace(/,/g, "");
  if (!s || s === "-") return null;
  const m = s.match(/^([\d.]+)\s*([KkMm]?)/);
  if (!m) return null;
  const n = parseFloat(m[1]);
  if (Number.isNaN(n)) return null;
  const unit = m[2].toLowerCase();
  const mult = unit === "k" ? 1e3 : unit === "m" ? 1e6 : 1;
  return Math.round(n * mult);
}

/** Resolve a listing date cell ("Today 01:31", "Yesterday", "2026-09-20"). */
export function parseListedDate(text: string | null | undefined, today: string): string | null {
  const s = String(text ?? "").trim().toLowerCase();
  if (/^today/.test(s)) return today;
  if (/^yesterday/.test(s)) {
    return new Date(Date.parse(`${today}T00:00:00Z`) - 86_400_000).toISOString().slice(0, 10);
  }
  return parseDropDate(s);
}

/** Extract a normalized domain from a listing row's domain cell. */
function readDomain($row: cheerio.Cheerio<any>, $: cheerio.CheerioAPI): string | null {
  const a = $row.find(".field_domain a").first();
  let d = String(a.attr("title") || a.text() || "").trim().toLowerCase();
  if (!DOMAIN_RE.test(d)) {
    const first = $row.find("td").first().text().trim().toLowerCase();
    const tok = first.match(/^([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/);
    d = tok ? tok[1] : "";
  }
  if (d.startsWith("www.")) d = d.slice(4);
  return DOMAIN_RE.test(d) ? d : null;
}

/**
 * Parse one public listing page. `stage` decides how the date column is used:
 * deleted rows carry the drop date, expired rows carry the expiry date.
 */
export function parsePublicListing(
  html: string,
  stage: DropStage,
  today: string,
): AdapterResult {
  const $ = cheerio.load(html);
  const rows: RawDropRow[] = [];
  let skipped = 0;

  const table = $("#listing");
  if (!table.length) return { rows, skipped };

  const headers: string[] = [];
  table.find("thead th").each((_, th) => { headers.push($(th).text().trim().toLowerCase()); });
  const col = (needles: string[]) => headers.findIndex((h) => needles.some((n) => h.includes(n)));
  const iBl = col(["bl"]);
  const iDp = col(["dp"]);
  const iDate = stage === "deleted" ? col(["dropped", "delete"]) : col(["end date", "expir"]);

  table.find("tbody tr").each((_, tr) => {
    const $row = $(tr);
    const domain = readDomain($row, $);
    if (!domain) { skipped++; return; }

    const cells = $row.find("td");
    const read = (i: number) => (i >= 0 && i < cells.length ? $(cells.get(i)).text().trim() : "");
    const listedDate = parseListedDate(iDate >= 0 ? read(iDate) : "", today);

    const row: RawDropRow = {
      domain,
      stage,
      dropDate: stage === "deleted" ? listedDate : null,
      expiryDate: stage === "expiring" ? listedDate : null,
      bl: iBl >= 0 ? parseMetric(read(iBl)) : null,
      dp: iDp >= 0 ? parseMetric(read(iDp)) : null,
      sourceDateType: stage === "deleted" && listedDate ? "source" : "derived",
    };
    rows.push(row);
  });

  return { rows, skipped };
}

async function fetchListing(path: string, stage: DropStage, maxRows: number, today: string): Promise<AdapterResult> {
  const rows: RawDropRow[] = [];
  let skipped = 0;
  const pages = Math.max(1, Math.ceil(maxRows / PAGE_SIZE));

  for (let page = 0; page < pages; page++) {
    if (page > 0) await delay(PAGE_DELAY_MS);
    const url = `${EXPIREDDOMAINS_WWW}${path}?start=${page * PAGE_SIZE}`;
    const res = await fetch(url, {
      headers: {
        "User-Agent": EXPIREDDOMAINS_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": `${EXPIREDDOMAINS_WWW}${path}`,
      },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`${path} returned HTTP ${res.status}`);

    const html = await res.text();
    const parsed = parsePublicListing(html, stage, today);
    if (parsed.rows.length === 0) {
      if (!html.includes('id="listing"')) {
        throw new Error(`${path} served no listing table (rate-limited or login required)`);
      }
      break;
    }
    rows.push(...parsed.rows);
    skipped += parsed.skipped;
    if (rows.length >= maxRows) break;
  }

  return { rows: rows.slice(0, maxRows), skipped };
}

export const expiredDomainsPublicAdapter: DropSourceAdapter = {
  id: "expireddomains-public",
  stages: ["deleted", "expiring"],
  async fetch(): Promise<AdapterResult> {
    const settings = await getSettings(["expireddomains_public_enabled", "expireddomains_public_rows"]);
    if (String(settings.expireddomains_public_enabled ?? "1") === "0") {
      return { rows: [], skipped: 0 };
    }
    const maxRows = Math.min(500, Math.max(25, parseInt(String(settings.expireddomains_public_rows ?? "50"), 10) || 50));
    const today = new Date().toISOString().slice(0, 10);

    // Sequential (not parallel) to stay within the site's anonymous rate limits.
    const deleted = await fetchListing(DELETED_PATH, "deleted", maxRows, today);
    await delay(PAGE_DELAY_MS);
    const expired = await fetchListing(EXPIRED_PATH, "expiring", maxRows, today);

    return { rows: [...deleted.rows, ...expired.rows], skipped: deleted.skipped + expired.skipped };
  },
};
