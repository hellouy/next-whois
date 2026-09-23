/**
 * expireddomains.net pending-delete adapter.
 *
 * Reuses the shared login flow and parses the "Pending Delete" listing — names
 * already inside the registry's pending-delete window, so their drop date is
 * known in advance. Column positions are resolved from the table header to stay
 * robust across the site's views.
 */

import * as cheerio from "cheerio";
import { getSettings } from "@/lib/server/site-settings-server";
import { parseDropDate } from "@/lib/drop-normalize";
import { EXPIREDDOMAINS_BASE, EXPIREDDOMAINS_UA, loginToExpiredDomains } from "./expireddomains-auth";
import type { AdapterResult, DropSourceAdapter, RawDropRow } from "./types";

export const PENDING_DELETE_PATH = "/domains/pendingdelete/";

export function parsePendingDelete(html: string): AdapterResult {
  const $ = cheerio.load(html);
  const rows: RawDropRow[] = [];
  let skipped = 0;

  const table = $("#listing");
  if (!table.length) return { rows, skipped };

  const headers: string[] = [];
  table.find("thead th").each((_, th) => { headers.push($(th).text().trim().toLowerCase()); });
  if (!headers.length) {
    table.find("tr").first().find("th, td").each((_, c) => { headers.push($(c).text().trim().toLowerCase()); });
  }
  const col = (needles: string[]) => headers.findIndex((h) => needles.some((n) => h.includes(n)));
  const iDomain = col(["domain"]);
  const iBl = col(["bl"]);
  const iDp = col(["dp"]);
  const iDrop = col(["drop", "delete"]);

  table.find("tbody tr").each((_, row) => {
    const cells = $(row).find("td");
    if (!cells.length) return;

    const readCell = (i: number) => (i >= 0 && i < cells.length ? $(cells.get(i)).text().trim() : "");
    let domain = readCell(iDomain >= 0 ? iDomain : 0).toLowerCase();
    if (!domain) domain = $(row).find(".field_domain a").first().text().trim().toLowerCase();
    if (domain.startsWith("www.")) domain = domain.slice(4);
    if (!domain || !domain.includes(".")) {
      skipped++;
      return;
    }

    const num = (i: number) => {
      const t = readCell(i).replace(/[^0-9]/g, "");
      const n = parseInt(t, 10);
      return isNaN(n) ? null : n;
    };
    const dropText = iDrop >= 0 ? readCell(iDrop) : "";
    const dropDate = parseDropDate(dropText);

    rows.push({
      domain,
      stage: "pending_delete",
      dropDate,
      expiryDate: null,
      bl: iBl >= 0 ? num(iBl) : null,
      dp: iDp >= 0 ? num(iDp) : null,
      sourceDateType: dropDate ? "source" : "derived",
    });
  });

  return { rows, skipped };
}

export const expiredDomainsAdapter: DropSourceAdapter = {
  id: "expireddomains",
  stages: ["pending_delete"],
  async fetch(): Promise<AdapterResult> {
    const settings = await getSettings([
      "expireddomains_username",
      "expireddomains_password",
      "expireddomains_rows",
    ]);
    const username = settings.expireddomains_username?.trim();
    const password = settings.expireddomains_password?.trim();
    if (!username || !password) throw new Error("expireddomains credentials are not configured");

    const wanted = Math.min(500, Math.max(50, parseInt(String(settings.expireddomains_rows ?? "200"), 10) || 200));
    const cookie = await loginToExpiredDomains(username, password);

    const params = new URLSearchParams({ rows: String(wanted), filterunregistered: "yes" });
    const res = await fetch(`${EXPIREDDOMAINS_BASE}${PENDING_DELETE_PATH}?${params.toString()}`, {
      headers: {
        "Cookie": cookie,
        "User-Agent": EXPIREDDOMAINS_UA,
        "Referer": `${EXPIREDDOMAINS_BASE}${PENDING_DELETE_PATH}`,
      },
      signal: AbortSignal.timeout(45_000),
    });
    if (!res.ok) throw new Error(`pending-delete page returned HTTP ${res.status}`);

    const html = await res.text();
    if (html.includes("id_username") || html.includes("loginForm")) {
      throw new Error("session expired or login failed");
    }
    return parsePendingDelete(html);
  },
};
