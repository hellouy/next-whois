/**
 * /api/admin/expired-domains-crawl
 *
 * Crawls member.expireddomains.net for short/high-value expired domain leads.
 *
 * GET  ?action=list                 → paginated + filtered list of stored leads
 * GET  ?action=stats                → length / TLD distribution counts
 * POST ?action=crawl&mode=length    → crawl by min/max SLD length
 * POST ?action=crawl&mode=prefix    → crawl each configured prefix in series
 * POST ?action=crawl&prefix=ai      → crawl a single specific prefix
 * PATCH                             → update a lead (seen / starred / notes)
 * DELETE ?id=N                      → delete one lead
 * DELETE ?action=clear              → delete all leads
 * DELETE ?action=clear_prefix&prefix=ai → delete leads for a specific prefix
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { getSettings } from "@/lib/server/site-settings-server";
import * as cheerio from "cheerio";

export const config = { maxDuration: 60 };

const BASE = "https://member.expireddomains.net";
const LOGIN_URL = `${BASE}/login/`;
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// ── Cookie helpers ────────────────────────────────────────────────────────────

function extractCookies(res: Response): string[] {
  if (typeof (res.headers as any).getSetCookie === "function") {
    return (res.headers as any).getSetCookie().map((c: string) => c.split(";")[0].trim());
  }
  const raw = res.headers.get("set-cookie");
  if (!raw) return [];
  return raw.split(/,(?=\s*\w+=)/).map((c) => c.split(";")[0].trim());
}

function cookieHeader(cookies: string[]): string {
  const map = new Map<string, string>();
  for (const c of cookies) {
    const [name] = c.split("=");
    map.set(name.trim(), c);
  }
  return Array.from(map.values()).join("; ");
}

// ── Login ─────────────────────────────────────────────────────────────────────

async function loginToExpiredDomains(username: string, password: string): Promise<string> {
  const getRes = await fetch(LOGIN_URL, {
    headers: { "User-Agent": UA },
    redirect: "follow",
  });
  const loginCookies = extractCookies(getRes);
  const html = await getRes.text();
  // Match csrfmiddlewaretoken regardless of attribute order in the <input> tag
  const csrfMatch =
    html.match(/name=["']csrfmiddlewaretoken["'][^>]+value=["']([^"']+)["']/) ||
    html.match(/value=["']([^"']+)["'][^>]+name=["']csrfmiddlewaretoken["']/) ||
    html.match(/csrfmiddlewaretoken.*?value=["']([^"']+)["']/s);
  const csrf = csrfMatch?.[1] ?? "";

  const postRes = await fetch(LOGIN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": cookieHeader(loginCookies),
      "Referer": LOGIN_URL,
      "User-Agent": UA,
      "Origin": BASE,
    },
    body: new URLSearchParams({ username, password, csrfmiddlewaretoken: csrf }).toString(),
    redirect: "manual",
  });

  const postCookies = extractCookies(postRes);
  const allCookies = cookieHeader([...loginCookies, ...postCookies]);

  if (!allCookies.includes("sessionid")) {
    const hint = !csrf
      ? " (CSRF token not found — the login page structure may have changed)"
      : postRes.status !== 302 && postRes.status !== 200
      ? ` (unexpected HTTP ${postRes.status} after POST)`
      : "";
    throw new Error(`Login failed — check your expireddomains.net username and password${hint}`);
  }
  return allCookies;
}

// ── Parse listing page ────────────────────────────────────────────────────────

export type ExpiredDomainRow = {
  domain: string;
  tld: string;
  sld: string;
  char_count: number;
  bl: number | null;
  dp: number | null;
  deleted_date: string | null;
  available_date: string | null;
  status: string;
};

function parseListing(html: string): ExpiredDomainRow[] {
  const $ = cheerio.load(html);
  const results: ExpiredDomainRow[] = [];

  const table = $("#listing");
  if (!table.length) return results;

  table.find("tr").each((_, row) => {
    const cells = $(row).find("td");
    if (cells.length < 3) return;

    const domainCell = $(row).find(".field_domain a").first();
    let domain = domainCell.text().trim().toLowerCase();
    if (!domain) {
      domain = $(cells.get(0)).find("a").first().text().trim().toLowerCase();
    }
    if (!domain || !domain.includes(".")) return;
    if (domain.startsWith("www.")) domain = domain.slice(4);

    const parts = domain.split(".");
    if (parts.length < 2) return;
    const sld = parts.slice(0, parts.length - 1).join(".");
    const tld = parts[parts.length - 1];
    const char_count = sld.length;

    const parseNum = (el: any): number | null => {
      const txt = $(el).text().trim().replace(/[^0-9]/g, "");
      const n = parseInt(txt, 10);
      return isNaN(n) ? null : n;
    };
    const parseDate = (el: any): string | null => {
      const txt = $(el).text().trim();
      return txt && txt !== "-" && txt !== "n/a" ? txt : null;
    };

    // Column order: 0:domain 1:len 2:ACR 3:CR 4:BL 5:DP 6:Deleted 7:Available
    const bl = parseNum(cells.get(4));
    const dp = parseNum(cells.get(5));
    const deleted_date = parseDate(cells.get(6));
    const available_date = parseDate(cells.get(7));

    results.push({ domain, tld, sld, char_count, bl, dp, deleted_date, available_date, status: "available" });
  });

  return results;
}

// ── Single page fetch + upsert ────────────────────────────────────────────────

async function fetchAndUpsert(
  cookieStr: string,
  urlParams: URLSearchParams,
): Promise<{ inserted: number; updated: number; leads: ExpiredDomainRow[] }> {
  const url = `${BASE}/domains/combinedexpired/?${urlParams.toString()}`;
  const res = await fetch(url, {
    headers: {
      "Cookie": cookieStr,
      "User-Agent": UA,
      "Referer": `${BASE}/domains/combinedexpired/`,
    },
  });

  if (!res.ok) throw new Error(`Listing page returned HTTP ${res.status}`);

  const html = await res.text();

  if (html.includes("id_username") || html.includes("loginForm")) {
    throw new Error("Session expired or login failed — please re-check credentials");
  }

  const leads = parseListing(html);
  let inserted = 0;
  let updated = 0;

  for (const lead of leads) {
    const affected = await run(
      `INSERT INTO expired_domain_leads
         (domain, tld, sld, char_count, bl, dp, deleted_date, available_date, status, source, crawled_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'expireddomains.net',NOW())
       ON CONFLICT (domain) DO UPDATE SET
         bl             = EXCLUDED.bl,
         dp             = EXCLUDED.dp,
         deleted_date   = EXCLUDED.deleted_date,
         available_date = EXCLUDED.available_date,
         crawled_at     = NOW()`,
      [lead.domain, lead.tld, lead.sld, lead.char_count, lead.bl, lead.dp,
       lead.deleted_date, lead.available_date, lead.status],
    ).catch(() => 0);
    if (affected > 0) inserted++;
    else updated++;
  }

  return { inserted, updated, leads };
}

// ── Crawl: length mode ────────────────────────────────────────────────────────

async function crawlByLength(
  cookieStr: string,
  opts: { minLen: number; maxLen: number; tldFilter: string; rows: number },
): Promise<{ inserted: number; updated: number; leads: ExpiredDomainRow[] }> {
  const p = new URLSearchParams({
    o: "length", r: "a",
    rows: String(opts.rows),
    fl: String(opts.minLen),
    flength: String(opts.maxLen),
    filterunregistered: "yes",
  });
  if (opts.tldFilter) p.set("ftld", opts.tldFilter);
  return fetchAndUpsert(cookieStr, p);
}

// ── Crawl: prefix mode ────────────────────────────────────────────────────────

async function crawlByPrefix(
  cookieStr: string,
  prefix: string,
  opts: { tldFilter: string; rows: number },
): Promise<{ inserted: number; updated: number; leads: ExpiredDomainRow[]; prefix: string }> {
  const p = new URLSearchParams({
    o: "bl", r: "d",                // sort by backlinks descending — highest value first
    rows: String(opts.rows),
    fldomain: prefix.trim().toLowerCase(),
    fpre: "1",                       // prefix match (not substring)
    filterunregistered: "yes",
  });
  if (opts.tldFilter) p.set("ftld", opts.tldFilter);
  const result = await fetchAndUpsert(cookieStr, p);
  return { ...result, prefix };
}

// ── Handler ───────────────────────────────────────────────────────────────────

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!(await requireAdmin(req, res))) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "DB unavailable" });

  const action = req.query.action as string | undefined;

  // ── GET: list leads or stats ───────────────────────────────────────────────
  if (req.method === "GET") {

    // ── Stats endpoint ──────────────────────────────────────────────────────
    if (action === "stats") {
      const [byLen, byTld, totRow] = await Promise.all([
        many<{ char_count: number; cnt: string }>(
          `SELECT char_count, COUNT(*)::text AS cnt
           FROM expired_domain_leads
           GROUP BY char_count ORDER BY char_count`,
        ),
        many<{ tld: string; cnt: string }>(
          `SELECT tld, COUNT(*)::text AS cnt
           FROM expired_domain_leads
           GROUP BY tld ORDER BY cnt::int DESC LIMIT 15`,
        ),
        one<{ total: string; starred: string; unseen: string }>(
          `SELECT
             COUNT(*)::text                             AS total,
             COUNT(*) FILTER (WHERE starred)::text      AS starred,
             COUNT(*) FILTER (WHERE NOT seen)::text     AS unseen
           FROM expired_domain_leads`,
        ),
      ]);
      return res.json({
        byLength: byLen,
        byTld,
        total:   parseInt(totRow?.total   ?? "0"),
        starred: parseInt(totRow?.starred ?? "0"),
        unseen:  parseInt(totRow?.unseen  ?? "0"),
      });
    }

    // ── List endpoint ────────────────────────────────────────────────────────
    const page      = Math.max(1, parseInt(String(req.query.page  ?? "1")));
    const limit     = Math.min(200, Math.max(10, parseInt(String(req.query.limit ?? "50"))));
    const offset    = (page - 1) * limit;
    const exactLen  = parseInt(String(req.query.exactLen ?? "0")) || 0;
    const maxLen    = parseInt(String(req.query.maxLen   ?? "0")) || 0;
    const minBl     = parseInt(String(req.query.minBl    ?? "0")) || 0;
    const tld       = String(req.query.tld     ?? "").trim().toLowerCase();
    const prefix    = String(req.query.prefix  ?? "").trim().toLowerCase();
    const onlyStar  = req.query.starred === "1";
    const onlyNew   = req.query.unseen  === "1";
    const sort      = String(req.query.sort ?? "value"); // value | newest | longest

    const conditions: string[] = [];
    const params: (string | number | boolean)[] = [];
    let idx = 1;

    if (exactLen > 0) { conditions.push(`char_count = $${idx++}`);    params.push(exactLen); }
    else if (maxLen > 0) { conditions.push(`char_count <= $${idx++}`); params.push(maxLen); }
    if (minBl > 0)    { conditions.push(`bl >= $${idx++}`);           params.push(minBl); }
    if (tld)          { conditions.push(`tld = $${idx++}`);           params.push(tld); }
    if (prefix)       { conditions.push(`sld LIKE $${idx++}`);        params.push(`${prefix}%`); }
    if (onlyStar)     { conditions.push(`starred = true`); }
    if (onlyNew)      { conditions.push(`seen = false`); }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const orderBy = sort === "newest"  ? "crawled_at DESC"
                  : sort === "longest" ? "char_count DESC, bl DESC NULLS LAST"
                  : sort === "bl"      ? "bl DESC NULLS LAST, char_count ASC"
                  : sort === "dp"      ? "dp DESC NULLS LAST, char_count ASC"
                  :                     "char_count ASC, bl DESC NULLS LAST, crawled_at DESC"; // default: value

    const [rows, countRow] = await Promise.all([
      many<{
        id: number; domain: string; tld: string; sld: string; char_count: number;
        bl: number | null; dp: number | null; deleted_date: string | null;
        available_date: string | null; status: string; seen: boolean; starred: boolean;
        notes: string | null; crawled_at: string;
      }>(
        `SELECT * FROM expired_domain_leads ${where}
         ORDER BY ${orderBy}
         LIMIT $${idx++} OFFSET $${idx++}`,
        [...params, limit, offset],
      ),
      one<{ total: string }>(
        `SELECT COUNT(*)::text AS total FROM expired_domain_leads ${where}`,
        params,
      ),
    ]);

    const total = parseInt(countRow?.total ?? "0");
    return res.json({ leads: rows, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
  }

  // ── POST: trigger crawl ────────────────────────────────────────────────────
  if (req.method === "POST" && action === "crawl") {
    const settings = await getSettings([
      "expireddomains_username",
      "expireddomains_password",
      "expireddomains_max_length",
      "expireddomains_min_length",
      "expireddomains_tld_filter",
      "expireddomains_rows",
      "expireddomains_prefix_list",
    ]);

    const username = settings.expireddomains_username?.trim();
    const password = settings.expireddomains_password?.trim();

    if (!username || !password) {
      return res.status(400).json({ error: "expireddomains.net 账号未配置，请先在设置中填写用户名和密码" });
    }

    const tldFilter = settings.expireddomains_tld_filter?.trim() || "";
    const rows      = Math.min(500, parseInt(settings.expireddomains_rows || "200") || 200);
    const mode      = String(req.query.mode ?? "length");

    // Single-prefix crawl from the UI "crawl this prefix" button
    const singlePrefix = String(req.query.prefix ?? "").trim().toLowerCase();

    let cookieStr: string;
    try {
      cookieStr = await loginToExpiredDomains(username, password);
    } catch (err: any) {
      console.error("[expired-domains-crawl] login error:", err.message);
      return res.status(500).json({ error: err.message });
    }

    // ── Prefix mode ──────────────────────────────────────────────────────────
    if (mode === "prefix" || singlePrefix) {
      const prefixesToCrawl: string[] = singlePrefix
        ? [singlePrefix]
        : (settings.expireddomains_prefix_list || "")
            .split(",")
            .map(p => p.trim().toLowerCase())
            .filter(Boolean);

      if (!prefixesToCrawl.length) {
        return res.status(400).json({ error: "没有配置前缀列表，请在设置中添加前缀（如: ai,gpt,nft）" });
      }

      let totalInserted = 0;
      let totalUpdated  = 0;
      const results: { prefix: string; inserted: number; updated: number; count: number }[] = [];

      for (const pfx of prefixesToCrawl) {
        try {
          const r = await crawlByPrefix(cookieStr, pfx, { tldFilter, rows });
          totalInserted += r.inserted;
          totalUpdated  += r.updated;
          results.push({ prefix: pfx, inserted: r.inserted, updated: r.updated, count: r.leads.length });
        } catch (err: any) {
          console.error(`[expired-domains-crawl] prefix "${pfx}" error:`, err.message);
          results.push({ prefix: pfx, inserted: 0, updated: 0, count: -1 });
        }
      }

      return res.json({ ok: true, mode: "prefix", inserted: totalInserted, updated: totalUpdated, results });
    }

    // ── Length mode (default) ────────────────────────────────────────────────
    const maxLen = parseInt(settings.expireddomains_max_length || "4") || 4;
    const minLen = parseInt(settings.expireddomains_min_length || "1") || 1;

    try {
      const result = await crawlByLength(cookieStr, { minLen, maxLen, tldFilter, rows });
      return res.json({ ok: true, mode: "length", ...result });
    } catch (err: any) {
      console.error("[expired-domains-crawl]", err.message);
      return res.status(500).json({ error: err.message });
    }
  }

  // ── PATCH: update a lead ───────────────────────────────────────────────────
  if (req.method === "PATCH") {
    const { id, seen, starred, notes } = req.body ?? {};
    if (!id) return res.status(400).json({ error: "id 必填" });

    const updates: string[] = [];
    const params: (string | boolean | null | number)[] = [];
    let idx = 1;

    if (seen    !== undefined) { updates.push(`seen    = $${idx++}`); params.push(Boolean(seen)); }
    if (starred !== undefined) { updates.push(`starred = $${idx++}`); params.push(Boolean(starred)); }
    if (notes   !== undefined) { updates.push(`notes   = $${idx++}`); params.push(notes ?? null); }
    if (!updates.length)       return res.status(400).json({ error: "no fields" });

    params.push(Number(id));
    await run(`UPDATE expired_domain_leads SET ${updates.join(", ")} WHERE id = $${idx}`, params);
    return res.json({ ok: true });
  }

  // ── DELETE ─────────────────────────────────────────────────────────────────
  if (req.method === "DELETE") {
    if (action === "clear") {
      await run("DELETE FROM expired_domain_leads");
      return res.json({ ok: true });
    }
    if (action === "clear_prefix") {
      const pfx = String(req.query.prefix ?? "").trim().toLowerCase();
      if (!pfx) return res.status(400).json({ error: "prefix 必填" });
      const n = await run("DELETE FROM expired_domain_leads WHERE sld LIKE $1", [`${pfx}%`]);
      return res.json({ ok: true, deleted: n });
    }
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "id 必填" });
    await run("DELETE FROM expired_domain_leads WHERE id = $1", [Number(id)]);
    return res.json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
