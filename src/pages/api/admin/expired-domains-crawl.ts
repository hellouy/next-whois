/**
 * /api/admin/expired-domains-crawl
 *
 * Crawls member.expireddomains.net for short/high-value expired domain leads
 * using the admin's stored credentials.
 *
 * GET  ?action=list      → paginated list of stored leads
 * POST ?action=crawl     → trigger a live crawl and upsert results
 * PATCH                  → update a lead (seen / starred / notes)
 * DELETE ?id=            → delete one lead
 * DELETE ?action=clear   → clear all leads
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { getSetting, getSettings } from "@/lib/server/site-settings-server";
import * as cheerio from "cheerio";

export const config = { maxDuration: 60 };

const BASE = "https://member.expireddomains.net";
const LOGIN_URL = `${BASE}/login/`;

// ── Cookie helpers ────────────────────────────────────────────────────────────

function extractCookies(res: Response): string[] {
  // Node.js 18.14+ / undici exposes getSetCookie()
  if (typeof (res.headers as any).getSetCookie === "function") {
    return (res.headers as any).getSetCookie().map((c: string) => c.split(";")[0].trim());
  }
  const raw = res.headers.get("set-cookie");
  if (!raw) return [];
  // Fallback: split on ", " boundary (works for simple cookies)
  return raw.split(/,(?=\s*\w+=)/).map((c) => c.split(";")[0].trim());
}

function cookieHeader(cookies: string[]): string {
  // Deduplicate by name (last one wins)
  const map = new Map<string, string>();
  for (const c of cookies) {
    const [name] = c.split("=");
    map.set(name.trim(), c);
  }
  return Array.from(map.values()).join("; ");
}

// ── Login ─────────────────────────────────────────────────────────────────────

async function loginToExpiredDomains(username: string, password: string): Promise<string> {
  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

  // 1. GET login page to collect cookies + CSRF token
  const getRes = await fetch(LOGIN_URL, {
    headers: { "User-Agent": ua },
    redirect: "follow",
  });
  const loginCookies = extractCookies(getRes);
  const html = await getRes.text();

  // Extract Django CSRF token
  const csrfMatch = html.match(/name=["']csrfmiddlewaretoken["']\s+value=["']([^"']+)["']/);
  const csrf = csrfMatch?.[1] ?? "";

  // 2. POST credentials
  const body = new URLSearchParams({ username, password, csrfmiddlewaretoken: csrf });
  const postRes = await fetch(LOGIN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Cookie": cookieHeader(loginCookies),
      "Referer": LOGIN_URL,
      "User-Agent": ua,
      "Origin": BASE,
    },
    body: body.toString(),
    redirect: "manual",
  });

  const postCookies = extractCookies(postRes);
  const allCookies = cookieHeader([...loginCookies, ...postCookies]);

  // Verify we got a session cookie
  if (!allCookies.includes("sessionid")) {
    throw new Error("Login failed — check your expireddomains.net username and password");
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

  // expireddomains.net listing table has id="listing"
  const table = $("#listing");
  if (!table.length) return results;

  table.find("tr").each((_, row) => {
    const cells = $(row).find("td");
    if (cells.length < 3) return;

    // Domain is in the first <td class="field_domain"> or first anchor
    const domainCell = $(row).find(".field_domain a").first();
    let domain = domainCell.text().trim().toLowerCase();

    // Fallback: first cell anchor
    if (!domain) {
      domain = $(cells.get(0)).find("a").first().text().trim().toLowerCase();
    }
    if (!domain || !domain.includes(".")) return;

    // Strip www. prefix if present
    if (domain.startsWith("www.")) domain = domain.slice(4);

    const parts = domain.split(".");
    if (parts.length < 2) return;
    const sld = parts.slice(0, parts.length - 1).join(".");
    const tld = parts[parts.length - 1];
    const char_count = sld.length;

    // Try to parse numeric columns (BL, DP are usually columns 3 & 4)
    const parseNum = (el: any): number | null => {
      const txt = $(el).text().trim().replace(/[^0-9]/g, "");
      const n = parseInt(txt, 10);
      return isNaN(n) ? null : n;
    };
    const parseDate = (el: any): string | null => {
      const txt = $(el).text().trim();
      return txt && txt !== "-" && txt !== "n/a" ? txt : null;
    };

    // Column order on expireddomains.net combinedexpired:
    // 0: domain, 1: len, 2: ACR, 3: CR, 4: BL, 5: DP, 6: Deleted, 7: Available, 8: Registered, ...
    const bl = parseNum(cells.get(4));
    const dp = parseNum(cells.get(5));
    const deleted_date = parseDate(cells.get(6));
    const available_date = parseDate(cells.get(7));

    results.push({ domain, tld, sld, char_count, bl, dp, deleted_date, available_date, status: "available" });
  });

  return results;
}

// ── Crawl logic ───────────────────────────────────────────────────────────────

async function crawl(username: string, password: string, opts: {
  maxLen: number;
  minLen: number;
  tldFilter: string;
  rows: number;
}): Promise<{ inserted: number; skipped: number; leads: ExpiredDomainRow[] }> {
  const cookieStr = await loginToExpiredDomains(username, password);

  const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

  const params = new URLSearchParams({
    o: "length",
    r: "a",
    rows: String(opts.rows),
    fl: String(opts.minLen),
    flength: String(opts.maxLen),
    filterunregistered: "yes",
  });
  if (opts.tldFilter) params.set("ftld", opts.tldFilter);

  const url = `${BASE}/domains/combinedexpired/?${params.toString()}`;
  const res = await fetch(url, {
    headers: {
      "Cookie": cookieStr,
      "User-Agent": ua,
      "Referer": `${BASE}/domains/combinedexpired/`,
    },
  });

  if (!res.ok) throw new Error(`Listing page returned HTTP ${res.status}`);

  const html = await res.text();
  const leads = parseListing(html);
  if (leads.length === 0) {
    // Check if we were redirected to login (session lost)
    if (html.includes("id_username") || html.includes("loginForm")) {
      throw new Error("Session expired or login failed — please check credentials");
    }
  }

  // Upsert into DB
  let inserted = 0;
  let skipped = 0;
  for (const lead of leads) {
    const affected = await run(
      `INSERT INTO expired_domain_leads
         (domain, tld, sld, char_count, bl, dp, deleted_date, available_date, status, source, crawled_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'expireddomains.net',NOW())
       ON CONFLICT (domain) DO UPDATE SET
         bl            = EXCLUDED.bl,
         dp            = EXCLUDED.dp,
         deleted_date  = EXCLUDED.deleted_date,
         available_date= EXCLUDED.available_date,
         crawled_at    = NOW()`,
      [lead.domain, lead.tld, lead.sld, lead.char_count, lead.bl, lead.dp,
       lead.deleted_date, lead.available_date, lead.status],
    ).catch(() => 0);
    if (affected > 0) inserted++;
    else skipped++;
  }

  return { inserted, skipped, leads };
}

// ── Handler ───────────────────────────────────────────────────────────────────

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!(await requireAdmin(req, res))) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "DB unavailable" });

  const action = req.query.action as string | undefined;

  // ── GET: list stored leads ────────────────────────────────────────────────
  if (req.method === "GET") {
    const page    = Math.max(1, parseInt(String(req.query.page  ?? "1")));
    const limit   = Math.min(200, Math.max(10, parseInt(String(req.query.limit ?? "50"))));
    const offset  = (page - 1) * limit;
    const maxLen  = parseInt(String(req.query.maxLen ?? "0")) || 0;
    const tld     = String(req.query.tld ?? "").trim().toLowerCase();
    const onlyStar= req.query.starred === "1";
    const onlyNew = req.query.unseen  === "1";

    const conditions: string[] = [];
    const params: (string | number | boolean)[] = [];
    let idx = 1;

    if (maxLen > 0) { conditions.push(`char_count <= $${idx++}`); params.push(maxLen); }
    if (tld)        { conditions.push(`tld = $${idx++}`);         params.push(tld); }
    if (onlyStar)   { conditions.push(`starred = true`); }
    if (onlyNew)    { conditions.push(`seen = false`); }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const [rows, countRow] = await Promise.all([
      many<{
        id: number; domain: string; tld: string; sld: string; char_count: number;
        bl: number | null; dp: number | null; deleted_date: string | null;
        available_date: string | null; status: string; seen: boolean; starred: boolean;
        notes: string | null; crawled_at: string;
      }>(
        `SELECT * FROM expired_domain_leads ${where} ORDER BY char_count ASC, bl DESC NULLS LAST, crawled_at DESC LIMIT $${idx++} OFFSET $${idx++}`,
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

  // ── POST: trigger crawl ───────────────────────────────────────────────────
  if (req.method === "POST" && action === "crawl") {
    const settings = await getSettings([
      "expireddomains_username",
      "expireddomains_password",
      "expireddomains_max_length",
      "expireddomains_min_length",
      "expireddomains_tld_filter",
      "expireddomains_rows",
    ]);

    const username = settings.expireddomains_username?.trim();
    const password = settings.expireddomains_password?.trim();

    if (!username || !password) {
      return res.status(400).json({ error: "expireddomains.net 账号未配置，请先在设置中填写用户名和密码" });
    }

    const maxLen    = parseInt(settings.expireddomains_max_length  || "4")  || 4;
    const minLen    = parseInt(settings.expireddomains_min_length  || "1")  || 1;
    const tldFilter = settings.expireddomains_tld_filter?.trim() || "";
    const rows      = Math.min(500, parseInt(settings.expireddomains_rows || "100") || 100);

    try {
      const result = await crawl(username, password, { maxLen, minLen, tldFilter, rows });
      return res.json({ ok: true, ...result });
    } catch (err: any) {
      console.error("[expired-domains-crawl]", err.message);
      return res.status(500).json({ error: err.message });
    }
  }

  // ── PATCH: update a lead ──────────────────────────────────────────────────
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

  // ── DELETE: remove lead(s) ────────────────────────────────────────────────
  if (req.method === "DELETE") {
    if (action === "clear") {
      await run("DELETE FROM expired_domain_leads");
      return res.json({ ok: true });
    }
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: "id 必填" });
    await run("DELETE FROM expired_domain_leads WHERE id = $1", [Number(id)]);
    return res.json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
