/**
 * /api/admin/tld-registry
 *
 * Scans IANA root zone pages to discover TLD registry metadata.
 * Streams results via SSE so Vercel serverless timeouts are avoided.
 *
 * GET  /api/admin/tld-registry              → list stored records from DB
 * GET  /api/admin/tld-registry?stream=1&type=cc|gtld|all|custom&tlds=jp,cn
 *                                           → SSE scan stream
 * DELETE /api/admin/tld-registry?tld=xyz   → remove one record
 * DELETE /api/admin/tld-registry?tld=__all → wipe all records
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";
import * as cheerio from "cheerio";
import { syncRegistryServer } from "@/lib/whois/custom-servers";

export const config = { maxDuration: 300 };

// ── ccTLD master list ─────────────────────────────────────────────────────────
const CC_TLDS = [
  "ac","ad","ae","af","ag","ai","al","am","ao","aq","ar","as","at","au","aw","ax","az",
  "ba","bb","bd","be","bf","bg","bh","bi","bj","bm","bn","bo","br","bs","bt","bw","by","bz",
  "ca","cc","cd","cf","cg","ch","ci","ck","cl","cm","cn","co","cr","cu","cv","cw","cx","cy","cz",
  "de","dj","dk","dm","do","dz","ec","ee","eg","er","es","et","eu",
  "fi","fj","fk","fm","fo","fr","ga","gd","ge","gf","gg","gh","gi","gl","gm","gn","gp","gq",
  "gr","gs","gt","gu","gw","gy","hk","hm","hn","hr","ht","hu",
  "id","ie","il","im","in","io","iq","ir","is","it","je","jm","jo","jp",
  "ke","kg","kh","ki","km","kn","kp","kr","kw","ky","kz",
  "la","lb","lc","li","lk","lr","ls","lt","lu","lv","ly",
  "ma","mc","md","me","mg","mh","mk","ml","mm","mn","mo","mp","mq","mr","ms","mt","mu","mv","mw","mx","my","mz",
  "na","nc","ne","nf","ng","ni","nl","no","np","nr","nu","nz",
  "om","pa","pe","pf","pg","ph","pk","pl","pm","pn","pr","ps","pt","pw","py","qa",
  "re","ro","rs","ru","rw",
  "sa","sb","sc","sd","se","sg","sh","si","sk","sl","sm","sn","so","sr","ss","st","su","sv","sx","sy","sz",
  "tc","td","tf","tg","th","tj","tk","tl","tm","tn","to","tr","tt","tv","tw","tz",
  "ua","ug","uk","us","uy","uz","va","vc","ve","vg","vi","vn","vu","wf","ws",
  "ye","yt","za","zm","zw",
];

// ── IANA page parser ──────────────────────────────────────────────────────────
export interface TldRegistryInfo {
  tld: string;
  tld_type: string | null;
  status: string | null;
  manager: string | null;
  registry_url: string | null;
  whois_server: string | null;
  country: string | null;
  address: string | null;
  nameservers: string | null;
  created_date: string | null;
  changed_date: string | null;
  iana_url: string;
  scan_error: string | null;
}

function normalizeUrl(raw: string): string | null {
  if (!raw) return null;
  const s = raw.trim().replace(/\/$/, "");
  if (!s) return null;
  try {
    const u = new URL(s.startsWith("http") ? s : "https://" + s);
    return u.origin;
  } catch {
    return s;
  }
}

export async function parseIanaPage(tld: string): Promise<TldRegistryInfo> {
  const iana_url = `https://www.iana.org/domains/root/db/${tld}.html`;
  const info: TldRegistryInfo = {
    tld, tld_type: null, status: null, manager: null,
    registry_url: null, whois_server: null, country: null,
    address: null, nameservers: null, created_date: null,
    changed_date: null, iana_url, scan_error: null,
  };

  try {
    const resp = await fetch(iana_url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; next-whois-ui/3.23 IANA-crawler; +https://x.rw)",
        Accept: "text/html,*/*;q=0.9",
      },
      signal: AbortSignal.timeout(14_000),
    });

    if (resp.status === 404) {
      info.status = "not-delegated";
      info.scan_error = "404 Not Found";
      return info;
    }
    if (!resp.ok) {
      info.scan_error = `HTTP ${resp.status}`;
      return info;
    }

    const html = await resp.text();
    const $ = cheerio.load(html);

    // --- Parse key-value pairs from the IANA table ---
    // IANA uses: <tr><td><b>Key</b></td><td>value / <a href>link</a></td></tr>
    const kv: Record<string, string> = {};
    const kvLinks: Record<string, string> = {};

    $("table tr").each((_, tr) => {
      const cells = $(tr).find("td");
      if (cells.length < 2) return;
      const rawKey = cells.eq(0).find("b").first().text().trim()
        || cells.eq(0).text().trim();
      const key = rawKey.toLowerCase().replace(/:$/, "").replace(/\s+/g, " ").trim();
      if (!key) return;
      const valCell = cells.eq(1);
      kv[key] = valCell.text().replace(/\s+/g, " ").trim();
      const href = valCell.find("a[href]").first().attr("href") || "";
      if (href) kvLinks[key] = href;
    });

    // Also try <th>/<td> format
    $("table tr").each((_, tr) => {
      const th = $(tr).find("th").first();
      const td = $(tr).find("td").first();
      if (!th.length || !td.length) return;
      const key = th.text().toLowerCase().replace(/:$/, "").replace(/\s+/g, " ").trim();
      if (!key || kv[key]) return;
      kv[key] = td.text().replace(/\s+/g, " ").trim();
      const href = td.find("a[href]").first().attr("href") || "";
      if (href) kvLinks[key] = href;
    });

    // Populate fields from parsed key-value map
    info.tld_type   = kv["type"] || kv["tld type"] || null;
    info.status     = kv["status"] || null;
    info.manager    = kv["organisation"] || kv["organization"] || kv["registrant"] || kv["manager"] || null;
    info.country    = kv["country"] || null;
    info.address    = kv["address"] ? kv["address"].slice(0, 300) : null;
    info.whois_server = kv["whois server"] || kv["whois"] || null;
    info.created_date = kv["created"] || kv["registration date"] || null;
    info.changed_date = kv["changed"] || kv["last updated"] || kv["modified"] || null;

    // Nameservers — may be in "nameservers" or "name servers" or "dns"
    const nsRaw = kv["nameservers"] || kv["name servers"] || kv["dns servers"] || "";
    info.nameservers = nsRaw ? nsRaw.slice(0, 500) : null;

    // Registry URL — try "registry" link first (ccTLD format), then "url for registration services" (gTLD format)
    const registryKey = Object.keys(kvLinks).find(k => k === "registry" || k === "url for registration services" || k === "registration url");
    if (registryKey) {
      info.registry_url = normalizeUrl(kvLinks[registryKey]);
    }

    // Fallback: regex patterns for both formats in raw HTML
    if (!info.registry_url) {
      const m1 = html.match(/<b>URL for registration services:<\/b>\s*<a[^>]+href="([^"]+)"/i)
               || html.match(/URL for registration services[^<]*<a[^>]+href="([^"]+)"/i);
      if (m1) info.registry_url = normalizeUrl(m1[1]);
    }
    if (!info.registry_url) {
      const m2 = html.match(/<b>Registry<\/b><\/td>\s*<td[^>]*><a[^>]+href="([^"]+)"/i)
               || html.match(/Registry<\/b>[^<]*<a[^>]+href="([^"]+)"/i);
      if (m2) info.registry_url = normalizeUrl(m2[1]);
    }

    // Normalize type label
    if (info.tld_type) {
      const t = info.tld_type.toLowerCase();
      if (t.includes("country")) info.tld_type = "country-code";
      else if (t.includes("sponsored")) info.tld_type = "sponsored";
      else if (t.includes("infrastructure")) info.tld_type = "infrastructure";
      else if (t.includes("not assigned")) info.tld_type = "not-assigned";
      else if (t.includes("test")) info.tld_type = "test";
      else if (t.includes("generic-restricted") || t.includes("restricted")) info.tld_type = "generic-restricted";
      else if (t.includes("generic")) info.tld_type = "generic";
    }

    // If still no type, infer from TLD length
    if (!info.tld_type) {
      info.tld_type = tld.length === 2 ? "country-code" : "generic";
    }

    // Infer status from page content
    if (!info.status) {
      const lower = html.toLowerCase();
      if (lower.includes("not delegated")) info.status = "not-delegated";
      else if (lower.includes("terminated")) info.status = "terminated";
      else if (info.registry_url || info.manager) info.status = "active";
    }

  } catch (e: any) {
    info.scan_error = (e.message || "Unknown error").slice(0, 200);
  }

  return info;
}

// ── DB helpers ────────────────────────────────────────────────────────────────
async function upsertInfo(db: import("pg").Pool, info: TldRegistryInfo) {
  await db.query(
    `INSERT INTO tld_registry_info
       (tld, tld_type, status, manager, registry_url, whois_server,
        country, address, nameservers, created_date, changed_date, iana_url,
        scan_error, scraped_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
     ON CONFLICT (tld) DO UPDATE SET
       tld_type=$2, status=$3, manager=$4, registry_url=$5, whois_server=$6,
       country=$7, address=$8, nameservers=$9, created_date=$10,
       changed_date=$11, iana_url=$12, scan_error=$13,
       scraped_at=NOW(), updated_at=NOW()`,
    [
      info.tld, info.tld_type, info.status, info.manager, info.registry_url,
      info.whois_server, info.country, info.address, info.nameservers,
      info.created_date, info.changed_date, info.iana_url, info.scan_error,
    ]
  );
}

// ── Batch runner with concurrency ─────────────────────────────────────────────
async function processBatch(
  tlds: string[],
  concurrency: number,
  onResult: (info: TldRegistryInfo, index: number, total: number) => Promise<void>
) {
  let idx = 0;
  const total = tlds.length;

  async function worker() {
    while (idx < total) {
      const i = idx++;
      const info = await parseIanaPage(tlds[i]);
      await onResult(info, i, total);
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
}

// ── Handler ───────────────────────────────────────────────────────────────────
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  // ── DELETE: remove records ───────────────────────────────────────────────
  if (req.method === "DELETE") {
    const tld = (req.query.tld as string) || "";
    if (tld === "__all") {
      await db.query("DELETE FROM tld_registry_info");
      return res.json({ ok: true, message: "All records deleted" });
    }
    if (tld) {
      await db.query("DELETE FROM tld_registry_info WHERE tld=$1", [tld.toLowerCase().replace(/^\./, "")]);
      return res.json({ ok: true, message: `Deleted .${tld}` });
    }
    return res.status(400).json({ error: "tld param required" });
  }

  // ── GET list: return stored records ──────────────────────────────────────
  if (req.method === "GET" && !req.query.stream) {
    const rows = await db.query(
      `SELECT tld, tld_type, status, manager, registry_url, whois_server,
              country, nameservers, created_date, changed_date, iana_url,
              probe_result, probe_method, probe_latency_ms, probed_at,
              scan_error, scraped_at, updated_at
       FROM tld_registry_info
       ORDER BY tld ASC`
    );
    const statsRow = await db.query(
      `SELECT
         COUNT(*) as total,
         COUNT(*) FILTER (WHERE tld_type='country-code') as cc,
         COUNT(*) FILTER (WHERE tld_type='generic') as generic,
         COUNT(*) FILTER (WHERE tld_type='sponsored') as sponsored,
         COUNT(*) FILTER (WHERE registry_url IS NOT NULL) as with_registry,
         COUNT(*) FILTER (WHERE whois_server IS NOT NULL) as with_whois,
         MAX(scraped_at) as last_scan
       FROM tld_registry_info`
    );
    return res.json({ records: rows.rows, stats: statsRow.rows[0] });
  }

  // ── GET stream: SSE scan ──────────────────────────────────────────────────
  if (req.method === "GET" && req.query.stream) {
    const type       = (req.query.type as string) || "cc";
    const force      = req.query.force === "1";
    const concur     = Math.min(parseInt((req.query.concur as string) || "15", 10), 30);
    const syncServers = req.query.syncServers === "1";
    const customRaw  = (req.query.tlds as string) || "";

    // Build TLD list
    let tldList: string[] = [];
    if (type === "custom" && customRaw) {
      tldList = customRaw.split(/[\s,，]+/).map(t => t.trim().toLowerCase().replace(/^\./, "")).filter(Boolean);
    } else if (type === "cc") {
      tldList = [...CC_TLDS];
    } else if (type === "gtld") {
      // Fetch gTLD list from IANA
      try {
        const r = await fetch("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", {
          signal: AbortSignal.timeout(15_000),
        });
        const text = await r.text();
        tldList = text.split("\n")
          .map(l => l.trim().toLowerCase())
          .filter(t => t && !t.startsWith("#") && t.length > 2 && !t.startsWith("xn--"));
      } catch {
        tldList = ["com","net","org","info","biz","xyz","app","dev","shop","blog","tech","online","site","store","club","co","io","ai","gg","ltd","vip","top","cloud","pro","media","digital","global"];
      }
    } else if (type === "all") {
      tldList = [...CC_TLDS];
      try {
        const r = await fetch("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", {
          signal: AbortSignal.timeout(15_000),
        });
        const text = await r.text();
        const gtlds = text.split("\n")
          .map(l => l.trim().toLowerCase())
          .filter(t => t && !t.startsWith("#") && t.length > 2 && !t.startsWith("xn--"));
        tldList = [...new Set([...tldList, ...gtlds])];
      } catch {}
    }

    // Skip already-scanned unless force
    if (!force) {
      const existing = await db.query("SELECT tld FROM tld_registry_info WHERE scan_error IS NULL");
      const done = new Set(existing.rows.map((r: { tld: string }) => r.tld));
      tldList = tldList.filter(t => !done.has(t));
    }

    tldList = [...new Set(tldList)];
    const total = tldList.length;

    // Set up SSE
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders();

    const send = (event: string, data: object) => {
      try {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        (res as any).flush?.();
      } catch {}
    };

    // Heartbeat to keep connection alive
    const hb = setInterval(() => {
      try { res.write(": heartbeat\n\n"); (res as any).flush?.(); } catch {}
    }, 8_000);

    send("start", { total, type, force, syncServers });

    let done = 0, errors = 0;
    let serverAdded = 0, serverUpdated = 0, serverConflict = 0;

    try {
      await processBatch(tldList, concur, async (info, _i, _total) => {
        // Upsert into DB
        try {
          await upsertInfo(db, info);
        } catch {}

        // Sync WHOIS server to custom_whois_servers if requested
        if (syncServers && info.whois_server && !info.scan_error) {
          try {
            const syncResult = await syncRegistryServer(info.tld, info.whois_server);
            if (syncResult.action === "added")    { serverAdded++;    send("server_sync", { tld: info.tld, ...syncResult, serverAdded, serverUpdated, serverConflict }); }
            if (syncResult.action === "updated")  { serverUpdated++;  send("server_sync", { tld: info.tld, ...syncResult, serverAdded, serverUpdated, serverConflict }); }
            if (syncResult.action === "conflict") { serverConflict++; send("server_sync", { tld: info.tld, ...syncResult, serverAdded, serverUpdated, serverConflict }); }
            // unchanged/skipped → silent
          } catch {}
        }

        done++;
        if (info.scan_error) errors++;

        send("result", {
          ...info,
          done,
          total,
          errors,
        });
      });
    } catch (e: any) {
      send("error", { message: e.message });
    }

    clearInterval(hb);
    send("done", { done, total, errors, serverAdded, serverUpdated, serverConflict });
    res.end();
    return;
  }

  res.setHeader("Allow", "GET, DELETE");
  return res.status(405).json({ error: "Method not allowed" });
}
