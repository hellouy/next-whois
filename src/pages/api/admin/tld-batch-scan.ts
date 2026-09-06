/**
 * Batch-scan TLDs that have no configured WHOIS/RDAP server.
 * For each TLD, tries multiple discovery strategies in priority order:
 *   1. IANA RDAP bootstrap (data.iana.org/rdap/dns.json) — official
 *   2. IANA WHOIS referral (whois.iana.org TCP query) — most reliable
 *   3. Common RDAP URL patterns (rdap.nic.{tld}, rdap.{tld}, etc.)
 *   4. Common TCP WHOIS hostname patterns
 * Records the results and auto-saves working servers to custom_whois_servers.
 *
 * POST /api/admin/tld-batch-scan
 *   body: { tlds?: string[]; limit?: number; timeout_ms?: number }
 */
import type { NextApiRequest, NextApiResponse } from "next";
import net from "net";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export const config = { maxDuration: 60 };

type ScanStatus = "ok" | "fail";

export type TldScanResult = {
  tld: string;
  status: ScanStatus;
  method: string | null;
  server: string | null;
  elapsed_ms: number;
  error: string | null;
  saved: boolean;
  discovery: string | null;
};

// ── IANA bootstrap cache (1 h TTL) ────────────────────────────────────────
let bootstrapCache: Record<string, string[]> | null = null;
let bootstrapFetchedAt = 0;

async function getIanaRdapBootstrap(): Promise<Record<string, string[]>> {
  if (bootstrapCache && Date.now() - bootstrapFetchedAt < 3_600_000) return bootstrapCache;
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch("https://data.iana.org/rdap/dns.json", { signal: ctrl.signal });
    const json = await res.json() as {
      services: [string[][], string[]][];
    };
    const map: Record<string, string[]> = {};
    for (const [[tlds], urls] of json.services) {
      for (const tld of tlds) {
        map[tld.toLowerCase().replace(/^\./, "")] = urls;
      }
    }
    bootstrapCache = map;
    bootstrapFetchedAt = Date.now();
    return map;
  } catch {
    return bootstrapCache ?? {};
  }
}

// ── IANA WHOIS referral query ─────────────────────────────────────────────
async function ianaWhoisReferral(tld: string, timeoutMs: number): Promise<string | null> {
  return new Promise(resolve => {
    let data = "";
    const socket = net.createConnection({ host: "whois.iana.org", port: 43 }, () => {
      socket.write(tld + "\r\n");
    });
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    socket.on("close", () => {
      // Parse "whois: whois.example.com" line
      const match = data.match(/whois:\s+(\S+)/i);
      resolve(match ? match[1].toLowerCase().trim() : null);
    });
    socket.on("timeout", () => { socket.destroy(); resolve(null); });
    socket.on("error", () => resolve(null));
  });
}

// ── TCP WHOIS probe ───────────────────────────────────────────────────────
function tcpQuery(host: string, port: number, query: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const socket = net.createConnection({ host, port }, () => {
      socket.write(query + "\r\n");
    });
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    socket.on("close", () => resolve(data));
    socket.on("timeout", () => socket.destroy(new Error("TCP timeout")));
    socket.on("error", reject);
  });
}

// ── HTTP / RDAP probe ─────────────────────────────────────────────────────
async function httpGet(url: string, timeoutMs: number): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json,application/json" },
    });
    const body = await res.text();
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

// Validate that a TCP WHOIS response contains meaningful data
function isValidWhoisResponse(raw: string): boolean {
  if (!raw || raw.trim().length < 20) return false;
  const lower = raw.toLowerCase();
  // Must NOT be pure error responses
  const errorPatterns = ["no match", "not found", "no data", "error:", "query refused", "rate limit", "access denied"];
  // If it contains useful field markers, it's valid
  const goodPatterns = ["whois:", "domain:", "registrar:", "status:", "name server", "nserver", "registered", "created", "expir", "contact"];
  const hasGood = goodPatterns.some(p => lower.includes(p));
  const allBad  = errorPatterns.every(p => lower.includes(p));
  // Accept if it has good patterns OR (non-empty and not all error patterns)
  return hasGood || (!allBad && raw.trim().length > 50);
}

// Validate RDAP JSON response
function isValidRdapResponse(body: string, status: number): boolean {
  if (status === 404) return false; // domain not found is still a valid server!
  if (status < 200 || (status >= 400 && status !== 404)) return false;
  try {
    const json = JSON.parse(body);
    // Valid RDAP: has objectClassName or links or notices (even error responses are valid servers)
    return !!(json.objectClassName || json.links || json.notices || json.ldhName || json.handle || json.rdapConformance || json.errorCode);
  } catch {
    // Not JSON — not RDAP
    return false;
  }
}

// ── Main scan logic per TLD ───────────────────────────────────────────────
async function scanTld(tld: string, timeoutMs: number, rdapBootstrap: Record<string, string[]>): Promise<TldScanResult> {
  const domainQuery = `example.${tld}`;
  const tcpTimeout  = Math.min(timeoutMs, 6000);
  const httpTimeout = Math.min(timeoutMs, 8000);

  // ── Strategy 1: IANA RDAP bootstrap (most authoritative) ─────────────
  const bootstrapUrls = rdapBootstrap[tld] ?? [];
  for (const baseUrl of bootstrapUrls) {
    const url = `${baseUrl.replace(/\/$/, "")}/domain/${domainQuery}`;
    const start = Date.now();
    try {
      const { status, body } = await httpGet(url, httpTimeout);
      const elapsed = Date.now() - start;
      if (isValidRdapResponse(body, status)) {
        const server = baseUrl.replace(/\/$/, "");
        return { tld, status: "ok", method: "RDAP (IANA bootstrap)", server, elapsed_ms: elapsed, error: null, saved: false, discovery: "iana_bootstrap" };
      }
    } catch { /* try next */ }
  }

  // ── Strategy 2: IANA WHOIS referral ──────────────────────────────────
  const referralHost = await ianaWhoisReferral(tld, Math.min(timeoutMs, 5000));
  if (referralHost && referralHost !== "whois.iana.org") {
    const start = Date.now();
    try {
      const raw = await tcpQuery(referralHost, 43, domainQuery, tcpTimeout);
      const elapsed = Date.now() - start;
      if (isValidWhoisResponse(raw)) {
        return { tld, status: "ok", method: "WHOIS (IANA referral)", server: referralHost, elapsed_ms: elapsed, error: null, saved: false, discovery: "iana_referral" };
      }
    } catch { /* fall through */ }
  }

  // ── Strategy 3: Common RDAP patterns ─────────────────────────────────
  const rdapCandidates = [
    `https://rdap.nic.${tld}/domain/${domainQuery}`,
    `https://rdap.${tld}/domain/${domainQuery}`,
    `https://www.registry.${tld}/rdap/domain/${domainQuery}`,
    `https://registry.${tld}/rdap/domain/${domainQuery}`,
    `https://rdap.registry.${tld}/domain/${domainQuery}`,
  ];
  for (const url of rdapCandidates) {
    const baseServer = url.replace(/\/domain\/.*$/, "");
    const start = Date.now();
    try {
      const { status, body } = await httpGet(url, httpTimeout);
      const elapsed = Date.now() - start;
      if (isValidRdapResponse(body, status)) {
        return { tld, status: "ok", method: "RDAP HTTP", server: baseServer, elapsed_ms: elapsed, error: null, saved: false, discovery: "pattern" };
      }
    } catch { /* try next */ }
  }

  // ── Strategy 4: Common TCP WHOIS patterns ────────────────────────────
  const tcpCandidates = [
    `whois.nic.${tld}`,
    `whois.${tld}`,
    `whois.registry.${tld}`,
    `whois.${tld}-nic.net`,
    `whois.${tld}-nic.com`,
    ...(referralHost && referralHost !== "whois.iana.org" ? [referralHost] : []),
  ];
  for (const host of tcpCandidates) {
    const start = Date.now();
    try {
      const raw = await tcpQuery(host, 43, domainQuery, tcpTimeout);
      const elapsed = Date.now() - start;
      if (isValidWhoisResponse(raw)) {
        return { tld, status: "ok", method: "TCP WHOIS", server: host, elapsed_ms: elapsed, error: null, saved: false, discovery: "pattern" };
      }
    } catch { /* try next */ }
  }

  return { tld, status: "fail", method: null, server: null, elapsed_ms: 0, error: "No working server found via any strategy", saved: false, discovery: null };
}

// ── Save a working server to DB ───────────────────────────────────────────
async function saveServer(db: Awaited<ReturnType<typeof getDbReady>>, tld: string, result: TldScanResult): Promise<boolean> {
  if (!db || result.status !== "ok" || !result.server) return false;
  const client = await db.connect().catch(() => null);
  if (!client) return false;
  try {
    const isRdap = result.method?.includes("RDAP");
    const entry = isRdap
      ? JSON.stringify({ type: "rdap", url: result.server })
      : JSON.stringify({ host: result.server, port: 43 });

    // Don't overwrite manual entries
    await client.query(
      `INSERT INTO custom_whois_servers (tld, entry, source, updated_at)
       VALUES ($1, $2::jsonb, 'repair', NOW())
       ON CONFLICT (tld) DO UPDATE
         SET entry = EXCLUDED.entry, source = 'repair', updated_at = NOW()
         WHERE custom_whois_servers.source <> 'manual'`,
      [tld, entry],
    );

    await client.query(
      `UPDATE tld_fallback_stats
       SET repair_status = 'fixed', found_server = $2, repaired_at = NOW()
       WHERE tld = $1`,
      [tld, result.server],
    );
    return true;
  } catch {
    return false;
  } finally {
    client.release();
  }
}

// ── Handler ───────────────────────────────────────────────────────────────
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  let { tlds, limit = 30, timeout_ms = 6000, source = "failed" } = req.body as {
    tlds?: string[];
    limit?: number;
    timeout_ms?: number;
    source?: "failed" | "uncovered";
  };

  limit      = Math.min(Math.max(limit, 1), 100);
  timeout_ms = Math.min(Math.max(timeout_ms, 3000), 15000);

  // Fetch IANA bootstrap in parallel with DB query
  const [rdapBootstrap, fromDb] = await Promise.all([
    getIanaRdapBootstrap(),
    (async () => {
      if (tlds && tlds.length > 0) return [] as string[];
      const client = await db.connect();
      try {
        let query: string;
        if (source === "uncovered") {
          // TLDs in tld_rules that have never been queried (no failure stats, no custom server)
          query = `
            SELECT r.tld FROM tld_rules r
            LEFT JOIN tld_fallback_stats f ON f.tld = r.tld
            LEFT JOIN custom_whois_servers c ON c.tld = r.tld
            WHERE f.tld IS NULL
              AND c.tld IS NULL
              AND char_length(r.tld) BETWEEN 2 AND 10
              AND r.tld ~ '^[a-z]+'
            ORDER BY r.tld
            LIMIT $1`;
        } else {
          // Default: failed TLDs with no repair attempted
          // Metric source = tld_failure_events (R5; fail_count is frozen).
          query = `
            SELECT ev.tld FROM (
              SELECT tld, COUNT(*) AS cnt
              FROM tld_failure_events
              WHERE created_at > NOW() - INTERVAL '90 days'
              GROUP BY tld
            ) ev
            LEFT JOIN tld_fallback_stats f ON f.tld = ev.tld
            LEFT JOIN custom_whois_servers c ON c.tld = ev.tld
            WHERE (f.repair_status IS NULL OR f.repair_status = 'pending')
              AND c.tld IS NULL
              AND char_length(ev.tld) BETWEEN 2 AND 10
              AND ev.tld ~ '^[a-z]+$'
            ORDER BY ev.cnt DESC
            LIMIT $1`;
        }
        const { rows } = await client.query<{ tld: string }>(query, [limit]);
        return rows.map(r => r.tld);
      } finally {
        client.release();
      }
    })(),
  ]);

  const targetTlds = (tlds && tlds.length > 0)
    ? tlds.map(t => t.trim().toLowerCase().replace(/^\./, "")).filter(Boolean).slice(0, 100)
    : fromDb;

  if (targetTlds.length === 0) {
    return res.status(200).json({ results: [], summary: { total: 0, found: 0, saved: 0, failed: 0 }, message: "没有需要扫描的 TLD" });
  }

  // Scan with limited concurrency (3 at a time to avoid connection flooding)
  const results: TldScanResult[] = [];
  const CONCURRENCY = 3;

  for (let i = 0; i < targetTlds.length; i += CONCURRENCY) {
    const batch = targetTlds.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(tld => scanTld(tld, timeout_ms, rdapBootstrap)));
    for (const r of batchResults) {
      if (r.status === "ok") r.saved = await saveServer(db, r.tld, r);
      results.push(r);
    }
  }

  const found  = results.filter(r => r.status === "ok").length;
  const saved  = results.filter(r => r.saved).length;
  const failed = results.filter(r => r.status === "fail").length;

  return res.status(200).json({
    results,
    summary: { total: targetTlds.length, found, saved, failed },
  });
}
