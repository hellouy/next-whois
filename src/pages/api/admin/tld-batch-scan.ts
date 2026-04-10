/**
 * Batch-scan TLDs that have no configured WHOIS/RDAP server.
 * For each TLD, tries common server patterns (TCP WHOIS and RDAP HTTP),
 * records the results, and auto-saves working servers.
 *
 * POST /api/admin/tld-batch-scan
 *   body: { tlds?: string[]; limit?: number; timeout_ms?: number }
 *
 * Returns a streaming-friendly JSON array of per-TLD scan results.
 */
import type { NextApiRequest, NextApiResponse } from "next";
import net from "net";
import { requireAdmin } from "@/lib/admin";
import { getDbReady } from "@/lib/db";

export const config = { maxDuration: 60 };

type ScanStatus = "ok" | "fail" | "skip";

export type TldScanResult = {
  tld: string;
  status: ScanStatus;
  method: string | null;
  server: string | null;
  elapsed_ms: number;
  error: string | null;
  saved: boolean;
};

function tcpQuery(host: string, port: number, query: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const socket = net.createConnection({ host, port }, () => {
      socket.write(query + "\r\n");
    });
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk: Buffer) => { data += chunk.toString(); });
    socket.on("close", () => resolve(data));
    socket.on("timeout", () => socket.destroy(new Error(`TCP timeout`)));
    socket.on("error", reject);
  });
}

async function httpGet(url: string, timeoutMs: number): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json,application/json,text/plain" },
    });
    const body = await res.text();
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

/** Generate candidate server addresses for a given TLD. */
function candidateServers(tld: string): Array<{ method: "tcp" | "http"; server: string; host?: string; port?: number; url?: string }> {
  return [
    // RDAP candidates (faster, structured)
    { method: "http", server: `https://rdap.nic.${tld}/domain/`, url: `https://rdap.nic.${tld}/domain/example.${tld}` },
    { method: "http", server: `https://rdap.${tld}/domain/`,     url: `https://rdap.${tld}/domain/example.${tld}` },
    { method: "http", server: `https://www.registry.${tld}/rdap/domain/`, url: `https://www.registry.${tld}/rdap/domain/example.${tld}` },
    // TCP WHOIS candidates
    { method: "tcp", server: `whois.nic.${tld}`,      host: `whois.nic.${tld}`,      port: 43 },
    { method: "tcp", server: `whois.${tld}`,           host: `whois.${tld}`,           port: 43 },
    { method: "tcp", server: `whois.registry.${tld}`,  host: `whois.registry.${tld}`,  port: 43 },
    { method: "tcp", server: `whois.${tld}-nic.net`,   host: `whois.${tld}-nic.net`,   port: 43 },
  ];
}

async function scanTld(tld: string, timeoutMs: number): Promise<TldScanResult> {
  const candidates = candidateServers(tld);
  const query = `example.${tld}`;

  for (const cand of candidates) {
    const start = Date.now();
    try {
      if (cand.method === "tcp" && cand.host) {
        const raw = await tcpQuery(cand.host, cand.port ?? 43, query, timeoutMs);
        const elapsed = Date.now() - start;
        if (raw && raw.trim().length > 10) {
          return { tld, status: "ok", method: "TCP WHOIS", server: cand.server, elapsed_ms: elapsed, error: null, saved: false };
        }
      } else if (cand.method === "http" && cand.url) {
        const { status, body } = await httpGet(cand.url, timeoutMs);
        const elapsed = Date.now() - start;
        if (status >= 200 && status < 400 && body.trim().length > 10) {
          return { tld, status: "ok", method: "RDAP HTTP", server: cand.server, elapsed_ms: elapsed, error: null, saved: false };
        }
      }
    } catch {
      // try next candidate
    }
  }

  return { tld, status: "fail", method: null, server: null, elapsed_ms: 0, error: "No working server found", saved: false };
}

async function saveServer(db: Awaited<ReturnType<typeof getDbReady>>, tld: string, result: TldScanResult): Promise<boolean> {
  if (!db || result.status !== "ok" || !result.server) return false;
  const client = await db.connect().catch(() => null);
  if (!client) return false;
  try {
    const isHttp = result.method === "RDAP HTTP";
    // Build an entry compatible with the custom_whois_servers JSON schema.
    const entry = isHttp
      ? JSON.stringify({ type: "rdap", url: result.server })
      : JSON.stringify({ host: result.server, port: 43 });

    // Insert/update only if no manual entry already exists (source <> 'manual').
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

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const db = await getDbReady();
  if (!db) return res.status(503).json({ error: "Database unavailable" });

  let { tlds, limit = 30, timeout_ms = 5000 } = req.body as {
    tlds?: string[];
    limit?: number;
    timeout_ms?: number;
  };

  limit      = Math.min(Math.max(limit, 1), 100);
  timeout_ms = Math.min(Math.max(timeout_ms, 2000), 10000);

  // If no specific TLDs provided, fetch from tld_fallback_stats where fail_reason is no_server/iana_fallback
  if (!tlds || tlds.length === 0) {
    const client = await db.connect();
    try {
      const { rows } = await client.query<{ tld: string }>(
        `SELECT f.tld FROM tld_fallback_stats f
         LEFT JOIN custom_whois_servers c ON c.tld = f.tld
         WHERE f.fail_reason IN ('no_server', 'iana_fallback')
           AND (f.repair_status IS NULL OR f.repair_status = 'pending')
           AND c.tld IS NULL
           AND char_length(f.tld) BETWEEN 2 AND 10
           AND f.tld ~ '^[a-z]+$'
         ORDER BY f.fail_count DESC
         LIMIT $1`,
        [limit],
      );
      tlds = rows.map(r => r.tld);
    } finally {
      client.release();
    }
  }

  if (tlds.length === 0) {
    return res.status(200).json({ results: [], message: "没有需要扫描的 TLD" });
  }

  // Scan each TLD with limited concurrency (3 at a time)
  const results: TldScanResult[] = [];
  const CONCURRENCY = 3;

  for (let i = 0; i < tlds.length; i += CONCURRENCY) {
    const batch = tlds.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(batch.map(tld => scanTld(tld, timeout_ms)));

    for (const r of batchResults) {
      if (r.status === "ok") {
        r.saved = await saveServer(db, r.tld, r);
      }
      results.push(r);
    }
  }

  const found   = results.filter(r => r.status === "ok").length;
  const saved   = results.filter(r => r.saved).length;
  const failed  = results.filter(r => r.status === "fail").length;

  return res.status(200).json({ results, summary: { total: tlds.length, found, saved, failed } });
}
