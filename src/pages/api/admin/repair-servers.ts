/**
 * Admin API — TLD Server Repair Queue
 *
 * GET    /api/admin/repair-servers               → list pending / recent repair records
 * POST   /api/admin/repair-servers               → trigger repair for queued TLDs
 * POST   /api/admin/repair-servers?reset=1       → reset all not_found → pending
 * DELETE /api/admin/repair-servers?tld=xx        → mark a TLD as ignored
 */
import type { NextApiRequest, NextApiResponse } from "next";
import net from "net";
import { getServerSession } from "next-auth";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, run, isDbReady } from "@/lib/db-query";
import { setCustomServer } from "@/lib/whois/custom-servers";
import { markTldRepaired, markTldNotFound, markTldIgnored } from "@/lib/whois/server-failure-tracker";
import { callProviderWithFallback } from "@/lib/server/ai-providers";

async function isAdmin(req: NextApiRequest, res: NextApiResponse): Promise<boolean> {
  const session = await getServerSession(req, res, authOptions);
  const adminEmails = (process.env.ADMIN_EMAILS ?? "").split(",").map(e => e.trim()).filter(Boolean);
  const email = (session?.user as any)?.email ?? "";
  return adminEmails.length > 0 && adminEmails.includes(email);
}

// ── RDAP bootstrap (cached 1 h) ────────────────────────────────────────────────
let _rdapMap: Record<string, string> | null = null;
let _rdapMapAt = 0;

async function getRdapBootstrap(): Promise<Record<string, string>> {
  if (_rdapMap && Date.now() - _rdapMapAt < 3_600_000) return _rdapMap;
  try {
    const res = await fetch("https://data.iana.org/rdap/dns.json", {
      headers: { "User-Agent": "xrw-admin-repair/1.0" },
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json() as { services: [string[], string[]][] };
    const map: Record<string, string> = {};
    for (const [tlds, urls] of json.services ?? []) {
      const url = urls[0]; if (!url) continue;
      for (const tld of tlds) map[tld.toLowerCase()] = url;
    }
    _rdapMap = map; _rdapMapAt = Date.now();
    return map;
  } catch { return _rdapMap ?? {}; }
}

// ── TCP helpers ────────────────────────────────────────────────────────────────
function queryWhoisTcp(host: string, query: string, timeoutMs = 7_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port: 43 });
    let data = "";
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("TCP timeout")); }, timeoutMs);
    sock.once("connect", () => sock.write(query + "\r\n"));
    sock.on("data", chunk => { data += chunk.toString("utf8"); });
    sock.once("end", () => { clearTimeout(timer); resolve(data); });
    sock.once("error", e => { clearTimeout(timer); reject(e); });
  });
}

function tcpPing(host: string, timeoutMs = 6_000): Promise<boolean> {
  return new Promise(resolve => {
    const sock = net.createConnection({ host, port: 43 });
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, timeoutMs);
    sock.once("connect", () => { clearTimeout(timer); sock.destroy(); resolve(true); });
    sock.once("error", () => { clearTimeout(timer); resolve(false); });
  });
}

async function getIanaWhoisReferral(tld: string): Promise<string | null> {
  try {
    const raw = await queryWhoisTcp("whois.iana.org", tld, 8_000);
    const m = raw.match(/^refer:\s*(\S+)/im);
    return m ? m[1].trim().toLowerCase() : null;
  } catch { return null; }
}

// ── RDAP HTTP validation ───────────────────────────────────────────────────────
async function validateRdap(baseUrl: string, tld: string): Promise<boolean> {
  try {
    const url = `${baseUrl.replace(/\/$/, "")}/domain/example.${tld}`;
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json,application/json" },
      signal: AbortSignal.timeout(6_000),
    });
    return res.status === 200 || res.status === 404;
  } catch { return false; }
}

// ── AI lookup ──────────────────────────────────────────────────────────────────
async function aiLookupServer(tld: string): Promise<{ type: string; server: string | null; notes: string } | null> {
  try {
    const { content } = await callProviderWithFallback([
      {
        role: "system",
        content: `You are a WHOIS/RDAP expert. Respond ONLY with valid JSON:
{"type":"rdap"|"whois"|"none","server":"hostname_or_base_url_or_null","notes":"brief reason"}
- type "rdap": server is the base RDAP URL (e.g. https://rdap.nic.example/)
- type "whois": server is the TCP hostname (e.g. whois.nic.example)
- type "none": no public server exists for this TLD`,
      },
      {
        role: "user",
        content: `What is the authoritative public WHOIS (port 43) or RDAP server for the .${tld} TLD? Check IANA, ccTLD registry, and NIC.${tld}.`,
      },
    ]);
    const cleaned = content.replace(/```[a-z]*\n?/g, "").trim();
    return JSON.parse(cleaned) as { type: string; server: string | null; notes: string };
  } catch { return null; }
}

// ── Repair one TLD ─────────────────────────────────────────────────────────────
async function repairOne(tld: string): Promise<{ ok: boolean; method: string; server: string | null; error?: string }> {
  const bootstrap = await getRdapBootstrap();

  // 1. RDAP bootstrap
  const rdapUrl = bootstrap[tld];
  if (rdapUrl) {
    const valid = await validateRdap(rdapUrl, tld);
    if (valid) {
      const entry = { type: "http" as const, url: `${rdapUrl.replace(/\/$/, "")}/domain/`, method: "GET" as const };
      await setCustomServer(tld, entry);
      await markTldRepaired(tld, rdapUrl, "IANA RDAP bootstrap");
      return { ok: true, method: "rdap-bootstrap", server: rdapUrl };
    }
  }

  // 2. IANA WHOIS TCP referral
  const ianaWhois = await getIanaWhoisReferral(tld);
  if (ianaWhois) {
    const ok = await tcpPing(ianaWhois);
    if (ok) {
      await setCustomServer(tld, ianaWhois);
      await markTldRepaired(tld, ianaWhois, "IANA WHOIS TCP referral");
      return { ok: true, method: "iana-tcp", server: ianaWhois };
    }
  }

  // 3. AI lookup
  const ai = await aiLookupServer(tld);
  if (ai) {
    if (ai.type === "none") {
      await markTldNotFound(tld, `AI: ${ai.notes}`);
      return { ok: false, method: "ai-none", server: null };
    }
    if (ai.type === "rdap" && ai.server) {
      const valid = await validateRdap(ai.server, tld);
      if (valid) {
        const entry = { type: "http" as const, url: `${ai.server.replace(/\/$/, "")}/domain/`, method: "GET" as const };
        await setCustomServer(tld, entry);
        await markTldRepaired(tld, ai.server, `AI: ${ai.notes}`);
        return { ok: true, method: "ai-rdap", server: ai.server };
      }
    }
    if (ai.type === "whois" && ai.server) {
      const ok = await tcpPing(ai.server);
      if (ok) {
        await setCustomServer(tld, ai.server);
        await markTldRepaired(tld, ai.server, `AI: ${ai.notes}`);
        return { ok: true, method: "ai-whois", server: ai.server };
      }
    }
  }

  const whyFailed = [
    rdapUrl ? `RDAP bootstrap ${rdapUrl} invalid` : "",
    ianaWhois ? `IANA referral ${ianaWhois} unreachable` : "no IANA referral",
    ai ? `AI suggested ${ai.server ?? "none"}, validation failed` : "AI unavailable",
  ].filter(Boolean).join("; ");

  await markTldNotFound(tld, whyFailed);
  return { ok: false, method: "exhausted", server: null, error: whyFailed };
}

// ── Handler ────────────────────────────────────────────────────────────────────
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!(await isAdmin(req, res))) return res.status(403).json({ error: "Forbidden" });
  if (!(await isDbReady())) return res.status(503).json({ error: "DB not ready" });

  // GET — list failure records
  if (req.method === "GET") {
    const rows = await many(
      `SELECT tld, fail_count, error_type, last_failed_at, repair_status,
              found_server, ai_notes, repaired_at
       FROM   tld_server_failures
       ORDER BY
         CASE repair_status WHEN 'pending' THEN 0 WHEN 'not_found' THEN 1 ELSE 2 END,
         fail_count DESC
       LIMIT 300`,
    );
    const summary = await many(
      `SELECT repair_status, COUNT(*)::int AS count
       FROM   tld_server_failures GROUP BY repair_status ORDER BY count DESC`,
    );
    return res.json({ rows, summary });
  }

  // DELETE — ignore a TLD
  if (req.method === "DELETE") {
    const tld = (req.query.tld as string | undefined)?.toLowerCase().replace(/^\./, "");
    if (!tld) return res.status(400).json({ error: "Missing ?tld=" });
    await markTldIgnored(tld);
    return res.json({ ok: true, tld });
  }

  // POST — trigger repair or reset
  if (req.method === "POST") {
    if ("reset" in req.query) {
      await run(`UPDATE tld_server_failures SET repair_status = 'pending', repaired_at = NULL WHERE repair_status = 'not_found'`);
      return res.json({ ok: true, action: "reset" });
    }

    const limit = Math.min(parseInt((req.query.limit as string) ?? "20"), 50);
    const rows = await many<{ tld: string }>(
      `SELECT tld FROM tld_server_failures
       WHERE repair_status = 'pending' AND fail_count >= 2
       ORDER BY fail_count DESC LIMIT $1`,
      [limit],
    );

    const results: { tld: string; ok: boolean; method: string; server: string | null; error?: string }[] = [];
    for (const { tld } of rows) {
      try {
        results.push({ tld, ...(await repairOne(tld)) });
      } catch (e: any) {
        results.push({ tld, ok: false, method: "error", server: null, error: e.message });
      }
    }

    return res.json({ ok: true, processed: results.length, results });
  }

  return res.status(405).json({ error: "Method not allowed" });
}
