import type { NextApiRequest, NextApiResponse } from "next";
import { timingSafeEqual } from "crypto";
import { one, run, isDbReady } from "@/lib/db-query";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

const RL_LIMIT  = 20;
const RL_WINDOW = 60_000;

// ─── DoH Resolvers only (UDP port 53 is blocked in most server environments) ──

const DOH_RESOLVERS = [
  {
    name: "Google DoH",
    url: (h: string) => `https://dns.google/resolve?name=${encodeURIComponent(h)}&type=TXT`,
  },
  {
    name: "Cloudflare DoH",
    url: (h: string) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=TXT`,
  },
  {
    name: "Quad9 DoH",
    url: (h: string) => `https://dns.quad9.net:5053/dns-query?name=${encodeURIComponent(h)}&type=TXT`,
  },
  {
    name: "AdGuard DoH",
    url: (h: string) => `https://dns.adguard-dns.com/dns-query?name=${encodeURIComponent(h)}&type=TXT`,
  },
] as const;

const DOH_TIMEOUT_MS  = 8000;
const HTTP_TIMEOUT_MS = 8000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeRecord(raw: string): string {
  return raw
    .replace(/^"+|"+$/g, "")
    .replace(/"\s*"/g, "")
    .trim();
}

function tokenMatch(records: string[], expected: string): { found: boolean; exactMatch: boolean; nearMatch: boolean; matchedRecord: string | null } {
  for (const r of records) {
    const norm = normalizeRecord(r);
    if (norm === expected) return { found: true, exactMatch: true, nearMatch: false, matchedRecord: norm };
    if (norm.includes(expected)) return { found: true, exactMatch: false, nearMatch: true, matchedRecord: norm };
  }
  return { found: false, exactMatch: false, nearMatch: false, matchedRecord: null };
}

async function queryDoH(
  urlFn: (h: string) => string, host: string, timeoutMs: number
): Promise<{ records: string[]; latencyMs: number; error?: string }> {
  const start = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(urlFn(host), {
      headers: { Accept: "application/dns-json" },
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const rcode: number = data.Status ?? 0;
    if (rcode !== 0) {
      return { records: [], latencyMs: Date.now() - start, error: rcode === 3 ? "no_record" : "servfail" };
    }
    const records: string[] = ((data.Answer as any[]) || [])
      .filter((a: any) => a.type === 16)
      .map((a: any) => normalizeRecord(String(a.data)));
    return { records, latencyMs: Date.now() - start };
  } catch (err: any) {
    clearTimeout(timer);
    return {
      records: [],
      latencyMs: Date.now() - start,
      error: err.name === "AbortError" ? "timeout" : "dns_error",
    };
  }
}

async function checkHttpFile(
  domain: string, expectedValue: string
): Promise<{ found: boolean; latencyMs: number; error: string | null; url: string; nearMatch: boolean }> {
  for (const scheme of ["https", "http"] as const) {
    const url = `${scheme}://${domain}/.well-known/next-whois-verify.txt`;
    const start = Date.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    try {
      const res = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
      clearTimeout(timer);
      if (!res.ok) {
        if (scheme === "https") continue;
        return { found: false, latencyMs: Date.now() - start, error: `HTTP ${res.status}`, url, nearMatch: false };
      }
      const body = (await res.text()).trim();
      const found = body === expectedValue || body.includes(expectedValue);
      const nearMatch = !found && body.length > 0 && body.includes("next-whois-verify");
      return { found, latencyMs: Date.now() - start, error: null, url, nearMatch };
    } catch (err: any) {
      clearTimeout(timer);
      if (scheme === "https") continue;
      return {
        found: false,
        latencyMs: Date.now() - start,
        error: err.name === "AbortError" ? "timeout" : "fetch_error",
        url,
        nearMatch: false,
      };
    }
  }
  return { found: false, latencyMs: 0, error: "unreachable", url: `https://${domain}/.well-known/next-whois-verify.txt`, nearMatch: false };
}

// ─── Types ───────────────────────────────────────────────────────────────────

interface ResolverResult {
  name: string;
  proto: "doh";
  latencyMs: number;
  found: boolean;
  nearMatch: boolean;
  records: string[];
  error: string | null;
}

// ─── Handler ─────────────────────────────────────────────────────────────────

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  // Rate limiting: 20 requests per minute per IP (each verify triggers 4 DoH + 1 HTTP call)
  const { ok: allowed } = await checkRateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) return res.status(429).json({ error: "Too many requests, please try again later" });

  const { id, domain } = req.body;
  if (!id || !domain) return res.status(400).json({ error: "Missing id or domain" });

  const cleanDomain = String(domain).toLowerCase().trim();

  if (!(await isDbReady())) return res.status(503).json({ error: "Database not configured, stamp verification is currently unavailable" });

  // Admin override — use constant-time comparison to prevent timing attacks
  const adminSecretEnv = process.env.ADMIN_VERIFY_SECRET;
  const adminSecretReq = String(req.body.adminSecret || "");
  const adminMatch = adminSecretEnv && adminSecretReq &&
    adminSecretReq.length === adminSecretEnv.length &&
    timingSafeEqual(Buffer.from(adminSecretReq), Buffer.from(adminSecretEnv));
  if (adminMatch) {
    await run(
      "UPDATE stamps SET verified = true, verified_at = $1 WHERE id = $2",
      [new Date().toISOString(), id],
    );
    return res.status(200).json({ verified: true, adminOverride: true });
  }

  const stamp = await one<{ verify_token: string; verified: boolean }>(
    "SELECT verify_token, verified FROM stamps WHERE id = $1 AND domain = $2",
    [id, cleanDomain],
  );

  if (!stamp) return res.status(404).json({ error: "Stamp not found" });
  if (stamp.verified) return res.status(200).json({ verified: true, already: true });

  const verifyToken   = stamp.verify_token;
  const expectedValue = `next-whois-verify=${verifyToken}`;
  const txtHost       = `_next-whois.${cleanDomain}`;

  const [dohResults, httpResult] = await Promise.all([
    Promise.all(
      DOH_RESOLVERS.map(async (r): Promise<ResolverResult> => {
        const { records, latencyMs, error } = await queryDoH(r.url, txtHost, DOH_TIMEOUT_MS);
        const match = tokenMatch(records, expectedValue);
        return {
          name: r.name, proto: "doh", latencyMs,
          found: match.found, nearMatch: match.nearMatch,
          records: records.slice(0, 5),
          error: error ?? null,
        };
      })
    ),
    checkHttpFile(cleanDomain, expectedValue),
  ]);

  const allResolverResults = dohResults;
  const dnsVerified = allResolverResults.some(r => r.found);
  const verified    = dnsVerified || httpResult.found;

  const anyNearMatch   = allResolverResults.some(r => r.nearMatch) || httpResult.nearMatch;
  const anyRecordFound = allResolverResults.some(r => r.records.length > 0);
  const allDnsError    = allResolverResults.every(r =>
    r.error === "dns_error" || r.error === "timeout" || r.error === "servfail"
  );

  if (verified) {
    await run(
      "UPDATE stamps SET verified = true, verified_at = $1 WHERE id = $2",
      [new Date().toISOString(), id],
    );
    return res.status(200).json({
      verified: true,
      resolvers: allResolverResults,
      httpCheck: httpResult,
      txtRecord: txtHost,
    });
  }

  return res.status(200).json({
    verified: false,
    dnsError: allDnsError,
    anyNearMatch,
    anyRecordFound,
    resolvers: allResolverResults,
    httpCheck: httpResult,
    expected: expectedValue,
  });
}
