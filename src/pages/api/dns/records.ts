import type { NextApiRequest, NextApiResponse } from "next";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 20 };

const RL_LIMIT  = 60;
const RL_WINDOW = 60_000;

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "CAA"] as const;
type RecordType = typeof RECORD_TYPES[number];

const TYPE_NUM: Record<RecordType, number> = { A: 1, AAAA: 28, MX: 15, NS: 2, CNAME: 5, TXT: 16, SOA: 6, CAA: 257 };

const DOH_RESOLVERS = [
  { name: "Google DoH",     url: "https://dns.google/resolve",                        kind: "doh" as const },
  { name: "Cloudflare DoH", url: "https://cloudflare-dns.com/dns-query",              kind: "doh" as const },
  { name: "Quad9 DoH",      url: "https://dns.quad9.net:5053/dns-query",              kind: "doh" as const },
  { name: "AdGuard DoH",    url: "https://dns.adguard-dns.com/dns-query",             kind: "doh" as const },
];

function parseDoHData(data: string, type: RecordType): any {
  const d = data.trim();
  switch (type) {
    case "A":
    case "AAAA":
      return d;
    case "NS":
    case "CNAME":
      return d.replace(/\.$/, "");
    case "MX": {
      const sp = d.indexOf(" ");
      if (sp < 0) return { priority: 10, exchange: d.replace(/\.$/, "") };
      return { priority: parseInt(d.slice(0, sp)), exchange: d.slice(sp + 1).replace(/\.$/, "") };
    }
    case "TXT":
      return d.replace(/^"/, "").replace(/"$/, "").replace(/""/g, "");
    case "SOA": {
      const parts = d.split(/\s+/);
      return {
        nsname:     (parts[0] ?? "").replace(/\.$/, ""),
        hostmaster: (parts[1] ?? "").replace(/\.$/, ""),
        serial:  parseInt(parts[2] ?? "0"),
        refresh: parseInt(parts[3] ?? "0"),
        retry:   parseInt(parts[4] ?? "0"),
        expire:  parseInt(parts[5] ?? "0"),
        minttl:  parseInt(parts[6] ?? "0"),
      };
    }
    case "CAA":
      return d;
  }
}

async function resolveDoH(url: string, name: string, type: RecordType): Promise<any[]> {
  const typeNum = TYPE_NUM[type];
  const endpoint = `${url}?name=${encodeURIComponent(name)}&type=${typeNum}`;
  const headers: Record<string, string> = { Accept: "application/dns-json" };

  const resp = await fetch(endpoint, {
    headers,
    signal: AbortSignal.timeout(7000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const json = await resp.json();

  if (json.Status === 3) throw Object.assign(new Error("NXDOMAIN"), { code: "ENOTFOUND" });
  if (json.Status !== 0) throw new Error(`DNS Status ${json.Status}`);

  const answers: any[] = json.Answer ?? [];
  return answers
    .filter((a: any) => a.type === typeNum)
    .map((a: any) => parseDoHData(a.data, type));
}

function normalizeToString(type: RecordType, raw: any): string {
  if (typeof raw === "string") return raw;
  if (type === "MX")  return `${raw.priority} ${raw.exchange}`;
  if (type === "SOA") return `${raw.nsname} ${raw.hostmaster} ${raw.serial} refresh=${raw.refresh} retry=${raw.retry} expire=${raw.expire} minttl=${raw.minttl}`;
  return JSON.stringify(raw);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) return res.status(429).json({ error: "Too many requests" });

  const name = (req.query.name as string | undefined)?.trim().toLowerCase();
  const typeRaw = ((req.query.type as string) || "A").toUpperCase();

  if (!name) return res.status(400).json({ error: "name parameter is required" });
  if (!RECORD_TYPES.includes(typeRaw as RecordType))
    return res.status(400).json({ error: `Unsupported type. Supported: ${RECORD_TYPES.join(", ")}` });
  const type = typeRaw as RecordType;

  const t0 = Date.now();

  type ResolverResult = {
    name: string; kind: "doh";
    records: any[]; flat: string[]; latencyMs: number; error?: string;
  };

  const dohJobs = DOH_RESOLVERS.map(async (r): Promise<ResolverResult> => {
    const rt0 = Date.now();
    try {
      const records = await resolveDoH(r.url, name, type);
      const flat = records.map(rec => normalizeToString(type, rec));
      return { name: r.name, kind: r.kind, records, flat, latencyMs: Date.now() - rt0 };
    } catch (e: any) {
      const code = e?.code ?? "";
      const error =
        e?.name === "TimeoutError"                       ? "timeout" :
        code === "ENOTFOUND" || e?.message === "NXDOMAIN" ? "no_record" :
        (e?.message || "unknown");
      return { name: r.name, kind: r.kind, records: [], flat: [], latencyMs: Date.now() - rt0, error };
    }
  });

  const results = await Promise.allSettled(dohJobs);
  const resolvers: ResolverResult[] = results.map((s, i) => {
    if (s.status === "fulfilled") return s.value;
    return { name: DOH_RESOLVERS[i].name, kind: "doh" as const, records: [], flat: [], latencyMs: 0, error: "rejected" };
  });

  const seenFlat = new Set<string>();
  const allFlat: string[] = [];
  const allRaw: any[] = [];

  for (const r of resolvers) {
    for (let i = 0; i < r.flat.length; i++) {
      const f = r.flat[i];
      if (!seenFlat.has(f)) {
        seenFlat.add(f);
        allFlat.push(f);
        allRaw.push(r.records[i]);
      }
    }
  }

  if (type === "MX") {
    const paired = allRaw.map((r, i) => ({ r, f: allFlat[i] }));
    paired.sort((a, b) => (a.r?.priority ?? 0) - (b.r?.priority ?? 0));
    allRaw.splice(0, allRaw.length, ...paired.map(p => p.r));
    allFlat.splice(0, allFlat.length, ...paired.map(p => p.f));
  }

  res.setHeader("Cache-Control", "public, s-maxage=30, stale-while-revalidate=60");
  return res.status(200).json({
    name, type,
    found: allFlat.length > 0,
    records: allRaw,
    flat: allFlat,
    resolvers,
    latencyMs: Date.now() - t0,
  });
}
