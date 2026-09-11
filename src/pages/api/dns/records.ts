import type { NextApiRequest, NextApiResponse } from "next";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const config = { maxDuration: 20 };

const RL_LIMIT  = 60;
const RL_WINDOW = 60_000;

const RECORD_TYPES = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "CAA", "PTR", "SRV", "HTTPS", "DS", "DNSKEY", "NSEC", "NSEC3", "NAPTR", "TLSA", "SMIMEA"] as const;
type RecordType = typeof RECORD_TYPES[number];

const TYPE_NUM: Record<RecordType, number> = {
  A: 1, AAAA: 28, MX: 15, NS: 2, CNAME: 5, TXT: 16, SOA: 6, CAA: 257,
  PTR: 12, SRV: 33, HTTPS: 65, DS: 43, DNSKEY: 48, NSEC: 47, NSEC3: 50,
  NAPTR: 35, TLSA: 52, SMIMEA: 53,
};

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
    case "PTR":
      return d.replace(/\.$/, "");
    case "MX": {
      const sp = d.indexOf(" ");
      if (sp < 0) return { priority: 10, exchange: d.replace(/\.$/, "") };
      return { priority: parseInt(d.slice(0, sp)), exchange: d.slice(sp + 1).replace(/\.$/, "") };
    }
    case "SRV": {
      const parts = d.split(/\s+/);
      if (parts.length < 4) return d;
      return {
        priority: parseInt(parts[0]),
        weight:   parseInt(parts[1]),
        port:     parseInt(parts[2]),
        target:   parts[3].replace(/\.$/, ""),
      };
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
    case "HTTPS":
      return d;
    case "DS": {
      const p = d.split(/\s+/);
      return {
        keyTag:     parseInt(p[0] ?? "0"),
        algorithm:  parseInt(p[1] ?? "0"),
        digestType: parseInt(p[2] ?? "0"),
        digest:     p[3] ?? "",
      };
    }
    case "DNSKEY": {
      const p = d.split(/\s+/);
      return {
        flags:     parseInt(p[0] ?? "0"),
        protocol:  parseInt(p[1] ?? "0"),
        algorithm: parseInt(p[2] ?? "0"),
        publicKey: p[3] ?? "",
      };
    }
    case "NSEC": {
      const p = d.split(/\s+/);
      const nextDomain = (p[0] ?? "").replace(/\.$/, "");
      // Type bitmap in presentation format is the remaining space-separated
      // record-type mnemonics; fall back to the raw string when unparseable.
      const types = p.length > 1
        ? p.slice(1).filter(s => /^[A-Z0-9-]+$/.test(s))
        : [];
      return { nextDomain, types };
    }
    case "NSEC3": {
      const p = d.split(/\s+/);
      return {
        algorithm:        parseInt(p[0] ?? "0"),
        flags:            parseInt(p[1] ?? "0"),
        iterations:       parseInt(p[2] ?? "0"),
        salt:             p[3] ?? "",
        nextHashedOwner:  p[4] ?? "",
      };
    }
    case "NAPTR": {
      const p = d.split(/\s+/);
      return {
        order:       parseInt(p[0] ?? "0"),
        preference:  parseInt(p[1] ?? "0"),
        flags:       (p[2] ?? "").replace(/"/g, ""),
        service:     (p[3] ?? "").replace(/"/g, ""),
        regexp:      (p[4] ?? "").replace(/"/g, ""),
        replacement: (p[5] ?? "").replace(/\.$/, ""),
      };
    }
    case "TLSA":
    case "SMIMEA": {
      const p = d.split(/\s+/);
      return {
        usage:                 parseInt(p[0] ?? "0"),
        selector:              parseInt(p[1] ?? "0"),
        matchingType:          parseInt(p[2] ?? "0"),
        certAssociationData:   p[3] ?? "",
      };
    }
  }
}

type DoHEntry = { data: any; ttl: number };

async function resolveDoH(url: string, name: string, type: RecordType): Promise<DoHEntry[]> {
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
    .map((a: any) => ({ data: parseDoHData(a.data, type), ttl: a.TTL ?? 0 }));
}

function normalizeToString(type: RecordType, raw: any): string {
  if (typeof raw === "string") return raw;
  if (type === "MX")  return `${raw.priority} ${raw.exchange}`;
  if (type === "SRV") return `${raw.priority} ${raw.weight} ${raw.port} ${raw.target}`;
  if (type === "SOA") return `${raw.nsname} ${raw.hostmaster} ${raw.serial} refresh=${raw.refresh} retry=${raw.retry} expire=${raw.expire} minttl=${raw.minttl}`;
  if (type === "DS")  return `${raw.keyTag} ${raw.algorithm} ${raw.digestType} ${raw.digest}`;
  if (type === "DNSKEY") return `${raw.flags} ${raw.protocol} ${raw.algorithm} ${raw.publicKey}`;
  if (type === "NSEC")  return `${raw.nextDomain} ${raw.types.join(" ")}`.trim();
  if (type === "NSEC3") return `${raw.algorithm} ${raw.flags} ${raw.iterations} ${raw.salt} ${raw.nextHashedOwner}`;
  if (type === "NAPTR") return `${raw.order} ${raw.preference} "${raw.flags}" "${raw.service}" "${raw.regexp}" ${raw.replacement}`;
  if (type === "TLSA" || type === "SMIMEA") return `${raw.usage} ${raw.selector} ${raw.matchingType} ${raw.certAssociationData}`;
  return JSON.stringify(raw);
}

export type Propagation = {
  consistent: boolean;
  differing: { resolver: string; missing: string[]; extra: string[] }[];
};

/**
 * Compute propagation consistency across resolvers.
 * `merged` is the deduplicated record list; each healthy resolver is compared
 * against it. Resolvers carrying an error are excluded from the comparison.
 */
export function computePropagation(
  resolvers: { name: string; flat: string[]; error?: string }[],
  merged: string[],
): Propagation {
  const mergedSet = new Set(merged);
  const differing: Propagation["differing"] = [];
  for (const r of resolvers) {
    if (r.error || r.flat.length === 0) continue;
    const rSet = new Set(r.flat);
    const missing = merged.filter(f => !rSet.has(f));
    const extra = r.flat.filter(f => !mergedSet.has(f));
    if (missing.length > 0 || extra.length > 0) {
      differing.push({ resolver: r.name, missing, extra });
    }
  }
  return { consistent: differing.length === 0, differing };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { ok: allowed } = await checkRateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) return res.status(429).json({ error: "Too many requests" });

  const name = (req.query.name as string | undefined)?.trim().toLowerCase();
  const typeRaw = ((req.query.type as string) || "A").toUpperCase();

  if (!name) return res.status(400).json({ error: "name parameter is required" });
  if (name.length > 253) return res.status(400).json({ error: "name too long (max 253 characters)" });
  if (!/^[a-z0-9._*\-[\]]+$/.test(name)) return res.status(400).json({ error: "name contains invalid characters" });
  if (!RECORD_TYPES.includes(typeRaw as RecordType))
    return res.status(400).json({ error: `Unsupported type. Supported: ${RECORD_TYPES.join(", ")}` });
  const type = typeRaw as RecordType;

  const t0 = Date.now();

  type ResolverResult = {
    name: string; kind: "doh";
    records: any[]; flat: string[]; ttls: number[]; latencyMs: number; error?: string;
  };

  const dohJobs = DOH_RESOLVERS.map(async (r): Promise<ResolverResult> => {
    const rt0 = Date.now();
    try {
      const entries = await resolveDoH(r.url, name, type);
      const records = entries.map(e => e.data);
      const flat = records.map(rec => normalizeToString(type, rec));
      const ttls = entries.map(e => e.ttl);
      return { name: r.name, kind: r.kind, records, flat, ttls, latencyMs: Date.now() - rt0 };
    } catch (e: any) {
      const code = e?.code ?? "";
      const error =
        e?.name === "TimeoutError"                        ? "timeout" :
        code === "ENOTFOUND" || e?.message === "NXDOMAIN" ? "no_record" :
        (e?.message || "unknown");
      return { name: r.name, kind: r.kind, records: [], flat: [], ttls: [], latencyMs: Date.now() - rt0, error };
    }
  });

  const results = await Promise.allSettled(dohJobs);
  const resolvers: ResolverResult[] = results.map((s, i) => {
    if (s.status === "fulfilled") return s.value;
    return { name: DOH_RESOLVERS[i].name, kind: "doh" as const, records: [], flat: [], ttls: [], latencyMs: 0, error: "rejected" };
  });

  const seenFlat = new Set<string>();
  const allFlat: string[] = [];
  const allRaw: any[] = [];
  const allTtls: number[] = [];

  for (const r of resolvers) {
    for (let i = 0; i < r.flat.length; i++) {
      const f = r.flat[i];
      if (!seenFlat.has(f)) {
        seenFlat.add(f);
        allFlat.push(f);
        allRaw.push(r.records[i]);
        allTtls.push(r.ttls[i] ?? 0);
      }
    }
  }

  if (type === "MX") {
    const paired = allRaw.map((r, i) => ({ r, f: allFlat[i], t: allTtls[i] }));
    paired.sort((a, b) => (a.r?.priority ?? 0) - (b.r?.priority ?? 0));
    allRaw.splice(0, allRaw.length, ...paired.map(p => p.r));
    allFlat.splice(0, allFlat.length, ...paired.map(p => p.f));
    allTtls.splice(0, allTtls.length, ...paired.map(p => p.t));
  }

  if (type === "SRV") {
    const paired = allRaw.map((r, i) => ({ r, f: allFlat[i], t: allTtls[i] }));
    paired.sort((a, b) => (a.r?.priority ?? 0) - (b.r?.priority ?? 0) || (a.r?.weight ?? 0) - (b.r?.weight ?? 0));
    allRaw.splice(0, allRaw.length, ...paired.map(p => p.r));
    allFlat.splice(0, allFlat.length, ...paired.map(p => p.f));
    allTtls.splice(0, allTtls.length, ...paired.map(p => p.t));
  }

  // ── Propagation consistency ─────────────────────────────────────────────
  // Compare each healthy resolver's record set against the merged set.
  const propagation = computePropagation(resolvers, allFlat);

  res.setHeader("Cache-Control", "public, s-maxage=30, stale-while-revalidate=60");
  return res.status(200).json({
    name, type,
    found: allFlat.length > 0,
    records: allRaw,
    flat: allFlat,
    ttls: allTtls,
    resolvers,
    propagation,
    latencyMs: Date.now() - t0,
  });
}
