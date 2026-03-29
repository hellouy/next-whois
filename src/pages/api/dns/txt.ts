import type { NextApiRequest, NextApiResponse } from "next";
import dns from "dns/promises";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 12 };

const RL_LIMIT  = 60;
const RL_WINDOW = 60_000;

type ResolverResult = {
  name: string;
  records: string[][];     // raw chunks per record
  flat: string[];          // joined records for easy display
  latencyMs: number;
  error?: string;
};

type Data = {
  name: string;
  found: boolean;
  records: string[][];     // merged raw chunks
  flat: string[];          // merged joined records
  resolvers: ResolverResult[];
  latencyMs: number;
  error?: string;
};

const RESOLVERS = [
  { name: "Google DNS",  ip: "8.8.8.8" },
  { name: "Cloudflare",  ip: "1.1.1.1" },
  { name: "Quad9",       ip: "9.9.9.9" },
  { name: "OpenDNS",     ip: "208.67.222.222" },
];

async function queryTxt(
  ip: string, name: string, timeoutMs = 7000
): Promise<{ records: string[][]; latencyMs: number }> {
  const resolver = new dns.Resolver();
  resolver.setServers([ip]);
  const t0 = Date.now();
  const raw = await Promise.race([
    resolver.resolveTxt(name),
    new Promise<never>((_, rej) =>
      setTimeout(() => rej(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), timeoutMs)
    ),
  ]);
  return { records: raw, latencyMs: Date.now() - t0 };
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) return res.status(429).json({
    name: "", found: false, records: [], flat: [], resolvers: [], latencyMs: 0,
    error: "Too many requests",
  });

  const name = (req.query.name as string | undefined)?.trim();
  if (!name) {
    return res.status(400).json({
      name: "", found: false, records: [], flat: [], resolvers: [], latencyMs: 0,
      error: "name parameter is required",
    });
  }

  const t0 = Date.now();

  const settled = await Promise.allSettled(
    RESOLVERS.map(async (r): Promise<ResolverResult> => {
      const rt0 = Date.now();
      try {
        const { records, latencyMs } = await queryTxt(r.ip, name);
        const flat = records.map(chunks => chunks.join(""));
        return { name: r.name, records, flat, latencyMs };
      } catch (e: any) {
        const code = e?.code ?? "";
        const error =
          code === "ETIMEOUT" || e?.message === "timeout" ? "timeout" :
          code === "ENODATA" || code === "ENOTFOUND"      ? "no_record" :
          code === "ESERVFAIL"                             ? "servfail" :
          code === "ECONNREFUSED"                          ? "udp_blocked" :
                                                             (e?.message || "unknown");
        return { name: r.name, records: [], flat: [], latencyMs: Date.now() - rt0, error };
      }
    })
  );

  const resolvers: ResolverResult[] = settled.map((r, i) =>
    r.status === "fulfilled"
      ? r.value
      : { name: RESOLVERS[i].name, records: [], flat: [], latencyMs: 0, error: "rejected" }
  );

  // Deduplicate records (same joined value from multiple resolvers)
  const seenJoined = new Set<string>();
  const allRecords: string[][] = [];
  const allFlat: string[] = [];
  for (const r of resolvers) {
    for (let i = 0; i < r.records.length; i++) {
      const joined = r.flat[i];
      if (!seenJoined.has(joined)) {
        seenJoined.add(joined);
        allRecords.push(r.records[i]);
        allFlat.push(joined);
      }
    }
  }

  const found = allFlat.length > 0;

  res.setHeader("Cache-Control", "public, s-maxage=30, stale-while-revalidate=60");
  return res.status(200).json({
    name, found, records: allRecords, flat: allFlat, resolvers, latencyMs: Date.now() - t0,
  });
}
