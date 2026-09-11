// Reverse DNS (PTR) lookup across multiple resolvers for comparison.

import dns from "dns/promises";

export const RDNS_RESOLVERS = ["8.8.8.8", "1.1.1.1"] as const;
export const RDNS_TIMEOUT_MS = 3000;

export type RdnsResult = {
  resolver: string;
  hostname: string | null;
  latencyMs: number;
};

async function resolvePtr(resolver: string, ip: string): Promise<RdnsResult> {
  const t0 = Date.now();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("RDNS_TIMEOUT")), RDNS_TIMEOUT_MS);
  });
  try {
    const r = new dns.Resolver();
    r.setServers([resolver]);
    const hostnames = await Promise.race([r.resolvePtr(ip), timeout]);
    return { resolver, hostname: hostnames[0] ?? null, latencyMs: Date.now() - t0 };
  } catch {
    return { resolver, hostname: null, latencyMs: Date.now() - t0 };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function checkRdns(ip: string, resolvers: readonly string[] = RDNS_RESOLVERS): Promise<{ consistent: boolean; records: RdnsResult[] }> {
  const settled = await Promise.allSettled(resolvers.map(resolver => resolvePtr(resolver, ip)));
  const records = settled.map((s, i) =>
    s.status === "fulfilled" ? s.value : { resolver: resolvers[i], hostname: null, latencyMs: RDNS_TIMEOUT_MS }
  );
  const hostnames = new Set(records.map(r => r.hostname));
  const consistent = hostnames.size <= 1;
  return { consistent, records };
}
