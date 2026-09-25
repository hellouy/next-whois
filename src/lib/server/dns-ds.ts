/**
 * Best-effort DS record lookup for the domain-info enrichment layer.
 *
 * R3.3: WHEN DS 记录可查, 系统 SHALL 尝试补充 DS 记录信息, 查询失败不阻断结果。
 *
 * A failed / timed-out / NXDOMAIN query returns `[]` (no DS records), never
 * throws — callers treat it as an optional supplement that must not block or
 * fail the WHOIS lookup path. Records are returned in presentation format
 * `"keyTag algorithm digestType digest"`, deduplicated and TTL-free.
 */

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
] as const;

const DS_TYPE_NUM = 43;

async function resolveDs(
  endpoint: string,
  name: string,
): Promise<string[]> {
  const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${DS_TYPE_NUM}`;
  const resp = await fetch(url, {
    headers: { Accept: "application/dns-json" },
    signal: AbortSignal.timeout(4000),
  });
  if (!resp.ok) return [];
  const json = await resp.json().catch(() => null);
  if (!json || typeof json !== "object") return [];
  // Status 3 (NXDOMAIN) or 0 with no answers — both mean no DS here.
  if (json.Status === 3) return [];
  if (json.Status !== 0) return [];
  const answers: Array<{ type?: number; data?: string }> = Array.isArray(json.Answer)
    ? json.Answer
    : [];
  const out: string[] = [];
  for (const a of answers) {
    if (a.type !== DS_TYPE_NUM || typeof a.data !== "string") continue;
    const p = a.data.trim().split(/\s+/);
    if (p.length < 4) continue;
    const [keyTag, algorithm, digestType] = p;
    const digest = p.slice(3).join(" ").replace(/\.$/, "");
    if (!/^\d+$/.test(keyTag) || !/^\d+$/.test(algorithm) || !/^\d+$/.test(digestType)) continue;
    if (!out.includes(`${keyTag} ${algorithm} ${digestType} ${digest}`)) {
      out.push(`${keyTag} ${algorithm} ${digestType} ${digest}`);
    }
  }
  return out;
}

/**
 * Fetch DS records for a domain, best-effort.
 * Returns a deduplicated list of presentation-format DS strings, or `[]` when
 * the domain has no DS records or the query cannot be completed.
 */
export async function fetchDsRecords(domain: string): Promise<string[]> {
  const name = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!name || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(name)) return [];
  for (const endpoint of DOH_ENDPOINTS) {
    try {
      const records = await resolveDs(endpoint, name);
      if (records.length > 0) return records;
    } catch {
      // try the next resolver
    }
  }
  return [];
}