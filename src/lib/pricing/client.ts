import { createLogger } from "@/lib/logger";

const logger = createLogger("pricing/client");

const NAZHUMI_API_URL = "https://www.nazhumi.com/api/v1";
const MIQINGJU_API_URL = "https://api.miqingju.com/api/v1/query";
const TIANHU_API_URL = "https://api.tian.hu/tlds/pricing";

// ── TLD-level in-memory cache ────────────────────────────────────────────────
// Prices change at most daily; a per-TLD cache removes the 6-8 external HTTP
// calls (nazhumi + miqingju + tianhu across new/renew/transfer) that would
// otherwise fire on EVERY cold WHOIS lookup. TTL is 30 minutes.
const PRICE_CACHE_TTL_MS = 30 * 60 * 1000;
const priceCache = new Map<
  string,
  { value: unknown; expiresAt: number }
>();
// In-flight dedup: concurrent callers (WHOIS-lookup prewarming + applyParams)
// share a single network fetch instead of firing duplicate API requests.
const inflightPrices = new Map<string, Promise<unknown>>();

function cachedValue<T>(key: string, producer: () => Promise<T>): Promise<T> {
  const hit = priceCache.get(key);
  const now = Date.now();
  if (hit && now < hit.expiresAt) return Promise.resolve(hit.value as T);
  let inflight = inflightPrices.get(key);
  if (!inflight) {
    inflight = Promise.resolve()
      .then(producer)
      .then((val) => {
        priceCache.set(key, { value: val, expiresAt: now + PRICE_CACHE_TTL_MS });
        return val;
      })
      .finally(() => {
        inflightPrices.delete(key);
      });
    inflightPrices.set(key, inflight);
  }
  return inflight as Promise<T>;
}

type NazhumiOrder = "new" | "renew" | "transfer";

interface NazhumiRegistrar {
  registrar: string;
  registrarname: string;
  registrarweb: string;
  new: number | "n/a";
  renew: number | "n/a";
  transfer: number | "n/a";
  currency: string;
  currencyname: string;
  currencytype: string;
  promocode: boolean;
  updatedtime: string;
}

interface NazhumiResponse {
  domain: string;
  order: "new" | "renew" | "transfer";
  count: number;
  price: NazhumiRegistrar[];
}

interface MiqingjuEntry {
  type: "registration" | "renewal" | "transfer";
  registrar: string;
  website: string;
  logo: string;
  tld: string;
  price: number;
  currency: string;
  price_cny: number;
}

interface MiqingjuResponse {
  success: boolean;
  timestamp: string;
  data: MiqingjuEntry[];
}

export interface DomainPricing extends NazhumiRegistrar {
  externalLink: string;
}

export async function getDomainTransferNegotiable(domain: string): Promise<boolean | null> {
  const tld = domain
    .substring(domain.lastIndexOf(".") + 1)
    .replace("www.", "")
    .toLowerCase()
    .trim();
  return cachedValue(`negotiable:${tld}`, async () => {
    try {
      // Run pricing check and domain scoring concurrently for speed
      const [nazhumiData, miqingjuData, scoreResult] = await Promise.all([
        fetchNazhumiData(tld, "transfer"),
        fetchMiqingjuData(tld, "transfer"),
        (async () => {
          try {
            const { scoreDomain } = await import("@/lib/domain-value");
            return scoreDomain(domain, "domain");
          } catch {
            return null;
          }
        })(),
      ]);

      const score = scoreResult?.score ?? 0;

      // High-value domains (score ≥ 65) are almost always negotiable regardless of
      // whether standard transfer pricing exists — owners of premium domains expect
      // direct offers.
      if (score >= 65) return true;

      const combined = [...nazhumiData, ...miqingjuData].filter(
        (r) => typeof r.transfer === "number" && (r.transfer as number) > 0,
      );

      // If no standard transfer pricing is available for this TLD, mid-value and
      // above domains can still be acquired via direct owner negotiation.
      if (combined.length === 0) return score >= 35;

      // Standard transfer pricing exists → not an aftermarket negotiation scenario.
      return false;
    } catch {
      return null;
    }
  });
}

const MQ_TYPE_MAP: Record<NazhumiOrder, string> = {
  new: "registration",
  renew: "renewal",
  transfer: "transfer",
};

function registrarKey(name: string): string {
  return name
    .toLowerCase()
    .replace(/\.(com|net|org|io|co|biz|info|cn)$/i, "")
    .replace(/[\s\-_.]+/g, "");
}

async function fetchNazhumiData(
  tld: string,
  type: NazhumiOrder,
): Promise<NazhumiRegistrar[]> {
  try {
    const { getApiConfig } = await import("@/lib/api-config");
    const cfg = await getApiConfig();
    if (!cfg.nazhumi_enabled) return [];

    const url = `${NAZHUMI_API_URL}?domain=${encodeURIComponent(tld)}&order=${type}`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return [];
    const res = await response.json();
    const data: NazhumiResponse | undefined = res.data;
    if (!data || !Array.isArray(data.price) || data.price.length === 0) return [];
    return data.price;
  } catch {
    return [];
  }
}

interface TianhuPriceEntry {
  registrar: string;
  registrarname: string;
  registrarweb: string;
  new_usd?: number;
  renew_usd?: number;
  transfer_usd?: number;
  new?: number;
  renew?: number;
  transfer?: number;
  currency?: string;
  updatedtime?: string;
}

async function fetchTianhuData(
  tld: string,
  type: NazhumiOrder,
): Promise<NazhumiRegistrar[]> {
  try {
    const { getApiConfig } = await import("@/lib/api-config");
    const cfg = await getApiConfig();
    if (!cfg.tianhu_enabled) return [];

    const url = `${TIANHU_API_URL}/${encodeURIComponent(tld)}`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return [];
    const json = await response.json();
    if (json.code !== 200 || !Array.isArray(json.data)) return [];

    return (json.data as TianhuPriceEntry[])
      .filter((r) => typeof r.new_usd === "number" || typeof r.new === "number")
      .map((r) => {
        const newPrice = r.new_usd ?? r.new ?? "n/a";
        const renewPrice = r.renew_usd ?? r.renew ?? "n/a";
        const transferPrice = r.transfer_usd ?? r.transfer ?? "n/a";
        return {
          registrar: r.registrar,
          registrarname: r.registrarname || r.registrar,
          registrarweb: r.registrarweb || "",
          new: type === "new" ? newPrice : "n/a",
          renew: type === "renew" ? renewPrice : "n/a",
          transfer: type === "transfer" ? transferPrice : "n/a",
          currency: "USD",
          currencyname: "USD",
          currencytype: "standard",
          promocode: false,
          updatedtime: r.updatedtime ?? "",
        };
      });
  } catch {
    return [];
  }
}

async function fetchMiqingjuData(
  tld: string,
  type: NazhumiOrder,
): Promise<NazhumiRegistrar[]> {
  try {
    const { getApiConfig } = await import("@/lib/api-config");
    const cfg = await getApiConfig();
    if (!cfg.miqingju_enabled) return [];

    const mqType = MQ_TYPE_MAP[type];
    const url = `${MIQINGJU_API_URL}?tld=${encodeURIComponent(tld)}`;
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(2500),
    });
    if (!response.ok) return [];
    const json: MiqingjuResponse = await response.json();
    if (!json.success || !Array.isArray(json.data)) return [];

    return json.data
      .filter((r) => r.type === mqType && typeof r.price === "number")
      .map((r) => ({
        registrar: r.registrar,
        registrarname: r.registrar,
        registrarweb: r.website ?? "",
        new: type === "new" ? r.price : "n/a",
        renew: type === "renew" ? r.price : "n/a",
        transfer: type === "transfer" ? r.price : "n/a",
        currency: (r.currency ?? "USD").toUpperCase(),
        currencyname: r.currency ?? "USD",
        currencytype: "standard",
        promocode: false,
        updatedtime: "",
      }));
  } catch {
    return [];
  }
}

function mergeRegistrars(
  sources: NazhumiRegistrar[][],
  type: NazhumiOrder,
): NazhumiRegistrar[] {
  const map = new Map<string, NazhumiRegistrar>();

  for (const source of sources) {
    for (const r of source) {
      const key = registrarKey(r.registrarname || r.registrar);
      if (!key) continue;
      if (map.has(key)) {
        const existing = map.get(key)!;
        // If existing entry is already premium-flagged by the source, preserve it.
        // External sources (miqingju, tianhu) always hardcode "standard" and cannot
        // distinguish premium pricing — their lower price is not the correct premium price.
        if (existing.currencytype?.toLowerCase().includes("premium")) continue;
        const ePrice = typeof existing[type] === "number" ? (existing[type] as number) : Infinity;
        const mPrice = typeof r[type] === "number" ? (r[type] as number) : Infinity;
        if (mPrice < ePrice) {
          map.set(key, { ...existing, [type]: r[type] });
        }
      } else {
        map.set(key, r);
      }
    }
  }

  return Array.from(map.values()).filter((r) => typeof r[type] === "number" && (r[type] as number) > 0);
}

export async function getDomainPricing(
  domain: string,
  type: NazhumiOrder,
): Promise<DomainPricing | null> {
  const tld = domain
    .substring(domain.lastIndexOf(".") + 1)
    .replace("www.", "")
    .toLowerCase()
    .trim();
  return cachedValue(`price:${tld}:${type}`, async () => {
    try {
      const [nazhumiData, miqingjuData, tianhuData] = await Promise.all([
        fetchNazhumiData(tld, type),
        fetchMiqingjuData(tld, type),
        fetchTianhuData(tld, type),
      ]);

      // Prefer nazhumi/miqingju (authoritative) over tianhu.
      // Only use tianhu if neither nazhumi nor miqingju has any entry for this TLD.
      const trustedSources = nazhumiData.length > 0 || miqingjuData.length > 0;
      const merged = trustedSources
        ? mergeRegistrars([nazhumiData, miqingjuData], type)
        : mergeRegistrars([tianhuData], type);
      if (merged.length === 0) return null;

      merged.sort((a, b) => {
        const av = typeof a[type] === "number" ? (a[type] as number) : Infinity;
        const bv = typeof b[type] === "number" ? (b[type] as number) : Infinity;
        return av - bv;
      });

      const best = merged[0];
      return {
        ...best,
        externalLink: `https://www.nazhumi.com/domain/${tld}/${type}`,
      };
    } catch (error) {
      logger.error("Error fetching domain pricing:", error);
      return null;
    }
  });
}

export async function getTopRegistrars(
  domain: string,
  type: NazhumiOrder,
  count = 3,
): Promise<DomainPricing[]> {
  const tld = domain
    .substring(domain.lastIndexOf(".") + 1)
    .replace("www.", "")
    .toLowerCase()
    .trim();
  return cachedValue(`top:${tld}:${type}`, async () => {
    try {
      const [nazhumiData, miqingjuData, tianhuData] = await Promise.all([
        fetchNazhumiData(tld, type),
        fetchMiqingjuData(tld, type),
        fetchTianhuData(tld, type),
      ]);

      const trustedSourcesTop = nazhumiData.length > 0 || miqingjuData.length > 0;
      const merged = trustedSourcesTop
        ? mergeRegistrars([nazhumiData, miqingjuData], type)
        : mergeRegistrars([tianhuData], type);

      return merged
        .filter((r) => typeof r[type] === "number" && (r[type] as number) > 0)
        .sort((a, b) => {
          const av = typeof a[type] === "number" ? (a[type] as number) : Infinity;
          const bv = typeof b[type] === "number" ? (b[type] as number) : Infinity;
          return av - bv;
        })
        .slice(0, count)
        .map((r) => ({
          ...r,
          externalLink: `https://www.nazhumi.com/domain/${tld}/${type}`,
        }));
    } catch {
      return [];
    }
  });
}
