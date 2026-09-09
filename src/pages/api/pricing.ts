import type { NextApiRequest, NextApiResponse } from "next";

const NAZHUMI_API_URL = "https://www.nazhumi.com/api/v1";
const MIQINGJU_API_URL = "https://api.miqingju.com/api/v1/query";

const MQ_TYPE: Record<string, string> = {
  new: "registration",
  renew: "renewal",
  transfer: "transfer",
};

async function fetchNazhumi(tld: string, type: string): Promise<any[]> {
  try {
    const url = `${NAZHUMI_API_URL}?domain=${encodeURIComponent(tld)}&order=${type}`;
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const json = await res.json();
    const data = json?.data;
    if (!data || !Array.isArray(data.price)) return [];
    return data.price.filter((r: any) => typeof r[type] === "number");
  } catch {
    return [];
  }
}

async function fetchMiqingju(tld: string, type: string): Promise<any[]> {
  try {
    const mqType = MQ_TYPE[type] ?? type;
    const url = `${MIQINGJU_API_URL}?tld=${encodeURIComponent(tld)}`;
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const json = await res.json();
    if (!json.success || !Array.isArray(json.data)) return [];
    return json.data
      .filter((r: any) => r.type === mqType && typeof r.price === "number")
      .map((r: any) => ({
        registrar: r.registrar,
        registrarname: r.registrar,
        registrarweb: r.website ?? "",
        [type]: r.price,
        currency: (r.currency ?? "USD").toUpperCase(),
        currencyname: r.currency ?? "USD",
        currencytype: "standard",
        promocode: false,
        updatedtime: "",
        _source: "miqingju",
      }));
  } catch {
    return [];
  }
}

function registrarKey(r: any): string {
  return ((r.registrarname || r.registrar) ?? "")
    .toLowerCase()
    .replace(/\.(com|net|org|io|co|biz|info|cn)$/i, "")
    .replace(/[\s\-_.]+/g, "");
}

function mergeResults(nazhumi: any[], miqingju: any[], type: string): any[] {
  const map = new Map<string, any>();

  for (const r of nazhumi) {
    const key = registrarKey(r);
    if (key) map.set(key, { ...r, _source: "nazhumi" });
  }

  for (const r of miqingju) {
    const key = registrarKey(r);
    if (!key) continue;
    if (map.has(key)) {
      const existing = map.get(key)!;
      // Preserve premium-flagged nazhumi entry — miqingju always sets currencytype=standard
      // and cannot reflect per-TLD premium pricing; its lower price would be incorrect.
      if (existing.currencytype && String(existing.currencytype).toLowerCase().includes("premium")) continue;
      const ePrice = typeof existing[type] === "number" ? (existing[type] as number) : Infinity;
      const mPrice = typeof r[type] === "number" ? (r[type] as number) : Infinity;
      if (mPrice < ePrice) {
        map.set(key, { ...existing, [type]: r[type], _source: "both" });
      }
    } else {
      map.set(key, r);
    }
  }

  return Array.from(map.values())
    .filter((r) => typeof r[type] === "number")
    .sort((a, b) => (a[type] as number) - (b[type] as number));
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { tld, type = "new" } = req.query;
  if (!tld || typeof tld !== "string") {
    return res.status(400).json({ error: "Missing tld" });
  }
  const cleanTld = tld.toLowerCase().replace(/^\./, "").trim();
  const cleanType = typeof type === "string" ? type : "new";

  try {
    const [nazhumiData, miqingjuData] = await Promise.all([
      fetchNazhumi(cleanTld, cleanType),
      fetchMiqingju(cleanTld, cleanType),
    ]);

    const merged = mergeResults(nazhumiData, miqingjuData, cleanType);
    res.setHeader("Cache-Control", "public, s-maxage=3600, stale-while-revalidate=86400");
    return res.status(200).json({ price: merged });
  } catch {
    return res.status(200).json({ price: [] });
  }
}
