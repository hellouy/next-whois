import type { NextApiRequest, NextApiResponse } from "next";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";
import { getRedisValue, setRedisValue } from "@/lib/server/redis";

export const config = { maxDuration: 20 };

const RL_LIMIT   = 30;
const RL_WINDOW  = 60_000;
const CACHE_TTL  = 600; // 10 minutes — IP geolocation is stable

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;
const ASN_RE = /^as?(\d+)$/i;

async function resolveHostname(host: string): Promise<string | null> {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
  try {
    const r = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) return null;
    const data = await r.json();
    const answer = (data.Answer as any[] | undefined)?.find((a: any) => a.type === 1);
    if (answer?.data) return answer.data as string;
    const url6 = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=AAAA`;
    const r6 = await fetch(url6, { headers: { Accept: "application/dns-json" }, signal: AbortSignal.timeout(4000) });
    if (!r6.ok) return null;
    const data6 = await r6.json();
    const answer6 = (data6.Answer as any[] | undefined)?.find((a: any) => a.type === 28);
    return answer6?.data ?? null;
  } catch {
    return null;
  }
}

async function fetchIpApi(ip: string): Promise<any> {
  const fields = "status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
  const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}&lang=zh-CN`;
  const res = await fetch(url, {
    headers: { "User-Agent": "NextWhois/1.0" },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`ip-api.com returned ${res.status}`);
  return res.json();
}

async function fetchRdapIp(ip: string): Promise<any> {
  const endpoints = [
    `https://rdap.arin.net/registry/ip/${ip}`,
    `https://rdap.db.ripe.net/ip/${ip}`,
    `https://rdap.apnic.net/ip/${ip}`,
    `https://rdap.lacnic.net/rdap/ip/${ip}`,
    `https://rdap.afrinic.net/rdap/ip/${ip}`,
  ];
  const controller = new AbortController();
  const jobs = endpoints.map(async (url) => {
    const r = await fetch(url, {
      headers: { Accept: "application/rdap+json", "User-Agent": "NextWhois/1.0" },
      signal: AbortSignal.any
        ? AbortSignal.any([controller.signal, AbortSignal.timeout(7000)])
        : controller.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    controller.abort();
    return data;
  });
  try {
    return await Promise.any(jobs);
  } catch {
    return null;
  }
}

async function fetchRdapAsn(asn: number): Promise<any> {
  const endpoints = [
    `https://rdap.arin.net/registry/autnum/${asn}`,
    `https://rdap.db.ripe.net/autnum/${asn}`,
    `https://rdap.apnic.net/autnum/${asn}`,
    `https://rdap.lacnic.net/rdap/autnum/${asn}`,
    `https://rdap.afrinic.net/rdap/autnum/${asn}`,
  ];
  const controller = new AbortController();
  const jobs = endpoints.map(async (url) => {
    const r = await fetch(url, {
      headers: { Accept: "application/rdap+json", "User-Agent": "NextWhois/1.0" },
      signal: AbortSignal.any
        ? AbortSignal.any([controller.signal, AbortSignal.timeout(8000)])
        : controller.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    controller.abort();
    return data;
  });
  try {
    return await Promise.any(jobs);
  } catch {
    return null;
  }
}

function extractVcard(vcardArray: any[]): { name?: string; org?: string; email?: string } {
  const result: { name?: string; org?: string; email?: string } = {};
  const items: any[] = vcardArray?.[1] ?? [];
  for (const item of items) {
    if (item[0] === "fn"  && !result.name)  result.name  = item[3];
    if (item[0] === "org" && !result.org)   result.org   = typeof item[3] === "string" ? item[3] : item[3]?.[0];
    if (item[0] === "email" && !result.email) {
      const raw = Array.isArray(item[3]) ? item[3][0] : item[3];
      result.email = typeof raw === "string" ? raw.replace(/^mailto:/i, "") : undefined;
    }
  }
  return result;
}

function extractRdapInfo(rdap: any): Record<string, string> {
  if (!rdap) return {};
  const info: Record<string, string> = {};

  if (rdap.name)         info.name         = rdap.name;
  if (rdap.handle)       info.handle       = rdap.handle;
  if (rdap.type)         info.type         = rdap.type;
  if (rdap.startAutnum)  info.startAutnum  = String(rdap.startAutnum);
  if (rdap.endAutnum)    info.endAutnum    = String(rdap.endAutnum);
  if (rdap.startAddress) info.startAddress = rdap.startAddress;
  if (rdap.endAddress)   info.endAddress   = rdap.endAddress;
  if (rdap.ipVersion)    info.ipVersion    = rdap.ipVersion;

  // CIDR prefix from cidr0_cidrs extension (RFC 8045)
  const cidrs: any[] = rdap.cidr0_cidrs ?? [];
  if (cidrs.length > 0) {
    const c = cidrs[0];
    if (c.v4prefix) info.cidr = `${c.v4prefix}/${c.length}`;
    else if (c.v6prefix) info.cidr = `${c.v6prefix}/${c.length}`;
  }

  const entities: any[] = rdap.entities || [];
  for (const e of entities) {
    const roles: string[] = e.roles ?? [];

    if (roles.includes("registrant") || roles.includes("administrative")) {
      const vc = extractVcard(e.vcardArray);
      if (vc.name && !info.contact_name)  info.contact_name  = vc.name;
      if (vc.org  && !info.contact_org)   info.contact_org   = vc.org;
      if (vc.email && !info.contact_email) info.contact_email = vc.email;
    }

    if (roles.includes("abuse")) {
      const vc = extractVcard(e.vcardArray);
      if (vc.email && !info.abuse_email) info.abuse_email = vc.email;
      if (vc.name  && !info.abuse_name)  info.abuse_name  = vc.name;
    }
  }

  const remarks: any[] = rdap.remarks || [];
  for (const r of remarks) {
    if (r.description) {
      info.description = Array.isArray(r.description) ? r.description.join(" ") : r.description;
    }
  }
  return info;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) return res.status(429).json({ error: "Too many requests" });

  let query = (req.query.q as string | undefined)?.trim();
  if (!query) return res.status(400).json({ error: "q parameter is required" });

  res.setHeader("Cache-Control", "no-store");

  const cacheKey = `ip:lookup:${query.toLowerCase()}`;
  const refresh = req.query.refresh === "1";

  // ── L2 Redis cache ─────────────────────────────────────────────────────
  if (!refresh) {
    try {
      const cached = await getRedisValue(cacheKey);
      if (cached) {
        res.setHeader("X-Cache", "HIT");
        return res.status(200).json(JSON.parse(cached));
      }
    } catch {
      // Redis unavailable → fall through to live lookup
    }
  }

  const asnMatch = query.match(ASN_RE);
  if (asnMatch) {
    const asn = parseInt(asnMatch[1]);
    try {
      const rdap = await fetchRdapAsn(asn);
      const info = extractRdapInfo(rdap);
      const payload = { type: "asn", asn, rdap: info, raw: rdap };
      void saveToCache(cacheKey, payload);
      return res.json(payload);
    } catch (e: any) {
      console.error("[ip/lookup]", e);
      return res.status(500).json({ error: "Lookup failed" });
    }
  }

  let ip = query;
  let resolvedFrom: string | null = null;
  if (!IP_RE.test(query) && !IPV6_RE.test(query)) {
    const resolved = await resolveHostname(query);
    if (!resolved) return res.status(400).json({ error: "Cannot resolve hostname. Please enter a valid IP address or hostname." });
    resolvedFrom = query;
    ip = resolved;
  }

  try {
    const [ipData, rdap] = await Promise.allSettled([
      fetchIpApi(ip),
      fetchRdapIp(ip),
    ]);

    const geo = ipData.status === "fulfilled" ? ipData.value : null;
    const rdapData = rdap.status === "fulfilled" ? rdap.value : null;
    const rdapInfo = extractRdapInfo(rdapData);

    if (geo?.status === "fail") {
      return res.status(400).json({ error: geo.message || "IP lookup failed" });
    }

    const flagEmoji = geo?.countryCode
      ? geo.countryCode.toUpperCase().split("").map((c: string) => String.fromCodePoint(c.charCodeAt(0) + 127397)).join("")
      : null;

    const payload = {
      type: IPV6_RE.test(ip) ? "ipv6" : "ipv4",
      query: ip,
      resolvedFrom,
      flag: flagEmoji,
      country: geo?.country ?? null,
      countryCode: geo?.countryCode ?? null,
      region: geo?.regionName ?? null,
      city: geo?.city ?? null,
      district: geo?.district ?? null,
      zip: geo?.zip ?? null,
      timezone: geo?.timezone ?? null,
      offset: geo?.offset ?? null,
      currency: geo?.currency ?? null,
      lat: geo?.lat ?? null,
      lon: geo?.lon ?? null,
      isp: geo?.isp ?? null,
      org: geo?.org ?? null,
      as: geo?.as ?? null,
      asname: geo?.asname ?? null,
      reverse: geo?.reverse ?? null,
      mobile: geo?.mobile ?? null,
      proxy: geo?.proxy ?? null,
      hosting: geo?.hosting ?? null,
      rdap: rdapInfo,
    };
    void saveToCache(cacheKey, payload);
    return res.json(payload);
  } catch (e: any) {
    console.error("[ip/lookup]", e);
    return res.status(500).json({ error: "Lookup failed" });
  }
}

async function saveToCache(key: string, payload: unknown) {
  try {
    await setRedisValue(key, JSON.stringify(payload), CACHE_TTL);
  } catch {
    // ignore
  }
}
