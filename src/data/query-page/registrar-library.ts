/**
 * Curated registrar knowledge base: registrar name → IANA registrar ID.
 *
 * Used to backfill `ianaId` when a WHOIS/RDAP response names a registrar but
 * omits its IANA Registrar ID. Matches are normalized (lowercase, punctuation
 * stripped) and matched by substring, so "Alibaba Cloud Computing (Beijing)
 * Co., Ltd." hits the "alibaba" entry.
 *
 * IANA IDs are the canonical IANA Registrar ID (see https://www.iana.org/assignments/registrar-ids/).
 */

export type RegistrarInfo = {
  name: string;
  /** Comma-separated aliases used for substring matching (lowercased, no punctuation). */
  matchKeys: string[];
  ianaId: string;
  website: string | null;
};

export const REGISTRAR_LIBRARY: RegistrarInfo[] = [
  {
    name: "GoDaddy",
    matchKeys: ["godaddy"],
    ianaId: "146",
    website: "https://www.godaddy.com",
  },
  {
    name: "Namecheap",
    matchKeys: ["namecheap"],
    ianaId: "1068",
    website: "https://www.namecheap.com",
  },
  {
    name: "Porkbun",
    matchKeys: ["porkbun"],
    ianaId: "1861",
    website: "https://porkbun.com",
  },
  {
    name: "Gandi",
    matchKeys: ["gandi"],
    ianaId: "81",
    website: "https://www.gandi.net",
  },
  {
    name: "Cloudflare",
    matchKeys: ["cloudflare"],
    ianaId: "1910",
    website: "https://www.cloudflare.com",
  },
  {
    name: "Alibaba Cloud",
    matchKeys: ["alibaba", "aliyun", "万网", "xinnet.cn"],
    ianaId: "1938",
    website: "https://www.alibabacloud.com",
  },
  {
    name: "Xinnet",
    matchKeys: ["xinnet", "新网"],
    ianaId: "120",
    website: "https://www.xinnet.com",
  },
  {
    name: "Tencent Cloud",
    matchKeys: ["tencent", "dnspod"],
    ianaId: "2406",
    website: "https://www.tencentcloud.com",
  },
  {
    name: "Huawei Cloud",
    matchKeys: ["huawei"],
    ianaId: "3602",
    website: "https://www.huaweicloud.com",
  },
  {
    name: "Amazon Registrar",
    matchKeys: ["amazon registrar", "amazon technologies"],
    ianaId: "2470",
    website: "https://registrar.amazon.com",
  },
  {
    name: "Network Solutions",
    matchKeys: ["network solutions"],
    ianaId: "2",
    website: "https://www.networksolutions.com",
  },
  {
    name: "Register.com",
    matchKeys: ["register.com"],
    ianaId: "7",
    website: "https://www.register.com",
  },
  {
    name: "eNom",
    matchKeys: ["enom"],
    ianaId: "48",
    website: "https://www.enom.com",
  },
  {
    name: "Web.com",
    matchKeys: ["web.com", "register.com"],
    ianaId: "7",
    website: "https://www.web.com",
  },
  {
    name: "MarkMonitor",
    matchKeys: ["markmonitor"],
    ianaId: "292",
    website: "https://www.markmonitor.com",
  },
  {
    name: "CSC",
    matchKeys: ["csc corporate", "corporation service company"],
    ianaId: "299",
    website: "https://www.cscdbs.com",
  },
  {
    name: "Sedo",
    matchKeys: ["sedo"],
    ianaId: "1316",
    website: "https://www.sedo.com",
  },
  {
    name: "Afternic",
    matchKeys: ["afternic"],
    ianaId: "392",
    website: "https://www.afternic.com",
  },
  {
    name: "HugeDomains",
    matchKeys: ["hugedomains"],
    ianaId: "925",
    website: "https://www.hugedomains.com",
  },
  {
    name: "BuyDomains",
    matchKeys: ["buydomains"],
    ianaId: "2638",
    website: "https://www.buydomains.com",
  },
  {
    name: "Tucows",
    matchKeys: ["tucows", "opensrs"],
    ianaId: "69",
    website: "https://tucows.com",
  },
  {
    name: "Dynadot",
    matchKeys: ["dynadot"],
    ianaId: "472",
    website: "https://www.dynadot.com",
  },
  {
    name: "1&1 IONOS",
    matchKeys: ["ionos", "1&1", "united internet"],
    ianaId: "83",
    website: "https://www.ionos.com",
  },
  {
    name: "OVH",
    matchKeys: ["ovh"],
    ianaId: "1319",
    website: "https://www.ovhcloud.com",
  },
  {
    name: "Hetzner",
    matchKeys: ["hetzner"],
    ianaId: "1383",
    website: "https://www.hetzner.com",
  },
  {
    name: "Hostinger",
    matchKeys: ["hostinger", "hosting24"],
    ianaId: "1636",
    website: "https://www.hostinger.com",
  },
  {
    name: "Name.com",
    matchKeys: ["name.com"],
    ianaId: "625",
    website: "https://www.name.com",
  },
  {
    name: "Netim",
    matchKeys: ["netim"],
    ianaId: "2283",
    website: "https://www.netim.com",
  },
  {
    name: "Wholesale Internet / PDR",
    matchKeys: ["public domain registry", "pdr ltd"],
    ianaId: "303",
    website: "https://www.publicdomainregistry.com",
  },
  {
    name: "GoDaddy (Wild West)",
    matchKeys: ["wild west domains"],
    ianaId: "440",
    website: "https://www.wildwestdomains.com",
  },
  {
    name: "Moniker",
    matchKeys: ["moniker"],
    ianaId: "472",
    website: "https://www.moniker.com",
  },
  {
    name: "Fabulous.com",
    matchKeys: ["fabulous"],
    ianaId: "118",
    website: "https://www.fabulous.com",
  },
  {
    name: "DirectNIC",
    matchKeys: ["directnic"],
    ianaId: "297",
    website: "https://www.directnic.com",
  },
  {
    name: "22.cn",
    matchKeys: ["22.cn", "22net", "亿网"],
    ianaId: "1556",
    website: "https://www.22.cn",
  },
  {
    name: "China NIC",
    matchKeys: ["chinese domain name registration", "chinanic", "中国互联网络信息中心"],
    ianaId: "1479",
    website: "https://www.cnnic.cn",
  },
  {
    name: "ResellerClub",
    matchKeys: ["resellerclub"],
    ianaId: "1495",
    website: "https://www.resellerclub.com",
  },
  {
    name: "EPAG",
    matchKeys: ["epag"],
    ianaId: "85",
    website: "https://www.epag.de",
  },
  {
    name: "United-Domains",
    matchKeys: ["united-domains"],
    ianaId: "1408",
    website: "https://www.united-domains.de",
  },
];

const NORMALIZED_REGISTRAR_CACHE = REGISTRAR_LIBRARY.map((r) => ({
  info: r,
  keys: r.matchKeys.map((k) => k.toLowerCase().replace(/[\s.,\-_()]+/g, "")),
}));

function normalize(s: string): string {
  return s.toLowerCase().replace(/[\s.,\-_()]+/g, "");
}

/**
 * Look up a registrar by name. Returns the matching RegistrarInfo or null.
 * Substring match against aliases; the cache is pre-normalized so callers
 * pass the raw registrar string.
 */
export function findRegistrarInfo(registrar: string): RegistrarInfo | null {
  if (!registrar || registrar === "Unknown") return null;
  const normalized = normalize(registrar);
  for (const { info, keys } of NORMALIZED_REGISTRAR_CACHE) {
    if (keys.some((k) => k.length > 3 && normalized.includes(k))) return info;
    if (normalized.includes(normalize(info.name))) return info;
  }
  return null;
}

/**
 * Resolve the IANA registrar ID for a registrar name, returning the ID string
 * or null when unknown. Used to backfill ianaId when the record omits it.
 */
export function resolveRegistrarIanaId(registrar: string): string | null {
  return findRegistrarInfo(registrar)?.ianaId ?? null;
}
