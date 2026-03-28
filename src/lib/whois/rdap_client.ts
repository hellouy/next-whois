// node-rdap is ESM-only; use dynamic import() so CJS serverless can load it
const getRdap = () => import("node-rdap");
import { WhoisAnalyzeResult, DomainStatusProps } from "./types";
import { extractDomain } from "@/lib/utils";
import { applyParams } from "./common_parser";
import { domainToASCII } from "url";
import { getGtldRdapServer } from "./rdap_gtld_bootstrap";

function derivePunycode(unicodeName: string): string | undefined {
  try {
    const ascii = domainToASCII(unicodeName.toLowerCase());
    if (ascii && ascii !== unicodeName.toLowerCase()) {
      return ascii.toUpperCase();
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export interface RdapResponse {
  handle?: string;
  ldhName?: string;
  unicodeName?: string;
  entities?: Array<{
    handle?: string;
    roles?: string[];
    vcardArray?: any[];
    publicIds?: Array<{
      type: string;
      identifier: string;
    }>;
  }>;
  nameservers?: Array<{
    ldhName?: string;
    unicodeName?: string;
  }>;
  status?: string[];
  events?: Array<{
    eventAction: string;
    eventDate: string;
  }>;
  secureDNS?: {
    delegationSigned?: boolean;
    dsData?: Array<{
      keyTag?: number;
      algorithm?: number;
      digest?: string;
      digestType?: number;
    }>;
  };
  notices?: Array<{
    title?: string;
    description?: string[];
    links?: Array<{
      href: string;
      rel?: string;
      type?: string;
    }>;
  }>;
  startAddress?: string;
  endAddress?: string;
  ipVersion?: string;
  name?: string;
  type?: string;
  country?: string;
  parentHandle?: string;
  startAutnum?: string | number;
  endAutnum?: string | number;
}

function isIPAddress(query: string): boolean {
  const bare = query.replace(/\/\d{1,3}$/, "");
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Regex.test(bare) || ipv6Regex.test(bare);
}

function isASNumber(query: string): boolean {
  return /^AS\d+$/i.test(query) || /^\d+$/.test(query);
}

/**
 * Fast-path RDAP endpoints for ccTLDs.
 * Entries here bypass the node-rdap IANA bootstrap lookup entirely — the domain
 * query is sent directly to the listed URL.  Sources:
 *   • IANA RDAP bootstrap  (https://data.iana.org/rdap/dns.json)  ← authoritative
 *   • registry public announcements for TLDs not yet in IANA bootstrap
 */
const CCTLD_RDAP_OVERRIDES: Record<string, string> = {
  // ── Western Europe ───────────────────────────────────────────────────────
  ad: "https://rdap.nic.ad/",
  at: "https://rdap.nic.at/",
  be: "https://rdap.dns.be/",
  ch: "https://rdap.nic.ch/",
  de: "https://rdap.denic.de/",
  dk: "https://rdap.punktum.dk/",
  ee: "https://rdap.tld.ee/",
  es: "https://rdap.nic.es/",
  fi: "https://rdap.fi/rdap/rdap/",
  fo: "https://rdap.centralnic.com/fo/",          // IANA: CentralNIC
  fr: "https://rdap.nic.fr/",
  gr: "https://rdap.gr/",
  hr: "https://rdap.dns.hr/",
  hu: "https://rdap.hu/",
  ie: "https://rdap.iedr.ie/",
  is: "https://rdap.isnic.is/rdap/",              // IANA: /rdap/ suffix
  it: "https://rdap.nic.it/",
  li: "https://rdap.nic.li/",
  lt: "https://rdap.domreg.lt/",
  lu: "https://rdap.dns.lu/",
  lv: "https://rdap.nic.lv/",
  me: "https://rdap.nic.me/",
  nl: "https://rdap.sidn.nl/",
  no: "https://rdap.norid.no/",
  pl: "https://rdap.dns.pl/",
  pt: "https://rdap.dns.pt/",
  ro: "https://rdap.rotld.ro/",
  rs: "https://rdap.rnids.rs/",
  se: "https://rdap.iis.se/",
  si: "https://rdap.register.si/",
  sk: "https://rdap.sk-nic.sk/",
  uk: "https://rdap.nominet.uk/uk/",
  // ── Eastern Europe / CIS ────────────────────────────────────────────────
  al: "https://rdap.nic.al/",
  am: "https://rdap.nic.am/",
  az: "https://rdap.nic.az/",
  ba: "https://rdap.nic.ba/",
  by: "https://rdap.cctld.by/",                   // confirmed: rdap.cctld.by
  cy: "https://rdap.nic.cy/",
  cz: "https://rdap.nic.cz/",
  ge: "https://rdap.nic.ge/",
  kg: "http://rdap.cctld.kg/",                    // IANA: http only (no TLS)
  kz: "https://rdap.nic.kz/",                     // confirmed: rdap.nic.kz
  md: "https://rdap.nic.md/",
  mk: "https://rdap.nic.mk/",
  mt: "https://rdap.nic.mt/",
  ru: "https://rdap.nic.ru/",                     // confirmed: rdap.nic.ru
  su: "https://rdap.tcinet.ru/",                  // Soviet Union legacy TLD (same operator)
  tj: "https://rdap.nic.tj/",
  tm: "https://rdap.nic.tm/",
  ua: "https://rdap.hostmaster.ua/",
  uz: "https://rdap.cctld.uz/",                   // IANA: cctld.uz, not nic.uz
  // ── Other Europe ─────────────────────────────────────────────────────────
  gl: "https://rdap.nic.gl/",
  im: "https://rdap.centralnic.com/im/",           // Isle of Man via CentralNIC
  xk: "https://rdap.nic.xk/",
  // ── Africa ───────────────────────────────────────────────────────────────
  ao: "https://rdap.nic.ao/",
  bw: "https://rdap.nic.bw/",
  cd: "https://rdap.nic.cd/",
  ci: "https://rdap.nic.ci/",
  cm: "https://rdap.nic.cm/",                     // IANA: nic.cm, not netcom.cm
  dj: "https://rdap.nic.dj/",
  et: "https://rdap.nic.et/",
  gh: "https://rdap.nic.gh/",
  ke: "https://rdap.kenic.or.ke/",
  ly: "https://rdap.nic.ly/",
  mg: "https://rdap.nic.mg/",
  ml: "https://rdap.nic.ml/",
  mu: "https://rdap.identitydigital.services/rdap/", // IANA: IdentityDigital
  mw: "https://rdap.nic.mw/",
  mz: "https://rdap.nic.mz/",
  na: "https://keetmans.omadhina.co.na/",          // IANA: Namibian ccTLD registrar
  ng: "https://rdap.nic.net.ng/",
  rw: "https://rdap.ricta.org.rw/",
  sc: "https://rdap.nic.sc/",
  sd: "https://rdap.nic.sd/",
  sn: "https://rdap.nic.sn/whois43/",             // IANA: /whois43/ path required
  so: "https://rdap.nic.so/",
  ss: "https://rdap.nic.ss/",
  td: "https://rdap.nic.td/",
  tz: "https://whois.tznic.or.tz/rdap/",          // IANA: whois.tznic.or.tz/rdap/
  ug: "https://rdap.nic.ug/",
  za: "https://rdap.registry.net.za/",             // confirmed: registry.net.za
  zm: "https://rdap.nic.zm/",                      // IANA: nic.zm, not zicta.zm
  zw: "https://rdap.zispa.co.zw/",
  // ── Middle East ──────────────────────────────────────────────────────────
  ae: "https://rdap.aeda.net.ae/",                 // confirmed: aeda.net.ae
  bh: "https://rdap.nic.bh/",
  iq: "https://rdap.nic.iq/",
  jo: "https://rdap.nic.jo/",
  lb: "https://rdap.lbdr.org.lb/",
  om: "https://rdap.nic.om/",
  ps: "https://rdap.nic.ps/",
  sy: "https://rdap.nic.sy/",
  ye: "https://rdap.y.net.ye/",
  // ── Asia / Pacific ───────────────────────────────────────────────────────
  af: "https://rdap.nic.af/",
  as: "https://rdap.nic.as/",
  au: "https://rdap.cctld.au/rdap/",
  // bn: rdap.bnnic.bn is NXDOMAIN (no RDAP service); WHOIS via whois.bnnic.bn works with DoH fallback
  bt: "https://rdap.nic.bt/",
  cc: "https://tld-rdap.verisign.com/cc/v1/",
  cx: "https://rdap.nic.cx/",
  fj: "https://www.rdap.fj/",                      // IANA: www.rdap.fj
  fm: "https://rdap.centralnic.com/fm/",
  gs: "https://rdap.nic.gs/",
  hk: "https://rdap.hkirc.hk/",
  id: "https://rdap.pandi.id/rdap/",
  in: "https://rdap.nixiregistry.in/rdap/",
  io: "https://rdap.identitydigital.services/rdap/", // confirmed: IdentityDigital
  jp: "https://rdap.jprs.jp/",
  kh: "https://rdap.nic.kh/",
  kr: "https://rdap.kr/",
  la: "https://rdap.nic.la/",
  mm: "https://rdap.nic.mm/",
  mn: "https://rdap.nic.mn/",
  ms: "https://rdap.nic.ms/",
  mv: "https://rdap.nic.mv/",
  my: "https://rdap.mynic.my/rdap/",               // confirmed: mynic.my/rdap/
  nf: "https://rdap.nic.nf/",
  np: "https://rdap.nic.np/",
  nu: "https://rdap.nic.nu/",
  nz: "https://rdap.srs.net.nz/",
  pg: "https://rdap.nic.pg/",
  ph: "https://rdap.dot.ph/",
  pk: "https://rdap.pknic.net.pk/",
  pn: "https://rdap.nominet.uk/pn/",
  pw: "https://rdap.radix.host/rdap/",
  sb: "https://rdap.nic.sb/",
  sg: "https://rdap.sgnic.sg/rdap/",
  th: "https://rdap.thains.co.th/",
  tl: "https://rdap.nic.tl/",                      // confirmed: rdap.nic.tl
  to: "https://rdap.tonicregistry.to/rdap/",       // IANA: tonicregistry.to
  tv: "https://rdap.nic.tv/",
  tw: "https://ccrdap.twnic.tw/tw/",
  vu: "https://rdap.nic.vu/",
  ws: "https://rdap.nic.ws/",
  // ── Americas ─────────────────────────────────────────────────────────────
  ag: "https://rdap.nic.ag/",
  ai: "https://rdap.identitydigital.services/rdap/",
  ar: "https://rdap.nic.ar/",
  bb: "https://rdap.nic.bb/",
  bm: "https://rdap.identitydigital.services/rdap/",
  br: "https://rdap.registro.br/",
  bz: "https://rdap.nic.bz/",
  ca: "https://rdap.ca.fury.ca/rdap/",
  co: "https://rdap.cctld.co/",
  cr: "https://rdap.nic.cr/",
  cu: "https://rdap.nic.cu/",
  // cv: removed — rdap.nic.cv returns HTTP 404 for ALL paths (server broken/unconfigured as of 2025).
  //   Port 43 WHOIS (whois.nic.cv) also returns ECONNREFUSED.  Registry moved to ola.cv with no
  //   public machine-readable WHOIS.  Keeping cv in the override would make rdapIsDirect=true,
  //   delaying the WHOIS fallback by RDAP_DIRECT_WHOIS_SHADOW_MS for every query unnecessarily.
  dm: "https://rdap.nic.dm/",
  ec: "https://rdap.registry.ec/",
  gd: "https://rdap.centralnic.com/gd/",           // IANA: CentralNIC
  gy: "https://rdap.registry.gy/",                 // IANA: registry.gy
  hn: "https://rdap.nic.hn/",
  ht: "https://rdap.nic.ht/",
  jm: "https://rdap.nic.jm/",
  kn: "https://rdap.nic.kn/",
  ky: "https://whois.kyregistry.ky/rdap/",
  lc: "https://rdap.nic.lc/",
  mx: "https://rdap.mx/",
  pe: "https://rdap.nic.pe/",
  pm: "https://rdap.nic.pm/",
  re: "https://rdap.nic.re/",
  sr: "https://whois.sr/rdap/",                    // IANA: whois.sr/rdap/
  tf: "https://rdap.nic.tf/",
  tt: "https://rdap.nic.tt/",
  vc: "https://rdap.nic.vc/",
  ve: "https://rdap.nic.ve/",                      // confirmed: rdap.nic.ve
  vg: "https://rdap.centralnic.com/vg/",
  vi: "https://rdap.nic.vi/",
  wf: "https://rdap.nic.wf/",
  yt: "https://rdap.nic.yt/",
};

/**
 * Set of all ccTLDs with a known direct RDAP endpoint (keys of CCTLD_RDAP_OVERRIDES).
 * Used by lookup.ts to skip the parallel WHOIS race for these TLDs — RDAP is
 * the primary protocol and WHOIS only runs as a sequential fallback if RDAP fails.
 */
export const RDAP_DIRECT_CCTLDS = new Set<string>(Object.keys(CCTLD_RDAP_OVERRIDES));

/**
 * Per-TLD RDAP timeout overrides (milliseconds).
 * Used for registries that are consistently slow to respond.
 * Default timeout is 4000ms; entries here extend that for specific TLDs.
 */
const RDAP_TLD_TIMEOUT_MS: Record<string, number> = {
  // CIS / Eastern Europe — some servers have higher latency
  ru: 7000, su: 7000, by: 6000, kz: 6000, kg: 6000,
  // Africa — many registries are slower from global infra
  ng: 8000, ke: 7000, tz: 7000, gh: 6000, ug: 6000, rw: 6000,
  zm: 6000, zw: 6000, na: 6000, za: 6000, cm: 6000, cd: 6000,
  // Middle East
  iq: 7000, sy: 7000, ye: 7000, ps: 6000,
  // Asia / Pacific — some have higher latency
  pk: 6000, np: 6000, mm: 6000, la: 6000, kh: 6000, bn: 6000,
  bt: 6000, mv: 6000, pg: 6000, sb: 6000, tl: 6000,
};

/**
 * Direct RDAP fetch to a known server URL.
 * Returns the parsed JSON on success, an error object for HTTP errors (including 404),
 * or null on network failure / timeout.
 */
async function tryRdapWithUrl(
  baseUrl: string,
  domainToQuery: string,
  timeoutMs = 4000,
): Promise<any | null> {
  const url = `${baseUrl}domain/${domainToQuery}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(timeoutMs),
    });
    // 404 = domain not found — return the RDAP error object so callers can
    // distinguish "domain doesn't exist" from "server unreachable".
    if (res.status === 404) {
      try {
        const errJson = await res.json();
        return errJson?.errorCode ? errJson : { errorCode: 404, title: "Object Not Found" };
      } catch {
        return { errorCode: 404, title: "Object Not Found" };
      }
    }
    if (!res.ok) return null;
    const json = await res.json();
    return json?.ldhName || json?.handle ? json : null;
  } catch {
    return null;
  }
}

export async function lookupRdap(query: string): Promise<any> {
  const cleanQuery = query.trim().toLowerCase();

  if (isIPAddress(cleanQuery)) {
    const { ip } = await getRdap();
    return await ip(cleanQuery);
  } else if (isASNumber(cleanQuery)) {
    const asNumber = cleanQuery.replace(/^as/i, "");
    const { autnum } = await getRdap();
    return await autnum(parseInt(asNumber));
  } else {
    const domainToQuery = extractDomain(cleanQuery) || cleanQuery;
    const tld = domainToQuery.split(".").pop()?.toLowerCase() ?? "";

    // ── Local bootstrap fast path ─────────────────────────────────────────
    // Check our local maps first (ccTLD overrides + embedded IANA gTLD bootstrap).
    // This bypasses the node-rdap IANA-bootstrap network round-trip entirely for
    // any TLD we know about locally (130+ ccTLDs + 1128+ gTLDs = ~1260 TLDs total).
    const localServer = CCTLD_RDAP_OVERRIDES[tld] ?? getGtldRdapServer(tld);
    if (localServer) {
      const timeoutMs = RDAP_TLD_TIMEOUT_MS[tld] ?? 4000;
      const result = await tryRdapWithUrl(localServer, domainToQuery, timeoutMs);
      if (result !== null) return result;
      // Network/timeout failure on the local-bootstrap server.
      // For ccTLDs: we committed to this server — fail immediately (no fallback).
      // For gTLDs:  fall through to node-rdap which may know an alternate path.
      if (CCTLD_RDAP_OVERRIDES[tld]) {
        throw new Error(`No RDAP server found for ${domainToQuery}`);
      }
    }

    // ── node-rdap fallback (unknown or new TLDs) ──────────────────────────
    try {
      const { domain } = await getRdap();
      const result = await domain(domainToQuery);
      if (result && result.errorCode) throw new Error(`RDAP error ${result.errorCode}`);
      return result;
    } catch {
      throw new Error(`No RDAP server found for ${domainToQuery}`);
    }
  }
}

function extractVcardField(vcardArray: any[], fieldName: string): string {
  if (!vcardArray || !Array.isArray(vcardArray)) return "Unknown";

  for (const entry of vcardArray) {
    if (Array.isArray(entry) && entry[0] === fieldName) {
      return Array.isArray(entry[3])
        ? entry[3].join(", ")
        : String(entry[3] || "Unknown");
    }
  }
  return "Unknown";
}

/**
 * Extract a specific component from a vCard `adr` field.
 * vCard 4.0 adr format: [po-box, ext-addr, street, locality, region, postal-code, country]
 */
function extractVcardAdr(vcardArray: any[], component: "street" | "locality" | "region" | "postal-code" | "country"): string {
  if (!vcardArray || !Array.isArray(vcardArray)) return "Unknown";
  const idxMap = { street: 2, locality: 3, region: 4, "postal-code": 5, country: 6 };
  const idx = idxMap[component];
  for (const entry of vcardArray) {
    if (Array.isArray(entry) && entry[0] === "adr") {
      const val = Array.isArray(entry[3]) ? entry[3][idx] : undefined;
      if (val && String(val).trim()) return String(val).trim();
    }
  }
  return "Unknown";
}

/**
 * Extract fax number from vCard tel entries with type=fax.
 */
function extractVcardFax(vcardArray: any[]): string {
  if (!vcardArray || !Array.isArray(vcardArray)) return "Unknown";
  for (const entry of vcardArray) {
    if (Array.isArray(entry) && entry[0] === "tel") {
      const params = entry[1] as Record<string, any> | undefined;
      if (params && (
        String(params.type || "").toLowerCase().includes("fax") ||
        String(params["type"] || "").toLowerCase().includes("fax")
      )) {
        return String(entry[3] || "Unknown").replace(/^tel:/i, "").trim();
      }
    }
  }
  return "Unknown";
}

function parseRdapEntity(entities: any[]): {
  registrar: string;
  registrarURL: string;
  ianaId: string;
  registrantName: string;
  registrantOrganization: string;
  registrantCountry: string;
  registrantProvince: string;
  registrantCity: string;
  registrantAddress: string;
  registrantPostalCode: string;
  registrantPhone: string;
  registrantFax: string;
  registrantEmail: string;
  adminName: string;
  adminOrganization: string;
  adminCountry: string;
  adminEmail: string;
  adminPhone: string;
  techName: string;
  techOrganization: string;
  techEmail: string;
  techPhone: string;
  abuseEmail: string;
  abusePhone: string;
} {
  let registrar = "Unknown";
  let registrarURL = "Unknown";
  let ianaId = "N/A";
  let registrantName = "Unknown";
  let registrantOrganization = "Unknown";
  let registrantCountry = "Unknown";
  let registrantProvince = "Unknown";
  let registrantCity = "Unknown";
  let registrantAddress = "Unknown";
  let registrantPostalCode = "Unknown";
  let registrantPhone = "Unknown";
  let registrantFax = "Unknown";
  let registrantEmail = "Unknown";
  let adminName = "Unknown";
  let adminOrganization = "Unknown";
  let adminCountry = "Unknown";
  let adminEmail = "Unknown";
  let adminPhone = "Unknown";
  let techName = "Unknown";
  let techOrganization = "Unknown";
  let techEmail = "Unknown";
  let techPhone = "Unknown";
  let abuseEmail = "Unknown";
  let abusePhone = "Unknown";

  for (const entity of entities) {
    if (entity.roles?.includes("registrar")) {
      if (entity.vcardArray?.[1]) {
        const fn = extractVcardField(entity.vcardArray[1], "fn");
        if (fn && fn !== "Unknown") registrar = fn;
      }
      if (entity.publicIds) {
        const ianaEntry = entity.publicIds.find(
          (pub: any) => pub.type === "IANA Registrar ID",
        );
        if (ianaEntry) ianaId = ianaEntry.identifier;
      }
      // Prefer explicit `url` field on entity, then fall back to links
      if (entity.url && entity.url.startsWith("http")) {
        registrarURL = entity.url;
      } else if (entity.links) {
        const aboutLink = entity.links.find(
          (l: any) => l.rel === "about" || l.rel === "related",
        );
        const selfLink = entity.links.find(
          (l: any) => l.rel === "self" || l.type === "application/rdap+json",
        );
        const anyLink = entity.links.find((l: any) => l.href?.startsWith("http"));
        const best = aboutLink || selfLink || anyLink;
        if (best?.href && best.href.startsWith("http")) {
          registrarURL = best.href;
        }
      }
      // Check nested entities inside registrar for abuse contact
      if (entity.entities) {
        for (const sub of entity.entities) {
          if (sub.roles?.includes("abuse") && sub.vcardArray?.[1]) {
            const email = extractVcardField(sub.vcardArray[1], "email");
            const phone = extractVcardField(sub.vcardArray[1], "tel");
            if (email && email !== "Unknown") abuseEmail = email;
            if (phone && phone !== "Unknown") abusePhone = phone.replace(/^tel:/i, "").trim();
          }
        }
      }
    }

    // Top-level abuse entity
    if (entity.roles?.includes("abuse") && entity.vcardArray?.[1]) {
      const email = extractVcardField(entity.vcardArray[1], "email");
      const phone = extractVcardField(entity.vcardArray[1], "tel");
      if (email && email !== "Unknown") abuseEmail = email;
      if (phone && phone !== "Unknown") abusePhone = phone.replace(/^tel:/i, "").trim();
    }

    if (entity.roles?.includes("registrant") && entity.vcardArray?.[1]) {
      const vc = entity.vcardArray[1];
      const fn = extractVcardField(vc, "fn");
      const org = extractVcardField(vc, "org");
      const country = extractVcardField(vc, "country-name") !== "Unknown"
        ? extractVcardField(vc, "country-name")
        : extractVcardAdr(vc, "country");
      const province = extractVcardField(vc, "region") !== "Unknown"
        ? extractVcardField(vc, "region")
        : extractVcardAdr(vc, "region");
      const city = extractVcardAdr(vc, "locality");
      const address = extractVcardAdr(vc, "street");
      const postal = extractVcardAdr(vc, "postal-code");
      const phone = extractVcardField(vc, "tel");
      const fax = extractVcardFax(vc);
      const email = extractVcardField(vc, "email");

      if (fn && fn !== "Unknown") registrantName = fn;
      if (org && org !== "Unknown") registrantOrganization = org;
      if (country && country !== "Unknown") registrantCountry = country;
      if (province && province !== "Unknown") registrantProvince = province;
      if (city && city !== "Unknown") registrantCity = city;
      if (address && address !== "Unknown") registrantAddress = address;
      if (postal && postal !== "Unknown") registrantPostalCode = postal;
      if (phone && phone !== "Unknown") registrantPhone = phone.replace(/^tel:/i, "").trim();
      if (fax && fax !== "Unknown") registrantFax = fax;
      if (email && email !== "Unknown") registrantEmail = email;
    }

    // Administrative contact
    if (entity.roles?.includes("administrative") && entity.vcardArray?.[1]) {
      const vc = entity.vcardArray[1];
      const fn = extractVcardField(vc, "fn");
      const org = extractVcardField(vc, "org");
      const country = extractVcardField(vc, "country-name") !== "Unknown"
        ? extractVcardField(vc, "country-name")
        : extractVcardAdr(vc, "country");
      const phone = extractVcardField(vc, "tel");
      const email = extractVcardField(vc, "email");

      if (fn && fn !== "Unknown" && adminName === "Unknown") adminName = fn;
      if (org && org !== "Unknown" && adminOrganization === "Unknown") adminOrganization = org;
      if (country && country !== "Unknown" && adminCountry === "Unknown") adminCountry = country;
      if (phone && phone !== "Unknown" && adminPhone === "Unknown")
        adminPhone = phone.replace(/^tel:/i, "").trim();
      if (email && email !== "Unknown" && adminEmail === "Unknown") adminEmail = email;
    }

    // Technical contact
    if (entity.roles?.includes("technical") && entity.vcardArray?.[1]) {
      const vc = entity.vcardArray[1];
      const fn = extractVcardField(vc, "fn");
      const org = extractVcardField(vc, "org");
      const phone = extractVcardField(vc, "tel");
      const email = extractVcardField(vc, "email");

      if (fn && fn !== "Unknown" && techName === "Unknown") techName = fn;
      if (org && org !== "Unknown" && techOrganization === "Unknown") techOrganization = org;
      if (phone && phone !== "Unknown" && techPhone === "Unknown")
        techPhone = phone.replace(/^tel:/i, "").trim();
      if (email && email !== "Unknown" && techEmail === "Unknown") techEmail = email;
    }
  }

  return {
    registrar,
    registrarURL,
    ianaId,
    registrantName,
    registrantOrganization,
    registrantCountry,
    registrantProvince,
    registrantCity,
    registrantAddress,
    registrantPostalCode,
    registrantPhone,
    registrantFax,
    registrantEmail,
    adminName,
    adminOrganization,
    adminCountry,
    adminEmail,
    adminPhone,
    techName,
    techOrganization,
    techEmail,
    techPhone,
    abuseEmail,
    abusePhone,
  };
}

export async function convertRdapToWhoisResult(
  rdapData: any,
  originalQuery: string,
): Promise<WhoisAnalyzeResult> {
  const entities = rdapData.entities || [];
  const entityData = parseRdapEntity(entities);

  const events = rdapData.events || [];
  const creationEvent = events.find(
    (e: any) => e.eventAction === "registration",
  );
  const updateEvent = events.find((e: any) => e.eventAction === "last changed");
  const expirationEvent = events.find(
    (e: any) => e.eventAction === "expiration",
  );

  const creationDate = creationEvent?.eventDate || "Unknown";
  const updatedDate = updateEvent?.eventDate || "Unknown";
  const expirationDate = expirationEvent?.eventDate || "Unknown";

  const domainAge =
    creationDate !== "Unknown"
      ? Math.floor(
          (Date.now() - new Date(creationDate).getTime()) /
            (1000 * 60 * 60 * 24),
        )
      : null;

  const remainingDays =
    expirationDate !== "Unknown"
      ? Math.floor(
          (new Date(expirationDate).getTime() - Date.now()) /
            (1000 * 60 * 60 * 24),
        )
      : null;

  const status: DomainStatusProps[] = (rdapData.status || []).map((s: any) => ({
    status: s,
    url: "https://icann.org/epp",
  }));

  const nameServers = (rdapData.nameservers || []).map(
    (ns: any) => (ns.ldhName || ns.unicodeName || "Unknown").split(/\s+/)[0],
  );

  const ldhNameRaw = rdapData.ldhName || undefined;
  const ldhName = ldhNameRaw ? ldhNameRaw.toUpperCase() : undefined;
  const unicodeName = rdapData.unicodeName || undefined;

  let displayDomain: string;
  let punycodeDomain: string | undefined;

  if (unicodeName) {
    displayDomain = unicodeName;
    if (ldhName && ldhName.toLowerCase() !== unicodeName.toLowerCase()) {
      punycodeDomain = ldhName;
    } else {
      punycodeDomain = derivePunycode(unicodeName);
    }
  } else if (ldhNameRaw) {
    const { domainToUnicode } = require("url");
    try {
      const unicode = domainToUnicode(ldhNameRaw.toLowerCase());
      if (unicode && unicode !== ldhNameRaw.toLowerCase()) {
        displayDomain = unicode;
        punycodeDomain = ldhName;
      } else {
        displayDomain = ldhName || ldhNameRaw;
      }
    } catch {
      displayDomain = ldhName || ldhNameRaw;
    }
  } else {
    displayDomain = originalQuery;
  }

  const result = {
    domain: displayDomain,
    domainPunycode: punycodeDomain,
    registrar: entityData.registrar,
    registrarURL: entityData.registrarURL,
    ianaId: entityData.ianaId,
    whoisServer: "https://rdap.org",
    registryDomainId: rdapData.handle || "Unknown",
    updatedDate,
    creationDate,
    expirationDate,
    status,
    nameServers,
    registrantName: entityData.registrantName,
    registrantOrganization: entityData.registrantOrganization,
    registrantCountry: entityData.registrantCountry,
    registrantProvince: entityData.registrantProvince,
    registrantCity: entityData.registrantCity,
    registrantAddress: entityData.registrantAddress,
    registrantPostalCode: entityData.registrantPostalCode,
    registrantPhone: entityData.registrantPhone,
    registrantFax: entityData.registrantFax,
    registrantEmail: entityData.registrantEmail,
    adminName: entityData.adminName,
    adminOrganization: entityData.adminOrganization,
    adminCountry: entityData.adminCountry,
    adminEmail: entityData.adminEmail,
    adminPhone: entityData.adminPhone,
    techName: entityData.techName,
    techOrganization: entityData.techOrganization,
    techEmail: entityData.techEmail,
    techPhone: entityData.techPhone,
    abuseEmail: entityData.abuseEmail,
    abusePhone: entityData.abusePhone,
    dnssec: rdapData.secureDNS?.delegationSigned
      ? "signedDelegation"
      : "unsigned",
    rawWhoisContent: "",
    rawRdapContent: JSON.stringify(rdapData, null, 2),
    domainAge,
    remainingDays,
    registerPrice: null,
    renewPrice: null,
    negotiable: null,
    cidr:
      rdapData.startAddress && rdapData.endAddress
        ? `${rdapData.startAddress}-${rdapData.endAddress}`
        : "Unknown",
    inetNum: rdapData.startAddress || "Unknown",
    inet6Num:
      rdapData.ipVersion === "v6"
        ? rdapData.startAddress || "Unknown"
        : "Unknown",
    netRange:
      rdapData.startAddress && rdapData.endAddress
        ? `${rdapData.startAddress} - ${rdapData.endAddress}`
        : "Unknown",
    netName: rdapData.name || "Unknown",
    netType: rdapData.type || "Unknown",
    originAS: rdapData.startAutnum ? `AS${rdapData.startAutnum}` : "Unknown",
  };

  return await applyParams(result);
}
