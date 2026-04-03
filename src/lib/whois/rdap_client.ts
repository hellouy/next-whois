// node-rdap is ESM-only; use dynamic import() so CJS serverless can load it.
// Pre-warm at module load time so the first request doesn't pay import cost.
let _rdapModuleCache: typeof import("node-rdap") | null = null;
void import("node-rdap").then(m => { _rdapModuleCache = m; }).catch(() => {});
const getRdap = () => _rdapModuleCache ? Promise.resolve(_rdapModuleCache) : import("node-rdap");
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

/** A single vcard property row: [name, params, type, value]. */
type VcardRow = [string, Record<string, unknown>, string, unknown];

export interface RdapEntity {
  handle?: string;
  roles?: string[];
  /** vcardArray[0] is "vcard"; vcardArray[1] is the array of property rows. */
  vcardArray?: ["vcard", VcardRow[]];
  publicIds?: Array<{ type: string; identifier: string }>;
  links?: Array<{ href?: string; rel?: string; type?: string }>;
  entities?: RdapEntity[];
}

export interface RdapResponse {
  handle?: string;
  ldhName?: string;
  unicodeName?: string;
  entities?: RdapEntity[];
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
  // hu: removed — rdap.hu ENODATA (no A record, endpoint is permanently dead); WHOIS via whois.nic.hu works
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
  // su: removed — rdap.tcinet.ru ENOTFOUND (not in IANA bootstrap); WHOIS via whois.tcinet.ru still works
  // tj: removed — rdap.nic.tj ENOTFOUND (not in IANA bootstrap)
  tm: "https://rdap.nic.tm/",
  ua: "https://rdap.hostmaster.ua/",
  uz: "https://rdap.cctld.uz/",                   // IANA: cctld.uz, not nic.uz
  // ── Other Europe ─────────────────────────────────────────────────────────
  // gl: removed — rdap.nic.gl ENOTFOUND (not in IANA bootstrap); WHOIS via whois.nic.gl works
  im: "https://rdap.centralnic.com/im/",           // Isle of Man via CentralNIC
  // xk: removed — rdap.nic.xk ENOTFOUND (not in IANA bootstrap; Kosovo not ICANN-delegated)
  // ── Africa ───────────────────────────────────────────────────────────────
  // ao: removed — rdap.nic.ao ENOTFOUND; whois.dns.pt in cctld-whois-servers.json is also wrong (Portugal DNS)
  // bw: removed — rdap.nic.bw ENOTFOUND; no known WHOIS server for Botswana
  // cd: removed — rdap.nic.cd ENOTFOUND; WHOIS via whois.nic.cd works
  ci: "https://rdap.nic.ci/",
  cm: "https://rdap.nic.cm/",                     // IANA: nic.cm, not netcom.cm
  // dj: removed — rdap.nic.dj ENOTFOUND; WHOIS whois.nic.dj also ENOTFOUND
  // et: removed — rdap.nic.et ENOTFOUND; no known WHOIS server for Ethiopia
  // gh: removed — rdap.nic.gh ENOTFOUND; WHOIS via whois.nic.gh works
  ke: "https://rdap.kenic.or.ke/",
  ly: "https://rdap.nic.ly/",
  mg: "https://rdap.nic.mg/",
  ml: "https://rdap.nic.ml/",
  mu: "https://rdap.identitydigital.services/rdap/", // IANA: IdentityDigital
  // mw: removed — rdap.nic.mw ENOTFOUND; WHOIS whois.nic.mw also times out
  mz: "https://rdap.nic.mz/",
  na: "https://keetmans.omadhina.co.na/",          // IANA: Namibian ccTLD registrar
  ng: "https://rdap.nic.net.ng/",
  rw: "https://rdap.ricta.org.rw/",
  // sc: removed — rdap.nic.sc ENOTFOUND; WHOIS now fixed to whois.nic.sc
  sd: "https://rdap.nic.sd/",
  sn: "https://rdap.nic.sn/whois43/",             // IANA: /whois43/ path required
  so: "https://rdap.nic.so/",
  ss: "https://rdap.nic.ss/",
  td: "https://rdap.nic.td/",
  tz: "https://whois.tznic.or.tz/rdap/",          // IANA: whois.tznic.or.tz/rdap/
  // ug: removed — rdap.nic.ug ENOTFOUND; WHOIS whois.co.ug also ENOTFOUND
  za: "https://rdap.registry.net.za/",             // confirmed: registry.net.za
  zm: "https://rdap.nic.zm/",                      // IANA: nic.zm, not zicta.zm
  // zw: removed — rdap.zispa.co.zw ENOTFOUND; no known WHOIS server for Zimbabwe
  // ── Middle East ──────────────────────────────────────────────────────────
  ae: "https://rdap.aeda.net.ae/",                 // confirmed: aeda.net.ae
  // bh: removed — rdap.nic.bh ENOTFOUND; WHOIS via whois.nic.bh works
  // iq: removed — rdap.nic.iq SERVFAIL in DoH; whois.cmc.iq also NXDOMAIN. No working lookup for Iraq.
  // jo: removed — rdap.nic.jo ENOTFOUND; whois.ripe.net in cctld-whois is wrong for .jo domains
  lb: "https://rdap.lbdr.org.lb/",
  // om: removed — rdap.nic.om ENOTFOUND; WHOIS via whois.registry.om works
  // ps: removed — rdap.nic.ps ENOTFOUND; WHOIS whois.pnina.ps ECONNREFUSED
  // sy: removed — rdap.nic.sy ENOTFOUND; WHOIS via whois.tld.sy works
  ye: "https://rdap.y.net.ye/",
  // ── Asia / Pacific ───────────────────────────────────────────────────────
  af: "https://rdap.nic.af/",
  as: "https://rdap.nic.as/",                      // IANA-confirmed; HTTP 403 from cloud → fail-fast to WHOIS
  au: "https://rdap.cctld.au/rdap/",
  // bn: rdap.bnnic.bn is NXDOMAIN (no RDAP service); WHOIS via whois.bnnic.bn works with DoH fallback
  // bt: removed — rdap.nic.bt ENOTFOUND; WHOIS whois.netnames.net is wrong server
  cc: "https://tld-rdap.verisign.com/cc/v1/",
  cx: "https://rdap.nic.cx/",
  fj: "https://www.rdap.fj/",                      // IANA: www.rdap.fj
  fm: "https://rdap.centralnic.com/fm/",
  gs: "https://rdap.nic.gs/",
  // hk: removed — rdap.hkirc.hk ENOTFOUND; WHOIS via whois.hkirc.hk works
  id: "https://rdap.pandi.id/rdap/",
  in: "https://rdap.nixiregistry.in/rdap/",
  // io: moved to GTLD_RDAP_BOOTSTRAP — IdentityDigital; WHOIS deprecated Aug 2025, all TCP timeouts
  jp: "https://jprs.jp/rdap/",                     // fixed: rdap.jprs.jp ENOTFOUND; jprs.jp/rdap/ works
  // kh: removed — rdap.nic.kh ENOTFOUND; WHOIS whois.nic.kh also ENOTFOUND
  // kr: removed — rdap.kr ENOTFOUND; WHOIS via whois.kr works
  la: "https://rdap.nic.la/",
  // mm: removed — rdap.nic.mm ENOTFOUND; no known working WHOIS server
  // mn: moved to GTLD_RDAP_BOOTSTRAP — IdentityDigital; WHOIS deprecated Aug 2025, all TCP timeouts
  ms: "https://rdap.nic.ms/",
  // mv: removed — rdap.nic.mv ENOTFOUND (Maldives, no public RDAP/WHOIS)
  my: "https://rdap.mynic.my/rdap/",               // confirmed: mynic.my/rdap/
  nf: "https://rdap.nic.nf/",
  // np: removed — rdap.nic.np ENOTFOUND; no known WHOIS server for Nepal
  // nu: removed — rdap.nic.nu ENOTFOUND; WHOIS whois.nic.nu also ENOTFOUND
  // nz: removed — rdap.srs.net.nz ENOTFOUND; WHOIS via whois.srs.net.nz works
  pg: "https://rdap.nic.pg/",
  // ph: removed — rdap.dot.ph SSL/TLS error; WHOIS whois.dot.ph also times out
  // pk: removed — rdap.pknic.net.pk ENOTFOUND; WHOIS via whois.pknic.net.pk works
  pn: "https://rdap.nominet.uk/pn/",
  pw: "https://rdap.radix.host/rdap/",
  sb: "https://rdap.nic.sb/",
  sg: "https://rdap.sgnic.sg/rdap/",
  th: "https://rdap.thains.co.th/",
  tl: "https://rdap.nic.tl/",                      // confirmed: rdap.nic.tl
  to: "https://rdap.tonicregistry.to/rdap/",       // IANA: tonicregistry.to
  tv: "https://rdap.nic.tv/",
  tw: "https://ccrdap.twnic.tw/tw/",
  // vu: removed — rdap.nic.vu ENOTFOUND; WHOIS whois.dnrs.vu also ENOTFOUND
  // ws: removed — rdap.nic.ws ENOTFOUND; WHOIS via whois.website.ws works
  // ── Americas ─────────────────────────────────────────────────────────────
  // ag: moved to GTLD_RDAP_BOOTSTRAP — IdentityDigital; WHOIS deprecated Aug 2025, all TCP timeouts
  // ai: moved to GTLD_RDAP_BOOTSTRAP — IdentityDigital; WHOIS deprecated Aug 2025, all TCP timeouts
  ar: "https://rdap.nic.ar/",                      // IANA-confirmed; slow → see RDAP_TLD_TIMEOUT_MS
  // bb: removed — rdap.nic.bb ENOTFOUND; WHOIS whois.telecoms-barbados.gov.bb also ENOTFOUND
  // bm: moved to GTLD_RDAP_BOOTSTRAP — IdentityDigital; WHOIS deprecated Aug 2025, all TCP timeouts
  br: "https://rdap.registro.br/",                 // IANA-confirmed; HTTP 403 from cloud → fail-fast to WHOIS
  // bz: moved to GTLD_RDAP_BOOTSTRAP — IdentityDigital; rdap.nic.bz ECONNREFUSED
  ca: "https://rdap.ca.fury.ca/rdap/",
  // co: removed — rdap.cctld.co SSL/TLS error (unrecognized SNI); not in IANA bootstrap
  cr: "https://rdap.nic.cr/",
  // cu: removed — rdap.nic.cu ENOTFOUND; .cu also in STATIC_ALWAYS_FALLBACK (political restriction)
  // cv: removed — rdap.nic.cv returns HTTP 404 for ALL paths (server broken/unconfigured as of 2025).
  //   Port 43 WHOIS (whois.nic.cv) also returns ECONNREFUSED.  Registry moved to ola.cv with no
  //   public machine-readable WHOIS.  Keeping cv in the override would make rdapIsDirect=true,
  //   delaying the WHOIS fallback by RDAP_DIRECT_WHOIS_SHADOW_MS for every query unnecessarily.
  // dm: removed — rdap.nic.dm ENOTFOUND; WHOIS via whois.nic.dm works
  ec: "https://rdap.registry.ec/",
  gd: "https://rdap.centralnic.com/gd/",           // IANA: CentralNIC
  gy: "https://rdap.registry.gy/",                 // IANA: registry.gy
  hn: "https://rdap.nic.hn/",
  ht: "https://rdap.nic.ht/",
  // jm: removed — rdap.nic.jm ENOTFOUND; no known WHOIS server for Jamaica
  kn: "https://rdap.nic.kn/",
  ky: "https://whois.kyregistry.ky/rdap/",
  // lc: moved to GTLD_RDAP_BOOTSTRAP — RDAP is complete, WHOIS blocked from our net
  // mx: removed — rdap.mx ENOTFOUND; WHOIS via whois.mx works
  // pe: removed — rdap.nic.pe ENOTFOUND; WHOIS now fixed to whois.nic.pe
  pm: "https://rdap.nic.pm/",
  re: "https://rdap.nic.re/",
  sr: "https://whois.sr/rdap/",                    // IANA: whois.sr/rdap/
  tf: "https://rdap.nic.tf/",
  // tt: removed — rdap.nic.tt ENOTFOUND; WHOIS whois.nic.tt also ENOTFOUND
  // vc: moved to GTLD_RDAP_BOOTSTRAP — RDAP is complete, WHOIS blocked from our net
  ve: "https://rdap.nic.ve/",                      // confirmed: rdap.nic.ve
  vg: "https://rdap.centralnic.com/vg/",
  vi: "https://rdap.nic.vi/",
  wf: "https://rdap.nic.wf/",
  yt: "https://rdap.nic.yt/",
  // ── IDN ccTLDs (Internationalised Country-Code TLDs) ────────────────────
  // Chinese-script
  "xn--j6w193g":       "https://rdap.hkirc.hk/",              // .香港 Hong Kong
  "xn--kprw13d":       "https://ccrdap.twnic.tw/taiwan/",     // .台灣 Taiwan (traditional)
  // Cyrillic
  "xn--p1ai":          "https://rdap.nic.ru/",                // .рф Russia
  "xn--90a3ac":        "https://rdap.rnids.rs/",              // .срб Serbia
  "xn--j1amh":         "https://rdap.hostmaster.ua/",         // .укр Ukraine
  "xn--90ais":         "https://rdap.cctld.by/",              // .бел Belarus
  "xn--y9a3aq":        "https://rdap.nic.am/",                // .հայ Armenia
  "xn--node":          "https://rdap.nic.ge/",                // .გე Georgia
  // Arabic-script
  "xn--mgbah1a3hjkrd": "https://rdap.aeda.net.ae/",           // .الإمارات UAE
  // Korean
  "xn--3e0b707e":      "https://rdap.kr/",                    // .한국 South Korea
  // Indian-script
  "xn--h2brj9c":       "https://rdap.nixiregistry.in/rdap/",  // .भारत India (Devanagari)
  "xn--h2breg3eve":    "https://rdap.nixiregistry.in/rdap/",  // .भारतम् India (Sanskrit)
  "xn--gecrj9c":       "https://rdap.nixiregistry.in/rdap/",  // .ભારત India (Gujarati)
  "xn--45brj9c":       "https://rdap.nixiregistry.in/rdap/",  // .ভারত India (Bengali)
  "xn--xkc2al3hye2a":  "https://rdap.nixiregistry.in/rdap/",  // .இந்தியா India (Tamil)
  "xn--mgbai9azgqp6j": "https://rdap.nixiregistry.in/rdap/",  // .بھارت India (Urdu)
  // Sinhala/Tamil
  "xn--xkc2dl3a5ee0h": "https://rdap.nic.lk/",               // .இலங்கை Sri Lanka (Tamil)
  "xn--fzc2c9e2c":     "https://rdap.nic.lk/",               // .ශ්‍රී ලංකා Sri Lanka (Sinhala)
  // Greek
  "xn--qxam":          "https://rdap.gr/",                   // .ελ Greece
};

/**
 * Set of all ccTLDs with a known direct RDAP endpoint (keys of CCTLD_RDAP_OVERRIDES).
 * Used by lookup.ts to skip the parallel WHOIS race for these TLDs — RDAP is
 * the primary protocol and WHOIS only runs as a sequential fallback if RDAP fails.
 */
export const RDAP_DIRECT_CCTLDS = new Set<string>(Object.keys(CCTLD_RDAP_OVERRIDES));

/**
 * Returns the hand-curated ccTLD RDAP override map (168 entries).
 * Used by the admin built-in server viewer.
 */
export function getCctldRdapOverrides(): Record<string, string> {
  return { ...CCTLD_RDAP_OVERRIDES };
}

/**
 * Per-TLD RDAP timeout overrides (milliseconds).
 * Used for registries that are consistently slow to respond.
 * Default timeout is 4000ms; entries here extend that for specific TLDs.
 */
const RDAP_TLD_TIMEOUT_MS: Record<string, number> = {
  // CIS / Eastern Europe — some servers have higher latency
  ru: 7000, by: 6000, kz: 6000, kg: 6000,
  // Africa — many registries are slower from global infra
  ng: 8000, ke: 7000, tz: 7000, rw: 6000,
  na: 6000, za: 6000, zm: 6000,
  // Middle East
  ye: 7000,
  // Americas — Argentina is genuinely slow from global infra
  ar: 10000,
  // Asia / Pacific — some have higher latency
  la: 6000, bn: 6000, pg: 6000, sb: 6000, tl: 6000,
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

function extractVcardField(vcardArray: VcardRow[], fieldName: string): string {
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
function extractVcardAdr(vcardArray: VcardRow[], component: "street" | "locality" | "region" | "postal-code" | "country"): string {
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
function extractVcardFax(vcardArray: VcardRow[]): string {
  if (!vcardArray || !Array.isArray(vcardArray)) return "Unknown";
  for (const entry of vcardArray) {
    if (Array.isArray(entry) && entry[0] === "tel") {
      const params = entry[1] as Record<string, unknown> | undefined;
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

function parseRdapEntity(entities: RdapEntity[]): {
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
          (pub) => pub.type === "IANA Registrar ID",
        );
        if (ianaEntry) ianaId = ianaEntry.identifier;
      }
      // Prefer explicit `url` field on entity, then fall back to links
      if (entity.links) {
        const aboutLink = entity.links.find(
          (l) => l.rel === "about" || l.rel === "related",
        );
        const selfLink = entity.links.find(
          (l) => l.rel === "self" || l.type === "application/rdap+json",
        );
        const anyLink = entity.links.find((l) => l.href?.startsWith("http"));
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
  rdapData: RdapResponse,
  originalQuery: string,
): Promise<WhoisAnalyzeResult> {
  const entities = rdapData.entities || [];
  const entityData = parseRdapEntity(entities);

  const events = rdapData.events || [];
  const creationEvent = events.find(
    (e) => e.eventAction === "registration",
  );
  const updateEvent = events.find((e) => e.eventAction === "last changed");
  const expirationEvent = events.find(
    (e) => e.eventAction === "expiration",
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

  const status: DomainStatusProps[] = (rdapData.status || []).map((s) => ({
    status: s,
    url: "https://icann.org/epp",
  }));

  const nameServers = (rdapData.nameservers || []).map(
    (ns) => (ns.ldhName || ns.unicodeName || "Unknown").split(/\s+/)[0],
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
