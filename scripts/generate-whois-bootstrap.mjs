#!/usr/bin/env node
/**
 * Generates src/lib/whois/whois_gtld_bootstrap.ts
 * from IANA's RDAP bootstrap JSON + known RDAP→WHOIS server mappings.
 *
 * Run: node scripts/generate-whois-bootstrap.mjs
 */

import fs from "fs";
import path from "path";

const OUT = path.resolve("src/lib/whois/whois_gtld_bootstrap.ts");

// ── RDAP host → WHOIS host mappings ──────────────────────────────────────────
// Ordered longest-match first so substrings don't shadow full hosts.
const RDAP_TO_WHOIS = [
  // Identity Digital (fka Donuts) — largest gTLD operator
  ["rdap.identitydigital.services",  "whois.identity.digital"],
  // CentralNic
  ["rdap.centralnic.com",            "whois.centralnic.com"],
  // Nominet
  ["rdap.nominet.uk",                "whois.nominet.uk"],
  // Google Registry
  ["pubapi.registry.google",         "whois.nic.google"],
  // GMO Registry
  ["rdap.gmoregistry.net",           "whois.gmoregistry.net"],
  // ZDNS (ChinaCache)
  ["rdap.zdnsgtld.com",              "whois.zdnsgtld.com"],
  // Verisign (.com, .net, .name, .cc, .tv, .edu, etc.)
  ["tld-rdap.verisign.com",          "whois.verisign-grs.com"],
  // Tucows
  ["rdap.tucowsregistry.net",        "whois.tucowsregistry.net"],
  // Mobile Registry
  ["rdap.mobile-registry.com",       "whois.mobile-registry.com"],
  // Public Interest Registry (.org)
  ["rdap.publicinterestregistry.org","whois.publicinterestregistry.org"],
  // Radix
  ["rdap.radix.host",                "whois.radix.host"],
  // Teleinfo / CNNIC
  ["rdap.teleinfo.cn",               "whois.teleinfo.cn"],
  // NIC Brazil
  ["rdap.gtlds.nic.br",              "whois.registro.br"],
  // Registry.click (Minds + Machines)
  ["rdap.registry.click",            "whois.mm-registry.com"],
  // Ryce-RSP
  ["rdap.ryce-rsp.com",              "whois.ryce-rsp.com"],
  // nGTLD (CNNIC)
  ["restwhois.ngtld.cn",             "whois.ngtld.cn"],
  // TWNIC
  ["ccrdap.twnic.tw",                "whois.twnic.net.tw"],
  // Samsung
  ["nic.samsung",                    "whois.nic.samsung"],
  // CONAC (China)
  ["rdap.conac.cn",                  "whois.conac.cn"],
  // FlexiReg
  ["rdap.flexireg.net",              "whois.flexireg.net"],
  // Afilias (now Identity Digital, legacy endpoint)
  ["rdap.afilias.net",               "whois.afilias.net"],
  // Donuts legacy endpoint (some older TLDs)
  ["rdap.donuts.co",                 "whois.donuts.co"],
  // Rightside / Rightside Group
  ["rdap.rightside.co",              "whois.rightside.co"],
  // Neustar
  ["rdap.neustar.biz",               "whois.neustar.biz"],
  // MMX / Minds and Machines
  ["rdap.mmx.co",                    "whois.mmx.co"],
  // Famous Four Media
  ["rdap.get.domains",               "whois.get.domains"],
  // RegistryPro
  ["rdap.registrypro.pro",           "whois.registrypro.pro"],
  // Internet.bs
  ["rdap.internet.bs",               "whois.internet.bs"],
  // Uniregistry (now GoDaddy)
  ["rdap.uniregistry.net",           "whois.uniregistry.net"],
  // Moniker
  ["rdap.moniker.com",               "whois.moniker.com"],
  // NameSilo
  ["rdap.namesilo.com",              "whois.namesilo.com"],
  // KNET
  ["rdap.knet.cn",                   "whois.knet.cn"],
  // CNNIC
  ["rdap.cnnic.cn",                  "whois.cnnic.cn"],
  // JPRS
  ["rdap.jprs.jp",                   "whois.jprs.jp"],
  // DENIC
  ["rdap.denic.de",                  "whois.denic.de"],
  // Namecheap
  ["rdap.namecheap.com",             "whois.namecheap.com"],
  // EPAG
  ["rdap.epag.de",                   "whois.epag.de"],
  // Aridna
  ["rdap.aridna.com",                "whois.aridna.com"],
  // 101domain
  ["rdap.101domain.com",             "whois.101domain.com"],
  // CORE
  ["rdap.core-registry.net",         "whois.core-registry.net"],
];

// ── Well-known individual TLD overrides ──────────────────────────────────────
// These take precedence over pattern-derived values.
const OVERRIDES = {
  // Verisign managed
  "com":   "whois.verisign-grs.com",
  "net":   "whois.verisign-grs.com",
  "cc":    "whois.verisign-grs.com",
  "tv":    "whois.verisign-grs.com",
  "name":  "whois.verisign-grs.com",
  "edu":   "whois.educause.edu",
  // PIR
  "org":   "whois.pir.org",
  // AFILIAS
  "info":  "whois.afilias.net",
  "mobi":  "whois.dotmobiregistry.net",
  "biz":   "whois.biz",
  // Google
  "app":   "whois.nic.google",
  "dev":   "whois.nic.google",
  "page":  "whois.nic.google",
  "how":   "whois.nic.google",
  "soy":   "whois.nic.google",
  "zip":   "whois.nic.google",
  "mov":   "whois.nic.google",
  "foo":   "whois.nic.google",
  "esq":   "whois.nic.google",
  "ing":   "whois.nic.google",
  "rsvp":  "whois.nic.google",
  // ICANN-managed
  "int":   "whois.iana.org",
  "arpa":  "whois.iana.org",
  // Anguilla — managed by IANA/Tucows but WHOIS stays at nic.ai
  "ai":    "whois.nic.ai",
  // Palau — WHOIS at nic.pw
  "pw":    "whois.nic.pw",
  // Donuts (some not yet moved to identity.digital endpoint)
  "academy":      "whois.donuts.co",
  "accountants":  "whois.donuts.co",
  "actor":        "whois.donuts.co",
  "agency":       "whois.donuts.co",
  "airforce":     "whois.donuts.co",
  "apartments":   "whois.donuts.co",
  "associates":   "whois.donuts.co",
  "auction":      "whois.donuts.co",
  "audio":        "whois.donuts.co",
  "band":         "whois.donuts.co",
  "bargains":     "whois.donuts.co",
  "bike":         "whois.donuts.co",
  "bingo":        "whois.donuts.co",
  "boutique":     "whois.donuts.co",
  "builders":     "whois.donuts.co",
  "business":     "whois.donuts.co",
  "cab":          "whois.donuts.co",
  "camera":       "whois.donuts.co",
  "camp":         "whois.donuts.co",
  "capital":      "whois.donuts.co",
  "cards":        "whois.donuts.co",
  "care":         "whois.donuts.co",
  "careers":      "whois.donuts.co",
  "cash":         "whois.donuts.co",
  "catering":     "whois.donuts.co",
  "center":       "whois.donuts.co",
  "chat":         "whois.donuts.co",
  "cheap":        "whois.donuts.co",
  "church":       "whois.donuts.co",
  "city":         "whois.donuts.co",
  "claims":       "whois.donuts.co",
  "cleaning":     "whois.donuts.co",
  "clinic":       "whois.donuts.co",
  "clothing":     "whois.donuts.co",
  "coach":        "whois.donuts.co",
  "codes":        "whois.donuts.co",
  "coffee":       "whois.donuts.co",
  "community":    "whois.donuts.co",
  "company":      "whois.donuts.co",
  "computer":     "whois.donuts.co",
  "condos":       "whois.donuts.co",
  "construction": "whois.donuts.co",
  "consulting":   "whois.donuts.co",
  "contractors":  "whois.donuts.co",
  "cool":         "whois.donuts.co",
  "coupons":      "whois.donuts.co",
  "cruises":      "whois.donuts.co",
  "dance":        "whois.donuts.co",
  "dating":       "whois.donuts.co",
  "deals":        "whois.donuts.co",
  "degree":       "whois.donuts.co",
  "democrat":     "whois.donuts.co",
  "dental":       "whois.donuts.co",
  "design":       "whois.donuts.co",
  "diamonds":     "whois.donuts.co",
  "digital":      "whois.donuts.co",
  "direct":       "whois.donuts.co",
  "directory":    "whois.donuts.co",
  "discount":     "whois.donuts.co",
  "dog":          "whois.donuts.co",
  "domains":      "whois.donuts.co",
  "education":    "whois.donuts.co",
  "email":        "whois.donuts.co",
  "energy":       "whois.donuts.co",
  "engineering":  "whois.donuts.co",
  "enterprises":  "whois.donuts.co",
  "equipment":    "whois.donuts.co",
  "estate":       "whois.donuts.co",
  "events":       "whois.donuts.co",
  "exchange":     "whois.donuts.co",
  "expert":       "whois.donuts.co",
  "exposed":      "whois.donuts.co",
  "express":      "whois.donuts.co",
  "fail":         "whois.donuts.co",
  "farm":         "whois.donuts.co",
  "finance":      "whois.donuts.co",
  "financial":    "whois.donuts.co",
  "fish":         "whois.donuts.co",
  "fitness":      "whois.donuts.co",
  "flights":      "whois.donuts.co",
  "florist":      "whois.donuts.co",
  "football":     "whois.donuts.co",
  "foundation":   "whois.donuts.co",
  "fun":          "whois.donuts.co",
  "fund":         "whois.donuts.co",
  "furniture":    "whois.donuts.co",
  "gallery":      "whois.donuts.co",
  "gifts":        "whois.donuts.co",
  "glass":        "whois.donuts.co",
  "global":       "whois.donuts.co",
  "gold":         "whois.donuts.co",
  "golf":         "whois.donuts.co",
  "graphics":     "whois.donuts.co",
  "gratis":       "whois.donuts.co",
  "gripe":        "whois.donuts.co",
  "guide":        "whois.donuts.co",
  "guitars":      "whois.donuts.co",
  "guru":         "whois.donuts.co",
  "haus":         "whois.donuts.co",
  "healthcare":   "whois.donuts.co",
  "help":         "whois.donuts.co",
  "hockey":       "whois.donuts.co",
  "holdings":     "whois.donuts.co",
  "holiday":      "whois.donuts.co",
  "homes":        "whois.donuts.co",
  "horse":        "whois.donuts.co",
  "hospital":     "whois.donuts.co",
  "house":        "whois.donuts.co",
  "immo":         "whois.donuts.co",
  "immobilien":   "whois.donuts.co",
  "industries":   "whois.donuts.co",
  "institute":    "whois.donuts.co",
  "insure":       "whois.donuts.co",
  "international":"whois.donuts.co",
  "investments":  "whois.donuts.co",
  "kitchen":      "whois.donuts.co",
  "land":         "whois.donuts.co",
  "lease":        "whois.donuts.co",
  "legal":        "whois.donuts.co",
  "life":         "whois.donuts.co",
  "lighting":     "whois.donuts.co",
  "limited":      "whois.donuts.co",
  "limo":         "whois.donuts.co",
  "loans":        "whois.donuts.co",
  "ltd":          "whois.donuts.co",
  "maison":       "whois.donuts.co",
  "management":   "whois.donuts.co",
  "marketing":    "whois.donuts.co",
  "media":        "whois.donuts.co",
  "memorial":     "whois.donuts.co",
  "mobi":         "whois.donuts.co",
  "moda":         "whois.donuts.co",
  "money":        "whois.donuts.co",
  "mortgage":     "whois.donuts.co",
  "moto":         "whois.donuts.co",
  "network":      "whois.donuts.co",
  "news":         "whois.donuts.co",
  "ninja":        "whois.donuts.co",
  "partners":     "whois.donuts.co",
  "parts":        "whois.donuts.co",
  "photography":  "whois.donuts.co",
  "photos":       "whois.donuts.co",
  "pictures":     "whois.donuts.co",
  "pizza":        "whois.donuts.co",
  "place":        "whois.donuts.co",
  "plumbing":     "whois.donuts.co",
  "plus":         "whois.donuts.co",
  "productions":  "whois.donuts.co",
  "properties":   "whois.donuts.co",
  "property":     "whois.donuts.co",
  "pub":          "whois.donuts.co",
  "recipes":      "whois.donuts.co",
  "reisen":       "whois.donuts.co",
  "rentals":      "whois.donuts.co",
  "repair":       "whois.donuts.co",
  "report":       "whois.donuts.co",
  "republican":   "whois.donuts.co",
  "restaurant":   "whois.donuts.co",
  "reviews":      "whois.donuts.co",
  "rip":          "whois.donuts.co",
  "run":          "whois.donuts.co",
  "sale":         "whois.donuts.co",
  "school":       "whois.donuts.co",
  "schule":       "whois.donuts.co",
  "services":     "whois.donuts.co",
  "shoes":        "whois.donuts.co",
  "show":         "whois.donuts.co",
  "singles":      "whois.donuts.co",
  "soccer":       "whois.donuts.co",
  "solar":        "whois.donuts.co",
  "solutions":    "whois.donuts.co",
  "studio":       "whois.donuts.co",
  "style":        "whois.donuts.co",
  "supplies":     "whois.donuts.co",
  "supply":       "whois.donuts.co",
  "support":      "whois.donuts.co",
  "surgery":      "whois.donuts.co",
  "systems":      "whois.donuts.co",
  "tax":          "whois.donuts.co",
  "taxi":         "whois.donuts.co",
  "team":         "whois.donuts.co",
  "technology":   "whois.donuts.co",
  "tips":         "whois.donuts.co",
  "tires":        "whois.donuts.co",
  "today":        "whois.donuts.co",
  "tools":        "whois.donuts.co",
  "tours":        "whois.donuts.co",
  "town":         "whois.donuts.co",
  "trade":        "whois.donuts.co",
  "training":     "whois.donuts.co",
  "university":   "whois.donuts.co",
  "vacations":    "whois.donuts.co",
  "ventures":     "whois.donuts.co",
  "villas":       "whois.donuts.co",
  "vision":       "whois.donuts.co",
  "voyage":       "whois.donuts.co",
  "watch":        "whois.donuts.co",
  "webcam":       "whois.donuts.co",
  "wiki":         "whois.donuts.co",
  "works":        "whois.donuts.co",
  "world":        "whois.donuts.co",
  "wtf":          "whois.donuts.co",
  "zone":         "whois.donuts.co",
};

function rdapHostToWhoisHost(rdapHost, tld) {
  // 1. Check known RDAP host mappings
  for (const [pattern, whois] of RDAP_TO_WHOIS) {
    if (rdapHost === pattern || rdapHost.endsWith("." + pattern)) {
      return whois;
    }
  }
  // 2. Pattern: rdap.nic.{tld} → whois.nic.{tld}
  if (rdapHost === `rdap.nic.${tld}`) {
    return `whois.nic.${tld}`;
  }
  // 3. Pattern: {tld}.rdap.* → try whois.nic.{tld}
  if (rdapHost.startsWith(`${tld}.`)) {
    return `whois.nic.${tld}`;
  }
  // 4. Generic: replace "rdap" with "whois" in host
  if (rdapHost.startsWith("rdap.")) {
    return "whois." + rdapHost.slice(5);
  }
  // 5. Fallback: whois.nic.{tld} (always at least try)
  return `whois.nic.${tld}`;
}

async function main() {
  console.log("Fetching IANA RDAP bootstrap...");
  const res = await fetch("https://data.iana.org/rdap/dns.json");
  const data = await res.json();

  const result = {};

  // Apply overrides first
  Object.assign(result, OVERRIDES);

  // Process IANA data
  for (const [tlds, servers] of data.services) {
    for (const tld of tlds) {
      if (tld in result) continue; // override wins
      const rdapUrl = servers[0] || "";
      const rdapHost = rdapUrl.replace(/https?:\/\//, "").replace(/\/.*$/, "");
      if (!rdapHost) continue;
      result[tld] = rdapHostToWhoisHost(rdapHost, tld);
    }
  }

  // Sort alphabetically
  const sorted = Object.entries(result).sort(([a], [b]) => a.localeCompare(b));

  // Deduplicate by counting unique WHOIS servers
  const serverCounts = {};
  for (const [, whois] of sorted) {
    serverCounts[whois] = (serverCounts[whois] || 0) + 1;
  }
  const topServers = Object.entries(serverCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);

  console.log(`Total entries: ${sorted.length}`);
  console.log("Top WHOIS servers:");
  for (const [host, count] of topServers) {
    console.log(`  ${count.toString().padStart(4)}  ${host}`);
  }

  // Generate TypeScript file
  const lines = [
    `/**`,
    ` * Static WHOIS server bootstrap for gTLDs and ccTLDs.`,
    ` * Used as a performance optimization to skip IANA auto-discovery for known TLDs.`,
    ` * If a TLD is not in this list, the app falls back to IANA WHOIS auto-discovery.`,
    ` *`,
    ` * Sources: IANA RDAP bootstrap (data.iana.org/rdap/dns.json) + known registry mappings`,
    ` * Generated: ${new Date().toISOString().slice(0, 10)}`,
    ` * Entries: ${sorted.length}`,
    ` */`,
    `export const GTLD_WHOIS_BOOTSTRAP: Record<string, string> = {`,
  ];

  for (const [tld, whois] of sorted) {
    lines.push(`  "${tld}": "${whois}",`);
  }
  lines.push(`};`);
  lines.push(``);
  lines.push(`/** Look up the WHOIS server for a given TLD. Returns undefined if not in the bootstrap. */`);
  lines.push(`export function getGtldWhoisServer(tld: string): string | undefined {`);
  lines.push(`  return GTLD_WHOIS_BOOTSTRAP[tld.toLowerCase().replace(/^\\./, "")];`);
  lines.push(`}`);
  lines.push(``);

  fs.writeFileSync(OUT, lines.join("\n"), "utf8");
  console.log(`\nWritten to ${OUT}`);
}

main().catch(console.error);
