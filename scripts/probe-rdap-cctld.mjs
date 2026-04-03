#!/usr/bin/env node
/**
 * Probe all active ccTLD RDAP endpoints in CCTLD_RDAP_OVERRIDES.
 * Tests each by fetching <base>domain/test with a 5-second timeout.
 * Results: alive (any HTTP response), dead (DNS/conn fail), timeout.
 */

const ENDPOINTS = {
  // Western Europe
  ad: "https://rdap.nic.ad/",
  ch: "https://rdap.nic.ch/",
  de: "https://rdap.denic.de/",
  fi: "https://rdap.fi/rdap/rdap/",
  fo: "https://rdap.centralnic.com/fo/",
  fr: "https://rdap.nic.fr/",
  gr: "https://rdap.gr/",
  is: "https://rdap.isnic.is/rdap/",
  li: "https://rdap.nic.li/",
  nl: "https://rdap.sidn.nl/",
  no: "https://rdap.norid.no/",
  pl: "https://rdap.dns.pl/",
  si: "https://rdap.register.si/",
  sk: "https://rdap.sk-nic.sk/",
  uk: "https://rdap.nominet.uk/uk/",
  // Eastern Europe / CIS
  by: "https://rdap.cctld.by/",
  cz: "https://rdap.nic.cz/",
  kg: "http://rdap.cctld.kg/",
  kz: "https://rdap.nic.kz/",
  ru: "https://rdap.nic.ru/",
  tm: "https://rdap.nic.tm/",
  ua: "https://rdap.hostmaster.ua/",
  uz: "https://rdap.cctld.uz/",
  // Other Europe
  im: "https://rdap.centralnic.com/im/",
  // Africa
  ci: "https://rdap.nic.ci/",
  cm: "https://rdap.nic.cm/",
  ke: "https://rdap.kenic.or.ke/",
  ly: "https://rdap.nic.ly/",
  mg: "https://rdap.nic.mg/",
  ml: "https://rdap.nic.ml/",
  mu: "https://rdap.identitydigital.services/rdap/",
  mz: "https://rdap.nic.mz/",
  na: "https://keetmans.omadhina.co.na/",
  ng: "https://rdap.nic.net.ng/",
  rw: "https://rdap.ricta.org.rw/",
  sd: "https://rdap.nic.sd/",
  sn: "https://rdap.nic.sn/whois43/",
  so: "https://rdap.nic.so/",
  ss: "https://rdap.nic.ss/",
  td: "https://rdap.nic.td/",
  tz: "https://whois.tznic.or.tz/rdap/",
  za: "https://rdap.registry.net.za/",
  zm: "https://rdap.nic.zm/",
  // Middle East
  ae: "https://rdap.aeda.net.ae/",
  lb: "https://rdap.lbdr.org.lb/",
  ye: "https://rdap.y.net.ye/",
  // Asia / Pacific
  af: "https://rdap.nic.af/",
  as: "https://rdap.nic.as/",
  au: "https://rdap.cctld.au/rdap/",
  cc: "https://tld-rdap.verisign.com/cc/v1/",
  cx: "https://rdap.nic.cx/",
  fj: "https://www.rdap.fj/",
  fm: "https://rdap.centralnic.com/fm/",
  gs: "https://rdap.nic.gs/",
  id: "https://rdap.pandi.id/rdap/",
  in: "https://rdap.nixiregistry.in/rdap/",
  jp: "https://jprs.jp/rdap/",
  la: "https://rdap.nic.la/",
  ms: "https://rdap.nic.ms/",
  my: "https://rdap.mynic.my/rdap/",
  nf: "https://rdap.nic.nf/",
  pg: "https://rdap.nic.pg/",
  pn: "https://rdap.nominet.uk/pn/",
  pw: "https://rdap.radix.host/rdap/",
  sb: "https://rdap.nic.sb/",
  sg: "https://rdap.sgnic.sg/rdap/",
  th: "https://rdap.thains.co.th/",
  tl: "https://rdap.nic.tl/",
  to: "https://rdap.tonicregistry.to/rdap/",
  tv: "https://rdap.nic.tv/",
  tw: "https://ccrdap.twnic.tw/tw/",
  // Americas
  ar: "https://rdap.nic.ar/",
  br: "https://rdap.registro.br/",
  ca: "https://rdap.ca.fury.ca/rdap/",
  cr: "https://rdap.nic.cr/",
  ec: "https://rdap.registry.ec/",
  gd: "https://rdap.centralnic.com/gd/",
  gy: "https://rdap.registry.gy/",
  hn: "https://rdap.nic.hn/",
  ht: "https://rdap.nic.ht/",
  kn: "https://rdap.nic.kn/",
  ky: "https://whois.kyregistry.ky/rdap/",
  pm: "https://rdap.nic.pm/",
  re: "https://rdap.nic.re/",
  sr: "https://whois.sr/rdap/",
  tf: "https://rdap.nic.tf/",
  ve: "https://rdap.nic.ve/",
  vg: "https://rdap.centralnic.com/vg/",
  vi: "https://rdap.nic.vi/",
  wf: "https://rdap.nic.wf/",
  yt: "https://rdap.nic.yt/",
  // IDN ccTLDs
  "xn--kprw13d":       "https://ccrdap.twnic.tw/taiwan/",
  "xn--p1ai":          "https://rdap.nic.ru/",
  "xn--j1amh":         "https://rdap.hostmaster.ua/",
  "xn--90ais":         "https://rdap.cctld.by/",
  "xn--mgbah1a3hjkrd": "https://rdap.aeda.net.ae/",
  "xn--h2brj9c":       "https://rdap.nixiregistry.in/rdap/",
  "xn--h2breg3eve":    "https://rdap.nixiregistry.in/rdap/",
  "xn--gecrj9c":       "https://rdap.nixiregistry.in/rdap/",
  "xn--45brj9c":       "https://rdap.nixiregistry.in/rdap/",
  "xn--xkc2al3hye2a":  "https://rdap.nixiregistry.in/rdap/",
  "xn--mgbai9azgqp6j": "https://rdap.nixiregistry.in/rdap/",
  "xn--qxam":          "https://rdap.gr/",
};

const TIMEOUT_MS = 7000;
const CONCURRENCY = 10;

async function probe(tld, baseUrl) {
  const url = baseUrl.endsWith("/") ? `${baseUrl}domain/test` : `${baseUrl}/domain/test`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json, application/json, */*" },
      redirect: "follow",
    });
    clearTimeout(timer);
    return { tld, baseUrl, status: res.status, result: "alive" };
  } catch (err) {
    clearTimeout(timer);
    const msg = err.message || String(err);
    let result = "dead";
    if (err.name === "AbortError") result = "timeout";
    else if (msg.includes("ENOTFOUND") || msg.includes("NXDOMAIN")) result = "nxdomain";
    else if (msg.includes("ECONNREFUSED")) result = "connrefused";
    else if (msg.includes("certificate") || msg.includes("TLS") || msg.includes("SSL") || msg.includes("ERR_CERT")) result = "tls_error";
    return { tld, baseUrl, status: null, result, error: msg };
  }
}

async function runBatch(entries) {
  return Promise.all(entries.map(([tld, url]) => probe(tld, url)));
}

const all = Object.entries(ENDPOINTS);
const results = [];

for (let i = 0; i < all.length; i += CONCURRENCY) {
  const batch = all.slice(i, i + CONCURRENCY);
  const batchResults = await runBatch(batch);
  results.push(...batchResults);
  process.stdout.write(`Probed ${Math.min(i + CONCURRENCY, all.length)}/${all.length}...\r`);
}

console.log("\n\n=== RESULTS ===\n");

const alive = results.filter(r => r.result === "alive");
const dead = results.filter(r => r.result !== "alive");

console.log(`ALIVE (${alive.length}):`);
for (const r of alive.sort((a,b) => a.tld.localeCompare(b.tld))) {
  console.log(`  ✓ .${r.tld.padEnd(20)} HTTP ${r.status}  ${r.baseUrl}`);
}

console.log(`\nDEAD/TIMEOUT (${dead.length}):`);
for (const r of dead.sort((a,b) => a.tld.localeCompare(b.tld))) {
  console.log(`  ✗ .${r.tld.padEnd(20)} [${r.result}]  ${r.baseUrl}`);
  if (r.error) console.log(`      ${r.error.substring(0, 120)}`);
}

console.log(`\nSUMMARY: ${alive.length} alive, ${dead.length} dead/timeout out of ${results.length} total`);
