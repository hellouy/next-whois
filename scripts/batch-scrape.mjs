/**
 * TLD Lifecycle Batch Scraper — v2 (Improved)
 *
 * Usage:
 *   node scripts/batch-scrape.mjs [options]
 *
 * Options:
 *   --tld jp            Single TLD (debug mode)
 *   --type cc|gtld|all  Which TLDs to scrape (default: cc)
 *   --force             Overwrite fresh/manually-edited records
 *   --clear-defaults    Re-scrape records where all values are defaults (30/30/5)
 *   --concurrency 2     Parallel TLD workers
 *   --delay 2000        ms delay between batches
 *   --dry-run           Simulate without saving
 *   --debug             Print page text sent to AI
 *
 * Key improvements in v2:
 *  1. Curated registry URL database (50+ major ccTLDs)
 *  2. Per-TLD custom discovery strategy
 *  3. Better Jina Reader integration for JS-rendered sites
 *  4. AI result validation: flags "all defaults" for review
 *  5. Fallback retry with second AI model
 *  6. Better source_url: only set if AI actually found data
 *  7. Smarter path probing (TLD-specific paths first)
 *  8. ICANN gTLD auto-classify for contracted registries
 */

import pg from "pg";
import * as cheerio from "cheerio";
import fs from "fs";

// ── CLI ───────────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const getArg  = n => { const i = args.indexOf(n); return i >= 0 ? args[i+1] : null; };
const hasFlag = n => args.includes(n);
const SINGLE_TLD   = getArg("--tld");
const TYPE         = getArg("--type") ?? "cc";
const FORCE        = hasFlag("--force");
const CLEAR_DEFS   = hasFlag("--clear-defaults");
const CONCURRENCY  = parseInt(getArg("--concurrency") ?? "2");
const DELAY_MS     = parseInt(getArg("--delay") ?? "3000");
const DRY_RUN      = hasFlag("--dry-run");
const DEBUG        = hasFlag("--debug");

// ── Database ──────────────────────────────────────────────────────────────────
const DB_URL =
  process.env.POSTGRES_URL ||
  process.env.POSTGRES_URL_NON_POOLING ||
  process.env.SUPABASE_DATABASE_URL ||
  process.env.DATABASE_URL;
if (!DB_URL) {
  console.error("[batch-scrape] No database URL found. Set POSTGRES_URL or SUPABASE_DATABASE_URL.");
  process.exit(1);
}
const pool = new pg.Pool({
  connectionString: DB_URL,
  ssl: { rejectUnauthorized: false },
  max: 4,
});
const dbOne = (sql, p=[]) => pool.query(sql, p).then(r => r.rows[0] ?? null);
const dbRun = (sql, p=[]) => pool.query(sql, p);

// ── Curated lifecycle page URLs for known registries ──────────────────────────
// Direct links to lifecycle/deletion policy pages — skips all discovery
const CURATED_LIFECYCLE_URLS = {
  // Europe
  de: "https://www.denic.de/en/products/de-domains/deletion/",
  uk: "https://www.nominet.uk/domain-support/frequently-asked-questions/what-happens-when-domain-expires/",
  fr: "https://www.afnic.fr/en/domain-names-and-support/everything-there-is-to-know-about-domain-names/the-lifecycle-of-a-fr-domain-name/",
  nl: "https://www.sidn.nl/en/nl-domain/expiry-and-deletion-of-a-nl-domain-name",
  it: "https://www.nic.it/en/faqs",
  es: "https://www.dominios.es/en/domain-names/expiration-and-deletion",
  ch: "https://www.nic.ch/en/domains/whats-happening/",
  at: "https://www.nic.at/en/domain/lifecycle",
  pl: "https://dns.pl/en/domain-lifecycle",
  se: "https://www.iis.se/en/domains/frequently-asked-questions/",
  no: "https://www.norid.no/en/registrant/domain-lifecycle/",
  dk: "https://www.punktum.dk/en/about-dk/domain-lifecycle/",
  fi: "https://www.traficom.fi/en/communications/domains/fi-domain-name-lifecycle",
  be: "https://www.dnsbelgium.be/en/the-dot-be-domain/lifecycle",
  pt: "https://pt.pt/en/pt-domain/lifecycle/",
  ie: "https://www.iedr.ie/domain-lifecycle/",
  lu: "https://www.dns.lu/en/domain-names-a-services/your-domain-name/domain-lifecycle/",
  li: "https://www.nic.li/en/domain/lifecycle/",
  hu: "https://www.domain.hu/en/lifecycle/",
  cz: "https://www.nic.cz/en/domain/lifecycle/",
  sk: "https://sk-nic.sk/en/domain/lifecycle/",
  ro: "https://www.rotld.ro/en/policies/lifecycle/",
  bg: "https://www.register.bg/user/static/info/lifecycle/index.html",
  hr: "https://www.dns.hr/en/domain/lifecycle",
  si: "https://www.register.si/en/domain-names/lifecycle/",
  rs: "https://www.rnids.rs/en/domains/domain-lifecycle",
  me: "https://www.domena.me/en/domain/lifecycle",
  ba: "https://www.nic.ba/en/domain/lifecycle/",
  gr: "https://grweb.ics.forth.gr/en/domain/lifecycle",
  cy: "https://www.nic.cy/nslookup/en/domain/lifecycle",
  ee: "https://www.internet.ee/en/domain-lifecycle",
  lv: "https://www.nic.lv/en/domain/lifecycle",
  lt: "https://domreg.lt/en/domain/lifecycle",
  is: "https://www.isnic.is/en/domain/lifecycle",
  // Asia-Pacific
  jp: "https://jprs.jp/about/dom-rule/lifecycle/",
  cn: "https://www.cnnic.net.cn/en/rules-policy/",
  hk: "https://www.hkirc.hk/en/registration/domainInfo/lifecycle.htm",
  tw: "https://www.twnic.tw/en/registration/lifecycle.php",
  kr: "https://www.kisa.or.kr/en/service/domainLifecycle.do",
  sg: "https://www.sgnic.sg/domainregistration/lifecycle.html",
  au: "https://www.auda.org.au/au-domain-names/life-and-death-of-an-au-domain-name/",
  nz: "https://dnc.org.nz/domain-names/managing-your-domain-name/expiry-and-deletion/",
  in: "https://registry.in/en/domain-lifecycle",
  id: "https://pandi.id/en/lifecycle",
  my: "https://mynic.my/en/domain-lifecycle",
  ph: "https://dot.ph/domain-lifecycle",
  vn: "https://vnnic.vn/en/domain/lifecycle",
  th: "https://www.thnic.co.th/en/domain/lifecycle",
  pk: "https://pk.cctld.pk/domain/lifecycle",
  bd: "https://www.btcl.com.bd/en/domain/lifecycle",
  lk: "https://domreg.lk/en/domain/lifecycle",
  // Americas
  us: "https://about.nic.us/en/domain-lifecycle",
  ca: "https://www.cira.ca/en/domain-names/about-ca/lifecycle-of-a-domain-name/",
  mx: "https://www.nic.mx/en/lifecycle",
  br: "https://registro.br/en/domain/lifecycle/",
  ar: "https://nic.ar/en/domain/lifecycle",
  cl: "https://www.nic.cl/en/domain/lifecycle",
  co: "https://www.cointernet.co/en/domain/lifecycle",
  pe: "https://punto.pe/en/domain/lifecycle",
  ve: "https://www.nic.ve/en/domain/lifecycle",
  uy: "https://www.nic.org.uy/en/domain/lifecycle",
  // Africa & Middle East
  za: "https://www.registry.net.za/lifecycle.shtml",
  ng: "https://www.nira.org.ng/lifecycle",
  ke: "https://www.kenic.or.ke/en/domain/lifecycle",
  eg: "https://www.egregistry.eg/en/lifecycle",
  ma: "https://www.iam.net.ma/en/domain/lifecycle",
  ae: "https://aeda.ae/en/domain-lifecycle",
  sa: "https://nic.sa/en/service/lifecycle",
  // Other important
  ru: "https://cctld.ru/en/domains/rules/lifecycle/",
  ua: "https://hostmaster.ua/en/domain/lifecycle/",
  tr: "https://www.nic.tr/en/domain/lifecycle",
  il: "https://www.isoc.org.il/en/domain/lifecycle",
};

// Curated well-known data for registries with documented specific policies.
// Only use when scraping completely fails to extract real data.
// Format: { grace, redemption, pending, drop_hour, drop_minute, drop_timezone, pre_expiry, note }
const KNOWN_POLICIES = {
  de: { grace: 0, redemption: 30, pending: 0, note: "DENIC: immediate deletion then 30-day RGP; no autorenew grace; no pending-delete" },
  nl: { grace: 0, redemption: 40, pending: 5, note: "SIDN: 40-day quarantine, 5-day pending purge; no autorenew grace" },
  au: { grace: 29, redemption: 30, pending: 5, pre_expiry: 0, note: "auDA: 29-day autorenew grace + 30-day redemption + 5-day pending" },
  ca: { grace: 40, redemption: 30, pending: 5, note: "CIRA: 40-day grace + 30-day redemption + 5-day pending" },
  uk: { grace: 0, redemption: 90, pending: 0, note: "Nominet: 90-day suspension, then available; no autorenew grace period" },
  fr: { grace: 30, redemption: 30, pending: 5, note: "AFNIC: 30-day grace + 30-day redemption + 5-day pending" },
  jp: { grace: 0, redemption: 30, pending: 0, note: "JPRS generic .jp: Suspended 1 month (recovery 1-20th), then deleted; no pending-delete" },
  cn: { grace: 30, redemption: 30, pending: 5, note: "CNNIC: 30-day grace + 30-day redemption + 5-day pending (estimated based on ICANN)" },
  in: { grace: 0, redemption: 30, pending: 0, pre_expiry: 30, note: "NIXI: domain deleted 30 days BEFORE expiry date; 30-day redemption after" },
  br: { grace: 30, redemption: 30, pending: 5, note: "Registro.br: 30/30/5 standard" },
  ru: { grace: 30, redemption: 30, pending: 0, note: "CCTLD.ru: 30-day grace + 30-day hold; no pending-delete phase" },
  se: { grace: 0, redemption: 60, pending: 0, note: "IIS .se: 60-day hold period after deletion; no autorenew grace" },
  dk: { grace: 0, redemption: 30, pending: 0, drop_hour: 11, drop_minute: 0, drop_timezone: "Europe/Copenhagen", note: "Punktum.dk: 30-day quarantine, drops at 11:00 CET" },
  no: { grace: 0, redemption: 30, pending: 0, note: "Norid .no: 30-day quarantine period" },
  fi: { grace: 0, redemption: 30, pending: 0, note: "Traficom .fi: 30-day quarantine" },
  be: { grace: 0, redemption: 40, pending: 0, note: "DNS Belgium .be: 40-day quarantine" },
  at: { grace: 30, redemption: 30, pending: 0, note: "NIC.at .at: 30-day grace + 30-day hold; no pending-delete" },
  ch: { grace: 0, redemption: 40, pending: 0, note: "SWITCH .ch: 40-day quarantine after deletion" },
  pl: { grace: 0, redemption: 30, pending: 0, note: "DNS.pl .pl: 30-day hold period" },
  it: { grace: 30, redemption: 30, pending: 5, note: "NIC.it .it: standard 30/30/5" },
  nz: { grace: 90, redemption: 0, pending: 0, note: "DNC .nz: 90-day auto-renew grace, no redemption, no pending" },
  za: { grace: 30, redemption: 30, pending: 5, note: "ZACR .za: 30/30/5 ICANN-style" },
};

// Sites known to require Jina Reader (JS-rendered, blocks crawlers, etc.)
const JINA_FIRST_SITES = new Set([
  "denic.de", "nic.fr", "afnic.fr", "nominet.uk", "auda.org.au",
  "cira.ca", "registro.br", "cctld.ru", "iis.se", "punktum.dk",
  "norid.no", "traficom.fi", "dnsbelgium.be", "nic.at", "nic.cz",
  "jprs.jp", "hkirc.hk",
]);

// ── Lifecycle keyword detection ───────────────────────────────────────────────
const LIFECYCLE_KEYWORDS = [
  "grace period","redemption period","pending delete","pendingdelete",
  "rgp","autorenew grace","auto-renew grace","registry grace period",
  "add grace period","drop time","drop date","drop catch",
  "lifecycle","life cycle","domain lifecycle","domain expiration",
  "expiry period","expiration period","renewal grace period",
  "domain deletion","domain expiry","restore period","redemption grace",
  "quarantine period","suspension period","hold period",
  // German
  "schonfrist","löschfrist","löschantrag","wiederherstellungsphase",
  "domainlöschung","freigabephase","kulanzzeit","sperrphase",
  "redemption grace period","rgp","30 tage","60 tage","40 tage",
  // French
  "période de grâce","rédemption","suppression en attente","cycle de vie",
  "durée de grâce","quarantaine",
  // Japanese
  "ライフサイクル","猶予期間","回復期間","削除待ち","登録回復","廃止","Suspended",
  "廃止申請","期限","月末","Deleted",
  // Chinese
  "宽限期","赎回期","待删除","掉落时间","释放时间","删除时间","续费宽限","到期删除",
  // Korean
  "갱신유예","복구기간","삭제대기","라이프사이클",
  // Russian
  "период льготы","период выкупа","карантин",
  // Dutch
  "quarantaine","verwijderingsperiode","restoratieperiode",
  // Norwegian/Swedish/Danish
  "karanteneperiode","karantän","sletteperiode","opsigelsesperiode",
];

function hasLifecycleInfo(text) {
  const lower = text.toLowerCase();
  return LIFECYCLE_KEYWORDS.some(kw => lower.includes(kw.toLowerCase()));
}

const LINK_KEYWORDS = [
  "lifecycle","life-cycle","grace","redemption","renewal","expir",
  "policy","policies","deletion","expiry","suspend","quarantine","restore",
  "lebenszyklus","lösch","kündig","schonfrist",
  "cycle","suppression","rédem","quarantaine",
  "ライフサイクル","猶予","削除","廃止","回復",
  "라이프사이클","갱신","삭제","복구",
  "待删","宽限","赎回","续费","生命周期","到期",
  "karantän","karantene","sletteperiode",
];

function hasLinkKeyword(href, text) {
  const combo = `${href} ${text}`.toLowerCase();
  return LINK_KEYWORDS.some(kw => combo.includes(kw.toLowerCase()));
}

// ── Targeted probe paths (tried in order, most likely first) ─────────────────
const PROBE_PATHS = [
  "/domain-lifecycle", "/lifecycle", "/en/lifecycle", "/domains/lifecycle",
  "/en/domains/lifecycle", "/en/domain-lifecycle", "/en/domain-names/lifecycle",
  "/domains/domain-lifecycle", "/en/domains/domain-lifecycle",
  "/domain-names/lifecycle", "/support/lifecycle", "/faq/lifecycle",
  "/about/domain-lifecycle", "/about/dom-rule/lifecycle",
  "/en/products/de-domains/deletion", "/en/products/de-domains/lifecycle",
  "/deletion", "/en/deletion", "/domains/deletion", "/en/domains/deletion",
  "/domain-expiry", "/domain-expiration",
  "/policies", "/en/policies", "/domains/policies",
  "/en/domain-names-and-support/managing-a-domain-name",
  "/for-registrants/au-domain-administration",
  "/registrant/domain-lifecycle", "/en/registrant",
  "/faq", "/en/faq", "/help", "/en/help", "/support", "/en/support",
  "/domain-names", "/en/domain-names", "/en/domains",
  "/about", "/en/about", "/about/jp-dom/spec",
  "/en/the-dot-de-domain", "/en/domains/conditions",
  "/en/service/domainLifecycle",
  "/lifecycle.shtml", "/lifecycle.html", "/lifecycle.php",
  "/registration/lifecycle", "/registration/lifecycle.php",
];

// ── HTTP helpers ──────────────────────────────────────────────────────────────
async function fetchRaw(url, ms = 15000) {
  const res = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; domain-lifecycle-crawler/2.0; +https://x.rw)",
      Accept: "text/html,application/xhtml+xml,*/*;q=0.9",
      "Accept-Language": "en,zh;q=0.9,ja;q=0.8,de;q=0.7,fr;q=0.6,ko;q=0.5,nl;q=0.4",
    },
    signal: AbortSignal.timeout(ms),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

async function fetchViaJina(url, ms = 30000) {
  const jinaUrl = `https://r.jina.ai/${url}`;
  const res = await fetch(jinaUrl, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; domain-lifecycle-crawler/2.0)",
      Accept: "text/plain,text/markdown,*/*",
      "X-No-Cache": "true",
    },
    signal: AbortSignal.timeout(ms),
  });
  if (!res.ok) throw new Error(`Jina HTTP ${res.status}`);
  const text = await res.text();
  if (!text || text.length < 80 || text.includes("Warning: Target URL returned error 404")) {
    throw new Error("Jina: empty or 404");
  }
  return text;
}

function pageOrigin(url) {
  try { return new URL(url).origin; } catch { return ""; }
}

function extractText(html, maxChars = 12000) {
  const $ = cheerio.load(html);
  $("script,style,nav,header,footer,noscript,iframe,svg,button,form,aside,cookie").remove();
  // Try content-specific selectors first
  const selectors = ["main","article","[class*=content]","[id*=content]","[class*=policy]",
                     "[class*=lifecycle]","[class*=domain]",".entry-content",".page-content","body"];
  let rawText = "";
  for (const sel of selectors) {
    const el = $(sel).first();
    if (el.length && el.text().trim().length > 200) {
      rawText = el.text();
      break;
    }
  }
  if (!rawText) rawText = $("body").text();
  rawText = rawText.replace(/\s{3,}/g, "\n").replace(/\n{4,}/g, "\n\n").trim();
  if (rawText.length <= maxChars) return rawText;
  // Prioritize lines with lifecycle keywords
  const lines = rawText.split("\n");
  const relevant = [], other = [];
  for (const line of lines) {
    if (LIFECYCLE_KEYWORDS.some(kw => line.toLowerCase().includes(kw.toLowerCase()))) {
      relevant.push(line);
    } else { other.push(line); }
  }
  const p1 = relevant.join("\n").slice(0, Math.floor(maxChars * 0.75));
  const p2 = other.join("\n").slice(0, maxChars - p1.length);
  return (p1 + "\n\n" + p2).slice(0, maxChars);
}

function extractRegistryUrl(html) {
  // IANA page format: "URL for registration services: http://..."
  const m1 = html.match(/<b>URL for registration services:<\/b>\s*<a href="([^"]+)"/i);
  if (m1) return m1[1].replace(/\/$/, "");
  const m2 = html.match(/URL for registration services[^\n]*\n?\s*(https?:\/\/[^\s\n<>]+)/i);
  if (m2) return m2[1].replace(/\/$/, "").replace(/[)\]>]+$/, "");
  return null;
}

function extractLinksFromHtml(html, baseUrl) {
  const $ = cheerio.load(html);
  const origin = pageOrigin(baseUrl);
  const seen = new Set(), links = [];
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href") ?? "";
    const text = $(el).text().trim();
    if (!hasLinkKeyword(href, text)) return;
    let abs;
    try { abs = new URL(href, baseUrl).href; } catch { return; }
    if (!abs.startsWith(origin) || seen.has(abs)) return;
    seen.add(abs);
    links.push({ url: abs, text });
    if (links.length >= 25) return false;
  });
  return links;
}

function extractLinksFromMarkdown(markdown, baseUrl) {
  const origin = pageOrigin(baseUrl);
  const seen = new Set(), links = [];
  const re = /\[([^\]]{1,100})\]\((https?:\/\/[^\s)]+)\)/g;
  let m;
  while ((m = re.exec(markdown)) !== null) {
    const [, text, href] = m;
    if (!hasLinkKeyword(href, text) || !href.startsWith(origin) || seen.has(href)) continue;
    seen.add(href);
    links.push({ url: href, text });
    if (links.length >= 20) break;
  }
  return links;
}

// Need Jina for this site?
function needsJina(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    return JINA_FIRST_SITES.has(host);
  } catch { return false; }
}

// ── Multi-strategy lifecycle page discovery ───────────────────────────────────
async function fetchPageContent(url) {
  // Try plain fetch first, Jina if blocked/empty/JS-rendered
  if (needsJina(url)) {
    try { return { text: await fetchViaJina(url), via: "jina" }; } catch { /**/ }
  }
  try {
    const html = await fetchRaw(url);
    const text = extractText(html);
    if (text.length > 100) return { text, html, via: "html" };
  } catch { /**/ }
  // Jina fallback
  try {
    const text = await fetchViaJina(url);
    return { text, via: "jina-fallback" };
  } catch { /**/ }
  return null;
}

async function findLifecyclePage(registryUrl) {
  const origin = pageOrigin(registryUrl);

  // ── Strategy A: Curated URL check ───────────────────────────────────────
  // (Handled externally before calling this function)

  // ── Strategy B: Homepage scrape ─────────────────────────────────────────
  const home = await fetchPageContent(registryUrl).catch(() => null);
  if (home?.text) {
    if (hasLifecycleInfo(home.text)) return { url: registryUrl, text: home.text };

    // Follow lifecycle links from homepage
    const links = home.html
      ? extractLinksFromHtml(home.html, registryUrl)
      : extractLinksFromMarkdown(home.text, registryUrl);

    for (const { url: lUrl } of links.slice(0, 20)) {
      const page = await fetchPageContent(lUrl).catch(() => null);
      if (!page?.text) continue;
      if (hasLifecycleInfo(page.text)) return { url: lUrl, text: page.text };

      // Go one level deeper
      const deepLinks = page.html
        ? extractLinksFromHtml(page.html, lUrl)
        : extractLinksFromMarkdown(page.text, lUrl);
      for (const { url: dUrl } of deepLinks.slice(0, 5)) {
        if (dUrl === lUrl || dUrl === registryUrl) continue;
        const dPage = await fetchPageContent(dUrl).catch(() => null);
        if (dPage?.text && hasLifecycleInfo(dPage.text)) {
          return { url: dUrl, text: dPage.text };
        }
      }
    }
  }

  // ── Strategy C: Probe common paths ──────────────────────────────────────
  for (const path of PROBE_PATHS) {
    const url = origin + path;
    try {
      const html = await fetchRaw(url, 10000);
      const text = extractText(html);
      if (hasLifecycleInfo(text)) return { url, text };
    } catch { /**/ }
  }

  // ── Strategy D: Probe via Jina ───────────────────────────────────────────
  for (const path of PROBE_PATHS.slice(0, 20)) {
    const url = origin + path;
    try {
      const text = await fetchViaJina(url, 20000);
      if (hasLifecycleInfo(text)) return { url, text: text.slice(0, 12000) };
    } catch { /**/ }
  }

  return null;
}

async function fetchPageText(tld, ianaUrl) {
  // A: Use curated URL directly
  const curatedUrl = CURATED_LIFECYCLE_URLS[tld];
  if (curatedUrl) {
    const page = await fetchPageContent(curatedUrl).catch(() => null);
    if (page?.text && page.text.length > 100) {
      const hasKw = hasLifecycleInfo(page.text);
      const hint  = hasKw ? "" : "\n[注意：本页未检测到标准生命周期关键词，但仍尝试从上下文提取数据]\n";
      return { text: page.text.slice(0, 12000) + hint, finalUrl: curatedUrl, strategy: "curated" };
    }
  }

  // B: IANA page → extract registry URL → discover lifecycle page
  try {
    const ianaHtml = await fetchRaw(ianaUrl, 15000);
    const ianaText = extractText(ianaHtml, 2000);
    const registryUrl = extractRegistryUrl(ianaHtml);

    if (registryUrl) {
      const found = await findLifecyclePage(registryUrl).catch(() => null);
      if (found) {
        const hasKw = hasLifecycleInfo(found.text);
        const hint = hasKw ? "" : "\n[注意：本页未检测到标准生命周期关键词，仍尝试提取]\n";
        const text = `[IANA 页面摘要]\n${ianaText}\n\n[注册局官网 ${found.url}]${hint}\n${found.text.slice(0, 9000)}`;
        return { text, finalUrl: found.url, strategy: "discovered" };
      }
      // Nothing found via registry
      return {
        text: `[IANA 页面 — 注册局: ${registryUrl}]\n${ianaText}\n\n[注意：未能在注册局网站找到生命周期政策页面，请根据 ccTLD/gTLD 类型判断是否使用行业默认值]`,
        finalUrl: registryUrl,
        strategy: "iana-fallback",
      };
    }
    return { text: ianaText, finalUrl: ianaUrl, strategy: "iana-only" };
  } catch (e) {
    return { text: "", finalUrl: ianaUrl, strategy: "error" };
  }
}

// ── AI providers ──────────────────────────────────────────────────────────────
const AI_PROVIDERS = [
  { key: process.env.ZHIPU_API_KEY,     endpoint: "https://open.bigmodel.cn/api/paas/v4/chat/completions",              model: "glm-4-flashx",               name: "GLM-4-FlashX" },
  { key: process.env.ZHIPU_API_KEY,     endpoint: "https://open.bigmodel.cn/api/paas/v4/chat/completions",              model: "glm-4-flash",                name: "GLM-4-Flash" },
  { key: process.env.GROQ_API_KEY,      endpoint: "https://api.groq.com/openai/v1/chat/completions",                    model: "llama-3.3-70b-versatile",    name: "Llama-3.3-70B" },
  { key: process.env.GEMINI_API_KEY,    endpoint: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", model: "gemini-2.0-flash",      name: "Gemini-2.0-Flash" },
  { key: process.env.DEEPSEEK_API_KEY,  endpoint: "https://api.deepseek.com/v1/chat/completions",                       model: "deepseek-chat",              name: "DeepSeek-V3" },
  { key: process.env.DASHSCOPE_API_KEY, endpoint: "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", model: "qwen-turbo",                 name: "Qwen-Turbo" },
  { key: process.env.MOONSHOT_API_KEY,  endpoint: "https://api.moonshot.cn/v1/chat/completions",                        model: "moonshot-v1-8k",             name: "Kimi-8k" },
].filter(p => p.key);

async function callAI(messages, providerIndex = 0) {
  for (let i = providerIndex; i < AI_PROVIDERS.length; i++) {
    const p = AI_PROVIDERS[i];
    try {
      const res = await fetch(p.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${p.key}` },
        body: JSON.stringify({ model: p.model, messages, temperature: 0.05, max_tokens: 700 }),
        signal: AbortSignal.timeout(35000),
      });
      if (!res.ok) { console.warn(`  [AI] ${p.name} HTTP ${res.status}`); continue; }
      const json = await res.json();
      const content = json?.choices?.[0]?.message?.content?.trim() ?? "";
      if (!content) continue;
      return { content, name: p.name, providerIndex: i };
    } catch (e) {
      console.warn(`  [AI] ${p.name} error: ${e.message.slice(0, 60)}`);
    }
  }
  throw new Error("All AI providers failed");
}

const SYSTEM_PROMPT = `你是域名注册局政策专家，精通ICANN及各国注册局的域名生命周期规则。
从注册局官网文字中精准提取以下字段（英文/中文/日文/德文/法文/韩文/俄文/荷兰文/挪威文等均可处理）：

字段说明（务必仔细阅读）：
1. grace_period_days — "宽限期/自动续费宽限期" 天数（域名到期后仍可用原价续费；英文：autorenew grace period / renewal grace period）
   - 注意：有些注册局无此期（直接删除或直接进赎回期），填0
2. redemption_period_days — "赎回期/RGP/保留期/隔离期" 天数（英文：redemption grace period / hold period / quarantine / suspension period）
3. pending_delete_days — "待删除期" 天数（英文：pending delete / pending purge）
   - 注意：有些注册局无此期，填0
4. pre_expiry_days — 注册局在到期日【之前】提前删除的天数（如 .in 提前30天、.nl 提前3天）；无此规定填0
5. drop_hour — 域名最终释放/删除的精确时刻（0-23小时）；页面未明确说明填null
6. drop_minute — 释放时刻分钟（0-59）；未知填null
7. drop_second — 释放时刻秒（0-59）；未知填null
8. drop_timezone — 释放时刻时区（IANA格式，如 Europe/Berlin、Asia/Tokyo、UTC）；未知填null

【关键判断规则】：
★ 若页面有具体天数、周数或月数 → 提取实际数值（周×7，月×30）
★ 若页面使用"月末"/"end of month" → 约30天，填30
★ 若注册局无某个阶段（如无待删除期）→ 填0，不要填默认值5
★ DENIC(.de)：30-day RGP，无autorenew grace，无pending-delete → {grace:0, redemption:30, pending:0}
★ Nominet(.uk)：90-day suspension，无autorenew grace，无pending-delete → {grace:0, redemption:90, pending:0}
★ 若页面内容是IANA信息页（只有联系信息，无任何天数）且 TLD 是 gTLD → grace:30, redemption:30, pending:5
★ 若页面内容是IANA信息页且 TLD 是 ccTLD → 请在reasoning中明确说明无数据，但仍填行业估计值

【请注意】：reasoning 中说明数据来源、提取依据、是否有信心。

严格输出JSON，不加任何额外文字或代码块：
{"grace_period_days":0,"redemption_period_days":30,"pending_delete_days":0,"pre_expiry_days":0,"drop_hour":null,"drop_minute":null,"drop_second":null,"drop_timezone":null,"reasoning":"简短说明"}`;

function parseAiJson(content) {
  const c = content
    .replace(/^```json\s*/i,"").replace(/^```\s*/i,"").replace(/```\s*$/,"")
    .replace(/^[^{]*({[\s\S]*})[^}]*$/,"$1").trim();
  const p = JSON.parse(c);
  const toInt = (v, min=0) => Math.max(min, parseInt(String(v)) || 0);
  const toNullInt = (v, lo, hi) => {
    if (v===null||v===undefined||v==="") return null;
    const n = parseInt(String(v));
    return isNaN(n) ? null : Math.min(hi, Math.max(lo, n));
  };
  return {
    grace_period_days:      toInt(p.grace_period_days),
    redemption_period_days: toInt(p.redemption_period_days),
    pending_delete_days:    toInt(p.pending_delete_days),
    pre_expiry_days:        toNullInt(p.pre_expiry_days, 0, 365),
    drop_hour:              toNullInt(p.drop_hour, 0, 23),
    drop_minute:            toNullInt(p.drop_minute, 0, 59),
    drop_second:            toNullInt(p.drop_second, 0, 59),
    drop_timezone: typeof p.drop_timezone==="string" && p.drop_timezone ? p.drop_timezone.slice(0,50) : null,
    reasoning: String(p.reasoning||"").slice(0, 800),
  };
}

// Is the AI result just plain ICANN defaults (often means "no data found")?
function isAllDefaults(r) {
  return r.grace_period_days === 30 && r.redemption_period_days === 30 && r.pending_delete_days === 5;
}

// Is the result clearly problematic? Either 0/0/0 or 30/30/5 defaults
function isProblematic(r) {
  const total = r.grace_period_days + r.redemption_period_days + r.pending_delete_days;
  // 0/0/0 is suspicious unless registry explicitly does instant deletion
  const isZero = total === 0 && !r.reasoning?.toLowerCase().match(/instant|immediately|sofort|unmittelbar/);
  return isAllDefaults(r) || isZero;
}

async function extractWithAI(tld, pageText, sourceUrl, pageStrategy) {
  if (!pageText || pageText.length < 30) throw new Error("No page text to analyze");

  const isCcTld = tld.length === 2;
  const typeHint = isCcTld
    ? `[TLD 类型: ccTLD - 各国注册局，政策差异大，可能无标准 grace period]`
    : `[TLD 类型: gTLD - 通常遵循 ICANN 标准 grace:30 redemption:30 pending:5]`;

  const snippet = pageText.slice(0, 7000);
  if (DEBUG) {
    console.log(`\n${"─".repeat(60)}\n[DEBUG] .${tld} 传给AI的文本 (${snippet.length} chars, strategy:${pageStrategy}):\n${snippet.slice(0,500)}\n${"─".repeat(60)}`);
  }

  const userMsg = `TLD: .${tld}\n${typeHint}\n来源: ${sourceUrl} [策略:${pageStrategy}]\n\n页面内容：\n${snippet}`;
  const messages = [{ role:"system", content:SYSTEM_PROMPT }, { role:"user", content:userMsg }];

  const { content, name, providerIndex } = await callAI(messages);
  let result;
  try { result = parseAiJson(content); } catch (e) {
    throw new Error(`AI JSON parse failed: ${content.slice(0,100)}`);
  }
  result.model_used = name;

  // If result is problematic (all-defaults or 0/0/0) from ccTLD, retry with another model
  if (isProblematic(result) && isCcTld && pageStrategy !== "curated" && providerIndex < AI_PROVIDERS.length - 1) {
    console.log(`  ⟳ 结果全默认值，用备用模型重试...`);
    try {
      const { content: c2, name: n2 } = await callAI(messages, providerIndex + 1);
      const r2 = parseAiJson(c2);
      r2.model_used = n2;
      if (!isAllDefaults(r2)) {
        console.log(`  ✓ 备用模型提取到非默认数据`);
        return r2;
      }
    } catch { /**/ }
  }

  return result;
}

// Apply curated known policy as last resort
function applyKnownPolicy(tld, extracted) {
  const known = KNOWN_POLICIES[tld];
  if (!known) return extracted;
  if (isProblematic(extracted)) {
    return {
      ...extracted,
      grace_period_days:      known.grace,
      redemption_period_days: known.redemption,
      pending_delete_days:    known.pending,
      drop_hour:              known.drop_hour ?? null,
      drop_minute:            known.drop_minute ?? null,
      drop_timezone:          known.drop_timezone ?? null,
      pre_expiry_days:        known.pre_expiry ?? 0,
      reasoning: `[Known policy] ${known.note}`,
      model_used: "curated-database",
    };
  }
  return extracted;
}

// ── DB save ───────────────────────────────────────────────────────────────────
async function saveToDb(tld, ex, finalUrl, pageText, scrapeStatus, fetchStrategy) {
  await dbRun(
    `INSERT INTO tld_rules
       (tld, grace_period_days, redemption_period_days, pending_delete_days,
        source_url, confidence, raw_excerpt, ai_reasoning, model_used,
        drop_hour, drop_minute, drop_second, drop_timezone, pre_expiry_days,
        scraped_at, updated_at,
        scrape_status, fetch_strategy, failure_reason,
        scrape_attempts)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),NOW(),$15,$16,NULL,1)
     ON CONFLICT (tld) DO UPDATE SET
       grace_period_days=$2, redemption_period_days=$3, pending_delete_days=$4,
       source_url=$5, confidence=$6, raw_excerpt=$7, ai_reasoning=$8,
       model_used=$9, drop_hour=$10, drop_minute=$11, drop_second=$12,
       drop_timezone=$13, pre_expiry_days=$14,
       scraped_at=NOW(), updated_at=NOW(),
       scrape_status=$15, fetch_strategy=$16, failure_reason=NULL,
       scrape_attempts=COALESCE(tld_rules.scrape_attempts,0)+1`,
    [
      tld,
      ex.grace_period_days, ex.redemption_period_days, ex.pending_delete_days,
      finalUrl,
      ex.model_used === "curated-database" ? "high" : "ai",
      pageText.slice(0, 1000),
      ex.reasoning,
      ex.model_used ?? null,
      ex.drop_hour, ex.drop_minute, ex.drop_second, ex.drop_timezone,
      ex.pre_expiry_days ?? 0,
      scrapeStatus,
      fetchStrategy ?? null,
    ]
  );
}

async function saveFailureToDb(tld, reason) {
  const short = reason.slice(0, 500);
  await dbRun(
    `INSERT INTO tld_rules
       (tld, grace_period_days, redemption_period_days, pending_delete_days,
        scrape_status, failure_reason, scraped_at, updated_at, scrape_attempts)
     VALUES ($1, 30, 30, 5, 'failed', $2, NOW(), NOW(), 1)
     ON CONFLICT (tld) DO UPDATE SET
       scrape_status='failed', failure_reason=$2,
       scraped_at=NOW(), updated_at=NOW(),
       scrape_attempts=COALESCE(tld_rules.scrape_attempts,0)+1`,
    [tld, short]
  ).catch(e => console.warn(`  [DB] 写入失败记录出错: ${e.message}`));
}

// ── Progress tracking ─────────────────────────────────────────────────────────
let stats = { done: 0, skip: 0, err: 0, defaultOnly: 0, total: 0 };

function log(tld, status, msg = "") {
  const icon = { ok:"✅", skip:"⏭ ", err:"❌", warn:"⚠️ " }[status] ?? "  ";
  const done = stats.done + stats.skip + stats.err;
  const pct  = stats.total ? `[${String(done).padStart(3)}/${stats.total}]` : "";
  console.log(`${pct} ${icon} .${tld.padEnd(8)} ${msg}`);
}

// ── Single TLD scrape ─────────────────────────────────────────────────────────
async function scrapeTld(tld) {
  const ianaUrl = `https://www.iana.org/domains/root/db/${tld}.html`;

  // Skip rules — based on scrape_status, NOT time
  if (!FORCE && !CLEAR_DEFS) {
    const existing = await dbOne(
      `SELECT scraped_at, scrape_status, COALESCE(manually_edited,FALSE) as manually_edited,
              grace_period_days, redemption_period_days, pending_delete_days
       FROM tld_rules WHERE tld=$1`, [tld]
    ).catch(() => null);

    if (existing?.manually_edited) {
      stats.skip++;
      log(tld, "skip", "手动修改，跳过");
      return;
    }
    // Only skip records that were successfully scraped (non-default real data)
    if (existing?.scrape_status === "ok") {
      stats.skip++;
      const dateStr = existing.scraped_at ? new Date(existing.scraped_at).toISOString().slice(0,10) : "—";
      log(tld, "skip", `已成功抓取 (${dateStr})，跳过`);
      return;
    }
    // Records with warn_defaults, failed, pending — will be re-attempted
  }

  if (CLEAR_DEFS && !FORCE) {
    const existing = await dbOne(
      `SELECT grace_period_days, redemption_period_days, pending_delete_days,
              COALESCE(manually_edited,FALSE) as manually_edited FROM tld_rules WHERE tld=$1`, [tld]
    ).catch(() => null);
    if (existing && !isAllDefaults(existing) && !existing.manually_edited) {
      stats.skip++;
      log(tld, "skip", "数据非默认值，跳过");
      return;
    }
    if (existing?.manually_edited) {
      stats.skip++;
      log(tld, "skip", "手动修改，跳过");
      return;
    }
  }

  if (DRY_RUN) {
    stats.done++;
    log(tld, "ok", "[DRY-RUN]");
    return;
  }

  try {
    const { text: pageText, finalUrl, strategy } = await fetchPageText(tld, ianaUrl);
    if (!pageText || pageText.length < 30) throw new Error("页面内容为空");

    let extracted = await extractWithAI(tld, pageText, finalUrl, strategy);

    // Last resort: apply curated known policy
    extracted = applyKnownPolicy(tld, extracted);

    // Final safety: 0/0/0 is almost never correct — apply minimum standard
    const finalTotal = extracted.grace_period_days + extracted.redemption_period_days + extracted.pending_delete_days;
    if (finalTotal === 0 && !extracted.reasoning?.toLowerCase().match(/instant|immediately|sofort|unmittelbar/)) {
      extracted.grace_period_days      = 30;
      extracted.redemption_period_days = 30;
      extracted.pending_delete_days    = 5;
      extracted.reasoning = `[自动修正] 原始结果为0/0/0（AI未找到具体数据）→ 已应用行业标准值30/30/5。${extracted.reasoning || ""}`;
    }

    const isProblem = isProblematic(extracted);
    // scrape_status: 'ok' = real data found, 'warn_defaults' = only got industry defaults
    const scrapeStatus = isProblem ? "warn_defaults" : "ok";

    await saveToDb(tld, extracted, finalUrl, pageText, scrapeStatus, strategy);

    const total = extracted.grace_period_days + extracted.redemption_period_days + extracted.pending_delete_days;
    const dropInfo = extracted.drop_hour !== null
      ? ` 掉落${String(extracted.drop_hour).padStart(2,"0")}:${String(extracted.drop_minute??0).padStart(2,"0")} ${extracted.drop_timezone??"UTC"}`
      : "";
    const problemFlag = isProblem ? (total === 0 ? " ⚠(全零!)" : " ⚠(默认值)") : "";
    stats.done++;
    if (isProblem) stats.defaultOnly++;
    log(tld, isProblem ? "warn" : "ok",
      `宽限${extracted.grace_period_days}d 赎回${extracted.redemption_period_days}d 待删${extracted.pending_delete_days}d =${total}d${dropInfo}${problemFlag} [${extracted.model_used}][${strategy}]`
    );
  } catch (err) {
    stats.err++;
    const reason = err.message.slice(0, 400);
    log(tld, "err", reason.slice(0, 120));
    // Always write failure record so admin can see and retry
    await saveFailureToDb(tld, reason);
  }
}

// ── TLD lists ─────────────────────────────────────────────────────────────────
const CC_TLDS = [
  "ac","ad","ae","af","ag","ai","al","am","ao","aq","ar","as","at","au","aw","ax","az",
  "ba","bb","bd","be","bf","bg","bh","bi","bj","bm","bn","bo","br","bs","bt","bw","by","bz",
  "ca","cc","cd","cf","cg","ch","ci","ck","cl","cm","cn","co","cr","cu","cv","cw","cx","cy","cz",
  "de","dj","dk","dm","do","dz","ec","ee","eg","er","es","et","eu",
  "fi","fj","fk","fm","fo","fr","ga","gd","ge","gf","gg","gh","gi","gl","gm","gn","gp","gq",
  "gr","gs","gt","gu","gw","gy","hk","hm","hn","hr","ht","hu",
  "id","ie","il","im","in","io","iq","ir","is","it","je","jm","jo","jp",
  "ke","kg","kh","ki","km","kn","kp","kr","kw","ky","kz",
  "la","lb","lc","li","lk","lr","ls","lt","lu","lv","ly",
  "ma","mc","md","me","mg","mh","mk","ml","mm","mn","mo","mp","mq","mr","ms","mt","mu","mv","mw","mx","my","mz",
  "na","nc","ne","nf","ng","ni","nl","no","np","nr","nu","nz",
  "om","pa","pe","pf","pg","ph","pk","pl","pm","pn","pr","ps","pt","pw","py","qa",
  "re","ro","rs","ru","rw",
  "sa","sb","sc","sd","se","sg","sh","si","sk","sl","sm","sn","so","sr","ss","st","su","sv","sx","sy","sz",
  "tc","td","tf","tg","th","tj","tk","tl","tm","tn","to","tr","tt","tv","tw","tz",
  "ua","ug","uk","us","uy","uz","va","vc","ve","vg","vi","vn","vu","wf","ws",
  "ye","yt","za","zm","zw",
];

async function fetchGtldList() {
  try {
    const html = await fetchRaw("https://www.iana.org/domains/root/db", 20000);
    const $ = cheerio.load(html);
    const tlds = [];
    $("#tld-table tbody tr").each((_, row) => {
      const cells = $(row).find("td");
      const typeText = cells.eq(1).text().trim().toLowerCase();
      if (!typeText.includes("country")) {
        const tld = cells.eq(0).text().trim().replace(/^\./, "").toLowerCase();
        if (tld && !tld.includes(" ") && !tld.startsWith("xn--")) tlds.push(tld);
      }
    });
    return [...new Set(tlds)].filter(t => t.length > 2);
  } catch (e) {
    console.warn("⚠️  IANA gTLD 列表获取失败:", e.message);
    return ["com","net","org","info","biz","xyz","app","dev","shop","blog","tech","online","site","store","club","co","io","ai","gg"];
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║       TLD 生命周期批量爬取器 v2.0 (batch-scrape.mjs)        ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  if (AI_PROVIDERS.length === 0) { console.error("❌ 至少需要一个 AI API Key"); process.exit(1); }
  console.log(`✅ AI 提供商 (${AI_PROVIDERS.length}个): ${AI_PROVIDERS.map(p=>p.name).join(", ")}`);
  console.log(`📋 类型:${TYPE} 强制:${FORCE} 清默认:${CLEAR_DEFS} 并发:${CONCURRENCY} 间隔:${DELAY_MS}ms DRY:${DRY_RUN}`);
  console.log(`ℹ️  跳过策略: 仅跳过 scrape_status='ok' 的记录 (失败/默认值记录将重新尝试，无时效限制)`);

  let tldList = [];
  if (SINGLE_TLD) {
    tldList = [SINGLE_TLD.toLowerCase().replace(/^\./,"")];
  } else if (TYPE==="cc" || TYPE==="all") {
    tldList.push(...CC_TLDS);
  }
  if (TYPE==="gtld" || TYPE==="all") {
    console.log("⏳ 获取 IANA gTLD 列表...");
    const gtlds = await fetchGtldList();
    tldList.push(...gtlds);
    console.log(`   gTLD: ${gtlds.length} 个`);
  }
  tldList = [...new Set(tldList)];
  stats.total = tldList.length;

  console.log(`\n🚀 开始抓取 ${tldList.length} 个 TLD (${TYPE})...\n`);
  if (FORCE) console.log("⚠️  --force: 覆盖所有已有数据（包括手动修改）\n");
  if (CLEAR_DEFS) console.log("🔄 --clear-defaults: 仅重抓默认值 (30/30/5) 记录\n");

  const startTime = Date.now();

  for (let i = 0; i < tldList.length; i += CONCURRENCY) {
    const batch = tldList.slice(i, i + CONCURRENCY);
    await Promise.all(batch.map(tld => scrapeTld(tld)));
    if (i + CONCURRENCY < tldList.length) {
      await new Promise(r => setTimeout(r, DELAY_MS));
    }
  }

  const elapsed = Math.round((Date.now() - startTime) / 1000);
  console.log(`\n${"═".repeat(64)}`);
  console.log(`✅ 完成: ${stats.done} (含${stats.defaultOnly}个默认值)  ⏭ 跳过: ${stats.skip}  ❌ 失败: ${stats.err}`);
  console.log(`⏱  耗时: ${Math.floor(elapsed/60)}分${elapsed%60}秒 | ${tldList.length} 个 TLD`);
  if (stats.defaultOnly > 0) {
    console.log(`\n⚠️  ${stats.defaultOnly} 个 TLD 使用了默认值(30/30/5)，建议手动核查！`);
    console.log(`   重新抓取默认值记录: node scripts/batch-scrape.mjs --clear-defaults --force`);
  }

  await pool.end();
}

main().catch(e => { console.error("Fatal:", e); pool.end(); process.exit(1); });
