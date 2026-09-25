/**
 * Unified TLD lifecycle scrape service (R6).
 *
 * Shared by:
 *   - admin manual POST   (src/pages/api/admin/tld-rules.ts)
 *   - cron batch queue    (src/pages/api/cron/tld-scrape.ts)
 *   - bulk re-scrape      (PATCH action "rescan-many")
 *
 * Every entry point funnels through `scrapeTld`, which performs discovery
 * (IANA → registry lifecycle page), AI extraction with multi-model fallback,
 * unified save SQL, cache invalidation, and failure persistence — so field
 * semantics (needs_admin_review / scrape_attempts / failure_reason /
 * fetch_strategy / raw_excerpt) stay consistent everywhere.
 *
 * Also implements:
 *   R7  — per-field source markers (page_explicit / page_hint / industry_default)
 *   R8  — IANA timezone whitelist + drop-time bounds validation
 *   R12 — concurrent link discovery (limit 3) + Jina skip after 2 consecutive fails
 */

import { run } from "@/lib/db-query";
import { isRedisAvailable, getRedisValue, setRedisValue } from "@/lib/server/redis";
import { createLogger } from "@/lib/logger";
import * as cheerio from "cheerio";
import { callProviderWithFallback } from "@/lib/server/ai-providers";
import { invalidateLifecycleOverridesCache } from "@/lib/server/lifecycle-overrides";

const logger = createLogger("lib/server/tld-scrape");

// ─── SSRF protection: only allow public HTTP/HTTPS URLs ───────────────────────
const PRIVATE_IP_RE =
  /^(localhost|127\.\d+\.\d+\.\d+|::1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)/i;

export function validatePublicUrl(raw: string): { ok: true; url: string } | { ok: false; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: "Invalid URL format" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, error: "Only http:// and https:// URLs are allowed" };
  }
  if (PRIVATE_IP_RE.test(parsed.hostname)) {
    return { ok: false, error: "Private or loopback addresses are not allowed" };
  }
  return { ok: true, url: parsed.toString() };
}

// ─── Redis cache keys ─────────────────────────────────────────────────────────
export const SCRAPE_CACHE_KEY = (url: string) =>
  `tld_rules_scrape:${Buffer.from(url).toString("base64").slice(0, 60)}`;
const REGISTRY_URL_CACHE_KEY = (tld: string) => `tld_registry_url:${tld}`;

const SCRAPE_CACHE_TTL_S = 60 * 60 * 6;            // raw page text cached 6 h
const REGISTRY_URL_TTL_S = 60 * 60 * 24 * 7;       // registry URL cached 7 days

// Lifecycle keywords that signal a page has actual domain lifecycle policy info.
// IMPORTANT: Keep these SPECIFIC enough to avoid false positives from cookie banners,
// privacy policies, and general website content that also use words like "delete", "expir".
const LIFECYCLE_KEYWORDS = [
  // English — multi-word or domain-specific single terms only
  "grace period", "redemption period", "pending delete", "pendingdelete",
  "rgp", "autorenew grace", "auto-renew grace", "registry grace period",
  "add grace period", "drop time", "drop date", "drop catch",
  "lifecycle", "life cycle", "domain lifecycle",
  "expiry period", "expiration period", "renewal grace period",
  "registry lock period", "domain deletion", "domain expiration",
  "domain expiry", "restore period", "redemption grace",
  // Chinese (Simplified + Traditional) — multi-char terms are naturally specific
  "宽限期", "赎回期", "待删除", "掉落时间", "释放时间", "删除时间",
  "续费宽限", "到期删除", "赎回", "注册局宽限",
  // Japanese — domain-specific multi-character terms
  "ライフサイクル", "猶予期間", "回復期間", "削除待ち", "更新猶予",
  "ドメイン有効期限", "削除期間",
  // Korean
  "갱신유예", "복구기간", "삭제대기", "라이프사이클",
  // German — compound terms unique to domain industry
  "löschfrist", "kündigungsfrist", "löschantrag", "wiederherstellungsphase",
  "domainlöschung", "freigabephase", "domainlebenszykl",
  // French — specific domain lifecycle terms
  "période de grâce", "rédemption", "suppression en attente", "cycle de vie",
  "durée de grâce",
  // Russian
  "период льготы", "период выкупа",
];

function hasLifecycleInfo(text: string): boolean {
  const lower = text.toLowerCase();
  return LIFECYCLE_KEYWORDS.some(kw => lower.includes(kw.toLowerCase()));
}

// ─── Fetch & clean page text (with lifecycle keyword prioritization) ──────────
async function fetchRawHtml(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; next-whois-ui/1.0; domain-lifecycle-crawler)",
      Accept: "text/html,application/xhtml+xml,*/*",
      "Accept-Language": "en,zh;q=0.9",
    },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.text();
}

function extractText(html: string, maxChars = 10_000): string {
  const $ = cheerio.load(html);
  $("script,style,nav,header,footer,noscript,iframe,svg,button,form").remove();

  const mainEl = $("main,article,[class*=content],[id*=content],.policy,.lifecycle,.domain-info,body").first();
  const rawText = (mainEl.text() || $("body").text())
    .replace(/\s{3,}/g, "\n")
    .replace(/\n{4,}/g, "\n\n")
    .trim();

  if (rawText.length <= maxChars) return rawText;

  const lines = rawText.split("\n");
  const relevantLines: string[] = [];
  const otherLines: string[] = [];

  for (const line of lines) {
    if (LIFECYCLE_KEYWORDS.some(kw => line.toLowerCase().includes(kw.toLowerCase()))) {
      relevantLines.push(line);
    } else {
      otherLines.push(line);
    }
  }

  const priority = relevantLines.join("\n").slice(0, Math.floor(maxChars * 0.7));
  const rest = otherLines.join("\n").slice(0, maxChars - priority.length);
  return (priority + "\n\n" + rest).trim().slice(0, maxChars);
}

/**
 * Extract the registry's official URL from an IANA root-db page.
 * Works on both raw HTML (preferred) and extracted plain text.
 */
function extractRegistryUrl(htmlOrText: string): string | null {
  const hrefMatch = htmlOrText.match(
    /URL for registration services[^<]*<[^>]+>\s*<a[^>]+href=["']?(https?:\/\/[^"'\s>]+)["']?/i
  );
  if (hrefMatch) {
    return hrefMatch[1].replace(/\/$/, "").replace(/[)\]>]+$/, "");
  }

  const urlMatch = htmlOrText.match(
    /URL for registration services[^\n]*\n?\s*(https?:\/\/[^\s\n<>]+)/i
  );
  if (urlMatch) {
    return urlMatch[1].replace(/\/$/, "").replace(/[)\]>]+$/, "");
  }

  const wwwMatch = htmlOrText.match(
    /URL for registration services[^\n]*\n?\s*(www\.[^\s\n<>]+)/i
  );
  if (wwwMatch) {
    return `https://${wwwMatch[1]}`.replace(/\/$/, "");
  }

  return null;
}

function extractRegistryUrlFromHtml(html: string): string | null {
  const $ = cheerio.load(html);
  let found: string | null = null;

  $("*").each((_, el) => {
    const text = $(el).clone().children().remove().end().text();
    if (/URL for registration services/i.test(text)) {
      const nextA = $(el).next("a").attr("href") ??
        $(el).parent().find("a").first().attr("href") ?? null;
      if (nextA?.match(/^https?:\/\//)) {
        found = nextA.replace(/\/$/, "");
        return false;
      }
    }
  });

  if (found) return found;

  const blockMatch = html.match(
    /URL for registration services[\s\S]{0,200}?href=["']?(https?:\/\/[^"'\s>]+)/i
  );
  if (blockMatch) return blockMatch[1].replace(/\/$/, "");

  return extractRegistryUrl($.text());
}

/** Common lifecycle path suffixes to probe on a registry domain */
const LIFECYCLE_PATHS = [
  "/domain-lifecycle", "/domains/lifecycle", "/en/domains/lifecycle",
  "/lifecycle", "/en/lifecycle", "/policies/lifecycle",
  "/domain-names/lifecycle", "/support/lifecycle", "/faq/lifecycle",
  "/about/lifecycle", "/en/domain-lifecycle", "/domains/domain-lifecycle",
  "/en/domains/domain-lifecycle", "/registrar/lifecycle",
  "/policies", "/en/policies", "/domains/policies", "/domains",
  "/en/domains", "/en/domain-names", "/domain-names",
  "/registrar-information", "/registrar-resources",
  "/faq", "/en/faq", "/help", "/en/help", "/support", "/en/support",
  "/help-center", "/knowledge-base", "/kb",
  "/en/the-dot-de-domain", "/en/domains/conditions",
  "/domainrichtlinien", "/richtlinien",
  "/en/domain-names/conditions",
  "/en/domain-names-and-support/managing-a-domain-name",
  "/en/domain-names-and-support",
  "/for-registrants/au-domain-administration",
  "/domain-names", "/registrants",
];

const LIFECYCLE_LINK_KEYWORDS = [
  "lifecycle", "life-cycle", "grace", "redemption", "renewal", "expir",
  "policy", "policies", "domain-rules", "domain-policy", "rgp", "purge", "delete",
  "待删", "宽限", "赎回", "续费", "政策", "规则", "生命周期", "到期",
  "ライフサイクル", "猶予", "削除", "更新", "有効期限", "ルール",
  "라이프사이클", "갱신", "삭제",
  "lebenszyklus", "lösch", "kündig",
  "cycle", "suppression", "rédem",
];

function hasLifecycleLinkKeyword(href: string, text: string): boolean {
  const combined = `${href} ${text}`.toLowerCase();
  return LIFECYCLE_LINK_KEYWORDS.some(kw => combined.includes(kw.toLowerCase()));
}

function extractLifecycleLinks(html: string, baseUrl: string): string[] {
  const $ = cheerio.load(html);
  const base = new URL(baseUrl).origin;
  const seen = new Set<string>();
  const links: string[] = [];

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href") ?? "";
    const text = $(el).text().trim();
    if (!hasLifecycleLinkKeyword(href, text)) return;

    let abs: string;
    try {
      abs = new URL(href, baseUrl).href;
    } catch { return; }

    if (!abs.startsWith(base)) return;
    if (seen.has(abs)) return;
    seen.add(abs);
    links.push(abs);
    if (links.length >= 20) return false;
  });

  return links;
}

/**
 * Fetch a URL via Jina Reader (r.jina.ai) which renders JS and returns clean Markdown.
 * No API key needed. Returns the rendered Markdown text.
 */
async function fetchViaJina(url: string): Promise<string> {
  const jinaUrl = `https://r.jina.ai/${url}`;
  const res = await fetch(jinaUrl, {
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; next-whois-ui/1.0)",
      Accept: "text/plain,text/markdown,*/*",
      "X-No-Cache": "true",
    },
    signal: AbortSignal.timeout(25_000),
  });
  if (!res.ok) throw new Error(`Jina HTTP ${res.status} for ${url}`);
  const text = await res.text();
  if (!text || text.length < 100) throw new Error(`Jina returned empty content for ${url}`);
  return text;
}

function extractLifecycleLinksFromMarkdown(markdown: string, baseUrl: string): string[] {
  const base = new URL(baseUrl).origin;
  const seen = new Set<string>();
  const links: string[] = [];

  const mdLinkRe = /\[([^\]]{1,80})\]\((https?:\/\/[^\s)]+)\)/g;
  let match: RegExpExecArray | null;
  while ((match = mdLinkRe.exec(markdown)) !== null) {
    const text = match[1];
    const href = match[2];
    if (!hasLifecycleLinkKeyword(href, text)) continue;
    if (!href.startsWith(base)) continue;
    if (seen.has(href)) continue;
    seen.add(href);
    links.push(href);
    if (links.length >= 15) break;
  }
  return links;
}

// ─── R12: bounded-concurrency pool ────────────────────────────────────────────
async function pMap<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<Array<{ item: T; result: R } | { item: T; error: unknown }>> {
  const out: Array<{ item: T; result: R } | { item: T; error: unknown }> = [];
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const idx = cursor++;
      const item = items[idx];
      try {
        out[idx] = { item, result: await fn(item, idx) };
      } catch (error) {
        out[idx] = { item, error };
      }
    }
  });
  await Promise.all(workers);
  return out;
}

// ─── Discovery strategy result ────────────────────────────────────────────────
export type FetchStrategy =
  | "direct"           // fetched URL itself contained lifecycle data
  | "registry_cached"  // registry lifecycle page hit from 7-day URL cache
  | "registry_paths"   // found by probing common registry path suffixes
  | "link_crawl"       // found by crawling homepage lifecycle-looking links
  | "jina";            // found via Jina Reader (JS-rendered sites)

/**
 * Multi-strategy registry lifecycle page finder.
 * Returns { url, text, strategy } of the best page found, or null.
 *
 * R12 AC1: link/path candidates are parsed with concurrency 3 instead of serially.
 * R12 AC2: after 2 consecutive Jina failures for this TLD, remaining Jina
 *          strategies are skipped.
 */
async function findRegistryLifecyclePage(
  registryUrl: string
): Promise<{ url: string; text: string; strategy: FetchStrategy } | null> {
  const base = new URL(registryUrl).origin;
  const jinaFailCount = { n: 0 };

  // ── Strategy 1-3: Static HTML crawl ─────────────────────────────────────────
  try {
    const html = await fetchRawHtml(registryUrl);
    const text = extractText(html, 10_000);
    if (hasLifecycleInfo(text)) {
      return { url: registryUrl, text, strategy: "direct" };
    }

    // ── Strategy 2: Try common path suffixes (concurrent 3) ───────────────────
    const pathResults = await pMap(LIFECYCLE_PATHS, 3, async (path) => {
      const url = base + path;
      const pHtml = await fetchRawHtml(url);
      return { url, text: extractText(pHtml, 10_000) };
    });
    for (const r of pathResults) {
      if ("result" in r && hasLifecycleInfo(r.result.text)) {
        return { url: r.result.url, text: r.result.text, strategy: "registry_paths" };
      }
    }

    // ── Strategy 3: Follow lifecycle-looking links (concurrent 3, one level deep) ─
    const linkedUrls = extractLifecycleLinks(html, registryUrl);
    const linkResults = await pMap(linkedUrls, 3, async (linkedUrl) => {
      const lHtml = await fetchRawHtml(linkedUrl);
      const lText = extractText(lHtml, 10_000);
      return { url: linkedUrl, text: lText, html: lHtml };
    });
    for (const r of linkResults) {
      if ("result" in r) {
        if (hasLifecycleInfo(r.result.text)) {
          return { url: r.result.url, text: r.result.text, strategy: "link_crawl" };
        }
        const deepLinks = extractLifecycleLinks(r.result.html, r.result.url).slice(0, 5);
        const deepResults = await pMap(deepLinks, 3, async (deepUrl) => {
          if (deepUrl === r.result.url || deepUrl === registryUrl) throw new Error("skip self");
          const dHtml = await fetchRawHtml(deepUrl);
          return { url: deepUrl, text: extractText(dHtml, 10_000) };
        });
        for (const d of deepResults) {
          if ("result" in d && hasLifecycleInfo(d.result.text)) {
            return { url: d.result.url, text: d.result.text, strategy: "link_crawl" };
          }
        }
      }
    }
  } catch {
    /* registry unreachable via direct fetch — fall through to Jina */
  }

  // ── Strategy 4: Jina Reader (JS-rendered sites) ───────────────────────────
  logger.info(`[tld-scrape] Strategy 4: Trying Jina Reader for ${registryUrl}`);
  const jinaFetch = async (url: string): Promise<string> => {
    if (jinaFailCount.n >= 2) throw new Error("Jina skipped (2 consecutive fails)");
    try {
      const txt = await fetchViaJina(url);
      return txt;
    } catch (e) {
      jinaFailCount.n += 1;
      throw e;
    }
  };

  try {
    // 4a: Render registry homepage via Jina
    const jinaMarkdown = await jinaFetch(registryUrl);
    if (hasLifecycleInfo(jinaMarkdown)) {
      return { url: registryUrl, text: jinaMarkdown.slice(0, 10_000), strategy: "jina" };
    }

    // 4b: Extract lifecycle links from Jina-rendered Markdown, follow them via Jina
    const jinaLinks = extractLifecycleLinksFromMarkdown(jinaMarkdown, registryUrl);
    logger.info(`[tld-scrape] Jina found ${jinaLinks.length} lifecycle-keyword links`);
    const jinaLinkResults = await pMap(jinaLinks, 3, async (jLink) => {
      return { url: jLink, text: await jinaFetch(jLink) };
    });
    for (const r of jinaLinkResults) {
      if ("result" in r && hasLifecycleInfo(r.result.text)) {
        return { url: r.result.url, text: r.result.text.slice(0, 10_000), strategy: "jina" };
      }
    }
    // One level deeper from Jina-rendered linked pages
    const deepJinaResults = await pMap(
      jinaLinkResults.filter((r): r is { item: string; result: { url: string; text: string } } => "result" in r),
      3,
      async (r) => {
        const deepJinaLinks = extractLifecycleLinksFromMarkdown(r.result.text, r.result.url).slice(0, 4);
        return { source: r.result.url, deep: await pMap(deepJinaLinks, 3, async (djLink) => {
          if (djLink === r.result.url || djLink === registryUrl) throw new Error("skip self");
          return { url: djLink, text: await jinaFetch(djLink) };
        }) };
      },
    );
    for (const r of deepJinaResults) {
      if ("result" in r) {
        for (const d of r.result.deep) {
          if ("result" in d && hasLifecycleInfo(d.result.text)) {
            return { url: d.result.url, text: d.result.text.slice(0, 10_000), strategy: "jina" };
          }
        }
      }
    }

    // 4c: Try common lifecycle path suffixes via Jina
    const jinaPathsToTry = LIFECYCLE_PATHS.slice(0, 20);
    const jinaPathResults = await pMap(jinaPathsToTry, 3, async (path) => {
      const url = base + path;
      return { url, text: await jinaFetch(url) };
    });
    for (const r of jinaPathResults) {
      if ("result" in r && hasLifecycleInfo(r.result.text)) {
        return { url: r.result.url, text: r.result.text.slice(0, 10_000), strategy: "jina" };
      }
    }
  } catch (jinaErr) {
    logger.warn(`[tld-scrape] Jina Reader failed for ${registryUrl}:`, (jinaErr as Error).message);
  }

  return null;
}

async function fetchPageText(url: string): Promise<{ text: string; finalUrl: string; strategy: FetchStrategy }> {
  // Check cache first (R12 AC4: reuse unexpired cache, skip network)
  const cacheKey = SCRAPE_CACHE_KEY(url);
  if (isRedisAvailable()) {
    const cached = await getRedisValue(cacheKey);
    if (cached) {
      try {
        const obj = JSON.parse(cached);
        return { text: obj.text, finalUrl: obj.finalUrl ?? url, strategy: obj.strategy ?? "direct" };
      } catch {
        return { text: cached, finalUrl: url, strategy: "direct" };
      }
    }
  }

  let html = await fetchRawHtml(url);
  const ianaText = extractText(html, 10_000);
  let text = ianaText;
  let finalUrl = url;
  let strategy: FetchStrategy = "direct";

  // ── Smart URL discovery: if IANA page has no lifecycle data, find registry page ──
  if (!hasLifecycleInfo(ianaText) && url.includes("iana.org")) {
    const registryUrl = extractRegistryUrlFromHtml(html) ?? extractRegistryUrl(ianaText);
    if (registryUrl) {
      const tldKey = new URL(url).pathname.split("/").pop()?.replace(/\.html$/, "") ?? "";
      const cacheKey2 = REGISTRY_URL_CACHE_KEY(tldKey);

      let cachedPayload: string | null = null;
      if (isRedisAvailable()) {
        cachedPayload = await getRedisValue(cacheKey2);
      }

      let found: { url: string; text: string; strategy: FetchStrategy } | null = null;
      if (cachedPayload) {
        try {
          const parsed = JSON.parse(cachedPayload);
          found = { url: parsed.url, text: parsed.text, strategy: "registry_cached" };
        } catch {
          try {
            const fHtml = await fetchRawHtml(cachedPayload);
            found = { url: cachedPayload, text: extractText(fHtml, 10_000), strategy: "registry_cached" };
          } catch { /* ignore */ }
        }
      }

      if (!found) {
        const discovered = await findRegistryLifecyclePage(registryUrl).catch(() => null);
        if (discovered) {
          found = discovered;
          if (isRedisAvailable()) {
            await setRedisValue(cacheKey2, found.url, REGISTRY_URL_TTL_S);
          }
        }
      }

      if (found) {
        const hasKw = hasLifecycleInfo(found.text);
        const hint = hasKw
          ? ""
          : "\n[注意：本页未检测到标准生命周期关键词，但仍尝试从上下文提取数据，如无法提取请使用行业默认值]\n";
        text = `[IANA 页面 — 注册局信息]\n${ianaText.slice(0, 1500)}\n\n[注册局官网 ${found.url}]${hint}\n${found.text.slice(0, 7500)}`;
        finalUrl = found.url;
        strategy = found.strategy;
      } else if (!hasLifecycleInfo(ianaText)) {
        text = `[IANA 页面 — 注册局信息，无注册局官网数据]\n${ianaText}\n[注意：未能找到注册局生命周期政策页，请根据TLD类型判断是否使用行业默认值]`;
        strategy = "direct";
      }
    }
  }

  const payload = JSON.stringify({ text, finalUrl, strategy });
  if (text && isRedisAvailable()) {
    await setRedisValue(cacheKey, payload, SCRAPE_CACHE_TTL_S);
  }
  return { text, finalUrl, strategy };
}

// ─── AI extraction with multi-model fallback ──────────────────────────────────
export type FieldSource = "page_explicit" | "page_hint" | "industry_default";

export interface ExtractedLifecycle {
  grace_period_days: number;
  redemption_period_days: number;
  pending_delete_days: number;
  drop_hour: number | null;
  drop_minute: number | null;
  drop_second: number | null;
  drop_timezone: string | null;
  pre_expiry_days: number | null;
  reasoning: string;
  model_used: string;
  field_sources: Record<string, FieldSource>;
  confidence: "high" | "ai";
}

const SYSTEM_PROMPT = `你是域名注册局政策专家，精通ICANN及各国注册局的域名生命周期规则。
从注册局官网文字中精准提取以下字段（英文/中文页面均可）：

1. grace_period_days — 宽限期天数（域名到期后仍可续费；英文：grace period / autorenew grace period）
2. redemption_period_days — 赎回期天数（RGP；英文：redemption grace period / redemption period）
3. pending_delete_days — 待删除期天数（英文：pending delete / pending purge / pending deletion）
4. pre_expiry_days — 注册局在到期日【之前】多少天提前删除（如 .nl 提前3天、.in 提前30天）；无此规定填0
5. drop_hour — 域名最终被释放/删除的确切时刻（小时 0-23）；若页面未明确提及填null
6. drop_minute — 释放时刻分钟（0-59）；未知填null
7. drop_second — 释放时刻秒（0-59）；未知填null
8. drop_timezone — 释放时刻的时区（IANA格式，如 Europe/Berlin、Asia/Shanghai、UTC）；未知填null

【关键规则】：
- 若页面内容是IANA注册局信息页（只有注册局联系信息，无任何天数/时间信息），grace/redemption/pending_delete仍需填行业默认值（30/30/5），并在reasoning中注明"IANA页面无具体数据，使用ICANN gTLD默认值"
- 若是ccTLD且页面无数据，reasoning中注明"ccTLD注册局页面无具体政策数据"
- drop_hour/drop_timezone只有页面明确说明时才填，不要猜测

【字段来源标记 field_sources】（R7）：
对 grace_period_days / redemption_period_days / pending_delete_days / pre_expiry_days / drop_hour 五个数值字段，
逐一标注其可信来源：
- "page_explicit"：页面原文明确写出的数值（如 "grace period: 30 days"）
- "page_hint"：页面上下文推算的合理值（如按日期区间推算、FAQ暗示）
- "industry_default"：页面无数据，采用 ICANN 行业默认猜测（30/30/5）
若页面有明确掉落时刻，drop_hour/drop_minute/drop_second/drop_timezone 应标 page_explicit。

严格输出JSON，不加任何额外文字、注释或代码块标记：
{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":null,"drop_minute":null,"drop_second":null,"drop_timezone":null,"field_sources":{"grace_period_days":"industry_default","redemption_period_days":"industry_default","pending_delete_days":"industry_default","pre_expiry_days":"industry_default","drop_hour":"industry_default"},"reasoning":"数据来源和提取说明"}`;

const FIELD_SOURCE_VALUES: FieldSource[] = ["page_explicit", "page_hint", "industry_default"];
const FIELD_KEYS = ["grace_period_days", "redemption_period_days", "pending_delete_days", "pre_expiry_days", "drop_hour"];

// ─── R8: IANA timezone whitelist ──────────────────────────────────────────────
let _tzWhitelist: Set<string> | null = null;
function timezoneWhitelist(): Set<string> {
  if (_tzWhitelist) return _tzWhitelist;
  try {
    const zones = new Set<string>((Intl as any).supportedValuesOf?.("timeZone") ?? []);
    zones.add("UTC");
    zones.add("GMT");
    _tzWhitelist = zones;
    return zones;
  } catch {
    return new Set<string>(["UTC", "GMT"]);
  }
}

function normalizeTimezone(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const zones = timezoneWhitelist();
  // Accept exact match (case-insensitive) or offsets like "UTC+8", "GMT+1", "CET", "EST"
  if (zones.has(trimmed)) return trimmed;
  if (zones.has(trimmed.toUpperCase())) return trimmed.toUpperCase();
  const offsetRe = /^(UTC|GMT)([+-]\d{1,2})(?::(\d{2}))?$/i;
  const m = trimmed.match(offsetRe);
  if (m) {
    const base = m[1].toUpperCase();
    const h = String(parseInt(m[2], 10)).padStart(2, "0");
    const min = m[3] ? `:${m[3]}` : ":00";
    return `${base}${h >= "00" && parseInt(m[2], 10) >= 0 ? "+" : ""}${parseInt(m[2], 10) >= 0 ? h : h}${min}`;
  }
  // Whitelisted legacy abbreviations → IANA equivalents
  const legacy: Record<string, string> = {
    "CET": "Europe/Berlin", "CEST": "Europe/Berlin",
    "EST": "America/New_York", "EDT": "America/New_York",
    "PST": "America/Los_Angeles", "PDT": "America/Los_Angeles",
    "JST": "Asia/Tokyo", "KST": "Asia/Seoul", "CST": "Asia/Shanghai",
  };
  if (legacy[trimmed.toUpperCase()]) return legacy[trimmed.toUpperCase()];
  return null;
}

function parseAiJson(content: string): ExtractedLifecycle {
  const cleaned = content
    .replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/```\s*$/, "")
    .replace(/^[^{]*({[\s\S]*})[^}]*$/, "$1")
    .trim();
  const parsed = JSON.parse(cleaned);
  const toInt = (v: unknown, min = 0) => Math.max(min, parseInt(String(v)) || 0);
  const toNullInt = (v: unknown, lo: number, hi: number): number | null => {
    if (v === null || v === undefined || v === "") return null;
    const n = parseInt(String(v));
    return isNaN(n) ? null : Math.min(hi, Math.max(lo, n));
  };

  // ── R8: timezone whitelist ───────────────────────────────────────────────
  const rawTz = typeof parsed.drop_timezone === "string" && parsed.drop_timezone
    ? parsed.drop_timezone.slice(0, 50) : null;
  const drop_timezone = normalizeTimezone(rawTz);
  // R8 AC2: when the timezone is absent/invalid, the whole drop-time trio is null.
  const hasDropTime = parsed.drop_hour !== null && parsed.drop_hour !== undefined && parsed.drop_hour !== "";
  const drop_hour   = drop_timezone && hasDropTime ? toNullInt(parsed.drop_hour, 0, 23) : null;
  const drop_minute = drop_timezone && hasDropTime ? toNullInt(parsed.drop_minute, 0, 59) : null;
  const drop_second = drop_timezone && hasDropTime ? toNullInt(parsed.drop_second, 0, 59) : null;

  // ── R7: field source markers ─────────────────────────────────────────────
  const rawSources = parsed.field_sources as Record<string, unknown> | null | undefined;
  const field_sources: Record<string, FieldSource> = {};
  const defaultByValue: Record<string, number> = {
    grace_period_days: 30, redemption_period_days: 30,
    pending_delete_days: 5, pre_expiry_days: 0,
  };
  for (const key of FIELD_KEYS) {
    if (rawSources && FIELD_SOURCE_VALUES.includes(rawSources[key] as FieldSource)) {
      field_sources[key] = rawSources[key] as FieldSource;
    } else {
      const val = key === "drop_hour" ? drop_hour : parsed[key];
      field_sources[key] = val === defaultByValue[key]
        ? "industry_default"
        : "page_hint";
    }
  }
  const explicitCount = Object.values(field_sources).filter(v => v === "page_explicit").length;
  const graceExplicit = field_sources.grace_period_days === "page_explicit";
  const redemptionExplicit = field_sources.redemption_period_days === "page_explicit";
  const confidence: "high" | "ai" =
    graceExplicit && redemptionExplicit ? "high"
    : explicitCount > 0 ? "ai"
    : "ai";

  return {
    grace_period_days: toInt(parsed.grace_period_days),
    redemption_period_days: toInt(parsed.redemption_period_days),
    pending_delete_days: toInt(parsed.pending_delete_days),
    pre_expiry_days: toNullInt(parsed.pre_expiry_days, 0, 365),
    drop_hour,
    drop_minute,
    drop_second,
    drop_timezone,
    reasoning: String(parsed.reasoning || "").slice(0, 600),
    model_used: "",
    field_sources,
    confidence,
  };
}

async function extractWithAI(
  tld: string,
  pageText: string,
  sourceUrl: string,
  preferredModel?: string
): Promise<ExtractedLifecycle> {
  const pageSnippet = pageText.slice(0, 8000);
  const userMessage = `TLD: .${tld}\n来源页面: ${sourceUrl}\n\n页面内容：\n${pageSnippet}`;
  const messages = [
    { role: "system" as const, content: SYSTEM_PROMPT },
    { role: "user" as const, content: userMessage },
  ];

  const errors: string[] = [];
  const { content, provider } = await callProviderWithFallback(
    messages,
    preferredModel,
    errors,
    { kind: "tld_extract", tld }
  );

  try {
    const result = parseAiJson(content);
    result.model_used = provider.name;
    return result;
  } catch (e) {
    throw new Error(
      `AI(${provider.name}) returned unparseable JSON: ${content.slice(0, 300)}\nErrors: ${errors.join("; ")}`
    );
  }
}

// ─── Unified save pipeline (R6 AC3/AC4) ───────────────────────────────────────
interface SaveTldFields {
  grace_period_days: number;
  redemption_period_days: number;
  pending_delete_days: number;
  drop_hour: number | null;
  drop_minute: number | null;
  drop_second: number | null;
  drop_timezone: string | null;
  pre_expiry_days: number | null;
  reasoning: string;
  model_used: string;
  field_sources: Record<string, FieldSource>;
  confidence: "high" | "ai";
}

async function saveTldRule(
  tld: string,
  extracted: SaveTldFields,
  finalUrl: string,
  scrapeStatus: string,
  fetchStrategy: FetchStrategy,
  rawExcerpt: string
): Promise<void> {
  const fieldsSourceJson = JSON.stringify(extracted.field_sources ?? {});
  await run(
    `INSERT INTO tld_rules
       (tld, grace_period_days, redemption_period_days, pending_delete_days,
        source_url, confidence, raw_excerpt, ai_reasoning, model_used,
        drop_hour, drop_minute, drop_second, drop_timezone, pre_expiry_days,
        fetch_strategy, fields_source,
        scraped_at, updated_at, scrape_status, failure_reason, needs_admin_review, scrape_attempts)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW(),$17,NULL,$18,1)
     ON CONFLICT (tld) DO UPDATE SET
       grace_period_days      = EXCLUDED.grace_period_days,
       redemption_period_days = EXCLUDED.redemption_period_days,
       pending_delete_days    = EXCLUDED.pending_delete_days,
       source_url             = EXCLUDED.source_url,
       confidence             = EXCLUDED.confidence,
       raw_excerpt            = EXCLUDED.raw_excerpt,
       ai_reasoning           = EXCLUDED.ai_reasoning,
       model_used             = EXCLUDED.model_used,
       drop_hour              = EXCLUDED.drop_hour,
       drop_minute            = EXCLUDED.drop_minute,
       drop_second            = EXCLUDED.drop_second,
       drop_timezone          = EXCLUDED.drop_timezone,
       pre_expiry_days        = EXCLUDED.pre_expiry_days,
       fetch_strategy         = EXCLUDED.fetch_strategy,
       fields_source          = EXCLUDED.fields_source,
       scraped_at             = NOW(),
       updated_at             = NOW(),
       scrape_status          = EXCLUDED.scrape_status,
       failure_reason         = NULL,
       needs_admin_review     = EXCLUDED.needs_admin_review,
       processing_at          = NULL,
       processing_from        = NULL,
       scrape_attempts        = COALESCE(tld_rules.scrape_attempts, 0) + 1`,
    [
      tld,
      extracted.grace_period_days,
      extracted.redemption_period_days,
      extracted.pending_delete_days,
      finalUrl,
      extracted.confidence,
      rawExcerpt.slice(0, 1000),
      extracted.reasoning,
      extracted.model_used || null,
      extracted.drop_hour,
      extracted.drop_minute,
      extracted.drop_second,
      extracted.drop_timezone,
      extracted.pre_expiry_days ?? 0,
      fetchStrategy,
      fieldsSourceJson,
      scrapeStatus,
      scrapeStatus !== "ok",
    ]
  );
}

async function saveFailure(tld: string, reason: string): Promise<void> {
  await run(
    `INSERT INTO tld_rules
       (tld, grace_period_days, redemption_period_days, pending_delete_days,
        scrape_status, failure_reason, scraped_at, updated_at,
        needs_admin_review, confidence, scrape_attempts)
     VALUES ($1,30,30,5,'failed',$2,NOW(),NOW(),TRUE,'low',1)
     ON CONFLICT (tld) DO UPDATE SET
       scrape_status      = 'failed',
       failure_reason     = $2,
       scraped_at         = NOW(),
       updated_at         = NOW(),
       needs_admin_review = TRUE,
       processing_at      = NULL,
       processing_from    = NULL,
       scrape_attempts    = COALESCE(tld_rules.scrape_attempts, 0) + 1`,
    [tld, reason.slice(0, 500)]
  ).catch((e: Error) =>
    logger.warn(`[tld-scrape] DB write failure for ${tld}:`, e.message)
  );
}

function isAllDefaults(r: {
  grace_period_days: number;
  redemption_period_days: number;
  pending_delete_days: number;
}): boolean {
  return (
    r.grace_period_days === 30 &&
    r.redemption_period_days === 30 &&
    r.pending_delete_days === 5
  );
}

// ─── Unified entry point (R6 AC1/AC2) ─────────────────────────────────────────
export interface ScrapeTldOptions {
  tld: string;
  sourceUrl?: string;
  preferredModel?: string;
  force?: boolean;
}

export interface ScrapeTldResult {
  tld: string;
  ok: boolean;
  skipped?: boolean;
  skipReason?: "manually_edited" | "already_ok";
  extracted?: ExtractedLifecycle;
  finalUrl?: string;
  pageText?: string;
  hasLifecycleInfo?: boolean;
  scrapeStatus?: "ok" | "warn_defaults";
  fetchStrategy?: FetchStrategy;
  error?: string;
}

/**
 * Scrape a single TLD through the unified pipeline:
 * discovery → AI extraction → unified save → cache invalidation.
 *
 * When `sourceUrl` is provided and is a non-IANA URL, discovery is skipped and
 * that URL is scraped directly (R12 AC3).
 */
export async function scrapeTld(options: ScrapeTldOptions): Promise<ScrapeTldResult> {
  const tld = options.tld.toLowerCase().replace(/^\./, "");
  const rawUrl = (options.sourceUrl ?? "").trim();
  if (rawUrl) {
    const check = validatePublicUrl(rawUrl);
    if (!check.ok) return { tld, ok: false, error: check.error };
  }
  const cleanUrl = rawUrl || `https://www.iana.org/domains/root/db/${tld}.html`;
  const force = !!options.force;

  try {
    // 1. Skip check — protect manually-edited and (unless forced) already-ok rows
    if (!force) {
      const existing = await (async () => {
        const { one } = await import("@/lib/db-query");
        return one<{
          manually_edited: boolean;
          scrape_status: string;
        }>(
          `SELECT COALESCE(manually_edited, FALSE) AS manually_edited,
                  COALESCE(scrape_status, 'pending') AS scrape_status
           FROM tld_rules WHERE tld = $1`,
          [tld]
        ).catch(() => null);
      })();

      if (existing?.manually_edited) {
        return { tld, ok: true, skipped: true, skipReason: "manually_edited" };
      }
      if (existing?.scrape_status === "ok") {
        return { tld, ok: true, skipped: true, skipReason: "already_ok" };
      }
    }

    // 2. Fetch page text (smart discovery: IANA → registry lifecycle page)
    const { text: pageText, finalUrl, strategy } = await fetchPageText(cleanUrl);
    if (!pageText || pageText.length < 50) {
      throw new Error("Could not extract meaningful text from the page");
    }

    // 3. AI extraction with multi-model fallback
    const extracted = await extractWithAI(tld, pageText, finalUrl, options.preferredModel);

    // 4. Status: 'ok' if non-default data, 'warn_defaults' if only industry defaults
    const scrapeStatus: "ok" | "warn_defaults" = isAllDefaults(extracted) ? "warn_defaults" : "ok";

    // 5. Unified save
    await saveTldRule(tld, extracted, finalUrl, scrapeStatus, strategy, pageText);

    // 6. Invalidate lifecycle override cache so new data is live immediately
    invalidateLifecycleOverridesCache();

    return {
      tld,
      ok: true,
      extracted,
      finalUrl,
      pageText,
      hasLifecycleInfo: hasLifecycleInfo(pageText),
      scrapeStatus,
      fetchStrategy: strategy,
    };
  } catch (err: any) {
    const reason = (err.message ?? String(err)).slice(0, 400);
    await saveFailure(tld, reason);
    return { tld, ok: false, error: reason };
  }
}

export { hasLifecycleInfo, fetchPageText, extractWithAI, parseAiJson };
export type { FetchStrategy as TldFetchStrategy };
