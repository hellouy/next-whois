/**
 * Pure helpers extracted from the query result page ([...query].tsx):
 * query validation, registrar/NS icon resolution, WHOIS date formatting,
 * DNSSEC localization, OG URL building, and card motion variants.
 * No React component lives here — safe to import from server and client.
 */
import { cleanDomain } from "@/lib/utils";
import { TranslationKey } from "@/lib/i18n";
import { WhoisAnalyzeResult } from "@/lib/whois/types";
import { REGISTRAR_ICONS } from "@/data/query-page/registrar-icons";
import { NS_BRANDS } from "@/data/query-page/ns-brands";

// Shared validity check used by both getServerSideProps (SSR) and the
// client-side useEffect.  A "query" must have a dot (domain/IP), be an ASN
// (AS12345), or be an IPv6 address.  Bare words like "zhouzhouw" are invalid.
export function looksLikeDomainQuery(t: string | undefined | null): boolean {
  if (!t || typeof t !== "string") return false;
  return (
    !t.startsWith(".") &&
    (t.includes(".") ||
      /^AS\d+$/i.test(t) ||
      /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(t))
  );
}

export const CARD_CONTAINER_VARIANTS = {
  hidden: { opacity: 1 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.025, delayChildren: 0.03 },
  },
};

export const CARD_ITEM_VARIANTS = {
  hidden: { opacity: 0, y: 5 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] },
  },
};



export function getNsBrand(
  ns: string,
): { brand: string; slug: string | null; color: string } | null {
  const lower = ns.toLowerCase();
  for (const info of NS_BRANDS) {
    if (info.domains.some((d) => lower.includes(d))) return info;
  }
  return null;
}

export function getRegistrarIcon(
  registrar: string,
  registrarURL?: string,
): { slug: string | null; color: string } | null {
  if (!registrar || registrar === "Unknown") return null;
  const normalized = registrar.toLowerCase().replace(/[\s.,\-_()]+/g, "");
  for (const [key, info] of Object.entries(REGISTRAR_ICONS)) {
    if (normalized.includes(key)) return info;
  }
  if (registrarURL) {
    const urlLower = registrarURL.toLowerCase();
    for (const [key, info] of Object.entries(REGISTRAR_ICONS)) {
      if (urlLower.includes(key)) return info;
    }
  }
  return null;
}

export function getDarkModeIconColor(color: string): string {
  const hex = color.replace("#", "");
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance < 0.4 ? "white" : hex;
}

export function resolveIconUrl(slug: string, color: string, dark: boolean): string {
  if (slug.startsWith("/")) return slug;
  const c = dark ? getDarkModeIconColor(color) : color.replace("#", "");
  return `https://cdn.simpleicons.org/${slug}/${c}`;
}

export function getRegistrarFallbackColor(registrar: string): string {
  let hash = 0;
  for (let i = 0; i < registrar.length; i++) {
    hash = registrar.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 65%, 50%)`;
}

/**
 * Robustly parse a WHOIS date string into a Date object.
 * Handles formats like:
 *   "1996-07-01T02:00:00Z"
 *   "1996-07-01 02:00:00 U"    ← .ba / some ccTLDs append a TZ letter
 *   "1996-07-01 02:00:00 UTC"
 *   "1996-07-01 02:00:00+08:00"
 *   "2022-11-08 12:31:01"
 */
export function parseWhoisDate(dateStr: string): Date | null {
  if (!dateStr || dateStr === "Unknown") return null;
  // 1. Try as-is first (covers ISO 8601 with Z or offset)
  let d = new Date(dateStr);
  if (!isNaN(d.getTime())) return d;
  // 2. Strip trailing timezone code: single letters (U, Z) or abbreviations (UTC, EST, CET…)
  //    and numeric offsets (+08:00, -05:00) then retry
  const stripped = dateStr
    .replace(/\s+[+-]\d{2}:?\d{2}$/, "")   // remove " +08:00" / " -0500"
    .replace(/\s+[A-Z]{1,5}$/, "")          // remove " U" / " UTC" / " EST"
    .replace(/\.\d+$/, "")                  // remove fractional seconds
    .trim();
  d = new Date(stripped);
  if (!isNaN(d.getTime())) return d;
  // 3. Replace whitespace separator(s) with T for strict ISO parsing.
  // Global replace handles any whitespace run (e.g. "2020-01-15  10:30:00").
  const isoLike = stripped.replace(/\s+/g, "T") + "Z";
  d = new Date(isoLike);
  if (!isNaN(d.getTime())) return d;
  return null;
}

export function getRelativeTime(
  dateStr: string,
  t: (key: TranslationKey, values?: Record<string, string | number>) => string,
): string {
  if (!dateStr || dateStr === "Unknown") return "";
  try {
    const date = parseWhoisDate(dateStr);
    if (!date) return "";
    const now = new Date();
    const diffDays = Math.floor(
      (now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24),
    );
    if (diffDays < 0) {
      const abs = Math.abs(diffDays);
      if (abs < 30) return t("relative_time.in_days", { days: abs });
      if (abs < 365)
        return t("relative_time.in_months", { months: Math.floor(abs / 30) });
      return t("relative_time.in_years", { years: Math.floor(abs / 365) });
    }
    if (diffDays < 1) return t("relative_time.today");
    if (diffDays < 30) return t("relative_time.days_ago", { days: diffDays });
    if (diffDays < 365)
      return t("relative_time.months_ago", {
        months: Math.floor(diffDays / 30),
      });
    return t("relative_time.years_ago", { years: Math.floor(diffDays / 365) });
  } catch {
    return "";
  }
}

export function formatDate(dateStr: string): string {
  if (!dateStr || dateStr === "Unknown") return "—";
  const d = parseWhoisDate(dateStr);
  if (!d) return dateStr.slice(0, 10) || dateStr; // best-effort: first 10 chars
  return d.toISOString().slice(0, 10); // always YYYY-MM-DD
}

/**
 * Translate DNSSEC field values and embedded technical terms.
 * For zh/zh-tw locales, known DNSSEC terms are replaced with Chinese equivalents.
 * For all other locales the original value is returned unchanged.
 */
export function translateDnssecValue(value: string, locale: string): string {
  if (!locale.startsWith("zh")) return value;
  const isTraditional = locale === "zh-tw";

  // Simple whole-value mapping for common RDAP/WHOIS values
  const WHOLE: Record<string, string> = {
    unsigned: "未签名",
    signed: "已签名",
    signeddelegation: "已签名",
    yes: "已签名",
    no: "未签名",
  };
  const key = value.toLowerCase().replace(/[\s\-_]/g, "");
  if (WHOLE[key]) {
    const v = WHOLE[key];
    return isTraditional ? v.replace("签", "簽") : v;
  }

  // Substring replacement for values that contain multiple terms
  const SUBS: [RegExp, string, string][] = [
    // [pattern, simplified, traditional]
    [/\bZone Signing Key\b/gi, "区域签名密钥", "區域簽名金鑰"],
    [/\bZSK\b/g, "ZSK", "ZSK"],
    [/\bKey Signing Key\b/gi, "密钥签名密钥", "金鑰簽名金鑰"],
    [/\bKSK\b/g, "KSK", "KSK"],
    [/\bDS Record\b/gi, "委托签名记录", "委託簽名記錄"],
    [/\bRRSIG\b/g, "资源记录签名", "資源記錄簽名"],
    [/\bDNSKEY\b/g, "DNS 密钥记录", "DNS 金鑰記錄"],
    [/\bNSEC3\b/g, "下一安全记录3", "下一安全記錄3"],
    [/\bNSEC\b/g, "下一安全记录", "下一安全記錄"],
    [/\bValidating Resolver\b/gi, "验证解析器", "驗證解析器"],
    [/\bValidation\b/gi, "验证", "驗證"],
    [/\bTrust Anchor\b/gi, "信任锚", "信任錨"],
    [/\bChain of Trust\b/gi, "信任链", "信任鏈"],
    [/\bKey Rollover\b/gi, "密钥滚动", "金鑰滾動"],
    [/\bDenial of Existence\b/gi, "存在否定", "存在否定"],
    [/\bAlgorithm\b/gi, "算法", "演算法"],
    [/\bsignedDelegation\b/gi, "已签名", "已簽名"],
    [/\bsigned\b/gi, "已签名", "已簽名"],
    [/\bunsigned\b/gi, "未签名", "未簽名"],
    [/\bDNSSEC\b/g, "DNS 安全扩展", "DNS 安全延伸"],
  ];

  let result = value;
  for (const [pattern, simplified, traditional] of SUBS) {
    result = result.replace(pattern, isTraditional ? traditional : simplified);
  }
  return result;
}

export function buildOgUrl(
  target: string,
  result?: WhoisAnalyzeResult | undefined,
  overrides?: { w?: number; h?: number; theme?: string },
): string {
  const params = new URLSearchParams();
  params.set("query", target);
  if (overrides?.w) params.set("w", String(overrides.w));
  if (overrides?.h) params.set("h", String(overrides.h));
  const themeVal =
    overrides?.theme ||
    (typeof window !== "undefined" &&
    document.documentElement.classList.contains("dark")
      ? "dark"
      : "light");
  if (themeVal === "dark") params.set("theme", "dark");

  // Embed compact WHOIS fields so the OG handler can skip the lookup fetch.
  if (result) {
    const r = result;
    const ok = (v: unknown): v is string =>
      typeof v === "string" && v.length > 0 && v !== "Unknown";
    if (ok(r.registrar))            params.set("reg", r.registrar.slice(0, 60));
    if (ok(r.creationDate))         params.set("cr",  r.creationDate.slice(0, 10));
    if (ok(r.expirationDate))       params.set("ex",  r.expirationDate.slice(0, 10));
    if (ok(r.updatedDate))          params.set("up",  r.updatedDate.slice(0, 10));
    if (r.remainingDays != null)    params.set("rd",  String(r.remainingDays));
    if (r.domainAge != null)        params.set("age", String(r.domainAge));
    if (Array.isArray(r.nameServers) && r.nameServers.length > 0)
      params.set("ns", r.nameServers.slice(0, 3).join(","));
    if (Array.isArray(r.status) && r.status.length > 0)
      params.set("st", r.status.slice(0, 4).map((s: { status: string }) => s.status).join(","));
    if (ok(r.registrantCountry))    params.set("co",  r.registrantCountry);
    if (ok(r.registrantOrganization))
      params.set("org", r.registrantOrganization.slice(0, 50));
    if (ok(r.dnssec))               params.set("dn",  r.dnssec.slice(0, 30));
    if (ok(r.whoisServer))          params.set("ws",  r.whoisServer.slice(0, 60));
  }

  return `/api/og?${params.toString()}`;
}


export function targetToDisplayName(target: string): string {
  try {
    const hasAce = target
      .toLowerCase()
      .split(".")
      .some((l: string) => l.startsWith("xn--"));
    if (!hasAce) return target;
    // domainToUnicode is a Node.js built-in — require() at call-site so webpack
    // does NOT bundle it into the client-side JavaScript chunk.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { domainToUnicode } = require("url") as typeof import("url");
    const unicode = domainToUnicode(target.toLowerCase());
    return unicode && unicode !== target.toLowerCase() ? unicode : target;
  } catch {
    return target;
  }
}

/** Extract the cleaned query target from Next.js router.query (client-side). */
export function targetFromRouterQuery(query: NodeJS.Dict<string | string[]>): string {
  const segments = (query.query as string[] | undefined) ?? [];
  return cleanDomain(segments.join("/").replace(/\s+/g, ""));
}
