import {
  cleanDomain,
  cn,
  getWindowHref,
  isValidDomainTld,
  isSearchRoute,
  toSearchURI,
  useClipboard,
  useSaver,
} from "@/lib/utils";
import { GetServerSidePropsContext } from "next";
import { useRouter } from "next/router";
import { getOrigin } from "@/lib/seo";
import { Input } from "@/components/ui/input";
import Link from "next/link";
import Head from "next/head";
import { Button } from "@/components/ui/button";
import {
  RiCameraLine,
  RiFileCopyLine,
  RiExternalLinkLine,
  RiLinkM,
  RiShareLine,
  RiTwitterXLine,
  RiFacebookFill,
  RiRedditLine,
  RiWhatsappLine,
  RiTelegramLine,
  RiTimeLine,
  RiExchangeDollarFill,
  RiBillLine,
  RiDownloadLine,
  RiServerLine,
  RiGlobalLine,
  RiForbidLine,
  RiLockLine,
  RiPauseCircleLine,
  RiScalesLine,
  RiLoopLeftLine,
  RiDeleteBin2Line,
  RiCheckLine,
  RiShoppingCartLine,
  RiBookmarkLine,
  RiBookmarkFill,
  RiCalendar2Line,
  RiStickyNoteLine,
  RiTimerLine,
  RiCalendarEventLine,
  RiShieldCheckLine,
  RiLoader4Line,
  RiErrorWarningLine,
  RiSearchLine,
  RiCheckboxCircleLine,
  RiCheckboxBlankCircleLine,
  RiVipCrownLine,
  RiAlertLine,
  RiArrowRightSLine,
  RiFlagLine,
  RiInformationLine,
  RiMegaphoneLine,
} from "@remixicon/react";
import { getTopRegistrars, DomainPricing } from "@/lib/pricing/client";
import { useSiteSettings } from "@/lib/site-settings";
import { computeLifecycle, fmtDate, fmtDateTime, fmtCountdown } from "@/lib/lifecycle";
import React, { useEffect, useMemo } from "react";
import ReactDOM from "react-dom";
import { addHistory, detectQueryType, RegStatus } from "@/lib/history";
import { prefetchLookup, consumePrefetch } from "@/lib/lookup-prefetch";
import { useSession } from "next-auth/react";
import { Badge } from "@/components/ui/badge";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { WhoisAnalyzeResult, WhoisResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { domainToUnicode } from "url";
import { getSetting as getSettingServer } from "@/lib/server/site-settings-server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import {
  getEppStatusInfo,
  getEppStatusColor,
  getEppStatusDisplayName,
  getEppStatusLink,
  getEppStatusDescription,
} from "@/lib/whois/epp_status";
import { SearchBox } from "@/components/search_box";
import {
  KeyboardShortcut,
  SearchHotkeysText,
} from "@/components/search_shortcuts";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { StampPreviewCard } from "@/components/stamp-preview-card";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { useTheme } from "next-themes";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { useSearchHotkeys } from "@/hooks/useSearchHotkeys";
import dynamic from "next/dynamic";
import { REGISTRAR_ICONS } from "@/data/query-page/registrar-icons";
import { NS_BRANDS } from "@/data/query-page/ns-brands";
import { GLOBE_COUNTRY_COORDS } from "@/data/query-page/globe-coords";
import { MAINSTREAM_DOMAINS } from "@/data/query-page/mainstream-domains";
import { OFFICIAL_DOMAIN_DESC } from "@/data/query-page/official-domain-desc";
import { QueryProgressBar } from "@/components/query/query-progress-bar";
import { CssGlobe } from "@/components/query/css-globe";
import { ResponsePanel } from "@/components/query/response-panel";

// Lazy-loaded: only needed when the user opens the feedback panel
const FeedbackDrawer = dynamic(
  () => import("@/components/feedback-drawer").then((m) => ({ default: m.FeedbackDrawer })),
  { ssr: false, loading: () => null }
);

const CARD_CONTAINER_VARIANTS = {
  hidden: { opacity: 1 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.04, delayChildren: 0.08 },
  },
};

const CARD_ITEM_VARIANTS = {
  hidden: { opacity: 0, y: 8 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3, ease: [0.22, 1, 0.36, 1] },
  },
};



function getNsBrand(
  ns: string,
): { brand: string; slug: string | null; color: string } | null {
  const lower = ns.toLowerCase();
  for (const info of NS_BRANDS) {
    if (info.domains.some((d) => lower.includes(d))) return info;
  }
  return null;
}

function getRegistrarIcon(
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

function getDarkModeIconColor(color: string): string {
  const hex = color.replace("#", "");
  const r = parseInt(hex.substring(0, 2), 16);
  const g = parseInt(hex.substring(2, 4), 16);
  const b = parseInt(hex.substring(4, 6), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance < 0.4 ? "white" : hex;
}

function resolveIconUrl(slug: string, color: string, dark: boolean): string {
  if (slug.startsWith("/")) return slug;
  const c = dark ? getDarkModeIconColor(color) : color.replace("#", "");
  return `https://cdn.simpleicons.org/${slug}/${c}`;
}

function getRegistrarFallbackColor(registrar: string): string {
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
function parseWhoisDate(dateStr: string): Date | null {
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

function getRelativeTime(
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

function formatDate(dateStr: string): string {
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
function translateDnssecValue(value: string, locale: string): string {
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

function buildOgUrl(
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


function targetToDisplayName(target: string): string {
  try {
    const hasAce = target
      .toLowerCase()
      .split(".")
      .some((l: string) => l.startsWith("xn--"));
    if (!hasAce) return target;
    const unicode = domainToUnicode(target.toLowerCase());
    return unicode && unicode !== target.toLowerCase() ? unicode : target;
  } catch {
    return target;
  }
}

export async function getServerSideProps(context: GetServerSidePropsContext) {
  const querySegments: string[] = (context.params?.query as string[]) ?? [];
  const origin = getOrigin(context.req);

  // ── Strip locale prefix from catch-all segments ───────────────────────────
  // URLs no longer include a locale prefix.  Old bookmarked URLs like
  // /zh/x.rw or /en/x.rw are 301-redirected to /x.rw for canonicality.
  const VALID_LOCALES = new Set(["en", "zh", "zh-tw", "de", "ru", "ja", "fr", "ko"]);
  const hasLocalePrefix =
    querySegments.length >= 2 && VALID_LOCALES.has(querySegments[0]);
  if (hasLocalePrefix) {
    const cleanPath = "/" + querySegments.slice(1).join("/");
    return { redirect: { destination: cleanPath, permanent: true } };
  }
  const effectiveSegments = querySegments;

  // ── Smart URL cleaning + canonical redirect ──────────────────────────────
  // Strip spaces first (handles URL-encoded spaces like %20 decoded to " ")
  // then run cleanDomain which strips protocols, paths, ports, auth, etc.
  const rawPath = effectiveSegments.join("/");
  const spacelessPath = rawPath.replace(/\s+/g, "");
  const target = cleanDomain(spacelessPath);
  const displayTarget = targetToDisplayName(target);

  const looksLikeQuery = (t: string) =>
    // Reject bare TLDs like ".cc" or ".com" — a leading dot means an empty
    // label before it, which is never a valid domain, IP, or ASN.
    !t.startsWith(".") &&
    (t.includes(".") ||
      /^AS\d+$/i.test(t) ||
      /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(t));

  // If cleaning changed the URL (spaces removed, protocol stripped, path trimmed…),
  // redirect to the canonical clean URL to avoid duplicate/broken results.
  if (looksLikeQuery(target) && `/${target}` !== `/${rawPath}`) {
    return { redirect: { destination: `/${target}`, permanent: false } };
  }

  // If it still doesn't look like any known query type, redirect to home
  // instead of a hard 404 — real app routes (/admin, /zh/about, etc.) are
  // handled by their own pages before they ever reach this catch-all.
  if (!looksLikeQuery(target)) {
    return { redirect: { destination: "/", permanent: false } };
  }

  // ── CN Reserved SLD early-return (before cleanDomain rewrites the query) ──
  // Some .cn functional SLDs (gov.cn, edu.cn, etc.) are mapped by the WHOIS
  // lib to their www.* equivalents so the lookup works.  We must intercept
  // BEFORE that mapping so the user sees "保留域名" instead of www.gov.cn data.
  const rawQuery = target.toLowerCase();
  const cnReservedSsr = getCnReservedSldInfo(rawQuery);
  if (cnReservedSsr) {
    const syntheticData: WhoisResult = {
      time: 0,
      status: true,
      cached: false,
      source: "whois",
      result: {
        ...initialWhoisAnalyzeResult,
        domain: rawQuery,
        status: [{ status: "registry-reserved", url: "" }],
        rawWhoisContent: `[CN Reserved] ${cnReservedSsr.descZh}`,
      },
    };
    // CN reserved SLDs are static — safe to cache at edge for 12 h
    context.res.setHeader("Cache-Control", "public, s-maxage=43200, stale-while-revalidate=86400");
    return {
      props: {
        data: JSON.parse(JSON.stringify(syntheticData)),
        target: rawQuery,
        displayTarget: targetToDisplayName(rawQuery),
        origin,
      },
    };
  }

  // Server-side TLD validation — reject clearly invalid domains before lookup
  if (!isValidDomainTld(target)) {
    return {
      props: {
        data: {
          time: 0,
          status: false,
          cached: false,
          error: "INVALID_DOMAIN_TLD",
        } as WhoisResult,
        target,
        displayTarget,
        origin,
      },
    };
  }

  // ── Parallel: require_login check + cache lookup ────────────────────────────
  // Both are independently fetchable: settings has a 30s in-process cache;
  // the WHOIS cache check is a quick Postgres read.  Firing them together
  // removes the sequential gap (~20-60ms) on every page request.
  const requireLoginPromise = getSettingServer("require_login");
  const ssrCachePromise = lookupWhoisWithCache(target, { cacheOnly: true }).catch(() => null);

  const requireLogin = await requireLoginPromise;
  if (requireLogin === "1") {
    const session = await getServerSession(context.req, context.res, authOptions);
    if (!session?.user?.email) {
      const callbackUrl = `/${target}`;
      return { redirect: { destination: `/login?callbackUrl=${encodeURIComponent(callbackUrl)}&msg=require_login`, permanent: false } };
    }
  }

  // Try to serve cached WHOIS data for SSR (gives search engines rich content).
  // cacheOnly=true means we only check Redis/L1 — if there's no cache hit we
  // return data:null immediately (no live lookup, no latency added).
  let ssrData: WhoisResult | null = null;
  try {
    const cached = await ssrCachePromise;
    if (cached?.cached === true && cached.status) {
      ssrData = cached;
    }
  } catch {
    ssrData = null;
  }

  // ── Edge / CDN caching for SSR HTML ─────────────────────────────────────
  // When require_login is OFF, allow Vercel's CDN to cache the rendered HTML
  // at the edge so repeat visitors don't hit the origin server.
  // - With WHOIS data: cache matches the data TTL (capped at 1 h) so the HTML
  //   is as fresh as the underlying WHOIS cache.
  // - Without WHOIS data (loading shell): short TTL so the shell is cached
  //   briefly; the client will fetch live data via /api/lookup regardless.
  // When require_login is ON, the response is user-specific — no edge caching.
  if (requireLogin !== "1") {
    const sMaxAge = ssrData?.cacheTtl && ssrData.cacheTtl > 0
      ? Math.min(ssrData.cacheTtl, 3600)
      : 30;
    const swr = Math.min(sMaxAge * 4, 86_400);
    context.res.setHeader(
      "Cache-Control",
      `public, s-maxage=${sMaxAge}, stale-while-revalidate=${swr}`,
    );
  }

  return {
    props: {
      data: ssrData,
      target,
      displayTarget,
      origin,
    },
  };
}





type RegistrationStatusType =
  | "registered"
  | "available"
  | "reserved"
  | "prohibited"
  | "hold"
  | "dispute"
  | "redemption"
  | "pending-delete";

const STATUS_LABELS: Record<RegistrationStatusType, { zh: string; en: string }> = {
  registered: { zh: "已注册", en: "Registered" },
  available: { zh: "未注册", en: "Available" },
  reserved: { zh: "保留域名", en: "Reserved" },
  prohibited: { zh: "禁止注册", en: "Prohibited" },
  hold: { zh: "暂停", en: "On Hold" },
  dispute: { zh: "争议中", en: "In Dispute" },
  redemption: { zh: "赎回期", en: "Redemption" },
  "pending-delete": { zh: "待删除", en: "Pending Delete" },
};

function getDomainRegistrationStatus(
  result: WhoisAnalyzeResult,
  locale = "en",
): {
  type: RegistrationStatusType;
  label: string;
  color: string;
  dotColor: string;
  isPremiumReserved: boolean;
} {
  const isZh = locale.startsWith("zh");

  // EPP lock statuses that contain "prohibited" in their name but are NOT
  // about registration prohibition — they protect already-registered domains.
  const EPP_PROHIBITED_LOCK_STATUSES = new Set([
    "clientdeleteprohibited",
    "clienttransferprohibited",
    "clientrenewprohibited",
    "clientupdateprohibited",
    "serverdeleteprohibited",
    "servertransferprohibited",
    "serverrenewprohibited",
    "serverupdateprohibited",
    // hyphenated / space variants used by some ccTLDs
    "client-delete-prohibited",
    "client-transfer-prohibited",
    "client-renew-prohibited",
    "client-update-prohibited",
    "server-delete-prohibited",
    "server-transfer-prohibited",
    "server-renew-prohibited",
    "server-update-prohibited",
  ]);

  const allStatusCodes = result.status.map((s) => s.status.toLowerCase().trim());
  const allStatusText = allStatusCodes.join(" ");

  // Build a separate text excluding EPP lock statuses for the prohibit check
  // so that "clientTransferProhibited" / "client transfer prohibited" /
  // "client-transfer-prohibited" do not trigger "禁止注册".
  // We check THREE forms of each code: the raw first-word, the full hyphenated
  // string (some ccTLDs emit "client-delete-prohibited"), and the concatenated
  // no-separator form (TWNIC WHOIS emits "client delete prohibited" with spaces).
  const prohibitCheckText = allStatusCodes
    .filter((s) => {
      const firstWord = s.split(/\s+/)[0];            // "client" from "client delete prohibited"
      const noSep = s.replace(/[\s_\-]/g, "");        // "clientdeleteprohibited"
      return (
        !EPP_PROHIBITED_LOCK_STATUSES.has(firstWord) &&
        !EPP_PROHIBITED_LOCK_STATUSES.has(noSep)
      );
    })
    .join(" ");

  // ── Raw content scan (safety net for RDAP and exotic ccTLD WHOIS formats) ───
  // Some registries embed state as free text in WHOIS/RDAP rather than EPP
  // codes. Scan the raw content with specific phrases to capture these signals.
  const rawContent = [
    typeof result.rawWhoisContent === "string" ? result.rawWhoisContent : "",
    result.rawRdapContent
      ? typeof result.rawRdapContent === "string"
        ? result.rawRdapContent
        : JSON.stringify(result.rawRdapContent)
      : "",
  ]
    .join("\n")
    .toLowerCase();

  // ── RESERVED — mirrors common_parser.ts syntheticReserved exactly ───────────
  const rawHasReserved =
    // English free-text phrases
    rawContent.includes("reserved name") ||
    rawContent.includes("this name is reserved") ||
    rawContent.includes("is a reserved name") ||
    rawContent.includes("domain is reserved") ||
    rawContent.includes("this domain is reserved") ||
    rawContent.includes("domain name is reserved") ||
    rawContent.includes("reserved by the registry") ||
    rawContent.includes("registry reserved") ||
    rawContent.includes("reserved-name") ||
    rawContent.includes("reserved domain") ||
    rawContent.includes("in the reserved list") ||
    rawContent.includes("on the reserved list") ||
    rawContent.includes("is in the reserved list") ||
    rawContent.includes("is on the reserved list") ||
    rawContent.includes("has been reserved") ||
    rawContent.includes("name is reserved") ||
    rawContent.includes("is reserved for") ||
    rawContent.includes("is reserved by") ||
    rawContent.includes("reserved for registry") ||
    rawContent.includes("reserved for the registry") ||
    rawContent.includes("registry has reserved") ||
    rawContent.includes("registry hold") ||
    rawContent.includes("held by the registry") ||
    rawContent.includes("domain is held") ||
    rawContent.includes("being held by") ||
    rawContent.includes("reserved for future use") ||
    rawContent.includes("reserved for official use") ||
    rawContent.includes("reserved for this registry") ||
    rawContent.includes("reserved at the registry") ||
    rawContent.includes("sunrise reserved") ||
    rawContent.includes("reserved for sunrise") ||
    rawContent.includes("reserved for landrush") ||
    rawContent.includes("landrush reserved") ||
    // Withheld — Donuts, Radix, ICM, Minds + Machines new gTLDs
    rawContent.includes("withheld") ||
    rawContent.includes("withheld by registry") ||
    rawContent.includes("withheld for registry") ||
    rawContent.includes("registry withheld") ||
    rawContent.includes("name withheld") ||
    rawContent.includes("domain withheld") ||
    /\bstatus\s*:\s*withheld\b/.test(rawContent) ||
    // IANA / ICANN delegations — "not delegated" / "not assigned"
    rawContent.includes("not delegated") ||
    rawContent.includes("not-delegated") ||
    rawContent.includes("not assigned") ||
    rawContent.includes("iana reserved") ||
    rawContent.includes("iana hold") ||
    rawContent.includes("blocked by iana") ||
    rawContent.includes("has not been delegated") ||
    rawContent.includes("this tld has not") ||
    /\bstatus\s*:\s*not.delegated\b/.test(rawContent) ||
    // Available only by specific request (some ccTLDs, e.g. .uk)
    rawContent.includes("available-by-request") ||
    rawContent.includes("available by request") ||
    rawContent.includes("registration by request only") ||
    rawContent.includes("available to specific registrants") ||
    rawContent.includes("restricted to qualified") ||
    // "Allocated" (RIPE/RIR context, some country ccTLDs)
    /\bstatus\s*:\s*allocated\b/.test(rawContent) ||
    // Blocked by registry (for reserved/sensitive strings — not abuse block)
    /\bstatus\s*:\s*blocked\b/.test(rawContent) ||
    rawContent.includes("blocked for registration") ||
    rawContent.includes("registry block") ||
    // RDAP "remarks" text: "This domain has not been delegated"
    rawContent.includes("not been delegated") ||
    // Structured field patterns (EURID .eu, IIS .se/.nu, Donuts, CentralNic, CIRA, etc.)
    /\bstatus\s*:\s*reserved\b/.test(rawContent) ||
    /\bstate\s*:\s*reserved\b/.test(rawContent) ||
    /\bdomainstatus\s*:\s*reserved\b/.test(rawContent) ||
    // German (DENIC .de): "% Status: reserviert"
    rawContent.includes("reserviert") ||
    /\bstatus\s*:\s*reserviert\b/.test(rawContent) ||
    // Czech/Slovak (CZ.NIC .cz .sk): "rezervovan: ano"
    rawContent.includes("rezervovan") ||
    // French ccTLD (AFNIC .fr .re .pm .tf .wf .yt)
    rawContent.includes("réservé") ||
    rawContent.includes("domaine réservé") ||
    rawContent.includes("domaine reserve") ||
    /\bstatus\s*:\s*r[eé]serv[eé]\b/.test(rawContent) ||
    // Spanish ccTLD (.es, .ar, .mx, .co, .cl, .pe, .uy, etc.)
    rawContent.includes("reservado") ||
    rawContent.includes("dominio reservado") ||
    /\bestado\s*:\s*reservado\b/.test(rawContent) ||
    // Portuguese (.pt / .br)
    rawContent.includes("domínio reservado") ||
    // Italian (NIC.it .it): RISERVATO
    /\bstatus\s*:\s*riservato\b/.test(rawContent) ||
    rawContent.includes("dominio riservato") ||
    // Swedish (IIS .se .nu): "state: reserverad"
    /\bstate\s*:\s*reserverad\b/.test(rawContent) ||
    /\bstatus\s*:\s*reserverad\b/.test(rawContent) ||
    rawContent.includes("domännamnet är reserverat") ||
    // Norwegian (Norid .no)
    /\bstatus\s*:\s*reservert\b/.test(rawContent) ||
    rawContent.includes("domenet er reservert") ||
    // Danish (DK Hostmaster .dk)
    /\bstatus\s*:\s*reserveret\b/.test(rawContent) ||
    rawContent.includes("domænet er reserveret") ||
    // Polish (DNS Polska / NASK .pl)
    /\bstatus\s*:\s*zarezerwowany\b/.test(rawContent) ||
    rawContent.includes("domena zarezerwowana") ||
    // Dutch (SIDN .nl)
    /\bstatus\s*:\s*gereserveerd\b/.test(rawContent) ||
    rawContent.includes("domein is gereserveerd") ||
    // Finnish (Traficom .fi): "varattu"
    /\bstatus\s*:\s*varattu\b/.test(rawContent) ||
    rawContent.includes("verkkotunnus varattu") ||
    rawContent.includes("on varattu") ||
    // Hungarian (.hu): "fenntartott"
    /\bstatus\s*:\s*fenntartott\b/.test(rawContent) ||
    rawContent.includes("fenntartott tartomány") ||
    // Romanian (RoTLD .ro): "rezervat"
    /\bstatus\s*:\s*rezervat\b/.test(rawContent) ||
    rawContent.includes("domeniu rezervat") ||
    // Turkish (NIC.TR .tr): "rezerve"
    /\bstatus\s*:\s*rezerve\b/.test(rawContent) ||
    rawContent.includes("alan adı rezerve") ||
    // Greek (ICS.FORTH .gr)
    rawContent.includes("δεσμευμένο") ||
    rawContent.includes("δεσμεύτηκε") ||
    // Bulgarian (.bg)
    rawContent.includes("резервиран") ||
    // Serbian / Bosnian / Croatian (.rs / .ba / .hr)
    rawContent.includes("rezervisano") ||
    rawContent.includes("rezervirano") ||
    // Latvian (NIC.lv .lv)
    rawContent.includes("rezervēts") ||
    // Lithuanian (DOMREG .lt)
    rawContent.includes("rezervuotas") ||
    // Estonian (EIS .ee)
    rawContent.includes("reserveeritud") ||
    // Slovak (.sk)
    rawContent.includes("rezervovaný") ||
    // Russian (.ru / .рф) — non-Latin, safe direct includes
    rawContent.includes("зарезервирован") ||
    rawContent.includes("зарезервировано") ||
    rawContent.includes("зарезервирована") ||
    rawContent.includes("домен зарезервирован") ||
    rawContent.includes("заблокирован") ||
    // Ukrainian (.ua)
    rawContent.includes("зарезервовано") ||
    rawContent.includes("домен зарезервовано") ||
    // Japanese (.jp — JPRS): bilingual WHOIS
    rawContent.includes("予約済み") ||
    rawContent.includes("利用停止") ||
    rawContent.includes("登録停止") ||
    // Korean (.kr — KRNIC)
    rawContent.includes("예약됨") ||
    rawContent.includes("예약된") ||
    rawContent.includes("예약된 도메인") ||
    // Arabic ccTLDs (.sa / .ae / .eg / .iq / .ly)
    rawContent.includes("محجوز") ||
    rawContent.includes("النطاق محجوز") ||
    rawContent.includes("مخصص") ||
    // Hebrew (.il — ISOC-IL)
    rawContent.includes("שמור") ||
    rawContent.includes("הדומיין שמור") ||
    // Traditional Chinese (.tw / .hk)
    rawContent.includes("保留網域") ||
    rawContent.includes("已保留") ||
    // Simplified Chinese (CNNIC, TELE-INFO, ZDNS)
    rawContent.includes("保留域名") ||
    rawContent.includes("已被保留") ||
    rawContent.includes("注册局保留") ||
    rawContent.includes("保留中") ||
    rawContent.includes("该域名已保留") ||
    rawContent.includes("域名已锁定") ||
    // CNNIC (.cn) reserved domains — registry holds name, offline only
    // Response text: "the Domain Name you apply can not be registered online.
    //                 Please consult your Domain Name registrar"
    rawContent.includes("can not be registered online") ||
    rawContent.includes("cannot be registered online") ||
    // Standalone "reserved" on its own line (TWNIC / NZRS)
    /(?:^|\n)\s*reserved\s*(?:\n|$)/.test(rawContent);

  // ── PREMIUM RESERVED — mirrors common_parser.ts syntheticPremiumReserved ────
  const rawHasPremiumReserved =
    rawContent.includes("premium domain") ||
    rawContent.includes("premium name") ||
    rawContent.includes("premium price") ||
    rawContent.includes("premium pricing") ||
    rawContent.includes("premium listing") ||
    rawContent.includes("registry premium") ||
    rawContent.includes("available at a premium") ||
    rawContent.includes("this is a premium") ||
    rawContent.includes("premium registration") ||
    rawContent.includes("early access program") ||
    rawContent.includes("early access pricing") ||
    rawContent.includes("early access period") ||
    rawContent.includes("available for purchase") ||
    rawContent.includes("available for sale") ||
    rawContent.includes("this name is for sale") ||
    rawContent.includes("domain is for sale") ||
    rawContent.includes("make an offer") ||
    rawContent.includes("aftermarket") ||
    rawContent.includes("reserve price") ||
    rawContent.includes("starting bid") ||
    rawContent.includes("minimum bid") ||
    rawContent.includes("please contact the registry") ||
    rawContent.includes("contact the registry to") ||
    rawContent.includes("contact the registry for") ||
    rawContent.includes("contact your registrar to") ||
    rawContent.includes("contact your registrar for") ||
    rawContent.includes("enquire about this domain") ||
    rawContent.includes("inquire about this domain") ||
    rawContent.includes("may be available for purchase") ||
    rawContent.includes("can be acquired") ||
    rawContent.includes("reach out to the registry");

  // ── PROHIBITED — mirrors common_parser.ts syntheticProhibited ────────────
  const rawHasProhibited =
    rawContent.includes("registration is prohibited") ||
    rawContent.includes("registration prohibited") ||
    rawContent.includes("cannot be registered") ||
    rawContent.includes("registration not possible") ||
    rawContent.includes("registration not available") ||
    rawContent.includes("not available for registration") ||
    rawContent.includes("not eligible for registration") ||
    rawContent.includes("not open for registration") ||
    rawContent.includes("not open for general registration") ||
    rawContent.includes("not open to general registrations") ||
    rawContent.includes("not currently open for registration") ||
    rawContent.includes("not available for public registration") ||
    rawContent.includes("not permitted to register") ||
    rawContent.includes("registration is not permitted") ||
    rawContent.includes("registrations are not permitted") ||
    rawContent.includes("registrations not permitted") ||
    rawContent.includes("not accepting registrations") ||
    rawContent.includes("registrations not accepted") ||
    rawContent.includes("no registrations are accepted") ||
    rawContent.includes("does not accept registrations") ||
    rawContent.includes("cannot be publicly registered") ||
    rawContent.includes("prohibited string") ||
    rawContent.includes("prohibited by policy") ||
    rawContent.includes("policy prohibited") ||
    rawContent.includes("not available for public use") ||
    rawContent.includes("registrar banned") ||
    rawContent.includes("registry banned") ||
    rawContent.includes("blacklisted") ||
    // Additional English patterns
    rawContent.includes("registration is blocked") ||
    rawContent.includes("domain is blocked") ||
    rawContent.includes("name is blocked") ||
    rawContent.includes("blackholed") ||
    rawContent.includes("registration disallowed") ||
    rawContent.includes("registration is disallowed") ||
    rawContent.includes("registrations are disallowed") ||
    rawContent.includes("registration has been blocked") ||
    rawContent.includes("domain name cannot be registered") ||
    rawContent.includes("name cannot be registered") ||
    rawContent.includes("does not allow registrations") ||
    rawContent.includes("registry does not allow") ||
    rawContent.includes("ineligible for registration") ||
    rawContent.includes("registration ineligible") ||
    rawContent.includes("this string is prohibited") ||
    rawContent.includes("this label is prohibited") ||
    rawContent.includes("this domain cannot be registered") ||
    rawContent.includes("cannot register this domain") ||
    rawContent.includes("registration of this name is not") ||
    rawContent.includes("not available at this time") ||
    rawContent.includes("agency forbidden") ||
    rawContent.includes("forbidden by") ||
    /\bstatus\s*:\s*prohibited\b/.test(rawContent) ||
    /\bstatus\s*:\s*forbidden\b/.test(rawContent) ||
    /\bstatus\s*:\s*blocked\-prohibited\b/.test(rawContent) ||
    // Simplified / Traditional Chinese
    rawContent.includes("禁止注册") ||
    rawContent.includes("不开放注册") ||
    rawContent.includes("不可注册") ||
    rawContent.includes("禁止使用") ||
    rawContent.includes("禁止域名") ||
    rawContent.includes("限制注册") ||
    rawContent.includes("禁止") && rawContent.includes("注册") ||
    // Russian / Ukrainian
    rawContent.includes("запрещена регистрация") ||
    rawContent.includes("регистрация запрещена") ||
    rawContent.includes("реєстрація заборонена") ||
    rawContent.includes("реєстрація не дозволена") ||
    rawContent.includes("регистрация недоступна") ||
    // German (.de / .at / .ch)
    rawContent.includes("registrierung nicht möglich") ||
    rawContent.includes("nicht registrierbar") ||
    rawContent.includes("gesperrte zeichenfolge") ||
    /\bstatus\s*:\s*verboten\b/.test(rawContent) ||
    // French
    rawContent.includes("enregistrement interdit") ||
    rawContent.includes("non disponible à l'enregistrement") ||
    // Spanish
    rawContent.includes("registro prohibido") ||
    rawContent.includes("no se puede registrar") ||
    rawContent.includes("no disponible para registro") ||
    // Italian
    /\bstatus\s*:\s*vietato\b/.test(rawContent) ||
    rawContent.includes("registrazione vietata") ||
    rawContent.includes("non registrabile") ||
    // Portuguese
    rawContent.includes("registro não permitido") ||
    rawContent.includes("domínio proibido") ||
    // Dutch
    rawContent.includes("registratie niet mogelijk") ||
    rawContent.includes("niet registreerbaar") ||
    // Polish
    rawContent.includes("rejestracja zabroniona") ||
    rawContent.includes("niedostępne do rejestracji") ||
    // Japanese
    rawContent.includes("登録不可") ||
    rawContent.includes("登録制限") ||
    rawContent.includes("利用不可") ||
    rawContent.includes("申請不可") ||
    // Korean
    rawContent.includes("등록불가") ||
    rawContent.includes("등록 금지") ||
    rawContent.includes("등록 불가능") ||
    // Arabic
    rawContent.includes("محظور") ||
    rawContent.includes("التسجيل محظور") ||
    rawContent.includes("غير متاح للتسجيل") ||
    // Hebrew
    rawContent.includes("אסור לרישום") ||
    rawContent.includes("חסום לרישום") ||
    // Turkish
    rawContent.includes("kayıt yasak") ||
    rawContent.includes("tescil edilemez") ||
    /\bblocked\s+by\s+(?:registry|registrar)\b/.test(rawContent) ||
    /\bregistration\s+blocked\b/.test(rawContent);

  // ── SUSPENDED / HOLD ─────────────────────────────────────────────────────
  const rawHasSuspended =
    rawContent.includes("suspended by registry") ||
    rawContent.includes("suspended by registrar") ||
    rawContent.includes("registry-suspended") ||
    rawContent.includes("domain is suspended") ||
    rawContent.includes("domain suspended") ||
    rawContent.includes("domain has been suspended") ||
    rawContent.includes("account suspended") ||
    rawContent.includes("abuse suspension") ||
    rawContent.includes("abuse hold") ||
    rawContent.includes("fraud hold") ||
    rawContent.includes("compliance hold") ||
    rawContent.includes("billing suspension") ||
    rawContent.includes("billing hold") ||
    rawContent.includes("payment hold") ||
    rawContent.includes("domain is on hold") ||
    rawContent.includes("domain on hold") ||
    rawContent.includes("placed on hold") ||
    rawContent.includes("put on hold") ||
    rawContent.includes("account on hold") ||
    rawContent.includes("account hold") ||
    rawContent.includes("registrar hold") ||
    rawContent.includes("agency hold") ||
    rawContent.includes("legal hold") ||
    rawContent.includes("judicial hold") ||
    rawContent.includes("government hold") ||
    rawContent.includes("seized by") ||
    rawContent.includes("domain seized") ||
    rawContent.includes("domain has been seized") ||
    rawContent.includes("confiscated by") ||
    rawContent.includes("domain confiscated") ||
    rawContent.includes("law enforcement hold") ||
    rawContent.includes("enforcement hold") ||
    rawContent.includes("frozen by") ||
    rawContent.includes("domain frozen") ||
    rawContent.includes("domain has been frozen") ||
    rawContent.includes("domain is frozen") ||
    rawContent.includes("suspended for") ||
    rawContent.includes("suspended due to") ||
    rawContent.includes("temporarily suspended") ||
    rawContent.includes("domain is temporarily") ||
    rawContent.includes("temporarily unavailable") ||
    rawContent.includes("domain is inactive") ||
    /\bstatus\s*:\s*(?:hold|on-hold|onhold|inactive)\b/.test(rawContent) ||
    // German (.de / .at / .ch)
    rawContent.includes("gesperrt") ||
    rawContent.includes("sperrung") ||
    rawContent.includes("domain gesperrt") ||
    rawContent.includes("beschlagnahmt") ||
    rawContent.includes("eingefroren") ||
    // Spanish (.es / .ar / .mx / ...)
    rawContent.includes("suspendido") ||
    rawContent.includes("dominio suspendido") ||
    rawContent.includes("en espera") ||
    rawContent.includes("confiscado") ||
    rawContent.includes("embargado") ||
    // French (.fr / .be / .ch / ...)
    rawContent.includes("suspendu") ||
    rawContent.includes("domaine suspendu") ||
    rawContent.includes("bloqué") ||
    rawContent.includes("saisi") ||
    rawContent.includes("gelé") ||
    // Portuguese (.pt / .br)
    rawContent.includes("suspenso") ||
    rawContent.includes("domínio suspenso") ||
    rawContent.includes("congelado") ||
    rawContent.includes("apreendido") ||
    // Italian (NIC.it .it)
    /\bstatus\s*:\s*sospeso\b/.test(rawContent) ||
    rawContent.includes("dominio sospeso") ||
    rawContent.includes("bloccato") ||
    rawContent.includes("sequestrato") ||
    // Dutch (.nl)
    rawContent.includes("opgeschort") ||
    rawContent.includes("domein opgeschort") ||
    rawContent.includes("bevroren") ||
    rawContent.includes("in beslag") ||
    // Polish (.pl)
    rawContent.includes("zawieszony") ||
    rawContent.includes("domena zawieszona") ||
    rawContent.includes("zablokowany") ||
    // Finnish (.fi)
    rawContent.includes("keskeytetty") ||
    rawContent.includes("jäädytetty") ||
    // Swedish (.se)
    rawContent.includes("spärrad") ||
    rawContent.includes("inaktiv") ||
    // Norwegian (.no)
    rawContent.includes("suspendert") ||
    // Danish (.dk)
    rawContent.includes("suspenderet") ||
    rawContent.includes("deaktiveret") ||
    // Romanian (.ro)
    rawContent.includes("suspendat") ||
    // Hungarian (.hu)
    rawContent.includes("felfüggesztett") ||
    // Turkish (.tr)
    rawContent.includes("askıya alındı") ||
    rawContent.includes("donduruldu") ||
    // Greek (.gr)
    rawContent.includes("ανεσταλμένο") ||
    rawContent.includes("αδρανές") ||
    // Russian (.ru / .рф)
    rawContent.includes("приостановлен") ||
    rawContent.includes("приостановлено") ||
    rawContent.includes("домен заблокирован") ||
    rawContent.includes("изъят") ||
    rawContent.includes("заморожен") ||
    // Ukrainian (.ua)
    rawContent.includes("призупинено") ||
    rawContent.includes("заморожено") ||
    // Japanese (.jp)
    rawContent.includes("停止中") ||
    rawContent.includes("利用停止") ||
    rawContent.includes("凍結") ||
    rawContent.includes("差し押さえ") ||
    // Korean (.kr)
    rawContent.includes("정지됨") ||
    rawContent.includes("사용 정지") ||
    rawContent.includes("동결") ||
    // Arabic
    rawContent.includes("موقوف") ||
    rawContent.includes("معلق") ||
    rawContent.includes("مجمد") ||
    rawContent.includes("مضبوط") ||
    // Hebrew
    rawContent.includes("מושעה") ||
    rawContent.includes("קפוא") ||
    // Chinese (Simplified)
    rawContent.includes("已暂停") ||
    rawContent.includes("域名暂停") ||
    rawContent.includes("已停用") ||
    rawContent.includes("暂停使用") ||
    rawContent.includes("已冻结") ||
    rawContent.includes("冻结域名") ||
    rawContent.includes("被扣押") ||
    rawContent.includes("被没收") ||
    /(?:^|\n)\s*suspended\s*(?:\n|$)/.test(rawContent);

  // ── DISPUTE ─────────────────────────────────────────────────────────────────
  const rawHasDispute =
    // UDRP (Uniform Domain-Name Dispute-Resolution Policy) — most common
    rawContent.includes("udrp") ||
    rawContent.includes("uniform domain-name dispute") ||
    rawContent.includes("udrp proceeding") ||
    rawContent.includes("udrp complaint") ||
    rawContent.includes("udrp-lock") ||
    rawContent.includes("udrp lock") ||
    rawContent.includes("locked-udrp") ||
    rawContent.includes("locked for udrp") ||
    rawContent.includes("locked during udrp") ||
    rawContent.includes("pending udrp") ||
    rawContent.includes("udrp transfer") ||
    rawContent.includes("udrp decision") ||
    // General dispute
    rawContent.includes("domain dispute") ||
    rawContent.includes("name dispute") ||
    rawContent.includes("in dispute") ||
    rawContent.includes("under dispute") ||
    rawContent.includes("dispute in progress") ||
    rawContent.includes("dispute pending") ||
    rawContent.includes("subject to dispute") ||
    rawContent.includes("currently disputed") ||
    rawContent.includes("domain conflict") ||
    // DRP / ADR variants (EU/ICANN alternative dispute resolution)
    rawContent.includes("adr proceeding") ||
    rawContent.includes("alternative dispute") ||
    rawContent.includes("domain resolution") ||
    rawContent.includes("drp proceeding") ||
    rawContent.includes("icann drp") ||
    // Trademark / legal dispute
    rawContent.includes("trademark dispute") ||
    rawContent.includes("trademark conflict") ||
    rawContent.includes("trademark complaint") ||
    rawContent.includes("trademark objection") ||
    rawContent.includes("legal dispute") ||
    rawContent.includes("legal proceedings") ||
    rawContent.includes("legal action") ||
    rawContent.includes("court order") ||
    rawContent.includes("court ordered") ||
    rawContent.includes("court proceeding") ||
    rawContent.includes("arbitration") ||
    rawContent.includes("pending arbitration") ||
    rawContent.includes("in arbitration") ||
    rawContent.includes("dispute resolution") ||
    rawContent.includes("locked for dispute") ||
    rawContent.includes("lock for dispute") ||
    rawContent.includes("locked pending") ||
    /\bstatus\s*:\s*(?:dispute|disputed|in-dispute)\b/.test(rawContent) ||
    // German (.de / .at)
    rawContent.includes("streitfall") ||
    rawContent.includes("rechtstreit") ||
    rawContent.includes("widerspruch") ||
    rawContent.includes("markenstreit") ||
    rawContent.includes("schiedsverfahren") ||
    // French (.fr)
    rawContent.includes("litige") ||
    rawContent.includes("en litige") ||
    rawContent.includes("différend") ||
    rawContent.includes("contentieux") ||
    rawContent.includes("arbitrage") ||
    // Spanish
    rawContent.includes("disputa") ||
    rawContent.includes("en disputa") ||
    rawContent.includes("conflicto de dominio") ||
    rawContent.includes("procedimiento arbitral") ||
    // Italian
    rawContent.includes("contesa") ||
    rawContent.includes("in contesa") ||
    rawContent.includes("disputa di dominio") ||
    rawContent.includes("procedimento arbitrale") ||
    // Portuguese
    rawContent.includes("disputa de domínio") ||
    rawContent.includes("arbitragem") ||
    // Dutch
    rawContent.includes("geschil") ||
    rawContent.includes("in geschil") ||
    rawContent.includes("arbitrage") ||
    // Polish
    rawContent.includes("spór domenowy") ||
    rawContent.includes("postępowanie arbitrażowe") ||
    // Russian
    rawContent.includes("спор") ||
    rawContent.includes("арбитраж") ||
    rawContent.includes("судебное") ||
    // Ukrainian
    rawContent.includes("спір") ||
    rawContent.includes("арбітраж") ||
    // Japanese
    rawContent.includes("係争中") ||
    rawContent.includes("異議申立") ||
    rawContent.includes("紛争") ||
    rawContent.includes("仲裁") ||
    // Korean
    rawContent.includes("분쟁 중") ||
    rawContent.includes("분쟁") ||
    rawContent.includes("중재") ||
    // Chinese (Simplified)
    rawContent.includes("争议中") ||
    rawContent.includes("域名争议") ||
    rawContent.includes("商标争议") ||
    rawContent.includes("仲裁中") ||
    rawContent.includes("法律纠纷") ||
    // Arabic
    rawContent.includes("نزاع") ||
    rawContent.includes("تحكيم") ||
    rawContent.includes("في نزاع") ||
    // Hebrew
    rawContent.includes("סכסוך") ||
    rawContent.includes("בוררות") ||
    // Turkish
    rawContent.includes("uyuşmazlık") ||
    rawContent.includes("ihtilaf") ||
    rawContent.includes("tahkim");

  // ── GUARD: A domain with registrar + creation + expiration date is definitively
  // registered. Reserved/prohibited domains have no registrar or dates.
  // Without this guard, WHOIS boilerplate text (e.g. RegistrarSafe privacy
  // notice containing "withheld") triggers false reserved/prohibited positives.
  const isDefinitelyRegistered =
    result.registrar && result.registrar !== "Unknown" &&
    result.creationDate && result.creationDate !== "Unknown" &&
    result.expirationDate && result.expirationDate !== "Unknown";

  const isProhibited =
    !isDefinitelyRegistered &&
    (prohibitCheckText.includes("prohibited") ||
    prohibitCheckText.includes("registrationprohibited") ||
    prohibitCheckText.includes("cannot be registered") ||
    prohibitCheckText.includes("not available for registration") ||
    prohibitCheckText.includes("not-available") ||
    prohibitCheckText.includes("ineligible") ||
    prohibitCheckText.includes("forbidden") ||
    prohibitCheckText.includes("registry-prohibited") ||
    prohibitCheckText.includes("registrybanned") ||
    rawHasProhibited);

  function makeStatus(
    type: RegistrationStatusType,
    color: string,
    dotColor: string,
    isPremiumReserved = false,
  ) {
    return { type, label: isZh ? STATUS_LABELS[type].zh : STATUS_LABELS[type].en, color, dotColor, isPremiumReserved };
  }

  if (isProhibited)
    return makeStatus("prohibited", "text-red-600 border-red-400/50 bg-red-50 dark:bg-red-950/20", "bg-red-500");

  // "reserved" should not be triggered by "registry-hold" (that is a hold, not a reserve)
  // Also guarded: an actively registered domain (has registrar + dates) cannot be reserved.
  const isReserved =
    !isDefinitelyRegistered &&
    (prohibitCheckText.includes("reserved") ||
    allStatusText.includes("reserved-delegated") ||
    allStatusText.includes("registryreserved") ||
    allStatusText.includes("registry-reserved") ||
    allStatusText.includes("registry-premium") ||
    rawHasReserved);

  // A "premium reserved" domain is held by the registry for sale — different
  // from an "official use" reserved domain.  Both display as "reserved" but
  // carry different descriptions in the info card.
  const isPremiumReserved =
    allStatusText.includes("registry-premium") ||
    rawHasPremiumReserved;

  if (isReserved)
    return makeStatus("reserved", "text-amber-600 border-amber-400/50 bg-amber-50 dark:bg-amber-950/20", "bg-amber-500", isPremiumReserved);

  const isRedemption =
    allStatusText.includes("redemptionperiod") ||
    allStatusText.includes("redemption period") ||
    allStatusText.includes("redemption-period");

  if (isRedemption)
    return makeStatus("redemption", "text-purple-600 border-purple-400/50 bg-purple-50 dark:bg-purple-950/20", "bg-purple-500");

  const isPendingDelete =
    allStatusText.includes("pendingdelete") ||
    allStatusText.includes("pending delete") ||
    allStatusText.includes("pending-delete");

  if (isPendingDelete)
    return makeStatus("pending-delete", "text-slate-600 border-slate-400/50 bg-slate-50 dark:bg-slate-950/20", "bg-slate-500");

  // ── DISPUTE — check before hold (more specific; UDRP domains often have serverHold too)
  const isDispute =
    allStatusText.includes("dispute") ||
    allStatusText.includes("udrp") ||
    allStatusText.includes("locked-udrp") ||
    allStatusText.includes("adr") ||
    rawHasDispute;

  if (isDispute)
    return makeStatus("dispute", "text-rose-600 border-rose-400/50 bg-rose-50 dark:bg-rose-950/20", "bg-rose-500");

  // ── HOLD / SUSPENDED — Match EPP codes ("serverhold") and hyphenated / spaced variants
  const hasServerHold =
    allStatusText.includes("serverhold") ||
    allStatusText.includes("server-hold") ||
    allStatusText.includes("server hold") ||
    allStatusText.includes("registry-hold") ||
    allStatusText.includes("registryhold");

  const hasClientHold =
    allStatusText.includes("clienthold") ||
    allStatusText.includes("client-hold") ||
    allStatusText.includes("client hold");

  const hasOk =
    allStatusText.includes(" ok ") ||
    allStatusText === "ok" ||
    allStatusText.includes("active");

  const hasSuspended =
    allStatusText.includes("suspended") ||
    allStatusText.includes("hold") ||
    allStatusText.includes("frozen") ||
    allStatusText.includes("inactive") ||
    rawHasSuspended;

  const isHold = (hasServerHold || hasClientHold || hasSuspended) && !hasOk;

  if (isHold)
    return makeStatus("hold", "text-orange-600 border-orange-400/50 bg-orange-50 dark:bg-orange-950/20", "bg-orange-500");

  return {
    type: "registered" as RegistrationStatusType,
    label: isZh ? STATUS_LABELS.registered.zh : STATUS_LABELS.registered.en,
    color: "text-emerald-600 border-emerald-400/50 bg-emerald-50 dark:bg-emerald-950/20",
    dotColor: "bg-emerald-500",
    isPremiumReserved: false,
  };
}

const STATUS_INFO: Record<
  RegistrationStatusType,
  {
    icon: React.ReactNode;
    titleZh: string;
    titleEn: string;
    descZh: string;
    descEn: string;
    border: string;
    bg: string;
    iconBg: string;
    iconText: string;
    titleText: string;
    descText: string;
  }
> = {
  prohibited: {
    icon: <RiForbidLine className="w-5 h-5" />,
    titleZh: "禁止注册域名",
    titleEn: "Prohibited Domain",
    descZh: "该域名被注册局标记为禁止注册字符串，无法通过任何常规渠道注册。通常为政策性保护词汇或敏感字符串。",
    descEn: "This domain is marked as a prohibited string by the registry and cannot be registered through any conventional channel.",
    border: "border-red-300/60 dark:border-red-800/50",
    bg: "bg-gradient-to-r from-red-50/80 to-red-50/30 dark:from-red-950/30 dark:to-transparent",
    iconBg: "bg-red-100 dark:bg-red-900/40",
    iconText: "text-red-600 dark:text-red-400",
    titleText: "text-red-800 dark:text-red-300",
    descText: "text-red-700/80 dark:text-red-400/70",
  },
  reserved: {
    icon: <RiLockLine className="w-5 h-5" />,
    titleZh: "保留域名",
    titleEn: "Reserved Domain",
    descZh: "该域名为注册局保留域名，由官方机构专用或预留，暂不向公众开放注册。",
    descEn: "This domain is reserved by the registry for official use and is not available for public registration.",
    border: "border-amber-300/60 dark:border-amber-800/50",
    bg: "bg-gradient-to-r from-amber-50/80 to-amber-50/30 dark:from-amber-950/30 dark:to-transparent",
    iconBg: "bg-amber-100 dark:bg-amber-900/40",
    iconText: "text-amber-600 dark:text-amber-400",
    titleText: "text-amber-800 dark:text-amber-300",
    descText: "text-amber-700/80 dark:text-amber-400/70",
  },
  hold: {
    icon: <RiPauseCircleLine className="w-5 h-5" />,
    titleZh: "域名暂停",
    titleEn: "Domain On Hold",
    descZh: "该域名当前处于暂停状态（Server Hold / Client Hold），可能由于违规行为、未付款或争议被暂时锁定，无法正常解析。",
    descEn: "This domain is currently on hold (Server Hold / Client Hold) and cannot resolve normally. This is usually due to a policy violation, non-payment, or dispute.",
    border: "border-orange-300/60 dark:border-orange-800/50",
    bg: "bg-gradient-to-r from-orange-50/80 to-orange-50/30 dark:from-orange-950/30 dark:to-transparent",
    iconBg: "bg-orange-100 dark:bg-orange-900/40",
    iconText: "text-orange-600 dark:text-orange-400",
    titleText: "text-orange-800 dark:text-orange-300",
    descText: "text-orange-700/80 dark:text-orange-400/70",
  },
  dispute: {
    icon: <RiScalesLine className="w-5 h-5" />,
    titleZh: "域名争议",
    titleEn: "Domain Dispute",
    descZh: "该域名正处于 UDRP 争议程序或其他争议处理中，当前处于锁定状态，等待仲裁结果。",
    descEn: "This domain is currently undergoing a UDRP dispute or other legal proceedings and is locked pending arbitration.",
    border: "border-rose-300/60 dark:border-rose-800/50",
    bg: "bg-gradient-to-r from-rose-50/80 to-rose-50/30 dark:from-rose-950/30 dark:to-transparent",
    iconBg: "bg-rose-100 dark:bg-rose-900/40",
    iconText: "text-rose-600 dark:text-rose-400",
    titleText: "text-rose-800 dark:text-rose-300",
    descText: "text-rose-700/80 dark:text-rose-400/70",
  },
  redemption: {
    icon: <RiLoopLeftLine className="w-5 h-5" />,
    titleZh: "赎回期",
    titleEn: "Redemption Period",
    descZh: "该域名已过期并进入赎回期，原注册人可在此期间支付额外费用赎回，赎回期结束后将被公开删除。",
    descEn: "This domain has expired and entered the redemption period. The original registrant can reclaim it for an extra fee before it is deleted.",
    border: "border-purple-300/60 dark:border-purple-800/50",
    bg: "bg-gradient-to-r from-purple-50/80 to-purple-50/30 dark:from-purple-950/30 dark:to-transparent",
    iconBg: "bg-purple-100 dark:bg-purple-900/40",
    iconText: "text-purple-600 dark:text-purple-400",
    titleText: "text-purple-800 dark:text-purple-300",
    descText: "text-purple-700/80 dark:text-purple-400/70",
  },
  "pending-delete": {
    icon: <RiDeleteBin2Line className="w-5 h-5" />,
    titleZh: "待删除",
    titleEn: "Pending Delete",
    descZh: "该域名即将从注册系统中删除，删除后将重新开放注册。删除通常在 5 天内完成。",
    descEn: "This domain is about to be deleted from the registry and will soon become available for registration again.",
    border: "border-slate-300/60 dark:border-slate-700/50",
    bg: "bg-gradient-to-r from-slate-50/80 to-slate-50/30 dark:from-slate-950/30 dark:to-transparent",
    iconBg: "bg-slate-100 dark:bg-slate-800/60",
    iconText: "text-slate-600 dark:text-slate-400",
    titleText: "text-slate-700 dark:text-slate-300",
    descText: "text-slate-600/80 dark:text-slate-400/70",
  },
  available: {
    icon: <RiCheckLine className="w-5 h-5" />,
    titleZh: "域名可注册",
    titleEn: "Domain Available",
    descZh: "该域名当前未被注册，您可以立即前往域名注册商注册此域名。",
    descEn: "This domain is currently unregistered and available for purchase.",
    border: "border-emerald-300/60 dark:border-emerald-800/50",
    bg: "bg-gradient-to-r from-emerald-50/80 to-emerald-50/30 dark:from-emerald-950/30 dark:to-transparent",
    iconBg: "bg-emerald-100 dark:bg-emerald-900/40",
    iconText: "text-emerald-600 dark:text-emerald-400",
    titleText: "text-emerald-800 dark:text-emerald-300",
    descText: "text-emerald-700/80 dark:text-emerald-400/70",
  },
  registered: {
    icon: null,
    titleZh: "",
    titleEn: "",
    descZh: "",
    descEn: "",
    border: "",
    bg: "",
    iconBg: "",
    iconText: "",
    titleText: "",
    descText: "",
  },
};

function DomainStatusInfoCard({
  type,
  locale,
  customDesc,
}: {
  type: RegistrationStatusType;
  locale: string;
  customDesc?: { zh: string; en: string };
}) {
  if (type === "registered") return null;
  const info = STATUS_INFO[type];
  const isZh = locale.startsWith("zh");
  const desc = customDesc
    ? (isZh ? customDesc.zh : customDesc.en)
    : (isZh ? info.descZh : info.descEn);
  return (
    <div
      className={cn(
        "rounded-xl border p-4 mt-5",
        "flex items-start gap-3.5",
        info.border,
        info.bg,
      )}
    >
      <div
        className={cn(
          "w-9 h-9 rounded-xl flex items-center justify-center shrink-0",
          info.iconBg,
          info.iconText,
        )}
      >
        {info.icon}
      </div>
      <div className="min-w-0">
        <p className={cn("text-sm font-semibold leading-tight", info.titleText)}>
          {isZh ? info.titleZh : info.titleEn}
        </p>
        <p className={cn("text-xs mt-1 leading-relaxed", info.descText)}>
          {desc}
        </p>
      </div>
    </div>
  );
}


const ALL_REMINDER_THRESHOLDS = [60, 30, 10, 5, 1];
const DEFAULT_REMINDER_THRESHOLDS = [60, 30, 1];

function DomainReminderDialog({
  domain,
  expirationDate,
  remainingDays,
  open,
  onOpenChange,
  isZh,
  userEmail,
  registerPriceFmt,
  renewPriceFmt,
  isPremium,
  eppStatuses,
  regStatusType,
}: {
  domain: string;
  expirationDate: string | null | undefined;
  remainingDays: number | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  isZh: boolean;
  userEmail?: string;
  registerPriceFmt?: string;
  renewPriceFmt?: string;
  isPremium?: boolean;
  eppStatuses?: string[];
  regStatusType?: RegistrationStatusType;
}) {
  const hasExpiry = !!(expirationDate && expirationDate !== "Unknown");
  const [email, setEmail] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);
  const [selectedThresholds, setSelectedThresholds] = React.useState<number[]>(DEFAULT_REMINDER_THRESHOLDS);

  const [lcFeedbackOpen, setLcFeedbackOpen] = React.useState(false);
  const [lcForm, setLcForm] = React.useState({ grace: "0", redemption: "0", pendingDelete: "0", sourceUrl: "", notes: "", email: "" });
  const [lcSubmitting, setLcSubmitting] = React.useState(false);
  const [lcDone, setLcDone] = React.useState(false);

  function toggleThreshold(d: number) {
    setSelectedThresholds(prev =>
      prev.includes(d) ? prev.filter(x => x !== d) : [...prev, d]
    );
  }

  React.useEffect(() => {
    if (open) { setEmail(userEmail || ""); setDone(false); setSelectedThresholds(DEFAULT_REMINDER_THRESHOLDS); }
  }, [open, userEmail]);

  const isRestricted = regStatusType === "prohibited" || regStatusType === "reserved";

  async function handleSubmit() {
    if (!email || !email.includes("@")) {
      toast.error(isZh ? "请输入有效邮箱" : "Please enter a valid email");
      return;
    }
    if (!isRestricted && selectedThresholds.length === 0) {
      toast.error(isZh ? "请至少选择一个到期前提醒时间" : "Please select at least one pre-expiry reminder");
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/remind/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain, email, expirationDate, phaseAlerts,
          thresholds: isRestricted ? [] : selectedThresholds,
          regStatusType,
        }),
      });
      if (res.ok) {
        setDone(true);
      } else {
        toast.error(isZh ? "提交失败，请重试" : "Submission failed");
      }
    } catch {
      toast.error(isZh ? "网络错误" : "Network error");
    } finally {
      setSubmitting(false);
    }
  }

  const lc = React.useMemo(
    () => computeLifecycle(domain, expirationDate ?? null, eppStatuses),
    [domain, expirationDate, eppStatuses]
  );
  const tldUpper = domain.split(".").pop()?.toUpperCase() ?? "";
  const hasPricing = !!(registerPriceFmt || renewPriceFmt);

  // Lifecycle feedback – placed after `lc` to avoid TDZ
  React.useEffect(() => {
    if (lcFeedbackOpen && lc) {
      setLcForm({
        grace: String(lc.cfg.grace),
        redemption: String(lc.cfg.redemption),
        pendingDelete: String(lc.cfg.pendingDelete),
        sourceUrl: "",
        notes: "",
        email: userEmail || "",
      });
      setLcDone(false);
    }
  }, [lcFeedbackOpen, lc, userEmail]);

  async function handleLcFeedbackSubmit() {
    const sg = parseInt(lcForm.grace, 10);
    const sr = parseInt(lcForm.redemption, 10);
    const sp = parseInt(lcForm.pendingDelete, 10);
    if (isNaN(sg) || isNaN(sr) || isNaN(sp) || sg < 0 || sr < 0 || sp < 0) {
      toast.error(isZh ? "天数必须为非负整数" : "Days must be a non-negative integer");
      return;
    }
    if (lcForm.email && !lcForm.email.includes("@")) {
      toast.error(isZh ? "请输入有效邮箱" : "Please enter a valid email");
      return;
    }
    setLcSubmitting(true);
    try {
      const tld = domain.split(".").pop()?.toLowerCase() ?? "";
      const res = await fetch("/api/user/tld-lifecycle-feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tld,
          current_grace: lc?.cfg.grace ?? null,
          current_redemption: lc?.cfg.redemption ?? null,
          current_pending_delete: lc?.cfg.pendingDelete ?? null,
          suggested_grace: sg,
          suggested_redemption: sr,
          suggested_pending_delete: sp,
          source_url: lcForm.sourceUrl || null,
          notes: lcForm.notes || null,
          submitter_email: lcForm.email || null,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "提交失败");
      }
      setLcDone(true);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : (isZh ? "提交失败" : "Submission failed"));
    } finally {
      setLcSubmitting(false);
    }
  }

  const PHASE_UI = {
    active:        { label: isZh ? "正常有效" : "Active",        colorClass: "text-emerald-600 dark:text-emerald-400", bgClass: "bg-emerald-50/70 dark:bg-emerald-950/25", borderClass: "border-emerald-200/60 dark:border-emerald-800/40", dotClass: "bg-emerald-500" },
    grace:         { label: isZh ? "宽限期"   : "Grace Period",  colorClass: "text-amber-600 dark:text-amber-400",    bgClass: "bg-amber-50/70 dark:bg-amber-950/25",    borderClass: "border-amber-200/60 dark:border-amber-800/40",    dotClass: "bg-amber-500" },
    redemption:    { label: isZh ? "赎回期"   : "Redemption",    colorClass: "text-orange-600 dark:text-orange-400",  bgClass: "bg-orange-50/70 dark:bg-orange-950/25",  borderClass: "border-orange-200/60 dark:border-orange-800/40",  dotClass: "bg-orange-500" },
    pendingDelete: { label: isZh ? "待删除"   : "Pending Delete", colorClass: "text-red-600 dark:text-red-400",        bgClass: "bg-red-50/70 dark:bg-red-950/25",        borderClass: "border-red-200/60 dark:border-red-800/40",        dotClass: "bg-red-500" },
    dropped:       { label: isZh ? "已释放"   : "Available",     colorClass: "text-emerald-600 dark:text-emerald-400",        bgClass: "bg-emerald-50/70 dark:bg-emerald-950/25",        borderClass: "border-emerald-200/60 dark:border-emerald-800/40",        dotClass: "bg-emerald-400" },
  };

  const PHASE_ADVICE: Record<string, { zh: string; en: string }> = {
    active:        { zh: "域名状态正常，我们将在到期前自动发送提醒邮件。", en: "Domain is active. We'll alert you before expiry." },
    grace:         { zh: "域名已过期，仍处于宽限期内，可按正常价格续费，请尽快操作！", en: "Expired but renewable at normal price during grace — act now!" },
    redemption:    { zh: "已进入赎回期，续费费用大幅增加，请立即联系注册商赎回。", en: "In redemption. Recovery fees are much higher — contact your registrar." },
    pendingDelete: { zh: "即将被注册局删除，通常无法再续期，请提前做好准备。", en: "Pending deletion. Usually cannot be renewed anymore." },
    dropped:       { zh: "域名已被删除，即将或已可重新注册。", en: "Domain has been deleted and may be available for re-registration." },
  };

  const urgencyNum =
    remainingDays === null ? "text-muted-foreground" :
    remainingDays <= 0  ? "text-red-500 dark:text-red-400" :
    remainingDays <= 30 ? "text-orange-500 dark:text-orange-400" :
    remainingDays <= 90 ? "text-amber-500 dark:text-amber-400" :
    "text-emerald-500 dark:text-emerald-400";

  const phaseUI = lc ? PHASE_UI[lc.phase] : null;

  type PhaseAlerts = { grace: boolean; redemption: boolean; pendingDelete: boolean; dropSoon: boolean; dropped: boolean };
  const [phaseAlerts, setPhaseAlerts] = React.useState<PhaseAlerts>({
    grace: true, redemption: true, pendingDelete: true, dropSoon: true, dropped: true,
  });
  function togglePhase(key: keyof PhaseAlerts) {
    setPhaseAlerts((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  type PhaseChip = {
    key: keyof PhaseAlerts;
    label: string;
    icon: React.ReactNode;
    activeCls: string;
    inactiveCls: string;
    always?: boolean;
  };
  const phaseChips: PhaseChip[] = lc ? [
    lc.cfg.grace > 0         && { key: "grace"       as const, label: isZh ? "进入宽限期"   : "Grace Period",    icon: <RiTimeLine className="w-2.5 h-2.5" />,            activeCls: "bg-amber-500/18 border-amber-400/60 text-amber-700 dark:text-amber-300",   inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    lc.cfg.redemption > 0    && { key: "redemption"  as const, label: isZh ? "进入赎回期"   : "Redemption",      icon: <RiExchangeDollarFill className="w-2.5 h-2.5" />,  activeCls: "bg-orange-500/18 border-orange-400/60 text-orange-700 dark:text-orange-300", inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    lc.cfg.pendingDelete > 0 && { key: "pendingDelete" as const, label: isZh ? "进入待删除期" : "Pending Delete",  icon: <RiDeleteBin2Line className="w-2.5 h-2.5" />,     activeCls: "bg-red-500/18 border-red-400/60 text-red-700 dark:text-red-300",          inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    (lc.cfg.pendingDelete > 0 || lc.cfg.redemption > 0 || lc.cfg.grace > 0) && { key: "dropSoon" as const, always: true, label: isZh ? "即将可注册" : "Drop Soon",       icon: <RiAlertLine className="w-2.5 h-2.5" />,           activeCls: "bg-foreground/10 border-foreground/25 text-foreground",                   inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    (lc.cfg.pendingDelete > 0 || lc.cfg.redemption > 0 || lc.cfg.grace > 0) && { key: "dropped"  as const, always: true, label: isZh ? "域名可注册"  : "Available",      icon: <RiShoppingCartLine className="w-2.5 h-2.5" />,    activeCls: "bg-emerald-500/18 border-emerald-400/60 text-emerald-700 dark:text-emerald-300", inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
  ].filter(Boolean) as PhaseChip[] : [];

  return (<>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[420px] p-0 overflow-hidden gap-0">

        {/* ── Header ── */}
        <div className="px-5 pt-5 pb-4 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-muted border border-border/60 flex items-center justify-center shrink-0">
              <RiTimerLine className="w-[18px] h-[18px] text-foreground/70" />
            </div>
            <h2 className="text-sm font-bold text-foreground leading-none">
              {isZh ? "域名监控订阅" : "Domain Monitoring"}
            </h2>
          </div>
        </div>

        {/* ── Body ── */}
        <div className="px-5 pb-5 overflow-y-auto max-h-[72dvh]">

          {/* ── Domain name card — centered, above pricing ── */}
          <div className="flex flex-col items-center justify-center pt-4 pb-1 gap-1">
            <div className="px-4 py-2.5 rounded-xl border border-border/60 bg-muted/30 text-center min-w-0 max-w-full">
              <p className="text-[15px] font-mono font-bold text-foreground truncate tracking-tight">{domain}</p>
              {lc?.cfg.registry && (
                <p className="text-[10px] text-muted-foreground/55 mt-0.5 truncate">{lc.cfg.registry}</p>
              )}
            </div>
          </div>

          <AnimatePresence mode="wait" initial={false}>

            {/* ── Success ── */}
            {done ? (
              <motion.div
                key="done"
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.96 }}
                transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
                className="py-7 text-center space-y-4"
              >
                <div className="relative w-16 h-16 mx-auto">
                  <div className="absolute inset-0 rounded-full bg-emerald-500/15 animate-ping" style={{ animationDuration: "1.6s" }} />
                  <div className="relative w-16 h-16 bg-emerald-500/10 border-2 border-emerald-400/30 rounded-full flex items-center justify-center">
                    <RiCheckLine className="w-7 h-7 text-emerald-500" />
                  </div>
                </div>
                <div>
                  <p className="font-bold text-[15px] text-foreground">{isZh ? "订阅成功！" : "Subscribed!"}</p>
                  <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                    {isZh ? "将向" : "We'll notify"}{" "}
                    <strong className="text-foreground font-mono text-[11px]">{email}</strong>{" "}
                    {isZh ? "发送以下提醒" : "with the alerts below"}
                  </p>
                </div>
                <div className="text-left rounded-xl border border-border/60 bg-muted/15 p-3 space-y-2.5">
                  <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                    {isZh ? "已订阅的提醒类型" : "Subscribed alerts"}
                  </p>
                  {isRestricted ? (
                    <div className="flex items-center gap-1.5">
                      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-foreground/8 border border-foreground/20 text-foreground/80 text-[10px] font-semibold">
                        <RiCheckboxCircleLine className="w-2.5 h-2.5" />
                        {isZh ? "域名状态变化通知" : "Status change alert"}
                      </span>
                    </div>
                  ) : (
                    <>
                      <div>
                        <p className="text-[10px] text-foreground/60 font-semibold mb-1.5">{isZh ? "到期前提醒" : "Pre-expiry"}</p>
                        <div className="flex flex-wrap gap-1">
                          {[...selectedThresholds].sort((a, b) => b - a).map((d) => (
                            <span key={d} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-foreground/8 border border-foreground/20 text-foreground/80 text-[10px] font-semibold">
                              <RiTimerLine className="w-2.5 h-2.5" />{isZh ? `提前${d}天` : `${d}d`}
                            </span>
                          ))}
                        </div>
                      </div>
                      {phaseChips.filter((c) => phaseAlerts[c.key]).length > 0 && (
                        <div>
                          <p className="text-[10px] text-foreground/60 font-semibold mb-1.5">{isZh ? "阶段提醒" : "Phase alerts"}</p>
                          <div className="flex flex-wrap gap-1">
                            {phaseChips.filter((c) => phaseAlerts[c.key]).map((chip) => (
                              <span key={chip.key} className={cn("inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md border text-[10px] font-semibold", chip.activeCls)}>
                                <RiCheckboxCircleLine className="w-2.5 h-2.5" />{chip.label}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
                <p className="text-[10px] text-muted-foreground/55">{isZh ? "确认邮件已发送，请查收" : "Check your inbox for confirmation"}</p>
                <button
                  type="button"
                  onClick={() => setDone(false)}
                  className="text-xs text-muted-foreground/70 hover:text-foreground transition-colors underline-offset-2 hover:underline"
                >
                  {isZh ? "← 返回修改信息" : "← Edit subscription"}
                </button>
              </motion.div>

            ) : (
              /* ── Form ── */
              <motion.div
                key="form"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="space-y-3 pt-2"
              >
                {/* ── Prohibited / Reserved warning banner ─────────────── */}
                {(regStatusType === "prohibited" || regStatusType === "reserved") && (
                  <div className={cn(
                    "flex items-start gap-2.5 rounded-xl border px-3.5 py-3",
                    regStatusType === "prohibited"
                      ? "bg-red-50/60 dark:bg-red-950/20 border-red-300/50 dark:border-red-700/40"
                      : "bg-amber-50/60 dark:bg-amber-950/20 border-amber-300/50 dark:border-amber-700/40"
                  )}>
                    <RiInformationLine className={cn(
                      "w-4 h-4 mt-0.5 shrink-0",
                      regStatusType === "prohibited" ? "text-red-500" : "text-amber-500"
                    )} />
                    <div className="min-w-0">
                      <p className={cn(
                        "text-xs font-bold leading-snug",
                        regStatusType === "prohibited" ? "text-red-600 dark:text-red-400" : "text-amber-600 dark:text-amber-400"
                      )}>
                        {regStatusType === "prohibited"
                          ? (isZh ? "该域名被禁止注册" : "Registration Prohibited")
                          : (isZh ? "该域名为保留域名" : "Reserved Domain")}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {regStatusType === "prohibited"
                          ? (isZh
                              ? "该域名被注册局标记为禁止注册字符串，通常无法通过常规渠道注册。仍可订阅，当域名状态变化时会发送通知。"
                              : "This domain is marked as prohibited by the registry and cannot be registered through normal channels. You can still subscribe to receive status change notifications.")
                          : (isZh
                              ? "该域名目前为保留状态，不对公众开放注册。仍可订阅，如状态发生变化或域名开放注册时会收到通知。"
                              : "This domain is currently reserved and not available for public registration. You can still subscribe to receive notifications if the status changes.")}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Hold warning banner ───────────────────────────────── */}
                {regStatusType === "hold" && (
                  <div className="flex items-start gap-2.5 rounded-xl border px-3.5 py-3 bg-orange-50/60 dark:bg-orange-950/20 border-orange-300/50 dark:border-orange-700/40">
                    <RiInformationLine className="w-4 h-4 mt-0.5 shrink-0 text-orange-500" />
                    <div className="min-w-0">
                      <p className="text-xs font-bold leading-snug text-orange-600 dark:text-orange-400">
                        {isZh ? "该域名当前处于暂停状态" : "Domain On Hold"}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {isZh
                          ? "该域名已被注册局或注册商暂停（如违规、欠款或政府扣押），目前无法正常解析。仍可订阅到期提醒，以便跟踪续费或状态变化。"
                          : "This domain has been suspended by the registry or registrar (e.g. policy violation, non-payment, or seizure) and cannot currently resolve. You can still subscribe for expiry and status alerts."}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Dispute warning banner ────────────────────────────── */}
                {regStatusType === "dispute" && (
                  <div className="flex items-start gap-2.5 rounded-xl border px-3.5 py-3 bg-rose-50/60 dark:bg-rose-950/20 border-rose-300/50 dark:border-rose-700/40">
                    <RiInformationLine className="w-4 h-4 mt-0.5 shrink-0 text-rose-500" />
                    <div className="min-w-0">
                      <p className="text-xs font-bold leading-snug text-rose-600 dark:text-rose-400">
                        {isZh ? "该域名正处于争议程序中" : "Domain In Dispute"}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {isZh
                          ? "该域名正处于 UDRP 或其他争议解决程序中，当前被锁定，等待仲裁结果。仍可订阅到期提醒，以便及时获知域名状态变化。"
                          : "This domain is currently locked in a UDRP or other dispute resolution proceeding. You can still subscribe for expiry and status alerts to stay informed of any outcome."}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Pricing + premium row ────────────────────────────── */}
                {hasPricing && (
                  <div className="grid grid-cols-3 gap-1.5 rounded-xl border border-border/50 bg-muted/15 overflow-hidden">
                    {/* Register price */}
                    <div className="flex flex-col items-center justify-center px-2 py-2.5 gap-0.5">
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "注册" : "Register"}
                      </p>
                      <p className={cn("text-[13px] font-black tabular-nums leading-none", isPremium ? "text-amber-500" : "text-foreground")}>
                        {registerPriceFmt ?? "—"}
                      </p>
                    </div>
                    {/* Renew price */}
                    <div className="flex flex-col items-center justify-center px-2 py-2.5 gap-0.5 border-x border-border/40">
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "续费" : "Renew"}
                      </p>
                      <p className={cn("text-[13px] font-black tabular-nums leading-none", isPremium ? "text-amber-500" : "text-foreground")}>
                        {renewPriceFmt ?? "—"}
                      </p>
                    </div>
                    {/* Premium badge */}
                    <div className={cn(
                      "flex flex-col items-center justify-center px-2 py-2.5 gap-0.5",
                      isPremium ? "bg-amber-500/8 dark:bg-amber-500/12" : ""
                    )}>
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "溢价" : "Premium"}
                      </p>
                      <p className={cn(
                        "text-[12px] font-black leading-none",
                        isPremium
                          ? "text-amber-500"
                          : "text-emerald-600 dark:text-emerald-400"
                      )}>
                        {isPremium
                          ? (isZh ? "是" : "Yes")
                          : (isZh ? "否" : "No")}
                      </p>
                    </div>
                  </div>
                )}

                {/* Lifecycle card — phase dot + expiry countdown + drop date multi-tz */}
                {hasExpiry && lc && phaseUI ? (
                  <div className={cn("rounded-xl border overflow-hidden", phaseUI.borderClass)}>
                    {/* Expiry + countdown row */}
                    <div className={cn("flex items-center justify-between px-3.5 py-3", phaseUI.bgClass)}>
                      <div className="min-w-0">
                        <p className="text-[9px] text-muted-foreground/70 uppercase tracking-wider font-bold mb-1">
                          {isZh ? "到期日期" : "Expiry date"}
                        </p>
                        <p className="text-[13px] font-mono font-bold text-foreground leading-none">{fmtDate(lc.expiry)}</p>
                        <p className="text-[10px] font-mono text-muted-foreground/60 mt-0.5 tabular-nums">
                          {`${String(lc.expiry.getUTCHours()).padStart(2,"0")}:${String(lc.expiry.getUTCMinutes()).padStart(2,"0")}:${String(lc.expiry.getUTCSeconds()).padStart(2,"0")} UTC`}
                        </p>
                      </div>
                      <div className="text-right shrink-0 pl-2">
                        {remainingDays !== null && remainingDays >= 0 && remainingDays <= 7 ? (
                          <>
                            <p className={cn("text-[20px] font-black tabular-nums leading-none", urgencyNum)}>
                              {fmtCountdown(lc.expiry, isZh)}
                            </p>
                            <p className="text-[10px] text-muted-foreground mt-0.5">{isZh ? "后到期" : "remaining"}</p>
                          </>
                        ) : (
                          <>
                            <p className={cn("text-[30px] font-black tabular-nums leading-none", urgencyNum)}>
                              {remainingDays !== null ? Math.max(0, remainingDays) : "—"}
                            </p>
                            <p className="text-[10px] text-muted-foreground mt-0.5">{isZh ? "天后到期" : "days left"}</p>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Current phase — animated dot + label + advice */}
                    <div className="px-3.5 py-3 bg-background/60 border-t border-border/25">
                      <div className="flex items-center gap-2">
                        <span className="relative flex h-2 w-2 shrink-0">
                          {lc.phase !== "active" && (
                            <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-60", phaseUI.dotClass)} />
                          )}
                          <span className={cn("relative inline-flex rounded-full h-2 w-2", phaseUI.dotClass)} />
                        </span>
                        <span className={cn("text-[11px] font-bold tracking-wide", phaseUI.colorClass)}>
                          {phaseUI.label}
                        </span>
                        {lc.phaseSource === "epp" && (
                          <span className="ml-auto inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-400/20 text-[9px] font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wide">
                            <RiShieldCheckLine className="w-2 h-2" />EPP
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-muted-foreground leading-relaxed mt-1.5">
                        {isZh ? PHASE_ADVICE[lc.phase]?.zh : PHASE_ADVICE[lc.phase]?.en}
                      </p>
                    </div>

                    {/* Drop/available date with multi-timezone breakdown */}
                    {(lc.cfg.pendingDelete > 0 || lc.cfg.grace > 0 || lc.cfg.redemption > 0) && (() => {
                      const dropIsPast = new Date() > lc.dropDate;
                      const daysToDropDate = Math.ceil((lc.dropDate.getTime() - Date.now()) / 86_400_000);

                      // Build timezone rows — always UTC, + locale-specific cities
                      type TzRow = { label: string; tz: string };
                      const tzRows: TzRow[] = [{ label: "UTC", tz: "UTC" }];
                      if (isZh) {
                        tzRows.push({ label: isZh ? "北京时间" : "Beijing", tz: "Asia/Shanghai" });
                      } else {
                        tzRows.push({ label: "New York", tz: "America/New_York" });
                        tzRows.push({ label: "London",   tz: "Europe/London"   });
                      }
                      // Always add browser local timezone if it differs from the above
                      try {
                        const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                        if (!tzRows.some(r => r.tz === localTz)) {
                          tzRows.push({ label: isZh ? "本地时间" : "Local", tz: localTz });
                        }
                      } catch { /* ignore */ }

                      const fmtInTz = (d: Date, tz: string) => {
                        try {
                          return new Intl.DateTimeFormat(isZh ? "zh-CN" : "en-US", {
                            timeZone: tz,
                            year: "numeric", month: "2-digit", day: "2-digit",
                            hour: "2-digit", minute: "2-digit", second: "2-digit",
                            hour12: false,
                          }).format(d).replace(/\//g, "/");
                        } catch { return "—"; }
                      };

                      return (
                        <div className={cn(
                          "border-t px-3.5 py-3",
                          dropIsPast ? "border-emerald-300/40 bg-emerald-50/40 dark:bg-emerald-950/15" : "border-border/25 bg-muted/20"
                        )}>
                          {/* Header row */}
                          <div className="flex items-center gap-2 mb-2.5">
                            <RiShoppingCartLine className={cn("w-3.5 h-3.5 shrink-0", dropIsPast ? "text-emerald-500" : "text-foreground/50")} />
                            <span className={cn("text-[11px] font-bold", dropIsPast ? "text-emerald-600 dark:text-emerald-400" : "text-foreground/70")}>
                              {isZh ? "预计可注册" : "Est. available"}
                            </span>
                            {dropIsPast ? (
                              <span className="ml-auto inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-400/30 uppercase tracking-wide">
                                {isZh ? "现在可注册" : "NOW"}
                              </span>
                            ) : (
                              <span className={cn("ml-auto text-[11px] font-black tabular-nums", urgencyNum === "text-muted-foreground" ? "text-foreground/80" : urgencyNum)}>
                                {Math.max(0, daysToDropDate)}{isZh ? "天后" : "d"}
                              </span>
                            )}
                          </div>
                          {/* Timezone rows */}
                          <div className="space-y-1.5">
                            {tzRows.map(({ label, tz }) => (
                              <div key={tz} className="flex items-center justify-between gap-2">
                                <span className="text-[10px] text-muted-foreground/70 font-medium shrink-0 w-[64px]">{label}</span>
                                <span className="text-[10px] font-mono font-semibold tabular-nums text-foreground/80 text-right">
                                  {fmtInTz(lc.dropDate, tz)}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Feedback row */}
                    <div className="px-3.5 py-2 border-t border-border/20 bg-background/40 flex items-center justify-between">
                      <p className="text-[10px] text-muted-foreground/50">
                        {isZh ? "时间不准确？" : "Timing incorrect?"}
                      </p>
                      <button
                        type="button"
                        onClick={() => setLcFeedbackOpen(true)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border border-border/40 bg-muted/20 text-muted-foreground hover:bg-amber-50 dark:hover:bg-amber-950/30 hover:border-amber-400/40 hover:text-amber-600 dark:hover:text-amber-400 transition-colors cursor-pointer"
                      >
                        <RiFlagLine className="w-2.5 h-2.5" />
                        {isZh ? "反馈纠错" : "Report"}
                      </button>
                    </div>
                  </div>
                ) : !hasExpiry ? (
                  <div className="px-3.5 py-3 rounded-xl border border-border/50 bg-muted/15 flex items-center gap-2.5">
                    <span className="relative flex h-2 w-2 shrink-0">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-40 bg-foreground/40" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-foreground/50" />
                    </span>
                    <p className="text-[11px] text-muted-foreground">
                      {isZh ? "暂无到期日期，仍可订阅提醒" : "No expiry info yet, but you can still subscribe"}
                    </p>
                  </div>
                ) : null}

                {/* Reminder plan */}
                {isRestricted ? (
                  /* Restricted (prohibited / reserved) — status-change only */
                  <div className="rounded-xl border border-border/60 bg-muted/15 p-3.5 space-y-2.5">
                    <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                      {isZh ? "提醒计划" : "Reminder plan"}
                    </p>
                    <div className="flex items-center gap-2.5 rounded-lg border border-border/50 bg-muted/30 px-3 py-2.5">
                      <RiCheckboxCircleLine className="w-4 h-4 text-foreground/60 shrink-0" />
                      <div>
                        <p className="text-[11px] font-bold text-foreground/80">
                          {isZh ? "域名状态变化通知" : "Status change alert"}
                        </p>
                        <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
                          {isZh
                            ? "当该域名注册状态发生变化（如解禁、开放注册）时，系统将自动发送邮件通知。"
                            : "You'll be notified by email if this domain's status changes (e.g. restriction lifted, becomes available)."}
                        </p>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground/65 border-t border-border/40 pt-2 leading-relaxed">
                      {isZh ? "可随时取消订阅" : "Unsubscribe anytime"}
                    </p>
                  </div>
                ) : (
                  /* Normal domain — pre-expiry + phase chips */
                  <div className="rounded-xl border border-border/60 bg-muted/15 p-3.5 space-y-3">
                    <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                      {isZh ? "提醒计划" : "Reminder plan"}
                    </p>
                    {/* Pre-expiry day alerts — interactive */}
                    <div>
                      <p className="text-[10px] text-foreground/70 mb-2 flex items-center gap-1.5 font-semibold">
                        <RiTimerLine className="w-3 h-3 text-foreground/50" />
                        {isZh ? "到期前提醒" : "Pre-expiry alerts"}
                        <span className="ml-auto text-[9px] text-muted-foreground/60 font-normal normal-case">
                          {isZh ? "点击选择" : "tap to toggle"}
                        </span>
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {ALL_REMINDER_THRESHOLDS.map((d) => {
                          const on = selectedThresholds.includes(d);
                          return (
                            <button
                              key={d}
                              type="button"
                              onClick={() => toggleThreshold(d)}
                              className={cn(
                                "inline-flex items-center gap-0.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold transition-all cursor-pointer select-none",
                                on
                                  ? "bg-foreground/10 border-foreground/30 text-foreground"
                                  : "bg-muted/30 border-border/50 text-muted-foreground/55"
                              )}
                            >
                              {on
                                ? <RiCheckboxCircleLine className="w-2.5 h-2.5 shrink-0" />
                                : <RiCheckboxBlankCircleLine className="w-2.5 h-2.5 shrink-0" />}
                              {isZh ? `提前 ${d} 天` : `${d}d`}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    {/* Phase event alerts */}
                    {phaseChips.length > 0 ? (
                      <div>
                        <p className="text-[10px] text-foreground/70 mb-2 flex items-center gap-1.5 font-semibold">
                          <RiCalendarEventLine className="w-3 h-3 text-violet-500" />
                          {isZh ? `阶段提醒（.${tldUpper}）` : `Phase alerts (.${tldUpper})`}
                          <span className="ml-auto text-[9px] text-muted-foreground/60 font-normal normal-case">
                            {isZh ? "点击选择" : "tap to toggle"}
                          </span>
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {phaseChips.map((chip) => {
                            const on = phaseAlerts[chip.key];
                            return (
                              <button
                                key={chip.key}
                                type="button"
                                onClick={() => togglePhase(chip.key)}
                                className={cn(
                                  "inline-flex items-center gap-0.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold transition-all cursor-pointer select-none",
                                  on ? chip.activeCls : chip.inactiveCls
                                )}
                              >
                                {on
                                  ? <RiCheckboxCircleLine className="w-2.5 h-2.5 shrink-0" />
                                  : <RiCheckboxBlankCircleLine className="w-2.5 h-2.5 shrink-0" />}
                                {chip.label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ) : lc ? (
                      <p className="text-[10px] text-muted-foreground/55 italic">
                        {isZh
                          ? `.${tldUpper} 注册局不设宽限期，仅发送到期前提醒`
                          : `.${tldUpper} has no grace/redemption — pre-expiry alerts only`}
                      </p>
                    ) : null}
                    <p className="text-[10px] text-muted-foreground/65 border-t border-border/40 pt-2.5 leading-relaxed">
                      {isZh
                        ? "域名释放后自动停止 · 续费时提醒保留直至到期 · 可随时取消"
                        : "Auto-stops on drop · Reminders continue after renewal until new expiry · Unsubscribe anytime"}
                    </p>
                  </div>
                )}

                {/* Email input */}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1.5">
                    {isZh ? "接收邮箱" : "Email address"} <span className="text-red-500">*</span>
                  </p>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                    placeholder="your@email.com"
                    className="w-full text-sm rounded-xl border border-border bg-background px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-ring/30 transition-shadow font-mono"
                  />
                  {userEmail && email === userEmail && (
                    <p className="text-[10px] text-muted-foreground/60 mt-1 flex items-center gap-1">
                      <RiShieldCheckLine className="w-3 h-3 text-emerald-500" />
                      {isZh ? "已自动填入您的账户邮箱" : "Pre-filled from your account"}
                    </p>
                  )}
                </div>

                {/* Submit */}
                <Button
                  onClick={handleSubmit}
                  disabled={submitting}
                  className="w-full gap-2 h-10 bg-primary hover:bg-primary/90 active:bg-primary/80 text-primary-foreground border-0 rounded-xl font-semibold text-sm transition-all"
                >
                  {submitting
                    ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{isZh ? "订阅中…" : "Subscribing…"}</>
                    : <><RiCalendarEventLine className="w-4 h-4" />{isZh ? "订阅域名监控" : "Subscribe"}</>
                  }
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </DialogContent>
    </Dialog>

    {/* TLD Lifecycle Correction feedback dialog */}
    <Dialog open={lcFeedbackOpen} onOpenChange={setLcFeedbackOpen}>
      <DialogContent className="max-w-sm rounded-2xl gap-0 p-0 overflow-hidden">
        <DialogHeader className="px-5 pt-5 pb-3 border-b border-border/40">
          <DialogTitle className="text-base flex items-center gap-2">
            <RiFlagLine className="w-4 h-4 text-amber-500" />
            {isZh ? `纠正 .${tldUpper} 生命周期数据` : `Correct .${tldUpper} Lifecycle Data`}
          </DialogTitle>
          <p className="text-xs text-muted-foreground mt-1">
            {isZh
              ? "若实际注册局政策与显示数据不符，请填写正确天数并提交，管理员审核后将更新数据。"
              : "If the registry policy differs from what's shown, enter the correct days and submit. Admin will review and update."}
          </p>
        </DialogHeader>

        {lcDone ? (
          <div className="px-5 py-8 text-center space-y-2">
            <p className="text-2xl">✅</p>
            <p className="text-sm font-semibold">
              {isZh ? "感谢您的反馈！" : "Thanks for your feedback!"}
            </p>
            <p className="text-xs text-muted-foreground">
              {isZh ? "管理员审核后将更新数据，届时页面会自动反映最新信息。" : "Admin will review and update the data accordingly."}
            </p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => setLcFeedbackOpen(false)}>
              {isZh ? "关闭" : "Close"}
            </Button>
          </div>
        ) : (
          <div className="px-5 py-4 space-y-4">
            <p className="text-[10px] text-muted-foreground/60 uppercase tracking-widest font-bold">
              {isZh ? "建议天数（填 0 表示无该阶段）" : "Suggested Days (0 = phase does not exist)"}
            </p>

            <div className="grid grid-cols-3 gap-3">
              {([
                { key: "grace",        label: isZh ? "宽限期" : "Grace",      placeholder: "30" },
                { key: "redemption",   label: isZh ? "赎回期" : "Redemption", placeholder: "30" },
                { key: "pendingDelete",label: isZh ? "待删除" : "Pending Del", placeholder: "5"  },
              ] as const).map(f => (
                <div key={f.key} className="space-y-1">
                  <label className="text-[10px] font-semibold text-muted-foreground/80">{f.label}</label>
                  <Input
                    type="number"
                    min="0"
                    max="365"
                    value={lcForm[f.key]}
                    onChange={e => setLcForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                    placeholder={f.placeholder}
                    className="h-9 text-sm font-mono text-center"
                  />
                  {lc && (
                    <p className="text-[9px] text-muted-foreground/50 text-center font-mono">
                      {isZh ? "当前" : "now"}: {f.key === "grace" ? lc.cfg.grace : f.key === "redemption" ? lc.cfg.redemption : lc.cfg.pendingDelete}d
                    </p>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "来源链接（可选）" : "Source URL (optional)"}
              </label>
              <Input
                type="url"
                value={lcForm.sourceUrl}
                onChange={e => setLcForm(prev => ({ ...prev, sourceUrl: e.target.value }))}
                placeholder="https://registry.example/policy"
                className="h-9 text-xs font-mono"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "备注（可选）" : "Notes (optional)"}
              </label>
              <Input
                type="text"
                value={lcForm.notes}
                onChange={e => setLcForm(prev => ({ ...prev, notes: e.target.value }))}
                placeholder={isZh ? "如：官网政策更新日期 2025-01-01" : "e.g. Registry policy updated 2025-01-01"}
                className="h-9 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "联系邮箱（可选，用于告知审核结果）" : "Contact email (optional)"}
              </label>
              <Input
                type="email"
                value={lcForm.email}
                onChange={e => setLcForm(prev => ({ ...prev, email: e.target.value }))}
                placeholder="your@email.com"
                className="h-9 text-xs font-mono"
              />
            </div>
          </div>
        )}

        {!lcDone && (
          <div className="flex flex-row gap-2 px-5 pb-5 pt-0">
            <Button variant="outline" size="sm" onClick={() => setLcFeedbackOpen(false)} className="flex-1">
              {isZh ? "取消" : "Cancel"}
            </Button>
            <Button
              size="sm"
              onClick={handleLcFeedbackSubmit}
              disabled={lcSubmitting}
              className="flex-1 bg-amber-500 hover:bg-amber-600 text-white"
            >
              {lcSubmitting
                ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" />{isZh ? "提交中…" : "Submitting…"}</>
                : <><RiFlagLine className="w-3.5 h-3.5 mr-1" />{isZh ? "提交纠错" : "Submit Correction"}</>}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  </>);
}

function RegistrarIcon({ faviconDomain, name }: { faviconDomain: string | null; name: string }) {
  const [imgFailed, setImgFailed] = React.useState(false);
  return (
    <div className="shrink-0 w-9 h-9 rounded-xl flex items-center justify-center overflow-hidden bg-muted/40 border border-border/30">
      {faviconDomain && !imgFailed ? (
        <img
          src={`/api/favicon?domain=${encodeURIComponent(faviconDomain)}`}
          alt={name}
          className="w-6 h-6 object-contain"
          onError={() => setImgFailed(true)}
        />
      ) : (
        <span className="text-xs font-bold text-muted-foreground select-none">
          {name.charAt(0).toUpperCase()}
        </span>
      )}
    </div>
  );
}

function DomainFavicon({
  domain,
  size = 20,
  className = "",
  fallback,
}: {
  domain: string;
  size?: number;
  className?: string;
  fallback: React.ReactNode;
}) {
  const [failed, setFailed] = React.useState(false);
  if (!domain || failed) return <>{fallback}</>;
  return (
    <img
      src={`/api/favicon?domain=${encodeURIComponent(domain)}`}
      alt=""
      width={size}
      height={size}
      className={`object-contain rounded-sm ${className}`}
      onError={() => setFailed(true)}
    />
  );
}

function AvailableDomainCard({ domain, locale, isPremiumByWhois = false }: { domain: string; locale: string; isPremiumByWhois?: boolean }) {
  const [rawPrices, setRawPrices] = React.useState<DomainPricing[]>([]);
  const [registrars, setRegistrars] = React.useState<DomainPricing[]>([]);
  const [renewRegistrars, setRenewRegistrars] = React.useState<DomainPricing[]>([]);
  const [loadingPrices, setLoadingPrices] = React.useState(true);
  const [anyApiPremium, setAnyApiPremium] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const CARD_FALLBACK_RATES: Record<string, number> = {
    AUD: 1.65, CAD: 1.49, CHF: 0.94, CNY: 7.82, DKK: 7.46,
    GBP: 0.85, HKD: 8.50, JPY: 162, KRW: 1520, NOK: 11.7,
    NZD: 1.80, SEK: 11.3, SGD: 1.46, TWD: 34.8, USD: 1.09,
  };
  const [eurRates, setEurRates] = React.useState<Record<string, number>>(CARD_FALLBACK_RATES);
  const isZh = locale.startsWith("zh");

  React.useEffect(() => {
    const tld = domain.substring(domain.lastIndexOf(".") + 1).toLowerCase();
    const ctrl = new AbortController();
    fetch(`/api/pricing?tld=${encodeURIComponent(tld)}&type=new`, { signal: ctrl.signal })
      .then((r) => r.json())
      .then((data) => {
        if (data.anyPremium) setAnyApiPremium(true);
        const prices: DomainPricing[] = (data.price || [])
          .filter((r: any) => typeof r.new === "number")
          .map((r: any) => ({
            ...r,
            isPremium: r.isPremium ?? (
              (r.currencytype && r.currencytype.toLowerCase().includes("premium")) ||
              (typeof r.new === "number" && (() => {
                const cur = (r.currency || "").toLowerCase();
                const t: Record<string, number> = { usd: 60, eur: 55, cad: 80, gbp: 50, aud: 90, cny: 420, hkd: 470, sgd: 80, jpy: 9000 };
                return t[cur] !== undefined && r.new > t[cur];
              })())
            ),
            externalLink: `https://www.nazhumi.com/domain/${tld}/new`,
          }));
        setRawPrices(prices);
      })
      .catch(() => {})
      .finally(() => setLoadingPrices(false));
    return () => ctrl.abort();
  }, [domain]);

  React.useEffect(() => {
    fetch("https://api.frankfurter.dev/v1/latest")
      .then((r) => r.json())
      .then((data) => { if (data?.rates) setEurRates(data.rates); })
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    if (rawPrices.length === 0) return;
    const toEur = (amount: number, currency: string) => {
      const cur = currency.toUpperCase();
      if (cur === "EUR") return amount;
      return amount / (eurRates[cur] ?? 1);
    };
    // Registration price sort
    const sortedNew = [...rawPrices]
      .sort((a, b) => {
        if (anyApiPremium) {
          if (a.isPremium !== b.isPremium) return a.isPremium ? -1 : 1;
        } else {
          if (a.isPremium !== b.isPremium) return a.isPremium ? 1 : -1;
        }
        return toEur(a.new as number, a.currency) - toEur(b.new as number, b.currency);
      })
      .slice(0, 5);
    setRegistrars(sortedNew);
    // Renewal price sort — from the same data (NazhumiRegistrar has renew field)
    const sortedRenew = [...rawPrices]
      .filter((r) => typeof r.renew === "number" && r.renew !== -1)
      .sort((a, b) => {
        if (a.isPremium !== b.isPremium) return a.isPremium ? 1 : -1;
        return toEur(a.renew as number, a.currency) - toEur(b.renew as number, b.currency);
      })
      .slice(0, 5);
    setRenewRegistrars(sortedRenew);
  }, [rawPrices, eurRates, anyApiPremium]);

  function formatPrice(amount: number, currency: string): string {
    const cur = (currency ?? "").toUpperCase();
    if (isZh) {
      if (cur === "CNY") return `¥${amount.toFixed(2)}`;
      const cnyRate = eurRates["CNY"] ?? 7.82;
      const eurAmount = cur === "EUR" ? amount : amount / (eurRates[cur] ?? 1);
      return `¥${(eurAmount * cnyRate).toFixed(2)}`;
    }
    const SYMBOLS: Record<string, string> = {
      USD: "$", EUR: "€", CNY: "¥", GBP: "£",
      CAD: "CA$", AUD: "A$", HKD: "HK$", SGD: "S$",
      NZD: "NZ$", TWD: "NT$", KRW: "₩", JPY: "¥",
    };
    const sym = SYMBOLS[cur] ?? (cur + "\u00a0");
    const decimals = ["JPY", "KRW"].includes(cur) ? 0 : 2;
    return `${sym}${amount.toFixed(decimals)}`;
  }

  function handleCopy() {
    navigator.clipboard.writeText(domain).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }

  const tldForDisplay = domain.substring(domain.lastIndexOf(".")).toLowerCase();
  const sldForDisplay = domain.substring(0, domain.lastIndexOf("."));
  const isPremium = anyApiPremium || isPremiumByWhois || registrars.some((r) => r.isPremium);
  const premiumRegistrars = registrars.filter((r) => r.isPremium);
  const bestRegistrar = (isPremium && premiumRegistrars.length > 0)
    ? premiumRegistrars[0]
    : (registrars.find((r) => !r.isPremium) ?? registrars[0] ?? null);

  // Shared registrar row renderer for both new and renew tables
  function RegistrarRow({ r, idx, priceField, colorFirst }: { r: DomainPricing; idx: number; priceField: "new" | "renew"; colorFirst: boolean }) {
    const faviconDomain = (() => { try { return new URL(r.registrarweb).hostname; } catch { return null; } })();
    const rowIsPremium = r.isPremium;
    const isFirst = idx === 0;
    const price = r[priceField];
    return (
      <a
        href={r.registrarweb}
        target="_blank"
        rel="noopener noreferrer"
        className={cn(
          "flex items-center gap-3 px-4 sm:px-5 py-2.5 transition-colors duration-150 group hover:bg-muted/40",
          isFirst && colorFirst && "bg-muted/20",
        )}
      >
        <RegistrarIcon faviconDomain={faviconDomain} name={r.registrarname} />
        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="shrink-0 text-[11px] font-bold text-muted-foreground/25 w-4 text-right tabular-nums">{idx + 1}</span>
          <p className={cn("text-sm truncate", isFirst ? "font-semibold text-foreground" : "font-medium text-foreground/70")}>
            {r.registrarname}
          </p>
          {isFirst && !rowIsPremium && !isPremium && colorFirst && (
            <span className="shrink-0 text-[9px] font-bold text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border border-emerald-400/30 dark:border-emerald-500/30 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "最低价" : "BEST"}
            </span>
          )}
          {rowIsPremium && (
            <span className="shrink-0 text-[9px] font-bold text-amber-600 dark:text-amber-400 bg-amber-500/8 border border-amber-400/25 dark:border-amber-500/25 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "溢价" : "PREMIUM"}
            </span>
          )}
          {!rowIsPremium && anyApiPremium && (
            <span className="shrink-0 text-[9px] font-bold text-muted-foreground/50 bg-muted/50 border border-border/50 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "参考价" : "STD"}
            </span>
          )}
        </div>
        <div className="shrink-0 text-right flex items-center gap-1.5">
          <div className="flex items-baseline gap-0.5">
            <span className={cn(
              "font-bold tabular-nums",
              rowIsPremium
                ? (isFirst ? "text-base text-amber-600 dark:text-amber-400" : "text-sm text-amber-500/60 dark:text-amber-500/50")
                : (isFirst && colorFirst ? "text-base text-emerald-600 dark:text-emerald-400" : "text-sm text-foreground/60"),
            )}>
              {typeof price === "number" ? formatPrice(price, r.currency) : "N/A"}
            </span>
            <span className="text-xs text-muted-foreground/40">/{isZh ? "年" : "yr"}</span>
          </div>
          <svg className="w-3.5 h-3.5 text-muted-foreground/25 group-hover:text-muted-foreground/50 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      </a>
    );
  }

  return (
    <div className="glass-panel rounded-xl overflow-hidden border border-border/60">
      {/* Accent bar */}
      <div className={cn("h-1 w-full", isPremium ? "bg-gradient-to-r from-amber-400 to-amber-500" : "bg-gradient-to-r from-emerald-400 to-emerald-500")} />

      {/* ── Hero ── */}
      <div className={cn(
        "px-5 sm:px-8 pt-6 pb-5",
        isPremium ? "bg-amber-500/5 dark:bg-amber-950/15" : "bg-emerald-500/5 dark:bg-emerald-950/15"
      )}>
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            {/* Icon */}
            <div className={cn(
              "shrink-0 w-11 h-11 rounded-xl flex items-center justify-center border",
              isPremium
                ? "bg-amber-500/10 border-amber-400/30 dark:border-amber-500/30"
                : "bg-emerald-500/10 border-emerald-400/30 dark:border-emerald-500/30"
            )}>
              {isPremium
                ? <RiVipCrownLine className="w-5 h-5 text-amber-500 dark:text-amber-400" />
                : <RiCheckLine className="w-6 h-6 text-emerald-500 dark:text-emerald-400" />}
            </div>
            <div className="min-w-0">
              {/* Domain name */}
              <div className="mb-1 leading-tight">
                <span className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground break-all">{sldForDisplay}</span>
                <span className={cn(
                  "text-2xl sm:text-3xl font-bold tracking-tight",
                  isPremium ? "text-amber-500 dark:text-amber-400" : "text-emerald-500 dark:text-emerald-400"
                )}>{tldForDisplay}</span>
              </div>
              {/* Description */}
              <p className="text-sm text-muted-foreground leading-relaxed">
                {isPremium
                  ? (anyApiPremium && premiumRegistrars.length > 0
                      ? (isZh
                          ? `溢价域名，注册费约 ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/年起，实际以注册商报价为准。`
                          : `Premium domain — starting from ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/yr. Confirm price with registrar.`)
                      : (isZh
                          ? "溢价域名，注册价格高于普通域名，请以注册商实时报价为准。"
                          : "Premium domain — registration costs above standard rates. Confirm with registrar."))
                  : (isZh
                      ? "该域名目前可注册，抓紧时间抢注吧！"
                      : "This domain is available. Grab it before someone else does.")}
              </p>
            </div>
          </div>
          {/* Badge */}
          <div className="shrink-0 flex flex-row sm:flex-col items-center sm:items-end gap-2">
            <span className={cn(
              "inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border",
              isPremium
                ? "text-amber-700 dark:text-amber-300 bg-amber-500/10 border-amber-400/30 dark:border-amber-500/30"
                : "text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border-emerald-400/30 dark:border-emerald-500/30"
            )}>
              <span className={cn("w-1.5 h-1.5 rounded-full animate-pulse", isPremium ? "bg-amber-500" : "bg-emerald-500")} />
              {isPremium ? (isZh ? "溢价域名" : "Premium") : (isZh ? "可注册" : "Available")}
            </span>
          </div>
        </div>
      </div>

      {/* ── Action buttons ── */}
      <div className="px-5 sm:px-8 py-4 border-t border-border/40">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-2.5">
          {loadingPrices ? (
            <div className="h-9 w-44 rounded-lg bg-muted/40 animate-pulse mx-auto" />
          ) : bestRegistrar ? (
            <a
              href={bestRegistrar.registrarweb}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "inline-flex items-center justify-center gap-2 font-semibold text-sm px-5 py-2.5 rounded-lg border transition-all duration-150 active:scale-[0.98]",
                isPremium
                  ? "border-amber-400/40 dark:border-amber-500/35 text-amber-700 dark:text-amber-300 bg-amber-500/10 dark:bg-amber-500/12 hover:bg-amber-500/18 dark:hover:bg-amber-500/20"
                  : "border-emerald-400/40 dark:border-emerald-500/35 text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 dark:bg-emerald-500/12 hover:bg-emerald-500/18 dark:hover:bg-emerald-500/20"
              )}
            >
              <RiShoppingCartLine className="w-4 h-4 shrink-0" />
              <span>
                {isZh
                  ? `${isPremium ? "查看价格" : "立即注册"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/首年起`
                  : `${isPremium ? "Check Price" : "Register Now"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/yr`}
              </span>
            </a>
          ) : null}
          <button
            onClick={handleCopy}
            className="inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.98]"
          >
            {copied
              ? <RiCheckLine className="w-4 h-4 shrink-0 text-emerald-500" />
              : <RiFileCopyLine className="w-4 h-4 shrink-0" />}
            {isZh ? (copied ? "已复制" : "复制域名") : (copied ? "Copied!" : "Copy Domain")}
          </button>
          <Link href="/">
            <button className="w-full sm:w-auto inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.98]">
              <RiSearchLine className="w-4 h-4 shrink-0" />
              {isZh ? "新查询" : "New Search"}
            </button>
          </Link>
        </div>
      </div>

      {/* ── Registration tips ── */}
      <div className="border-t border-border/50 px-5 py-4">
        <p className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground/60 mb-3 flex items-center gap-1.5">
          <RiInformationLine className="w-3.5 h-3.5" />
          {isZh ? "注册建议" : "Tips"}
        </p>
        <ul className="space-y-2">
          {[
            isZh ? "建议尽快通过正规注册商完成注册" : "Register through an accredited registrar promptly",
            isZh ? "注册前请确认域名用途符合相关法规" : "Confirm your intended use complies with relevant regulations",
            isZh ? "建议同时注册常见后缀以保护品牌" : "Consider registering common TLD variants to protect your brand",
          ].map((tip, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground leading-snug">
              <span className={cn("mt-1 w-1.5 h-1.5 rounded-full shrink-0", isPremium ? "bg-amber-400" : "bg-emerald-400")} />
              {tip}
            </li>
          ))}
        </ul>
      </div>

      {/* ── Price section ── */}
      <div className="border-t border-border/50">
        {/* Premium notice */}
        {isPremium && !loadingPrices && (
          <div className="mx-4 sm:mx-5 mt-4 flex items-start gap-2 rounded-lg border border-border/60 bg-muted/30 px-3 py-2.5">
            <RiInformationLine className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-[11px] text-muted-foreground leading-snug">
              {anyApiPremium && premiumRegistrars.length > 0
                ? (isZh
                    ? "溢价注册商报价（标注「溢价」）为域名真实价格，其余为参考标准价，实际价格以注册商报价为准。"
                    : "Entries marked \"Premium\" reflect the actual premium fee. Others show standard TLD reference prices — always confirm with the registrar.")
                : (isZh
                    ? "以下为该 TLD 标准/参考价，实际溢价金额可能显著更高，以注册商报价为准。"
                    : "Prices shown are standard/reference rates. Actual premium cost may be significantly higher — confirm with the registrar.")}
            </p>
          </div>
        )}

        {/* Registration prices */}
        <div className="px-4 sm:px-5 pt-4 pb-1 flex items-center justify-between">
          <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 font-bold uppercase tracking-wider">
            <RiShoppingCartLine className="w-3 h-3" />
            {isZh ? "注册价格" : "Registration"}
          </p>
          {registrars.length > 0 && (
            <span className="text-[10px] text-muted-foreground/40">{isZh ? "以官网为准" : "Reference only"}</span>
          )}
        </div>

        {loadingPrices ? (
          <div className="px-4 sm:px-5 pb-4 pt-2 space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-3 py-1.5">
                <div className="w-8 h-8 rounded-lg bg-muted/50 animate-pulse shrink-0" />
                <div className="flex-1 h-3.5 rounded bg-muted/40 animate-pulse" />
                <div className="w-16 h-4 rounded bg-muted/40 animate-pulse shrink-0" />
              </div>
            ))}
          </div>
        ) : registrars.length > 0 ? (
          <div className="pb-1">
            {registrars.map((r, idx) => (
              <RegistrarRow key={r.registrar} r={r} idx={idx} priceField="new" colorFirst={true} />
            ))}
          </div>
        ) : (
          <div className="px-4 sm:px-5 pb-4 pt-1">
            <p className="text-[10px] text-muted-foreground/40 mb-3 text-center">
              {isZh ? "暂无聚合价格数据，可直接前往以下注册商查询" : "No aggregated price data — search directly on these registrars"}
            </p>
            <div className="grid grid-cols-2 gap-2">
              {[
                { name: "Namecheap", color: "#de3723", logo: "namecheap.com", url: `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(domain)}` },
                { name: "GoDaddy",   color: "#1bdbdb", logo: "godaddy.com",   url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(domain)}` },
                { name: "Porkbun",   color: "#f76b8a", logo: "porkbun.com",   url: `https://porkbun.com/checkout/search?q=${encodeURIComponent(domain)}` },
                { name: "Dynadot",   color: "#4e2998", logo: "dynadot.com",   url: `https://www.dynadot.com/domain/search.html?domain=${encodeURIComponent(domain)}` },
                { name: "Cloudflare",color: "#f48120", logo: "cloudflare.com",url: `https://www.cloudflare.com/products/registrar/` },
                { name: "Name.com",  color: "#0066cc", logo: "name.com",      url: `https://www.name.com/domain/search?search=${encodeURIComponent(domain)}` },
              ].map(reg => (
                <a
                  key={reg.name}
                  href={reg.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-2.5 py-2 rounded-lg border border-border/50 hover:border-primary/30 hover:bg-muted/40 transition-all group"
                >
                  <DomainFavicon
                    domain={reg.logo}
                    size={16}
                    className="w-4 h-4 rounded-sm shrink-0"
                    fallback={<RiGlobalLine className="w-4 h-4 text-muted-foreground/50 shrink-0" />}
                  />
                  <span className="text-xs font-medium text-foreground/80 group-hover:text-foreground transition-colors truncate flex-1">{reg.name}</span>
                  <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/30 group-hover:text-muted-foreground/60 shrink-0 transition-colors" />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Renewal prices */}
        {!loadingPrices && renewRegistrars.length > 0 && (
          <>
            <div className="border-t border-border/40 px-4 sm:px-5 pt-4 pb-1 flex items-center justify-between">
              <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 font-bold uppercase tracking-wider">
                <RiLoopLeftLine className="w-3 h-3" />
                {isZh ? "续费价格" : "Renewal"}
              </p>
            </div>
            <div className="pb-1">
              {renewRegistrars.map((r, idx) => (
                <RegistrarRow key={`renew-${r.registrar}`} r={r} idx={idx} priceField="renew" colorFirst={false} />
              ))}
            </div>
          </>
        )}

        {/* Footer note */}
        {!loadingPrices && registrars.length > 0 && (
          <p className="text-[10px] text-muted-foreground/30 px-4 sm:px-5 pt-2.5 pb-3">
            {isZh ? "数据来源：nazhumi.com & miqingju.com · 价格仅供参考" : "Source: nazhumi.com & miqingju.com · Reference only"}
          </p>
        )}
      </div>
    </div>
  );
}


const _EMPTY_WHOIS_RESULT: WhoisResult = {
  status: false,
  time: 0,
  cached: false,
  result: { ...initialWhoisAnalyzeResult },
};

/** Extract the cleaned query target from Next.js router.query (client-side). */
function targetFromRouterQuery(query: NodeJS.Dict<string | string[]>): string {
  const segments = (query.query as string[] | undefined) ?? [];
  return cleanDomain(segments.join("/").replace(/\s+/g, ""));
}

/** Text ad banner — multi-item with 4s fade cycling, only shown after results load. */
function ResultTextAd({ loading = false, inline = false }: { loading?: boolean; inline?: boolean }) {
  const settings = useSiteSettings();
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  const rawText = settings.result_ad_text || "";
  const items = React.useMemo(
    () => rawText.split("|").map(s => s.trim()).filter(Boolean),
    [rawText],
  );

  React.useEffect(() => {
    if (items.length <= 1) return;
    setActiveIdx(0);
    const timer = setInterval(() => {
      setFading(true);
      setTimeout(() => {
        setActiveIdx(i => (i + 1) % items.length);
        setFading(false);
      }, 350);
    }, 5000);
    return () => clearInterval(timer);
  }, [items.length, rawText]);

  if (settings.result_ad_enabled !== "1") return null;
  if (items.length === 0) return null;
  if (loading) return null;

  const label = settings.result_ad_label || "广告";
  const url   = settings.result_ad_url;
  const text  = items[activeIdx];

  const inner = (
    <div className="flex items-center gap-2 py-1 cursor-default">
      <RiMegaphoneLine
        className="w-3.5 h-3.5 shrink-0 text-primary/70"
        style={{ animation: "ad-icon 2.4s ease-in-out infinite" }}
      />
      <span
        className="text-xs text-foreground/65 flex-1 leading-snug"
        style={{ opacity: fading ? 0 : 1, transition: "opacity 0.35s ease" }}
      >
        <span className="font-semibold text-primary/80 mr-1">{label}：</span>
        {text}
      </span>
      {url && <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/40 shrink-0" />}
      <style>{`
        @keyframes ad-icon {
          0%, 100% { transform: rotate(-8deg) scale(1);   opacity: 0.7; }
          25%       { transform: rotate(8deg) scale(1.1);  opacity: 1;   }
          50%       { transform: rotate(-6deg) scale(1);   opacity: 0.7; }
          75%       { transform: rotate(6deg) scale(1.05); opacity: 1;   }
        }
      `}</style>
    </div>
  );

  const wrapper = url ? (
    <Link href={url} target="_blank" rel="noopener noreferrer sponsored" className="block hover:opacity-80 transition-opacity">
      {inner}
    </Link>
  ) : inner;

  if (inline) {
    return <div className="sm:hidden mt-3">{wrapper}</div>;
  }
  return <div className="hidden sm:block mt-4">{wrapper}</div>;
}

export default function LookupPage({
  data: initialData,
  target: propTarget,
  displayTarget: propDisplayTarget,
  origin,
}: {
  data: WhoisResult | null;
  target: string;
  displayTarget: string;
  origin: string;
}) {
  const { t, locale } = useTranslation();
  const router = useRouter();
  const settings = useSiteSettings();
  const hideRawWhois = settings.hide_raw_whois === "1";
  const enableSearchLinks = settings.enable_search_links !== "";

  // ── Shallow-routing target sync ──────────────────────────────────────────
  // `target` starts as the SSR-provided prop.  When the user searches again
  // from the same page (handleSearch uses shallow routing to skip SSR), only
  // router.query changes — props are NOT updated.  We track target in state
  // and re-derive it from router.query so useEffect([target]) re-fires and
  // fetches new data without a full page reload.
  const [target, setTarget] = React.useState(propTarget);
  const [displayTarget, setDisplayTarget] = React.useState(propDisplayTarget);

  useEffect(() => {
    const newTarget = targetFromRouterQuery(router.query);
    if (newTarget && newTarget !== target) {
      setTarget(newTarget);
      setDisplayTarget(newTarget); // domainToUnicode not available client-side
    }
  // router.query.query is the catch-all segment array; re-run when it changes
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.query.query]);

  // When SSR returns cached data (initialData != null), start with it so the
  // server-rendered HTML has real content (better SEO / Googlebot indexing).
  // The client-side useEffect always fires a fresh /api/lookup to get up-to-date
  // data, so the SSR snapshot is just a warm-start hint.
  const [loading, setLoading] = React.useState(initialData == null);
  // refreshing=true means partial RDAP data is shown; WHOIS enrichment still in-flight.
  // A subtle indicator is shown while refreshing, but the main content is visible.
  const [refreshing, setRefreshing] = React.useState(false);
  const [data, setData] = React.useState<WhoisResult>(initialData ?? _EMPTY_WHOIS_RESULT);
  // Incrementing this forces a fresh fetch for the same target (re-query button).
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [expandStatus, setExpandStatus] = React.useState(false);
  const [feedbackOpen, setFeedbackOpen] = React.useState(false);
  const suppressNextLoad = React.useRef(false);
  // Track if the first client-side fetch has completed to avoid flicker:
  // On first load, if SSR already provided data, do a silent background refresh
  // (keep showing SSR data while fresh data loads) instead of flashing a skeleton.
  const firstLoadDone = React.useRef(false);
  const scrollAreaRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleStart = (url: string) => {
      if (suppressNextLoad.current) {
        suppressNextLoad.current = false;
        return;
      }
      if (isSearchRoute(url)) { setLoading(true); setRefreshing(false); }
    };
    // routeChangeComplete is intentionally NOT handled here: the
    // client-side fetch useEffect sets loading=false once data arrives.
    const handleError = () => setLoading(false);
    router.events.on("routeChangeStart", handleStart);
    router.events.on("routeChangeError", handleError);
    return () => {
      router.events.off("routeChangeStart", handleStart);
      router.events.off("routeChangeError", handleError);
    };
  }, [router]);

  // Client-side WHOIS fetch — runs when target changes (shallow nav) or
  // refreshKey increments (re-query button forces a fresh lookup).
  useEffect(() => {
    // Flicker prevention: on the very first client-side render, if SSR already
    // provided data (initialData != null), skip resetting to empty and just
    // silently update the data in the background — no skeleton flash.
    const isFirstLoad = !firstLoadDone.current;
    firstLoadDone.current = true;
    const silentRefresh = isFirstLoad && initialData != null && refreshKey === 0;

    if (!silentRefresh) {
      setLoading(true);
      // Scroll back to top when navigating to a new domain
      if (scrollAreaRef.current) {
        const vp = scrollAreaRef.current.querySelector("[data-radix-scroll-area-viewport]");
        if (vp) vp.scrollTop = 0;
      }
      // Do NOT reset data to _EMPTY_WHOIS_RESULT here.
      // Keeping the previous result visible prevents the layout from
      // collapsing then re-expanding (the "jump") while the new lookup loads.
      // On the very first load data is already _EMPTY_WHOIS_RESULT (initial
      // useState), so the skeleton still shows correctly when there is nothing
      // to display yet.
    }

    let cancelled = false;
    // Use a pre-started fetch if handleSearch already fired one (hides SSR +
    // hydration latency ~400-700 ms inside the reported lookup time).
    // refreshKey > 0 means a forced re-query, skip the prefetch cache.
    const prefetched = refreshKey === 0 ? consumePrefetch(target) : undefined;
    const streamUrl = `/api/lookup-stream?query=${encodeURIComponent(target)}${refreshKey > 0 ? "&nocache=1" : ""}`;
    const responsePromise = prefetched ?? fetch(streamUrl);

    (async () => {
      try {
        const r = await responsePromise;
        if (cancelled) return;

        if (r.status === 401) {
          toast.warning(t("auth.require_login_notice"));
          setTimeout(() => router.replace(`/login?callbackUrl=${encodeURIComponent(router.asPath)}&msg=require_login`), 1200);
          return;
        }

        if (!r.ok || !r.body) {
          // Non-streaming fallback: parse single JSON response
          const d = await r.json().catch(() => null) as WhoisResult | null;
          if (!cancelled && d) {
            setData({ ...d, result: d.result ?? { ...initialWhoisAnalyzeResult } });
          }
          if (!cancelled) { setLoading(false); setRefreshing(false); }
          return;
        }

        // ── Consume NDJSON stream ──────────────────────────────────────────
        // Each newline-delimited JSON line is either a partial (RDAP-only)
        // or final (merged RDAP+WHOIS) result.  Partial results clear the
        // loading skeleton immediately; the final result stops the subtle
        // refreshing indicator.
        const reader = r.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (!cancelled) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            if (!line.trim() || cancelled) continue;
            try {
              const d = JSON.parse(line) as WhoisResult & { partial?: boolean };
              if (cancelled) break;
              setData({ ...d, result: d.result ?? { ...initialWhoisAnalyzeResult } });
              if (d.partial) {
                // First chunk: RDAP data — show result immediately, keep subtle refresh spinner
                setLoading(false);
                setRefreshing(true);
              } else {
                // Final chunk: fully merged result
                setLoading(false);
                setRefreshing(false);
              }
            } catch { /* malformed JSON line, skip */ }
          }
        }

        if (!cancelled) {
          // If stream ended without a final chunk (e.g. single-chunk response),
          // ensure loading/refreshing states are cleared.
          setLoading(false);
          setRefreshing(false);
        }
      } catch {
        if (!cancelled) {
          setData({ status: false, time: 0, cached: false, error: t("lookup_failed_fallback"), result: { ...initialWhoisAnalyzeResult } });
          setLoading(false);
          setRefreshing(false);
        }
      }
    })();

    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, refreshKey]);

  const [showImagePreview, setShowImagePreview] = React.useState(false);
  const [imgWidth, setImgWidth] = React.useState(1200);
  const [imgHeight, setImgHeight] = React.useState(630);
  const [imgTheme, setImgTheme] = React.useState<"light" | "dark">("light");
  const [imgActing, setImgActing] = React.useState<"download" | "copy" | null>(null);
  const copy = useClipboard();
  useSearchHotkeys({});

  useEffect(() => {
    setImgTheme(
      document.documentElement.classList.contains("dark") ? "dark" : "light",
    );
  }, []);

  const isChinese = locale === "zh" || locale === "zh-tw";
  const isZh = isChinese;

  const [reminderDialogOpen, setReminderDialogOpen] = React.useState(false);
  const [stampDetailOpen, setStampDetailOpen] = React.useState(false);
  const [officialPopoverOpen, setOfficialPopoverOpen] = React.useState(false);
  const [officialPopoverPos, setOfficialPopoverPos] = React.useState<{ bottom: number; centerX: number; isMobile: boolean } | null>(null);

  const [verifiedStamps, setVerifiedStamps] = React.useState<
    { id: string; tagName: string; tagStyle: string; cardTheme: string; link: string; nickname: string; description?: string }[]
  >([]);

  const isOfficialDomain = React.useMemo(() => {
    const d = (target || "").toLowerCase().replace(/^www\./, "");
    return MAINSTREAM_DOMAINS.has(d);
  }, [target]);


  const STAMP_STYLE_MAP: Record<string, string> = {
    personal: "bg-teal-500 text-white border-0",
    default:  "bg-teal-500 text-white border-0",
    official: "bg-blue-500 text-white border-0",
    brand:    "bg-violet-500 text-white border-0",
    verified: "bg-emerald-500 text-white border-0",
    partner:  "bg-orange-500 text-white border-0",
    dev:      "bg-sky-500 text-white border-0",
    warning:  "bg-amber-400 text-white border-0",
    premium:  "bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white border-0",
  };

  const STAMP_CARD_MAP: Record<string, { border: string; bg: string; iconColor: string }> = {
    personal: { border: "border-l-teal-500",    bg: "bg-teal-50   dark:bg-teal-900/20",     iconColor: "text-teal-500" },
    official: { border: "border-l-blue-500",    bg: "bg-blue-50   dark:bg-blue-900/20",     iconColor: "text-blue-500" },
    brand:    { border: "border-l-violet-500",  bg: "bg-violet-50 dark:bg-violet-900/20",   iconColor: "text-violet-500" },
    verified: { border: "border-l-emerald-500", bg: "bg-emerald-50 dark:bg-emerald-900/20", iconColor: "text-emerald-500" },
    partner:  { border: "border-l-orange-500",  bg: "bg-orange-50 dark:bg-orange-900/20",   iconColor: "text-orange-500" },
    dev:      { border: "border-l-sky-500",     bg: "bg-sky-50    dark:bg-sky-900/20",      iconColor: "text-sky-500" },
    warning:  { border: "border-l-amber-400",   bg: "bg-amber-50  dark:bg-amber-900/20",    iconColor: "text-amber-500" },
    premium:  { border: "border-l-fuchsia-500", bg: "bg-fuchsia-50 dark:bg-fuchsia-900/20", iconColor: "text-fuchsia-500" },
    default:  { border: "border-l-teal-500",    bg: "bg-teal-50   dark:bg-teal-900/20",     iconColor: "text-teal-500" },
  };

  useEffect(() => {
    const domainKey = data.result?.domain || target;
    if (!domainKey) return;

    let ctrl = new AbortController();

    const fetchStamps = () => {
      ctrl.abort();
      ctrl = new AbortController();
      fetch(`/api/stamp/check?domain=${encodeURIComponent(domainKey)}`, { signal: ctrl.signal })
        .then((r) => r.json())
        .then((d) => setVerifiedStamps(d.stamps || []))
        .catch(() => {});
    };

    // Defer until after initial paint so it doesn't compete with critical rendering
    const timer = setTimeout(fetchStamps, 300);

    // Re-fetch when tab regains focus so admin stamp changes are reflected immediately
    const onVisibility = () => { if (document.visibilityState === "visible") fetchStamps(); };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      clearTimeout(timer);
      ctrl.abort();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [data.result?.domain, target]);

  const FALLBACK_EUR_RATES: Record<string, number> = {
    AUD: 1.65, CAD: 1.49, CHF: 0.94, CNY: 7.82, DKK: 7.46,
    GBP: 0.85, HKD: 8.50, JPY: 162, KRW: 1520, NOK: 11.7,
    NZD: 1.80, SEK: 11.3, SGD: 1.46, TWD: 34.8, USD: 1.09,
  };
  const [eurRates, setEurRates] = React.useState<Record<string, number>>(FALLBACK_EUR_RATES);
  useEffect(() => {
    fetch("https://api.frankfurter.dev/v1/latest")
      .then((r) => r.json())
      .then((d) => { if (d?.rates) setEurRates(d.rates); })
      .catch(() => {});
  }, []);

  function formatRegistrarPrice(amount: number, currency: string): string {
    const cur = (currency ?? "").toUpperCase();
    if (isChinese) {
      if (cur === "CNY") return `¥${amount.toFixed(2)}`;
      const cnyRate = eurRates["CNY"] ?? 7.82;
      const eurAmount = cur === "EUR" ? amount : amount / (eurRates[cur] ?? 1);
      return `¥${(eurAmount * cnyRate).toFixed(2)}`;
    }
    const SYMBOLS: Record<string, string> = {
      USD: "$", EUR: "€", CNY: "¥", GBP: "£",
      CAD: "CA$", AUD: "A$", HKD: "HK$", SGD: "S$",
      NZD: "NZ$", TWD: "NT$", KRW: "₩", JPY: "¥",
    };
    const sym = SYMBOLS[cur] ?? (cur ? cur + "\u00a0" : "$");
    const decimals = ["JPY", "KRW"].includes(cur) ? 0 : 2;
    return `${sym}${amount.toFixed(decimals)}`;
  }

  type TianhuTranslation = { src: string; dst: string | null; parts: { part_name: string; means: string[] }[] } | null;
  const [tianhuTranslation, setTianhuTranslation] = React.useState<TianhuTranslation>(null);

  useEffect(() => {
    setTianhuTranslation(null);
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(target);
    if (!target || isIp) return;
    const timer = setTimeout(() => {
      fetch(`/api/tianhu/translate?domain=${encodeURIComponent(target)}`)
        .then((r) => r.json())
        .then((d) => { if (d.dst) setTianhuTranslation(d); })
        .catch(() => {});
    }, 400);
    return () => clearTimeout(timer);
  }, [target]);

  const current = getWindowHref();
  const queryType = detectQueryType(target);
  const { status, result, error, time, dnsProbe, registryUrl, cached, cachedAt, cacheTtl } = data as typeof data & { registryUrl?: string };

  const { data: session, status: sessionStatus } = useSession();

  // Auto-open the reminder dialog when navigated here with ?subscribe=1
  const autoOpenedRef = React.useRef(false);
  // Reset the guard whenever the domain changes so re-visiting with ?subscribe=1 always works
  const prevTargetRef = React.useRef(target);
  if (prevTargetRef.current !== target) {
    prevTargetRef.current = target;
    autoOpenedRef.current = false;
  }
  useEffect(() => {
    if (router.query.subscribe !== "1") return;
    if (sessionStatus === "loading") return;
    if (autoOpenedRef.current) return;
    autoOpenedRef.current = true;

    // Capture current path with ?subscribe=1 for use in callbacks before we clean the URL
    const pathWithSubscribe = router.asPath;
    // Remove the param from the URL cleanly (no re-fetch)
    const { subscribe: _s, ...rest } = router.query;
    router.replace({ pathname: router.pathname, query: rest }, undefined, { shallow: true });

    if (!session) {
      // Keep ?subscribe=1 in callbackUrl so the modal auto-opens after login
      router.push(`/login?callbackUrl=${encodeURIComponent(pathWithSubscribe)}`);
      return;
    }
    if (!(session?.user as any)?.subscriptionAccess) {
      toast.info(isChinese ? "需要开通会员才能使用域名订阅提醒" : "Subscription required to use domain reminders.", {
        action: { label: isChinese ? "去开通" : "Upgrade", onClick: () => router.push("/payment/checkout") },
      });
      return;
    }
    setReminderDialogOpen(true);
  }, [router.query.subscribe, sessionStatus]);

  const handleSearch = (query: string) => {
    const url = toSearchURI(query);
    if (url === router.asPath) return;
    const cleaned = cleanDomain(query.replace(/\s+/g, ""));
    if (cleaned) prefetchLookup(cleaned);
    // Shallow routing: URL changes but SSR is skipped entirely (~500 ms saved).
    // router.query updates → targetFromRouterQuery → setTarget → useEffect
    // re-fetches the new domain without unmounting/remounting the page.
    router.push(url, undefined, { shallow: true });
  };

  /** Force a fresh lookup for the current target (bypasses cache). */
  const handleRefresh = () => setRefreshKey((k) => k + 1);

  useEffect(() => {
    if (!status) return;
    const regStatus: RegStatus =
      status && result ? "registered" :
      dnsProbe?.registrationStatus === "unregistered" ? "unregistered" :
      dnsProbe?.registrationStatus === "registered" ? "registered" :
      "unknown";

    addHistory(target, regStatus);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, target]);

  const registrarIcon = result
    ? getRegistrarIcon(result.registrar, result.registrarURL)
    : null;
  const registrarInitial = result
    ? result.registrar && result.registrar !== "Unknown"
      ? result.registrar.charAt(0).toUpperCase()
      : "?"
    : "?";

  const displayStatuses = useMemo(() => {
    if (!result || result.status.length === 0) return [];
    if (result.status.length > 5 && !expandStatus)
      return result.status.slice(0, 5);
    return result.status;
  }, [result, expandStatus]);

  const hasIpFields =
    result &&
    ((result.cidr && result.cidr !== "Unknown") ||
      (result.netRange && result.netRange !== "Unknown") ||
      (result.netName && result.netName !== "Unknown") ||
      (result.netType && result.netType !== "Unknown") ||
      (result.originAS && result.originAS !== "Unknown") ||
      (result.inetNum && result.inetNum !== "Unknown") ||
      (result.inet6Num && result.inet6Num !== "Unknown"));

  const INVALID_FIELD_VALUES = new Set([
    "unknown", "n/a", "na", "none", "null", "undefined", "-", "--",
  ]);
  const isValidField = (v: string | null | undefined): boolean => {
    if (!v || !v.trim()) return false;
    return !INVALID_FIELD_VALUES.has(v.trim().toLowerCase());
  };

  const hasRegistrant =
    result &&
    (isValidField(result.registrantName) ||
      isValidField(result.registrantOrganization) ||
      isValidField(result.registrantCountry) ||
      isValidField(result.registrantProvince) ||
      isValidField(result.registrantCity) ||
      isValidField(result.registrantAddress) ||
      isValidField(result.registrantPostalCode) ||
      isValidField(result.registrantEmail) ||
      isValidField(result.registrantPhone) ||
      isValidField(result.registrantFax));

  const hasAdminContact =
    result &&
    (isValidField(result.adminName) ||
      isValidField(result.adminOrganization) ||
      isValidField(result.adminEmail) ||
      isValidField(result.adminPhone) ||
      isValidField(result.adminCountry));

  const hasTechContact =
    result &&
    (isValidField(result.techName) ||
      isValidField(result.techOrganization) ||
      isValidField(result.techEmail) ||
      isValidField(result.techPhone));

  return (
    <>
      <Head>
        <link rel="preconnect" href="https://www.nazhumi.com" />
        <link rel="preconnect" href="https://api.frankfurter.dev" />
        <link rel="dns-prefetch" href="https://www.miqingju.com" />
        {(() => {
          const r = result;
          const isRegistered = status && r;
          const registrar = isRegistered && r.registrar && r.registrar !== "Unknown" ? r.registrar : null;
          const creation = isRegistered && r.creationDate && r.creationDate !== "Unknown" ? r.creationDate : null;
          const expiry = isRegistered && r.expirationDate && r.expirationDate !== "Unknown" ? r.expirationDate : null;
          const ns = isRegistered && Array.isArray(r.nameServers) && r.nameServers.length > 0 ? r.nameServers[0] : null;
          const domainAge = isRegistered && typeof r.domainAge === "number" ? r.domainAge : null;
          const regStatus = !status
            ? "unknown"
            : r?.status?.some(s => s.status?.toLowerCase().includes("reserved")) ? "reserved"
            : r ? "registered" : "unknown";

          const isZhMeta = locale.startsWith("zh");
          const ogLocale = locale === "zh-tw" ? "zh_TW" : isZhMeta ? "zh_CN" : locale === "ja" ? "ja_JP" : locale === "ko" ? "ko_KR" : locale === "de" ? "de_DE" : locale === "fr" ? "fr_FR" : locale === "ru" ? "ru_RU" : "en_US";
          const metaLang = locale === "zh-tw" ? "zh-TW" : isZhMeta ? "zh-CN" : locale;

          const descParts: string[] = [isZhMeta
            ? `${displayTarget} 的 WHOIS / RDAP 查询结果`
            : `WHOIS / RDAP lookup result for ${displayTarget}`];
          if (regStatus === "registered") descParts.push(isZhMeta ? "已注册" : "Registered");
          if (registrar) descParts.push(isZhMeta ? `注册商：${registrar}` : `Registrar: ${registrar}`);
          if (creation) descParts.push(isZhMeta ? `注册：${creation.slice(0, 10)}` : `Created: ${creation.slice(0, 10)}`);
          if (expiry) descParts.push(isZhMeta ? `到期：${expiry.slice(0, 10)}` : `Expires: ${expiry.slice(0, 10)}`);
          if (domainAge) descParts.push(isZhMeta ? `域龄 ${domainAge} 天` : `${domainAge} days old`);
          if (ns) descParts.push(`NS: ${ns.toLowerCase()}`);
          const description = descParts.join(" · ");

          const keywords = isZhMeta
            ? [displayTarget, `${displayTarget} whois`, `${displayTarget} 域名查询`,
               `${displayTarget} 注册信息`, `${displayTarget} 到期时间`,
               ...(registrar ? [`${registrar} 域名`] : []),
               "域名查询", "whois查询", "rdap", "域名信息"].join(", ")
            : [displayTarget, `${displayTarget} whois`, `${displayTarget} domain lookup`,
               `${displayTarget} registration`, `${displayTarget} expiry`,
               ...(registrar ? [`${registrar} domain`] : []),
               "domain lookup", "whois lookup", "rdap", "domain info"].join(", ");

          const canonicalUrl = `${origin}/${target}`;
          // Build OG URL with embedded WHOIS fields so the edge handler skips
          // the internal /api/lookup fetch (saves 3-10 s on first crawl).
          const ogParams = new URLSearchParams();
          ogParams.set("query", target);
          ogParams.set("theme", "dark");
          if (r && isRegistered) {
            const ok = (v: unknown): v is string =>
              typeof v === "string" && v.length > 0 && v !== "Unknown";
            if (ok(r.registrar))              ogParams.set("reg", r.registrar.slice(0, 60));
            if (ok(r.creationDate))           ogParams.set("cr",  r.creationDate.slice(0, 10));
            if (ok(r.expirationDate))         ogParams.set("ex",  r.expirationDate.slice(0, 10));
            if (ok(r.updatedDate))            ogParams.set("up",  r.updatedDate.slice(0, 10));
            if (r.remainingDays != null)      ogParams.set("rd",  String(r.remainingDays));
            if (r.domainAge != null)          ogParams.set("age", String(r.domainAge));
            if (Array.isArray(r.nameServers) && r.nameServers.length > 0)
              ogParams.set("ns", r.nameServers.slice(0, 3).join(","));
            if (Array.isArray(r.status) && r.status.length > 0)
              ogParams.set("st", r.status.slice(0, 4).map((s: { status: string }) => s.status).join(","));
            if (ok(r.registrantCountry))      ogParams.set("co",  r.registrantCountry);
            if (ok(r.registrantOrganization)) ogParams.set("org", r.registrantOrganization.slice(0, 50));
            if (ok(r.dnssec))                 ogParams.set("dn",  r.dnssec.slice(0, 30));
            if (ok(r.whoisServer))            ogParams.set("ws",  r.whoisServer.slice(0, 60));
          }
          const ogImage = `${origin}/api/og?${ogParams.toString()}`;

          const jsonLd = JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": isZhMeta ? `${displayTarget} WHOIS 查询` : `${displayTarget} WHOIS Lookup`,
            "description": description,
            "url": canonicalUrl,
            "inLanguage": metaLang,
            "isPartOf": { "@type": "WebSite", "url": origin, "name": isZhMeta ? "RDAP+WHOIS 域名查询" : "RDAP+WHOIS Domain Lookup" },
            "about": {
              "@type": "Dataset",
              "name": isZhMeta ? `${displayTarget} 域名注册信息` : `${displayTarget} Domain Registration Info`,
              "description": description,
              "keywords": isZhMeta
                ? `${displayTarget}, whois, rdap, 域名注册, 域名查询`
                : `${displayTarget}, whois, rdap, domain registration, domain lookup`,
              ...(isRegistered && r ? {
                "temporalCoverage": creation && expiry ? `${creation.slice(0,10)}/${expiry.slice(0,10)}` : undefined,
              } : {}),
            },
            "breadcrumb": {
              "@type": "BreadcrumbList",
              "itemListElement": [
                { "@type": "ListItem", "position": 1, "name": isZhMeta ? "首页" : "Home", "item": origin },
                { "@type": "ListItem", "position": 2, "name": isZhMeta ? "域名查询" : "Domain Lookup", "item": `${origin}/` },
                { "@type": "ListItem", "position": 3, "name": displayTarget, "item": canonicalUrl },
              ],
            },
          });

          const metaTitle = isZhMeta
            ? `${displayTarget} WHOIS 查询 · 注册信息 · 到期时间`
            : `${displayTarget} WHOIS Lookup · Registration · Expiry`;
          const ogTitle = isZhMeta
            ? `${displayTarget} WHOIS 查询 · 注册信息`
            : `${displayTarget} WHOIS Lookup · Registration`;
          const twTitle = isZhMeta
            ? `${displayTarget} WHOIS 查询`
            : `${displayTarget} WHOIS Lookup`;

          return (
            <>
              <title key="title">{metaTitle}</title>
              <meta name="description" content={description} />
              <meta name="keywords" content={keywords} />
              <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1" />
              <link rel="canonical" href={canonicalUrl} />

              <meta property="og:type" content="website" />
              <meta property="og:url" content={canonicalUrl} />
              <meta property="og:title" content={ogTitle} />
              <meta property="og:description" content={description} />
              <meta property="og:image" content={ogImage} />
              <meta property="og:image:width" content="1200" />
              <meta property="og:image:height" content="630" />
              <meta property="og:locale" content={ogLocale} />

              <meta name="twitter:card" content="summary_large_image" />
              <meta name="twitter:title" content={twTitle} />
              <meta name="twitter:description" content={description} />
              <meta name="twitter:image" content={ogImage} />

              <script
                type="application/ld+json"
                dangerouslySetInnerHTML={{ __html: jsonLd }}
              />
            </>
          );
        })()}
      </Head>
      <ScrollArea ref={scrollAreaRef} className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 min-h-[calc(100vh-4rem)]">
          <div className="mb-6 relative z-10">
            <div className="relative group">
              <SearchBox
                initialValue={target}
                onSearch={handleSearch}
                loading={loading}
              />
              <div className="absolute left-4 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none opacity-50 group-hover:opacity-100 transition-opacity">
                <KeyboardShortcut k="/" />
              </div>
            </div>
            <SearchHotkeysText className="hidden sm:flex mt-2 px-1 justify-end" />
          </div>

          <div className="relative">
            <QueryProgressBar loading={loading} refreshing={refreshing} />
            <motion.div
              initial={false}
              animate={{ opacity: loading ? 0.85 : 1 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              style={{ pointerEvents: loading ? "none" : undefined }}
            >

          {result && (
            <div
              className="hidden sm:flex items-center flex-wrap gap-2 mb-6"
            >
              {result.registerPrice &&
                result.registerPrice.new !== -1 &&
                result.registerPrice.currency !== "Unknown" && (
                  <Link
                    target="_blank"
                    href={result.registerPrice.externalLink}
                    className="flex px-2 py-0.5 rounded-md border bg-background items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                  >
                    <RiBillLine className={cn("w-3 h-3 shrink-0", result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                    <span
                      className={cn(
                        "text-[11px] sm:text-xs font-normal",
                        result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground",
                      )}
                    >
                      {t("register_price")}
                      {formatRegistrarPrice(result.registerPrice.new as number, result.registerPrice.currency)}
                    </span>
                  </Link>
                )}
              {result.renewPrice &&
                result.renewPrice.renew !== -1 &&
                result.renewPrice.currency !== "Unknown" && (
                  <Link
                    href={result.renewPrice.externalLink}
                    target="_blank"
                    className="flex px-2 py-0.5 rounded-md border bg-background items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                  >
                    <RiExchangeDollarFill className={cn("w-3 h-3 shrink-0", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                    <span className={cn("text-[11px] sm:text-xs font-normal", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")}>
                      {t("renew_price")}
                      {formatRegistrarPrice(result.renewPrice.renew as number, result.renewPrice.currency)}
                    </span>
                  </Link>
                )}
              {result.negotiable !== null && (
                <div className="flex px-2 py-0.5 rounded-md border bg-background items-center space-x-1">
                  <RiExchangeDollarFill className="w-3 h-3 text-muted-foreground shrink-0" />
                  <span className="text-[11px] sm:text-xs font-normal text-muted-foreground">
                    {t("negotiable")}
                    <span className={result.negotiable ? "text-amber-500" : "text-emerald-600 dark:text-emerald-400"}>
                      {result.negotiable ? t("negotiable_yes") : t("negotiable_no")}
                    </span>
                  </span>
                </div>
              )}
              <div className="flex-grow" />
            </div>
          )}

          <AnimatePresence initial={false}>
          {loading && !status && (
            <motion.div
              key="skeleton"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, transition: { duration: 0.12, ease: "easeIn" } }}
              transition={{ duration: 0.18 }}
              className="grid grid-cols-1 gap-5"
            >
              <style>{`
                @keyframes sk-spin   { to { transform: rotate(360deg) } }
                @keyframes sk-ping   { 0%,100%{transform:scale(1);opacity:.7} 50%{transform:scale(1.14);opacity:1} }
                @keyframes sk-scan   { 0%{top:-6%;opacity:.55} 100%{top:108%;opacity:0} }
                @keyframes sk-step   { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:translateX(0)} }
                @keyframes sk-bar    { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
                .sk-shimbar { background: linear-gradient(90deg, hsl(var(--muted)/.45) 25%, hsl(var(--muted)/.7) 50%, hsl(var(--muted)/.45) 75%); background-size: 200% 100%; animation: sk-bar 1.6s ease-in-out infinite; }
              `}</style>

              {/* ── Lookup animation card ── */}
              <div className="glass-panel rounded-2xl border border-border/60 overflow-hidden">

                {/* Orb + steps */}
                <div className="flex flex-col items-center pt-10 pb-8 px-6 gap-6">

                  {/* Animated orb */}
                  <div className="relative flex items-center justify-center" style={{ width: 96, height: 96 }}>
                    {/* Outermost slow ring */}
                    <div className="absolute inset-0 rounded-full border-2 border-primary/10"
                      style={{ animation: "sk-ping 2.8s ease-in-out infinite" }} />
                    {/* Mid spinning ring */}
                    <div className="absolute rounded-full border-2 border-transparent"
                      style={{ inset: 8, borderTopColor: "hsl(var(--primary)/.55)", borderRightColor: "hsl(var(--primary)/.2)", animation: "sk-spin 1.1s linear infinite" }} />
                    {/* Inner pulse ring */}
                    <div className="absolute rounded-full border border-primary/20"
                      style={{ inset: 16, animation: "sk-ping 1.9s ease-in-out infinite 0.4s" }} />
                    {/* Core */}
                    <div className="relative z-10 w-10 h-10 rounded-full flex items-center justify-center"
                      style={{ background: "hsl(var(--primary)/.1)", border: "1.5px solid hsl(var(--primary)/.3)" }}>
                      <RiGlobalLine className="w-5 h-5 text-primary/60" />
                    </div>
                    {/* Scan line inside orb */}
                    <div className="absolute overflow-hidden pointer-events-none" style={{ inset: 8, borderRadius: "50%" }}>
                      <div className="absolute left-0 right-0 h-px"
                        style={{ background: "linear-gradient(90deg,transparent,hsl(var(--primary)/.5),transparent)", animation: "sk-scan 2s linear infinite" }} />
                    </div>
                  </div>

                  {/* Animated labels */}
                  <div className="text-center space-y-2">
                    <p className="text-sm font-semibold tracking-[0.06em] text-foreground/70 select-none">
                      {isChinese ? "正在查询…" : "Querying…"}
                    </p>
                    <p className="text-[11px] text-muted-foreground/45 select-none tracking-wide">
                      {isChinese ? "RDAP · WHOIS · DNS" : "RDAP · WHOIS · DNS"}
                    </p>
                  </div>

                  {/* Animated step list */}
                  <div className="w-full max-w-[280px] space-y-2">
                    {(isChinese
                      ? ["连接 RDAP 服务器…", "查询 WHOIS 数据库…", "解析注册信息…"]
                      : ["Connecting to RDAP server…", "Querying WHOIS database…", "Parsing registration data…"]
                    ).map((step, i) => (
                      <div key={i} className="flex items-center gap-2.5"
                        style={{ animation: "sk-step 0.35s ease both", animationDelay: `${0.28 + i * 0.42}s` }}>
                        <span className="w-1.5 h-1.5 rounded-full shrink-0 bg-primary/45 animate-pulse"
                          style={{ animationDelay: `${i * 0.3}s` }} />
                        <span className="text-[11px] text-muted-foreground/55 leading-none font-mono">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Bottom skeleton bars — preview of result layout */}
                <div className="border-t border-border/30 px-6 py-5 space-y-3">
                  <div className="grid grid-cols-3 gap-4">
                    {[["w-14","w-20"],["w-16","w-24"],["w-12","w-16"]].map(([a,b],i) => (
                      <div key={i} className="space-y-1.5">
                        <div className={cn("h-2.5 rounded-full sk-shimbar", a)} />
                        <div className={cn("h-3.5 rounded sk-shimbar", b)} />
                      </div>
                    ))}
                  </div>
                  <div className="space-y-1.5">
                    <div className="h-2.5 w-12 rounded-full sk-shimbar" />
                    <div className="h-3.5 w-40 rounded sk-shimbar" />
                  </div>
                  <div className="flex gap-2.5 pt-0.5">
                    <div className="h-7 w-20 rounded-lg sk-shimbar" />
                    <div className="h-7 w-20 rounded-lg sk-shimbar" style={{ opacity: 0.75 }} />
                    <div className="h-7 w-16 rounded-lg sk-shimbar" style={{ opacity: 0.55 }} />
                  </div>
                </div>
              </div>

              {/* ── Two secondary placeholder cards ── */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
                {[["w-24","w-full","w-4/5","w-3/5"],["w-20","w-full","w-3/4","w-2/3"]].map((ws, idx) => (
                  <div key={idx} className="glass-panel rounded-xl border border-border/50 p-5 space-y-3">
                    <div className={cn("h-3.5 rounded sk-shimbar", ws[0])} />
                    <div className="space-y-2">
                      {ws.slice(1).map((w,i) => <div key={i} className={cn("h-3 rounded sk-shimbar", w)} style={{ opacity: 1 - i * 0.15 }} />)}
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
          </AnimatePresence>

          {!loading && !status && (() => {
            const hasErrorRaw = !!(result && (result.rawWhoisContent || result.rawRdapContent));
            return (
            <motion.div
              key={target}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.26, ease: [0.22, 1, 0.36, 1], delay: 0.06 }}
            >
            <div
              className="grid grid-cols-1 lg:grid-cols-12 gap-6"
            >
              <div className={cn(hasErrorRaw ? "lg:col-span-8" : "lg:col-span-12", "space-y-6")}>
                {error === "INVALID_DOMAIN_TLD" ? (
                  <div className="glass-panel border border-amber-300/50 dark:border-amber-700/40 rounded-xl p-8 sm:p-12 text-center">
                    <div className="w-16 h-16 bg-amber-50 dark:bg-amber-950/30 rounded-full flex items-center justify-center mx-auto mb-5">
                      <RiErrorWarningLine className="w-8 h-8 text-amber-500" />
                    </div>
                    <Badge variant="outline" className="mb-4 font-mono text-[10px] font-bold uppercase tracking-wider text-amber-600 border-amber-400/50">
                      INVALID TLD
                    </Badge>
                    <h2 className="text-2xl font-bold mb-2">
                      {isChinese ? `".${target.split(".").pop()}" 不是真实的域名后缀` : `".${target.split(".").pop()}" isn't a real TLD`}
                    </h2>
                    <p className="text-muted-foreground max-w-md mx-auto text-sm leading-relaxed mb-2">
                      {isChinese
                        ? `我们查遍了 ICANN 的所有顶级域名列表，没找到 `
                        : `We searched the entire ICANN TLD registry and couldn't find `}
                      <span className="font-mono font-semibold text-foreground">{`.${target.split(".").pop()}`}</span>
                      {isChinese ? `。请检查拼写，常见的有 .com .net .org .io .cn` : `. Check for typos — try .com .net .org .io`}
                    </p>
                    <p className="text-xs text-muted-foreground/60 mb-8">
                      {isChinese ? "WHOIS 查询不支持不存在的后缀，这不是 bug，是常识。" : "WHOIS doesn't work for non-existent TLDs. Not a bug — just how the internet works."}
                    </p>
                    <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
                      <Link href="/">
                        <Button className="gap-2">
                          <RiSearchLine className="w-4 h-4" />
                          {isChinese ? "重新搜索" : "Search Again"}
                        </Button>
                      </Link>
                    </div>
                  </div>
                ) : dnsProbe?.registrationStatus === "registered" ? (
                  <>
                    <div className="glass-panel border border-emerald-400/40 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-xl p-6 sm:p-8 relative overflow-hidden">
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                        <div>
                          <div className="flex items-center gap-3 mb-2">
                            <Badge
                              variant="outline"
                              className="text-[10px] font-bold uppercase tracking-wider font-mono"
                            >
                              {queryType}
                            </Badge>
                          </div>
                          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-1 uppercase">
                            {displayTarget}
                          </h2>
                          <p className="text-muted-foreground text-sm mt-2 max-w-sm leading-relaxed">
                            {t("registered_no_whois_desc")}
                          </p>
                        </div>
                        <div className="flex flex-col items-start sm:items-end gap-2 shrink-0">
                          <Badge
                            variant="outline"
                            className="text-emerald-600 border-emerald-400/50 bg-emerald-50 dark:bg-emerald-950/30 font-medium"
                          >
                            <div className="w-2 h-2 rounded-full bg-emerald-500 mr-1.5" />
                            {t("registered_no_whois")}
                          </Badge>
                          <span className="text-[10px] text-muted-foreground font-mono">
                            {time.toFixed(2)}s
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-3">
                      <Button variant="outline" size="sm" onClick={handleRefresh}>
                        {t("re_query")}
                      </Button>
                      {registryUrl && (
                        <a href={registryUrl} target="_blank" rel="noopener noreferrer">
                          <Button variant="outline" size="sm" className="gap-2">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                            {t("registry_lookup")}
                          </Button>
                        </a>
                      )}
                      <Link href="/">
                        <Button variant="outline" size="sm">{t("new_search")}</Button>
                      </Link>
                    </div>
                  </>
                ) : dnsProbe?.registrationStatus === "unregistered" ? (
                  <AvailableDomainCard domain={target} locale={locale} isPremiumByWhois={result ? getDomainRegistrationStatus(result, locale).isPremiumReserved : false} />
                ) : (
                  <>
                    <div className="glass-panel border border-border rounded-xl p-8 sm:p-12 text-center">
                      <div className="w-16 h-16 bg-red-50 dark:bg-red-950/30 rounded-full flex items-center justify-center mx-auto mb-6">
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          width="32"
                          height="32"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          className="text-red-500"
                        >
                          <path d="m21 21-4.3-4.3" />
                          <circle cx="11" cy="11" r="8" />
                          <path d="m8 8 6 6" />
                          <path d="m14 8-6 6" />
                        </svg>
                      </div>
                      <h2 className="text-2xl font-bold mb-2">
                        {t("lookup_failed")}
                      </h2>
                      <p className="text-muted-foreground max-w-md mx-auto text-sm leading-relaxed mb-8">
                        {t("lookup_failed_description")}{" "}
                        <span className="font-mono font-medium text-foreground">
                          {target}
                        </span>
                        {". "}
                        {error || t("lookup_failed_fallback")}
                      </p>
                      <div className="flex flex-col sm:flex-row items-center justify-center gap-3 flex-wrap">
                        <Button onClick={handleRefresh}>
                          {t("try_again")}
                        </Button>
                        {registryUrl && (
                          <a href={registryUrl} target="_blank" rel="noopener noreferrer">
                            <Button variant="outline" className="gap-2">
                              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                              {isChinese ? "在注册局查询" : "Look up at Registry"}
                            </Button>
                          </a>
                        )}
                        <Link href="/">
                          <Button variant="outline">{t("new_search")}</Button>
                        </Link>
                      </div>
                    </div>
                  </>
                )}

                {/* External search engine links — controlled by admin toggle */}
                {queryType === "domain" && enableSearchLinks && (
                  <div className="glass-panel border border-border rounded-xl p-5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                      <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
                      </svg>
                      {isChinese ? "在搜索引擎中查询" : "Search Engine Lookup"}
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {/* Google search for the domain */}
                      <a
                        href={`https://www.google.com/search?q=${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                          <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                          <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                          <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                          <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Google
                      </a>
                      {/* Bing search for the domain */}
                      <a
                        href={`https://www.bing.com/search?q=${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg width="13" height="13" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                          <path d="M5 3v14.544l4.038 2.285 7.103-4.55-4.442-1.59V5.98L5 3zm4.038 10.285 3.647 1.305-3.647 2.337v-3.642z" fill="#0078D4"/>
                        </svg>
                        Bing
                      </a>
                      {/* Baidu search for the domain */}
                      <a
                        href={`https://www.baidu.com/s?wd=${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                          <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 2.5a7.5 7.5 0 1 1 0 15 7.5 7.5 0 0 1 0-15z" fill="#2932E1"/>
                          <text x="12" y="16" textAnchor="middle" fontSize="9" fontWeight="bold" fill="#2932E1">百</text>
                        </svg>
                        {isChinese ? "百度" : "Baidu"}
                      </a>
                      {/* Google site: check if this page is indexed */}
                      <a
                        href={`https://www.google.com/search?q=site:x.rw/${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg className="w-3 h-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                        </svg>
                        {isChinese ? "谷歌收录查询" : "Google Index Check"}
                      </a>
                      {/* Bing site: check */}
                      <a
                        href={`https://www.bing.com/search?q=site:x.rw/${encodeURIComponent(displayTarget)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-background hover:bg-muted/60 text-xs font-medium transition-colors"
                      >
                        <svg className="w-3 h-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
                        </svg>
                        {isChinese ? "必应收录查询" : "Bing Index Check"}
                      </a>
                    </div>
                  </div>
                )}

                {dnsProbe?.registrationStatus !== "registered" &&
                dnsProbe?.registrationStatus !== "unregistered" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                  <div className="glass-panel border border-border rounded-xl p-6">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                      <svg
                        className="w-4 h-4"
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <circle cx="12" cy="12" r="10" />
                        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                        <line x1="12" y1="17" x2="12.01" y2="17" />
                      </svg>
                      {t("common_issues")}
                    </h3>
                    <ul className="space-y-3">
                      {[
                        {
                          title: t("issue_invalid_tld"),
                          desc: t("issue_invalid_tld_desc"),
                        },
                        {
                          title: t("issue_not_registered"),
                          desc: t("issue_not_registered_desc"),
                        },
                        {
                          title: t("issue_rate_limited"),
                          desc: t("issue_rate_limited_desc"),
                        },
                      ].map((item) => (
                        <li key={item.title} className="flex items-start gap-2">
                          <div className="mt-1.5 w-1 h-1 rounded-full bg-muted-foreground/30 shrink-0" />
                          <p className="text-[11px] text-muted-foreground leading-normal">
                            <strong className="text-foreground">
                              {item.title}:
                            </strong>{" "}
                            {item.desc}
                          </p>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="glass-panel border border-border rounded-xl p-6">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4 flex items-center gap-2">
                      <RiTimeLine className="w-4 h-4" />
                      {t("query_details")}
                    </h3>
                    <div className="space-y-3 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground font-mono uppercase">
                          {t("target")}
                        </span>
                        <span className="font-mono font-medium">{target}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground font-mono uppercase">
                          {t("type")}
                        </span>
                        <Badge
                          variant="outline"
                          className="text-[10px] font-mono"
                        >
                          {queryType}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground font-mono uppercase">
                          {t("time")}
                        </span>
                        <span className="font-mono">{time.toFixed(2)}s</span>
                      </div>
                    </div>
                  </div>
                </div>
                )}
              </div>

              {hasErrorRaw && !hideRawWhois && (
                <div className="lg:col-span-4">
                  <ResponsePanel
                    whoisContent={result!.rawWhoisContent || ""}
                    rdapContent={result!.rawRdapContent}
                    target={target}
                    copy={copy}
                  />
                </div>
              )}
            </div>
            </motion.div>
            );
          })()}

          {status && result && (
            <>
              <motion.div
                variants={CARD_CONTAINER_VARIANTS}
                initial="hidden"
                animate="visible"
                className="grid grid-cols-1 lg:grid-cols-12 gap-6"
              >
                {" "}
                <motion.div variants={CARD_ITEM_VARIANTS} className="lg:col-span-8 space-y-6">
                  <div className="glass-panel border border-border rounded-xl p-6 sm:p-8 relative overflow-hidden">
                    {(() => {
                      const rc = result.registrantCountry?.trim().toUpperCase();
                      const hasCountryDot = !!rc && rc !== "UNKNOWN" && rc in GLOBE_COUNTRY_COORDS;
                      return (
                        <div className={cn(
                          "absolute top-3 right-2 select-none w-[120px] h-[120px]",
                          hasCountryDot ? "opacity-80 z-10" : "opacity-60 pointer-events-none overflow-hidden"
                        )}>
                          <CssGlobe countryCode={hasCountryDot ? rc : undefined} />
                        </div>
                      );
                    })()}
                    <div className="relative z-10">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge
                          variant="outline"
                          className="text-[10px] font-bold uppercase tracking-wider font-mono"
                        >
                          {queryType}
                        </Badge>
                        <button
                          onClick={() => {
                            if (!session) {
                              toast.info(isChinese ? "请先登录再订阅域名提醒" : "Please log in to subscribe for reminders");
                              router.push(`/login?callbackUrl=${encodeURIComponent(`/${result.domain || target}`)}`);
                              return;
                            }
                            if (!(session?.user as any)?.subscriptionAccess) {
                              toast.info(isChinese ? "需要开通会员才能使用域名订阅提醒" : "Subscription required to use domain reminders.", {
                                action: { label: isChinese ? "去开通" : "Upgrade", onClick: () => router.push("/payment/checkout") },
                              });
                              return;
                            }
                            setReminderDialogOpen(true);
                          }}
                          title={isChinese ? "域名订阅" : "Subscribe"}
                          className={cn(
                            "sm:hidden flex items-center justify-center w-6 h-6 rounded-full text-xs border transition-all active:scale-[0.93]",
                            (result.remainingDays !== null && result.remainingDays <= 30)
                              ? "bg-red-100 dark:bg-red-900/30 border-red-400/60 text-red-500"
                              : "bg-muted/50 border-border/50 text-muted-foreground hover:border-sky-400/50 hover:text-sky-500",
                          )}
                        >
                          <RiTimerLine className="w-3 h-3" />
                        </button>
                        {isOfficialDomain ? (
                          <button
                            onClick={(e) => {
                              const rect = e.currentTarget.getBoundingClientRect();
                              if (officialPopoverOpen) {
                                setOfficialPopoverOpen(false);
                                setOfficialPopoverPos(null);
                              } else {
                                setOfficialPopoverOpen(true);
                                setOfficialPopoverPos({ bottom: window.innerHeight - rect.top + 10, centerX: rect.left + rect.width / 2, isMobile: window.innerWidth < 640 });
                              }
                            }}
                            className={cn(
                              "stamp-claimed-badge sm:hidden flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border transition-all active:scale-[0.93]",
                              officialPopoverOpen
                                ? "bg-blue-100 dark:bg-blue-900/40 border-blue-500/80 text-blue-700 dark:text-blue-300"
                                : "bg-blue-50 dark:bg-blue-900/20 border-blue-400/60 text-blue-600 dark:text-blue-400"
                            )}
                          >
                            <RiGlobalLine className="w-3 h-3" />
                            {isChinese ? "官网认证" : "Official"}
                          </button>
                        ) : verifiedStamps.length > 0 ? (
                          <button
                            onClick={() => setStampDetailOpen(true)}
                            className="stamp-claimed-badge sm:hidden flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border transition-all active:scale-[0.93] bg-teal-50 dark:bg-teal-900/20 border-teal-400/50 text-teal-600 dark:text-teal-400"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                            {isChinese ? "已认领" : "Claimed"}
                          </button>
                        ) : (
                          <button
                            onClick={() => {
                              const domain = result.domain || target;
                              if (!session) {
                                router.push(`/login?callbackUrl=${encodeURIComponent(`/stamp?domain=${encodeURIComponent(domain)}`)}`);
                                return;
                              }
                              router.push(`/stamp?domain=${encodeURIComponent(domain)}`);
                            }}
                            title={isChinese ? "认领域名" : "Claim domain"}
                            className="sm:hidden flex items-center justify-center w-6 h-6 rounded-full text-xs border transition-all active:scale-[0.93] bg-muted/50 border-border/50 text-muted-foreground hover:border-violet-400/50 hover:text-violet-500"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                      <div className="flex items-start gap-2 mb-1">
                        <motion.h2
                          className="text-3xl sm:text-4xl font-bold tracking-tight cursor-pointer hover:opacity-80 transition-opacity uppercase select-none"
                          onClick={() => copy(result.domain || target)}
                          whileTap={{ scale: 0.97 }}
                          transition={{ type: "spring", stiffness: 500, damping: 30 }}
                        >
                          {result.domain || displayTarget}
                        </motion.h2>
                        <button
                          onClick={() => copy(result.domain || target)}
                          title={isChinese ? "复制域名" : "Copy domain"}
                          className="mt-1 shrink-0 text-muted-foreground/40 hover:text-muted-foreground transition-colors"
                        >
                          <RiFileCopyLine className="w-4 h-4" />
                        </button>
                      </div>
                      {result.domainPunycode && (
                        <p
                          className="text-xs text-muted-foreground font-mono mb-3 cursor-pointer hover:opacity-70 transition-opacity"
                          onClick={() => copy(result.domainPunycode!)}
                        >
                          {result.domainPunycode}
                        </p>
                      )}
                      {!result.domainPunycode && <div className="mb-3" />}
                      <div className="flex items-center gap-2 flex-wrap">
                        {result.remainingDays !== null ? (
                          result.remainingDays <= 0 ? (
                            <Badge className="bg-red-500 hover:bg-red-600 text-white border-0">
                              <div className="w-2 h-2 rounded-full bg-white/80 animate-pulse mr-1.5" />
                              {t("expired")}
                            </Badge>
                          ) : result.remainingDays <= 60 ? (
                            <Badge className="bg-amber-500 hover:bg-amber-600 text-white border-0">
                              <div className="w-2 h-2 rounded-full bg-white/80 animate-pulse mr-1.5" />
                              {t("expiring_soon")}
                            </Badge>
                          ) : (
                            <Badge className="bg-primary hover:bg-primary/90 text-primary-foreground border-0">
                              <div className="w-2 h-2 rounded-full bg-emerald-400 mr-1.5" />
                              {t("active")}
                            </Badge>
                          )
                        ) : (
                          (() => {
                            const regStatus = getDomainRegistrationStatus(result, locale);
                            return (
                              <Badge
                                variant="outline"
                                className={cn("font-medium", regStatus.color)}
                              >
                                <div className={cn("w-2 h-2 rounded-full mr-1.5", regStatus.dotColor)} />
                                {regStatus.label}
                              </Badge>
                            );
                          })()
                        )}
                        {result.domainAge !== null && (
                          <div className="flex items-center gap-1 px-2 py-0.5 rounded-md border border-primary/30 bg-primary/5">
                            <RiTimeLine className="w-3 h-3 text-primary shrink-0" />
                            <span className="text-[11px] font-normal text-primary">
                              {result.domainAge === 0 ? "<1" : result.domainAge}{" "}
                              {result.domainAge === 1 ? t("year") : t("years")}
                            </span>
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-3 flex-wrap">
                        {/* Mobile-only price tags (moved from above on mobile) */}
                        {result.registerPrice &&
                          result.registerPrice.new !== -1 &&
                          result.registerPrice.currency !== "Unknown" && (
                            <Link
                              target="_blank"
                              href={result.registerPrice.externalLink}
                              className="sm:hidden px-2 py-0.5 rounded-md border bg-background flex items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                            >
                              <RiBillLine className={cn("w-3 h-3 shrink-0", result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                              <span className={cn("text-[11px] font-normal", result.registerPrice.isPremium ? "text-amber-500" : "text-muted-foreground")}>
                                {t("register_price")}
                                {formatRegistrarPrice(result.registerPrice.new as number, result.registerPrice.currency)}
                              </span>
                            </Link>
                          )}
                        {result.renewPrice &&
                          result.renewPrice.renew !== -1 &&
                          result.renewPrice.currency !== "Unknown" && (
                            <Link
                              href={result.renewPrice.externalLink}
                              target="_blank"
                              className="sm:hidden px-2 py-0.5 rounded-md border bg-background flex items-center space-x-1 cursor-pointer hover:border-muted-foreground/50 transition-colors"
                            >
                              <RiExchangeDollarFill className={cn("w-3 h-3 shrink-0", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")} />
                              <span className={cn("text-[11px] font-normal", result.renewPrice.isPremium ? "text-amber-500" : "text-muted-foreground")}>
                                {t("renew_price")}
                                {formatRegistrarPrice(result.renewPrice.renew as number, result.renewPrice.currency)}
                              </span>
                            </Link>
                          )}
                        {result.negotiable !== null && (
                          <div className="sm:hidden px-2 py-0.5 rounded-md border bg-background flex items-center space-x-1">
                            <RiExchangeDollarFill className="w-3 h-3 text-muted-foreground shrink-0" />
                            <span className="text-[11px] font-normal text-muted-foreground">
                              {t("negotiable")}
                              <span className={result.negotiable ? "text-amber-500" : "text-emerald-600 dark:text-emerald-400"}>
                                {result.negotiable ? t("negotiable_yes") : t("negotiable_no")}
                              </span>
                            </span>
                          </div>
                        )}
                        {/* Desktop-only Subscribe text button */}
                        <button
                          onClick={() => {
                            if (!session) {
                              toast.info(isChinese ? "请先登录再订阅域名提醒" : "Please log in to subscribe for reminders");
                              router.push(`/login?callbackUrl=${encodeURIComponent(`/${result.domain || target}`)}`);
                              return;
                            }
                            if (!(session?.user as any)?.subscriptionAccess) {
                              toast.info(isChinese ? "需要开通会员才能使用域名订阅提醒" : "Subscription required to use domain reminders.", {
                                action: { label: isChinese ? "去开通" : "Upgrade", onClick: () => router.push("/payment/checkout") },
                              });
                              return;
                            }
                            setReminderDialogOpen(true);
                          }}
                          className={cn(
                            "hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border transition-all active:scale-[0.93]",
                            (result.remainingDays !== null && result.remainingDays <= 30)
                              ? "bg-red-100 dark:bg-red-900/30 border-red-400/60 text-red-500"
                              : "bg-muted/50 border-border/50 text-muted-foreground hover:border-sky-400/50 hover:text-sky-500",
                          )}
                        >
                          <RiTimerLine className="w-3 h-3" />
                          {isChinese ? "域名订阅" : "Subscribe"}
                        </button>
                        {isOfficialDomain ? (
                          <button
                            onClick={(e) => {
                              const rect = e.currentTarget.getBoundingClientRect();
                              if (officialPopoverOpen) {
                                setOfficialPopoverOpen(false);
                                setOfficialPopoverPos(null);
                              } else {
                                setOfficialPopoverOpen(true);
                                setOfficialPopoverPos({ bottom: window.innerHeight - rect.top + 10, centerX: rect.left + rect.width / 2, isMobile: window.innerWidth < 640 });
                              }
                            }}
                            className={cn(
                              "stamp-claimed-badge hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border transition-all active:scale-[0.93]",
                              officialPopoverOpen
                                ? "bg-blue-100 dark:bg-blue-900/40 border-blue-500/80 text-blue-700 dark:text-blue-300"
                                : "bg-blue-50 dark:bg-blue-900/20 border-blue-400/60 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40"
                            )}
                          >
                            <RiGlobalLine className="w-3 h-3" />
                            {isChinese ? "官网认证" : "Official"}
                          </button>
                        ) : verifiedStamps.length > 0 ? (
                          <button
                            onClick={() => setStampDetailOpen(true)}
                            className="stamp-claimed-badge hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border transition-all active:scale-[0.93] bg-teal-50 dark:bg-teal-900/20 border-teal-400/50 text-teal-600 dark:text-teal-400 hover:bg-teal-100 dark:hover:bg-teal-900/40"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                            {isChinese ? "已认领" : "Claimed"}
                          </button>
                        ) : (
                          <button
                            onClick={() => {
                              const domain = result.domain || target;
                              if (!session) {
                                router.push(`/login?callbackUrl=${encodeURIComponent(`/stamp?domain=${encodeURIComponent(domain)}`)}`);
                                return;
                              }
                              router.push(`/stamp?domain=${encodeURIComponent(domain)}`);
                            }}
                            className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border transition-all active:scale-[0.93] bg-muted/50 border-border/50 text-muted-foreground hover:border-violet-400/50 hover:text-violet-500"
                          >
                            <RiShieldCheckLine className="w-3 h-3" />
                            {isChinese ? "域名认领" : "Claim"}
                          </button>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {time.toFixed(2)}s
                          {cached && (
                            <>
                              {" · "}
                              {cachedAt && typeof window !== "undefined" ? (() => {
                                const ageMs = Date.now() - cachedAt;
                                const ageMins = Math.floor(ageMs / 60_000);
                                const ageHrs = Math.floor(ageMs / 3_600_000);
                                const ageStr = ageHrs >= 1
                                  ? isChinese ? `${ageHrs}小时前缓存` : `cached ${ageHrs}h ago`
                                  : ageMins >= 1
                                    ? isChinese ? `${ageMins}分钟前缓存` : `cached ${ageMins}m ago`
                                    : isChinese ? "刚刚缓存" : "cached just now";
                                return <span suppressHydrationWarning title={new Date(cachedAt).toLocaleString()}>{ageStr}</span>;
                              })() : t("cached")}
                              {cacheTtl && cacheTtl > 0 && (
                                <span className="opacity-60">
                                  {" "}(TTL {cacheTtl >= 3600
                                    ? `${Math.round(cacheTtl / 3600)}h`
                                    : cacheTtl >= 60
                                      ? `${Math.round(cacheTtl / 60)}m`
                                      : `${cacheTtl}s`})
                                </span>
                              )}
                            </>
                          )}
                          {data.source && (
                            <>
                              {" · "}
                              {(data.source === "tian.hu" || data.source === "YISI.YUN") ? (
                                <a
                                  href={data.source === "tian.hu" ? "https://tian.hu" : "https://yisi.yun"}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  title={isChinese ? "通过第三方 API 获取" : "Via third-party API"}
                                  className="text-amber-500/80 hover:text-amber-500 hover:underline transition-colors"
                                >
                                  {data.source}
                                </a>
                              ) : (
                                data.source
                              )}
                            </>
                          )}
                        </span>
                        {refreshing && (
                          <span className="flex items-center gap-1 text-[10px] text-primary/60 font-mono animate-pulse">
                            <RiLoader4Line className="w-2.5 h-2.5 animate-spin" />
                            {isChinese ? "更新中" : "Updating"}
                          </span>
                        )}
                        <div className="ml-auto flex items-center gap-1">
                          <button
                            onClick={() => setFeedbackOpen(true)}
                            title={t("feedback.issue_title")}
                            className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-muted-foreground hover:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-950/30 border border-transparent hover:border-amber-300/50 transition-all"
                          >
                            <RiErrorWarningLine className="w-3.5 h-3.5" />
                            {t("feedback.title")}
                          </button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <button
                                title={t("share")}
                                className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-muted-foreground hover:text-blue-500 hover:bg-blue-50 dark:hover:bg-blue-950/30 border border-transparent hover:border-blue-300/50 transition-all"
                              >
                                <RiShareLine className="w-3.5 h-3.5" />
                                {t("share")}
                              </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="min-w-[200px]">
                              <DropdownMenuLabel className="text-xs text-muted-foreground">
                                {t("share")}
                              </DropdownMenuLabel>
                              <DropdownMenuItem asChild>
                                <Link href={`https://twitter.com/intent/tweet?text=${encodeURIComponent(`Whois Lookup: ${target}`)}&url=${encodeURIComponent(current)}`} target="_blank">
                                  <RiTwitterXLine className="w-4 h-4 mr-2" />Twitter / X
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(current)}`} target="_blank">
                                  <RiFacebookFill className="w-4 h-4 mr-2" />Facebook
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://reddit.com/submit?url=${encodeURIComponent(current)}`} target="_blank">
                                  <RiRedditLine className="w-4 h-4 mr-2" />Reddit
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://api.whatsapp.com/send?text=${encodeURIComponent(current)}`} target="_blank">
                                  <RiWhatsappLine className="w-4 h-4 mr-2" />WhatsApp
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuItem asChild>
                                <Link href={`https://t.me/share/url?url=${encodeURIComponent(current)}`} target="_blank">
                                  <RiTelegramLine className="w-4 h-4 mr-2" />Telegram
                                </Link>
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem onClick={() => copy(current)}>
                                <RiLinkM className="w-4 h-4 mr-2" />{t("copy_url")}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuLabel className="text-xs text-muted-foreground">
                                {t("image")}
                              </DropdownMenuLabel>
                              <DropdownMenuItem
                                onClick={async () => {
                                  const ogUrl = buildOgUrl(target, result);
                                  const tid = toast.loading(isZh ? "正在生成图片…" : "Generating image…");
                                  try {
                                    const res = await fetch(ogUrl);
                                    const blob = await res.blob();
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement("a");
                                    a.href = url;
                                    a.download = `whois-${target}.png`;
                                    a.click();
                                    URL.revokeObjectURL(url);
                                    toast.success(t("toast.downloaded"), { id: tid });
                                  } catch {
                                    toast.error(t("toast.download_failed"), { id: tid });
                                  }
                                }}
                              >
                                <RiDownloadLine className="w-4 h-4 mr-2" />{t("download_png")}
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={async () => {
                                  const ogUrl = buildOgUrl(target, result);
                                  const tid = toast.loading(isZh ? "正在生成图片…" : "Generating image…");
                                  try {
                                    const res = await fetch(ogUrl);
                                    const blob = await res.blob();
                                    await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
                                    toast.success(t("toast.copied_to_clipboard"), { id: tid });
                                  } catch {
                                    toast.error(t("toast.copy_to_clipboard_failed"), { id: tid });
                                  }
                                }}
                              >
                                <RiFileCopyLine className="w-4 h-4 mr-2" />{t("copy_image")}
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => setShowImagePreview(true)}>
                                <RiCameraLine className="w-4 h-4 mr-2" />{t("preview_customize")}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                    </div>

                    {tianhuTranslation && tianhuTranslation.dst && (
                      <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.2 }}
                        className="flex flex-wrap items-center gap-x-3 gap-y-1.5 mt-3 px-3 py-2 rounded-lg bg-violet-50/60 dark:bg-violet-950/20 border border-violet-200/50 dark:border-violet-800/30"
                      >
                        <span className="text-[11px] font-mono text-muted-foreground/60 shrink-0">
                          {isChinese ? "含义" : "Meaning"}
                        </span>
                        <span className="text-[13px] font-semibold text-violet-700 dark:text-violet-300">
                          {tianhuTranslation.dst}
                        </span>
                        {tianhuTranslation.parts.flatMap((p, pi) =>
                          p.means.slice(0, 3).map((m, i) => (
                            <span key={`${pi}-${i}`} className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                              {i === 0 && p.part_name && (
                                <span className="text-[10px] font-medium text-muted-foreground/50 border border-border/40 rounded px-1 py-px">
                                  {p.part_name}
                                </span>
                              )}
                              {m}
                            </span>
                          ))
                        )}
                      </motion.div>
                    )}

                    {officialPopoverOpen && officialPopoverPos && typeof window !== "undefined" && ReactDOM.createPortal(
                      (() => {
                        const domainKey = (result?.domain || target || "").toLowerCase().replace(/^www\./, "");
                        const domainInfo = OFFICIAL_DOMAIN_DESC[domainKey];
                        const domainName = domainInfo?.name || (result?.domain || target || "").split(".")[0].toUpperCase();
                        const domainDesc = isChinese
                          ? (domainInfo?.zh || "该域名已被识别为全球知名主流网站，系统自动授予官网认证标识，无需人工审核。")
                          : (domainInfo?.en || "Recognized as a globally mainstream website and auto-certified without manual review.");
                        const isMob = officialPopoverPos.isMobile;
                        return (
                          <>
                            <motion.div
                              key="official-popover-backdrop"
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              className="fixed inset-0 z-[9998]"
                              style={{ background: isMob ? "rgba(0,0,0,0.35)" : "transparent" }}
                              onClick={() => { setOfficialPopoverOpen(false); setOfficialPopoverPos(null); }}
                            />
                            <AnimatePresence>
                              {isMob ? (
                                <div
                                  key="official-popover-mobile-wrapper"
                                  style={{ position: "fixed", inset: 0, zIndex: 9999, display: "flex", alignItems: "center", justifyContent: "center", pointerEvents: "none" }}
                                >
                                  <motion.div
                                    initial={{ opacity: 0, scale: 0.92, y: 20 }}
                                    animate={{ opacity: 1, scale: 1, y: 0 }}
                                    exit={{ opacity: 0, scale: 0.94, y: 16 }}
                                    transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                                    style={{ pointerEvents: "auto", width: "calc(100vw - 40px)", maxWidth: "320px" }}
                                    onClick={e => e.stopPropagation()}
                                  >
                                    <div className="rounded-2xl border border-blue-200/70 dark:border-blue-700/50 bg-white dark:bg-zinc-900 shadow-2xl shadow-blue-500/15 overflow-hidden relative">
                                      <div className="h-[3px] w-full bg-gradient-to-r from-blue-400 via-sky-400 to-indigo-500" />
                                      <div className="px-4 pt-4 pb-5">
                                        <div className="flex items-center gap-3 mb-3">
                                          <div className="relative shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/40 dark:to-indigo-900/40 border border-blue-200/60 dark:border-blue-700/50 flex items-center justify-center overflow-hidden">
                                            <DomainFavicon domain={domainKey} size={20} fallback={<RiGlobalLine className="w-5 h-5 text-blue-500" />} />
                                            <motion.span className="absolute inset-0 rounded-xl border-2 border-blue-400/40" animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }} transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }} />
                                          </div>
                                          <div className="min-w-0">
                                            <div className="flex items-center gap-1.5 flex-wrap">
                                              <p className="text-[13.5px] font-bold text-foreground leading-tight">{domainName}</p>
                                              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 border border-blue-200/60 dark:border-blue-700/40">
                                                <RiCheckLine className="w-2.5 h-2.5 text-blue-500" />
                                                <span className="text-[9.5px] text-blue-500 font-semibold leading-none">{isChinese ? "官网认证" : "Verified"}</span>
                                              </span>
                                            </div>
                                            <p className="text-[10px] text-muted-foreground mt-0.5">{isChinese ? "系统自动认证 · 无需人工审核" : "Auto-certified · No manual review"}</p>
                                          </div>
                                        </div>
                                        <p className="text-[11px] text-muted-foreground leading-relaxed">{domainDesc}</p>
                                        <button
                                          onClick={() => { setOfficialPopoverOpen(false); setOfficialPopoverPos(null); }}
                                          className="mt-4 w-full py-2 rounded-xl bg-blue-50 dark:bg-blue-900/30 border border-blue-200/50 dark:border-blue-700/40 text-[12px] font-semibold text-blue-600 dark:text-blue-400 active:scale-[0.97] transition-transform"
                                        >
                                          {isChinese ? "我知道了" : "Got it"}
                                        </button>
                                      </div>
                                    </div>
                                  </motion.div>
                                </div>
                              ) : (
                                <motion.div
                                  key="official-popover-portal-desktop"
                                  initial={{ opacity: 0, y: 8, scale: 0.94 }}
                                  animate={{ opacity: 1, y: 0, scale: 1 }}
                                  exit={{ opacity: 0, y: 5, scale: 0.96 }}
                                  transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                                  style={{ position: "fixed", bottom: `${officialPopoverPos.bottom}px`, left: `${officialPopoverPos.centerX}px`, transform: "translateX(-50%)", width: "260px", zIndex: 9999 }}
                                  onClick={e => e.stopPropagation()}
                                >
                                  <div className="rounded-2xl border border-blue-200/70 dark:border-blue-700/50 bg-white dark:bg-zinc-900 shadow-2xl shadow-blue-500/15 overflow-hidden relative">
                                    <div className="h-[3px] w-full bg-gradient-to-r from-blue-400 via-sky-400 to-indigo-500" />
                                    <div className="px-4 pt-4 pb-4">
                                      <div className="flex items-center gap-3 mb-3">
                                        <div className="relative shrink-0 w-10 h-10 rounded-xl bg-gradient-to-br from-blue-100 to-indigo-100 dark:from-blue-900/40 dark:to-indigo-900/40 border border-blue-200/60 dark:border-blue-700/50 flex items-center justify-center overflow-hidden">
                                          <DomainFavicon domain={domainKey} size={20} fallback={<RiGlobalLine className="w-5 h-5 text-blue-500" />} />
                                          <motion.span className="absolute inset-0 rounded-xl border-2 border-blue-400/40" animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }} transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }} />
                                        </div>
                                        <div className="min-w-0">
                                          <div className="flex items-center gap-1.5 flex-wrap">
                                            <p className="text-[13.5px] font-bold text-foreground leading-tight">{domainName}</p>
                                            <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full bg-blue-50 dark:bg-blue-900/30 border border-blue-200/60 dark:border-blue-700/40">
                                              <RiCheckLine className="w-2.5 h-2.5 text-blue-500" />
                                              <span className="text-[9.5px] text-blue-500 font-semibold leading-none">{isChinese ? "官网认证" : "Verified"}</span>
                                            </span>
                                          </div>
                                          <p className="text-[10px] text-muted-foreground mt-0.5">{isChinese ? "系统自动认证 · 无需人工审核" : "Auto-certified · No manual review"}</p>
                                        </div>
                                      </div>
                                      <p className="text-[11px] text-muted-foreground leading-relaxed">{domainDesc}</p>
                                    </div>
                                    <div className="absolute -bottom-[7px] left-1/2 -translate-x-1/2 w-3.5 h-3.5 rotate-45 bg-white dark:bg-zinc-900 border-r border-b border-blue-200/70 dark:border-blue-700/50" />
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </>
                        );
                      })(),
                      document.body
                    )}

                    <FeedbackDrawer
                      open={feedbackOpen}
                      onOpenChange={setFeedbackOpen}
                      query={result.domain || target}
                      queryType={queryType}
                    />

                    <DomainReminderDialog
                      domain={result.domain || target}
                      expirationDate={result.expirationDate}
                      remainingDays={result.remainingDays}
                      open={reminderDialogOpen}
                      onOpenChange={setReminderDialogOpen}
                      isZh={isChinese}
                      userEmail={session?.user?.email ?? ""}
                      registerPriceFmt={
                        result.registerPrice && result.registerPrice.new !== -1 && result.registerPrice.currency !== "Unknown"
                          ? formatRegistrarPrice(result.registerPrice.new as number, result.registerPrice.currency)
                          : undefined
                      }
                      renewPriceFmt={
                        result.renewPrice && result.renewPrice.renew !== -1 && result.renewPrice.currency !== "Unknown"
                          ? formatRegistrarPrice(result.renewPrice.renew as number, result.renewPrice.currency)
                          : undefined
                      }
                      isPremium={result.registerPrice?.isPremium ?? false}
                      eppStatuses={result.status?.map((s) => s.status) ?? []}
                      regStatusType={getDomainRegistrationStatus(result, locale).type}
                    />

                    {result.remainingDays === null &&
                      (() => {
                        const regStatus = getDomainRegistrationStatus(result, locale);
                        if (regStatus.type === "registered") return null;
                        const cnInfo = getCnReservedSldInfo(result.domain);
                        const premiumCustomDesc =
                          regStatus.type === "reserved" && regStatus.isPremiumReserved
                            ? {
                                zh: "该域名已被注册局列入高价值保留名单，目前正等待有缘人上门购买。如有意向，请直接联系该 TLD 注册局咨询报价与购买流程。",
                                en: "This domain is held in the registry's reserved list as a high-value premium name. It may be available for purchase at a premium price — contact the registry directly to inquire about pricing and the acquisition process.",
                              }
                            : undefined;
                        return (
                          <DomainStatusInfoCard
                            type={regStatus.type}
                            locale={locale}
                            customDesc={
                              cnInfo && regStatus.type === "reserved"
                                ? { zh: cnInfo.descZh, en: cnInfo.descEn }
                                : premiumCustomDesc
                            }
                          />
                        );
                      })()}

                    {(result.creationDate !== "Unknown" ||
                      result.expirationDate !== "Unknown" ||
                      result.updatedDate !== "Unknown") && (
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-6 mt-8 pt-8 border-t border-border/50">
                        {result.creationDate &&
                          result.creationDate !== "Unknown" && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                {t("whois_fields.creation_date")}
                              </p>
                              <p className="font-mono text-sm font-medium">
                                {formatDate(result.creationDate)}
                              </p>
                              <p className="text-[10px] text-muted-foreground mt-0.5">
                                {getRelativeTime(result.creationDate, t)}
                              </p>
                            </div>
                          )}
                        {result.expirationDate &&
                          result.expirationDate !== "Unknown" && (
                            <div>
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                {t("whois_fields.expiration_date")}
                              </p>
                              <p className="font-mono text-sm font-medium">
                                {formatDate(result.expirationDate)}
                              </p>
                              <p
                                className={cn(
                                  "text-[10px] mt-0.5 font-medium",
                                  result.remainingDays !== null &&
                                    result.remainingDays > 60
                                    ? "text-emerald-600 dark:text-emerald-400"
                                    : result.remainingDays !== null &&
                                        result.remainingDays <= 30
                                      ? "text-red-600 dark:text-red-400"
                                      : "text-amber-600 dark:text-amber-400",
                                )}
                              >
                                {result.remainingDays !== null
                                  ? result.remainingDays > 0
                                    ? t("d_remaining", {
                                        days: result.remainingDays,
                                      })
                                    : t("expired")
                                  : getRelativeTime(result.expirationDate, t)}
                              </p>
                            </div>
                          )}
                        {result.updatedDate &&
                          result.updatedDate !== "Unknown" && (
                            <div className="col-span-2 sm:col-span-1">
                              <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                {t("whois_fields.updated_date")}
                              </p>
                              <p className="font-mono text-sm font-medium">
                                {formatDate(result.updatedDate)}
                              </p>
                              <p className="text-[10px] text-muted-foreground mt-0.5">
                                {getRelativeTime(result.updatedDate, t)}
                              </p>
                            </div>
                          )}
                      </div>
                    )}

                    {/* Stamp detail dialog — triggered by "已认领" badge */}
                    <Dialog open={stampDetailOpen} onOpenChange={setStampDetailOpen}>
                      <DialogContent hideClose className="max-w-[360px] p-0 overflow-hidden gap-0 rounded-[22px]">
                        <DialogHeader className="sr-only">
                          <DialogTitle>{isChinese ? "品牌认领信息" : "Claimed Brand"}</DialogTitle>
                        </DialogHeader>
                        <div className="divide-y divide-border/30">
                          {verifiedStamps.map((stamp) => {
                            const labelMap: Record<string, { zh: string; en: string }> = {
                              personal: { zh: "个人认领", en: "Personal"  },
                              official: { zh: "官方认证", en: "Official"  },
                              brand:    { zh: "品牌认领", en: "Brand"     },
                              verified: { zh: "已认证",   en: "Verified"  },
                              partner:  { zh: "合作伙伴", en: "Partner"   },
                              dev:      { zh: "开发者",   en: "Developer" },
                              warning:  { zh: "注意",     en: "Warning"   },
                              premium:  { zh: "高级认证", en: "Premium"   },
                            };
                            const lbl = labelMap[stamp.tagStyle] ?? { zh: "已认领", en: "Claimed" };

                            return (
                              <div key={stamp.id} className="relative">
                                <button
                                  onClick={() => setStampDetailOpen(false)}
                                  className="absolute top-3 right-3 w-6 h-6 flex items-center justify-center rounded-full bg-black/20 hover:bg-black/45 text-white transition-all hover:scale-110 active:scale-95 z-20"
                                  aria-label="Close"
                                >
                                  <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                                    <path d="M1 1l8 8M9 1L1 9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
                                  </svg>
                                </button>
                                <StampPreviewCard
                                  themeKey={stamp.cardTheme}
                                  locale={isChinese ? "zh" : "en"}
                                  data={{
                                    tagName: stamp.tagName,
                                    domain: result.domain || target,
                                    description: stamp.description,
                                    link: stamp.link || undefined,
                                    tagLabel: isChinese ? lbl.zh : lbl.en,
                                  }}
                                />
                              </div>
                            );
                          })}
                        </div>
                      </DialogContent>
                    </Dialog>

                    {hasRegistrant && (
                      <div className="mt-6 pt-6 border-t border-border/50 space-y-4">
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                          {[
                            {
                              label: t("whois_fields.registrant_name"),
                              value: result.registrantName,
                            },
                            {
                              label: t("whois_fields.registrant_organization"),
                              value: result.registrantOrganization,
                            },
                            {
                              label: t("whois_fields.registrant_country"),
                              value: result.registrantCountry,
                              country: true,
                            },
                            {
                              label: t("whois_fields.registrant_province"),
                              value: result.registrantProvince,
                            },
                            {
                              label: t("whois_fields.registrant_city"),
                              value: result.registrantCity,
                            },
                            {
                              label: t("whois_fields.registrant_address"),
                              value: result.registrantAddress,
                            },
                            {
                              label: t("whois_fields.registrant_postal_code"),
                              value: result.registrantPostalCode,
                            },
                            {
                              label: t("whois_fields.registrant_email"),
                              value: result.registrantEmail,
                            },
                            {
                              label: t("whois_fields.registrant_phone"),
                              value: result.registrantPhone,
                            },
                            {
                              label: t("whois_fields.registrant_fax"),
                              value: result.registrantFax,
                            },
                          ]
                            .filter((f) => isValidField(f.value))
                            .map((f, i) => (
                              <div key={i} className="min-w-0">
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                  {f.label}
                                </p>
                                <p className="text-xs font-mono whitespace-pre-wrap break-all flex items-center gap-1.5">
                                  {"country" in f &&
                                    f.country &&
                                    f.value &&
                                    /^[A-Z]{2}$/i.test(f.value.trim()) && (
                                      <img
                                        src={`https://flagcdn.com/w40/${f.value.trim().toLowerCase()}.png`}
                                        alt=""
                                        className="w-4 h-3 object-cover rounded-[2px]"
                                      />
                                    )}
                                  {f.value}
                                </p>
                              </div>
                            ))}
                        </div>

                        {/* Admin contact */}
                        {hasAdminContact && (
                          <div className="pt-3 border-t border-border/30">
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-2">
                              {t("whois_fields.admin_contact")}
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                              {[
                                { label: t("whois_fields.admin_name"), value: result.adminName },
                                { label: t("whois_fields.admin_organization"), value: result.adminOrganization },
                                { label: t("whois_fields.admin_country"), value: result.adminCountry, country: true },
                                { label: t("whois_fields.admin_email"), value: result.adminEmail },
                                { label: t("whois_fields.admin_phone"), value: result.adminPhone },
                              ]
                                .filter((f) => isValidField(f.value))
                                .map((f, i) => (
                                  <div key={i} className="min-w-0">
                                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-0.5">
                                      {f.label}
                                    </p>
                                    <p className="text-xs font-mono break-all flex items-center gap-1.5">
                                      {"country" in f && f.country && f.value && /^[A-Z]{2}$/i.test(f.value.trim()) && (
                                        <img src={`https://flagcdn.com/w40/${f.value.trim().toLowerCase()}.png`} alt="" className="w-4 h-3 object-cover rounded-[2px]" />
                                      )}
                                      {f.value}
                                    </p>
                                  </div>
                                ))}
                            </div>
                          </div>
                        )}

                        {/* Tech contact */}
                        {hasTechContact && (
                          <div className="pt-3 border-t border-border/30">
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold mb-2">
                              {t("whois_fields.tech_contact")}
                            </p>
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                              {[
                                { label: t("whois_fields.tech_name"), value: result.techName },
                                { label: t("whois_fields.tech_organization"), value: result.techOrganization },
                                { label: t("whois_fields.tech_email"), value: result.techEmail },
                                { label: t("whois_fields.tech_phone"), value: result.techPhone },
                              ]
                                .filter((f) => isValidField(f.value))
                                .map((f, i) => (
                                  <div key={i} className="min-w-0">
                                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-0.5">
                                      {f.label}
                                    </p>
                                    <p className="text-xs font-mono break-all">{f.value}</p>
                                  </div>
                                ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Mobile-only inline ad — above status / nameservers cards */}
                  <ResultTextAd loading={loading} inline />

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                    {result.status.length > 0 && (
                      <div className="glass-panel border border-border rounded-xl p-5">
                        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                          <svg
                            className="w-4 h-4 text-muted-foreground"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.5"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          >
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            <path d="m9 12 2 2 4-4" />
                          </svg>
                          {t("whois_fields.status")}
                        </h3>
                        <div className="space-y-2.5">
                          {displayStatuses.map((s, i) => {
                            const info = getEppStatusInfo(s.status);
                            const color = getEppStatusColor(s.status);
                            const displayName = getEppStatusDisplayName(
                              s.status,
                            );
                            const link = getEppStatusLink(s.status);
                            return (
                              <div key={i} className="flex items-start gap-2.5">
                                <span
                                  className="w-1.5 h-1.5 rounded-full shrink-0 mt-[0.65rem]"
                                  style={{ backgroundColor: color }}
                                />
                                <div className="min-w-0">
                                  <a
                                    href={link}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs font-mono font-medium leading-tight hover:underline"
                                  >
                                    {displayName}
                                  </a>
                                  <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
                                    {info
                                      ? getEppStatusDescription(s.status, locale)
                                      : locale === "zh" || locale === "zh-tw"
                                        ? "注册局特定状态码，暂无标准释义。请参阅对应注册局文档了解详情。"
                                        : "Registry-specific status code with no standard description. Refer to the registry's documentation for details."}
                                  </p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                        {result.status.length > 5 && (
                          <button
                            onClick={() => setExpandStatus(!expandStatus)}
                            className="text-xs text-muted-foreground hover:text-foreground transition-colors font-medium mt-3"
                          >
                            {expandStatus
                              ? t("show_less")
                              : t("more_count", {
                                  count: result.status.length - 5,
                                })}
                          </button>
                        )}
                      </div>
                    )}

                    {result.nameServers.length > 0 && (
                      <div className="glass-panel border border-border rounded-xl p-5 flex flex-col">
                        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                          <RiServerLine className="w-4 h-4 text-muted-foreground" />
                          {t("whois_fields.name_servers")}
                        </h3>
                        <div className="space-y-2">
                          {result.nameServers.map((ns, i) => {
                            const nsBrand = getNsBrand(ns);
                            return (
                              <motion.div
                                key={i}
                                className="flex items-center gap-3 p-2 bg-muted/30 border border-border/50 rounded-md cursor-pointer hover:bg-muted/50 transition-colors"
                                onClick={() => copy(ns)}
                                whileTap={{ scale: 0.97 }}
                                whileHover={{ x: 2 }}
                                transition={{ type: "spring", stiffness: 500, damping: 30 }}
                              >
                                {nsBrand ? (
                                  nsBrand.slug ? (
                                    nsBrand.slug.startsWith("/") ? (
                                      <div className="w-4 h-4 shrink-0 flex items-center justify-center">
                                        <img
                                          src={nsBrand.slug}
                                          alt=""
                                          className="w-3.5 h-3.5 object-contain rounded-sm"
                                        />
                                      </div>
                                    ) : (
                                      <div className="w-4 h-4 shrink-0 flex items-center justify-center">
                                        <img
                                          src={resolveIconUrl(
                                            nsBrand.slug,
                                            nsBrand.color,
                                            false,
                                          )}
                                          alt=""
                                          className="w-3.5 h-3.5 object-contain dark:hidden"
                                        />
                                        <img
                                          src={resolveIconUrl(
                                            nsBrand.slug,
                                            nsBrand.color,
                                            true,
                                          )}
                                          alt=""
                                          className="w-3.5 h-3.5 object-contain hidden dark:block"
                                        />
                                      </div>
                                    )
                                  ) : (
                                    <div
                                      className="w-4 h-4 rounded-full shrink-0 flex items-center justify-center text-white text-[8px] font-bold"
                                      style={{ backgroundColor: nsBrand.color }}
                                    >
                                      {nsBrand.brand.charAt(0)}
                                    </div>
                                  )
                                ) : (
                                  <div className="w-2 h-2 rounded-full bg-emerald-500 shrink-0 ml-1" />
                                )}
                                <span className="font-mono text-xs text-muted-foreground truncate flex-1">
                                  {ns}
                                </span>
                                {nsBrand && (
                                  <span className="text-[9px] text-muted-foreground/60 shrink-0">
                                    {nsBrand.brand}
                                  </span>
                                )}
                              </motion.div>
                            );
                          })}
                        </div>
                        {result.dnssec && (
                          <div className="mt-auto pt-4 border-t border-border/50 flex justify-between items-center">
                            <span className="text-[10px] text-muted-foreground font-medium uppercase">
                              {t("whois_fields.dnssec")}
                            </span>
                            <span className="text-xs font-mono text-muted-foreground">
                              {translateDnssecValue(result.dnssec, locale)}
                            </span>
                          </div>
                        )}
                      </div>
                    )}


                    {hasIpFields && (
                      <div className="glass-panel border border-border rounded-xl p-5">
                        <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
                          <RiGlobalLine className="w-4 h-4 text-muted-foreground" />
                          {t("whois_fields.network_info")}
                        </h3>
                        <div className="space-y-3">
                          {[
                            {
                              label: t("whois_fields.cidr"),
                              value: result.cidr,
                            },
                            {
                              label: t("whois_fields.net_range"),
                              value: result.netRange,
                            },
                            {
                              label: t("whois_fields.net_name"),
                              value: result.netName,
                            },
                            {
                              label: t("whois_fields.net_type"),
                              value: result.netType,
                            },
                            {
                              label: t("whois_fields.origin_as"),
                              value: result.originAS,
                            },
                            {
                              label: t("whois_fields.inet_num"),
                              value: result.inetNum,
                            },
                            {
                              label: t("whois_fields.inet6_num"),
                              value: result.inet6Num,
                            },
                          ]
                            .filter((f) => isValidField(f.value))
                            .map((f, i) => (
                              <div key={i}>
                                <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium mb-1">
                                  {f.label}
                                </p>
                                <p className="font-mono text-xs">{f.value}</p>
                              </div>
                            ))}
                        </div>
                      </div>
                    )}
                  </div>

                </motion.div>
                <motion.div variants={CARD_ITEM_VARIANTS} className="lg:col-span-4 relative overflow-hidden">
                  <div className="flex flex-col gap-6 lg:absolute lg:inset-0 lg:overflow-y-auto">
                    {isValidField(result.registrar) && (() => {
                      const hasAbuseContact = isValidField(result.abuseEmail) || isValidField(result.abusePhone);
                      const hasRegistrantContact = isValidField(result.registrantName) || isValidField(result.registrantOrganization) || isValidField(result.registrantEmail) || isValidField(result.registrantPhone) || isValidField(result.registrantCountry) || isValidField(result.registrantProvince) || isValidField(result.registrantCity) || isValidField(result.registrantAddress) || isValidField(result.registrantPostalCode) || isValidField(result.registrantFax) || hasAdminContact || hasTechContact;
                      return (
                      <div className="glass-panel border border-border rounded-xl overflow-hidden shrink-0">
                        {/* Header: icon + name + IANA */}
                        <div className="p-5 pb-4">
                          <div className="flex items-center justify-between mb-3">
                            <h3 className="text-sm font-semibold">{t("whois_fields.registrar")}</h3>
                            {isValidField(result.ianaId) && (
                              <Link
                                href={`https://www.internic.net/registrars/registrar-${result.ianaId}.html`}
                                target="_blank"
                                className="text-[10px] bg-muted px-2 py-0.5 rounded text-muted-foreground font-mono hover:bg-muted/80 transition-colors"
                              >
                                IANA: {result.ianaId}
                              </Link>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            {registrarIcon && registrarIcon.slug ? (
                              registrarIcon.slug.startsWith("/") ? (
                                <div className="w-10 h-10 bg-white dark:bg-zinc-800 rounded-lg flex items-center justify-center p-1.5 border shrink-0">
                                  <img src={registrarIcon.slug} alt="" className="w-full h-full object-contain rounded-md" />
                                </div>
                              ) : (
                                <div className="w-10 h-10 bg-white dark:bg-zinc-800 rounded-lg flex items-center justify-center p-1.5 border shrink-0">
                                  <img src={resolveIconUrl(registrarIcon.slug, registrarIcon.color, false)} alt="" className="w-full h-full object-contain dark:hidden" />
                                  <img src={resolveIconUrl(registrarIcon.slug, registrarIcon.color, true)} alt="" className="w-full h-full object-contain hidden dark:block" />
                                </div>
                              )
                            ) : (
                              <div className="w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold text-lg shrink-0"
                                style={{ backgroundColor: registrarIcon ? registrarIcon.color : getRegistrarFallbackColor(result.registrar) }}>
                                {registrarInitial}
                              </div>
                            )}
                            <div className="min-w-0 flex-1">
                              <p className="font-semibold text-sm leading-tight">{result.registrar}</p>
                              {isValidField(result.registrarURL) && (
                                <a href={result.registrarURL.startsWith("http") ? result.registrarURL : `http://${result.registrarURL}`}
                                  target="_blank" rel="noopener noreferrer"
                                  className="text-[11px] text-blue-600 dark:text-blue-400 hover:underline break-all">
                                  {result.registrarURL}
                                </a>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Registrar technical info */}
                        {(isValidField(result.whoisServer) || isValidField(result.registryDomainId)) && (
                          <div className="border-t border-border/50 px-5 py-3 space-y-2.5">
                            {isValidField(result.whoisServer) && (
                              <div className="flex items-start justify-between gap-3">
                                <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{t("whois_fields.whois_server")}</span>
                                <span className="text-xs font-mono text-foreground/80 break-all text-right">{result.whoisServer}</span>
                              </div>
                            )}
                            {isValidField(result.registryDomainId) && (
                              <div className="flex items-start justify-between gap-3">
                                <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{t("whois_fields.registry_domain_id")}</span>
                                <span className="text-xs font-mono text-foreground/80 break-all text-right">{result.registryDomainId}</span>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Abuse contact */}
                        {hasAbuseContact && (
                          <div className="border-t border-border/50 px-5 py-3">
                            <p className="text-[10px] uppercase font-semibold text-muted-foreground/60 tracking-wider mb-2">
                              {isZh ? "滥用联系" : "Abuse Contact"}
                            </p>
                            <div className="space-y-2">
                              {isValidField(result.abuseEmail) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "邮箱" : "Email"}</span>
                                  <a href={`mailto:${result.abuseEmail}`} className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all text-right">{result.abuseEmail}</a>
                                </div>
                              )}
                              {isValidField(result.abusePhone) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "电话" : "Phone"}</span>
                                  <span className="text-xs font-mono text-foreground/80 text-right">{result.abusePhone}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Registrant contact */}
                        {hasRegistrantContact && (
                          <div className="border-t border-border/50 px-5 py-3">
                            <p className="text-[10px] uppercase font-semibold text-muted-foreground/60 tracking-wider mb-2">
                              {isZh ? "注册人信息" : "Registrant"}
                            </p>
                            <div className="space-y-2">
                              {isValidField(result.registrantName) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "姓名" : "Name"}</span>
                                  <span className="text-xs text-foreground/80 text-right break-all">{result.registrantName}</span>
                                </div>
                              )}
                              {isValidField(result.registrantOrganization) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "机构" : "Org"}</span>
                                  <span className="text-xs text-foreground/80 text-right break-all">{result.registrantOrganization}</span>
                                </div>
                              )}
                              {(isValidField(result.registrantCountry) || isValidField(result.registrantProvince)) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "地区" : "Location"}</span>
                                  <span className="text-xs text-foreground/80 text-right">
                                    {[result.registrantProvince, result.registrantCountry].filter(v => isValidField(v)).join(", ")}
                                  </span>
                                </div>
                              )}
                              {isValidField(result.registrantEmail) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "邮箱" : "Email"}</span>
                                  <a href={`mailto:${result.registrantEmail}`} className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all text-right">{result.registrantEmail}</a>
                                </div>
                              )}
                              {isValidField(result.registrantPhone) && (
                                <div className="flex items-start justify-between gap-3">
                                  <span className="text-[10px] uppercase font-medium text-muted-foreground/70 tracking-wide shrink-0 pt-0.5">{isZh ? "电话" : "Phone"}</span>
                                  <span className="text-xs font-mono text-foreground/80 text-right">{result.registrantPhone}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                      );
                    })()}

                    {(result.rawWhoisContent || result.rawRdapContent) && !hideRawWhois && (
                      <div className="flex-1 min-h-[250px]">
                        <ResponsePanel
                          whoisContent={result.rawWhoisContent}
                          rdapContent={result.rawRdapContent}
                          target={target}
                          copy={copy}
                        />
                      </div>
                    )}
                  </div>
                </motion.div>
              </motion.div>
            </>
          )}

          {/* Text ad — shown after successful result, desktop only (mobile version is inline) */}
          <ResultTextAd loading={loading} />

            </motion.div>
          </div>
        </main>
      </ScrollArea>
      <Dialog open={showImagePreview} onOpenChange={setShowImagePreview}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("image_preview")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">{t("width")}</Label>
                <Input
                  type="number"
                  value={imgWidth}
                  onChange={(e) =>
                    setImgWidth(
                      Math.min(
                        4096,
                        Math.max(200, parseInt(e.target.value) || 1200),
                      ),
                    )
                  }
                  className="h-8 text-xs font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("height")}</Label>
                <Input
                  type="number"
                  value={imgHeight}
                  onChange={(e) =>
                    setImgHeight(
                      Math.min(
                        4096,
                        Math.max(200, parseInt(e.target.value) || 630),
                      ),
                    )
                  }
                  className="h-8 text-xs font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{t("theme")}</Label>
                <Select
                  value={imgTheme}
                  onValueChange={(v: "light" | "dark") => setImgTheme(v)}
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="light">{t("light")}</SelectItem>
                    <SelectItem value="dark">{t("dark")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="rounded-lg border overflow-hidden bg-muted/30">
              <img
                src={buildOgUrl(target, result, {
                  w: imgWidth,
                  h: imgHeight,
                  theme: imgTheme,
                })}
                alt="OG Preview"
                className="w-full h-auto"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                disabled={imgActing !== null}
                onClick={async () => {
                  const ogUrl = buildOgUrl(target, result, {
                    w: imgWidth,
                    h: imgHeight,
                    theme: imgTheme,
                  });
                  setImgActing("download");
                  try {
                    const res = await fetch(ogUrl);
                    const blob = await res.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `whois-${target}-${imgWidth}x${imgHeight}.png`;
                    a.click();
                    URL.revokeObjectURL(url);
                    toast.success(t("toast.downloaded"));
                  } catch {
                    toast.error(t("toast.download_failed"));
                  } finally {
                    setImgActing(null);
                  }
                }}
              >
                {imgActing === "download"
                  ? <><RiLoader4Line className="w-3.5 h-3.5 mr-1.5 animate-spin" />{t("toast.generating")}</>
                  : <><RiDownloadLine className="w-3.5 h-3.5 mr-1.5" />{t("download")}</>
                }
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={imgActing !== null}
                onClick={async () => {
                  const ogUrl = buildOgUrl(target, result, {
                    w: imgWidth,
                    h: imgHeight,
                    theme: imgTheme,
                  });
                  setImgActing("copy");
                  try {
                    const res = await fetch(ogUrl);
                    const blob = await res.blob();
                    await navigator.clipboard.write([
                      new ClipboardItem({ "image/png": blob }),
                    ]);
                    toast.success(t("toast.copied_to_clipboard"));
                  } catch {
                    toast.error(t("toast.copy_to_clipboard_failed"));
                  } finally {
                    setImgActing(null);
                  }
                }}
              >
                {imgActing === "copy"
                  ? <><RiLoader4Line className="w-3.5 h-3.5 mr-1.5 animate-spin" />{t("toast.generating")}</>
                  : <><RiFileCopyLine className="w-3.5 h-3.5 mr-1.5" />{t("copy")}</>
                }
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const ogUrl = buildOgUrl(target, result, {
                    w: imgWidth,
                    h: imgHeight,
                    theme: imgTheme,
                  });
                  copy(window.location.origin + ogUrl);
                }}
              >
                <RiLinkM className="w-3.5 h-3.5 mr-1.5" />
                {t("copy_link")}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
