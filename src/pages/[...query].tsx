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
import { REGISTRAR_ICONS } from "@/data/query-page/registrar-icons";
import { NS_BRANDS } from "@/data/query-page/ns-brands";
import { GLOBE_COUNTRY_COORDS } from "@/data/query-page/globe-coords";
import { MAINSTREAM_DOMAINS } from "@/data/query-page/mainstream-domains";
import { OFFICIAL_DOMAIN_DESC } from "@/data/query-page/official-domain-desc";
import { QueryProgressBar } from "@/components/query/query-progress-bar";
import { QueryLoadingSkeleton } from "@/components/query/query-loading-skeleton";
import { CssGlobe } from "@/components/query/css-globe";
import { ResponsePanel } from "@/components/query/response-panel";
import { OgImageDialog } from "@/components/query/OgImageDialog";
import { SharePanel } from "@/components/query/SharePanel";
import { RegistrarCard } from "@/components/query/RegistrarCard";
import { DomainLifecycleSection } from "@/components/query/DomainLifecycleSection";
import { WhoisFieldsTable } from "@/components/query/WhoisFieldsTable";
import { DomainReminderDialog } from "@/components/query/DomainReminderDialog";
import { AvailableDomainCard, DomainFavicon } from "@/components/query/AvailableDomainCard";
import { RegistrationStatusType } from "@/lib/domain-status-types";
import { getDomainRegistrationStatus, DomainStatusInfoCard } from "@/components/query/DomainStatusHelpers";
import { FeedbackDrawer } from "@/components/feedback-drawer";

// Shared validity check used by both getServerSideProps (SSR) and the
// client-side useEffect.  A "query" must have a dot (domain/IP), be an ASN
// (AS12345), or be an IPv6 address.  Bare words like "zhouzhouw" are invalid.
function looksLikeDomainQuery(t: string | undefined | null): boolean {
  if (!t || typeof t !== "string") return false;
  return (
    !t.startsWith(".") &&
    (t.includes(".") ||
      /^AS\d+$/i.test(t) ||
      /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(t))
  );
}

const CARD_CONTAINER_VARIANTS = {
  hidden: { opacity: 1 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.025, delayChildren: 0.03 },
  },
};

const CARD_ITEM_VARIANTS = {
  hidden: { opacity: 0, y: 5 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] },
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

export async function getServerSideProps(context: GetServerSidePropsContext) {
  try {
  return await _getServerSidePropsImpl(context);
  } catch (err) {
    // Safety net: any unexpected error (encoding issues, library throws, etc.)
    // renders the "invalid domain" result page instead of a 500 crash.
    const querySegments: string[] = (context.params?.query as string[]) ?? [];
    const rawFallbackTarget = querySegments.join("/");
    const fallbackTarget = rawFallbackTarget || "unknown";
    console.error("[getServerSideProps] Unhandled error for query", fallbackTarget, err);
    return {
      props: {
        data: {
          time: 0,
          status: false,
          cached: false,
          error: "INVALID_DOMAIN_TLD",
        } as WhoisResult,
        target: fallbackTarget,
        displayTarget: fallbackTarget,
        origin: getOrigin(context.req),
      },
    };
  }
}

async function _getServerSidePropsImpl(context: GetServerSidePropsContext) {
  const querySegments: string[] = (context.params?.query as string[]) ?? [];
  const origin = getOrigin(context.req);

  // ── Strip locale prefix from catch-all segments ───────────────────────────
  // URLs no longer include a locale prefix.  Old bookmarked URLs like
  // /zh/x.rw or /en/x.rw are 301-redirected to /x.rw for canonicality.
  const VALID_LOCALES = new Set(["en", "zh", "zh-tw", "de", "ru", "ja", "fr", "ko"]);
  const hasLocalePrefix =
    querySegments.length >= 2 && VALID_LOCALES.has(querySegments[0]);
  if (hasLocalePrefix) {
    // encodeURI preserves valid URI chars (/ . - _) but encodes non-ASCII
    // characters (emoji, CJK surrogate pairs, etc.) so the HTTP Location
    // header never contains raw Unicode, which causes FUNCTION_INVOCATION_FAILED
    // on Vercel (HTTP headers must be ISO-8859-1 safe).
    const rawPath = "/" + querySegments.slice(1).join("/");
    const safePath = encodeURI(rawPath);
    return { redirect: { destination: safePath, permanent: true } };
  }
  const effectiveSegments = querySegments;

  // ── Smart URL cleaning + canonical redirect ──────────────────────────────
  // Strip spaces first (handles URL-encoded spaces like %20 decoded to " ")
  // then run cleanDomain which strips protocols, paths, ports, auth, etc.
  const rawPath = effectiveSegments.join("/");
  const spacelessPath = rawPath.replace(/\s+/g, "");
  const target = cleanDomain(spacelessPath);
  const displayTarget = targetToDisplayName(target);

  // If cleaning changed the URL (spaces removed, protocol stripped, path trimmed…),
  // redirect to the canonical clean URL to avoid duplicate/broken results.
  // Always use encodeURI so non-ASCII characters (emoji, CJK surrogates, etc.)
  // are percent-encoded in the HTTP Location header (required by HTTP spec).
  if (looksLikeDomainQuery(target) && `/${target}` !== `/${rawPath}`) {
    return { redirect: { destination: encodeURI(`/${target}`), permanent: false } };
  }

  // If it still doesn't look like any known query type, delegate to the 404 page.
  // Real app routes (/admin, /dashboard, /login, etc.) are handled by their own
  // Next.js pages BEFORE reaching this catch-all, so anything arriving here
  // with no dot / IP / ASN pattern is a genuinely invalid user input (e.g. a
  // mistyped URL or bare word with no TLD).  Showing the interactive 404 page
  // (which has a pre-filled search box) is a far better experience than a
  // generic "Invalid Domain" error card inside the WHOIS results layout.
  if (!looksLikeDomainQuery(target)) {
    return { notFound: true };
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

  // ── IDNA / encoding safety check ────────────────────────────────────────
  // Guard against domain labels that contain control characters, surrogates,
  // or other byte sequences that would cause Net/DNS modules to throw.
  // Note: emoji ARE handled by Node.js domainToASCII (converts to punycode),
  // so we only reject truly unprocessable inputs here.  Any domain that passes
  // this guard but still has no WHOIS/RDAP data will show "not found" — that
  // is the correct user experience for an unregistered or invalid domain.
  if (target.includes(".")) {
    let asciiEncoded: string | null = null;
    try {
      // domainToASCII is a Node.js built-in — require() at call-site to prevent
      // webpack from bundling it into the client-side JavaScript chunk.
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { domainToASCII } = require("url") as typeof import("url");
      asciiEncoded = domainToASCII(target.toLowerCase());
    } catch {
      asciiEncoded = null; // surrogate pairs or other unprocessable input
    }
    if (asciiEncoded === null || asciiEncoded === "") {
      // domainToASCII returned "" (null bytes, control chars) or threw
      // (malformed Unicode) → unprocessable input, show invalid domain page
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
  }

  // ── Fast-path for client-side navigations ────────────────────────────────
  // When Next.js fetches SSR data for a client-side router.push(), it sets the
  // x-nextjs-data header.  In this case the user's browser will immediately
  // start the real lookup via prefetchLookup + /api/lookup-stream, so there's
  // no benefit in hitting Redis here — skip the cache check and return in <5ms.
  // Bot crawlers and direct page loads still get the full Redis lookup path.
  const isClientNav = context.req.headers["x-nextjs-data"] === "1";

  // ── Parallel: require_login check + cache lookup ────────────────────────────
  // Both are independently fetchable: settings has a 30s in-process cache;
  // the WHOIS cache check is a quick Redis read.  Firing them together
  // removes the sequential gap (~20-60ms) on every page request.
  const requireLoginPromise = getSettingServer("require_login");
  const ssrCachePromise = isClientNav
    ? Promise.resolve(null)
    : lookupWhoisWithCache(target, { cacheOnly: true }).catch(() => null);

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
  // Skipped entirely for client-side navigation (see isClientNav above).
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
  // - Client-side navigation: skip caching (response is just an empty shell).
  // When require_login is ON, the response is user-specific — no edge caching.
  if (requireLogin !== "1" && !isClientNav) {
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
type AdRichItem = { text: string; color?: string; size?: "xs" | "sm" | "base"; bold?: boolean };
function parseAdItems(raw: string): AdRichItem[] {
  const trimmed = (raw || "").trim();
  if (trimmed.startsWith("[")) {
    try {
      const p = JSON.parse(trimmed);
      if (Array.isArray(p)) {
        const r = p.filter((i: unknown) => i && typeof (i as AdRichItem).text === "string" && (i as AdRichItem).text.trim());
        if (r.length > 0) return r as AdRichItem[];
      }
    } catch {}
  }
  return trimmed.split("|").map(s => s.trim()).filter(Boolean).map(t => ({ text: t }));
}

function ResultTextAd({ loading = false, inline = false }: { loading?: boolean; inline?: boolean }) {
  const settings = useSiteSettings();
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  const mode    = settings.result_ad_mode || "text";
  const rawText = settings.result_ad_text || "";
  const items   = React.useMemo(() => parseAdItems(rawText), [rawText]);

  React.useEffect(() => {
    if (mode !== "text" || items.length <= 1) return;
    setActiveIdx(0);
    const timer = setInterval(() => {
      setFading(true);
      setTimeout(() => {
        setActiveIdx(i => (i + 1) % items.length);
        setFading(false);
      }, 350);
    }, 5000);
    return () => clearInterval(timer);
  }, [mode, items.length, rawText]);

  if (settings.result_ad_enabled !== "1") return null;
  if (loading) return null;

  const url = settings.result_ad_url;

  // ── IMAGE mode ─────────────────────────────────────────────────────────────
  if (mode === "image") {
    const imgUrl = settings.result_ad_image_url;
    const imgAlt = settings.result_ad_image_alt || "广告";
    if (!imgUrl) return null;

    const imgEl = (
      <img
        src={imgUrl}
        alt={imgAlt}
        className={cn(
          "max-w-full max-h-24 object-contain rounded-xl mx-auto block",
          url && "hover:opacity-80 transition-opacity cursor-pointer",
        )}
        onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
      />
    );
    const wrapped = url
      ? <Link href={url} target="_blank" rel="noopener noreferrer sponsored">{imgEl}</Link>
      : imgEl;

    if (inline) return <div className="sm:hidden mt-4 px-1 text-center">{wrapped}</div>;
    return <div className="hidden sm:block mt-5 text-center">{wrapped}</div>;
  }

  // ── HTML mode ──────────────────────────────────────────────────────────────
  if (mode === "html") {
    const html = settings.result_ad_html;
    if (!html) return null;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const sanitized = typeof window !== "undefined"
      ? (require("dompurify") as typeof import("dompurify")).default.sanitize(html, { USE_PROFILES: { html: true } })
      : "";
    if (!sanitized) return null;
    const div = (
      <div
        className="result-ad-html max-w-full overflow-hidden"
        dangerouslySetInnerHTML={{ __html: sanitized }}
      />
    );
    if (inline) return <div className="sm:hidden mt-4 px-1">{div}</div>;
    return <div className="hidden sm:block mt-5">{div}</div>;
  }

  // ── TEXT mode (default) ────────────────────────────────────────────────────
  if (items.length === 0) return null;
  const label   = settings.result_ad_label || "广告";
  const current = items[activeIdx] ?? items[0];

  const content = (
    <div className={`flex items-center justify-center gap-2 ${url ? "hover:opacity-60 transition-opacity cursor-pointer" : ""}`}>
      <RiMegaphoneLine
        className="w-3 h-3 shrink-0 text-foreground/25"
        style={{ animation: "ad-float 3s ease-in-out infinite" }}
      />
      <span className="text-foreground/30 text-[10px] tracking-widest uppercase shrink-0">{label}</span>
      <span className="text-foreground/15 shrink-0">·</span>
      <span
        className="truncate text-foreground/40 leading-none"
        style={{
          opacity: fading ? 0 : 1,
          transition: "opacity 0.35s ease",
          color: current.color || undefined,
          fontWeight: current.bold ? "600" : undefined,
          fontSize: current.size === "xs" ? "10px" : current.size === "base" ? "12px" : "11px",
        }}
      >
        {current.text}
      </span>
      {items.length > 1 && (
        <div className="flex items-center gap-0.5 shrink-0">
          {items.map((_, i) => (
            <div
              key={i}
              className={`rounded-full transition-all duration-300 ${i === activeIdx ? "w-2.5 h-1 bg-foreground/25" : "w-1 h-1 bg-foreground/12"}`}
            />
          ))}
        </div>
      )}
      {url && <RiExternalLinkLine className="w-2.5 h-2.5 text-foreground/20 shrink-0" />}
    </div>
  );

  const wrapper = url
    ? <Link href={url} target="_blank" rel="noopener noreferrer sponsored" className="block">{content}</Link>
    : content;

  if (inline) return <div className="sm:hidden mt-4 px-1">{wrapper}</div>;
  return <div className="hidden sm:block mt-5 text-center">{wrapper}</div>;
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
  const enableSearchLinks = settings.enable_search_links === "1";
  const enableShare    = settings.enable_share    === "1";
  const enableFeedback = settings.enable_feedback === "1";
  const enableRemind   = settings.enable_remind   === "1";
  const enableStamps   = settings.enable_stamps   === "1";

  // ── Shallow-routing target sync ──────────────────────────────────────────
  // `target` starts as the SSR-provided prop.  When the user searches again
  // from the same page (handleSearch uses shallow routing to skip SSR), only
  // router.query changes — props are NOT updated.  We track target in state
  // and re-derive it from router.query so useEffect([target]) re-fires and
  // fetches new data without a full page reload.
  const [target, setTarget] = React.useState(propTarget);
  const [displayTarget, setDisplayTarget] = React.useState(propDisplayTarget);
  // First sync-effect run corresponds to the initial mount; later runs mean
  // an actual route change happened (e.g. a shallow push from handleSearch).
  const firstSyncRun = React.useRef(true);

  useEffect(() => {
    const newTarget = targetFromRouterQuery(router.query);
    if (newTarget && newTarget !== target) {
      setTarget(newTarget);
      setDisplayTarget(newTarget); // domainToUnicode not available client-side
    } else if (newTarget && newTarget === target && !firstSyncRun.current) {
      // Route changed to a variant URL (different case / protocol / www
      // prefix) that normalizes to the SAME target. The [target, refreshKey]
      // fetch effect will not re-fire, so nothing would clear the loading
      // skeleton set by routeChangeStart — clear it here to avoid an
      // infinite spinner.
      setLoading(false);
      setRefreshing(false);
    }
    firstSyncRun.current = false;
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
  const [mounted, setMounted] = React.useState(false);
  React.useEffect(() => { setMounted(true); }, []);
  const [showBackToTop, setShowBackToTop] = React.useState(false);
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

  // Back-to-top: track ScrollArea viewport scroll position
  useEffect(() => {
    const area = scrollAreaRef.current;
    if (!area) return;
    const vp = area.querySelector("[data-radix-scroll-area-viewport]");
    if (!vp) return;
    const onScroll = () => setShowBackToTop((vp as HTMLElement).scrollTop > 400);
    vp.addEventListener("scroll", onScroll, { passive: true });
    return () => vp.removeEventListener("scroll", onScroll);
  }, []);

  // Client-side WHOIS fetch — runs when target changes (shallow nav) or
  // refreshKey increments (re-query button forces a fresh lookup).
  useEffect(() => {
    // Flicker prevention: on the very first client-side render, if SSR already
    // provided data (initialData != null), skip resetting to empty and just
    // silently update the data in the background — no skeleton flash.
    const isFirstLoad = !firstLoadDone.current;
    firstLoadDone.current = true;

    // ── INVALID TLD short-circuit ────────────────────────────────────────────
    // Skip the fetch if the current target is demonstrably invalid — no dot,
    // no ASN pattern, no IPv6, or an unrecognised ICANN TLD.  This guard runs
    // on every useEffect invocation so it works for both:
    //   (a) direct navigation  — SSR returned INVALID_DOMAIN_TLD props
    //   (b) shallow routing    — user searched a new invalid domain from within
    //       the page (initialData still holds the old domain's SSR data, so the
    //       ref-based approach would silently miss this case)
    // Updating `data` here ensures the error card is visible even on a shallow
    // navigation where SSR props are not refreshed.
    const targetIsInvalid = !looksLikeDomainQuery(target) || !isValidDomainTld(target);
    if (targetIsInvalid) {
      firstLoadDone.current = true;
      setLoading(false);
      setData({ time: 0, status: false, cached: false, error: "INVALID_DOMAIN_TLD" });
      return;
    }

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
  const copy = useClipboard();
  useSearchHotkeys({});


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
    const cleaned = cleanDomain(query.replace(/\s+/g, ""));
    const url = toSearchURI(query);
    // Same domain searched again (raw input may differ in case / protocol /
    // www prefix but normalizes to the current target). A shallow push would
    // set the loading skeleton via routeChangeStart while the [target]
    // fetch effect never re-fires — an infinite spinner. Re-query instead.
    if (cleaned && cleaned === target) {
      setRefreshKey((k) => k + 1);
      return;
    }
    if (url === router.asPath) return;
    if (cleaned && looksLikeDomainQuery(cleaned) && isValidDomainTld(cleaned)) {
      prefetchLookup(cleaned);
    }
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
            : r?.status?.some(s => typeof s.status === "string" && s.status.toLowerCase().includes("reserved")) ? "reserved"
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
                    <RiBillLine className="w-3 h-3 shrink-0 text-muted-foreground" />
                    <span className="text-[11px] sm:text-xs font-normal text-muted-foreground">
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
                    <RiExchangeDollarFill className="w-3 h-3 shrink-0 text-muted-foreground" />
                    <span className="text-[11px] sm:text-xs font-normal text-muted-foreground">
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
            <QueryLoadingSkeleton domain={displayTarget} />
          )}
          </AnimatePresence>

          {!loading && !status && (() => {
            const hasErrorRaw = !!(result && (result.rawWhoisContent || result.rawRdapContent));
            return (
            <motion.div
              key={target}
              initial={{ opacity: 0, y: 3 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1], delay: 0.03 }}
            >
            <div
              className="grid grid-cols-1 lg:grid-cols-12 gap-6"
            >
              <div className={cn(hasErrorRaw ? "lg:col-span-8" : "lg:col-span-12", "space-y-6")}>
                {error === "INVALID_DOMAIN_TLD" ? (() => {
                  const hasDot = target.includes(".");
                  const tld = hasDot ? `.${target.split(".").pop()}` : null;
                  return (
                  <div className="glass-panel border border-amber-300/50 dark:border-amber-700/40 rounded-xl overflow-hidden">
                    {/* Top accent bar */}
                    <div className="h-1 w-full bg-gradient-to-r from-amber-400/60 via-amber-500/80 to-amber-400/60" />
                    <div className="p-8 sm:p-10 text-center">
                      {/* Icon */}
                      <div className="w-14 h-14 bg-amber-50 dark:bg-amber-950/40 rounded-full flex items-center justify-center mx-auto mb-5 ring-4 ring-amber-100 dark:ring-amber-900/30">
                        <RiErrorWarningLine className="w-7 h-7 text-amber-500" />
                      </div>
                      {/* Badge */}
                      <Badge variant="outline" className="mb-4 font-mono text-[10px] font-bold uppercase tracking-widest text-amber-600 border-amber-400/60 bg-amber-50/50 dark:bg-amber-950/20">
                        {hasDot ? "INVALID TLD" : "INVALID INPUT"}
                      </Badge>
                      {/* Heading */}
                      <h2 className="text-xl sm:text-2xl font-bold mb-3 leading-snug">
                        {hasDot
                          ? (isChinese ? `"${tld}" 不是真实的域名后缀` : `"${tld}" is not a real TLD`)
                          : (isChinese ? `"${target}" 不是有效的域名格式` : `"${target}" isn't a valid domain`)}
                      </h2>
                      {/* Input pill */}
                      <div className="inline-flex items-center gap-1.5 bg-muted/60 border border-border/60 rounded-full px-3 py-1 mb-5 max-w-full overflow-hidden">
                        <span className="text-[11px] text-muted-foreground shrink-0">{isChinese ? "你输入了：" : "You entered:"}</span>
                        <span className="font-mono text-[13px] font-semibold truncate">{target}</span>
                      </div>
                      {/* Description */}
                      <p className="text-muted-foreground max-w-sm mx-auto text-sm leading-relaxed">
                        {hasDot
                          ? (isChinese
                            ? <>{`我们在 ICANN 顶级域名列表中找不到 `}<span className="font-mono font-semibold text-foreground">{tld}</span>，请检查拼写是否正确。</>
                            : <>We couldn&apos;t find <span className="font-mono font-semibold text-foreground">{tld}</span> in the ICANN TLD registry. Check your spelling.</>)
                          : (isChinese
                            ? "请输入包含后缀的完整域名，例如 example.com、test.io 或 8.8.8.8"
                            : "Please enter a full domain name including a TLD, e.g. example.com, test.io or 8.8.8.8")}
                      </p>
                      {/* TLD hint — only for invalid TLD case */}
                      {hasDot && (
                        <p className="text-xs text-muted-foreground/50 mt-2">
                          {isChinese ? "常见后缀：.com .net .org .io .cn .rw .ai" : "Common TLDs: .com .net .org .io .cn .rw .ai"}
                        </p>
                      )}
                      {/* Actions */}
                      <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mt-7">
                        <Link href="/">
                          <Button className="gap-2 w-full sm:w-auto">
                            <RiSearchLine className="w-4 h-4" />
                            {isChinese ? "重新搜索" : "Search Again"}
                          </Button>
                        </Link>
                      </div>
                    </div>
                  </div>
                  );
                })() : dnsProbe?.registrationStatus === "registered" ? (
                  <>
                    <div className="glass-panel border border-emerald-400/40 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-xl p-6 sm:p-8 relative overflow-hidden">
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <Badge
                              variant="outline"
                              className="text-[10px] font-bold uppercase tracking-wider font-mono"
                            >
                              {queryType}
                            </Badge>
                          </div>
                          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-1 uppercase break-all">
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
                            {(time ?? 0).toFixed(2)}s
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
                    <div className="glass-panel border border-red-200/50 dark:border-red-900/40 rounded-xl overflow-hidden">
                      {/* Top accent bar */}
                      <div className="h-1 w-full bg-gradient-to-r from-red-400/60 via-red-500/80 to-red-400/60" />
                      <div className="p-8 sm:p-10 text-center">
                        {/* Icon */}
                        <div className="w-14 h-14 bg-red-50 dark:bg-red-950/40 rounded-full flex items-center justify-center mx-auto mb-5 ring-4 ring-red-100 dark:ring-red-900/30">
                          <RiAlertLine className="w-7 h-7 text-red-500" />
                        </div>
                        {/* Badge */}
                        <Badge variant="outline" className="mb-4 font-mono text-[10px] font-bold uppercase tracking-widest text-red-600 border-red-400/60 bg-red-50/50 dark:bg-red-950/20">
                          LOOKUP FAILED
                        </Badge>
                        {/* Heading */}
                        <h2 className="text-xl sm:text-2xl font-bold mb-3 leading-snug">
                          {t("lookup_failed")}
                        </h2>
                        {/* Domain pill */}
                        <div className="inline-flex items-center gap-1.5 bg-muted/60 border border-border/60 rounded-full px-3 py-1 mb-5 max-w-full overflow-hidden">
                          <span className="text-[11px] text-muted-foreground shrink-0">{isChinese ? "查询目标：" : "Target:"}</span>
                          <span className="font-mono text-[13px] font-semibold truncate">{target}</span>
                        </div>
                        {/* Error message */}
                        <p className="text-muted-foreground max-w-sm mx-auto text-sm leading-relaxed">
                          {error || t("lookup_failed_fallback")}
                        </p>
                        {/* Actions */}
                        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mt-7 flex-wrap">
                          <Button onClick={handleRefresh} className="gap-2 w-full sm:w-auto">
                            <RiSearchLine className="w-4 h-4" />
                            {t("try_again")}
                          </Button>
                          {registryUrl && (
                            <a href={registryUrl} target="_blank" rel="noopener noreferrer" className="w-full sm:w-auto">
                              <Button variant="outline" className="gap-2 w-full">
                                <RiLinkM className="w-4 h-4" />
                                {isChinese ? "在注册局查询" : "Look up at Registry"}
                              </Button>
                            </a>
                          )}
                          <Link href="/" className="w-full sm:w-auto">
                            <Button variant="outline" className="w-full">{t("new_search")}</Button>
                          </Link>
                        </div>
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
                        href={`https://www.google.com/search?q=site:${origin ? new URL(origin).host : ""}/${encodeURIComponent(displayTarget)}`}
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
                        href={`https://www.bing.com/search?q=site:${origin ? new URL(origin).host : ""}/${encodeURIComponent(displayTarget)}`}
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
                        <span className="font-mono">{(time ?? 0).toFixed(2)}s</span>
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
                        {enableRemind && (
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
                        )}
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
                        ) : enableStamps ? verifiedStamps.length > 0 ? (
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
                        ) : null}
                      </div>
                      <div className="flex items-start gap-2 mb-1 min-w-0">
                        <motion.h2
                          className="flex-1 min-w-0 text-3xl sm:text-4xl font-bold tracking-tight cursor-pointer hover:opacity-80 transition-opacity uppercase select-none break-all"
                          onClick={() => copy(result.domain || target)}
                          whileTap={{ scale: 0.97 }}
                          transition={{ type: "spring", stiffness: 500, damping: 30 }}
                        >
                          {result.domain || displayTarget}
                        </motion.h2>
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
                              <div className="relative mr-1.5 w-2 h-2 shrink-0" suppressHydrationWarning>
                                <div className="w-2 h-2 rounded-full bg-white/80 animate-ping absolute opacity-75" suppressHydrationWarning />
                                <div className="w-2 h-2 rounded-full bg-white/90" suppressHydrationWarning />
                              </div>
                              {t("expired")}
                            </Badge>
                          ) : result.remainingDays <= 60 ? (
                            <Badge className="bg-amber-500 hover:bg-amber-600 text-white border-0">
                              <div className="relative mr-1.5 w-2 h-2 shrink-0" suppressHydrationWarning>
                                <div className="w-2 h-2 rounded-full bg-white/80 animate-ping absolute opacity-75" suppressHydrationWarning />
                                <div className="w-2 h-2 rounded-full bg-white/90" suppressHydrationWarning />
                              </div>
                              {t("expiring_soon")}
                            </Badge>
                          ) : (
                            <Badge className="bg-primary hover:bg-primary/90 text-primary-foreground border-0">
                              <div className="relative mr-1.5 w-2 h-2 shrink-0" suppressHydrationWarning>
                                <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping absolute opacity-75" suppressHydrationWarning />
                                <div className="w-2 h-2 rounded-full bg-emerald-400" suppressHydrationWarning />
                              </div>
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
                              {result.domainAge <= 1 ? t("year") : t("years")}
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
                              <RiBillLine className="w-3 h-3 shrink-0 text-muted-foreground" />
                              <span className="text-[11px] font-normal text-muted-foreground">
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
                              <RiExchangeDollarFill className="w-3 h-3 shrink-0 text-muted-foreground" />
                              <span className="text-[11px] font-normal text-muted-foreground">
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
                        {enableRemind && (
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
                        )}
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
                        ) : enableStamps ? verifiedStamps.length > 0 ? (
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
                        ) : null}
                      </div>
                      <div className="flex items-center gap-2 mt-2">
                        <span suppressHydrationWarning className="text-[10px] text-muted-foreground font-mono">
                          {(time ?? 0).toFixed(2)}s
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
                          {enableFeedback && (
                          <button
                            onClick={() => setFeedbackOpen(true)}
                            title={t("feedback.issue_title")}
                            className="flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] text-muted-foreground hover:text-amber-500 hover:bg-amber-50 dark:hover:bg-amber-950/30 border border-transparent hover:border-amber-300/50 transition-all"
                          >
                            <RiErrorWarningLine className="w-3.5 h-3.5" />
                            {t("feedback.title")}
                          </button>
                          )}
                          {enableShare && (
                          <SharePanel
                            target={target}
                            result={result}
                            currentUrl={current}
                            isZh={isZh}
                            onOpenImagePreview={() => setShowImagePreview(true)}
                          />
                          )}
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

                    {mounted && enableFeedback && (
                    <FeedbackDrawer
                      open={feedbackOpen}
                      onOpenChange={setFeedbackOpen}
                      query={result.domain || target}
                      queryType={queryType}
                    />
                    )}

                    {mounted && enableRemind && (
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
                    )}

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
                    {enableStamps && <Dialog open={stampDetailOpen} onOpenChange={setStampDetailOpen}>
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
                    </Dialog>}

                    <WhoisFieldsTable
                      result={result}
                      hasRegistrant={!!hasRegistrant}
                      hasAdminContact={!!hasAdminContact}
                      hasTechContact={!!hasTechContact}
                    />
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
                    {isValidField(result.registrar) && (
                      <RegistrarCard
                        result={result}
                        isZh={isZh}
                        hasAdminContact={!!hasAdminContact}
                        hasTechContact={!!hasTechContact}
                      />
                    )}

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

      {/* Back-to-top button */}
      <AnimatePresence>
        {showBackToTop && (
          <motion.button
            initial={{ opacity: 0, scale: 0.8, y: 8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.8, y: 8 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            aria-label={t("back_to_top")}
            onClick={() => {
              const vp = scrollAreaRef.current?.querySelector("[data-radix-scroll-area-viewport]");
              if (vp) vp.scrollTo({ top: 0, behavior: "smooth" });
            }}
            className="fixed bottom-6 right-5 z-50 w-9 h-9 rounded-full bg-background/90 backdrop-blur border border-border shadow-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:border-primary/50 transition-colors"
          >
            <RiArrowRightSLine className="w-4 h-4 -rotate-90" />
          </motion.button>
        )}
      </AnimatePresence>

      <OgImageDialog
        open={showImagePreview}
        onOpenChange={setShowImagePreview}
        target={target}
        result={result}
        isZh={isZh}
      />
    </>
  );
}
