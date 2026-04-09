import { cn, toSearchURI, isSearchRoute, cleanDomain, isValidDomainTld } from "@/lib/utils";
import { prefetchLookup } from "@/lib/lookup-prefetch";
import React, { useEffect, useCallback, useState } from "react";
import { AnimatePresence } from "framer-motion";
import { QueryLoadingSkeleton } from "@/components/query/query-loading-skeleton";
import { useRouter } from "next/router";
import { useTranslation } from "@/lib/i18n";
import Head from "next/head";
import Link from "next/link";
import { SearchBox } from "@/components/search_box";
import {
  KeyboardShortcut,
  SearchHotkeysText,
} from "@/components/search_shortcuts";
import { useSearchHotkeys } from "@/hooks/useSearchHotkeys";
import type { GetStaticProps } from "next";
import { getSettings } from "@/lib/server/site-settings-server";
import { useSiteSettings } from "@/lib/site-settings";

interface HomeSeo {
  title: string;
  description: string;
  keywords: string;
  ogTitle: string;
  ogImage: string;
  ogSiteName: string;
  ogUrl: string;
  twitterCard: string;
  logoText: string;
  tagline: string;
  heroTitle: string;
  heroSubtitle: string;
  searchPlaceholder: string;
  showStats: boolean;
}

// ── Brand display ─────────────────────────────────────────────────────────────

const HERO_TITLE_SIZE_MAP: Record<string, string> = {
  xs: "text-3xl sm:text-4xl",
  sm: "text-4xl sm:text-5xl",
  md: "text-5xl sm:text-6xl",
  lg: "text-6xl sm:text-7xl",
  xl: "text-7xl sm:text-8xl",
};
const HERO_SUBTITLE_SIZE_MAP: Record<string, string> = {
  xs: "text-[9px]",
  sm: "text-[11px]",
  md: "text-xs",
  lg: "text-sm",
};

function XRWDisplay({ heroTitle, tagline }: { heroTitle: string; tagline: string }) {
  const settings = useSiteSettings();
  const displayTitle = settings.home_hero_title || heroTitle;
  const displayTagline = settings.home_hero_subtitle || tagline;
  const titleSizeClass = HERO_TITLE_SIZE_MAP[settings.home_hero_title_size] ?? HERO_TITLE_SIZE_MAP.md;
  const subtitleSizeClass = HERO_SUBTITLE_SIZE_MAP[settings.home_hero_subtitle_size] ?? HERO_SUBTITLE_SIZE_MAP.xs;
  return (
    <div className="w-full flex flex-col items-center justify-center select-none gap-2" suppressHydrationWarning>
      <span className={`text-shimmer font-bold tracking-[0.22em] ${titleSizeClass}`} suppressHydrationWarning>
        {displayTitle}
      </span>
      <span
        className={`text-muted-foreground/35 tracking-[0.22em] uppercase ${subtitleSizeClass}`}
        style={{ display: displayTagline ? undefined : "none" }}
        suppressHydrationWarning
      >
        {displayTagline}
      </span>
    </div>
  );
}

// ── Stats ─────────────────────────────────────────────────────────────────────

function usePublicStats(enabled: boolean) {
  const [stats, setStats] = React.useState<{ totalSearches: number; todaySearches: number } | null>(null);
  React.useEffect(() => {
    if (!enabled) return;
    fetch("/api/public-stats")
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.enabled) setStats({ totalSearches: d.totalSearches, todaySearches: d.todaySearches }); })
      .catch(() => {});
  }, [enabled]);
  return stats;
}

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${Math.floor(n / 1000)}K`;
  return n.toLocaleString();
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_TITLE       = "RDAP+WHOIS 域名查询 · 免费在线域名信息查询工具";
const DEFAULT_DESC        = "免费在线 WHOIS / RDAP 域名查询工具，支持查询域名注册信息、注册商、注册日期、到期时间、DNS、状态等，支持国际域名和 IP 地址查询。";
const DEFAULT_KEYWORDS    = "whois查询, rdap, 域名查询, 域名注册信息, 域名到期, whois工具, 域名信息, ip查询, 域名状态";
const DEFAULT_LOGO        = "X.RW";
const DEFAULT_TAGLINE     = "NiC.RW 提供技术支持";

const DEFAULT_SEO: HomeSeo = {
  title:             DEFAULT_TITLE,
  description:       DEFAULT_DESC,
  keywords:          DEFAULT_KEYWORDS,
  ogTitle:           DEFAULT_TITLE,
  ogImage:           "",
  ogSiteName:        DEFAULT_LOGO,
  ogUrl:             "",
  twitterCard:       "summary_large_image",
  logoText:          DEFAULT_LOGO,
  tagline:           DEFAULT_TAGLINE,
  heroTitle:         DEFAULT_LOGO,
  heroSubtitle:      "",
  searchPlaceholder: "",
  showStats:         false,
};

// ── Page ─────────────────────────────────────────────────────────────────────

export default function HomePage({ seo: seoProp }: { seo?: HomeSeo }) {
  const seo = seoProp ?? DEFAULT_SEO;
  const router = useRouter();
  const { t, locale } = useTranslation();
  const isChinese = locale === "zh";
  const settings = useSiteSettings();
  const stats = usePublicStats(seo.showStats);

  useEffect(() => {
    router.prefetch("/github.com");
    router.prefetch("/dns");
    router.prefetch("/ip");
    router.prefetch("/ssl");
    router.prefetch("/icp");
  }, [router]);

  useSearchHotkeys({});

  const [isSearching, setIsSearching] = useState(false);
  const [searchTarget, setSearchTarget] = useState<string>("");

  // Reset loading state when navigation finishes or errors (e.g. user presses back)
  useEffect(() => {
    const reset = () => { setIsSearching(false); setSearchTarget(""); };
    router.events.on("routeChangeComplete", reset);
    router.events.on("routeChangeError", reset);
    return () => {
      router.events.off("routeChangeComplete", reset);
      router.events.off("routeChangeError", reset);
    };
  }, [router]);

  const handleSearch = useCallback(
    (query: string) => {
      const cleaned = cleanDomain(query.replace(/\s+/g, ""));
      const queryLooksValid =
        cleaned &&
        !cleaned.startsWith(".") &&
        (cleaned.includes(".") || /^AS\d+$/i.test(cleaned) || /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(cleaned)) &&
        isValidDomainTld(cleaned);
      if (queryLooksValid) prefetchLookup(cleaned);
      setSearchTarget(cleaned || query.trim());
      setIsSearching(true);
      router.push(toSearchURI(query));
    },
    [router],
  );

  // Use og_url from live settings (overrides SSR prop) for canonical
  const siteUrl = settings.og_url || seo.ogUrl || "";
  const ogImage = seo.ogImage || `${siteUrl}/api/og?theme=dark`;

  return (
    <>
    <Head>
      <title>{seo.title}</title>
      <meta name="description" content={seo.description} />
      {seo.keywords && <meta name="keywords" content={seo.keywords} />}
      <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large" />
      <link rel="canonical" href={siteUrl + "/"} />

      <meta property="og:type" content="website" />
      <meta property="og:url" content={siteUrl + "/"} />
      <meta property="og:site_name" content={seo.ogSiteName} />
      <meta property="og:title" content={seo.ogTitle} />
      <meta property="og:description" content={seo.description} />
      <meta property="og:image" content={ogImage} />
      <meta property="og:image:width" content="1200" />
      <meta property="og:image:height" content="630" />

      <meta name="twitter:card" content={seo.twitterCard || "summary_large_image"} />
      <meta name="twitter:title" content={seo.ogTitle} />
      <meta name="twitter:description" content={seo.description} />
      <meta name="twitter:image" content={ogImage} />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebSite",
            "name": seo.ogSiteName,
            "url": siteUrl,
            "description": seo.description,
            "potentialAction": {
              "@type": "SearchAction",
              "target": {
                "@type": "EntryPoint",
                "urlTemplate": `${siteUrl}/{search_term_string}`,
              },
              "query-input": "required name=search_term_string",
            },
          }),
        }}
      />
    </Head>
    <div className="w-full">
      {/* ── Desktop layout ───────────────────────────────────────────────── */}
      <main className="hidden sm:block w-full max-w-5xl mx-auto px-6 py-6 min-h-[calc(100vh-4rem)]">
        <div className="mb-3">
          <div className="relative group">
            <SearchBox onSearch={handleSearch} loading={isSearching} placeholder={seo.searchPlaceholder || undefined} />
            <div className="absolute left-4 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none opacity-50 group-hover:opacity-100 transition-opacity">
              <KeyboardShortcut k="/" />
            </div>
          </div>
          <SearchHotkeysText className="flex mt-2 px-1 justify-end" />
        </div>

        <AnimatePresence mode="wait" initial={false}>
          {isSearching ? (
            <div key="skeleton" className="mt-4">
              <QueryLoadingSkeleton isChinese={isChinese} domain={searchTarget} />
            </div>
          ) : (
            <div key="home">
              {seo.showStats && stats && (
                <div className="flex justify-center gap-6 mt-3 mb-1">
                  <span className="text-xs text-muted-foreground/60 flex items-center gap-1.5">
                    <span className="font-semibold text-foreground/70">{fmt(stats.totalSearches)}</span>
                    {t("home.stats_total")}
                  </span>
                  <span className="text-muted-foreground/30">·</span>
                  <span className="text-xs text-muted-foreground/60 flex items-center gap-1.5">
                    <span className="font-semibold text-foreground/70">{fmt(stats.todaySearches)}</span>
                    {t("home.stats_today")}
                  </span>
                </div>
              )}
              <div className="flex items-center justify-center" style={{ height: "calc(100vh - 22rem)" }}>
                <XRWDisplay heroTitle={seo.heroTitle} tagline={seo.tagline} />
              </div>
            </div>
          )}
        </AnimatePresence>
      </main>

      {/* ── Mobile layout (one viewport, no scroll) ──────────────────────── */}
      <div className="sm:hidden flex flex-col w-full px-4" style={{ height: "calc(100dvh - 4rem - var(--ann-h, 0px))", paddingTop: "1.25rem", paddingBottom: "1.5rem" }}>

        {/* Search box — top of viewport */}
        <div className="relative group mb-3">
          <SearchBox onSearch={handleSearch} loading={isSearching} placeholder={seo.searchPlaceholder || undefined} />
          <div className="absolute left-4 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none opacity-40">
            <KeyboardShortcut k="/" />
          </div>
        </div>

        <AnimatePresence mode="wait" initial={false}>
          {isSearching ? (
            <div key="skeleton" className="flex-1 overflow-auto">
              <QueryLoadingSkeleton isChinese={isChinese} domain={searchTarget} />
            </div>
          ) : (
            <React.Fragment key="home">
              {/* Brand: fills remaining space in the middle */}
              <div className="flex flex-1 items-center justify-center">
                <XRWDisplay heroTitle={seo.heroTitle} tagline={seo.tagline} />
              </div>

              {/* Stats */}
              {seo.showStats && stats && (
                <div className="flex justify-center gap-5 mb-3">
                  <span className="text-xs text-muted-foreground/60 flex items-center gap-1.5">
                    <span className="font-semibold text-foreground/70">{fmt(stats.totalSearches)}</span>
                    {t("home.stats_total")}
                  </span>
                  <span className="text-muted-foreground/30">·</span>
                  <span className="text-xs text-muted-foreground/60 flex items-center gap-1.5">
                    <span className="font-semibold text-foreground/70">{fmt(stats.todaySearches)}</span>
                    {t("home.stats_today")}
                  </span>
                </div>
              )}

              {/* Quick-access tool links — pinned at bottom, above footer copyright */}
              <div className="flex items-center justify-center gap-2 flex-wrap">
                {(isChinese
                  ? [
                      { href: "/dns", label: "DNS 查询" },
                      { href: "/ip",  label: "IP 查询" },
                      { href: "/ssl", label: "SSL 证书" },
                      { href: "/icp", label: "ICP 备案" },
                    ]
                  : [
                      { href: "/dns", label: "DNS Lookup" },
                      { href: "/ip",  label: "IP Lookup" },
                      { href: "/ssl", label: "SSL Check" },
                      { href: "/icp", label: "ICP Query" },
                    ]
                ).map(({ href, label }) => (
                  <Link
                    key={href}
                    href={href}
                    className="px-3 py-1.5 rounded-full text-xs border border-border/60 text-muted-foreground hover:text-foreground hover:border-border transition-colors bg-background/50"
                  >
                    {label}
                  </Link>
                ))}
              </div>

              {/* Footer copyright — compact single line for mobile */}
              {settings.site_footer && (
                <p className="mt-2 text-center text-[10px] text-muted-foreground/30 leading-tight" suppressHydrationWarning>
                  {settings.site_footer}
                </p>
              )}
            </React.Fragment>
          )}
        </AnimatePresence>
      </div>
    </div>
    </>
  );
}

// ── ISR: revalidate every 60 s — avoids SSR cold-start on every request ───────
// The homepage only needs SEO metadata from the DB; using ISR means the page is
// served as a pre-rendered static file and only re-fetches settings once per
// minute, eliminating the 5-8 s cold-start DB round-trip that was causing
// mobile browsers to abort and display a "download file" dialog.
export const getStaticProps: GetStaticProps = async () => {
  let s: Record<string, string> = {};
  try {
    // Race the DB query against a 3-second timeout so dev-mode cold-starts
    // (Supabase connection latency) never stall the page for more than 3 s.
    // On Vercel with warm ISR cache this completes in < 100 ms.
    s = await Promise.race([
      getSettings([
        "site_title", "site_description", "site_keywords", "site_logo_text",
        "site_subtitle", "site_footer", "og_site_name", "og_image", "og_url", "twitter_card",
        "home_show_stats", "home_hero_title", "home_hero_subtitle", "home_hero_title_size",
        "home_hero_subtitle_size", "home_placeholder",
        "home_announcement_enabled", "home_announcement_text", "home_announcement_type",
        "home_announcement_url",
      ]),
      new Promise<Record<string, string>>(resolve => setTimeout(() => resolve({}), 3000)),
    ]);
  } catch {
    // DB unavailable — use all defaults; page will still render correctly
    s = {};
  }

  const siteTitle         = s["site_title"]             || "";
  const siteDesc          = s["site_description"]        || "";
  const siteKeywords      = s["site_keywords"]            || "";
  const siteLogo          = s["site_logo_text"]           || "";
  const siteSubtitle      = s["site_subtitle"]            || "";
  const siteFooter        = s["site_footer"]              || "";
  const ogSiteName        = s["og_site_name"]             || "";
  const ogImage           = s["og_image"]                 || "";
  const ogUrl             = s["og_url"]                   || "";
  const twitterCard       = s["twitter_card"]             || "";
  const homeShowStats     = s["home_show_stats"]          || "";
  const homeHeroTitle     = s["home_hero_title"]          || "";
  const homeHeroSubtitle  = s["home_hero_subtitle"]       || "";
  const homeHeroTitleSize = s["home_hero_title_size"]     || "";
  const homeHeroSubSize   = s["home_hero_subtitle_size"]  || "";
  const homePlaceholder   = s["home_placeholder"]         || "";

  const logoText   = siteLogo   || DEFAULT_LOGO;
  const tagline    = homeHeroSubtitle || siteSubtitle || DEFAULT_TAGLINE;
  const heroTitle  = homeHeroTitle || DEFAULT_LOGO;
  const title      = siteTitle  || DEFAULT_TITLE;
  const desc       = siteDesc   || DEFAULT_DESC;
  const keywords   = siteKeywords || DEFAULT_KEYWORDS;
  const siteName   = ogSiteName || logoText;

  const seo: HomeSeo = {
    title,
    description: desc,
    keywords,
    ogTitle: title,
    ogImage: ogImage || "",
    ogSiteName: siteName,
    ogUrl: ogUrl || "",
    twitterCard: twitterCard || "summary_large_image",
    logoText,
    tagline,
    heroTitle,
    heroSubtitle: homeHeroSubtitle || "",
    searchPlaceholder: homePlaceholder || "",
    showStats: homeShowStats === "1",
  };

  const initialSiteSettings = {
    site_logo_text:              logoText,
    site_title:                  title,
    site_description:            desc,
    site_keywords:               keywords,
    site_footer:                 siteFooter || "",
    og_site_name:                siteName,
    og_image:                    ogImage || "",
    og_url:                      ogUrl || "",
    twitter_card:                twitterCard || "summary_large_image",
    site_subtitle:               siteSubtitle || "",
    home_hero_title:             homeHeroTitle || "",
    home_hero_subtitle:          homeHeroSubtitle || "",
    home_hero_title_size:        homeHeroTitleSize || "",
    home_hero_subtitle_size:     homeHeroSubSize || "",
    home_placeholder:            homePlaceholder || "",
    home_announcement_enabled:   s["home_announcement_enabled"] || "",
    home_announcement_text:      s["home_announcement_text"]    || "",
    home_announcement_type:      s["home_announcement_type"]    || "info",
    home_announcement_url:       s["home_announcement_url"]     || "",
  };

  return {
    props: { seo, initialSiteSettings },
    revalidate: 60, // ISR: regenerate at most once per minute
  };
};
