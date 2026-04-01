import { cn, toSearchURI, isSearchRoute, cleanDomain } from "@/lib/utils";
import { prefetchLookup } from "@/lib/lookup-prefetch";
import React, { useEffect, useCallback } from "react";
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
import {
  RiInformationLine,
  RiAlertLine,
  RiCheckboxCircleLine,
  RiMegaphoneLine,
  RiCloseLine,
  RiArrowRightSLine,
} from "@remixicon/react";

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

// ── Homepage Announcement Banner ──────────────────────────────────────────────

const ANN_DISMISS_KEY = "home_ann_dismissed";

function HomeAnnouncementBanner() {
  const settings = useSiteSettings();
  const [dismissed, setDismissed] = React.useState(true);

  // Hydrate from localStorage after mount to avoid SSR mismatch
  useEffect(() => {
    const stored = localStorage.getItem(ANN_DISMISS_KEY);
    // Dismiss key includes the text hash so changing text un-dismisses
    const currentHash = settings.home_announcement_text.slice(0, 40);
    if (stored === currentHash) {
      setDismissed(true);
    } else {
      setDismissed(false);
    }
  }, [settings.home_announcement_text]);

  const handleDismiss = () => {
    const hash = settings.home_announcement_text.slice(0, 40);
    localStorage.setItem(ANN_DISMISS_KEY, hash);
    setDismissed(true);
  };

  if (settings.home_announcement_enabled !== "1") return null;
  if (!settings.home_announcement_text) return null;
  if (dismissed) return null;

  const type = settings.home_announcement_type || "info";
  const url = settings.home_announcement_url;

  const typeStyles: Record<string, { wrapper: string; icon: React.ReactNode }> = {
    info: {
      wrapper: "bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200",
      icon: <RiInformationLine className="w-4 h-4 shrink-0 text-blue-500 dark:text-blue-400" />,
    },
    warning: {
      wrapper: "bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200",
      icon: <RiAlertLine className="w-4 h-4 shrink-0 text-amber-500 dark:text-amber-400" />,
    },
    success: {
      wrapper: "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200",
      icon: <RiCheckboxCircleLine className="w-4 h-4 shrink-0 text-emerald-500 dark:text-emerald-400" />,
    },
    notice: {
      wrapper: "bg-violet-50 dark:bg-violet-950/40 border-violet-200 dark:border-violet-800 text-violet-800 dark:text-violet-200",
      icon: <RiMegaphoneLine className="w-4 h-4 shrink-0 text-violet-500 dark:text-violet-400" />,
    },
  };

  const style = typeStyles[type] ?? typeStyles.info;
  const content = (
    <div className={cn(
      "w-full flex items-center gap-2 px-3 py-2.5 rounded-lg border text-sm",
      style.wrapper,
    )}>
      {style.icon}
      <span className="flex-1 leading-snug">{settings.home_announcement_text}</span>
      {url && (
        <span className="flex items-center gap-0.5 text-xs opacity-70 shrink-0">
          <RiArrowRightSLine className="w-3 h-3" />
        </span>
      )}
      <button
        onClick={(e) => { e.preventDefault(); handleDismiss(); }}
        className="p-0.5 rounded hover:opacity-70 transition-opacity shrink-0"
        aria-label="关闭公告"
      >
        <RiCloseLine className="w-4 h-4" />
      </button>
    </div>
  );

  return (
    <div className="mb-3">
      {url ? (
        <Link href={url} target={url.startsWith("http") ? "_blank" : undefined} rel="noopener noreferrer">
          {content}
        </Link>
      ) : content}
    </div>
  );
}

// ── Brand display ─────────────────────────────────────────────────────────────

function XRWDisplay({ heroTitle, tagline }: { heroTitle: string; tagline: string }) {
  const settings = useSiteSettings();
  const displayTitle = settings.home_hero_title || heroTitle || settings.site_logo_text || "X.RW";
  const displayTagline = settings.home_hero_subtitle || tagline;
  return (
    <div className="w-full flex flex-col items-center justify-center select-none gap-2">
      <span className="text-shimmer text-4xl font-bold tracking-[0.22em]">
        {displayTitle}
      </span>
      {displayTagline && (
        <span className="text-[10px] text-muted-foreground/35 tracking-[0.22em] uppercase">
          {displayTagline}
        </span>
      )}
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

// ── Page ─────────────────────────────────────────────────────────────────────

export default function HomePage({ seo }: { seo: HomeSeo }) {
  const router = useRouter();
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const [loading, setLoading] = React.useState(false);
  const stats = usePublicStats(seo.showStats);

  useEffect(() => {
    router.prefetch("/github.com");
    router.prefetch("/dns");
    router.prefetch("/ip");
    router.prefetch("/ssl");
    router.prefetch("/icp");
    const handleStart = (url: string) => { if (isSearchRoute(url)) setLoading(true); };
    const handleComplete = () => setLoading(false);
    router.events.on("routeChangeStart", handleStart);
    router.events.on("routeChangeComplete", handleComplete);
    router.events.on("routeChangeError", handleComplete);
    return () => {
      router.events.off("routeChangeStart", handleStart);
      router.events.off("routeChangeComplete", handleComplete);
      router.events.off("routeChangeError", handleComplete);
    };
  }, [router]);

  useSearchHotkeys({});

  const handleSearch = useCallback(
    (query: string) => {
      const cleaned = cleanDomain(query.replace(/\s+/g, ""));
      if (cleaned) prefetchLookup(cleaned);
      setLoading(true);
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
      <main className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 min-h-[calc(100vh-4rem)]">
        {/* Search box */}
        <div className="mb-3">
          <div className="relative group">
            <SearchBox onSearch={handleSearch} loading={loading} autoFocus placeholder={seo.searchPlaceholder || undefined} />
            <div className="absolute left-4 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none opacity-50 group-hover:opacity-100 transition-opacity">
              <KeyboardShortcut k="/" />
            </div>
          </div>
          <SearchHotkeysText className="hidden sm:flex mt-2 px-1 justify-end" />
        </div>

        {/* Homepage announcement banner — inline, below search, not fixed */}
        <HomeAnnouncementBanner />

        {/* Stats bar */}
        {seo.showStats && stats && (
          <div
            className="flex justify-center gap-6 mt-3 mb-1"
            style={{ opacity: loading ? 0 : 1, transition: "opacity 0.1s ease" }}
          >
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

        {/* Mobile: centered brand display */}
        <div
          className="sm:hidden flex items-center justify-center"
          style={{
            height: "calc(100vh - 22rem)",
            opacity: loading ? 0 : 1,
            transition: "opacity 0.12s ease",
            pointerEvents: loading ? "none" : undefined,
          }}
        >
          <XRWDisplay heroTitle={seo.heroTitle} tagline={seo.tagline} />
        </div>
      </main>
    </div>
    </>
  );
}

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_TITLE       = "RDAP+WHOIS 域名查询 · 免费在线域名信息查询工具";
const DEFAULT_DESC        = "免费在线 WHOIS / RDAP 域名查询工具，支持查询域名注册信息、注册商、注册日期、到期时间、DNS、状态等，支持国际域名和 IP 地址查询。";
const DEFAULT_KEYWORDS    = "whois查询, rdap, 域名查询, 域名注册信息, 域名到期, whois工具, 域名信息, ip查询, 域名状态";
const DEFAULT_LOGO        = "X.RW";
const DEFAULT_TAGLINE     = "NiC.RW 提供技术支持";

// ── ISR: revalidate every 60 s — avoids SSR cold-start on every request ───────
// The homepage only needs SEO metadata from the DB; using ISR means the page is
// served as a pre-rendered static file and only re-fetches settings once per
// minute, eliminating the 5-8 s cold-start DB round-trip that was causing
// mobile browsers to abort and display a "download file" dialog.
export const getStaticProps: GetStaticProps = async () => {
  let s: Record<string, string> = {};
  try {
    s = await getSettings([
      "site_title", "site_description", "site_keywords", "site_logo_text",
      "site_subtitle", "og_site_name", "og_image", "og_url", "twitter_card",
      "home_show_stats", "home_hero_title", "home_hero_subtitle", "home_placeholder",
      "home_announcement_enabled", "home_announcement_text", "home_announcement_type",
      "home_announcement_url",
    ]);
  } catch {
    // DB unavailable — use all defaults; page will still render correctly
    s = {};
  }

  const siteTitle        = s["site_title"]        || "";
  const siteDesc         = s["site_description"]   || "";
  const siteKeywords     = s["site_keywords"]       || "";
  const siteLogo         = s["site_logo_text"]      || "";
  const siteSubtitle     = s["site_subtitle"]       || "";
  const ogSiteName       = s["og_site_name"]        || "";
  const ogImage          = s["og_image"]            || "";
  const ogUrl            = s["og_url"]              || "";
  const twitterCard      = s["twitter_card"]        || "";
  const homeShowStats    = s["home_show_stats"]     || "";
  const homeHeroTitle    = s["home_hero_title"]     || "";
  const homeHeroSubtitle = s["home_hero_subtitle"]  || "";
  const homePlaceholder  = s["home_placeholder"]    || "";

  const logoText   = siteLogo   || DEFAULT_LOGO;
  const tagline    = homeHeroSubtitle || siteSubtitle || DEFAULT_TAGLINE;
  const heroTitle  = homeHeroTitle || logoText;
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
    og_site_name:                siteName,
    og_image:                    ogImage || "",
    og_url:                      ogUrl || "",
    twitter_card:                twitterCard || "summary_large_image",
    site_subtitle:               siteSubtitle || "",
    home_hero_title:             homeHeroTitle || "",
    home_hero_subtitle:          homeHeroSubtitle || "",
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
