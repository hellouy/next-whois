import { cn, toSearchURI, isSearchRoute, cleanDomain } from "@/lib/utils";
import { prefetchLookup } from "@/lib/lookup-prefetch";
import React, { useEffect, useCallback } from "react";
import { useRouter } from "next/router";
import Head from "next/head";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SearchBox } from "@/components/search_box";
import {
  KeyboardShortcut,
  SearchHotkeysText,
} from "@/components/search_shortcuts";
import { useTranslation } from "@/lib/i18n";
import { motion } from "framer-motion";
import { useSearchHotkeys } from "@/hooks/useSearchHotkeys";
import { getOrigin } from "@/lib/seo";
import type { GetServerSideProps } from "next";
import { getSetting } from "@/lib/server/site-settings-server";
import { useSiteSettings } from "@/lib/site-settings";

interface HomeSeo {
  title: string;
  description: string;
  keywords: string;
  ogTitle: string;
  ogImage: string;
  ogSiteName: string;
  twitterCard: string;
  logoText: string;
  tagline: string;
  showStats: boolean;
}

function XRWDisplay({ tagline }: { tagline: string }) {
  const settings = useSiteSettings();
  const logoText = settings.site_logo_text || "X.RW";
  return (
    <div className="w-full flex flex-col items-center justify-center select-none gap-2">
      <span className="text-shimmer text-4xl font-bold tracking-[0.22em]">
        {logoText}
      </span>
      {tagline && (
        <span className="text-[10px] text-muted-foreground/35 tracking-[0.22em] uppercase">
          {tagline}
        </span>
      )}
    </div>
  );
}

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

export default function HomePage({ origin, seo }: { origin: string; seo: HomeSeo }) {
  const { t } = useTranslation();
  const router = useRouter();
  const [loading, setLoading] = React.useState(false);
  const stats = usePublicStats(seo.showStats);

  useEffect(() => {
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
      router.push(toSearchURI(query));
    },
    [router],
  );

  const siteUrl = origin || "";
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
    <ScrollArea className="w-full h-[calc(100vh-4rem)]">
      <main className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 min-h-[calc(100vh-4rem)]">
        <div className="mb-4">
          <div className="relative group">
            <SearchBox onSearch={handleSearch} loading={loading} autoFocus />
            <div className="absolute left-4 top-1/2 -translate-y-1/2 flex items-center gap-1 pointer-events-none opacity-50 group-hover:opacity-100 transition-opacity">
              <KeyboardShortcut k="/" />
            </div>
          </div>
          <SearchHotkeysText className="hidden sm:flex mt-2 px-1 justify-end" />
        </div>

        {/* Stats bar — shown when home_show_stats is enabled */}
        {seo.showStats && stats && !loading && (
          <div className="flex justify-center gap-6 mt-3 mb-1">
            <span className="text-xs text-muted-foreground/60 flex items-center gap-1.5">
              <span className="font-semibold text-foreground/70">{fmt(stats.totalSearches)}</span>
              次总查询
            </span>
            <span className="text-muted-foreground/30">·</span>
            <span className="text-xs text-muted-foreground/60 flex items-center gap-1.5">
              <span className="font-semibold text-foreground/70">{fmt(stats.todaySearches)}</span>
              次今日查询
            </span>
          </div>
        )}

        {/* Mobile: centered brand display */}
        {!loading && (
          <div className="sm:hidden flex items-center justify-center" style={{ height: "calc(100vh - 19rem)" }}>
            <XRWDisplay tagline={seo.tagline} />
          </div>
        )}

        {loading && (
          <motion.div
            initial={{ opacity: 1 }}
            animate={{ opacity: 1 }}
            className="space-y-6 mt-2"
          >
            <div className="text-center py-4">
              <span className="text-shimmer text-base font-semibold tracking-wide select-none">
                {t("loading_text")}
              </span>
            </div>
            <div className="glass-panel border border-border rounded-xl p-6 sm:p-8">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div className="space-y-3 flex-1">
                  <div className="h-4 w-14 rounded-md bg-muted animate-pulse" />
                  <div className="h-8 w-40 rounded-md bg-muted animate-pulse" />
                  <div className="h-3 w-52 rounded-md bg-muted/70 animate-pulse" />
                </div>
                <div className="flex flex-col items-start sm:items-end gap-2">
                  <div className="h-6 w-20 rounded-full bg-muted animate-pulse" />
                  <div className="h-3 w-24 rounded-md bg-muted/60 animate-pulse" />
                </div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-6 mt-8 pt-8 border-t border-border/50">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="space-y-1.5">
                    <div className="h-3 w-16 rounded bg-muted/60 animate-pulse" />
                    <div className="h-4 w-24 rounded bg-muted animate-pulse" />
                    <div className="h-3 w-12 rounded bg-muted/50 animate-pulse" />
                  </div>
                ))}
              </div>
            </div>
            <div className="glass-panel border border-border rounded-xl p-6">
              <div className="h-4 w-20 rounded bg-muted/70 animate-pulse mb-4" />
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-muted animate-pulse shrink-0" />
                    <div className="h-4 w-36 rounded bg-muted animate-pulse" />
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </main>
    </ScrollArea>
    </>
  );
}

const DEFAULT_TITLE       = "RDAP+WHOIS 域名查询 · 免费在线域名信息查询工具";
const DEFAULT_DESC        = "免费在线 WHOIS / RDAP 域名查询工具，支持查询域名注册信息、注册商、注册日期、到期时间、DNS、状态等，支持国际域名和 IP 地址查询。";
const DEFAULT_KEYWORDS    = "whois查询, rdap, 域名查询, 域名注册信息, 域名到期, whois工具, 域名信息, ip查询, 域名状态";
const DEFAULT_LOGO        = "X.RW";
const DEFAULT_TAGLINE     = "NiC.RW 提供技术支持";

export const getServerSideProps: GetServerSideProps = async ({ req }) => {
  const origin = getOrigin(req);

  const [
    siteTitle, siteDesc, siteKeywords, siteLogo, siteSubtitle,
    ogSiteName, ogImage, twitterCard, homeShowStats,
  ] = await Promise.all([
    getSetting("site_title"),
    getSetting("site_description"),
    getSetting("site_keywords"),
    getSetting("site_logo_text"),
    getSetting("site_subtitle"),
    getSetting("og_site_name"),
    getSetting("og_image"),
    getSetting("twitter_card"),
    getSetting("home_show_stats"),
  ]).catch(() => Array(9).fill("") as string[]);

  const logoText   = siteLogo   || DEFAULT_LOGO;
  const tagline    = siteSubtitle || DEFAULT_TAGLINE;
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
    twitterCard: twitterCard || "summary_large_image",
    logoText,
    tagline,
    showStats: homeShowStats === "1",
  };

  const initialSiteSettings = {
    site_logo_text:    logoText,
    site_title:        title,
    site_description:  desc,
    site_keywords:     keywords,
    og_site_name:      siteName,
    og_image:          ogImage || "",
    twitter_card:      twitterCard || "summary_large_image",
    site_subtitle:     tagline,
  };

  return { props: { origin, seo, initialSiteSettings } };
};
