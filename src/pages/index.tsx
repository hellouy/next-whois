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

function XRWDisplay() {
  return (
    <div className="w-full flex flex-col items-center justify-center select-none gap-2">
      <span className="text-shimmer text-4xl font-bold tracking-[0.22em]">
        X.RW
      </span>
      <span className="text-[10px] text-muted-foreground/35 tracking-[0.22em] uppercase">
        NiC.RW 提供技术支持
      </span>
    </div>
  );
}

export default function HomePage({ origin }: { origin: string }) {
  const { t } = useTranslation();
  const router = useRouter();
  const [loading, setLoading] = React.useState(false);

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
  const homeDescription = "免费在线 WHOIS / RDAP 域名查询工具，支持查询域名注册信息、注册商、注册日期、到期时间、DNS、状态等，支持国际域名和 IP 地址查询。";

  return (
    <>
    <Head>
      <title>RDAP+WHOIS 域名查询 · 免费在线域名信息查询工具</title>
      <meta name="description" content={homeDescription} />
      <meta name="keywords" content="whois查询, rdap, 域名查询, 域名注册信息, 域名到期, whois工具, 域名信息, ip查询, 域名状态" />
      <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large" />
      <link rel="canonical" href={siteUrl + "/"} />

      <meta property="og:type" content="website" />
      <meta property="og:url" content={siteUrl + "/"} />
      <meta property="og:title" content="RDAP+WHOIS 域名查询 · 免费在线域名信息查询工具" />
      <meta property="og:description" content={homeDescription} />
      <meta property="og:image" content={`${siteUrl}/api/og?theme=dark`} />
      <meta property="og:image:width" content="1200" />
      <meta property="og:image:height" content="630" />
      <meta property="og:locale" content="zh_CN" />

      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content="RDAP+WHOIS 域名查询" />
      <meta name="twitter:description" content={homeDescription} />
      <meta name="twitter:image" content={`${siteUrl}/api/og?theme=dark`} />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebSite",
            "name": "RDAP+WHOIS 域名查询",
            "url": siteUrl,
            "description": homeDescription,
            "inLanguage": "zh-CN",
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

        {/* Mobile: centered X.RW brand display */}
        {!loading && (
          <div className="sm:hidden flex items-center justify-center" style={{ height: "calc(100vh - 16rem)" }}>
            <XRWDisplay />
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

export const getServerSideProps: GetServerSideProps = async ({ req }) => {
  return { props: { origin: getOrigin(req) } };
};
