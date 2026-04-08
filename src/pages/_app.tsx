import "@/styles/globals.css";
import React from "react";
import NextApp from "next/app";
import type { AppProps, AppContext } from "next/app";
import { Analytics } from "@vercel/analytics/next";
import { SpeedInsights } from "@vercel/speed-insights/next";
import Head from "next/head";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/theme-provider";
import { siteTitle, siteDescription, siteKeywords } from "@/lib/seo";
import { Navbar } from "@/components/navbar";
import { useRouter } from "next/router";
import { AnimatePresence, motion } from "framer-motion";
import { SessionProvider, useSession } from "next-auth/react";
import { LocaleProvider, LOCALES, type Locale } from "@/lib/locale-context";
import { SiteSettingsProvider, useSiteSettings } from "@/lib/site-settings";
import { RiBellLine, RiCloseLine, RiWrenchLine, RiInformationLine, RiAlertLine, RiCheckLine } from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import Link from "next/link";
import { ErrorBoundary } from "@/components/error-boundary";


function AppHead({ origin }: { origin: string }) {
  const settings = useSiteSettings();
  const title = settings.site_title || siteTitle;
  const description = settings.site_description || siteDescription;
  const keywords = settings.site_keywords || siteKeywords;
  const siteName = settings.og_site_name || settings.site_title || siteTitle;
  const canonicalUrl = settings.og_url || origin;

  const base = canonicalUrl || origin;

  // Resolve a setting value to an absolute image URL.
  // Data-URL values are served via /api/image?key=<key> so crawlers get a real HTTP URL.
  function resolveImg(value: string, key: string): string {
    if (!value) return `${base}/og-banner.png`;
    if (value.startsWith("data:image/")) return `${base}/api/image?key=${key}`;
    if (value.startsWith("http")) return value;
    return `${base}${value.startsWith("/") ? "" : "/"}${value}`;
  }

  // og:image → bot-detection endpoint auto-selects WeChat / Facebook / YouTube / default
  const ogImage = base ? `${base}/api/og-image` : resolveImg(settings.og_image, "og_image");

  // twitter:image → explicit X/Twitter setting, falls back to general og_image
  const rawTwitterImage = settings.og_image_twitter || settings.og_image || "";
  const twitterKey = settings.og_image_twitter ? "og_image_twitter" : "og_image";
  const twitterImage = rawTwitterImage
    ? resolveImg(rawTwitterImage, twitterKey)
    : `${base}/og-banner.png`;

  const twitterCard = settings.twitter_card || "summary_large_image";

  return (
    <Head>
      <title key="title">{title}</title>
      <meta name="description" content={description} />
      <meta name="tags" content={keywords} />
      <meta name="keywords" content={keywords} />
      <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
      <meta name="format-detection" content="telephone=no" />

      {/* Open Graph */}
      <meta key="og:type" property="og:type" content="website" />
      <meta key="og:title" property="og:title" content={title} />
      <meta key="og:description" property="og:description" content={description} />
      <meta key="og:image" property="og:image" content={ogImage} />
      <meta key="og:image:width" property="og:image:width" content="1200" />
      <meta key="og:image:height" property="og:image:height" content="630" />
      <meta key="og:image:type" property="og:image:type" content="image/png" />
      {canonicalUrl && <meta key="og:url" property="og:url" content={canonicalUrl} />}
      <meta key="og:site_name" property="og:site_name" content={siteName} />

      {/* Twitter Card */}
      <meta key="twitter:card" name="twitter:card" content={twitterCard} />
      <meta key="twitter:title" name="twitter:title" content={title} />
      <meta key="twitter:description" name="twitter:description" content={description} />
      <meta key="twitter:image" name="twitter:image" content={twitterImage} />

      {/* Canonical */}
      {canonicalUrl && <link key="canonical" rel="canonical" href={canonicalUrl} />}

      {/* Favicon & app icons */}
      {settings.site_icon_url
        ? <link rel="icon" href={settings.site_icon_url} />
        : <link rel="icon" href="/favicon.ico" />
      }
      <link rel="apple-touch-icon" sizes="180x180" href="/apple-icon-180.png" />
      <link rel="icon" type="image/png" sizes="512x512" href="/icon-512.png" />
    </Head>
  );
}

// ── Analytics & custom head script injection ────────────────────────────────
// Reads analytics_google (GA4), analytics_umami, analytics_umami_src, and
// custom_head_script from site settings and injects the relevant scripts.
function AnalyticsScripts() {
  const settings = useSiteSettings();
  // Validate GA4 ID format (G-XXXXXXXXXX) to prevent script injection
  const rawGaId  = settings.analytics_google?.trim();
  const gaId     = rawGaId && /^G-[A-Z0-9]{4,20}$/i.test(rawGaId) ? rawGaId : undefined;
  const umamiId  = settings.analytics_umami?.trim();
  // Only allow http(s) URLs for Umami src to prevent javascript: injection
  const rawUmamiSrc = settings.analytics_umami_src?.trim() || "https://cloud.umami.is/script.js";
  const umamiSrc = /^https?:\/\//.test(rawUmamiSrc) ? rawUmamiSrc : "https://cloud.umami.is/script.js";
  const custom   = settings.custom_head_script?.trim();

  if (!gaId && !umamiId && !custom) return null;

  return (
    <Head>
      {/* Google Analytics 4 */}
      {gaId && (
        <>
          <script
            async
            src={`https://www.googletagmanager.com/gtag/js?id=${gaId}`}
          />
          <script
            dangerouslySetInnerHTML={{
              __html: `window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','${gaId}');`,
            }}
          />
        </>
      )}
      {/* Umami Analytics */}
      {umamiId && (
        <script
          defer
          src={umamiSrc}
          data-website-id={umamiId}
        />
      )}
      {/* Custom <head> script (admin-controlled) */}
      {custom && (
        <script
          dangerouslySetInnerHTML={{ __html: custom }}
        />
      )}
    </Head>
  );
}

function SiteFooter() {
  const settings = useSiteSettings();
  const router = useRouter();
  const { t } = useTranslation();
  const footerText = settings.site_footer;

  const footerLinks = [
    { href: "/faq",     label: t("nav_faq") },
    { href: "/privacy", label: t("nav_privacy") },
    { href: "/terms",   label: t("nav_terms") },
  ];

  if (router.pathname.startsWith("/admin")) return null;
  if (!footerText && footerLinks.length === 0) return null;
  return (
    <footer className="mt-4 py-4 px-4 text-center">
      <div className="flex items-center justify-center gap-5 mb-2">
        {footerLinks.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="text-xs text-muted-foreground/50 hover:text-muted-foreground transition-colors"
          >
            {link.label}
          </Link>
        ))}
      </div>
      {footerText && <p className="text-xs text-muted-foreground/40" suppressHydrationWarning>{footerText}</p>}
    </footer>
  );
}

const HOME_ANN_DISMISS_KEY = "home_ann_dismissed_v2";

type AnnRichItem = { text: string; color?: string; size?: "xs" | "sm" | "base"; bold?: boolean };
function parseAnnItems(raw: string): AnnRichItem[] {
  const trimmed = (raw || "").trim();
  if (trimmed.startsWith("[")) {
    try {
      const p = JSON.parse(trimmed);
      if (Array.isArray(p)) {
        const r = p.filter((i: unknown) => i && typeof (i as AnnRichItem).text === "string" && (i as AnnRichItem).text.trim());
        if (r.length > 0) return r as AnnRichItem[];
      }
    } catch {}
  }
  return trimmed.split("|").map(s => s.trim()).filter(Boolean).map(t => ({ text: t }));
}

function AnnouncementBanner() {
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const router = useRouter();
  const isHome = router.pathname === "/";

  const homeEnabled = settings.home_announcement_enabled === "1";
  const homeMsg = settings.home_announcement_text || "";
  const globalMsg = settings.site_announcement || "";
  const rawMsg = isHome && homeEnabled && homeMsg ? homeMsg : globalMsg;

  const [dismissed, setDismissed] = React.useState(false);
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  const items = React.useMemo(() => parseAnnItems(rawMsg), [rawMsg]);
  const visible = items.length > 0 && !dismissed;

  React.useEffect(() => {
    if (!isHome || !homeEnabled || !homeMsg) return;
    const hash = homeMsg.slice(0, 40);
    const stored = localStorage.getItem(HOME_ANN_DISMISS_KEY);
    setDismissed(stored === hash);
  }, [isHome, homeEnabled, homeMsg]);

  React.useEffect(() => {
    if (isHome) return;
    setDismissed(false);
  }, [globalMsg, isHome]);

  const handleDismiss = () => {
    if (isHome && homeEnabled && homeMsg) {
      localStorage.setItem(HOME_ANN_DISMISS_KEY, homeMsg.slice(0, 40));
    }
    setDismissed(true);
  };

  React.useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--ann-h", visible ? "32px" : "0px");
    return () => { root.style.setProperty("--ann-h", "0px"); };
  }, [visible]);

  React.useEffect(() => {
    if (items.length <= 1) return;
    setActiveIdx(0);
    const timer = setInterval(() => {
      setFading(true);
      setTimeout(() => {
        setActiveIdx(i => (i + 1) % items.length);
        setFading(false);
      }, 350);
    }, 4000);
    return () => clearInterval(timer);
  }, [items.length, rawMsg]);

  if (!visible) return null;

  const annUrl = isHome && homeEnabled ? (settings.home_announcement_url || "") : "";
  const current = items[activeIdx] ?? items[0];

  const textSpan = (
    <span
      className="min-w-0 truncate text-foreground/45"
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
  );

  return (
    <div className="fixed top-0 left-0 right-0 z-[60] flex items-center justify-center gap-2 px-4 h-8 text-[11px]">
      {/* Animated bell icon */}
      <RiBellLine
        className="w-3 h-3 shrink-0 text-foreground/30"
        style={{ animation: "ann-bell 5s ease-in-out infinite" }}
      />

      {/* Item text — centered, pure text, no box */}
      {annUrl ? (
        <Link
          href={annUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="min-w-0 truncate text-foreground/45 hover:text-foreground/70 transition-colors leading-none"
        >
          {textSpan}
        </Link>
      ) : (
        <span className="min-w-0 truncate leading-none">{textSpan}</span>
      )}

      {/* Dots for multiple items */}
      {items.length > 1 && (
        <div className="flex items-center gap-1 shrink-0">
          {items.map((_, i) => (
            <div
              key={i}
              className={`rounded-full transition-all duration-300 ${i === activeIdx ? "w-2.5 h-1 bg-foreground/25" : "w-1 h-1 bg-foreground/12"}`}
            />
          ))}
        </div>
      )}

      {/* Close */}
      <button
        onClick={handleDismiss}
        className="shrink-0 text-foreground/25 hover:text-foreground/55 transition-colors"
        aria-label={t("close_announcement")}
      >
        <RiCloseLine className="w-3 h-3" />
      </button>
    </div>
  );
}

const MAINTENANCE_TIP_KEYS = [
  "maintenance_tip_0",
  "maintenance_tip_1",
  "maintenance_tip_2",
  "maintenance_tip_3",
  "maintenance_tip_4",
] as const;

function MaintenanceGate({ children }: { children: React.ReactNode }) {
  const settings = useSiteSettings();
  const { t } = useTranslation();
  // Use the NextAuth session hook (already provided by SessionProvider above)
  // instead of a manual fetch so we never have a momentary undefined state
  // that causes a blank-page flash when navigating back to the homepage.
  const { data: session, status: sessionStatus } = useSession();
  const [tipIndex, setTipIndex] = React.useState(0);
  const [dots, setDots] = React.useState(".");

  React.useEffect(() => {
    if (settings.maintenance_mode !== "1") return;
    const tipTimer = setInterval(() => setTipIndex(i => (i + 1) % MAINTENANCE_TIP_KEYS.length), 3500);
    const dotTimer = setInterval(() => setDots(d => d.length >= 3 ? "." : d + "."), 500);
    return () => { clearInterval(tipTimer); clearInterval(dotTimer); };
  }, [settings.maintenance_mode]);

  if (settings.maintenance_mode !== "1") return <>{children}</>;
  // While auth status is resolving, render children so the page is never blank.
  // The maintenance screen replaces them once we know the user is not an admin.
  if (sessionStatus === "loading") return <>{children}</>;
  if ((session?.user as any)?.isAdmin === true) return <>{children}</>;

  const customMsg = settings.maintenance_message || settings.site_announcement;

  return (
    <div className="fixed inset-0 z-[200] flex flex-col items-center justify-center bg-background px-6 text-center overflow-hidden">
      {/* Subtle dot-grid background */}
      <div
        className="absolute inset-0 opacity-[0.03] dark:opacity-[0.06]"
        style={{ backgroundImage: "radial-gradient(circle, currentColor 1px, transparent 1px)", backgroundSize: "28px 28px" }}
      />

      {/* Animated icon cluster */}
      <div className="relative mb-8">
        {/* Outer slow orbit ring */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-28 h-28 rounded-full border border-amber-200/40 dark:border-amber-700/30 animate-spin" style={{ animationDuration: "8s" }} />
        </div>
        {/* Inner faster orbit */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-20 h-20 rounded-full border border-dashed border-amber-300/50 dark:border-amber-600/40 animate-spin" style={{ animationDuration: "4s", animationDirection: "reverse" }} />
        </div>
        {/* Center icon */}
        <div className="relative w-20 h-20 rounded-2xl bg-gradient-to-br from-amber-100 to-amber-50 dark:from-amber-900/40 dark:to-amber-950/60 border border-amber-200/60 dark:border-amber-700/40 flex items-center justify-center shadow-lg">
          <RiWrenchLine className="w-9 h-9 text-amber-600 dark:text-amber-400" style={{ animation: "maintenance-wrench 2s ease-in-out infinite" }} />
        </div>
        {/* Small satellites */}
        <div className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-blue-400/80 dark:bg-blue-500/60 flex items-center justify-center text-white text-[10px] animate-pulse">⚙</div>
        <div className="absolute -bottom-1 -left-1 w-4 h-4 rounded-full bg-emerald-400/80 dark:bg-emerald-500/60 flex items-center justify-center text-white text-[8px] animate-pulse" style={{ animationDelay: "0.5s" }}>✦</div>
      </div>

      {/* Title */}
      <h1 className="text-2xl font-bold mb-2 tracking-tight">
        <span className="bg-gradient-to-r from-amber-600 to-orange-500 dark:from-amber-400 dark:to-orange-400 bg-clip-text text-transparent">
          {t("maintenance_title")}
        </span>
        <span className="text-amber-600/60 dark:text-amber-400/60 font-normal ml-0.5">{dots}</span>
      </h1>

      {/* Progress bar (infinite looping) */}
      <div className="w-48 h-1 rounded-full bg-muted overflow-hidden mb-5">
        <div
          className="h-full rounded-full bg-gradient-to-r from-amber-400 to-orange-400"
          style={{
            animation: "maintenance-bar 2.5s ease-in-out infinite",
            width: "40%",
          }}
        />
      </div>

      {/* Rotating tip */}
      <p className="text-sm text-muted-foreground max-w-xs min-h-[2.5rem] flex items-center justify-center px-2">
        {t(MAINTENANCE_TIP_KEYS[tipIndex])}
      </p>

      {/* Custom message */}
      {customMsg && (
        <div className="mt-4 px-4 py-2.5 rounded-xl border border-border bg-muted/40 max-w-sm text-xs text-muted-foreground leading-relaxed">
          {customMsg}
        </div>
      )}

      {/* Refresh button */}
      <button
        onClick={() => window.location.reload()}
        className="mt-6 px-4 py-2 rounded-lg border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
      >
        {t("maintenance_refresh")}
      </button>

      {/* Keyframe injection */}
      <style>{`
        @keyframes maintenance-bar {
          0%   { transform: translateX(-100%); }
          50%  { transform: translateX(150%); }
          100% { transform: translateX(-100%); }
        }
        @keyframes maintenance-wrench {
          0%, 100% { transform: rotate(-12deg) scale(1); }
          50%       { transform: rotate(12deg) scale(1.08); }
        }
      `}</style>
    </div>
  );
}

// Pages that manage their own internal loading state via router events.
// They share a stable animation key so intra-page result updates don't
// trigger the global page-level enter/exit animation.
const STABLE_KEY_PAGES = new Set([
  "/",            // homepage — relies on search-box spinner + progress bar for feedback
  "/dns", "/ip", "/ssl", "/icp", "/tools", "/directory", "/http", "/feedback",
  "/[...query]",  // domain WHOIS results — skeleton handles loading feedback
]);

// Regular pages (about, login, privacy, etc.) get a subtle y slide-up on enter.
const pageVariants = {
  initial: { opacity: 0, y: 5 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.2, ease: [0.22, 1, 0.36, 1] as const },
  },
  exit: {
    opacity: 0,
    // ↓ Reduced from 0.1 → 0.05 s: shorter exit means less blank-screen gap
    //   before the new page's entry animation starts (AnimatePresence mode="wait").
    transition: { duration: 0.05, ease: "easeIn" as const },
  },
};

// Stable-key pages (result, DNS, IP…) manage their own skeleton/spinner loading
// feedback internally.  Enter and exit are instant with no opacity change so
// there is never a blank frame when swapping between stable pages — the new
// page mounts at full opacity the same frame the old page unmounts.
const stablePageVariants = {
  initial: { opacity: 1 },
  animate: { opacity: 1, transition: { duration: 0 } },
  exit:    { opacity: 1, transition: { duration: 0 } },
};

export default function App({ Component, pageProps: { session, ...pageProps } }: AppProps) {
  const origin: string = (pageProps as any).origin || process.env.NEXT_PUBLIC_SITE_URL || "";
  const initialLocale: Locale | undefined = (pageProps as any).initialLocale;
  const router = useRouter();
  const isAdminPage = router.pathname.startsWith("/admin");

  // ── Route-change progress bar ──────────────────────────────────────────────
  // Shown for navigations TO non-stable pages (login, about, etc.) AND for
  // cross-page navigations TO the result page (homepage → result).
  // Skipped for result → result shallow navigation (QueryProgressBar handles it).
  const [npStatus, setNpStatus] = React.useState<"idle" | "start" | "done">("idle");
  const npResetRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  // Track the current pathname so event handlers can know where we came from.
  const currentPathnameRef = React.useRef(router.pathname);
  React.useEffect(() => { currentPathnameRef.current = router.pathname; }, [router.pathname]);
  React.useEffect(() => {
    const isQueryPagePath = (p: string) =>
      p !== "/" && !p.startsWith("/admin") && !p.startsWith("/api") && p.split("/").length >= 2;
    const OTHER_STABLE = new Set(["/", "/dns", "/ip", "/ssl", "/icp", "/tools", "/directory", "/http", "/feedback"]);
    const onStart = (url: string) => {
      // Extract pathname from url (may include query string / hash)
      const dest = url.split("?")[0].split("#")[0];
      const destIsQueryPage = isQueryPagePath(dest);
      const sourceIsQueryPage = currentPathnameRef.current === "/[...query]";

      // result → result: shallow routing — QueryProgressBar handles this
      if (sourceIsQueryPage && destIsQueryPage) return;

      // Navigation TO any result/query page: the skeleton + QueryProgressBar
      // provide all the loading feedback needed — no top bar required here.
      // (The bar would linger until getServerSideProps finishes, making it look
      //  like the result page doesn't start until the bar completes.)
      if (destIsQueryPage) return;

      // Other self-contained stable pages (DNS, IP, etc.) manage their own feedback
      if (OTHER_STABLE.has(dest)) return;

      // Everything else (login, about, register …): show bar
      if (npResetRef.current) clearTimeout(npResetRef.current);
      setNpStatus("start");
    };
    const onDone = () => {
      setNpStatus("done");
      npResetRef.current = setTimeout(() => setNpStatus("idle"), 400);
    };
    router.events.on("routeChangeStart",    onStart);
    router.events.on("routeChangeComplete", onDone);
    router.events.on("routeChangeError",    onDone);
    return () => {
      router.events.off("routeChangeStart",    onStart);
      router.events.off("routeChangeComplete", onDone);
      router.events.off("routeChangeError",    onDone);
      if (npResetRef.current) clearTimeout(npResetRef.current);
    };
  }, [router]);

  // Pages in STABLE_KEY_PAGES manage their own loading feedback internally
  // (skeleton screens, spinners, etc.) and don't need the global page-level
  // enter/exit animation for intra-page navigations. Every other page gets
  // a unique key per URL, triggering the slide-up enter / fade-out exit.
  const isStablePage = STABLE_KEY_PAGES.has(router.pathname);
  const animationKey = isStablePage ? router.pathname : router.asPath;

  return (
    <SessionProvider session={session}>
    <LocaleProvider initialLocale={initialLocale}>
    <SiteSettingsProvider initialSettings={(pageProps as any).initialSiteSettings}>
      <AppHead origin={origin} />
      <AnalyticsScripts />
      <Toaster />
      {/* Route-change progress bar — only shown client-side (npStatus starts "idle") */}
      {npStatus !== "idle" && (
        <div
          aria-hidden
          style={{
            position:        "fixed",
            top:             0,
            left:            0,
            width:           "100%",
            height:          "2px",
            zIndex:          9999,
            pointerEvents:   "none",
            transformOrigin: "left center",
            transform:       "scaleX(0)",
            background:      "hsl(var(--primary))",
            animation:       npStatus === "done"
              ? "np-done 0.35s ease forwards"
              : "np-start 8s ease-out forwards",
          }}
        />
      )}
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
      >
        <div className="fixed inset-0 -z-10">
          <div className="absolute inset-0 bg-dot-pattern opacity-[0.055]" />
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/20 to-background" />
        </div>
        <MaintenanceGate>
        <div className="relative w-full min-h-screen font-sans">
          {!isAdminPage && <AnnouncementBanner />}
          {!isAdminPage && <Navbar />}
          <main style={!isAdminPage ? { paddingTop: "calc(4rem + var(--ann-h, 0px))" } : undefined}>
            {isAdminPage ? (
              <ErrorBoundary>
                <Component {...pageProps} />
              </ErrorBoundary>
            ) : (
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={animationKey}
                  variants={isStablePage ? stablePageVariants : pageVariants}
                  initial="initial"
                  animate="animate"
                  exit="exit"
                  style={{ willChange: isStablePage ? "opacity" : "opacity, transform" }}
                >
                  <ErrorBoundary>
                    <Component {...pageProps} />
                  </ErrorBoundary>
                </motion.div>
              </AnimatePresence>
            )}
            {!isAdminPage && <SiteFooter />}
          </main>
        </div>
        </MaintenanceGate>
      </ThemeProvider>
    </SiteSettingsProvider>
    </LocaleProvider>
    <Analytics />
    <SpeedInsights />
    </SessionProvider>
  );
}

/**
 * Read the locale that the middleware injected into the request headers
 * (x-detected-locale) and pass it to every page as initialLocale so that
 * SSR renders in the correct language from the very first byte — no flash.
 *
 * Note: adding getInitialProps here opts all pages into SSR (disables
 * automatic static optimisation), which is acceptable because this app is
 * already SSR-heavy (WHOIS/RDAP lookups, getServerSideProps everywhere).
 */
App.getInitialProps = async (appCtx: AppContext) => {
  let initialLocale: Locale = "en";

  if (appCtx.ctx.req) {
    // 1. Header injected by middleware (works for first-time visitors too)
    const fromHeader = appCtx.ctx.req.headers["x-detected-locale"];
    const hVal = Array.isArray(fromHeader) ? fromHeader[0] : fromHeader;
    if (hVal && (LOCALES as readonly string[]).includes(hVal)) {
      initialLocale = hVal as Locale;
    } else {
      // 2. Fallback: read NEXT_LOCALE cookie directly from the request
      const cookieHeader = appCtx.ctx.req.headers.cookie ?? "";
      const match = cookieHeader.match(/(?:^|;\s*)NEXT_LOCALE=([^;]+)/);
      if (match && (LOCALES as readonly string[]).includes(match[1])) {
        initialLocale = match[1] as Locale;
      }
    }
  }

  // Use the built-in Next.js App.getInitialProps so that getStaticProps and
  // getServerSideProps data is correctly fetched on client-side navigation.
  // The previous manual Component.getInitialProps call skipped getStaticProps
  // pages (like the homepage), causing their props to be undefined after
  // client-side navigation and rendering a blank page.
  const appProps = await NextApp.getInitialProps(appCtx);

  return {
    ...appProps,
    pageProps: { ...appProps.pageProps, initialLocale },
  };
};
