import "@/styles/globals.css";
import React from "react";
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
import { SessionProvider } from "next-auth/react";
import { LocaleProvider, LOCALES, type Locale } from "@/lib/locale-context";
import { SiteSettingsProvider, useSiteSettings } from "@/lib/site-settings";
import { RiMegaphoneLine, RiCloseLine, RiWrenchLine } from "@remixicon/react";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { useTranslation } from "@/lib/i18n";
import Link from "next/link";


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
      <meta name="viewport" content="width=device-width, initial-scale=1" />
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
    <footer className="border-t border-border/40 mt-12 py-5 px-4 text-center">
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
      {footerText && <p className="text-xs text-muted-foreground/40">{footerText}</p>}
    </footer>
  );
}

const HOME_ANN_DISMISS_KEY = "home_ann_dismissed_v2";

function AnnouncementBanner() {
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const router = useRouter();
  const isHome = router.pathname === "/";

  // Pick announcement source: homepage-specific on "/", global elsewhere
  const homeEnabled = settings.home_announcement_enabled === "1";
  const homeMsg = settings.home_announcement_text || "";
  const globalMsg = settings.site_announcement || "";
  const rawMsg = isHome && homeEnabled && homeMsg ? homeMsg : (!isHome ? globalMsg : globalMsg);

  const [dismissed, setDismissed] = React.useState(false);
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  const items = React.useMemo(
    () => (rawMsg || "").split("|").map(s => s.trim()).filter(Boolean),
    [rawMsg],
  );
  const visible = items.length > 0 && !dismissed;

  // For homepage announcement: persist dismiss in localStorage keyed by text hash
  // so changing the text auto-reappears the bar.
  React.useEffect(() => {
    if (!isHome || !homeEnabled || !homeMsg) return;
    const hash = homeMsg.slice(0, 40);
    const stored = localStorage.getItem(HOME_ANN_DISMISS_KEY);
    setDismissed(stored === hash);
  }, [isHome, homeEnabled, homeMsg]);

  // For global announcement: reset dismissed when message changes
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

  return (
    <div className="fixed top-0 left-0 right-0 z-[60] flex items-center justify-center gap-2 px-4 h-8 text-xs font-medium border-b border-border/30 bg-background/80 backdrop-blur-sm">
      <RiMegaphoneLine
        className="w-3.5 h-3.5 shrink-0 text-primary"
        style={{ animation: "ann-horn 2.4s ease-in-out infinite" }}
      />
      <span
        className="text-foreground/80 text-center truncate transition-opacity duration-300"
        style={{ opacity: fading ? 0 : 1 }}
      >
        <span className="font-semibold text-primary mr-1">公告：</span>
        {items[activeIdx]}
      </span>
      <button
        onClick={handleDismiss}
        className="ml-auto p-0.5 rounded hover:bg-muted/60 transition-colors shrink-0 text-muted-foreground hover:text-foreground"
        aria-label={t("close_announcement")}
      >
        <RiCloseLine className="w-3.5 h-3.5" />
      </button>
      <style>{`
        @keyframes ann-horn {
          0%, 100% { transform: rotate(-8deg) scale(1); }
          25%       { transform: rotate(8deg) scale(1.1); }
          50%       { transform: rotate(-6deg) scale(1); }
          75%       { transform: rotate(6deg) scale(1.05); }
        }
      `}</style>
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
  const [sessionEmail, setSessionEmail] = React.useState<string | null | undefined>(undefined);
  const [tipIndex, setTipIndex] = React.useState(0);
  const [dots, setDots] = React.useState(".");

  React.useEffect(() => {
    if (settings.maintenance_mode !== "1") return;
    fetch("/api/auth/session")
      .then(r => r.json())
      .then(s => setSessionEmail((s?.user?.email as string) || null))
      .catch(() => setSessionEmail(null));
  }, [settings.maintenance_mode]);

  React.useEffect(() => {
    if (settings.maintenance_mode !== "1") return;
    const tipTimer = setInterval(() => setTipIndex(i => (i + 1) % MAINTENANCE_TIP_KEYS.length), 3500);
    const dotTimer = setInterval(() => setDots(d => d.length >= 3 ? "." : d + "."), 500);
    return () => { clearInterval(tipTimer); clearInterval(dotTimer); };
  }, [settings.maintenance_mode]);

  if (settings.maintenance_mode !== "1") return <>{children}</>;
  if (sessionEmail === undefined) return null;
  if (sessionEmail && sessionEmail.toLowerCase().trim() === ADMIN_EMAIL) return <>{children}</>;

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
// feedback internally.  Both enter and exit are instant so there is no
// "blank flash" between the homepage and the result skeleton — the skeleton
// appears in the same frame that the homepage disappears.
const stablePageVariants = {
  initial: { opacity: 1 },
  animate: { opacity: 1, transition: { duration: 0 } },
  exit:    { opacity: 0, transition: { duration: 0 } },
};

export default function App({ Component, pageProps: { session, ...pageProps } }: AppProps) {
  const origin: string = (pageProps as any).origin || process.env.NEXT_PUBLIC_SITE_URL || "";
  const initialLocale: Locale | undefined = (pageProps as any).initialLocale;
  const router = useRouter();
  const isAdminPage = router.pathname.startsWith("/admin");

  // ── Route-change progress bar ──────────────────────────────────────────────
  // Only shown for navigations TO non-stable pages (login, about, etc.).
  // Stable pages (homepage, result, DNS…) show their own skeleton/spinner, so
  // the top bar would create a distracting double-loading signal.
  // Derive the destination pathname from the URL passed to routeChangeStart.
  const [npStatus, setNpStatus] = React.useState<"idle" | "start" | "done">("idle");
  const npResetRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  React.useEffect(() => {
    const onStart = (url: string) => {
      // Extract pathname from url (may include query string / hash)
      const dest = url.split("?")[0].split("#")[0];
      // Determine if destination matches any stable page pattern
      const destIsStable = [...STABLE_KEY_PAGES].some(p => {
        if (!p.includes("[")) return dest === p;           // exact match
        if (p === "/[...query]") return dest !== "/" && !dest.startsWith("/admin") && dest.split("/").length >= 2;
        return false;
      });
      if (destIsStable) return; // stable page handles its own loading feedback
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
              <Component {...pageProps} />
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
                  <Component {...pageProps} />
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

  // Collect page-level props (without triggering getInitialProps on the page
  // itself — pages with getServerSideProps handle their own data fetching).
  const pageProps = appCtx.Component.getInitialProps
    ? await appCtx.Component.getInitialProps(appCtx.ctx)
    : {};

  return { pageProps: { ...pageProps, initialLocale } };
};
