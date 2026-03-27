import "@/styles/globals.css";
import React from "react";
import type { AppProps } from "next/app";
import Head from "next/head";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/components/theme-provider";
import { siteTitle, siteDescription, siteKeywords } from "@/lib/seo";
import { Navbar } from "@/components/navbar";
import { useRouter } from "next/router";
import { AnimatePresence, motion } from "framer-motion";
import { SessionProvider } from "next-auth/react";
import { LocaleProvider } from "@/lib/locale-context";
import { SiteSettingsProvider, useSiteSettings } from "@/lib/site-settings";
import { RiMegaphoneLine, RiCloseLine, RiWrenchLine } from "@remixicon/react";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
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
      <meta key="og:image:height" property="og:image:height" content="1200" />
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

const FOOTER_LINKS = [
  { href: "/faq", label: "FAQ" },
  { href: "/privacy", label: "Privacy" },
  { href: "/terms", label: "Terms" },
];

function SiteFooter() {
  const settings = useSiteSettings();
  const router = useRouter();
  const footerText = settings.site_footer;
  if (router.pathname.startsWith("/admin")) return null;
  if (!footerText && FOOTER_LINKS.length === 0) return null;
  return (
    <footer className="border-t border-border/40 mt-12 py-5 px-4 text-center">
      <div className="flex items-center justify-center gap-5 mb-2">
        {FOOTER_LINKS.map((link) => (
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

function AnnouncementBanner() {
  const settings = useSiteSettings();
  const [dismissed, setDismissed] = React.useState(false);
  const msg = settings.site_announcement;
  const visible = !!msg && !dismissed;

  React.useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--ann-h", visible ? "36px" : "0px");
    return () => { root.style.setProperty("--ann-h", "0px"); };
  }, [visible]);

  if (!msg || dismissed) return null;
  return (
    <div className="fixed top-0 left-0 right-0 z-[60] flex items-center justify-center px-4 py-2 bg-gradient-to-r from-primary to-violet-600 text-white text-xs font-medium gap-2 shadow-md">
      <RiMegaphoneLine className="w-3.5 h-3.5 shrink-0" />
      <span className="flex-1 text-center">{msg}</span>
      <button
        onClick={() => setDismissed(true)}
        className="p-0.5 rounded hover:bg-white/20 transition-colors shrink-0"
        aria-label="关闭公告"
      >
        <RiCloseLine className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

function MaintenanceGate({ children }: { children: React.ReactNode }) {
  const settings = useSiteSettings();
  const [sessionEmail, setSessionEmail] = React.useState<string | null | undefined>(undefined);

  React.useEffect(() => {
    if (settings.maintenance_mode !== "1") return;
    fetch("/api/auth/session")
      .then(r => r.json())
      .then(s => setSessionEmail((s?.user?.email as string) || null))
      .catch(() => setSessionEmail(null));
  }, [settings.maintenance_mode]);

  if (settings.maintenance_mode !== "1") return <>{children}</>;
  if (sessionEmail === undefined) return null;
  if (sessionEmail && sessionEmail.toLowerCase().trim() === ADMIN_EMAIL) return <>{children}</>;

  return (
    <div className="fixed inset-0 z-[200] flex flex-col items-center justify-center bg-background px-6 text-center">
      <div className="w-14 h-14 rounded-2xl bg-amber-100 dark:bg-amber-950/50 flex items-center justify-center mb-5">
        <RiWrenchLine className="w-7 h-7 text-amber-600 dark:text-amber-400" />
      </div>
      <h1 className="text-xl font-bold mb-2">站点维护中</h1>
      <p className="text-sm text-muted-foreground max-w-xs">
        系统正在升级维护，请稍后再访问。感谢您的耐心等待。
      </p>
      {settings.site_announcement && (
        <p className="mt-4 text-xs text-muted-foreground/70 border border-border rounded-xl px-4 py-2 max-w-xs">
          {settings.site_announcement}
        </p>
      )}
    </div>
  );
}

// Pages that manage their own internal loading state via router events.
// They share a stable animation key so intra-page result updates don't
// trigger the global page-level enter/exit animation.
const STABLE_KEY_PAGES = new Set([
  "/dns", "/ip", "/ssl", "/icp", "/tools", "/directory", "/http", "/feedback",
  "/[...query]",  // domain WHOIS results — skeleton handles loading feedback
]);

const pageVariants = {
  initial: { opacity: 0 },
  animate: {
    opacity: 1,
    transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] as const },
  },
  exit: {
    opacity: 0,
    transition: { duration: 0.08, ease: "easeIn" as const },
  },
};


export default function App({ Component, pageProps: { session, ...pageProps } }: AppProps) {
  const origin: string = pageProps.origin || process.env.NEXT_PUBLIC_SITE_URL || "";
  const router = useRouter();
  const isAdminPage = router.pathname.startsWith("/admin");

  // Pages in STABLE_KEY_PAGES manage their own loading feedback internally
  // (skeleton screens, spinners, etc.) and don't need the global page-level
  // enter/exit animation for intra-page navigations. Every other page gets
  // a unique key per URL, triggering the slide-up enter / fade-out exit.
  const animationKey = STABLE_KEY_PAGES.has(router.pathname)
    ? router.pathname
    : router.asPath;

  return (
    <SessionProvider session={session}>
    <LocaleProvider>
    <SiteSettingsProvider>
      <AppHead origin={origin} />
      <Toaster />
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
                  variants={pageVariants}
                  initial="initial"
                  animate="animate"
                  exit="exit"
                  style={{ willChange: "opacity" }}
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
    </SessionProvider>
  );
}
