import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const LOCALES = ["en", "zh", "zh-tw", "de", "ru", "ja", "fr", "ko"] as const;
type Locale = (typeof LOCALES)[number];

/**
 * Parse the Accept-Language header into the best matching locale.
 * Handles weighted quality values (e.g. "zh-TW,zh;q=0.9,en;q=0.8").
 */
function detectFromAcceptLanguage(header: string | null): Locale | null {
  if (!header) return null;

  const entries = header
    .split(",")
    .map((s) => {
      const [lang, q] = s.trim().split(";q=");
      return { lang: lang.trim().toLowerCase(), q: q ? parseFloat(q) : 1.0 };
    })
    .sort((a, b) => b.q - a.q);

  for (const { lang } of entries) {
    if (lang.startsWith("zh-tw") || lang.startsWith("zh-hk") || lang.startsWith("zh-mo")) return "zh-tw";
    if (lang.startsWith("zh")) return "zh";
    if (lang.startsWith("de")) return "de";
    if (lang.startsWith("ru")) return "ru";
    if (lang.startsWith("ja")) return "ja";
    if (lang.startsWith("fr")) return "fr";
    if (lang.startsWith("ko")) return "ko";
    if (lang.startsWith("en")) return "en";
  }
  return null;
}

/**
 * Map a two-letter country code (from Vercel / Cloudflare headers) to a
 * locale.  Used only as a fallback when Accept-Language gives no useful
 * result (e.g. the browser sends only "en" but the user is in China).
 */
function detectFromCountry(country: string | null): Locale | null {
  if (!country) return null;
  const map: Record<string, Locale> = {
    CN: "zh",
    TW: "zh-tw",
    HK: "zh-tw",
    MO: "zh-tw",
    JP: "ja",
    KR: "ko",
    DE: "de",
    AT: "de",
    LI: "de",
    RU: "ru",
    BY: "ru",
    KZ: "ru",
    FR: "fr",
    MC: "fr",
  };
  return map[country.toUpperCase()] ?? null;
}

// Empty webpack HMR manifest — tells the browser "no modules changed".
// Used in development to prevent 404 → full-reload loops when a hot-update
// file for a stale compilation hash is no longer on disk.
const EMPTY_HMR_MANIFEST = JSON.stringify({ c: {}, r: [], m: [] });

export function middleware(request: NextRequest) {
  // ── Webpack static files: pass through or HMR fallback ─────────────────
  if (request.nextUrl.pathname.startsWith("/_next/static/webpack/")) {
    // In development, Next.js compiles on demand.  If the browser holds a
    // stale webpack runtime hash (e.g. from an immutable-cached old chunk),
    // the server generates hot-update files for a DIFFERENT hash transition
    // and tells the browser to fetch its hash's manifest, which 404s.
    // The 404 causes Fast Refresh to do a full reload — repeating forever.
    //
    // Returning an empty "no modules changed" manifest for ANY hot-update
    // JSON request (whether the file exists or not) makes HMR advance its
    // internal hash without crashing, breaking the loop.  The trade-off is
    // that HMR stops applying code diffs in this dev environment, but since
    // it was already broken by the infinite-loop, this is strictly better.
    if (
      process.env.NODE_ENV === "development" &&
      (request.nextUrl.pathname.includes(".webpack.hot-update.json") ||
        request.nextUrl.pathname.includes("._.hot-update.json"))
    ) {
      return new NextResponse(EMPTY_HMR_MANIFEST, {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      });
    }
    // All other webpack static files (chunks, HMR JS modules, etc.) —
    // let them pass through to the static file handler unchanged.
    return NextResponse.next();
  }

  // ── Determine which locale to use ───────────────────────────────────────
  const existingCookie = request.cookies.get("NEXT_LOCALE")?.value as Locale | undefined;
  const hasValidCookie = existingCookie && (LOCALES as readonly string[]).includes(existingCookie);

  let detected: Locale | null = null;
  if (!hasValidCookie) {
    // 1. Browser language (most accurate – reflects what the user configured)
    detected = detectFromAcceptLanguage(request.headers.get("accept-language"));

    // 2. CDN country header as fallback (Vercel or Cloudflare)
    if (!detected) {
      const country =
        request.headers.get("x-vercel-ip-country") ??
        request.headers.get("cf-ipcountry");
      detected = detectFromCountry(country);
    }
  }

  const locale: Locale = hasValidCookie ? existingCookie : detected ?? "en";

  // ── Forward detected locale to the page handler via a request header ────
  // This lets App.getInitialProps render in the right language on the server
  // without any URL locale prefix, avoiding the client-side hydration flash.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-detected-locale", locale);

  const res = NextResponse.next({
    request: { headers: requestHeaders },
  });

  // ── Persist the locale in a cookie (1-year, SameSite=Lax) ───────────────
  if (!hasValidCookie && detected) {
    res.cookies.set("NEXT_LOCALE", detected, {
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
      sameSite: "lax",
    });
  }

  // Prevent stale redirect caches from old locale-prefixed URLs.
  res.headers.set("Cache-Control", "no-store, must-revalidate");

  return res;
}

export const config = {
  matcher: [
    // Standard page routes (excludes _next/static, _next/image, api, assets)
    "/((?!_next/static|_next/image|api|favicon.ico|icons|images|.*\\..*).*)",
    // Dev-only: intercept webpack HMR hot-update manifests so stale hashes
    // don't cause 404 → infinite full-reload loops.
    "/_next/static/webpack/(.*)",
  ],
};
