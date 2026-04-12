import { Html, Head, Main, NextScript } from "next/document";
import { geistSans, geistMono } from "@/lib/fonts";

export default function Document() {
  return (
    <Html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <Head>
        {/* Baseline identity — overridden per-page by AppHead in _app.tsx */}
        <meta name="application-name" content="Next Whois" />

        {/* Theme color for mobile browser chrome / PWA */}
        <meta name="theme-color" content="#000000" media="(prefers-color-scheme: dark)" />
        <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)" />

        {/* Preconnect to third-party APIs actually called from the browser */}
        <link rel="preconnect" href="https://api.frankfurter.dev" />
        <link rel="dns-prefetch" href="https://api.frankfurter.dev" />
        <link rel="dns-prefetch" href="https://cdn.simpleicons.org" />
        <link rel="dns-prefetch" href="https://flagcdn.com" />
      </Head>
      <body>
        {/* Guard: In dev mode, Next.js compiles pages lazily; after first
            compile it sends an HMR full-reload signal. If navigation happens
            mid-reload, webpack's async chunk loader (require.e) may not be
            initialised yet — causing "require.e is not a function".
            We catch that specific error and do window.location.reload() to
            complete the HMR cycle that was already in progress.
            A 10-second cooldown prevents infinite reload loops. */}
        <script dangerouslySetInnerHTML={{ __html: `(function(){var K='__rqe_ts__';function fix(m){if(!m||m.indexOf('require.e')===-1)return;try{var t=parseInt(sessionStorage.getItem(K)||'0',10);if(Date.now()-t<10000)return;sessionStorage.setItem(K,String(Date.now()));}catch(e){}window.location.reload();}window.addEventListener('error',function(e){fix(e&&e.message);});window.addEventListener('unhandledrejection',function(e){fix(e&&e.reason&&(e.reason.message||String(e.reason)));});})();` }} />
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
