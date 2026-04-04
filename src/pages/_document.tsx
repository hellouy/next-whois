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
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
