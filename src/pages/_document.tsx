import { Html, Head, Main, NextScript } from "next/document";
import { geistSans, geistMono } from "@/lib/fonts";

export default function Document() {
  return (
    <Html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <Head>
        {/* Site-wide identity */}
        <meta property="og:site_name" content="RDAP+WHOIS 域名查询" />
        <meta name="twitter:site" content="@nextwhois" />
        <meta name="application-name" content="Next Whois" />

        {/* DNS prefetch for third-party APIs used client-side */}
        <link rel="preconnect" href="https://api.frankfurter.dev" />
        <link rel="dns-prefetch" href="https://api.frankfurter.dev" />
        <link rel="dns-prefetch" href="https://rdap.iana.org" />
        <link rel="dns-prefetch" href="https://data.iana.org" />
      </Head>
      <body>
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
