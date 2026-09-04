/** @type {import('next').NextConfig} */

const setupPWA = require('next-pwa');
const { withSentryConfig } = require('@sentry/nextjs');

const SECURITY_HEADERS = [
  { key: 'X-Frame-Options',              value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options',       value: 'nosniff' },
  { key: 'X-XSS-Protection',             value: '1; mode=block' },
  { key: 'Referrer-Policy',              value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy',           value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  { key: 'Strict-Transport-Security',    value: 'max-age=63072000; includeSubDomains; preload' },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      // Captcha providers (Turnstile / hCaptcha / MTCaptcha) need their own CDN
      // origins in both script-src (JS) and frame-src (verification iframe).
      "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://va.vercel-scripts.com https://challenges.cloudflare.com https://js.hcaptcha.com https://newassets.hcaptcha.com https://service.mtcaptcha.com",
      "style-src 'self' 'unsafe-inline' https://newassets.hcaptcha.com https://service.mtcaptcha.com",
      "img-src * data: blob:",
      "font-src 'self' data: https://newassets.hcaptcha.com",
      "connect-src * data:",
      "frame-src 'self' https://challenges.cloudflare.com https://newassets.hcaptcha.com https://hcaptcha.com https://service.mtcaptcha.com https://serviceworker.mtcaptcha.com",
      "media-src 'self'",
      "worker-src 'self' blob:",
    ].join('; '),
  },
];

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  compress: true,
  optimizeFonts: true,
  async redirects() {
    return [
      // Consolidated admin pages → unified pages
      { source: "/admin/access-keys",             destination: "/admin/access-control",          permanent: true },
      { source: "/admin/invite-codes",             destination: "/admin/access-control?tab=invite",      permanent: true },
      { source: "/admin/activation-codes",         destination: "/admin/access-control?tab=activation",  permanent: true },
      { source: "/admin/custom-servers",           destination: "/admin/domains?tab=servers",     permanent: true },
      { source: "/admin/repair-queue",             destination: "/admin/domains?tab=servers",     permanent: true },
      { source: "/admin/tld-lifecycle",            destination: "/admin/domains",                 permanent: true },
      { source: "/admin/tld-lifecycle-feedback",   destination: "/admin/domains",                 permanent: true },
      { source: "/admin/tld-probe",                destination: "/admin/domains?tab=servers",     permanent: true },
      { source: "/admin/tld-registry",             destination: "/admin/domains?tab=iana",        permanent: true },
    ];
  },
  // Allow proxied dev domains (e.g. ngrok, Replit, etc.) to load _next/* resources.
  // These are dev-only settings and have no effect in production.
  allowedDevOrigins: [
    ...(process.env.ALLOWED_DEV_ORIGINS ? process.env.ALLOWED_DEV_ORIGINS.split(",").map(s => s.trim()) : []),
    ...(process.env.REPLIT_DEV_DOMAIN ? [process.env.REPLIT_DEV_DOMAIN] : []),
    "*.replit.dev",
    "*.repl.co",
  ],
  images: {
    formats: ['image/avif', 'image/webp'],
    minimumCacheTTL: 86400,
  },
  async headers() {
    const isDev = process.env.NODE_ENV === 'development';
    return [
      {
        // Apply security headers to all pages and API routes
        source: '/(.*)',
        headers: SECURITY_HEADERS,
      },
      // In production, Next.js static assets are content-addressed (hash in
      // filename) so they can be cached indefinitely.  In development the same
      // paths are reused across recompilations, so "immutable" caching causes
      // the browser to serve stale webpack chunks and breaks HMR (the browser
      // keeps requesting old hot-update manifests → 404 → infinite full reload).
      ...(isDev ? [] : [{
        source: '/_next/static/(.*)',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
        ],
      }]),
      {
        // Icons and images in /public are mostly stable
        source: '/(icons|images)/(.*)',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=86400, stale-while-revalidate=604800' },
        ],
      },
      {
        // Favicon proxy — already sets its own Cache-Control in the handler,
        // but this ensures Vercel's edge cache also stores it
        source: '/api/favicon',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=86400, stale-while-revalidate=3600' },
        ],
      },
    ];
  },
  ...(process.env.NEXT_BUILD_DIR ? { distDir: process.env.NEXT_BUILD_DIR } : {}),
  webpack: (config, { isServer, dev }) => {
    if (isServer) {
      config.externals = [
        ...(Array.isArray(config.externals) ? config.externals : []),
        // These are ESM-only packages; keep as externals and load via dynamic
        // import() at runtime (CJS dynamic import() handles ESM correctly).
        'whoiser',
        'node-rdap',
        'ioredis',
        'nodemailer',
      ];
    } else {
      // In the client bundle, server-only packages should never be executed
      // (they live exclusively in getServerSideProps / API routes), but
      // webpack may still try to resolve their transitive Node.js built-in
      // dependencies, producing an undefined module factory and the runtime
      // error "originalFactory.call is not a function".
      // Setting each built-in to `false` tells webpack to emit an empty
      // stub module instead of leaving the factory undefined.
      config.resolve.fallback = {
        ...config.resolve.fallback,
        net: false,
        tls: false,
        dns: false,
        fs: false,
        crypto: false,
        stream: false,
        http: false,
        https: false,
        zlib: false,
        path: false,
        os: false,
        child_process: false,
        dgram: false,
        cluster: false,
      };

    }
    return config;
  },
};

const withPWA = setupPWA({
  dest: 'public',
  disable: process.env.NODE_ENV === 'development',
  register: true,
  skipWaiting: true,
  buildExcludes: [/manifest\.json$/, /_next\/data/, /_next\/static/],
  runtimeCaching: [
    {
      urlPattern: /^https?.*\.(css|js|woff2)$/,
      handler: 'CacheFirst',
      options: {
        cacheName: 'assets-cache',
        expiration: {
          maxEntries: 200,
          maxAgeSeconds: 7 * 24 * 60 * 60,
        },
      },
    },
  ],
});

// ── Sentry source-map upload (build-time only) ─────────────────────────────
// Runtime init stays lazy (src/lib/monitoring-server.ts + _app useEffect), so
// this wrapper ONLY handles source-map generation/upload during `next build`.
// When SENTRY_AUTH_TOKEN is unset (local dev, contributors) the plugin is
// fully disabled and the build behaves exactly as before.
const sentryWebpackPluginOptions = {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  authToken: process.env.SENTRY_AUTH_TOKEN,
  // Tag uploads with the commit SHA on Vercel so runtime events (which read
  // VERCEL_GIT_COMMIT_SHA) associate with the same release; locally the
  // plugin falls back to auto-detection (Next.js build ID).
  release: process.env.VERCEL_GIT_COMMIT_SHA || undefined,
  sourcemaps: { disable: !process.env.SENTRY_AUTH_TOKEN, deleteSourcemapsAfterUpload: true },
  telemetry: false,
  silent: true,
};

module.exports = withSentryConfig(withPWA(nextConfig), sentryWebpackPluginOptions);
