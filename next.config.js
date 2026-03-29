/** @type {import('next').NextConfig} */

const setupPWA = require('next-pwa');

const SECURITY_HEADERS = [
  { key: 'X-Frame-Options',           value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options',    value: 'nosniff' },
  { key: 'X-XSS-Protection',          value: '1; mode=block' },
  { key: 'Referrer-Policy',           value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy',        value: 'camera=(), microphone=(), geolocation=(), payment=()' },
];

const nextConfig = {
  typescript: { ignoreBuildErrors: true },
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
  // Allow Replit's proxied dev domain to load _next/* resources without warnings
  allowedDevOrigins: [
    "*.replit.dev",
    "*.kirk.replit.dev",
    "*.worf.replit.dev",
    "*.riker.replit.dev",
    "*.repl.co",
  ],
  images: {
    formats: ['image/avif', 'image/webp'],
    minimumCacheTTL: 86400,
  },
  async headers() {
    return [
      {
        // Apply security headers to all pages and API routes
        source: '/(.*)',
        headers: SECURITY_HEADERS,
      },
      {
        // Next.js build artifacts are content-addressed — safe to cache forever
        source: '/_next/static/(.*)',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
        ],
      },
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
  webpack: (config, { isServer }) => {
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

module.exports = withPWA(nextConfig);
