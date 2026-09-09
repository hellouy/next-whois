/**
 * Dev-server prewarm.
 *
 * `next dev` compiles routes lazily on first request ("on-demand
 * compilation"), which is what makes the homepage, a WHOIS query and its API
 * feel slow on the very first visit after a restart. This script walks every
 * major page/API once so their webpack bundles are compiled ahead of time;
 * after it finishes, real users hit warm routes and get results immediately.
 *
 * Usage:  node scripts/prewarm.mjs   (run after `npm run dev` is up)
 * Env:    PREWARM_BASE  base URL, defaults to http://localhost:5000
 */
const BASE = process.env.PREWARM_BASE || "http://localhost:5000";

const targets = [
  "/",
  "/a.app",
  "/batch-check",
  "/stamp?domain=a.app",
  "/about",
  "/docs",
  "/changelog",
  "/terms",
  "/privacy",
  "/api/og-config",
  "/api/og?query=a.app&theme=dark",
  "/api/og?query=a.app&theme=dark&lang=zh",
  "/api/whois-servers",
  "/api/pricing?tld=app",
  "/api/lookup?query=a.app",
  "/api/lookup-stream?query=a.app",
  "/api/user/dashboard",
  "/api/admin/settings",
];

async function hit(url) {
  const start = Date.now();
  try {
    const res = await fetch(BASE + url, {
      signal: AbortSignal.timeout(25000),
      headers: { Origin: BASE, Referer: BASE + "/" },
    });
    const ms = Date.now() - start;
    console.log(`${res.status}  ${String(ms).padStart(6)}ms  ${url}`);
  } catch (e) {
    const ms = Date.now() - start;
    console.log(`ERR  ${String(ms).padStart(6)}ms  ${url}  ${e.message}`);
  }
}

(async () => {
  console.log(`prewarm ${BASE}`);
  for (const u of targets) {
    await hit(u);
  }
  console.log("prewarm done");
})();
