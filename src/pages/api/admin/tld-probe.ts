/**
 * POST /api/admin/tld-probe
 *
 * Probes a list of TLDs to determine which can be queried natively
 * (WHOIS TCP or RDAP) vs which require yisi/tianhu fallback.
 *
 * For each TLD, tries a test domain lookup and reports:
 *   - "rdap"    — RDAP responded successfully
 *   - "whois"   — TCP WHOIS responded with data
 *   - "fallback"— Only yisi/tianhu returned data
 *   - "none"    — All methods failed
 *
 * Also supports:
 *   GET  — returns current STATIC_ALWAYS_FALLBACK list
 *   POST — runs probes for requested TLDs
 */
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";

// Test domains used to probe each TLD.
// We use a known-registered domain so we get real data back (not just "not found").
// The probing only checks *connectivity* — whether the server responds at all.
const TEST_DOMAINS: Record<string, string> = {
  // Common known registrations
  mm: "gov.mm",
  np: "gov.np",
  et: "ethionet.et",
  bw: "gov.bw",
  jm: "gov.jm",
  gm: "gamtel.gm",
  gu: "gu.gov.gu",
  fk: "falklandislands.com.fk",
  va: "vatican.va",
  mh: "ntamar.net.mh",
  zw: "zol.co.zw",
  al: "gov.al",
  ba: "gov.ba",
};
const DEFAULT_TEST_DOMAIN = (tld: string) => TEST_DOMAINS[tld] ?? `test.${tld}`;

const RDAP_OVERRIDES: Record<string, string> = {
  al: "https://rdap.nic.al/", am: "https://rdap.nic.am/", ba: "https://rdap.nic.ba/",
  bw: "https://rdap.nic.bw/", et: "https://rdap.nic.et/", jm: "https://rdap.nic.jm/",
  mm: "https://rdap.nic.mm/", np: "https://rdap.nic.np/", zw: "https://rdap.zispa.co.zw/",
  gh: "https://rdap.nic.gh/", ke: "https://rdap.kenic.or.ke/", ng: "https://rdap.nic.net.ng/",
  ug: "https://rdap.nic.ug/", rw: "https://rdap.ricta.org.rw/", cm: "https://rdap.nic.cm/",
  so: "https://rdap.nic.so/", sd: "https://rdap.nic.sd/", ss: "https://rdap.nic.ss/",
  tz: "https://whois.tznic.or.tz/rdap/", za: "https://rdap.registry.net.za/",
};

const STATIC_ALWAYS_FALLBACK = new Set([
  "bd","cg","er","gw","lr","ne","sz","kp","cu",
  "an","tp","aq","bv","sj","um","bl","bq","eh","fk","gb","gm","gu","mf","mh","va",
]);

async function probeRdap(tld: string, domain: string, timeoutMs = 5000): Promise<boolean> {
  const base = RDAP_OVERRIDES[tld];
  if (!base) return false;
  const url = `${base}domain/${domain}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { Accept: "application/rdap+json" } });
    return r.status < 500; // 200 (found) or 404 (not found) — both mean server is reachable
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function probeWhoisTcp(host: string, domain: string, timeoutMs = 4000): Promise<boolean> {
  return new Promise(resolve => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const net = require("net") as typeof import("net");
    let got = false;
    const s = net.connect({ host, port: 43 }, () => s.write(domain + "\r\n"));
    s.setTimeout(timeoutMs);
    s.on("data", () => { got = true; s.destroy(); resolve(true); });
    s.on("close", () => { if (!got) resolve(false); });
    s.on("timeout", () => { s.destroy(); resolve(false); });
    s.on("error", () => resolve(false));
  });
}

// ccTLD → WHOIS host mapping (from cctld-whois-servers.json, non-null subset)
const KNOWN_WHOIS: Record<string, string> = {
  al: "whois.ripe.net", am: "whois.amnic.net", ao: "whois.dns.pt",
  az: "whois.nic.az", ba: "whois.ripe.net", bw: "whois.nic.net.bw",
  by: "whois.cctld.by", et: "whois.nic.et", fj: "whois.domains.fj",
  gh: "whois.nic.gh", gm: "whois.nic.gm", jm: "whois.nic.jm",
  ke: "whois.kenic.or.ke", mm: "whois.registry.gov.mm",
  mw: "whois.nic.mw", mz: "whois.nic.mz", np: "whois.nic.np",
  ng: "whois.nic.net.ng", rw: "whois.ricta.org.rw", sd: "whois.nic.sd",
  sl: "whois.nic.sl", sn: "whois.nic.sn", so: "whois.nic.so",
  ss: "whois.nic.ss", td: "whois.nic.td", tz: "whois.tznic.or.tz",
  ug: "whois.co.ug", zm: "whois.nic.zm", zw: "whois.zispa.co.zw",
  za: "whois.registry.net.za", gu: "whois.nic.gu", fk: "whois.nic.fk",
  va: "whois.nic.va", mh: "whois.nic.mh",
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method === "GET") {
    return res.json({
      static_always_fallback: [...STATIC_ALWAYS_FALLBACK],
      rdap_overrides_known: Object.keys(RDAP_OVERRIDES),
      whois_known: Object.keys(KNOWN_WHOIS),
    });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { tlds = [], timeout = 5000 } = req.body as { tlds?: string[]; timeout?: number };

  if (!Array.isArray(tlds) || tlds.length === 0) {
    return res.status(400).json({ error: "tlds array is required" });
  }
  if (tlds.length > 30) {
    return res.status(400).json({ error: "Max 30 TLDs per request" });
  }

  const timeoutMs = Math.min(Math.max(timeout ?? 5000, 2000), 10_000);

  const results = await Promise.all(
    tlds.map(async (rawTld) => {
      const tld = rawTld.toLowerCase().replace(/^\./, "");
      const domain = DEFAULT_TEST_DOMAIN(tld);

      // If in STATIC_ALWAYS_FALLBACK, skip native probes
      if (STATIC_ALWAYS_FALLBACK.has(tld)) {
        return {
          tld,
          domain,
          result: "static_fallback" as const,
          method: null,
          latencyMs: 0,
          note: "Confirmed no WHOIS/RDAP — always uses yisi/tianhu",
        };
      }

      const start = Date.now();
      let result: "rdap" | "whois" | "none" = "none";
      let method: string | null = null;

      // Try RDAP first (if override known)
      if (RDAP_OVERRIDES[tld]) {
        const rdapOk = await probeRdap(tld, domain, timeoutMs);
        if (rdapOk) {
          result = "rdap";
          method = RDAP_OVERRIDES[tld];
        }
      }

      // Try TCP WHOIS if RDAP failed
      if (result === "none" && KNOWN_WHOIS[tld]) {
        const whoisOk = await probeWhoisTcp(KNOWN_WHOIS[tld], domain, timeoutMs);
        if (whoisOk) {
          result = "whois";
          method = KNOWN_WHOIS[tld];
        }
      }

      return {
        tld,
        domain,
        result,
        method,
        latencyMs: Date.now() - start,
        note: result === "none" ? "No response from native servers — should use fallback" : null,
      };
    })
  );

  const summary = {
    total: results.length,
    rdap: results.filter((r) => r.result === "rdap").length,
    whois: results.filter((r) => r.result === "whois").length,
    static_fallback: results.filter((r) => r.result === "static_fallback").length,
    none: results.filter((r) => r.result === "none").length,
  };

  return res.json({ ok: true, summary, results });
}
