import { lookup } from "node:dns/promises";
import {
  resolveSiteIdentity,
  matchesSiteIdentity,
  normalizeHref,
  hostToken,
  type SiteIdentity,
} from "./site-identity";

export interface BacklinkProbe {
  url: string;
  status?: number;
  found: boolean;
  reason?: string;
  error?: string;
}

export interface BacklinkCheckResult {
  found: boolean;
  pages: BacklinkProbe[];
  checkedAt: string;
}

const COMMON_PATHS = ["/", "/links", "/friends", "/friend", "/link", "/links.html", "/友情链接"];
const MAX_PAGES = 4;
const PAGE_TIMEOUT_MS = 8000;
const OVERALL_TIMEOUT_MS = 9000;

const USER_AGENT = "friendlink-checker/1.0 (+friendly link exchange)";

function isPrivateAddr(ip: string): boolean {
  if (ip === "::1" || ip === "0.0.0.0" || ip === "127.0.0.1") return true;
  if (ip.toLowerCase() === "localhost") return true;
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  // IPv4-mapped / literal IPv4
  const v4 = ip.includes(".") ? ip : "";
  if (v4) {
    const p = v4.split(".").map(Number);
    if (p.length !== 4 || p.some(isNaN)) return true;
    if (p[0] === 10) return true;
    if (p[0] === 127) return true;
    if (p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true; // link-local incl. metadata
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
    return false;
  }
  // IPv6 link-local / loopback / ULA
  if (ip.startsWith("fe8:") || ip.startsWith("fe9:") || ip.startsWith("fea:") || ip.startsWith("feb:")) return true;
  if (ip.startsWith("fc") || ip.startsWith("fd")) return true;
  if (ip.startsWith("::") && ip !== "::") return true;
  return false;
}

async function publicTarget(url: URL): Promise<boolean> {
  const host = url.hostname;
  const isIpLiteral = (host: string) => /^[0-9.]+$/.test(host) || host.includes(":");

  if (isIpLiteral(host)) return !isPrivateAddr(host);

  try {
    const addrs = await lookup(host, { all: true, verbatim: true });
    if (addrs.length === 0) return false;
    return addrs.every(a => !isPrivateAddr(a.address));
  } catch {
    return false;
  }
}

async function fetchPage(
  url: string,
  identity: SiteIdentity,
  pageTimeoutMs: number,
  outerSignal?: AbortSignal,
): Promise<BacklinkProbe> {
  const pageController = outerSignal ? undefined : new AbortController();
  const timer = setTimeout(() => pageController?.abort(), pageTimeoutMs);
  const signals = [
    ...(outerSignal ? [outerSignal] : []),
    ...(pageController ? [pageController.signal] : []),
  ];
  try {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) {
      return { url, found: false, reason: "none", error: "unsupported-protocol" };
    }
    if (!(await publicTarget(parsed))) {
      return { url, found: false, reason: "none", error: "private-target" };
    }

    const res = await fetch(parsed, {
      signal: signals.length > 0 ? AbortSignal.any(signals) : undefined,
      redirect: "follow",
      headers: { "user-agent": USER_AGENT, accept: "text/html,application/xhtml+xml" },
    });
    const ctype = String(res.headers.get("content-type") || "");
    if (!ctype.includes("text/html") && !ctype.includes("xhtml")) {
      return { url, status: res.status, found: false, reason: "none", error: "not-html" };
    }
    const text = await res.text();
    const m = matchesSiteIdentity(text, identity);
    return {
      url,
      status: res.status,
      found: m.found,
      reason: m.found ? m.reason : undefined,
      error: m.found ? undefined : "no-match",
    };
  } catch (err) {
    const msg = err instanceof Error ? err.name === "AbortError" ? "timeout" : err.message : "fetch-failed";
    return { url, found: false, reason: "none", error: msg };
  } finally {
    clearTimeout(timer);
  }
}

function candidateUrls(siteUrl: string): string[] {
  let base = String(siteUrl || "").trim();
  if (!base) return [];
  if (!/^https?:\/\//i.test(base)) base = "https://" + base;
  try {
    const u = new URL(base.replace(/\/$/, ""));
    const origins = [u.origin, u.origin + "/"];
    const pages: string[] = [];
    for (const p of COMMON_PATHS) pages.push(u.origin + p);
    return [...origins, ...pages];
  } catch {
    return [base];
  }
}

export async function checkBacklink(siteUrl: string): Promise<BacklinkCheckResult> {
  const checkedAt = new Date().toISOString();
  const identity = await resolveSiteIdentity();
  const candidates = candidateUrls(siteUrl);

  if (candidates.length === 0) {
    return { found: false, pages: [], checkedAt };
  }

  if (!identity.url && !identity.hostname && !identity.label) {
    return { found: false, pages: [], checkedAt };
  }

  const pending = candidates.slice(0, MAX_PAGES);
  const overall = new AbortController();
  const timer = setTimeout(() => overall.abort(), OVERALL_TIMEOUT_MS);
  try {
    const pages = await Promise.all(
      pending.map(url => fetchPage(url, identity, PAGE_TIMEOUT_MS, overall.signal)),
    );
    const hit = pages.find(p => p.found);
    return { found: Boolean(hit), pages, checkedAt };
  } finally {
    clearTimeout(timer);
  }
}

export { hostToken, normalizeHref, isPrivateAddr, candidateUrls };