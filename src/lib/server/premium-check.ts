/**
 * Premium-domain detection for *unregistered* domains.
 *
 * A "premium" domain is available to register but carries a registry-set price
 * far above the TLD's standard fee (or is held by the registry for sale). The
 * authoritative signal is a registrar API returning a per-domain price; we fall
 * back to Namesilo, then to a conservative heuristic for the cases where no API
 * key is configured.
 *
 * Order of precedence:
 *   1. Porkbun checkDomain  (returns a boolean `premium` flag + price)
 *   2. Namesilo checkRegisterAvailability (price only — compared to TLD base)
 *   3. Heuristic             (short / numeric SLDs only — high-confidence subset)
 *
 * Results are cached in-memory for 24 h: premium pricing rarely changes within a
 * day, and Porkbun rate-limits checks to ~1/10s per account.
 *
 * This module is intentionally fail-safe: any error or timeout returns `null`
 * (or a heuristic answer) so it can never break or slow the main WHOIS lookup.
 */
import { createLogger } from "@/lib/logger";
import { getDomainPricing } from "@/lib/pricing/client";
import type { PremiumCheckResult } from "@/lib/whois/types";

const logger = createLogger("server/premium-check");

const PREMIUM_CACHE_TTL_MS = 24 * 3600 * 1000;
const premiumCache = new Map<
  string,
  { value: PremiumCheckResult | null; expiresAt: number }
>();

// A domain is flagged premium when its per-domain price is at least this many
// times the TLD's standard registration price.
const PREMIUM_RATIO = 5;
const PORKBUN_TIMEOUT_MS = 3500;
const NAMESILO_TIMEOUT_MS = 3000;

const PORKBUN_API = "https://api.porkbun.com/api/json/v3/domain/checkDomain";
const NAMESILO_API = "https://www.namesilo.com/api/checkRegisterAvailability";

function readCached(domain: string): PremiumCheckResult | null | undefined {
  const hit = premiumCache.get(domain);
  if (!hit) return undefined;
  if (Date.now() < hit.expiresAt) return hit.value;
  premiumCache.delete(domain);
  return undefined;
}

function writeCache(domain: string, value: PremiumCheckResult | null): void {
  premiumCache.set(domain, { value, expiresAt: Date.now() + PREMIUM_CACHE_TTL_MS });
}

function timeoutSignal(ms: number): AbortSignal {
  return AbortSignal.timeout(ms);
}

async function postJson(url: string, body: unknown, ms: number): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: timeoutSignal(ms),
  });
  if (!res.ok) return null;
  return res.json();
}

function toNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v.replace(/[^0-9.-]/g, ""));
    if (Number.isFinite(n)) return n;
  }
  return null;
}

/** Parse a possibly-dollars or pennies price into USD. */
function toUsd(v: unknown, pennies: boolean): number | null {
  const n = toNumber(v);
  if (n === null) return null;
  return pennies ? n / 100 : n;
}

/** Extract TLD's standard (non-premium) registration price baseline in USD. */
async function getTldBasePriceUsd(domain: string): Promise<number | null> {
  try {
    const pricing = await getDomainPricing(domain, "new");
    const raw = pricing?.new;
    if (typeof raw === "number" && raw > 0) return raw;
    return null;
  } catch {
    return null;
  }
}

// ── Porkbun ─────────────────────────────────────────────────────────────────
async function checkPorkbun(domain: string): Promise<PremiumCheckResult | null> {
  const apikey = process.env.PORKBUN_API_KEY;
  const secret = process.env.PORKBUN_SECRET_KEY;
  if (!apikey || !secret) return null;

  try {
    const data = (await postJson(
      `${PORKBUN_API}/${encodeURIComponent(domain)}`,
      { apikey, secretapikey: secret },
      PORKBUN_TIMEOUT_MS,
    )) as Record<string, unknown> | null;

    if (!data || data.status !== "SUCCESS") return null;

    // v3 nests the answer under `response`; the older checkHost returned
    // `isPremium` / `price` at the top level. Support both shapes.
    const r = (data.response as Record<string, unknown>) ?? data;

    const premiumFlag =
      r.premium === true || r.isPremium === true || r.is_premium === true;

    // Cost can arrive as dollars (price/regPrice/registrationPrice) or pennies
    // (cost). Prefer explicit dollar strings first.
    const priceUsd =
      toUsd(r.price, false) ??
      toUsd(r.regPrice, false) ??
      toUsd(r.registrationPrice, false) ??
      toUsd(r.registration, false) ??
      toUsd(r.cost, true);

    const base = await getTldBasePriceUsd(domain);
    const priceImpliesPremium =
      priceUsd !== null &&
      base !== null &&
      priceUsd >= base * PREMIUM_RATIO;

    const isPremium = premiumFlag || priceImpliesPremium;

    return {
      isPremium,
      price: priceUsd,
      currency: "USD",
      source: "porkbun",
    };
  } catch (e) {
    logger.error("[premium-check] porkbun failed:", (e as Error).message);
    return null;
  }
}

// ── Namesilo ────────────────────────────────────────────────────────────────
async function checkNamesilo(domain: string): Promise<PremiumCheckResult | null> {
  const key = process.env.NAMESILO_API_KEY;
  if (!key) return null;

  try {
    const url = `${NAMESILO_API}?version=1&type=json&key=${encodeURIComponent(key)}&domain=${encodeURIComponent(domain)}`;
    const res = await fetch(url, { signal: timeoutSignal(NAMESILO_TIMEOUT_MS) });
    if (!res.ok) return null;
    const data = (await res.json()) as {
      reply?: { available?: { domain?: string; price?: string } };
    };
    const avail = data.reply?.available;
    if (!avail || avail.domain !== "yes") return null;

    const priceUsd = toNumber(avail.price);
    const base = await getTldBasePriceUsd(domain);
    const isPremium =
      priceUsd !== null && base !== null && priceUsd >= base * PREMIUM_RATIO;

    return {
      isPremium,
      price: priceUsd,
      currency: "USD",
      source: "namesilo",
    };
  } catch (e) {
    logger.error("[premium-check] namesilo failed:", (e as Error).message);
    return null;
  }
}

// ── Heuristic ───────────────────────────────────────────────────────────────
/**
 * Conservative heuristic for when no registrar API key is configured. Only
 * flags the high-confidence subset: short SLDs (≤3 chars) and all-numeric SLDs,
 * which are premium/reserved across the overwhelming majority of TLDs.
 */
export function heuristicPremium(domain: string): PremiumCheckResult | null {
  const sld = domain.split(".")[0]?.toLowerCase() ?? "";
  if (sld.length <= 3) {
    return { isPremium: true, price: null, currency: "USD", source: "heuristic" };
  }
  if (/^\d+$/.test(sld)) {
    return { isPremium: true, price: null, currency: "USD", source: "heuristic" };
  }
  return null;
}

// ── Entry point ─────────────────────────────────────────────────────────────
export async function checkDomainPremium(domain: string): Promise<PremiumCheckResult | null> {
  const cached = readCached(domain);
  if (cached !== undefined) return cached;

  // Try authoritative APIs in order; the first definitive answer wins.
  const fromPorkbun = await checkPorkbun(domain);
  if (fromPorkbun) {
    writeCache(domain, fromPorkbun);
    return fromPorkbun;
  }

  const fromNamesilo = await checkNamesilo(domain);
  if (fromNamesilo) {
    writeCache(domain, fromNamesilo);
    return fromNamesilo;
  }

  // Fall back to the heuristic when APIs are unavailable / unconfigured.
  const heuristic = heuristicPremium(domain);
  // Cache heuristic "premium" answers too; but don't cache a null (no signal)
  // aggressively — a null may flip once an API key is configured later.
  if (heuristic) writeCache(domain, heuristic);
  return heuristic;
}
