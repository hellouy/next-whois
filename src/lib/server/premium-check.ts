/**
 * Premium-domain detection for *unregistered* domains.
 *
 * A "premium" domain is available to register but carries a registry-set price
 * far above the TLD's standard fee. We rely exclusively on registrar APIs that
 * return an authoritative per-domain `premium` flag plus a real price:
 *
 *   1. Netim Direct SOAP    (queryDomainPrice → authoritative IsPremium flag
 *                            + Fee4Registration / Fee4Renewal, in EUR)
 *   2. Porkbun checkDomain  (string `premium` "yes"/"no" + regular/renewal price)
 *
 * Heuristic and price-ratio guessing were removed: they produced false
 * positives on short / numeric SLDs and ordinary promotional prices.
 *
 * Results are cached in-memory for 24 h: premium pricing rarely changes within
 * a day, and Porkbun rate-limits checks to ~1/10s per account.
 *
 * This module is intentionally fail-safe: any error or timeout returns `null`
 * so it can never break or slow the main WHOIS lookup.
 */
import { createLogger } from "@/lib/logger";
import type { PremiumCheckResult } from "@/lib/whois/types";

const logger = createLogger("server/premium-check");

// Warn loudly once per process when the premium sources are unconfigured.
// Missing Netim/Porkbun keys silently disable all premium detection — the UI
// then falls back to ordinary aggregate prices with no visible error, which is
// exactly how this regressed in production. The logger name lets ops grep for
// it; fail-safe behaviour (null verdict) is unchanged.
function warnIfSourcesUnconfigured(): void {
  const hasNetim = Boolean(process.env.NETIM_LOGIN) && Boolean(process.env.NETIM_PASSWORD);
  const hasPorkbun = Boolean(process.env.PORKBUN_API_KEY) && Boolean(process.env.PORKBUN_SECRET_KEY);
  if (!hasNetim && !hasPorkbun) {
    logger.warn(
      "[premium-check] Netim (NETIM_LOGIN/NETIM_PASSWORD) and Porkbun " +
      "(PORKBUN_API_KEY/PORKBUN_SECRET_KEY) are both unconfigured — premium " +
      "detection is disabled and will silently return null on every lookup. " +
      "Set all four keys in the deploy environment (see .env.example).",
    );
  }
}

const PREMIUM_CACHE_TTL_MS = 24 * 3600 * 1000;
// A null result usually means "price lookup unavailable" (Netim timed out and
// Porkbun can't price it) rather than a guaranteed non-premium verdict. Cache
// it briefly so a real premium name isn't hidden for a full day because of one
// transient timeout.
const PREMIUM_NULL_TTL_MS = 10 * 60 * 1000;
const premiumCache = new Map<
  string,
  { value: PremiumCheckResult | null; expiresAt: number }
>();
// In-flight dedup: the parallel WHOIS-lookup path and the post-lookup merge
// both query the same domain — share a single Netim/Porkbun request.
const inflightPremium = new Map<string, Promise<PremiumCheckResult | null>>();

const PORKBUN_TIMEOUT_MS = 3500;
const NETIM_TIMEOUT_MS = 4000;

const PORKBUN_API = "https://api.porkbun.com/api/json/v3/domain/checkDomain";
const NETIM_API = "https://api.netim.com/2.0/";
const NETIM_SESSION_TTL_MS = 20 * 60 * 1000;

function readCached(domain: string): PremiumCheckResult | null | undefined {
  const hit = premiumCache.get(domain);
  if (!hit) return undefined;
  if (Date.now() < hit.expiresAt) return hit.value;
  premiumCache.delete(domain);
  return undefined;
}

function writeCache(domain: string, value: PremiumCheckResult | null): void {
  premiumCache.set(domain, { value, expiresAt: Date.now() + (value ? PREMIUM_CACHE_TTL_MS : PREMIUM_NULL_TTL_MS) });
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

/** Parse a possibly-pennies price into USD dollars. */
function toUsd(v: unknown, pennies: boolean): number | null {
  const n = toNumber(v);
  if (n === null) return null;
  return pennies ? n / 100 : n;
}

/** Porkbun reports `premium` as the string "yes"/"no" (v3) or a boolean. */
function isTruthyPremium(v: unknown): boolean {
  return v === true || v === 1 || v === "1" || v === "yes" || v === "true";
}

// ── Porkbun ─────────────────────────────────────────────────────────────────

/** Parse a Porkbun checkDomain JSON response into a normalized result. */
export function parsePorkbunResponse(data: unknown): PremiumCheckResult | null {
  if (!data || typeof data !== "object") return null;
  const d = data as Record<string, unknown>;
  if (d.status !== "SUCCESS") return null;

  // v3 nests the answer under `response`; the older checkHost returned
  // `premium` / `price` at the top level. Support both shapes.
  const r = (d.response as Record<string, unknown>) ?? d;

  // Only unregistered domains are in scope: if Porkbun says it is already
  // taken, there is no "premium registration" to detect.
  const avail = r.avail;
  if (avail === "no" || avail === "false") return null;

  // Authoritative premium flag (string "yes"/"no" in v3).
  const premiumFlag = isTruthyPremium(r.premium ?? r.isPremium ?? r.is_premium);

  // Registration price: prefer the regular (non-promo) price, since `price`
  // may be a first-year discount that understates the true cost.
  const priceUsd =
    toUsd(r.regularPrice, false) ??
    toUsd(r.price, false) ??
    toUsd(r.registrationPrice, false) ??
    toUsd(r.registration, false) ??
    toUsd(r.cost, true);

  // Renewal price from the nested `additional.renewal` block.
  const renewal = (r.additional as Record<string, unknown> | undefined)?.renewal as
    | Record<string, unknown>
    | undefined;
  const renewalUsd =
    toUsd(renewal?.regularPrice, false) ?? toUsd(renewal?.price, false);

  return {
    isPremium: premiumFlag,
    price: priceUsd,
    renewalPrice: renewalUsd,
    currency: "USD",
    source: "porkbun",
  };
}

async function checkPorkbun(domain: string): Promise<PremiumCheckResult | null> {
  const apikey = process.env.PORKBUN_API_KEY;
  const secret = process.env.PORKBUN_SECRET_KEY;
  if (!apikey || !secret) return null;

  try {
    const data = await postJson(
      `${PORKBUN_API}/${encodeURIComponent(domain)}`,
      { apikey, secretapikey: secret },
      PORKBUN_TIMEOUT_MS,
    );
    return parsePorkbunResponse(data);
  } catch (e) {
    logger.error("[premium-check] porkbun failed:", (e as Error).message);
    return null;
  }
}

// ── Netim ───────────────────────────────────────────────────────────────────

const NETIM_NS = "urn:DRS";

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Extract the text of the first `<tag>value</tag>` element in a SOAP reply. */
function xmlValue(xml: string, tag: string): string | null {
  const m = xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`));
  return m ? m[1].trim() : null;
}

function soapEnvelope(body: string): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<SOAP-ENV:Envelope ' +
    'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" ' +
    `xmlns:ns1="${NETIM_NS}" ` +
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
    'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" ' +
    'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    "<SOAP-ENV:Body>" +
    body +
    "</SOAP-ENV:Body>" +
    "</SOAP-ENV:Envelope>"
  );
}

async function netimCall(action: string, body: string, ms: number): Promise<string | null> {
  const res = await fetch(NETIM_API, {
    method: "POST",
    headers: { "Content-Type": "text/xml; charset=utf-8", SOAPAction: action },
    body: soapEnvelope(body),
    signal: timeoutSignal(ms),
  });
  if (!res.ok) return null;
  return res.text();
}

// Netim sessions are server-side and capped; reuse a fresh one across calls
// within this process instead of opening one per lookup.
let netimSession: { id: string; at: number } | null = null;

async function netimSessionOpen(login: string, password: string): Promise<string | null> {
  const body =
    `<ns1:sessionOpen>` +
    `<idReseller xsi:type="xsd:string">${escapeXml(login.toUpperCase())}</idReseller>` +
    `<password xsi:type="xsd:string">${escapeXml(password)}</password>` +
    `<language xsi:type="xsd:string">EN</language>` +
    `</ns1:sessionOpen>`;
  const xml = await netimCall("sessionOpenAction", body, NETIM_TIMEOUT_MS);
  return xmlValue(xml ?? "", "IDSession");
}

async function netimQueryPrice(sid: string, domain: string): Promise<string | null> {
  const body =
    `<ns1:queryDomainPrice>` +
    `<IDSession xsi:type="xsd:string">${escapeXml(sid)}</IDSession>` +
    `<domain xsi:type="xsd:string">${escapeXml(domain)}</domain>` +
    `<authID xsi:type="xsd:string"></authID>` +
    `</ns1:queryDomainPrice>`;
  return netimCall("queryDomainPriceAction", body, NETIM_TIMEOUT_MS);
}

/**
 * Parse a Netim `queryDomainPrice` SOAP reply into a normalized result.
 *
 * StructQueryDomainPrice carries `IsPremium` (0/1), `Fee4Registration`,
 * `Fee4Renewal` and `FeeCurrency` (e.g. "EUR"). Prices are strings.
 */
export function parseNetimResponse(xml: string): PremiumCheckResult | null {
  if (!xml) return null;
  if (xml.includes("Fault")) return null;

  const premium = xmlValue(xml, "IsPremium");
  if (premium === null) return null;

  const currency = xmlValue(xml, "FeeCurrency") || "EUR";
  const price = toNumber(xmlValue(xml, "Fee4Registration"));
  const renewalPrice = toNumber(xmlValue(xml, "Fee4Renewal"));

  return {
    isPremium: premium === "1",
    price,
    renewalPrice,
    currency,
    source: "netim",
  };
}

async function checkNetim(domain: string): Promise<PremiumCheckResult | null> {
  const login = process.env.NETIM_LOGIN;
  const password = process.env.NETIM_PASSWORD;
  if (!login || !password) return null;

  try {
    let sid =
      netimSession && Date.now() - netimSession.at < NETIM_SESSION_TTL_MS
        ? netimSession.id
        : null;
    if (!sid) {
      sid = await netimSessionOpen(login, password);
      if (!sid) return null;
      netimSession = { id: sid, at: Date.now() };
    }

    let xml = await netimQueryPrice(sid, domain);

    // A stale session faults; re-open once and retry.
    if (!xml || xml.includes("Fault")) {
      sid = await netimSessionOpen(login, password);
      if (!sid) return null;
      netimSession = { id: sid, at: Date.now() };
      xml = await netimQueryPrice(sid, domain);
    }

    return parseNetimResponse(xml ?? "");
  } catch (e) {
    logger.error("[premium-check] netim failed:", (e as Error).message);
    return null;
  }
}

// ── Entry point ─────────────────────────────────────────────────────────────
warnIfSourcesUnconfigured();

export function checkDomainPremium(domain: string): Promise<PremiumCheckResult | null> {
  const cached = readCached(domain);
  if (cached !== undefined) return Promise.resolve(cached);

  let inflight = inflightPremium.get(domain);
  if (!inflight) {
    inflight = (async (): Promise<PremiumCheckResult | null> => {
      // Netim is the primary source (authoritative IsPremium flag). A Netim
      // "premium = true" verdict wins outright.
      const fromNetim = await checkNetim(domain);
      if (fromNetim && fromNetim.isPremium) {
        writeCache(domain, fromNetim);
        return fromNetim;
      }

      // Cross-check with Porkbun when Netim says "premium = false" or had no
      // quote: the two registries price different premium lists, so a Porkbun
      // "premium = yes" improves recall without sacrificing Netim's authority.
      const fromPorkbun = await checkPorkbun(domain);
      if (fromPorkbun && fromPorkbun.isPremium) {
        writeCache(domain, fromPorkbun);
        return fromPorkbun;
      }

      // Neither source reports premium: fall back to the Netim quote (even a
      // non-premium verdict) so we still show real registration/renewal fees.
      if (fromNetim) {
        writeCache(domain, fromNetim);
        return fromNetim;
      }

      if (fromPorkbun) {
        writeCache(domain, fromPorkbun);
        return fromPorkbun;
      }

      return null;
    })();
    inflightPremium.set(domain, inflight);
    void inflight.finally(() => {
      inflightPremium.delete(domain);
    });
  }
  return inflight;
}
