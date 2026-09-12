/**
 * Netim DRS SOAP 2.0 client — protocol layer shared by premium detection and
 * the domain-drop snipe engine.
 *
 * All functions are fail-safe: a network error, timeout or SOAP Fault returns
 * `null` (or an explicit `transient` classification on create) rather than
 * throwing, so callers never crash on registrar hiccups.
 *
 * Verified 2026-09-12 against the live API (api.netim.com/2.0):
 *   - sessionOpen → <IDSession>
 *   - queryResellerAccount → StructQueryResellerAccount
 *     (BALANCE_AMOUNT, DEFAULT_OWNER/ADMIN/TECH/BILLING, DEFAULT_DNS_1/2)
 *   - domainCheck → ArrayStructDomainCheckResponse of
 *     StructDomainCheckResponse { domain, result: AVAILABLE|NOT AVAILABLE, reason }
 *   - domainCreate → fault-driven signature probe confirmed the exact
 *     parameter names (domain, duration, idOwner, idAdmin, idTech, idBilling,
 *     ns1, ns2); successful reply carries an <IDOpe> operation id.
 *   - queryOpe(IDOpe) → StructQueryOpe { IDOpe, Status, Comment, ... }
 *   - queryDomainPrice → StructQueryDomainPrice
 *     (IsPremium, Fee4Registration, Fee4Renewal, FeeCurrency)
 *
 * A TLS handshake against api.netim.com intermittently drops in this sandbox,
 * so every network call retries with short backoff before giving up.
 */

import { createLogger } from "@/lib/logger";

const logger = createLogger("server/netim-client");

export const NETIM_API = "https://api.netim.com/2.0/";
export const NETIM_NS = "urn:DRS";

// Sessions are server-side and capped; reuse one fresh session across calls
// within this process instead of opening one per request.
const SESSION_TTL_MS = 20 * 60 * 1000;
let netimSession: { id: string; at: number } | null = null;

const NETIM_TIMEOUT_MS = 8000;
const CREATE_TIMEOUT_MS = 20000;
const NETWORK_RETRIES = 5;

// ── SOAP primitives ──────────────────────────────────────────────────────────

export function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Extract the text of the first `<tag>value</tag>` element in a SOAP reply. */
export function xmlValue(xml: string | null, tag: string): string | null {
  if (!xml) return null;
  const m = xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`));
  return m ? m[1].trim() : null;
}

export function soapEnvelope(body: string): string {
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

export interface NetimCallResult {
  xml: string;
  fault: string | null;
  status: number;
}

/**
 * POST one SOAP action with retries on network failure. Returns the raw reply
 * text; a SOAP Fault is surfaced via `fault` (callers decide how to classify).
 */
export async function netimCall(
  action: string,
  body: string,
  ms = NETIM_TIMEOUT_MS,
): Promise<NetimCallResult | null> {
  for (let attempt = 1; attempt <= NETWORK_RETRIES; attempt++) {
    try {
      const res = await fetch(NETIM_API, {
        method: "POST",
        headers: { "Content-Type": "text/xml; charset=utf-8", SOAPAction: action },
        body: soapEnvelope(body),
        signal: AbortSignal.timeout(ms),
      });
      if (!res.ok) {
        // 5xx / proxy failures are transient — retry before giving up.
        if (res.status >= 500) throw new Error(`HTTP ${res.status}`);
        return { xml: "", fault: `HTTP ${res.status}`, status: res.status };
      }
      const text = await res.text();
      const fault = text.includes("Fault") ? xmlValue(text, "faultstring") : null;
      return { xml: text, fault, status: res.status };
    } catch (e) {
      if (attempt === NETWORK_RETRIES) {
        logger.warn(`[netim-client] ${action} network failure: ${(e as Error).message}`);
        return null;
      }
      await new Promise((res) => setTimeout(res, 900 * attempt));
    }
  }
  return null;
}

function netimCredentials(): { login: string; password: string } | null {
  const login = process.env.NETIM_LOGIN;
  const password = process.env.NETIM_PASSWORD;
  if (!login || !password) return null;
  return { login: login.trim(), password };
}

async function netimSessionOpen(login: string, password: string): Promise<string | null> {
  const body =
    `<ns1:sessionOpen>` +
    `<idReseller xsi:type="xsd:string">${escapeXml(login.toUpperCase())}</idReseller>` +
    `<password xsi:type="xsd:string">${escapeXml(password)}</password>` +
    `<language xsi:type="xsd:string">EN</language>` +
    `</ns1:sessionOpen>`;
  const r = await netimCall("sessionOpenAction", body, 15000);
  return r ? xmlValue(r.xml, "IDSession") : null;
}

/**
 * Return a fresh session id, opening one if the cached session is stale or
 * missing. Callers should re-open once on a Fault (stale-session recovery).
 */
async function getSession(): Promise<string | null> {
  const cred = netimCredentials();
  if (!cred) return null;
  if (netimSession && Date.now() - netimSession.at < SESSION_TTL_MS) {
    return netimSession.id;
  }
  const sid = await netimSessionOpen(cred.login, cred.password);
  if (!sid) return null;
  netimSession = { id: sid, at: Date.now() };
  return sid;
}

/**
 * Ensure a live session id for a body built around an existing id: if the
 * caller's session produced a Fault (stale), reopen once and return the fresh
 * id. Returns null when no session could be established.
 */
async function refreshSessionIfStale(fault: string | null): Promise<string | null> {
  const cred = netimCredentials();
  if (!cred) return null;
  if (!fault && netimSession) return netimSession.id;
  const sid = await netimSessionOpen(cred.login, cred.password);
  if (!sid) return null;
  netimSession = { id: sid, at: Date.now() };
  return sid;
}

function sessionTag(sid: string): string {
  return `<IDSession xsi:type="xsd:string">${escapeXml(sid)}</IDSession>`;
}

/** True when a SOAP Fault means the session is stale and should be reopened. */
function isSessionFault(fault: string | null): boolean {
  if (!fault) return false;
  return /session|expired|E15|E14/i.test(fault);
}

// ── Reseller account ─────────────────────────────────────────────────────────

export interface NetimResellerAccount {
  balance: number;
  defaultOwner: string | null;
  defaultAdmin: string | null;
  defaultTech: string | null;
  defaultBilling: string | null;
  defaultDns1: string | null;
  defaultDns2: string | null;
}

/** Account balance + registrar-side defaults (owner/admin/tech/billing/DNS). */
export async function netimQueryResellerAccount(): Promise<NetimResellerAccount | null> {
  let sid = await getSession();
  if (!sid) return null;

  let r = await netimCall("queryResellerAccountAction", `<ns1:queryResellerAccount>${sessionTag(sid)}</ns1:queryResellerAccount>`);
  if (!r) return null;

  if (r.fault && isSessionFault(r.fault)) {
    sid = (await refreshSessionIfStale(r.fault)) ?? sid;
    r = await netimCall("queryResellerAccountAction", `<ns1:queryResellerAccount>${sessionTag(sid)}</ns1:queryResellerAccount>`);
    if (!r) return null;
  }
  if (r.fault) return null;

  const balance = parseFloat(xmlValue(r.xml, "BALANCE_AMOUNT") ?? "");
  return {
    balance: Number.isFinite(balance) ? balance : 0,
    defaultOwner: xmlValue(r.xml, "DEFAULT_OWNER"),
    defaultAdmin: xmlValue(r.xml, "DEFAULT_ADMIN"),
    defaultTech: xmlValue(r.xml, "DEFAULT_TECH"),
    defaultBilling: xmlValue(r.xml, "DEFAULT_BILLING"),
    defaultDns1: xmlValue(r.xml, "DEFAULT_DNS_1"),
    defaultDns2: xmlValue(r.xml, "DEFAULT_DNS_2"),
  };
}

// ── Domain check ─────────────────────────────────────────────────────────────

export interface NetimDomainCheck {
  available: boolean;
  reason: string; // FREE | PREMIUM | IN_USE | '' (available) | ...
}

/** Parse a domainCheck reply body (ArrayStructDomainCheckResponse). */
export function parseDomainCheckResponse(xml: string): NetimDomainCheck | null {
  if (!xml || xml.includes("Fault")) return null;
  const result = (xmlValue(xml, "result") ?? "").toUpperCase();
  if (result === "") return null;
  return {
    available: result === "AVAILABLE",
    reason: xmlValue(xml, "reason") ?? "",
  };
}

/** Authoritative availability probe (~600 ms measured). */
export async function netimDomainCheck(domain: string): Promise<NetimDomainCheck | null> {
  let sid = await getSession();
  if (!sid) return null;

  const body = (s: string) =>
    `<ns1:domainCheck>${sessionTag(s)}<domain xsi:type="xsd:string">${escapeXml(domain)}</domain><authID xsi:type="xsd:string"></authID></ns1:domainCheck>`;

  let r = await netimCall("domainCheckAction", body(sid));
  if (!r) return null;

  if (r.fault && isSessionFault(r.fault)) {
    sid = (await refreshSessionIfStale(r.fault)) ?? sid;
    r = await netimCall("domainCheckAction", body(sid));
    if (!r) return null;
  }
  if (r.fault) return null;

  return parseDomainCheckResponse(r.xml);
}

// ── Domain price ─────────────────────────────────────────────────────────────

export interface NetimPrice {
  isPremium: boolean;
  price: number | null;        // Fee4Registration, EUR
  renewalPrice: number | null; // Fee4Renewal, EUR
  currency: string;
}

export function parseNetimPriceResponse(xml: string): NetimPrice | null {
  if (!xml || xml.includes("Fault")) return null;
  const premium = xmlValue(xml, "IsPremium");
  if (premium === null) return null;
  const toNumber = (v: string | null): number | null => {
    if (!v || v.trim() === "") return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  };
  return {
    isPremium: premium === "1",
    price: toNumber(xmlValue(xml, "Fee4Registration")),
    renewalPrice: toNumber(xmlValue(xml, "Fee4Renewal")),
    currency: xmlValue(xml, "FeeCurrency") || "EUR",
  };
}

export async function netimQueryDomainPrice(domain: string): Promise<NetimPrice | null> {
  let sid = await getSession();
  if (!sid) return null;

  const body = (s: string) =>
    `<ns1:queryDomainPrice>${sessionTag(s)}<domain xsi:type="xsd:string">${escapeXml(domain)}</domain><authID xsi:type="xsd:string"></authID></ns1:queryDomainPrice>`;

  let r = await netimCall("queryDomainPriceAction", body(sid));
  if (!r) return null;

  if (r.fault && isSessionFault(r.fault)) {
    sid = (await refreshSessionIfStale(r.fault)) ?? sid;
    r = await netimCall("queryDomainPriceAction", body(sid));
    if (!r) return null;
  }
  if (r.fault) return null;

  return parseNetimPriceResponse(r.xml);
}

// ── Domain create ────────────────────────────────────────────────────────────

export interface NetimCreateResult {
  ok: boolean;
  opeId?: string;
  reason?: string;
  /** true → retryable (network/timeout/5xx); false → deterministic refusal. */
  transient: boolean;
}

/**
 * Register a domain with the account's default owner/admin/tech/billing
 * contacts and default nameservers, for the given number of years.
 *
 * Deterministic refusals (parameter error, "not available", unknown TLD) are
 * `transient: false`. Network timeouts / HTTP 5xx are `transient: true`.
 */
export async function netimDomainCreate(domain: string, periodYears: number): Promise<NetimCreateResult | null> {
  const cred = netimCredentials();
  if (!cred) return null;

  const account = await netimQueryResellerAccount();
  const idOwner = account?.defaultOwner ?? "LJ5552";
  const idAdmin = account?.defaultAdmin ?? "LJ5551";
  const idTech = account?.defaultTech ?? "LJ5551";
  const idBilling = account?.defaultBilling ?? "LJ5551";
  const ns1 = account?.defaultDns1 ?? "ns1.nic.bn";
  const ns2 = account?.defaultDns2 ?? "ns2.nic.bn";

  // The create call is preceded by a fresh session (never reuse across a long
  // gap). Open explicitly so a create never piggybacks on a stale id.
  const sid = await netimSessionOpen(cred.login, cred.password);
  if (!sid) return null;
  netimSession = { id: sid, at: Date.now() };

  const body =
    `<ns1:domainCreate>` +
    sessionTag(sid) +
    `<domain xsi:type="xsd:string">${escapeXml(domain)}</domain>` +
    `<duration xsi:type="xsd:int">${Math.max(1, Math.floor(periodYears))}</duration>` +
    `<idOwner xsi:type="xsd:string">${escapeXml(idOwner)}</idOwner>` +
    `<idAdmin xsi:type="xsd:string">${escapeXml(idAdmin)}</idAdmin>` +
    `<idTech xsi:type="xsd:string">${escapeXml(idTech)}</idTech>` +
    `<idBilling xsi:type="xsd:string">${escapeXml(idBilling)}</idBilling>` +
    `<ns1 xsi:type="xsd:string">${escapeXml(ns1)}</ns1>` +
    `<ns2 xsi:type="xsd:string">${escapeXml(ns2)}</ns2>` +
    `</ns1:domainCreate>`;

  const r = await netimCall("domainCreateAction", body, CREATE_TIMEOUT_MS);
  if (!r) return { ok: false, reason: "network/timeout", transient: true };

  if (r.fault) {
    // Deterministic refusals carry a concrete message (parameter error,
    // already registered, unknown TLD config, ...). Everything else faults
    // permanently too — only the network/timeout path is retried upstream.
    return { ok: false, reason: r.fault, transient: false };
  }

  const opeId = xmlValue(r.xml, "IDOpe");
  if (opeId) return { ok: true, opeId, transient: false };
  // No ope id and no fault — treat as unknown; the engine polls queryOpe when
  // it has an id, and falls back to an explicit "unknown" attempt otherwise.
  return { ok: true, transient: false };
}

// ── Operation status ─────────────────────────────────────────────────────────

export type NetimOpeStatus = {
  status: "done" | "pending" | "error";
  comment?: string;
};

export function mapOpeStatus(raw: string | null): NetimOpeStatus["status"] {
  const s = (raw ?? "").toLowerCase();
  if (/done|term|complete|success|ok|end/i.test(s)) return "done";
  if (/error|fail|annul|refus|cancel/i.test(s)) return "error";
  return "pending";
}

export async function netimQueryOpe(opeId: string): Promise<NetimOpeStatus | null> {
  let sid = await getSession();
  if (!sid) return null;

  const body = (s: string) =>
    `<ns1:queryOpe>${sessionTag(s)}<IDOpe xsi:type="xsd:string">${escapeXml(opeId)}</IDOpe></ns1:queryOpe>`;

  let r = await netimCall("queryOpeAction", body(sid));
  if (!r) return null;

  if (r.fault && isSessionFault(r.fault)) {
    sid = (await refreshSessionIfStale(r.fault)) ?? sid;
    r = await netimCall("queryOpeAction", body(sid));
    if (!r) return null;
  }
  if (r.fault) {
    // Unknown / expired operation id — surface as error so the engine can
    // downgrade an "unknown pending" to a permanent failure.
    return { status: "error", comment: r.fault };
  }

  const status = mapOpeStatus(xmlValue(r.xml, "Status"));
  const comment = xmlValue(r.xml, "Comment") ?? undefined;
  return { status, comment };
}
