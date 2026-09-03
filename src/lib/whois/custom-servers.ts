import fs from "fs";
import path from "path";
import { many, run, isDbReady } from "@/lib/db-query";
import { WhoisRawResult } from "@/lib/whois/types";
import { queryWhoisTcp, queryWhoisHttp } from "@/lib/whois/whois-transport";
import { isWhoisRateLimited } from "@/lib/whois/whois-patterns";
import { lookupNicBa } from "@/lib/whois/http-scrapers/nic-ba";
import { lookupNicPh } from "@/lib/whois/http-scrapers/nic-ph";
import { getGtldWhoisServer } from "@/lib/whois/whois_gtld_bootstrap";

export type TcpServerEntry = {
  type: "tcp";
  host: string;
  port?: number;
};

export type HttpServerEntry = {
  type: "http";
  url: string;
  method?: "GET" | "POST";
  body?: string;
};

/**
 * Scraper entry: a TLD handled by a custom scraper function (e.g. nic.ba).
 * The scraper name maps to a dedicated module in src/lib/whois/http-scrapers/.
 * registryUrl is shown to users when automated lookup is unavailable.
 */
export type ScraperEntry = {
  type: "scraper";
  name: string;
  registryUrl: string;
};

export type CustomServerEntry = string | TcpServerEntry | HttpServerEntry | ScraperEntry;

export type CustomServerMap = Record<string, CustomServerEntry>;

const WHOIS_FILE = path.join(process.cwd(), "src/data/whois-servers.json");
const DATA_FILE  = path.join(process.cwd(), "src/data/custom-tld-servers.json");

let _whoisFileCache: Record<string, string | null> | null = null;

function readWhoisServers(): Record<string, string | null> {
  if (_whoisFileCache) return _whoisFileCache;
  try {
    _whoisFileCache = JSON.parse(fs.readFileSync(WHOIS_FILE, "utf-8")) as Record<string, string | null>;
    return _whoisFileCache;
  } catch {
    return {};
  }
}

/**
 * Returns the WHOIS server hostname for a TLD.
 *
 * Lookup priority:
 *   1. whois-servers.json — explicit ccTLD map (null entry = definitively no server)
 *   2. GTLD_WHOIS_BOOTSTRAP — 1200+ gTLD entries derived from IANA RDAP bootstrap
 *
 * Returns null when no server is known for the TLD.
 * Used by the generic WHOIS fallback path to start a parallel TCP race
 * immediately rather than waiting for IANA discovery via TCP.
 */
export function getStaticWhoisServer(tld: string): string | null {
  const file = readWhoisServers();
  const normalized = tld.toLowerCase().replace(/^\./, "");
  const fileEntry = file[normalized];
  // Explicit null in whois-servers.json = registry confirmed no WHOIS service
  if (fileEntry === null) return null;
  // Explicit string = use this server directly
  if (typeof fileEntry === "string") return fileEntry;
  // Not in JSON file → check gTLD bootstrap (1200+ TLDs derived from IANA RDAP)
  return getGtldWhoisServer(normalized) ?? null;
}

/** Exported so admin pages can identify which TLDs are handled by built-in logic. */
export const BUILTIN_SERVER_TLDS: ReadonlySet<string> = new Set(["bn","ba","com.ba","org.ba","net.ba","gov.ba","edu.ba","mil.ba","ph","com.ph","net.ph","org.ph","edu.ph","gov.ph","mil.ph","gw"]);

const BUILTIN_SERVERS: CustomServerMap = {
  bn: "whois.bnnic.bn",
  gw: { type: "http", url: "https://registar.nic.gw/en/whois/{{domain}}/", method: "GET" },
  ba:      { type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "com.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "org.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "net.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "gov.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "edu.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "mil.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  ph:        { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
  "com.ph":  { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
  "net.ph":  { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
  "org.ph":  { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
  "edu.ph":  { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
  "gov.ph":  { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
  "mil.ph":  { type: "scraper", name: "nic-ph", registryUrl: "https://www.whois.ph/" },
};

function readFileServers(): CustomServerMap {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8")) as CustomServerMap;
  } catch {
    return {};
  }
}

async function readDbServers(): Promise<CustomServerMap> {
  if (!(await isDbReady())) return {};
  try {
    const rows = await many<{ tld: string; entry: unknown }>(
      "SELECT tld, entry FROM custom_whois_servers ORDER BY tld",
    );
    const map: CustomServerMap = {};
    for (const r of rows) {
      map[r.tld] = r.entry as CustomServerEntry;
    }
    return map;
  } catch {
    return {};
  }
}

/** Returns only entries explicitly added by an admin (source = 'manual'). */
async function readManualDbServers(): Promise<CustomServerMap> {
  if (!(await isDbReady())) return {};
  try {
    const rows = await many<{ tld: string; entry: unknown }>(
      `SELECT tld, entry FROM custom_whois_servers WHERE source = 'manual' ORDER BY tld`,
    );
    const map: CustomServerMap = {};
    for (const r of rows) {
      map[r.tld] = r.entry as CustomServerEntry;
    }
    return map;
  } catch {
    return {};
  }
}

/**
 * Reads whois_server values from tld_registry_info (scraped from IANA pages).
 * This is the lowest-priority server source — any explicit custom server or
 * whois-servers.json entry overrides it.  Gives a useful fallback for
 * TLDs not in our curated files.
 */
async function readRegistryInfoServers(): Promise<CustomServerMap> {
  if (!(await isDbReady())) return {};
  try {
    const rows = await many<{ tld: string; whois_server: string }>(
      `SELECT tld, whois_server FROM tld_registry_info
       WHERE whois_server IS NOT NULL AND whois_server <> ''
       ORDER BY tld`,
    );
    const map: CustomServerMap = {};
    for (const r of rows) {
      map[r.tld.toLowerCase().replace(/^\./, "")] = r.whois_server.trim();
    }
    return map;
  } catch {
    return {};
  }
}

async function readUserManagedServers(): Promise<CustomServerMap> {
  const fromDb = await readManualDbServers();
  if (Object.keys(fromDb).length > 0) return fromDb;
  return readFileServers();
}

let _allServersCache: CustomServerMap | null = null;
let _allServersCacheAt = 0;
// Custom server list changes rarely; explicit invalidation is called on every
// admin write/delete so a long TTL is safe and reduces DB queries significantly.
const ALL_SERVERS_TTL_MS = 300_000; // 5 minutes

// Separate cache for user-managed (DB-only) servers, used by isUserManagedServer.
// Must share the same TTL / invalidation cycle as _allServersCache.
let _userManagedCache: CustomServerMap | null = null;
let _userManagedCacheAt = 0;

// TLDs explicitly recorded as having NO public WHOIS server in our cctld file.
// Kept separate so lookup.ts can short-circuit without calling whoiser.
let _knownNoServerCache: Set<string> | null = null;

function invalidateAllServersCache() {
  _allServersCache = null;
  _allServersCacheAt = 0;
  _knownNoServerCache = null;
  _userManagedCache = null;
  _userManagedCacheAt = 0;
  _manualServersCacheShadow = null;
  _manualServersCacheShadowAt = 0;
}

async function writeDbServer(
  tld: string,
  entry: CustomServerEntry,
  source: "manual" | "iana" | "repair" | "registry" = "manual",
): Promise<void> {
  if (!(await isDbReady())) return;
  await run(
    `INSERT INTO custom_whois_servers (tld, entry, source, updated_at)
     VALUES ($1, $2::jsonb, $3, NOW())
     ON CONFLICT (tld) DO UPDATE SET entry = $2::jsonb, source = $3, updated_at = NOW()`,
    [tld, JSON.stringify(entry), source],
  );
}

/**
 * Writes an auto-discovered server (IANA referral or repair-queue result) only
 * when no manual entry already exists for this TLD.  Manual entries always win;
 * this function is purely additive and never degrades an admin override.
 */
async function writeAutoDiscoveredServer(
  tld: string,
  entry: CustomServerEntry,
  source: "iana" | "repair" | "registry",
): Promise<void> {
  if (!(await isDbReady())) return;
  await run(
    `INSERT INTO custom_whois_servers (tld, entry, source, updated_at)
     VALUES ($1, $2::jsonb, $3, NOW())
     ON CONFLICT (tld) DO UPDATE
       SET entry = $2::jsonb, source = $3, updated_at = NOW()
       WHERE custom_whois_servers.source <> 'manual'`,
    [tld, JSON.stringify(entry), source],
  );
}

async function deleteDbServer(tld: string): Promise<void> {
  if (!(await isDbReady())) return;
  await run("DELETE FROM custom_whois_servers WHERE tld = $1", [tld]);
}

export async function getAllCustomServers(): Promise<CustomServerMap> {
  const now = Date.now();
  if (_allServersCache && now - _allServersCacheAt < ALL_SERVERS_TTL_MS) {
    return _allServersCache;
  }
  // Include ALL DB entries (manual + iana-discovered + repair-promoted) in the hot cache.
  // whois-servers.json is intentionally excluded here — whoiser handles server discovery
  // natively, and the static file was causing Vercel-incompatible direct TCP lookups.
  const allDb    = await readDbServers();
  const user     = Object.keys(allDb).length > 0 ? allDb : await readFileServers();
  const registry = await readRegistryInfoServers();

  // No fast-fail set from static file — whoiser handles unknown TLDs gracefully.
  _knownNoServerCache = new Set();

  // Priority (highest wins):
  //   1. registry (tld_registry_info.whois_server) — lowest, fills gaps
  //   2. BUILTIN_SERVERS — hard-coded scrapers and special cases
  //   3. custom_whois_servers DB — highest, admin-managed supplements
  _allServersCache = { ...registry, ...BUILTIN_SERVERS, ...user };
  _allServersCacheAt = now;
  return _allServersCache;
}

/**
 * Returns true when the TLD is explicitly listed in our cctld file as having
 * NO public WHOIS server (value = null).  Used to skip the whoiser call and
 * return a fast "no server available" error without a TCP timeout.
 */
export async function isTldKnownNoServer(tld: string): Promise<boolean> {
  await getAllCustomServers(); // populates _knownNoServerCache
  const t = tld.toLowerCase().replace(/^\./, "");
  return _knownNoServerCache?.has(t) ?? false;
}

/**
 * Returns WHOIS servers scraped from tld_registry_info.
 * Used by the admin page to show the registry source separately.
 */
export async function getRegistryInfoServers(): Promise<CustomServerMap> {
  return readRegistryInfoServers();
}

export async function getUserManagedServers(): Promise<CustomServerMap> {
  return readUserManagedServers();
}

export type ServerWithSource = { entry: CustomServerEntry; source: "manual" | "iana" | "repair" | "registry" };

/** Returns all DB-stored servers with their source tag for admin UI display. */
export async function getAllDbServersWithSource(): Promise<Record<string, ServerWithSource>> {
  if (!(await isDbReady())) return {};
  try {
    const rows = await many<{ tld: string; entry: unknown; source: string }>(
      `SELECT tld, entry, COALESCE(source, 'manual') AS source
       FROM custom_whois_servers ORDER BY source, tld`,
    );
    const map: Record<string, ServerWithSource> = {};
    for (const r of rows) {
      map[r.tld] = {
        entry: r.entry as CustomServerEntry,
        source: (r.source as "manual" | "iana" | "repair"),
      };
    }
    return map;
  } catch {
    return {};
  }
}

export async function getCustomServerEntry(tld: string): Promise<CustomServerEntry | null> {
  const all = await getAllCustomServers();
  const normalized = tld.toLowerCase().replace(/^\./, "");
  return all[normalized] ?? null;
}

export async function getCustomServer(tld: string): Promise<string | null> {
  const entry = await getCustomServerEntry(tld);
  if (!entry) return null;
  if (typeof entry === "string") return entry;
  if (entry.type === "tcp") return entry.host;
  return null;
}

export async function setCustomServer(tld: string, entry: CustomServerEntry): Promise<void> {
  const normalized = tld.toLowerCase().replace(/^\./, "");
  await writeDbServer(normalized, entry, "manual");
  invalidateAllServersCache();
}

/**
 * Saves a server found by the AI repair queue.
 * Marked as source='repair' — distinguishable from admin-added entries in the UI.
 */
export async function setRepairedServer(tld: string, entry: CustomServerEntry): Promise<void> {
  const normalized = tld.toLowerCase().replace(/^\./, "");
  await writeDbServer(normalized, entry, "repair");
  invalidateAllServersCache();
}

/**
 * Persists an automatically discovered WHOIS server to the DB so future cold
 * starts skip the live IANA / whoiser discovery round-trip.  Never overwrites
 * a manually configured (admin-managed) server.
 */
export async function setDiscoveredServer(
  tld: string,
  entry: CustomServerEntry,
  source: "iana" | "repair",
): Promise<void> {
  const normalized = tld.toLowerCase().replace(/^\./, "");
  // Fire-and-forget: don't await so we don't slow down the response path.
  writeAutoDiscoveredServer(normalized, entry, source).catch(() => {});
  // Warm the in-process cache immediately without waiting for DB confirmation.
  if (_allServersCache && !(normalized in _allServersCache)) {
    _allServersCache[normalized] = entry;
  }
}

export async function deleteCustomServer(tld: string): Promise<boolean> {
  const normalized = tld.toLowerCase().replace(/^\./, "");
  const servers = await readUserManagedServers();
  if (normalized in servers) {
    await deleteDbServer(normalized);
    invalidateAllServersCache();
    return true;
  }
  return false;
}

export async function isUserManagedServer(tld: string): Promise<boolean> {
  const normalized = tld.toLowerCase().replace(/^\./, "");
  // Use the in-process cache to avoid a DB query on every lookup.
  // Cache is invalidated explicitly when admin writes/deletes a custom server.
  const now = Date.now();
  if (!_userManagedCache || now - _userManagedCacheAt >= ALL_SERVERS_TTL_MS) {
    _userManagedCache = await readUserManagedServers();
    _userManagedCacheAt = now;
  }
  return normalized in _userManagedCache;
}

export function isHttpEntry(entry: CustomServerEntry): entry is HttpServerEntry {
  return typeof entry === "object" && entry.type === "http";
}

export function isScraperEntry(entry: CustomServerEntry): entry is ScraperEntry {
  return typeof entry === "object" && entry.type === "scraper";
}

export function isTcpEntry(entry: CustomServerEntry): entry is TcpServerEntry | string {
  if (typeof entry === "string") return true;
  return typeof entry === "object" && entry.type === "tcp";
}

export function getTcpHost(entry: CustomServerEntry): string | null {
  if (typeof entry === "string") return entry;
  if (typeof entry === "object" && entry.type === "tcp") return entry.host;
  return null;
}

// ── Registry sync helper ──────────────────────────────────────────────────────

export type RegistrySyncAction = "added" | "updated" | "conflict" | "unchanged" | "skipped";

export type RegistrySyncResult = {
  action: RegistrySyncAction;
  /** The IANA-discovered server */
  ianaServer: string;
  /** The pre-existing custom entry (if any) */
  existingEntry?: CustomServerEntry;
  existingSource?: string;
};

/**
 * Syncs a WHOIS server discovered from an IANA page into custom_whois_servers.
 *
 * Rules:
 *   - No entry   → INSERT with source='registry'
 *   - registry/iana/repair entry → UPDATE if server differs, keep otherwise
 *   - manual entry → do NOT overwrite; return 'conflict' with both values
 */
export async function syncRegistryServer(
  tld: string,
  ianaServer: string,
): Promise<RegistrySyncResult> {
  if (!(await isDbReady())) return { action: "skipped", ianaServer };

  const normalized = tld.toLowerCase().replace(/^\./, "");
  const server = ianaServer.trim().toLowerCase();
  if (!server) return { action: "skipped", ianaServer };

  // Read existing DB entry
  const rows = await many<{ tld: string; entry: unknown; source: string }>(
    `SELECT tld, entry, COALESCE(source,'manual') AS source FROM custom_whois_servers WHERE tld=$1`,
    [normalized],
  );
  const existing = rows[0];

  if (!existing) {
    // No entry at all → add
    await writeAutoDiscoveredServer(normalized, server, "registry");
    invalidateAllServersCache();
    return { action: "added", ianaServer: server };
  }

  const existingEntry = existing.entry as CustomServerEntry;
  const existingSource = existing.source;

  // Derive host string from existing entry for comparison
  let existingHost = "";
  if (typeof existingEntry === "string") existingHost = existingEntry.toLowerCase().trim();
  else if (typeof existingEntry === "object" && existingEntry.type === "tcp") existingHost = existingEntry.host.toLowerCase().trim();

  if (existingSource === "manual") {
    // Manual takes priority — report conflict but don't overwrite
    return { action: "conflict", ianaServer: server, existingEntry, existingSource };
  }

  if (existingHost === server) {
    return { action: "unchanged", ianaServer: server, existingEntry, existingSource };
  }

  // Non-manual, different → update
  await writeAutoDiscoveredServer(normalized, server, "registry");
  invalidateAllServersCache();
  return { action: "updated", ianaServer: server, existingEntry, existingSource };
}

// ── ScraperRequiredError ───────────────────────────────────────────────────────

export class ScraperRequiredError extends Error {
  registryUrl: string;
  blocked: boolean;
  constructor(message: string, registryUrl: string, blocked = false) {
    super(message);
    this.name = "ScraperRequiredError";
    this.registryUrl = registryUrl;
    this.blocked = blocked;
  }
}

// ── Shared server-entry executor ──────────────────────────────────────────────
// Handles scraper / HTTP / TCP entries uniformly.
// isUserServer=true → throw on failure; false → return null on failure.

let _whoiserPromiseCustom: Promise<typeof import("whoiser")> | null = null;
const getWhoiserCustom = () => {
  if (!_whoiserPromiseCustom) _whoiserPromiseCustom = import("whoiser");
  return _whoiserPromiseCustom;
};

async function executeServerEntry(
  customEntry: CustomServerEntry,
  domainToQuery: string,
  isUserServer: boolean,
  innerTimeout: number,
): Promise<WhoisRawResult | null> {
  if (isScraperEntry(customEntry)) {
    const { name: scraperName, registryUrl } = customEntry;
    if (scraperName === "nic-ba") {
      const nicBaResult = await lookupNicBa(domainToQuery, innerTimeout);
      if (nicBaResult.success) {
        return { raw: nicBaResult.raw, structured: {}, server: "nic.ba", registryUrl };
      }
      const nicBaFail = nicBaResult as { success: false; blocked: boolean; reason: string };
      throw new ScraperRequiredError(
        nicBaFail.blocked
          ? "nic.ba requires CAPTCHA verification — automated WHOIS lookup is not available for .ba domains"
          : `nic.ba scraper error: ${nicBaFail.reason}`,
        registryUrl,
        nicBaFail.blocked,
      );
    }
    if (scraperName === "nic-ph") {
      const nicPhResult = await lookupNicPh(domainToQuery);
      if (nicPhResult.success) {
        return { raw: nicPhResult.rawWhoisContent, structured: {}, server: "whois.dot.ph", registryUrl };
      }
      const nicPhFail = nicPhResult as { success: false; blocked: boolean; reason: string };
      throw new ScraperRequiredError(
        nicPhFail.blocked
          ? "whois.ph requires verification — automated WHOIS lookup is not available, please check the registry directly"
          : `nic.ph scraper error: ${nicPhFail.reason}`,
        registryUrl,
        nicPhFail.blocked,
      );
    }
    throw new ScraperRequiredError(`No scraper implementation for "${scraperName}"`, customEntry.registryUrl);
  }

  if (isHttpEntry(customEntry)) {
    const raw = await queryWhoisHttp(customEntry, domainToQuery, innerTimeout);
    if (!raw || raw.trim().length === 0) {
      if (isUserServer) throw new Error(`No data returned from HTTP WHOIS server: ${customEntry.url}`);
      return null;
    }
    if (isUserServer && isWhoisRateLimited(raw)) {
      throw new Error(`Custom WHOIS server ${customEntry.url} is rate-limiting requests — please try again later`);
    }
    return { raw, structured: {}, server: customEntry.url };
  }

  const tcpHost = getTcpHost(customEntry);
  if (tcpHost) {
    const port =
      typeof customEntry === "object" && "port" in customEntry && customEntry.port
        ? customEntry.port
        : 43;
    try {
      const { whoisQuery } = await getWhoiserCustom();
      const raw =
        port === 43
          ? await whoisQuery(tcpHost, domainToQuery, innerTimeout)
          : await queryWhoisTcp(tcpHost, port, domainToQuery, innerTimeout);
      if (raw && raw.trim().length > 0) {
        if (isUserServer && isWhoisRateLimited(raw)) {
          throw new Error(`Custom WHOIS server ${tcpHost} is rate-limiting requests — please try again later`);
        }
        return { raw, structured: {}, server: tcpHost };
      }
      if (isUserServer) throw new Error(`No data returned from custom WHOIS server: ${tcpHost}`);
    } catch (tcpErr) {
      if (isUserServer) throw tcpErr;
    }
  }

  return null;
}

// ── Custom server lookup (merged cache: DB + builtin + registry) ──────────────
// Returns data if the configured server responded.
// Returns null if no custom server is configured, or if a non-user-managed
// (auto-discovered) server produced no data (caller falls through to RDAP/WHOIS).
// Throws for user-managed server failures and for scraper-required errors.

export async function tryCustomServerForDomain(
  domainToQuery: string,
  tld: string,
  tldSuffix: string,
  innerTimeout: number,
): Promise<WhoisRawResult | null> {
  let customEntry: Awaited<ReturnType<typeof getCustomServerEntry>>;
  let isUserServer: boolean;
  if (tld === tldSuffix) {
    const [ce, us] = await Promise.all([getCustomServerEntry(tld), isUserManagedServer(tld)]);
    customEntry = ce;
    isUserServer = us;
  } else {
    const [[ce1, ce2], [us1, us2]] = await Promise.all([
      Promise.all([getCustomServerEntry(tld), getCustomServerEntry(tldSuffix)]),
      Promise.all([isUserManagedServer(tld), isUserManagedServer(tldSuffix)]),
    ]);
    customEntry = ce1 || ce2;
    isUserServer = us1 || us2;
  }

  if (!customEntry) return null;
  return executeServerEntry(customEntry, domainToQuery, isUserServer, innerTimeout);
}

// ── Priority-aware wrappers used by the new lookup order ─────────────────────

/**
 * Step 1 of the new priority chain: try BUILTIN servers (scrapers, .bn).
 * Returns immediately if the TLD is in BUILTIN_SERVER_TLDS; otherwise null.
 * These TLDs are always handled before whoiser because they require scrapers
 * or special handling that whoiser cannot perform.
 */
export async function tryBuiltinServerForDomain(
  domainToQuery: string,
  tld: string,
  tldSuffix: string,
  innerTimeout: number,
): Promise<WhoisRawResult | null> {
  const n1 = tld.toLowerCase().replace(/^\./, "");
  const n2 = tldSuffix.toLowerCase().replace(/^\./, "");
  if (!BUILTIN_SERVER_TLDS.has(n1) && !BUILTIN_SERVER_TLDS.has(n2)) return null;
  // Delegate to the full merged-cache lookup; it resolves the correct entry.
  return tryCustomServerForDomain(domainToQuery, tld, tldSuffix, innerTimeout);
}

// Cached user-managed servers (source='manual' or file fallback).
// Shares the same TTL & invalidation cycle as _allServersCache.
// Invalidated by invalidateAllServersCache() above.
let _manualServersCacheShadow: CustomServerMap | null = null;
let _manualServersCacheShadowAt = 0;

/**
 * Step ③ of the new priority chain: try only admin-manually-configured
 * WHOIS servers — strictly those with source='manual' in the DB.
 * File-based fallback is intentionally excluded; this path is for admin
 * overrides only and must not silently query unrelated file entries.
 * Called after whoiser has already failed (or been bypassed).
 * BUILTIN TLDs are excluded — they are handled in step ①.
 */
export async function tryManualServerForDomain(
  domainToQuery: string,
  tld: string,
  tldSuffix: string,
  innerTimeout: number,
): Promise<WhoisRawResult | null> {
  const n1 = tld.toLowerCase().replace(/^\./, "");
  const n2 = tldSuffix.toLowerCase().replace(/^\./, "");

  // BUILTIN TLDs are handled before whoiser — don't double-process them here.
  if (BUILTIN_SERVER_TLDS.has(n1) || BUILTIN_SERVER_TLDS.has(n2)) return null;

  // Use the dedicated manual-server cache (strict DB source='manual' only).
  // This intentionally does NOT fall back to file-based servers so that only
  // admin-configured overrides are used in this fallback step.
  const now = Date.now();
  if (!_manualServersCacheShadow || now - _manualServersCacheShadowAt >= ALL_SERVERS_TTL_MS) {
    _manualServersCacheShadow = await readManualDbServers();
    _manualServersCacheShadowAt = now;
  }
  const manualMap = _manualServersCacheShadow;
  const entry = manualMap[n1] ?? (n1 !== n2 ? manualMap[n2] : null) ?? null;
  if (!entry) return null;

  // isUserServer=true: throw on failure so callers see a clear error.
  return executeServerEntry(entry, domainToQuery, true, innerTimeout);
}

/**
 * Like tryManualServerForDomain but used in the parallel race (step ②).
 * Uses isUserServer=false so failures return null instead of throwing,
 * allowing other race competitors (whoiser, static) to still win.
 * Called immediately before the bypass check so it runs concurrently.
 */
export async function queryManualServerRacing(
  domainToQuery: string,
  tld: string,
  tldSuffix: string,
  innerTimeout: number,
): Promise<WhoisRawResult | null> {
  const n1 = tld.toLowerCase().replace(/^\./, "");
  const n2 = tldSuffix.toLowerCase().replace(/^\./, "");
  if (BUILTIN_SERVER_TLDS.has(n1) || BUILTIN_SERVER_TLDS.has(n2)) return null;
  const now = Date.now();
  if (!_manualServersCacheShadow || now - _manualServersCacheShadowAt >= ALL_SERVERS_TTL_MS) {
    _manualServersCacheShadow = await readManualDbServers();
    _manualServersCacheShadowAt = now;
  }
  const entry = _manualServersCacheShadow[n1] ?? (n1 !== n2 ? _manualServersCacheShadow[n2] : null) ?? null;
  if (!entry) return null;
  // isUserServer=false → return null on failure (racing context, not sole fallback)
  return executeServerEntry(entry, domainToQuery, false, innerTimeout).catch(() => null);
}
