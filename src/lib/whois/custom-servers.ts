import fs from "fs";
import path from "path";
import { many, run, isDbReady } from "@/lib/db-query";

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

const CCTLD_FILE = path.join(process.cwd(), "src/data/cctld-whois-servers.json");
const DATA_FILE  = path.join(process.cwd(), "src/data/custom-tld-servers.json");

function readCctldServers(): Record<string, string | null> {
  try {
    return JSON.parse(fs.readFileSync(CCTLD_FILE, "utf-8")) as Record<string, string | null>;
  } catch {
    return {};
  }
}

/** Exported so admin pages can identify which TLDs are handled by built-in logic. */
export const BUILTIN_SERVER_TLDS: ReadonlySet<string> = new Set(["bn","ba","com.ba","org.ba","net.ba","gov.ba","edu.ba","mil.ba"]);

const BUILTIN_SERVERS: CustomServerMap = {
  bn: "whois.bnnic.bn",
  ba:      { type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "com.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "org.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "net.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "gov.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "edu.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
  "mil.ba":{ type: "scraper", name: "nic-ba", registryUrl: "https://www.nic.ba/?culture=en&handler=DomainSearch" },
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
 * cctld-whois-servers.json entry overrides it.  Gives a useful fallback for
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
}

async function writeDbServer(
  tld: string,
  entry: CustomServerEntry,
  source: "manual" | "iana" | "repair" = "manual",
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
  source: "iana" | "repair",
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
  const cctld    = readCctldServers();
  // Include ALL DB entries (manual + iana-discovered + repair-promoted) in the hot cache.
  // The file fallback only activates on a fresh install before any DB entries exist.
  const allDb    = await readDbServers();
  const user     = Object.keys(allDb).length > 0 ? allDb : await readFileServers();
  const registry = await readRegistryInfoServers();

  // Build the no-server set from cctld nulls (not overridden by user DB entries
  // or registry info servers — if we discovered a server via registry scrape,
  // it's no longer "no server").
  _knownNoServerCache = new Set(
    Object.entries(cctld)
      .filter(([tld, v]) => v === null && !(tld in user) && !(tld in registry))
      .map(([tld]) => tld),
  );

  const cctldFiltered = Object.fromEntries(
    Object.entries(cctld).filter(([, v]) => v !== null),
  ) as CustomServerMap;

  // Priority (highest wins, later entries override earlier ones):
  //   1. registry (tld_registry_info.whois_server) — lowest, fills gaps
  //   2. BUILTIN_SERVERS — hard-coded in source
  //   3. cctld-whois-servers.json — curated static file
  //   4. custom_whois_servers DB — highest, user / repair-queue managed
  _allServersCache = { ...registry, ...BUILTIN_SERVERS, ...cctldFiltered, ...user };
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

export type ServerWithSource = { entry: CustomServerEntry; source: "manual" | "iana" | "repair" };

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
