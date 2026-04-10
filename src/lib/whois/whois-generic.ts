import { WhoisRawResult, WhoisAnalyzeResult } from "@/lib/whois/types";
import { queryWhoisTcp } from "@/lib/whois/whois-transport";
import {
  setDiscoveredServer,
  tryBuiltinServerForDomain,
  tryManualServerForDomain,
  queryManualServerRacing,
  getStaticWhoisServer,
} from "@/lib/whois/custom-servers";
import { isWhoiserBypassed, recordWhoiserFailure, resetWhoiserFailureCounter } from "@/lib/whois/whoiser-bypass";

let _whoiserPromise: Promise<typeof import("whoiser")> | null = null;
const getWhoiser = () => {
  if (!_whoiserPromise) _whoiserPromise = import("whoiser");
  return _whoiserPromise;
};

// ── IANA WHOIS server cache ────────────────────────────────────────────────────
const _ianaServerCache = new Map<string, { server: string | null; expires: number }>();
const IANA_CACHE_MAX = 2000;

export async function getIanaWhoisServer(tld: string): Promise<string | null> {
  const now = Date.now();
  const cached = _ianaServerCache.get(tld);
  if (cached && cached.expires > now) return cached.server;
  try {
    const raw = await queryWhoisTcp("whois.iana.org", 43, tld, 5_000);
    const m = raw.match(/^refer:\s*(\S+)/im);
    const server = m ? m[1].trim().toLowerCase() : null;
    if (_ianaServerCache.size >= IANA_CACHE_MAX && !_ianaServerCache.has(tld)) {
      const oldest = _ianaServerCache.keys().next().value;
      if (oldest !== undefined) _ianaServerCache.delete(oldest);
    }
    _ianaServerCache.set(tld, { server, expires: now + 86_400_000 });
    if (server) setDiscoveredServer(tld, server, "iana").catch(() => {});
    return server;
  } catch {
    return null;
  }
}

// ── IP / ASN lookup ────────────────────────────────────────────────────────────
export async function lookupIpOrAsn(query: string): Promise<WhoisRawResult> {
  try {
    if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,3})?$/.test(query) ||
        /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(query)) {
      const ip = query.replace(/\/\d{1,3}$/, "");
      const { whoisIp } = await getWhoiser();
      const data = await whoisIp(ip, { timeout: 10_000 }) as Record<string, unknown>;
      return { raw: (data.__raw as string) || "", structured: data, server: "ip-whois" };
    }
    const asNum = parseInt(query.replace(/^AS/i, ""));
    const { whoisAsn } = await getWhoiser();
    const data = await whoisAsn(asNum, { timeout: 10_000 }) as Record<string, unknown>;
    return { raw: (data.__raw as string) || "", structured: data, server: "asn-whois" };
  } catch (err: unknown) {
    // Normalize all upstream errors to a consistent shape so that raw stack
    // traces or internal whoiser messages never reach the client.
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(msg.length > 120 ? msg.slice(0, 120) + "…" : msg);
  }
}

// ── Extract whoiser result into our WhoisRawResult shape ──────────────────────
function extractRawFromData(data: Record<string, unknown>): WhoisRawResult | null {
  const servers = Object.keys(data ?? {});
  if (servers.length === 0) return null;
  const lastServer = servers[servers.length - 1];
  const structured = (data[lastServer] as Record<string, unknown>) || {};
  const rawParts: string[] = [];
  for (const s of servers) {
    const entry = data[s] as Record<string, unknown> | null;
    if (entry?.__raw) {
      rawParts.push(entry.__raw as string);
    } else if (entry) {
      const lines: string[] = [];
      for (const [k, v] of Object.entries(entry)) {
        if (k === "text" || k === "__raw" || k === "__comments") continue;
        if (Array.isArray(v)) {
          for (const item of v) lines.push(`${k}: ${item}`);
        } else if (v !== undefined && v !== null && v !== "") {
          lines.push(`${k}: ${v}`);
        }
      }
      if (lines.length > 0) rawParts.push(lines.join("\n"));
    }
  }
  return { raw: rawParts.join("\n\n") || "", structured, server: lastServer };
}

/**
 * Resolves to the first non-null result from any of the given promises.
 * Returns null only when every promise resolves/rejects with null/error.
 */
function raceFirstNonNull(promises: Promise<WhoisRawResult | null>[]): Promise<WhoisRawResult | null> {
  return new Promise<WhoisRawResult | null>((resolve) => {
    if (promises.length === 0) { resolve(null); return; }
    let pending = promises.length;
    let resolved = false;
    for (const p of promises) {
      p.then((v) => {
        if (resolved) return;
        if (v !== null) { resolved = true; resolve(v); return; }
        if (--pending === 0) resolve(null);
      }).catch(() => {
        if (!resolved && --pending === 0) resolve(null);
      });
    }
  });
}

/**
 * Generic WHOIS lookup with the following priority order:
 *
 *   ① BUILTIN servers (.ba scraper, .bn) — whoiser cannot handle these.
 *   ② whoiser + static-map TCP + admin manual server race (skipped if bypassed):
 *      - All three run in parallel; first non-empty result wins.
 *      - Manual server is always included so admin-configured servers are
 *        preferred over whoiser's auto-discovery, not just a last resort.
 *      - Success → reset whoiser failure counter (if whoiser/static won) and return.
 *      - All fail → record failure; if ≥3 consecutive: mark TLD bypassed.
 *   ③ Admin manual DB server (source='manual') — primary path when bypassed.
 *   ④ IANA TCP fallback — last resort server discovery.
 *   ⑤ Throw with the most descriptive error available.
 */
export async function tryGenericWhoisForDomain(
  domainToQuery: string,
  tld: string,
  tldSuffix: string,
  innerTimeout: number,
  follow: 1 | 2,
): Promise<WhoisRawResult> {
  // ① BUILTIN scrapers / special-case servers (.ba, .bn, etc.)
  //    These are tried unconditionally before whoiser because whoiser cannot
  //    handle CAPTCHA-protected registries or non-standard WHOIS endpoints.
  const builtinResult = await tryBuiltinServerForDomain(
    domainToQuery, tld, tldSuffix, innerTimeout,
  );
  if (builtinResult) return builtinResult;

  let primaryError: unknown = null;

  // Start manual server query immediately (before bypass check) so it runs
  // concurrently with whoiser and the static-map TCP query.  When the admin
  // has configured a server for this TLD, it competes in the step ② race
  // rather than being relegated to a post-whoiser fallback — this ensures
  // the configured server is actually used instead of being shadowed by a
  // whoiser auto-discovery result that may be lower quality.
  let manualWon = false;
  const manualRacingP: Promise<WhoisRawResult | null> = queryManualServerRacing(
    domainToQuery, tld, tldSuffix, innerTimeout,
  ).then((r) => { if (r) manualWon = true; return r; }).catch((): null => null);

  // ② whoiser + static-map TCP + manual server race (unless TLD is bypassed)
  //    Bypass is set automatically after BYPASS_FAIL_THRESHOLD consecutive
  //    failures; it can also be set/cleared manually from the admin panel.
  const bypassed = await isWhoiserBypassed(tldSuffix);

  if (!bypassed) {
    const staticServer = getStaticWhoisServer(tldSuffix);

    const staticP: Promise<WhoisRawResult | null> = staticServer
      ? queryWhoisTcp(staticServer, 43, domainToQuery, innerTimeout)
          .then((raw): WhoisRawResult | null => {
            if (!raw || raw.trim().length === 0) return null;
            return { raw, structured: {}, server: staticServer };
          })
          .catch((): null => null)
      : Promise.resolve(null);

    const { whoisDomain } = await getWhoiser();

    const whoiserP: Promise<WhoisRawResult | null> = (async (): Promise<WhoisRawResult | null> => {
      try {
        const data = await whoisDomain(domainToQuery, { raw: true, follow, timeout: innerTimeout });
        const result = extractRawFromData(data as Record<string, unknown>);
        return result && result.raw.trim().length > 0 ? result : null;
      } catch (err) {
        primaryError = err;
        return null;
      }
    })();

    // All three run in parallel; first non-null result wins.
    const candidates: Promise<WhoisRawResult | null>[] = [whoiserP, manualRacingP];
    if (staticServer) candidates.push(staticP);
    let winner = await raceFirstNonNull(candidates);

    if (winner) {
      // Discard results that are whoiser-internal network error strings rather
      // than actual WHOIS data.  When whoiser cannot connect to the server (e.g.
      // ENOTFOUND whois.nic.google, ECONNREFUSED, ETIMEDOUT) it sometimes
      // embeds the Node.js error message in the result object, which passes the
      // raw.trim().length > 0 check above and masquerades as valid WHOIS data.
      // Such results start with "error: getaddrinfo …" or "connect E…".
      if (/^error:\s*(?:getaddrinfo|connect\s+E(?:NOTFOUND|CONNREFUSED|CONNRESET|TIMEDOUT))/im.test(winner.raw.trimStart())) {
        primaryError = primaryError ?? new Error(winner.raw.trim().slice(0, 120));
        winner = null;
      }
    }

    if (winner) {
      // Only reset the whoiser failure counter if whoiser or the static-map
      // server won — not when the manual server won (whoiser may still be broken).
      if (!manualWon) resetWhoiserFailureCounter(tldSuffix).catch(() => {});
      return winner;
    }

    // whoiser (and static-map) failed — record the failure.
    // recordWhoiserFailure is fire-and-forget; never awaited on the hot path.
    recordWhoiserFailure(tldSuffix).catch(() => {});
  }

  // ③ Admin manual DB server (source='manual') — primary path when bypassed.
  //    manualRacingP has already started; if it resolved with data, use it
  //    directly.  Otherwise fall back to a fresh call with isUserServer=true
  //    so errors are propagated clearly.
  const manualQuick = await manualRacingP;
  if (manualQuick) return manualQuick;
  try {
    const manualResult = await tryManualServerForDomain(
      domainToQuery, tld, tldSuffix, innerTimeout,
    );
    if (manualResult) return manualResult;
  } catch (manualErr) {
    // Manual server failed — keep going, prefer the original whoiser error
    if (!primaryError) primaryError = manualErr;
  }

  // ④ IANA TCP fallback — ask whois.iana.org for the canonical server
  const ianaServer = await getIanaWhoisServer(tldSuffix);
  if (ianaServer) {
    try {
      const raw = await queryWhoisTcp(ianaServer, 43, domainToQuery, innerTimeout);
      if (raw && raw.trim().length > 0) return { raw, structured: {}, server: ianaServer };
    } catch {}
  }

  throw primaryError ?? new Error("No WHOIS server responded");
}

// ── mergeResults helper ────────────────────────────────────────────────────────
export function pickStr(a: string, b: string): string {
  return a && a !== "Unknown" && a !== "" ? a : b;
}

export function mergeResults(
  rdap: WhoisAnalyzeResult,
  whoisParsed: WhoisAnalyzeResult,
): WhoisAnalyzeResult {
  const p = pickStr;
  return {
    domain: p(rdap.domain, whoisParsed.domain),
    domainPunycode: rdap.domainPunycode || whoisParsed.domainPunycode,
    registrar: p(rdap.registrar, whoisParsed.registrar),
    registrarURL: p(rdap.registrarURL, whoisParsed.registrarURL),
    ianaId: p(rdap.ianaId, whoisParsed.ianaId),
    whoisServer: p(rdap.whoisServer, whoisParsed.whoisServer),
    registryDomainId: p(rdap.registryDomainId, whoisParsed.registryDomainId),
    updatedDate: p(rdap.updatedDate, whoisParsed.updatedDate),
    creationDate: p(rdap.creationDate, whoisParsed.creationDate),
    expirationDate: p(rdap.expirationDate, whoisParsed.expirationDate),
    status: rdap.status.length > 0 ? rdap.status : whoisParsed.status,
    nameServers: rdap.nameServers.length > 0 ? rdap.nameServers : whoisParsed.nameServers,
    registrantName: p(rdap.registrantName, whoisParsed.registrantName),
    registrantOrganization: p(rdap.registrantOrganization, whoisParsed.registrantOrganization),
    registrantCountry: p(rdap.registrantCountry, whoisParsed.registrantCountry),
    registrantProvince: p(rdap.registrantProvince, whoisParsed.registrantProvince),
    registrantCity: p(rdap.registrantCity, whoisParsed.registrantCity),
    registrantAddress: p(rdap.registrantAddress, whoisParsed.registrantAddress),
    registrantPostalCode: p(rdap.registrantPostalCode, whoisParsed.registrantPostalCode),
    registrantPhone: p(rdap.registrantPhone, whoisParsed.registrantPhone),
    registrantFax: p(rdap.registrantFax, whoisParsed.registrantFax),
    registrantEmail: p(rdap.registrantEmail, whoisParsed.registrantEmail),
    adminName: p(rdap.adminName, whoisParsed.adminName),
    adminOrganization: p(rdap.adminOrganization, whoisParsed.adminOrganization),
    adminCountry: p(rdap.adminCountry, whoisParsed.adminCountry),
    adminEmail: p(rdap.adminEmail, whoisParsed.adminEmail),
    adminPhone: p(rdap.adminPhone, whoisParsed.adminPhone),
    techName: p(rdap.techName, whoisParsed.techName),
    techOrganization: p(rdap.techOrganization, whoisParsed.techOrganization),
    techEmail: p(rdap.techEmail, whoisParsed.techEmail),
    techPhone: p(rdap.techPhone, whoisParsed.techPhone),
    abuseEmail: p(rdap.abuseEmail, whoisParsed.abuseEmail),
    abusePhone: p(rdap.abusePhone, whoisParsed.abusePhone),
    dnssec: p(rdap.dnssec, whoisParsed.dnssec),
    rawWhoisContent: rdap.rawWhoisContent || whoisParsed.rawWhoisContent,
    rawRdapContent: rdap.rawRdapContent || whoisParsed.rawRdapContent,
    domainAge: rdap.domainAge ?? whoisParsed.domainAge,
    remainingDays: rdap.remainingDays ?? whoisParsed.remainingDays,
    registerPrice: rdap.registerPrice ?? whoisParsed.registerPrice,
    renewPrice: rdap.renewPrice ?? whoisParsed.renewPrice,
    negotiable: rdap.negotiable ?? whoisParsed.negotiable,
    cidr: p(rdap.cidr, whoisParsed.cidr),
    inetNum: p(rdap.inetNum, whoisParsed.inetNum),
    inet6Num: p(rdap.inet6Num, whoisParsed.inet6Num),
    netRange: p(rdap.netRange, whoisParsed.netRange),
    netName: p(rdap.netName, whoisParsed.netName),
    netType: p(rdap.netType, whoisParsed.netType),
    originAS: p(rdap.originAS, whoisParsed.originAS),
  };
}
