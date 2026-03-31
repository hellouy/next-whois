import { WhoisRawResult, WhoisAnalyzeResult } from "@/lib/whois/types";
import { queryWhoisTcp } from "@/lib/whois/whois-transport";
import { setDiscoveredServer, isTldKnownNoServer } from "@/lib/whois/custom-servers";
import { getGtldWhoisServer } from "@/lib/whois/whois_gtld_bootstrap";
import { isIanaFallback } from "@/lib/whois/whois-patterns";

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
  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,3})?$/.test(query) ||
      /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/.test(query)) {
    const ip = query.replace(/\/\d{1,3}$/, "");
    const { whoisIp } = await getWhoiser();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await whoisIp(ip, { timeout: LOOKUP_TIMEOUT }) as Record<string, unknown>;
    return { raw: (data.__raw as string) || "", structured: data, server: "ip-whois" };
  }
  const asNum = parseInt(query.replace(/^AS/i, ""));
  const { whoisAsn } = await getWhoiser();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const data = await whoisAsn(asNum, { timeout: LOOKUP_TIMEOUT }) as Record<string, unknown>;
  return { raw: (data.__raw as string) || "", structured: data, server: "asn-whois" };
}

// ── Generic WHOIS (bootstrap list → whoiser library → IANA refer) ─────────────
export async function tryGenericWhoisForDomain(
  domainToQuery: string,
  tld: string,
  tldSuffix: string,
  innerTimeout: number,
  follow: 1 | 2,
): Promise<WhoisRawResult> {
  if (await isTldKnownNoServer(tld || tldSuffix)) {
    throw new Error(`No public WHOIS server available for .${tld || tldSuffix} domains`);
  }

  const bootstrapWhoisHost = getGtldWhoisServer(tld) ?? getGtldWhoisServer(tldSuffix);
  let primaryError: unknown = null;

  if (bootstrapWhoisHost) {
    try {
      const raw = await queryWhoisTcp(bootstrapWhoisHost, 43, domainToQuery, innerTimeout);
      if (raw && raw.trim().length > 0 && !isIanaFallback(raw)) {
        return { raw, structured: {}, server: bootstrapWhoisHost };
      }
    } catch (err) {
      primaryError = err;
    }
  }

  const { whoisDomain } = await getWhoiser();

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

  try {
    const data = await whoisDomain(domainToQuery, { raw: true, follow, timeout: innerTimeout });
    const result = extractRawFromData(data as Record<string, unknown>);
    if (result && result.raw.trim().length > 0) return result;
  } catch (err) {
    if (!primaryError) primaryError = err;
  }

  const ianaServer = await getIanaWhoisServer(tldSuffix);
  if (ianaServer && ianaServer !== bootstrapWhoisHost) {
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
