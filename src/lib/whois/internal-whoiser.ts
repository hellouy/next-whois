/**
 * internal-whoiser.ts — self-hosted replacement for the `whoiser` package.
 *
 * Implements the package functions this project actually used, with behaviour
 * mirrored from whoiser 2.0.0-beta.10 (verified against its dist source):
 *
 *   whoisQuery        → queryWhoisTcp (whois-transport.ts — strictly better:
 *                       SSRF guard, DoH DNS fallback, 2 MiB response cap)
 *   whoisDomain       → whoisDomainInternal (IANA discovery + follow chain)
 *   whoisIp/whoisAsn  → whoisIpInternal / whoisAsnInternal
 *
 * Key behaviours kept identical:
 *   - server discovery via the IANA `whois:` referral field (24h cache, also
 *     persisted through setDiscoveredServer so future lookups skip the IANA
 *     round-trip entirely)
 *   - follow chain driven by the Registrar/Registry WHOIS Server fields found
 *     in the previous response
 *   - special query formats: DENIC (-T dn <unicode>), JPRS (<domain>/e),
 *     ARIN (+ n <ip> / + a <asn>)
 *   - misspelled referral hosts (URLs pasted as server names) normalized
 */
import { domainToUnicode } from "node:url";
import { queryWhoisTcp } from "@/lib/whois/whois-transport";
import { setDiscoveredServer } from "@/lib/whois/custom-servers";

// ── IANA WHOIS server cache ────────────────────────────────────────────────────
const _ianaServerCache = new Map<string, { server: string | null; expires: number }>();
const IANA_CACHE_MAX = 2000;

export async function getIanaWhoisServer(tld: string): Promise<string | null> {
  const now = Date.now();
  const cached = _ianaServerCache.get(tld);
  if (cached && cached.expires > now) return cached.server;
  try {
    const raw = await queryWhoisTcp("whois.iana.org", 43, tld, 5_000);
    // IANA's WHOIS server referral field is `whois:` (e.g. "whois: whois.nic.xn").
    // `refer:` is NOT present in current IANA responses — every one of the 248
    // queried TLDs used `whois:` and none used `refer:`. Matching only `refer:`
    // returned null for every TLD, silently disabling the IANA fallback that
    // auto-discovers servers for TLDs missing from our static maps. Accept both
    // field names for forward/backward compatibility.
    const m = raw.match(/^(?:whois|refer):[ \t]+(\S+)[ \t]*$/im);
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

// Referral lookup for IP/ASN queries against whois.iana.org (no persistent
// cache — IP/ASN allocations are looked up once per request).
async function queryIanaReferral(query: string, timeoutMs: number): Promise<string | null> {
  try {
    const raw = await queryWhoisTcp("whois.iana.org", 43, query, timeoutMs);
    const m = raw.match(/^(?:whois|refer):[ \t]+(\S+)[ \t]*$/im);
    return m ? m[1].trim().toLowerCase() : null;
  } catch {
    return null;
  }
}

// Some registries report a URL (or a path-bearing string) in the "WHOIS
// Server" referral field instead of a bare hostname. Normalize the known
// offenders (list mirrors whoiser's misspelledWhoisServer map).
const MISSPELLED_SERVERS: Record<string, string> = {
  "www.gandi.net/whois": "whois.gandi.net",
  "who.godaddy.com/": "whois.godaddy.com",
  "whois.godaddy.com/": "whois.godaddy.com",
  "www.nic.ru/whois/en/": "whois.nic.ru",
  "www.whois.corporatedomains.com": "whois.corporatedomains.com",
  "www.safenames.net/DomainNames/WhoisSearch.aspx": "whois.safenames.net",
  "WWW.GNAME.COM/WHOIS": "whois.gname.com",
};

const NEXT_SERVER_FIELDS =
  /^[ \t]*(?:Registrar WHOIS Server|Registry WHOIS Server|ReferralServer|Registrar Whois|Whois Server|WHOIS Server):[ \t]*(\S+?)[ \t]*$/im;

// Google Registry responses often omit "Registrar WHOIS Server" but carry a
// Registrar URL pointing at domains.google — whoiser hardcodes this fallback.
const GOOGLE_REGISTRAR_URL = /^Registrar URL:[ \t]*\S*domains\.google/im;

export interface NextWhoisServer {
  host: string;
  port: number;
}

export function extractNextWhoisServer(raw: string, queried: Set<string>): NextWhoisServer | null {
  const m = raw.match(NEXT_SERVER_FIELDS);
  let next = m ? m[1].trim() : null;
  if (!next && GOOGLE_REGISTRAR_URL.test(raw)) next = "whois.google.com";
  if (!next) return null;

  let port = 43;
  if (next.includes("://")) {
    try {
      const u = new URL(next);
      const p = parseInt(u.port, 10);
      if (Number.isFinite(p) && p > 0 && p !== 43) port = p;
      next = u.hostname;
    } catch {
      // Unparseable URL — strip the scheme and keep the remainder as host.
      next = next.replace(/^[\w+.-]+:\/\//, "");
    }
  }
  const host = MISSPELLED_SERVERS[next] ?? next;
  if (!host || queried.has(host)) return null;
  return { host, port };
}

// ── Domain lookup ──────────────────────────────────────────────────────────────

export interface InternalWhoisResult {
  [server: string]: Record<string, unknown> & { __raw?: string; error?: string };
}

export async function whoisDomainInternal(
  domain: string,
  opts: { follow?: number; timeout?: number } = {},
): Promise<InternalWhoisResult> {
  const tld = domain.split(".").pop()?.toLowerCase() ?? "";
  const follow = opts.follow ?? 1;
  const timeout = opts.timeout ?? 5_000;

  const host = await getIanaWhoisServer(tld);
  if (!host) throw new Error(`TLD for "${domain}" not supported`);

  const results: InternalWhoisResult = {};
  const queried = new Set<string>([host]);
  let current: string | null = host;
  let port = 43;
  let remaining = follow;

  while (current && remaining > 0) {
    let query = domain;
    if (current === "whois.denic.de") query = `-T dn ${domainToUnicode(domain)}`;
    else if (current === "whois.jprs.jp") query = `${domain}/e`;

    let raw = "";
    try {
      raw = await queryWhoisTcp(current, port, query, timeout);
    } catch (err) {
      results[current] = { error: err instanceof Error ? err.message : String(err) };
      break;
    }
    results[current] = { __raw: raw };
    remaining--;

    const next = extractNextWhoisServer(raw, queried);
    if (next) {
      current = next.host;
      port = next.port;
      queried.add(next.host);
    } else {
      current = null;
    }
  }
  return results;
}

// ── IP / ASN lookup ────────────────────────────────────────────────────────────

// Minimal "Key: Value" parser matching whoiser's parseSimpleWhois output shape
// closely enough for IP/ASN records: repeated keys become arrays, %/# comment
// lines are dropped, unparseable lines land in `text`. The project only
// consumes `__raw` (the RDAP path provides the structured data), so a full
// group-based parser would add complexity without any consumer.
export function parseSimpleWhoisLines(raw: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const text: string[] = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith("%") || t.startsWith("#")) continue;
    const idx = t.indexOf(":");
    if (idx > 0) {
      const key = t.slice(0, idx).trim();
      const val = t.slice(idx + 1).trim();
      if (key && val) {
        const prev = out[key];
        if (prev === undefined) out[key] = val;
        else if (Array.isArray(prev)) prev.push(val);
        else out[key] = [prev, val];
        continue;
      }
    }
    text.push(t);
  }
  if (text.length > 0) out.text = text;
  return out;
}

export interface InternalIpAsnResult extends Record<string, unknown> {
  __raw: string;
}

export async function whoisIpInternal(
  ip: string,
  opts: { timeout?: number } = {},
): Promise<InternalIpAsnResult> {
  const timeout = opts.timeout ?? 5_000;
  const host = await queryIanaReferral(ip, timeout);
  if (!host) throw new Error(`No WHOIS server for "${ip}"`);
  // ARIN requires its directed-query format; a bare IP works everywhere else.
  const query = host === "whois.arin.net" ? `+ n ${ip}` : ip;
  const raw = await queryWhoisTcp(host, 43, query, timeout);
  return { __raw: raw, ...parseSimpleWhoisLines(raw) };
}

export async function whoisAsnInternal(
  asn: number,
  opts: { timeout?: number } = {},
): Promise<InternalIpAsnResult> {
  const timeout = opts.timeout ?? 5_000;
  const host = await queryIanaReferral(String(asn), timeout);
  if (!host) throw new Error(`No WHOIS server for "${asn}"`);
  const query = host === "whois.arin.net" ? `+ a ${asn}` : String(asn);
  const raw = await queryWhoisTcp(host, 43, query, timeout);
  return { __raw: raw, ...parseSimpleWhoisLines(raw) };
}
