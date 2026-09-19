import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { getStaticWhoisServer, BUILTIN_SERVER_TLDS } from "./custom-servers";
import { getGtldWhoisServer } from "./whois_gtld_bootstrap";
import { getGtldRdapServer } from "./rdap_gtld_bootstrap";
import { getRdapServerForIpv4 } from "./rdap-bootstrap";
import { getKnownDiscoveryServer } from "./internal-whoiser";
import { NO_SERVER_TLDS } from "./lookup";

/**
 * Offline coverage audit (4c).
 *
 * Every TLD in IANA's list must be resolvable WITHOUT any live IANA access:
 * a WHOIS server from a static map, an explicit null (registry has no WHOIS),
 * a static RDAP endpoint, the NO_SERVER_TLDS fast path, a built-in scraper,
 * or a known-discovery override.
 *
 * IANA publishes no `whois:` referral for a few TLDs (e.g. mil) but their
 * WHOIS servers still exist; these are handled by the local
 * KNOWN_DISCOVERY_SERVERS override, so NO live IANA round-trip is needed.
 *
 * If this test fails, a new TLD was added to the IANA list (or a mapping was
 * removed) and the static tables must be updated before deploy — otherwise a
 * production query would stall waiting on live IANA discovery.
 */
describe("offline coverage: all IANA TLDs resolve without live IANA access", () => {
  const tlds = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), "src/data/iana-tlds.json"), "utf-8"),
  ) as string[];

  const noServer = new Set(NO_SERVER_TLDS);

  it("loads the full IANA TLD list", () => {
    expect(tlds.length).toBeGreaterThan(1400);
  });

  it("every TLD resolves via static WHOIS / RDAP / explicit-null / fast-path", () => {
    const uncovered: string[] = [];
    for (const tld of tlds) {
      const whois = getStaticWhoisServer(tld);
      const gtld = getGtldWhoisServer(tld);
      const rdap = getGtldRdapServer(tld);
      // BUILTIN_SERVER_TLDS are handled locally via custom scrapers (nic-ba,
      // nic-ph, nic-gw) or direct TCP — no live IANA access required.
      if (whois || gtld || rdap || noServer.has(tld) || BUILTIN_SERVER_TLDS.has(tld)) continue;
      // TLDs whose WHOIS server IANA omits but we know locally (KNOWN_DISCOVERY_SERVERS).
      if (getKnownDiscoveryServer(tld)) continue;
      uncovered.push(tld);
    }
    expect(uncovered).toEqual([]);
  });

  it("maintains ≥99% static coverage (no regression from the 1434/1436 baseline)", () => {
    const covered = tlds.filter((t) => {
      const whois = getStaticWhoisServer(t);
      const gtld = getGtldWhoisServer(t);
      const rdap = getGtldRdapServer(t);
      return Boolean(
        whois || gtld || rdap || noServer.has(t) || BUILTIN_SERVER_TLDS.has(t) || getKnownDiscoveryServer(t),
      );
    }).length;
    expect(covered / tlds.length).toBeGreaterThanOrEqual(0.99);
  });

  it("RDAP IP bootstrap covers all five RIRs", () => {
    expect(getRdapServerForIpv4("8.8.8.8")).toBe("https://rdap.arin.net/registry");
    expect(getRdapServerForIpv4("1.1.1.1")).toBe("https://rdap.apnic.net");
    expect(getRdapServerForIpv4("41.1.1.1")).toBe("https://rdap.afrinic.net/rdap");
    expect(getRdapServerForIpv4("2.2.2.2")).toBe("https://rdap.db.ripe.net");
    expect(getRdapServerForIpv4("177.0.0.1")).toBe("https://rdap.lacnic.net/rdap");
  });
});
