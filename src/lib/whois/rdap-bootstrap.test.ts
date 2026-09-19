import { describe, it, expect } from "vitest";
import {
  getRdapServerForIpv4,
  getRdapServerForIpv6,
  getRdapServerForAsn,
} from "./rdap-bootstrap";

describe("rdap-bootstrap (self-hosted IANA IP/ASN RDAP discovery)", () => {
  it("resolves IPv4 addresses to their RIR RDAP server", () => {
    expect(getRdapServerForIpv4("8.8.8.8")).toBe("https://rdap.arin.net/registry");
    expect(getRdapServerForIpv4("1.1.1.1")).toBe("https://rdap.apnic.net");
    expect(getRdapServerForIpv4("41.1.1.1")).toBe("https://rdap.afrinic.net/rdap");
    expect(getRdapServerForIpv4("2.2.2.2")).toBe("https://rdap.db.ripe.net");
    expect(getRdapServerForIpv4("177.0.0.1")).toBe("https://rdap.lacnic.net/rdap");
  });

  it("resolves IPv6 addresses to their RIR RDAP server", () => {
    expect(getRdapServerForIpv6("2001:4860:4860::8888")).toBe("https://rdap.arin.net/registry");
    expect(getRdapServerForIpv6("2001:200::1")).toBe("https://rdap.apnic.net");
    expect(getRdapServerForIpv6("2a00:1450::1")).toBe("https://rdap.db.ripe.net");
    expect(getRdapServerForIpv6("2001:1200::1")).toBe("https://rdap.lacnic.net/rdap");
    expect(getRdapServerForIpv6("2001:4200::1")).toBe("https://rdap.afrinic.net/rdap");
  });

  it("resolves AS numbers to their RIR RDAP server", () => {
    expect(getRdapServerForAsn(15169)).toBe("https://rdap.arin.net/registry"); // Google
    expect(getRdapServerForAsn(13335)).toBe("https://rdap.arin.net/registry"); // Cloudflare
    expect(getRdapServerForAsn(2516)).toBe("https://rdap.arin.net/registry"); // KDDI (per IANA asn.json)
    expect(getRdapServerForAsn(3320)).toBe("https://rdap.db.ripe.net"); // Deutsche Telekom
    expect(getRdapServerForAsn(36925)).toBe("https://rdap.afrinic.net/rdap"); // AFRINIC
    expect(getRdapServerForAsn(28000)).toBe("https://rdap.lacnic.net/rdap"); // LACNIC
  });

  it("returns null for unknown/mismatched values", () => {
    expect(getRdapServerForIpv4("999.999.999.999")).toBeNull();
    expect(getRdapServerForAsn(0)).toBeNull();
    expect(getRdapServerForAsn(-1)).toBeNull();
  });
});
