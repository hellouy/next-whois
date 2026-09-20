import { describe, it, expect } from "vitest";
import { convertRdapToWhoisResult } from "./rdap_client";
import type { RdapResponse } from "./rdap_client";

/**
 * Registrar-URL extraction hardening.
 *
 * RDAP registrar entities frequently carry "about"/"related" links that point
 * at RDAP/WHOIS service infrastructure instead of the registrar's actual
 * website (e.g. whois.org surfaced https://opensrs.rdap.tucows.com/ as
 * Tucows' website). The parser must filter service hosts and prefer the
 * curated registrar library whenever the RDAP link does not plausibly belong
 * to the registrar itself.
 */
function mkRdap(overrides: Record<string, unknown>): RdapResponse {
  return {
    ldhName: "test.example",
    events: [
      { eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" },
      { eventAction: "expiration", eventDate: "2028-01-01T00:00:00Z" },
    ],
    status: ["ok"],
    nameservers: [{ ldhName: "ns1.example.com" }],
    secureDNS: { delegationSigned: false },
    entities: [],
    ...overrides,
  } as unknown as RdapResponse;
}

describe("convertRdapToWhoisResult — registrar URL extraction", () => {
  it("keeps the RDAP link when the registrar is not in the library and the link is a real website", async () => {
    const r = await convertRdapToWhoisResult(mkRdap({
      entities: [{
        roles: ["registrar"], handle: "9999",
        vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Niche Registrar GmbH"]]],
        links: [{ rel: "about", type: "text/html", href: "https://www.nicheregistrar.de/" }],
      }],
    }), "test.example");
    expect(r.registrarURL).toBe("https://www.nicheregistrar.de/");
  });

  it("rejects an rdap.* service host as registrarURL (registry RDAP endpoint)", async () => {
    const r = await convertRdapToWhoisResult(mkRdap({
      entities: [{
        roles: ["registrar"], handle: "9999",
        vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Niche Registrar GmbH"]]],
        links: [{ rel: "about", type: "application/rdap+json", href: "https://rdap.niche-registrar-rdap.de/" }],
      }],
    }), "test.example");
    expect(r.registrarURL).toBe("Unknown");
  });

  it("surfaces the curated library website when the about link is a registry RDAP service (whois.org / Tucows case)", async () => {
    const r = await convertRdapToWhoisResult(mkRdap({
      entities: [{
        roles: ["registrar"], handle: "69",
        publicIds: [{ type: "IANA Registrar ID", identifier: "69" }],
        vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Tucows Domains Inc."]]],
        links: [{ rel: "about", type: "application/rdap+json", href: "https://rdap.publicinterestregistry.org/" }],
      }],
    }), "test.example");
    expect(r.registrar).toBe("Tucows Domains Inc.");
    expect(r.registrarURL).toBe("https://tucows.com");
    expect(r.ianaId).toBe("69");
  });

  it("falls back to the library via IANA Registrar ID when the registrar name does not match", async () => {
    const r = await convertRdapToWhoisResult(mkRdap({
      entities: [{
        roles: ["registrar"], handle: "69",
        publicIds: [{ type: "IANA Registrar ID", identifier: "69" }],
        vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "オープンエスアールエス"]]],
        links: [{ rel: "about", type: "application/rdap+json", href: "https://rdap.opensrs.rdap.tucows.com/" }],
      }],
    }), "test.example");
    expect(r.registrarURL).toBe("https://tucows.com");
    expect(r.ianaId).toBe("69");
  });

  it("keeps a registrar-owned subdomain link even when the library has a different path", async () => {
    const r = await convertRdapToWhoisResult(mkRdap({
      entities: [{
        roles: ["registrar"], handle: "146",
        publicIds: [{ type: "IANA Registrar ID", identifier: "146" }],
        vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "GoDaddy.com, LLC"]]],
        links: [{ rel: "about", type: "text/html", href: "https://sso.godaddy.com/" }],
      }],
    }), "test.example");
    expect(r.registrarURL).toBe("https://sso.godaddy.com/");
  });

  it("falls back to the library website when the registrar provides no links at all", async () => {
    const r = await convertRdapToWhoisResult(mkRdap({
      entities: [{
        roles: ["registrar"], handle: "146",
        publicIds: [{ type: "IANA Registrar ID", identifier: "146" }],
        vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "GoDaddy.com, LLC"]]],
      }],
    }), "test.example");
    expect(r.registrarURL).toBe("https://www.godaddy.com");
  });
});
