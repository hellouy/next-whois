import { describe, it, expect } from "vitest";
import {
  classifyQueryOutcome,
  isWhoisRateLimited,
  isIanaFallback,
  detectWhoisError,
  isNotRegisteredWhoisResponse,
} from "./whois-patterns";

// The Identity Digital / Afilias family of registries (.ac, .gi, .sh, .io, …)
// append the ENTIRE terms-of-use block after the real answer as ONE giant line
// that contains "If too many queries are received from a single IP address".
// That phrase matched /too many (?:requests|queries)/i and made a normal
// "Domain not found." reply look rate-limited — which also persisted a
// TLD-wide rate-limit flag that broke every later lookup for that TLD.
const IDENTITY_DIGITAL_NOT_FOUND = `Domain not found.
>>> Last update of WHOIS database: 2026-09-18T02:33:50Z <<<

Terms of Use: Access to WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the registry database. The data in this record is provided by Identity Digital or the Registry Operator for informational purposes only, and accuracy is not guaranteed. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than your own existing customers; If too many queries are received from a single IP address, the Registry Operator may restrict the sender. By submitting this query, you agree to abide by these terms.`;

// Genuine rate-limit responses must still be detected. whois.nic.hu reports
// access restrictions inside % comment lines.
const RATE_LIMITED_HU = `% This is the EURid Whois server.
% only queries for .eu domains are allowed.
% Too many queries received from your IP address.
% Please try again later.`;

const IANA_FALLBACK_SAMPLE = `% returns different details
% IANA WHOIS server
% internet Corporation for Assigned Names and Numbers
% Emails to Reception: reception@iana.org
% Queries: whois@iana.org
domain:       SWEDEN
organisation: The Swedish Post and Telecom Agency (PTS)`;

const IANA_FALLBACK_WITH_SERVER = `% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

domain:       HM
organisation: HM Domain Registry

whois:        whois.registry.hm
status:       ACTIVE`;

describe("isWhoisRateLimited", () => {
  it("does NOT flag a normal 'Domain not found.' with Identity Digital ToU banner", () => {
    expect(isWhoisRateLimited(IDENTITY_DIGITAL_NOT_FOUND)).toBe(false);
  });

  it("still flags a genuine %-comment rate-limit response", () => {
    expect(isWhoisRateLimited(RATE_LIMITED_HU)).toBe(true);
  });
});

describe("isIanaFallback", () => {
  it("detects IANA-generated responses", () => {
    expect(isIanaFallback(IANA_FALLBACK_SAMPLE)).toBe(true);
    expect(isIanaFallback(IANA_FALLBACK_WITH_SERVER)).toBe(true);
  });

  it("returns false for normal registry data", () => {
    expect(isIanaFallback("Domain Name: google.com\nRegistrar: MarkMonitor Inc.")).toBe(false);
    expect(isIanaFallback("Domain not found.")).toBe(false);
  });
});

describe("classifyQueryOutcome", () => {
  it("marks successful queries as registered", () => {
    expect(classifyQueryOutcome(true)).toBe("registered");
    expect(classifyQueryOutcome(true, undefined)).toBe("registered");
    expect(classifyQueryOutcome(true, "Domain not found")).toBe("registered");
  });

  it("marks not-registered responses as unregistered", () => {
    expect(classifyQueryOutcome(false, "No match for \"EXAMPLE.COM\".")).toBe("unregistered");
    expect(classifyQueryOutcome(false, "Domain not found")).toBe("unregistered");
    expect(classifyQueryOutcome(false, "%% NOT FOUND")).toBe("unregistered");
    expect(classifyQueryOutcome(false, "No Data Found")).toBe("unregistered");
  });

  it("marks invalid TLD input as invalid", () => {
    expect(classifyQueryOutcome(false, "Invalid TLD \"s\"")).toBe("invalid");
    expect(classifyQueryOutcome(false, "not a valid TLD: .k")).toBe("invalid");
  });

  it("marks real infrastructure failures as error", () => {
    expect(classifyQueryOutcome(false, "WHOIS/RDAP not available for this TLD")).toBe("error");
    expect(classifyQueryOutcome(false, "Empty WHOIS response")).toBe("error");
    expect(classifyQueryOutcome(false, "connect ETIMEDOUT 1.2.3.4:43")).toBe("error");
    expect(classifyQueryOutcome(false, "too many requests (429)")).toBe("error");
    expect(classifyQueryOutcome(false, undefined)).toBe("error");
    expect(classifyQueryOutcome(false, "")).toBe("error");
  });
});

// .ug (and other registries using the same "generic" WHOIS server software)
// place the "Domain not Found" verdict on a ">>>" marker line. Before the fix
// the whole ">>>" line was discarded, hiding the unregistered signal and
// causing the domain to be misreported as registered.
const UG_NOT_FOUND = `**********************************************************
*            The UG ccTLD Registry Database              *
**********************************************************

Domain Name: whois.ug
>>> Domain not Found
>>> Last update of WHOIS database: 2026-09-19T15:27:22 <<<`;

describe("detectWhoisError — >>> marker lines", () => {
  it("detects 'Domain not Found' on a >>> line (.ug)", () => {
    const err = detectWhoisError(UG_NOT_FOUND);
    expect(err).not.toBeNull();
    expect(isNotRegisteredWhoisResponse(err!)).toBe(true);
  });

  it("does NOT false-positive on a registered domain with >>> boilerplate", () => {
    const registered = `Domain Name: GOOGLE.COM
Registry Domain ID: 12345
Registrar: MarkMonitor Inc.
>>> Last update of WHOIS database: 2026-09-19T15:27:22 <<<`;
    expect(detectWhoisError(registered)).toBeNull();
  });

  it("detects rate-limit messages on >>> lines", () => {
    const rateLimited = `Domain Name: test.ug
>>> Query rate limit exceeded`;
    expect(isWhoisRateLimited(rateLimited)).toBe(true);
  });
});