import { describe, it, expect, vi } from "vitest";
import { normalizeHref, matchesSiteIdentity, hostToken } from "./site-identity";

vi.mock("@/lib/email", () => ({ getSiteLabel: vi.fn(async () => "DomainPulse") }));
vi.mock("./site-settings-server", () => ({ getSiteUrl: vi.fn(async () => "https://whois.example") }));

const IDENTITY = {
  url: "https://whois.example",
  hostname: "whois.example",
  label: "DomainPulse",
};

describe("normalizeHref", () => {
  it("keeps matching host while dropping protocol differences", () => {
    expect(normalizeHref("https://whois.example")).toBe("https://whois.example");
    expect(normalizeHref("http://whois.example")).toBe("http://whois.example");
  });

  it("strips the www. prefix so host comparison is stable", () => {
    expect(normalizeHref("https://www.whois.example")).toBe("https://whois.example");
  });

  it("drops trailing slashes and query strings", () => {
    expect(normalizeHref("https://whois.example/links/")).toBe("https://whois.example/links");
    expect(normalizeHref("https://whois.example/?utm=1")).toBe("https://whois.example");
  });

  it("returns empty for non-http protocols", () => {
    expect(normalizeHref("javascript:alert(1)")).toBe("");
    expect(normalizeHref("ftp://whois.example")).toBe("");
  });
});

describe("hostToken", () => {
  it("normalizes case and www for hostname matching", () => {
    expect(hostToken("www.Whois.Example")).toBe("whois.example");
    expect(hostToken("whois.example.")).toBe("whois.example");
  });
});

describe("matchesSiteIdentity", () => {
  it("matches an exact href to our site", () => {
    const html = `<a href="https://whois.example">Our site</a>`;
    expect(matchesSiteIdentity(html, IDENTITY).found).toBe(true);
  });

  it("matches a www-variant href", () => {
    const html = `<a href="http://www.whois.example">About</a>`;
    expect(matchesSiteIdentity(html, IDENTITY).found).toBe(true);
  });

  it("matches by anchor text equal to the site label", () => {
    const html = `<a href="https://redirect.example">DomainPulse</a>`;
    expect(matchesSiteIdentity(html, IDENTITY).found).toBe(true);
  });

  it("matches via site-label mentioned anywhere in the body", () => {
    const html = `<div>Powered by DomainPulse for whois lookups</div>`;
    expect(matchesSiteIdentity(html, IDENTITY).found).toBe(true);
  });

  it("treats too-short pages as empty (no match)", () => {
    expect(matchesSiteIdentity("<p>ok</p>", IDENTITY).found).toBe(false);
  });

  it("returns false when nothing matches", () => {
    const html = `<html><body><a href="https://other.example">Home</a><p>another blog</p></body></html>`;
    expect(matchesSiteIdentity(html, IDENTITY).found).toBe(false);
  });
});