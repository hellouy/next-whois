import { describe, it, expect, vi } from "vitest";
import { candidateUrls, isPrivateAddr } from "./backlink-check";

vi.mock("@/lib/email", () => ({ getSiteLabel: async () => "DomainPulse" }));
vi.mock("./site-identity", async () => {
  const actual = await vi.importActual<typeof import("./site-identity")>("./site-identity");
  return {
    ...actual,
    resolveSiteIdentity: async () => ({
      url: "https://whois.example",
      hostname: "whois.example",
      label: "DomainPulse",
    }),
  };
});

describe("candidateUrls", () => {
  it("builds homepage plus common friend-link paths", () => {
    const urls = candidateUrls("https://blog.example");
    expect(urls).toContain("https://blog.example/");
    expect(urls).toContain("https://blog.example/links");
    expect(urls).toContain("https://blog.example/friends");
    expect(urls).toContain("https://blog.example/friend");
    expect(urls).toContain("https://blog.example/link");
  });

  it("prefixes protocol when missing", () => {
    const urls = candidateUrls("blog.example");
    expect(urls[0]?.startsWith("https://blog.example")).toBe(true);
    expect(urls).toContain("https://blog.example/");
  });

  it("returns empty for unparseable input", () => {
    expect(candidateUrls("")).toEqual([]);
  });
});

describe("isPrivateAddr", () => {
  it("flags loopback and private ranges", () => {
    expect(isPrivateAddr("127.0.0.1")).toBe(true);
    expect(isPrivateAddr("::1")).toBe(true);
    expect(isPrivateAddr("10.0.0.5")).toBe(true);
    expect(isPrivateAddr("192.168.1.1")).toBe(true);
    expect(isPrivateAddr("172.16.0.1")).toBe(true);
    expect(isPrivateAddr("169.254.169.254")).toBe(true);
    expect(isPrivateAddr("100.64.0.1")).toBe(true);
  });

  it("accepts public addresses", () => {
    expect(isPrivateAddr("8.8.8.8")).toBe(false);
    expect(isPrivateAddr("1.1.1.1")).toBe(false);
  });
});