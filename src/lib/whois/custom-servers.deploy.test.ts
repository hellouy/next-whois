import { describe, it, expect, vi } from "vitest";

vi.mock("fs", () => ({
  readFileSync: () => {
    throw new Error("ENOENT: no such file — deployment environment");
  },
}));

/**
 * Deployment-scenario test: on serverless/deploy environments the file
 * src/data/whois-servers.json is not present on disk.  The bundled JSON
 * import (via readWhoisServers' catch path) must still resolve ccTLD
 * servers, otherwise every ccTLD falls through to IANA TCP discovery.
 */
describe("custom-servers deployment resilience", () => {
  it("resolves static ccTLD servers when the JSON file is absent from disk", async () => {
    const { getStaticWhoisServer: s } = await import("./custom-servers");
    expect(s("ac")).toBe("whois.nic.ac");
    expect(s("ae")).toBe("whois.aeda.net.ae");
    expect(s("at")).toBe("whois.nic.at");
  });

  it("still returns null for explicitly-null entries when file is absent", async () => {
    const { getStaticWhoisServer: s } = await import("./custom-servers");
    expect(s("ads")).toBeNull();
    expect(s("al")).toBeNull();
    expect(s("aq")).toBeNull();
  });

  it("falls back to gTLD bootstrap for TLDs not in the ccTLD file", async () => {
    const { getStaticWhoisServer: s } = await import("./custom-servers");
    expect(s("com")).toBeTypeOf("string");
  });
});
