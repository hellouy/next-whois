import { describe, it, expect, vi, beforeEach } from "vitest";
import dns from "dns/promises";
import { reverseIpv4, classifyReturnCode, checkDnsbl, DNSBL_ZONES } from "./dnsbl";

vi.mock("dns/promises", () => ({
  default: {
    resolve4: vi.fn(),
    Resolver: vi.fn(),
  },
}));

const mockDns = dns as unknown as {
  resolve4: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("reverseIpv4", () => {
  it("reverses octets", () => {
    expect(reverseIpv4("1.2.3.4")).toBe("4.3.2.1");
  });
});

describe("classifyReturnCode", () => {
  it("maps known codes", () => {
    expect(classifyReturnCode("127.0.0.2")).toBe("spam");
    expect(classifyReturnCode("127.0.0.3")).toBe("zombie");
    expect(classifyReturnCode("127.0.0.4")).toBe("open_proxy");
    expect(classifyReturnCode("127.0.0.10")).toBe("dynamic");
  });
  it("returns null for unknown codes", () => {
    expect(classifyReturnCode("127.0.0.99")).toBeNull();
  });
});

describe("checkDnsbl", () => {
  it("marks listed zones with a return code", async () => {
    mockDns.resolve4.mockImplementation((hostname: string) => {
      if (hostname.startsWith("4.3.2.1.zen.spamhaus.org")) {
        return Promise.resolve([{ address: "127.0.0.2", ttl: 60 }]);
      }
      const e = new Error("ENOTFOUND") as NodeJS.ErrnoException;
      e.code = "ENOTFOUND";
      return Promise.reject(e);
    });
    const results = await checkDnsbl("1.2.3.4");
    expect(results.find(r => r.zone === "zen.spamhaus.org")?.listed).toBe(true);
    expect(results.find(r => r.zone === "zen.spamhaus.org")?.returnCode).toBe("127.0.0.2");
    expect(results.find(r => r.zone === "zen.spamhaus.org")?.type).toBe("spam");
    expect(results.filter(r => r.listed).length).toBe(1);
  });

  it("marks unlisted zones as not listed", async () => {
    mockDns.resolve4.mockImplementation(() => {
      const e = new Error("ENOTFOUND") as NodeJS.ErrnoException;
      e.code = "ENOTFOUND";
      return Promise.reject(e);
    });
    const results = await checkDnsbl("1.2.3.4");
    expect(results.length).toBe(DNSBL_ZONES.length);
    expect(results.every(r => !r.listed)).toBe(true);
  });

  it("handles timeouts as not listed", async () => {
    mockDns.resolve4.mockImplementation(() => Promise.reject(Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" })));
    const results = await checkDnsbl("1.2.3.4");
    expect(results.every(r => !r.listed)).toBe(true);
  });
});
