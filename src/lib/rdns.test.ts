import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import dns from "dns/promises";
import { checkRdns } from "./rdns";

let resolvePtrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  resolvePtrSpy = vi.spyOn(dns.Resolver.prototype, "resolvePtr");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("checkRdns", () => {
  it("returns consistent hostnames", async () => {
    resolvePtrSpy.mockImplementation(() => Promise.resolve(["host.example.com"]));
    const r = await checkRdns("1.2.3.4");
    expect(r.records.length).toBe(2);
    expect(r.consistent).toBe(true);
    expect(r.records.every(x => x.hostname === "host.example.com")).toBe(true);
  });

  it("marks inconsistency when hostnames differ", async () => {
    resolvePtrSpy
      .mockImplementationOnce(() => Promise.resolve(["a.example.com"]))
      .mockImplementationOnce(() => Promise.resolve(["b.example.com"]));
    const r = await checkRdns("1.2.3.4");
    expect(r.consistent).toBe(false);
  });

  it("treats failures as null hostname", async () => {
    resolvePtrSpy.mockImplementation(() => Promise.reject(new Error("ENOTFOUND")));
    const r = await checkRdns("1.2.3.4");
    expect(r.records.every(x => x.hostname === null)).toBe(true);
    expect(r.consistent).toBe(true);
  });
});
