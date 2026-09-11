import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchCtLogs } from "./ct-crt-sh";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchCtLogs", () => {
  it("skips IP addresses", async () => {
    const r = await fetchCtLogs("8.8.8.8");
    expect(r.available).toBe(false);
  });

  it("skips IPv6 addresses", async () => {
    const r = await fetchCtLogs("2606:4700:4700::1111");
    expect(r.available).toBe(false);
  });

  it("deduplicates by id and caps at 50", async () => {
    const data = Array.from({ length: 60 }, (_, i) => ({
      id: i % 5 + 1,
      name_value: `x${i}.example.com`,
      not_before: "2024-01-01",
      not_after: "2025-01-01",
    }));
    vi.stubGlobal("fetch", vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve(data) })
    ));
    const r = await fetchCtLogs("example.com");
    expect(r.available).toBe(true);
    expect(r.entries!.length).toBe(5);
    expect(r.total).toBe(60);
  });

  it("returns unavailable on HTTP error", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: false, status: 500 })));
    const r = await fetchCtLogs("example.com");
    expect(r.available).toBe(false);
  });

  it("returns unavailable on network error", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("ECONNRESET"))));
    const r = await fetchCtLogs("example.com");
    expect(r.available).toBe(false);
  });

  it("returns unavailable on non-array JSON", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({ foo: 1 }) })));
    const r = await fetchCtLogs("example.com");
    expect(r.available).toBe(false);
  });
});
