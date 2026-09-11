import { describe, it, expect } from "vitest";
import {
  computeTiming,
  parseCookieHeader,
  analyzeCookie,
  computeCookieRating,
  type HttpTimingMarks,
} from "./http-timing";

describe("computeTiming", () => {
  const base: HttpTimingMarks = {
    start: 1000,
    dnsEnd: 1010,
    connectEnd: 1020,
    tlsEnd: 1030,
    headersEnd: 1060,
    end: 1100,
  };

  it("maps full timings correctly", () => {
    const t = computeTiming(base);
    expect(t.dnsMs).toBe(10);
    expect(t.connectMs).toBe(10);
    expect(t.tlsMs).toBe(10);
    expect(t.ttfbMs).toBe(60);
    expect(t.totalMs).toBe(100);
  });

  it("handles plain HTTP (no tls mark)", () => {
    const t = computeTiming({ ...base, tlsEnd: null });
    expect(t.tlsMs).toBeNull();
    expect(t.connectMs).toBe(10);
    expect(t.ttfbMs).toBe(60);
  });

  it("handles missing dns mark", () => {
    const t = computeTiming({ ...base, dnsEnd: null });
    expect(t.dnsMs).toBeNull();
    expect(t.connectMs).toBe(20);
  });

  it("handles null headersEnd by falling back to end", () => {
    const t = computeTiming({ ...base, headersEnd: null });
    expect(t.ttfbMs).toBe(100);
  });

  it("handles all-null timing marks", () => {
    const t = computeTiming({ start: 5, dnsEnd: null, connectEnd: null, tlsEnd: null, headersEnd: null, end: 5 });
    expect(t.dnsMs).toBeNull();
    expect(t.connectMs).toBeNull();
    expect(t.tlsMs).toBeNull();
    expect(t.ttfbMs).toBe(0);
    expect(t.totalMs).toBe(0);
  });
});

describe("parseCookieHeader", () => {
  it("parses full attributes", () => {
    const c = parseCookieHeader("sid=abc; Domain=example.com; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax");
    expect(c.name).toBe("sid");
    expect(c.domain).toBe("example.com");
    expect(c.path).toBe("/");
    expect(c.expires).toBe("Wed, 21 Oct 2026 07:28:00 GMT");
    expect(c.secure).toBe(true);
    expect(c.httpOnly).toBe(true);
    expect(c.sameSite).toBe("lax");
  });

  it("parses bare cookie", () => {
    const c = parseCookieHeader("tracking=1");
    expect(c.name).toBe("tracking");
    expect(c.secure).toBe(false);
    expect(c.httpOnly).toBe(false);
    expect(c.sameSite).toBeNull();
  });

  it("handles empty value", () => {
    const c = parseCookieHeader("");
    expect(c.name).toBe("");
  });
});

describe("analyzeCookie", () => {
  it("flags missing secure, httponly and samesite", () => {
    const issues = analyzeCookie(parseCookieHeader("a=1")).issues;
    expect(issues).toContain("no_secure");
    expect(issues).toContain("no_httponly");
    expect(issues).toContain("no_samesite");
  });

  it("keeps no issues for fully hardened cookie", () => {
    const issues = analyzeCookie(parseCookieHeader("a=1; Secure; HttpOnly; SameSite=Strict")).issues;
    expect(issues).toHaveLength(0);
  });
});

describe("computeCookieRating", () => {
  it("rates secure when all cookies hardened", () => {
    const c = analyzeCookie(parseCookieHeader("a=1; Secure; HttpOnly; SameSite=Strict"));
    expect(computeCookieRating([c])).toBe("secure");
  });

  it("rates needs_attention when missing one attribute", () => {
    const c = analyzeCookie(parseCookieHeader("a=1; Secure; HttpOnly"));
    expect(computeCookieRating([c])).toBe("needs_attention");
  });

  it("rates insecure when missing secure and httponly", () => {
    const c = analyzeCookie(parseCookieHeader("a=1"));
    expect(computeCookieRating([c])).toBe("insecure");
  });

  it("returns secure for no cookies", () => {
    expect(computeCookieRating([])).toBe("secure");
  });
});
