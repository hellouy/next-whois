import { describe, it, expect } from "vitest";
import { classifyFailure, isFailureReason, FAILURE_REASONS } from "./classify-failure";

describe("classifyFailure", () => {
  it("passes through already-normalized enum reasons", () => {
    for (const r of FAILURE_REASONS) {
      expect(classifyFailure("anything", r)).toBe(r);
    }
  });

  it("maps legacy reason strings to the new enum", () => {
    expect(classifyFailure("x", "timeout")).toBe("connect_timeout");
    expect(classifyFailure("x", "no_server")).toBe("no_server");
    expect(classifyFailure("x", "parse_error")).toBe("parse_error");
    expect(classifyFailure("x", "rate_limited")).toBe("rate_limited");
    expect(classifyFailure("x", "iana_fallback")).toBe("iana_fallback");
  });

  it("classifies connect timeouts by message", () => {
    expect(classifyFailure("connect ETIMEDOUT 1.2.3.4:43")).toBe("connect_timeout");
    expect(classifyFailure("request timed out after 3000ms")).toBe("connect_timeout");
  });

  it("classifies dns failures", () => {
    expect(classifyFailure("getaddrinfo ENOTFOUND whois.none.example")).toBe("dns_failure");
    expect(classifyFailure("querySrv ENOTFOUND")).toBe("dns_failure");
    expect(classifyFailure("DNS request timed out")).toBe("dns_failure");
  });

  it("classifies socket errors", () => {
    expect(classifyFailure("connect ECONNREFUSED at 10.0.0.1:43")).toBe("socket_error");
    expect(classifyFailure("socket hang up")).toBe("socket_error");
    expect(classifyFailure("read ECONNRESET")).toBe("socket_error");
  });

  it("classifies http blockers, missing and server errors", () => {
    expect(classifyFailure("Error: 403 Forbidden")).toBe("http_blocked");
    expect(classifyFailure("Access denied by Cloudflare")).toBe("http_blocked");
    expect(classifyFailure("404 Not Found")).toBe("http_not_found");
    expect(classifyFailure("503 Service Unavailable")).toBe("http_server_error");
    expect(classifyFailure("Response status 500")).toBe("http_server_error");
  });

  it("classifies empty and parse errors", () => {
    expect(classifyFailure("Empty WHOIS response")).toBe("empty_response");
    expect(classifyFailure("no content returned")).toBe("empty_response");
    expect(classifyFailure("Failed to parse response")).toBe("parse_error");
    expect(classifyFailure("unrecognized field structure")).toBe("parse_error");
  });

  it("classifies rate limits", () => {
    expect(classifyFailure("too many requests (429)")).toBe("rate_limited");
  });

  it("returns unknown for unmatched messages and empty input", () => {
    expect(classifyFailure("gibberish that matches nothing")).toBe("unknown");
    expect(classifyFailure(undefined)).toBe("unknown");
    expect(classifyFailure("")).toBe("unknown");
  });
});

describe("isFailureReason", () => {
  it("accepts enum values and rejects junk", () => {
    expect(isFailureReason("connect_timeout")).toBe(true);
    expect(isFailureReason("timeout")).toBe(false);
    expect(isFailureReason("")).toBe(false);
  });
});