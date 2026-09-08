import { describe, it, expect } from "vitest";
import { humanizeLookupError } from "./error-messages";

describe("humanizeLookupError", () => {
  it("returns null for empty/unknown input", () => {
    expect(humanizeLookupError(null, true)).toBeNull();
    expect(humanizeLookupError(undefined, true)).toBeNull();
    expect(humanizeLookupError("gibberish that matches nothing", true)).toBeNull();
    expect(humanizeLookupError("", true)).toBeNull();
  });

  it("maps INVALID_DOMAIN_TLD marker", () => {
    expect(humanizeLookupError("INVALID_DOMAIN_TLD", true)).toContain("域名");
    expect(humanizeLookupError("INVALID_DOMAIN_TLD", false)).toContain("Invalid domain");
  });

  it("maps rate limits, timeouts and connectivity issues", () => {
    expect(humanizeLookupError("too many requests (429)", true)).toContain("限流");
    expect(humanizeLookupError("WHOIS server temporarily rate-limited this query", true)).toContain("限流");
    expect(humanizeLookupError("request timed out", true)).toContain("超时");
    expect(humanizeLookupError("connect ETIMEDOUT 1.2.3.4:43", true)).toContain("超时");
    expect(humanizeLookupError("getaddrinfo ENOTFOUND whois.example", true)).toContain("连接");
  });

  it("maps unsupported/empty/scraper errors", () => {
    expect(humanizeLookupError("No WHOIS/RDAP server available for this TLD", true)).toContain("不支持");
    expect(humanizeLookupError("Empty WHOIS response", true)).toContain("空响应");
    expect(humanizeLookupError("nic.gw scraper error: could not parse", true)).toContain("暂不支持");
  });

  it("localizes output", () => {
    const en = humanizeLookupError("request timed out", false);
    expect(en).toContain("timed out");
    expect(en).not.toContain("超时");
  });
});
