import { describe, it, expect } from "vitest";
import { normalizeDomainPart, parseDomainParts, buildDomainMatrix } from "./batch-domain-matrix";

describe("normalizeDomainPart", () => {
  it("lowercases and strips surrounding dots", () => {
    expect(normalizeDomainPart("  .Example.  ")).toBe("example");
    expect(normalizeDomainPart("COM.")).toBe("com");
  });

  it("removes inner whitespace", () => {
    expect(normalizeDomainPart(" my prefix ")).toBe("myprefix");
  });

  it("returns empty for blank input", () => {
    expect(normalizeDomainPart("   ")).toBe("");
  });
});

describe("parseDomainParts", () => {
  it("splits on commas, CJK commas, and whitespace", () => {
    expect(parseDomainParts("ai,  app,dev\nio")).toEqual(["ai", "app", "dev", "io"]);
    expect(parseDomainParts("ai，io，net")).toEqual(["ai", "io", "net"]);
  });

  it("normalizes, strips dots, and de-duplicates", () => {
    expect(parseDomainParts(".COM, com, .CoM")).toEqual(["com"]);
  });

  it("returns [] for empty input", () => {
    expect(parseDomainParts("")).toEqual([]);
    expect(parseDomainParts("   ,,  ")).toEqual([]);
  });
});

describe("buildDomainMatrix", () => {
  it("builds the cartesian product", () => {
    expect(buildDomainMatrix(["ai", "app"], ["com", "io"])).toEqual([
      "ai.com", "ai.io", "app.com", "app.io",
    ]);
  });

  it("normalizes and de-duplicates both axes", () => {
    expect(buildDomainMatrix([".AI", "ai"], ["COM.", "com", "io"])).toEqual([
      "ai.com", "ai.io",
    ]);
  });

  it("returns [] when either axis is empty", () => {
    expect(buildDomainMatrix([], ["com"])).toEqual([]);
    expect(buildDomainMatrix(["ai"], [])).toEqual([]);
  });

  it("returns a stable sort", () => {
    expect(buildDomainMatrix(["b", "a"], ["net", "com"])).toEqual([
      "a.com", "a.net", "b.com", "b.net",
    ]);
  });
});
