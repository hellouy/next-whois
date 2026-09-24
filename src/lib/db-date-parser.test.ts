import { describe, it, expect } from "vitest";
import { types } from "pg";
import "@/lib/db";

describe("db DATE type parser", () => {
  it("returns DATE columns as plain YYYY-MM-DD strings", () => {
    const parse = types.getTypeParser(1082);
    expect(parse("2026-09-06")).toBe("2026-09-06");
    expect(typeof parse("2026-09-06")).toBe("string");
  });

  it("does not turn a DATE into a JS Date object", () => {
    const parse = types.getTypeParser(1082);
    // A JS Date would stringify to an English GMT string — the bug we fixed.
    expect(String(parse("2026-09-06"))).not.toContain("GMT");
  });
});
