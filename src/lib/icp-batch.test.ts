import { describe, it, expect } from "vitest";
import { splitSearchTerms, countBatchFailed, ICP_BATCH_MAX, ICP_BATCH_CONCURRENCY } from "./icp-batch";

describe("splitSearchTerms", () => {
  it("splits comma-separated terms", () => {
    expect(splitSearchTerms("a.com,b.com,c.com")).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("splits by comma, newline and whitespace", () => {
    expect(splitSearchTerms("a.com\n b.com ,c.com")).toEqual(["a.com", "b.com", "c.com"]);
  });

  it("supports full-width comma", () => {
    expect(splitSearchTerms("a.com，b.com")).toEqual(["a.com", "b.com"]);
  });

  it("dedupes repeated terms", () => {
    expect(splitSearchTerms("a.com,a.com,b.com")).toEqual(["a.com", "b.com"]);
  });

  it("returns empty array for empty input", () => {
    expect(splitSearchTerms("")).toEqual([]);
    expect(splitSearchTerms("   , \n ")).toEqual([]);
  });

  it("caps at ICP_BATCH_MAX", () => {
    const terms = Array.from({ length: ICP_BATCH_MAX + 5 }, (_, i) => `d${i}.com`).join(",");
    expect(splitSearchTerms(terms)).toHaveLength(ICP_BATCH_MAX);
  });
});

describe("countBatchFailed", () => {
  it("counts non-ok items", () => {
    expect(countBatchFailed([{ ok: true }, { ok: false }, { ok: false }])).toBe(2);
  });

  it("returns 0 when all succeed", () => {
    expect(countBatchFailed([{ ok: true }, { ok: true }])).toBe(0);
  });

  it("returns 0 for empty list", () => {
    expect(countBatchFailed([])).toBe(0);
  });
});

describe("constants", () => {
  it("defines concurrency of 3", () => {
    expect(ICP_BATCH_CONCURRENCY).toBe(3);
  });
});
