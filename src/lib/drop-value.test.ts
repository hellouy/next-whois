import { describe, it, expect } from "vitest";
import {
  isDictionaryWord,
  splitPinyin,
  scoreDomainExtended,
  shouldAlertExtended,
  DEFAULT_VALUE_THRESHOLDS,
  type ValueContext,
} from "./drop-value";

const ctx: ValueContext = {
  hotPrefixes: new Map([
    ["ai", 30],
    ["pay", 26],
    ["cloud", 20],
  ]),
};

describe("isDictionaryWord", () => {
  it("matches complete dictionary words", () => {
    expect(isDictionaryWord("car")).toBe(true);
    expect(isDictionaryWord("book")).toBe(true);
    expect(isDictionaryWord("zzzz")).toBe(false);
  });
});

describe("splitPinyin", () => {
  it("splits two-syllable pinyin", () => {
    expect(splitPinyin("qiche")).toEqual(["qi", "che"]);
    expect(splitPinyin("yuming")).toEqual(["yu", "ming"]);
  });

  it("prefers the minimal-syllable split", () => {
    expect(splitPinyin("baidu")).toEqual(["bai", "du"]);
  });

  it("returns null for non-pinyin and non-letter input", () => {
    expect(splitPinyin("zzzq")).toBeNull();
    expect(splitPinyin("ab12")).toBeNull();
    expect(splitPinyin("a")).toBeNull();
  });
});

describe("scoreDomainExtended", () => {
  it("returns null for non-domain input", () => {
    expect(scoreDomainExtended("notadomain", ctx)).toBeNull();
    expect(scoreDomainExtended("", ctx)).toBeNull();
  });

  it("gives the top length tier to single characters", () => {
    const r = scoreDomainExtended("a.io", ctx)!;
    expect(r.isSingleChar).toBe(true);
    expect(r.breakdown.lengthScore).toBe(25);
    expect(r.reasons.join(" ")).toContain("单字符");
  });

  it("scores double characters highly", () => {
    const r = scoreDomainExtended("ab.io", ctx)!;
    expect(r.breakdown.lengthScore).toBe(23);
  });

  it("recognizes dictionary words", () => {
    const r = scoreDomainExtended("car.com", ctx)!;
    expect(r.isDictionaryWord).toBe(true);
    expect(r.breakdown.lexicalScore).toBeGreaterThanOrEqual(15);
  });

  it("recognizes shuangpin pinyin", () => {
    const r = scoreDomainExtended("qiche.com", ctx)!;
    expect(r.isPinyin).toBe(true);
    expect(r.breakdown.lexicalScore).toBeGreaterThan(0);
    expect(r.reasons.join(" ")).toContain("双拼");
  });

  it("rewards hot-prefix matches", () => {
    const hit = scoreDomainExtended("aihub.com", ctx)!;
    const miss = scoreDomainExtended("zzhub.com", ctx)!;
    expect(hit.breakdown.trendingScore).toBeGreaterThan(miss.breakdown.trendingScore);
  });

  it("rewards market data (BL/DP)", () => {
    const withBl = scoreDomainExtended("randomword.com", { ...ctx, bl: 250_000 })!;
    const without = scoreDomainExtended("randomword.com", ctx)!;
    expect(withBl.breakdown.marketScore).toBeGreaterThan(without.breakdown.marketScore);
  });

  it("penalizes hyphens in the pattern dimension", () => {
    const hyphen = scoreDomainExtended("my-shop.com", ctx)!;
    const plain = scoreDomainExtended("myshop.com", ctx)!;
    expect(hyphen.breakdown.patternScore).toBeLessThan(plain.breakdown.patternScore);
  });

  it("handles multi-part TLDs", () => {
    const r = scoreDomainExtended("car.com.cn", ctx)!;
    expect(r).not.toBeNull();
    expect(r.score).toBeGreaterThan(0);
  });

  it("keeps every dimension within bounds and total <= 100", () => {
    const samples = ["a.io", "ab.com", "car.com", "qiche.com", "aihub.com", "my-shop.com", "888.com", "randomword123.org"];
    for (const s of samples) {
      const r = scoreDomainExtended(s, { ...ctx, bl: 999_999, dp: 99_999 })!;
      expect(r).not.toBeNull();
      expect(r.score).toBeLessThanOrEqual(100);
      expect(r.breakdown.lengthScore).toBeLessThanOrEqual(25);
      expect(r.breakdown.tldScore).toBeLessThanOrEqual(15);
      expect(r.breakdown.lexicalScore).toBeLessThanOrEqual(20);
      expect(r.breakdown.trendingScore).toBeLessThanOrEqual(15);
      expect(r.breakdown.patternScore).toBeLessThanOrEqual(15);
      expect(r.breakdown.marketScore).toBeLessThanOrEqual(10);
    }
  });

  it("is deterministic for the same input", () => {
    const a = scoreDomainExtended("qiche.com", ctx)!;
    const b = scoreDomainExtended("qiche.com", ctx)!;
    expect(a).toEqual(b);
  });

  it("honours custom thresholds", () => {
    const r = scoreDomainExtended("car.com", ctx)!;
    const strict = scoreDomainExtended("car.com", ctx, { top: 10, high: 8, medium: 6, normal: 4 })!;
    expect(strict.tier).toBe("极高");
    expect(DEFAULT_VALUE_THRESHOLDS.top).toBe(78);
    expect(r.score).toBe(strict.score);
  });
});

describe("shouldAlertExtended", () => {
  it("alerts on alert keywords and high scores", () => {
    expect(shouldAlertExtended(scoreDomainExtended("a.io", ctx)!)).toBe(true);
    const high = scoreDomainExtended("car.com", { ...ctx, bl: 500_000 })!;
    expect(shouldAlertExtended(high)).toBe(high.score >= 68 || high.isAlertKeyword);
  });
});
