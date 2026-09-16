import { describe, it, expect } from "vitest";
import { decodePunycodeLabel, tldToUnicode } from "./punycode";

describe("decodePunycodeLabel", () => {
  it("decodes extended-only labels (IDN TLDs)", () => {
    expect(decodePunycodeLabel("fiqs8s")).toBe("中国");
    expect(decodePunycodeLabel("55qx5d")).toBe("公司");
    expect(decodePunycodeLabel("io0a7i")).toBe("网络");
    expect(decodePunycodeLabel("ses554g")).toBe("网址");
    expect(decodePunycodeLabel("3bst00m")).toBe("集团");
    expect(decodePunycodeLabel("p1acf")).toBe("рус");
  });

  it("decodes labels that mix basic and extended code points (RFC 3492 example)", () => {
    expect(decodePunycodeLabel("bcher-kva")).toBe("bücher");
  });

  it("returns null on malformed input instead of guessing", () => {
    expect(decodePunycodeLabel("")).toBeNull();
    expect(decodePunycodeLabel("fiq$8s")).toBeNull(); // invalid character
    expect(decodePunycodeLabel("BCHER-KVA")).toBeNull(); // uppercase not accepted
    expect(decodePunycodeLabel("aa")).toBeNull(); // decodes to control chars — rejected
    expect(decodePunycodeLabel("fiqs8")).toBeNull(); // truncated — runs off the end mid-loop
  });
});

describe("tldToUnicode", () => {
  it("passes ASCII TLDs through unchanged", () => {
    expect(tldToUnicode("com")).toBe("com");
    expect(tldToUnicode("uk")).toBe("uk");
  });

  it("decodes IDN TLD labels", () => {
    expect(tldToUnicode("xn--fiqs8s")).toBe("中国");
    expect(tldToUnicode("xn--p1acf")).toBe("рус");
  });

  it("falls back to the punycode label when decoding fails", () => {
    expect(tldToUnicode("xn--")).toBe("xn--");
    expect(tldToUnicode("xn--!!!")).toBe("xn--!!!");
  });
});
