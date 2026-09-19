import { describe, it, expect } from "vitest";
import {
  isCommentLine,
  splitWhoisLine,
  stripNetworkPrefix,
} from "./line-tokenizer";

describe("isCommentLine", () => {
  it("flags % and # comment lines", () => {
    expect(isCommentLine("% IANA WHOIS server")).toBe(true);
    expect(isCommentLine("# hash comment")).toBe(true);
  });

  it("tolerates leading whitespace", () => {
    expect(isCommentLine("  % indented comment")).toBe(true);
  });

  it("rejects data lines and blanks", () => {
    expect(isCommentLine("Domain Name: example.com")).toBe(false);
    expect(isCommentLine("")).toBe(false);
    expect(isCommentLine("   ")).toBe(false);
  });
});

describe("splitWhoisLine", () => {
  it("splits on the first colon", () => {
    expect(splitWhoisLine("Key: value")).toEqual({
      key: "Key",
      value: "value",
    });
  });

  it("trims surrounding whitespace from key and value", () => {
    expect(splitWhoisLine("  NetName :  GOOGLE  ")).toEqual({
      key: "NetName",
      value: "GOOGLE",
    });
  });

  it("preserves extra colons inside the value", () => {
    expect(splitWhoisLine("Key: a:b:c")).toEqual({
      key: "Key",
      value: "a:b:c",
    });
  });

  it("returns null for blank lines and lines without a colon", () => {
    expect(splitWhoisLine("")).toBeNull();
    expect(splitWhoisLine("   ")).toBeNull();
    expect(splitWhoisLine("free text")).toBeNull();
  });

  it("returns null when key or value is empty", () => {
    expect(splitWhoisLine(": value")).toBeNull();
    expect(splitWhoisLine("Key:")).toBeNull();
    expect(splitWhoisLine("Key:   ")).toBeNull();
  });
});

describe("stripNetworkPrefix", () => {
  it("strips a leading Network: label from multi-colon lines", () => {
    expect(
      stripNetworkPrefix("Network: Class C: 192.0.2.0 - 192.0.2.255"),
    ).toBe(" Class C: 192.0.2.0 - 192.0.2.255");
  });

  it("matches the network label case-insensitively", () => {
    expect(stripNetworkPrefix("network: Class C: 192.0.2.0")).toBe(
      " Class C: 192.0.2.0",
    );
  });

  it("leaves single-colon Network lines untouched", () => {
    expect(stripNetworkPrefix("Network: 192.0.2.0")).toBe("Network: 192.0.2.0");
  });

  it("leaves unrelated lines untouched", () => {
    expect(stripNetworkPrefix("OrgName: Example Corp")).toBe(
      "OrgName: Example Corp",
    );
    expect(stripNetworkPrefix("NetName: GOOGLE")).toBe("NetName: GOOGLE");
  });

  it("combines with splitWhoisLine to drop the Network token entirely", () => {
    const pair = splitWhoisLine(
      stripNetworkPrefix("Network: Class C: 192.0.2.0"),
    );
    expect(pair).toEqual({ key: "Class C", value: "192.0.2.0" });
  });
});
