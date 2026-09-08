import { describe, it, expect } from "vitest";
import { classifyQueryOutcome } from "./whois-patterns";

describe("classifyQueryOutcome", () => {
  it("marks successful queries as registered", () => {
    expect(classifyQueryOutcome(true)).toBe("registered");
    expect(classifyQueryOutcome(true, undefined)).toBe("registered");
    expect(classifyQueryOutcome(true, "Domain not found")).toBe("registered");
  });

  it("marks not-registered responses as unregistered", () => {
    expect(classifyQueryOutcome(false, "No match for \"EXAMPLE.COM\".")).toBe("unregistered");
    expect(classifyQueryOutcome(false, "Domain not found")).toBe("unregistered");
    expect(classifyQueryOutcome(false, "%% NOT FOUND")).toBe("unregistered");
    expect(classifyQueryOutcome(false, "No Data Found")).toBe("unregistered");
  });

  it("marks invalid TLD input as invalid", () => {
    expect(classifyQueryOutcome(false, "Invalid TLD \"s\"")).toBe("invalid");
    expect(classifyQueryOutcome(false, "not a valid TLD: .k")).toBe("invalid");
  });

  it("marks real infrastructure failures as error", () => {
    expect(classifyQueryOutcome(false, "WHOIS/RDAP not available for this TLD")).toBe("error");
    expect(classifyQueryOutcome(false, "Empty WHOIS response")).toBe("error");
    expect(classifyQueryOutcome(false, "connect ETIMEDOUT 1.2.3.4:43")).toBe("error");
    expect(classifyQueryOutcome(false, "too many requests (429)")).toBe("error");
    expect(classifyQueryOutcome(false, undefined)).toBe("error");
    expect(classifyQueryOutcome(false, "")).toBe("error");
  });
});
