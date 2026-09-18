import { describe, it, expect } from "vitest";
import { isPrivateHost } from "./ssrf-guard";

describe("isPrivateHost", () => {
  it("blocks RFC1918 private ranges", () => {
    expect(isPrivateHost("10.0.0.1")).toBe(true);
    expect(isPrivateHost("172.16.0.1")).toBe(true);
    expect(isPrivateHost("192.168.1.1")).toBe(true);
  });

  it("blocks loopback and link-local", () => {
    expect(isPrivateHost("127.0.0.1")).toBe(true);
    expect(isPrivateHost("169.254.1.1")).toBe(true);
    expect(isPrivateHost("::1")).toBe(true);
  });

  it("blocks CGNAT and TEST-NET ranges", () => {
    expect(isPrivateHost("100.64.0.1")).toBe(true);
    expect(isPrivateHost("192.0.2.1")).toBe(true);
    expect(isPrivateHost("203.0.113.1")).toBe(true);
  });

  it("does NOT block IANA infrastructure 192.0.32.0/24", () => {
    expect(isPrivateHost("192.0.32.59")).toBe(false);
  });

  it("does NOT block other public addresses", () => {
    expect(isPrivateHost("8.8.8.8")).toBe(false);
    expect(isPrivateHost("1.1.1.1")).toBe(false);
    expect(isPrivateHost("whois.iana.org")).toBe(false);
  });

  it("blocks 192.0.0.0/24 but not 192.0.32.0/24", () => {
    expect(isPrivateHost("192.0.0.1")).toBe(true);
    expect(isPrivateHost("192.0.1.1")).toBe(false);
    expect(isPrivateHost("192.0.32.59")).toBe(false);
  });
});
