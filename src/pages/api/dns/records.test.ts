import { describe, it, expect } from "vitest";
import { computePropagation } from "./records";

describe("computePropagation", () => {
  const resolvers = [
    { name: "Google DoH", flat: ["1.2.3.4", "1.2.3.5"] },
    { name: "Cloudflare DoH", flat: ["1.2.3.4", "1.2.3.5"] },
    { name: "Quad9 DoH", flat: ["1.2.3.4", "1.2.3.5"] },
    { name: "AdGuard DoH", flat: ["1.2.3.4", "1.2.3.5"] },
  ];

  it("reports consistent when all healthy resolvers match the merged set", () => {
    const p = computePropagation(resolvers, ["1.2.3.4", "1.2.3.5"]);
    expect(p.consistent).toBe(true);
    expect(p.differing).toHaveLength(0);
  });

  it("flags a resolver missing a record from the merged set", () => {
    const merged = ["1.2.3.4", "1.2.3.5"];
    const res = [...resolvers];
    res[1] = { name: "Cloudflare DoH", flat: ["1.2.3.4"] };
    const p = computePropagation(res, merged);
    expect(p.consistent).toBe(false);
    expect(p.differing).toHaveLength(1);
    expect(p.differing[0].resolver).toBe("Cloudflare DoH");
    expect(p.differing[0].missing).toEqual(["1.2.3.5"]);
    expect(p.differing[0].extra).toEqual([]);
  });

  it("flags a resolver with extra records not present in the merged set", () => {
    const res = [...resolvers];
    res[2] = { name: "Quad9 DoH", flat: ["1.2.3.4", "1.2.3.5", "9.9.9.9"] };
    const p = computePropagation(res, ["1.2.3.4", "1.2.3.5"]);
    expect(p.consistent).toBe(false);
    expect(p.differing).toHaveLength(1);
    expect(p.differing[0].resolver).toBe("Quad9 DoH");
    expect(p.differing[0].missing).toEqual([]);
    expect(p.differing[0].extra).toEqual(["9.9.9.9"]);
  });

  it("ignores resolvers with errors and empty record sets", () => {
    const res = [
      { name: "Google DoH", flat: ["1.2.3.4"], error: "timeout" },
      { name: "Cloudflare DoH", flat: [] },
      { name: "Quad9 DoH", flat: ["1.2.3.4"] },
    ];
    const p = computePropagation(res as any, ["1.2.3.4"]);
    expect(p.consistent).toBe(true);
    expect(p.differing).toHaveLength(0);
  });

  it("reports consistent when no healthy resolver has records", () => {
    const p = computePropagation([{ name: "Google DoH", flat: [], error: "timeout" }], []);
    expect(p.consistent).toBe(true);
    expect(p.differing).toHaveLength(0);
  });

  it("handles multiple differing resolvers independently", () => {
    const res = [
      { name: "Google DoH", flat: ["a", "b"] },
      { name: "Cloudflare DoH", flat: ["a"] },
      { name: "Quad9 DoH", flat: ["b"] },
    ];
    const p = computePropagation(res, ["a", "b"]);
    expect(p.consistent).toBe(false);
    expect(p.differing).toHaveLength(2);
    expect(p.differing.map(d => d.resolver).sort()).toEqual(["Cloudflare DoH", "Quad9 DoH"]);
  });
});
