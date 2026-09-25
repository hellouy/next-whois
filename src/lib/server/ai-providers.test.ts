import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@/lib/db-query", () => ({
  run: vi.fn().mockResolvedValue(1),
  one: vi.fn(),
  many: vi.fn(),
}));

import { many, run } from "@/lib/db-query";
const mockMany = many as unknown as ReturnType<typeof vi.fn>;
const mockRun = run as unknown as ReturnType<typeof vi.fn>;

const OK_RESPONSE = {
  ok: true,
  status: 200,
  text: async () => "",
  json: async () => ({ choices: [{ message: { content: "hello" } }] }),
} as unknown as Response;

/** Fresh module instance per test so the in-memory circuit map starts clean. */
async function loadProviders() {
  vi.resetModules();
  return import("./ai-providers");
}

describe("callProviderWithFallback circuit breaker (R10)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockMany.mockResolvedValue([{ key: "api_ai_zhipu_key", value: "sk-test" }]);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("opens all providers after repeated failures and fails fast", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("boom")));
    const { callProviderWithFallback, getCircuitStates } = await loadProviders();

    for (let i = 0; i < 3; i++) {
      await expect(callProviderWithFallback([{ role: "user", content: "x" }])).rejects.toThrow();
    }
    const states = getCircuitStates();
    expect(states.length).toBeGreaterThan(0);
    for (const s of states) expect(s.state).toBe("open");

    await expect(
      callProviderWithFallback([{ role: "user", content: "x" }]),
    ).rejects.toThrow(/均已熔断/);
  });

  it("allows a single half-open probe after cooldown and re-closes on success", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("boom"));
    vi.stubGlobal("fetch", fetchMock);
    const { callProviderWithFallback, getCircuitStates } = await loadProviders();

    for (let i = 0; i < 3; i++) {
      await expect(callProviderWithFallback([{ role: "user", content: "x" }])).rejects.toThrow();
    }
    expect(getCircuitStates().every(s => s.state === "open")).toBe(true);

    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 11 * 60 * 1000);
    fetchMock.mockResolvedValue(OK_RESPONSE);
    try {
      const { content } = await callProviderWithFallback([{ role: "user", content: "x" }]);
      expect(content).toBe("hello");
    } finally {
      vi.useRealTimers();
    }

    const states = getCircuitStates();
    const probed = states.find(s => s.state === "closed");
    expect(probed).toBeTruthy();
  });

  it("resets failure count on a successful call before tripping", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("boom"));
    vi.stubGlobal("fetch", fetchMock);
    const { callProviderWithFallback, getCircuitStates } = await loadProviders();

    await expect(callProviderWithFallback([{ role: "user", content: "x" }])).rejects.toThrow();

    fetchMock.mockResolvedValue(OK_RESPONSE);
    const { content } = await callProviderWithFallback([{ role: "user", content: "x" }]);
    expect(content).toBe("hello");

    const states = getCircuitStates();
    for (const s of states) expect(s.state).toBe("closed");
    // Only the top-priority provider is probed on the success call; the
    // lower-priority ones keep their single recorded failure (below threshold).
    const top = states.find(s => s.id === "glm4flashx");
    expect(top?.consecutiveFails).toBe(0);
  });

  it("audits circuit transitions + calls to ai_call_log (R11)", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("boom"));
    vi.stubGlobal("fetch", fetchMock);
    const { callProviderWithFallback } = await loadProviders();

    for (let i = 0; i < 3; i++) {
      await expect(callProviderWithFallback(
        [{ role: "user", content: "x" }],
        undefined,
        [],
        { kind: "tld_extract", tld: "com" as string },
      )).rejects.toThrow();
    }

    const inserts = mockRun.mock.calls.filter(([sql]) => String(sql).includes("ai_call_log"));
    expect(inserts.length).toBeGreaterThanOrEqual(3);
    // writeAiLog params: (provider, model, kind, tld, ok, ms, error) → kind is index 2
    expect(inserts.some(([, params]) => Array.isArray(params) && params[2] === "tld_extract")).toBe(true);
  });
});