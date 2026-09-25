import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fetchDsRecords } from "./dns-ds";

const makeResponse = (body: unknown, ok = true) =>
  ({ ok, status: ok ? 200 : 500, json: async () => body }) as unknown as Response;

describe("fetchDsRecords", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns deduplicated DS records on success", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockResolvedValueOnce(
        makeResponse({
          Status: 0,
          Answer: [
            { type: 43, data: "12345 8 2 AAAA" },
            { type: 43, data: "54321 13 4 BBBB" },
            { type: 43, data: "12345 8 2 AAAA" },
            { type: 1, data: "1.2.3.4" },
          ],
        }),
      );
    const records = await fetchDsRecords("example.com");
    expect(records).toEqual(["12345 8 2 AAAA", "54321 13 4 BBBB"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns [] on NXDOMAIN", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockResolvedValueOnce(makeResponse({ Status: 3 }));
    expect(await fetchDsRecords("example.com")).toEqual([]);
  });

  it("falls back to the next resolver when the first throws", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValueOnce(makeResponse({ Status: 0, Answer: [] }));
    expect(await fetchDsRecords("example.com")).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("returns [] when all resolvers fail and never throws", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockRejectedValue(new Error("boom"));
    await expect(fetchDsRecords("example.com")).resolves.toEqual([]);
  });

  it("returns [] for invalid names", async () => {
    expect(await fetchDsRecords("")).toEqual([]);
    expect(await fetchDsRecords("..bad..name..")).toEqual([]);
  });
});