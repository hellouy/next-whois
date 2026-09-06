import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as dbQuery from "@/lib/db-query";
import {
  normalizeTld,
  isValidFailureTld,
  recordFailureEvent,
  pruneFailureEvents,
} from "./failure-events";

describe("normalizeTld", () => {
  it("strips a leading dot and lowercases", () => {
    expect(normalizeTld(".COM")).toBe("com");
    expect(normalizeTld("Com")).toBe("com");
    expect(normalizeTld("CO.UK")).toBe("co.uk");
  });

  it("passes through clean values", () => {
    expect(normalizeTld("dev")).toBe("dev");
    expect(normalizeTld("xn--p1ai")).toBe("xn--p1ai");
  });
});

describe("isValidFailureTld", () => {
  it("accepts plain suffixes", () => {
    expect(isValidFailureTld("com")).toBe(true);
    expect(isValidFailureTld(".xyz")).toBe(true);
    expect(isValidFailureTld("dev")).toBe(true);
  });

  it("rejects junk and numeric-only values", () => {
    expect(isValidFailureTld("")).toBe(false);
    expect(isValidFailureTld("c")).toBe(false); // too short
    expect(isValidFailureTld("12345")).toBe(false);
    expect(isValidFailureTld("a.b.c")).toBe(false); // contains dot
    expect(isValidFailureTld("aaaaaaaaaaaaaaaaaaaaaaaaa")).toBe(false); // > 24
  });
});

describe("recordFailureEvent", () => {
  let runSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    runSpy = vi.spyOn(dbQuery, "run").mockResolvedValue(1);
  });
  afterEach(() => vi.restoreAllMocks());

  it("skips invalid TLDs without touching the DB", async () => {
    await recordFailureEvent({ tld: "12345", reason: "dns_failure" });
    expect(runSpy).not.toHaveBeenCalled();
  });

  it("inserts a classified event with normalized tld", async () => {
    await recordFailureEvent({
      tld: ".COM",
      errorMsg: "connect ETIMEDOUT 1.2.3.4:43",
      domain: "example.com",
      context: "lookup",
    });
    expect(runSpy).toHaveBeenCalledTimes(1);
    const [sql, params] = runSpy.mock.calls[0];
    expect(sql).toContain("INSERT INTO tld_failure_events");
    expect(params).toEqual([
      "com",
      "connect_timeout",
      "connect ETIMEDOUT 1.2.3.4:43",
      "example.com",
      "lookup",
    ]);
  });

  it("respects an explicit reason over message heuristics", async () => {
    await recordFailureEvent({
      tld: "com",
      reason: "http_blocked",
      errorMsg: "connection refused",
    });
    const params = runSpy.mock.calls[0][1];
    expect(params[1]).toBe("http_blocked");
  });

  it("truncates long error and domain payloads", async () => {
    const longErr = "x".repeat(500);
    const longDomain = "y".repeat(500);
    await recordFailureEvent({ tld: "dev", errorMsg: longErr, domain: longDomain });
    const params = runSpy.mock.calls[0][1];
    expect(params[2].length).toBe(300);
    expect(params[3].length).toBe(253);
  });

  it("never throws when the DB write fails", async () => {
    runSpy.mockImplementation(async () => {
      throw new Error("connection lost");
    });
    await recordFailureEvent({ tld: "com", reason: "no_server" });
    expect(runSpy).toHaveBeenCalledTimes(1);
  });
});

describe("pruneFailureEvents", () => {
  let runSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    runSpy = vi.spyOn(dbQuery, "run").mockResolvedValue(12);
  });
  afterEach(() => vi.restoreAllMocks());

  it("deletes rows older than the given days", async () => {
    await pruneFailureEvents(90);
    expect(runSpy).toHaveBeenCalledTimes(1);
    const [sql, params] = runSpy.mock.calls[0];
    expect(sql).toContain("DELETE FROM tld_failure_events");
    expect(sql).toContain("make_interval");
    expect(params[0]).toBe(90);
  });

  it("does not reject when the DB is unavailable", async () => {
    runSpy.mockImplementation(async () => {
      throw new Error("boom");
    });
    await pruneFailureEvents(30);
    expect(runSpy).toHaveBeenCalledTimes(1);
  });
});
