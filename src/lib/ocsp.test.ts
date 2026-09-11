import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkOcsp } from "./ocsp";

const { mockRequest, mockUtils } = vi.hoisted(() => ({
  mockRequest: { generate: vi.fn() },
  mockUtils: { parseResponse: vi.fn() },
}));

vi.mock("ocsp", () => ({
  default: {
    request: mockRequest,
    utils: mockUtils,
  },
}));

function fakeRaw(): ArrayBuffer {
  return new ArrayBuffer(100);
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkOcsp", () => {
  it("returns unknown with reason when no responder in cert", async () => {
    vi.spyOn(require("crypto"), "X509Certificate").mockImplementation(
      class {
        infoAccess = "CA Issuers - URI:http://crt.sectigo.com/x.crt";
      } as any
    );
    const r = await checkOcsp(fakeRaw(), fakeRaw());
    expect(r.status).toBe("unknown");
    expect(r.responder).toBeNull();
    expect(r.reason).toBe("no_responder");
  });

  it("returns good on parseResponse good", async () => {
    vi.spyOn(require("crypto"), "X509Certificate").mockImplementation(
      class {
        infoAccess = "OCSP - URI:http://ocsp.example.com";
      } as any
    );
    mockRequest.generate.mockReturnValue({ data: Buffer.from([1, 2, 3]) });
    mockUtils.parseResponse.mockReturnValue({
      value: { tbsResponseData: { responses: [{ certStatus: { type: "good" } }] } },
    });
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: true, arrayBuffer: () => Promise.resolve(new ArrayBuffer(4)) })));
    const r = await checkOcsp(fakeRaw(), fakeRaw());
    expect(r.status).toBe("good");
    expect(r.responder).toBe("http://ocsp.example.com");
    expect(mockRequest.generate).toHaveBeenCalledTimes(1);
  });

  it("returns revoked", async () => {
    vi.spyOn(require("crypto"), "X509Certificate").mockImplementation(
      class {
        infoAccess = "OCSP - URI:http://ocsp.example.com";
      } as any
    );
    mockUtils.parseResponse.mockReturnValue({
      value: { tbsResponseData: { responses: [{ certStatus: { type: "revoked" } }] } },
    });
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: true, arrayBuffer: () => Promise.resolve(new ArrayBuffer(4)) })));
    const r = await checkOcsp(fakeRaw(), fakeRaw());
    expect(r.status).toBe("revoked");
  });

  it("returns unknown on HTTP error", async () => {
    vi.spyOn(require("crypto"), "X509Certificate").mockImplementation(
      class {
        infoAccess = "OCSP - URI:http://ocsp.example.com";
      } as any
    );
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve({ ok: false, status: 503 })));
    const r = await checkOcsp(fakeRaw(), fakeRaw());
    expect(r.status).toBe("unknown");
    expect(r.reason).toBe("http_503");
  });

  it("returns unknown on fetch failure", async () => {
    vi.spyOn(require("crypto"), "X509Certificate").mockImplementation(
      class {
        infoAccess = "OCSP - URI:http://ocsp.example.com";
      } as any
    );
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("ECONNREFUSED"))));
    const r = await checkOcsp(fakeRaw(), fakeRaw());
    expect(r.status).toBe("unknown");
  });
});
