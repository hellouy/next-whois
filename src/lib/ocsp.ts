// OCSP revocation status check using the `ocsp` package.
// Builds the request from the leaf cert + issuer cert DER, then POSTs to the
// responder URL found in the certificate's Authority Information Access.

import ocsp from "ocsp";
import crypto from "crypto";

const OCSP_TIMEOUT_MS = 4000;

export type OcspResult = {
  status: "good" | "revoked" | "unknown";
  responder: string | null;
  latencyMs: number;
  reason?: string;
};

function extractResponderUrl(raw: ArrayBuffer | Buffer): string | null {
  try {
    const cert = new crypto.X509Certificate(raw as any);
    const info = String((cert as any).infoAccess ?? "");
    const m = info.match(/OCSP - URI:(\S+)/);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

export async function checkOcsp(certRaw: ArrayBuffer | Buffer, issuerRaw: ArrayBuffer | Buffer): Promise<OcspResult> {
  const t0 = Date.now();
  const responder = extractResponderUrl(certRaw);
  if (!responder) {
    return { status: "unknown", responder: null, latencyMs: Date.now() - t0, reason: "no_responder" };
  }
  try {
    const req = ocsp.request.generate(Buffer.from(certRaw as any), Buffer.from(issuerRaw as any));
    const res = await fetch(responder, {
      method: "POST",
      headers: { "Content-Type": "application/ocsp-request" },
      body: Buffer.from(req.data),
      signal: AbortSignal.timeout(OCSP_TIMEOUT_MS),
    });
    if (!res.ok) {
      return { status: "unknown", responder, latencyMs: Date.now() - t0, reason: `http_${res.status}` };
    }
    const buf = Buffer.from(await res.arrayBuffer());
    const parsed = ocsp.utils.parseResponse(buf);
    const status = parsed?.value?.tbsResponseData?.responses?.[0]?.certStatus?.type;
    if (status === "good") {
      return { status: "good", responder, latencyMs: Date.now() - t0 };
    }
    if (status === "revoked") {
      return { status: "revoked", responder, latencyMs: Date.now() - t0 };
    }
    return { status: "unknown", responder, latencyMs: Date.now() - t0, reason: "unparsed" };
  } catch (e: any) {
    return { status: "unknown", responder, latencyMs: Date.now() - t0, reason: e?.message ?? "error" };
  }
}
