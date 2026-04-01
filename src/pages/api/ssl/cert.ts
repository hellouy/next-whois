import type { NextApiRequest, NextApiResponse } from "next";
import tls from "tls";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 20 };

const RL_LIMIT  = 20;
const RL_WINDOW = 60_000;

type SanEntry = { type: string; value: string };
type CertChainEntry = {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  valid_from: string;
  valid_to: string;
  fingerprint256: string;
  serialNumber: string;
};

type CertResult = {
  hostname: string;
  port: number;
  authorized: boolean;
  authError: string | null;
  protocol: string | null;
  cipher: string | null;
  cipherBits: number | null;
  subject: Record<string, string>;
  issuer: Record<string, string>;
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  is_expired: boolean;
  is_expiring_soon: boolean;
  fingerprint: string;
  fingerprint256: string;
  serialNumber: string;
  keyAlgorithm: string | null;
  keyBits: number | null;
  sans: SanEntry[];
  chain: CertChainEntry[];
  latencyMs: number;
};

function parseSans(altname: string): SanEntry[] {
  if (!altname) return [];
  return altname.split(", ").map(s => {
    const idx = s.indexOf(":");
    if (idx < 0) return { type: "DNS", value: s };
    return { type: s.slice(0, idx), value: s.slice(idx + 1) };
  });
}

function buildChain(cert: any, maxDepth = 6): CertChainEntry[] {
  const chain: CertChainEntry[] = [];
  let c = cert;
  const seen = new Set<string>();
  while (c && chain.length < maxDepth) {
    const fp = c.fingerprint256 || c.fingerprint || "";
    if (seen.has(fp)) break;
    seen.add(fp);
    chain.push({
      subject: (c.subject || {}) as Record<string, string>,
      issuer: (c.issuer || {}) as Record<string, string>,
      valid_from: c.valid_from || "",
      valid_to: c.valid_to || "",
      fingerprint256: c.fingerprint256 || "",
      serialNumber: c.serialNumber || "",
    });
    if (!c.issuerCertificate || c.issuerCertificate === c) break;
    c = c.issuerCertificate;
  }
  return chain;
}

function getKeyInfo(cert: any): { keyAlgorithm: string | null; keyBits: number | null } {
  const curve = (cert as any).nistCurve || (cert as any).asn1Curve;
  if (curve) {
    return { keyAlgorithm: `EC (${curve})`, keyBits: null };
  }
  const bits = (cert as any).bits;
  if (bits) {
    return { keyAlgorithm: "RSA", keyBits: bits };
  }
  return { keyAlgorithm: null, keyBits: null };
}

async function fetchCert(hostname: string, port: number): Promise<CertResult> {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false,
    });

    const cleanup = setTimeout(() => {
      socket.destroy();
      reject(new Error("Connection timed out"));
    }, 12000);

    socket.on("secureConnect", () => {
      clearTimeout(cleanup);
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol?.() ?? null;
        const cipherInfo = socket.getCipher?.();
        const authorized = socket.authorized;
        const authError = socket.authorizationError?.toString() ?? null;
        socket.end();

        if (!cert || Object.keys(cert).length === 0) {
          return reject(new Error("No certificate returned"));
        }

        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const msRemaining = validTo.getTime() - now.getTime();
        const daysRemaining = Math.floor(msRemaining / 86400000);
        const { keyAlgorithm, keyBits } = getKeyInfo(cert);

        const result: CertResult = {
          hostname,
          port,
          authorized,
          authError,
          protocol,
          cipher: cipherInfo?.name ?? null,
          cipherBits: (cipherInfo as any)?.secretKeyLength ?? null,
          subject: (cert.subject || {}) as Record<string, string>,
          issuer: (cert.issuer || {}) as Record<string, string>,
          valid_from: cert.valid_from || "",
          valid_to: cert.valid_to || "",
          days_remaining: daysRemaining,
          is_expired: daysRemaining < 0,
          is_expiring_soon: daysRemaining >= 0 && daysRemaining <= 30,
          fingerprint: cert.fingerprint || "",
          fingerprint256: cert.fingerprint256 || "",
          serialNumber: cert.serialNumber || "",
          keyAlgorithm,
          keyBits,
          sans: parseSans(cert.subjectaltname || ""),
          chain: buildChain(cert),
          latencyMs: Date.now() - t0,
        };
        resolve(result);
      } catch (e) {
        reject(e);
      }
    });

    socket.on("error", (e) => {
      clearTimeout(cleanup);
      reject(e);
    });
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { allowed } = rateLimit(getClientIp(req), RL_LIMIT, RL_WINDOW);
  if (!allowed) return res.status(429).json({ error: "Too many requests" });

  let hostname = (req.query.hostname as string | undefined)?.trim().toLowerCase();
  if (!hostname) return res.status(400).json({ error: "hostname parameter is required" });

  hostname = hostname.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];

  const port = Math.min(Math.max(parseInt(String(req.query.port || "443")), 1), 65535) || 443;

  try {
    const result = await fetchCert(hostname, port);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({ ok: true, ...result });
  } catch (e: any) {
    const msg = e?.message || "Unknown error";
    const isRefused = msg.includes("ECONNREFUSED") || msg.includes("connect");
    const isTimeout = msg.toLowerCase().includes("timeout");
    const isNoCert = msg.includes("No certificate");
    const errorCode = isRefused ? "err_refused" : isTimeout ? "err_timeout" : isNoCert ? "err_no_cert" : "err_unknown";
    return res.status(200).json({
      ok: false,
      hostname,
      port,
      errorCode,
      error: msg,
    });
  }
}
