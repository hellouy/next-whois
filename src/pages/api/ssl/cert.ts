import type { NextApiRequest, NextApiResponse } from "next";
import tls from "tls";
import dns from "dns";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";

export const config = { maxDuration: 20 };

const RL_LIMIT  = 20;
const RL_WINDOW = 60_000;

function isPrivateHost(host: string): boolean {
  if (/^(localhost|127\.|0\.0\.0\.0|::1|0:0:0:0:0:0:0:1)$/i.test(host)) return true;
  if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true;
  if (/^192\.168\.\d+\.\d+$/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)) return true;
  if (/^169\.254\.\d+\.\d+$/.test(host)) return true;
  if (/^fe80:/i.test(host)) return true;
  if (host === "169.254.169.254") return true;
  if (/\.local$/i.test(host)) return true;
  return false;
}

/**
 * Normalize any IPv4 notation (dotted, decimal, hex, octal, mixed) to a
 * dotted-quad string, or null when input is not an IPv4 literal. Closes the
 * integer/hex bypass (e.g. 2130706433 == 127.0.0.1).
 */
function normalizeIPv4(host: string): string | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host;
  if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) {
    const n = /^0x/i.test(host) ? parseInt(host, 16) : host.startsWith("0") && host.length > 1 ? parseInt(host, 8) : parseInt(host, 10);
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  if (/^(\d+|0x[0-9a-f]+)(\.(\d+|0x[0-9a-f]+)){0,3}$/i.test(host)) {
    const parts = host.split(".").map(p => (/^0x/i.test(p) ? parseInt(p, 16) : p.startsWith("0") && p.length > 1 ? parseInt(p, 8) : parseInt(p, 10)));
    if (parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return null;
    while (parts.length < 4) parts.push(0);
    return parts.join(".");
  }
  return null;
}

/**
 * Full private/internal-address guard: literal check plus DNS resolution so
 * hostnames resolving into private space are rejected before any TLS
 * connection is opened (SSRF protection for the cert checker).
 */
async function isBlockedHost(host: string): Promise<boolean> {
  if (isPrivateHost(host)) return true;
  const ipv4 = normalizeIPv4(host);
  if (ipv4) {
    if (isPrivateHost(ipv4)) return true;
    const m = ipv4.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) {
      const a = Number(m[1]), b = Number(m[2]);
      if (a === 0 || (a === 100 && b >= 64 && b <= 127)) return true;
      if (a >= 224) return true;
    }
    return false;
  }
  try {
    const addrs: { address: string }[] = await dns.promises.lookup(host.replace(/^\[|\]$/g, ""), { all: true });
    if (!addrs || addrs.length === 0) return false;
    return addrs.some(a => isPrivateHost(a.address));
  } catch {
    return false;
  }
}

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

  if (await isBlockedHost(hostname)) {
    return res.status(400).json({ ok: false, hostname, errorCode: "err_private", error: "Private or internal addresses are not allowed" });
  }

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
