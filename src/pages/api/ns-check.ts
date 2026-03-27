import type { NextApiRequest, NextApiResponse } from "next";
import dns from "dns/promises";
import { domainToASCII } from "url";
import { enforceApiKey } from "@/lib/access-key";
import { rateLimit, getClientIp } from "@/lib/server/rate-limit";
import { extractDomain } from "@/lib/utils";

export const config = {
  maxDuration: 10,
};

const RATE_LIMIT     = 120;
const RATE_WINDOW_MS = 60_000;
const DNS_TIMEOUT_MS = 3_000;

type NsCheckResult = {
  domain: string;
  registered: boolean | null;
  ns: string[];
  ipv4: string[];
  time: number;
};

function withTimeout<T>(p: Promise<T>): Promise<T | null> {
  return Promise.race([
    p.catch(() => null),
    new Promise<null>(resolve => setTimeout(() => resolve(null), DNS_TIMEOUT_MS)),
  ]);
}

function toAscii(input: string): string {
  if (!/[^\x00-\x7F]/.test(input)) return input;
  try {
    const a = domainToASCII(input.toLowerCase());
    if (a && !a.includes("\u0000")) return a;
  } catch {}
  return input;
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<NsCheckResult | { error: string }>,
) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.setHeader("Allow", "GET, HEAD");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const denied = await enforceApiKey(req, res);
  if (denied) return;

  const ip = getClientIp(req);
  const { allowed } = rateLimit(ip, RATE_LIMIT, RATE_WINDOW_MS);
  if (!allowed) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  const raw = typeof req.query.domain === "string" ? req.query.domain.trim() : "";
  if (!raw) return res.status(400).json({ error: "Missing domain parameter" });

  const extracted = extractDomain(raw) || raw;
  const domain = toAscii(extracted.toLowerCase());

  const start = Date.now();

  const [nsResult, aResult] = await Promise.all([
    withTimeout(dns.resolveNs(domain)),
    withTimeout(dns.resolve4(domain)),
  ]);

  const ns   = nsResult  ?? [];
  const ipv4 = aResult   ?? [];

  let registered: boolean | null = null;
  if (ns.length > 0 || ipv4.length > 0) registered = true;
  else if (nsResult !== null && aResult !== null) registered = false;

  const time = (Date.now() - start) / 1000;

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ domain, registered, ns, ipv4, time });
}
