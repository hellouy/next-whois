import type { NextApiRequest, NextApiResponse } from "next";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { checkRateLimit } from "@/lib/rate-limit";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ status: false });

  const ip = String(
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ?? req.socket?.remoteAddress ?? "unknown"
  );
  const rl = await checkRateLimit(ip, 10, 60_000);
  if (!rl.ok) return res.status(429).json({ status: false, error: "Too many requests" });

  const q = req.query.query;
  if (!q || typeof q !== "string" || !q.trim()) {
    return res.status(400).json({ status: false, error: "Query is required" });
  }
  const domain = q.trim().toLowerCase().slice(0, 253);

  // Basic domain format validation so arbitrary strings never reach the lookup
  // pipeline (which may hit external registry resources).
  if (
    !domain.includes(".") ||
    domain.startsWith(".") ||
    domain.endsWith(".") ||
    domain.includes("..")
  ) {
    return res.status(400).json({ status: false, error: "Invalid domain format" });
  }

  try {
    const result = await lookupWhoisWithCache(domain);
    if (!result.status || !result.result) {
      return res.status(500).json({ status: false, error: result.error ?? "Lookup failed" });
    }
    const r = result.result;
    res.setHeader("Cache-Control", "s-maxage=3600, stale-while-revalidate=7200");
    return res.status(200).json({
      status: true,
      source: result.source,
      result: {
        domain: r.domain,
        registrar: r.registrar,
        creationDate: r.creationDate,
        updatedDate: r.updatedDate,
        expirationDate: r.expirationDate,
        remainingDays: r.remainingDays,
        domainAge: r.domainAge,
        nameServers: r.nameServers,
        status: r.status,
        dnssec: r.dnssec,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ status: false, error: String(err?.message ?? "Internal error") });
  }
}
