import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one } from "@/lib/db-query";
import { snipeServicePrice } from "@/lib/server/snipe-pricing";

function isValidDomain(d: string): boolean {
  if (!d || d.length > 253) return false;
  if (!d.includes(".")) return false;
  if (d.startsWith(".") || d.endsWith(".")) return false;
  if (d.includes("..")) return false;
  const labels = d.split(".");
  const tld = labels[labels.length - 1];
  if (tld.length < 2) return false;
  return labels.every(l =>
    l.length > 0 && l.length <= 63 &&
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(l)
  );
}

/**
 * GET /api/snipe/quote?domain=example.com
 *
 * Lightweight read-only quotation for the preorder checkbox tooltip. Pricing is
 * always recomputed server-side via snipeServicePrice so the client can never
 * see or submit a cheaper amount. When an authenticated session is present the
 * caller's current balance is appended so the UI can show a shortfall hint.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const rawDomain = (req.query.domain as string | undefined)?.trim() ?? "";
  if (!rawDomain || !isValidDomain(rawDomain.toLowerCase())) {
    return res.status(400).json({ error: "Invalid domain" });
  }

  const quote = await snipeServicePrice(rawDomain);
  if (!quote) {
    return res.status(502).json({ error: "无法获取该域名的注册报价" });
  }

  if (quote.serviceCents == null) {
    return res.status(502).json({ error: quote.error ?? "无法获取该域名的注册报价" });
  }

  let balanceCents: number | null = null;
  try {
    const session = await getServerSession(req, res, authOptions);
    if (session?.user?.email) {
      const user = await one<{ balance_cents: number }>(
        "SELECT balance_cents FROM users WHERE email = $1",
        [session.user.email],
      );
      balanceCents = user?.balance_cents ?? 0;
    }
  } catch {
    // Optional enrichment; a failure here must not fail the public quote.
  }

  return res.status(200).json({
    domain: quote.domain,
    serviceCents: quote.serviceCents,
    cnyCost: quote.cnyCost,
    fxRate: quote.fxRate,
    markup: quote.markup,
    isPremium: quote.isPremium,
    balanceCents,
  });
}