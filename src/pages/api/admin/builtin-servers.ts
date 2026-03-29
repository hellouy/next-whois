import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdminSession } from "@/lib/admin-shared";
import { getCctldRdapOverrides } from "@/lib/whois/rdap_client";
import { getAllGtldRdapServers } from "@/lib/whois/rdap_gtld_bootstrap";
import cctldWhois from "@/data/cctld-whois-servers.json";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const denied = await requireAdminSession(req, res);
  if (denied) return;
  if (req.method !== "GET") return res.status(405).end();

  // ── RDAP: merge gtld bootstrap + ccTLD overrides ──────────────────────────
  // ccTLD overrides take precedence (hand-curated, more accurate).
  const gtld = getAllGtldRdapServers();
  const cctldOverrides = getCctldRdapOverrides();
  const rdapMerged: Record<string, { url: string; source: "cctld-override" | "gtld-bootstrap" }> = {};
  for (const [tld, url] of Object.entries(gtld)) {
    rdapMerged[tld] = { url, source: "gtld-bootstrap" };
  }
  for (const [tld, url] of Object.entries(cctldOverrides)) {
    rdapMerged[tld] = { url, source: "cctld-override" };
  }

  // ── WHOIS: cctld-whois-servers.json (null = no server) ───────────────────
  const whoisMap: Record<string, string | null> = cctldWhois as Record<string, string | null>;

  return res.status(200).json({
    rdap: rdapMerged,
    whois: whoisMap,
    rdapTotal: Object.keys(rdapMerged).length,
    whoisTotal: Object.keys(whoisMap).length,
  });
}
