/**
 * /api/admin/drop-lead-status — manually mark a drop-calendar lead's
 * registration availability.
 *
 *   POST { domain, status }  → status: available | reserved | prohibited
 *
 * Reserved/prohibited names are surfaced with a dedicated card treatment in
 * the drop calendar so operators can flag registry-reserved or registration-
 * prohibited names that the collectors do not report.
 *
 * Requires an admin session (requireAdmin).
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { invalidateDropCache } from "@/lib/server/drop-cache";
import type { RegStatus } from "@/lib/drop-types";

const VALID_STATUS = new Set<RegStatus>(["available", "reserved", "prohibited"]);

function normalizeDomain(raw: unknown): string | null {
  const d = String(raw ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!d || d.length > 253 || !/^[a-z0-9.-]+$/.test(d)) return null;
  if (!d.includes(".")) return null;
  return d;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  if (!(await isDbReady())) return res.status(500).json({ error: "Database unavailable" });

  const domain = normalizeDomain(req.body?.domain);
  if (!domain) return res.status(400).json({ error: "Invalid domain" });

  const status = String(req.body?.status ?? "").toLowerCase() as RegStatus;
  if (!VALID_STATUS.has(status)) return res.status(400).json({ error: "Invalid status" });

  try {
    const updated = await run(`UPDATE expired_domain_leads SET status = $1 WHERE domain = $2`, [status, domain]);
    if (updated <= 0) return res.status(404).json({ error: "Lead not found" });
    await invalidateDropCache();
    return res.status(200).json({ ok: true, domain, status });
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
}
