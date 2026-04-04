/**
 * POST /api/admin/subscription-sync
 * Admin-only: bulk-refresh WHOIS data for active reminder subscriptions.
 *
 * Body (all optional):
 *   tld      — only refresh reminders for this TLD (e.g. "com")
 *   limit    — max number of WHOIS lookups (default 50, max 200)
 *   force    — if true, refresh even if recently synced (ignores stale threshold)
 *
 * Response:
 *   { refreshed, skipped, failed, domains: string[] }
 */
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { many, run, isDbReady } from "@/lib/db-query";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();
  const admin = await requireAdmin(req, res);
  if (!admin) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  const tld = typeof req.body.tld === "string" ? req.body.tld.toLowerCase().trim().replace(/^\./, "") : null;
  const limit = Math.min(Number(req.body.limit) || 50, 200);
  const force = req.body.force === true || req.body.force === "true";

  try {
    // Build query: active reminders optionally filtered by TLD
    const rows = await many<{
      id: string; domain: string; expiration_date: string | null; whois_synced_at: string | null;
    }>(
      tld
        ? `SELECT id, domain, expiration_date, whois_synced_at
           FROM reminders
           WHERE active = true
             AND (domain = $1 OR domain LIKE $2)
           ORDER BY whois_synced_at NULLS FIRST, expiration_date ASC
           LIMIT $3`
        : `SELECT id, domain, expiration_date, whois_synced_at
           FROM reminders
           WHERE active = true
           ORDER BY whois_synced_at NULLS FIRST, expiration_date ASC
           LIMIT $1`,
      tld
        ? [tld, `%.${tld}`, limit]
        : [limit],
    );

    const now = Date.now();
    const msPerDay = 86_400_000;

    // If not forcing, skip domains synced within last 24h
    const candidates = force
      ? rows
      : rows.filter(r => {
          const lastSync = r.whois_synced_at ? new Date(r.whois_synced_at).getTime() : 0;
          return now - lastSync > msPerDay;
        });

    let refreshed = 0;
    let failed = 0;
    const domains: string[] = [];

    // Process in parallel batches of 5 to avoid rate-limiting
    const BATCH = 5;
    for (let i = 0; i < candidates.length; i += BATCH) {
      const batch = candidates.slice(i, i + BATCH);
      await Promise.all(batch.map(async (r) => {
        try {
          const res2 = await Promise.race([
            lookupWhoisWithCache(r.domain),
            new Promise<null>(resolve => setTimeout(() => resolve(null), 10_000)),
          ]);
          if (!res2?.result) { failed++; return; }
          const rv = res2.result;
          const expiry = rv.expirationDate;
          if (!expiry || expiry === "Unknown") { failed++; return; }
          const d = new Date(expiry);
          if (isNaN(d.getTime())) { failed++; return; }
          const dateStr = d.toISOString().slice(0, 10);

          const clean = (v: unknown) => (v && v !== "Unknown" && v !== "N/A" ? String(v) : null);
          const registrar = clean(rv.registrar);
          const creationDate = (() => {
            const raw = clean(rv.creationDate);
            if (!raw) return null;
            const cd = new Date(raw);
            return isNaN(cd.getTime()) ? null : cd.toISOString().slice(0, 10);
          })();
          const nameservers: string[] = Array.isArray(rv.nameServers)
            ? rv.nameServers.map((ns: unknown) => String(ns).toLowerCase().trim()).filter((ns: string) => ns && ns !== "unknown").slice(0, 6)
            : [];

          await run(
            `UPDATE reminders
             SET expiration_date = $1, whois_expiry_date = $2, whois_synced_at = NOW(),
                 registrar = $3, creation_date = $4, nameservers_json = $5
             WHERE id = $6`,
            [dateStr, dateStr, registrar, creationDate,
             nameservers.length ? JSON.stringify(nameservers) : null, r.id],
          );
          refreshed++;
          domains.push(r.domain);
        } catch (err) {
          console.warn(`[subscription-sync] failed for ${r.domain}:`, err instanceof Error ? err.message : String(err));
          failed++;
        }
      }));
    }

    const skipped = rows.length - candidates.length;
    console.log(`[subscription-sync] tld=${tld ?? "all"} refreshed=${refreshed} skipped=${skipped} failed=${failed}`);

    return res.status(200).json({
      ok: true,
      tld: tld ?? "all",
      total: rows.length,
      refreshed,
      skipped,
      failed,
      domains,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[subscription-sync] error:", msg);
    return res.status(500).json({ error: msg });
  }
}

