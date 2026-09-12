/**
 * /api/admin/snipe-targets — CRUD for domain-drop snipe targets.
 *
 *   GET              → list targets (with latest probe/attempt info)
 *   POST             → add a target (WHOIS-initialised drop ETA)
 *   PATCH ?id=…      → pause / resume / cancel / set max_price
 *   DELETE ?id=…     → remove a target (cancelled targets only)
 *
 * All routes require an admin session (requireAdmin).
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { many, one, run, isDbReady } from "@/lib/db-query";
import { requireAdmin } from "@/lib/admin";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { computeLifecycle } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { HUNT_PRE_DAYS, HUNT_POST_DAYS } from "@/lib/server/snipe-engine";

export const config = { maxDuration: 60 };

const VALID_PATCH = new Set(["pause", "resume", "cancel", "max_price"]);

function normalizeDomain(raw: string): string | null {
  const d = (raw ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!d || d.length > 253 || !/^[a-z0-9.-]+$/.test(d)) return null;
  if (!d.includes(".")) return null;
  return d;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;

  if (!(await isDbReady())) return res.status(500).json({ error: "Database unavailable" });

  try {
    switch (req.method) {
      case "GET":
        return await handleGet(res);
      case "POST":
        return await handlePost(req, res);
      case "PATCH":
        return await handlePatch(req, res);
      case "DELETE":
        return await handleDelete(req, res);
      default:
        return res.status(405).json({ error: "Method not allowed" });
    }
  } catch (e) {
    return res.status(500).json({ error: (e as Error).message });
  }
}

async function handleGet(res: NextApiResponse) {
  const targets = await many<any>(
    `SELECT t.*, p.result AS last_probe_result, p.channel AS last_probe_channel,
            p.created_at AS last_probe_at
     FROM snipe_targets t
     LEFT JOIN LATERAL (
       SELECT result, channel, created_at FROM snipe_probes
       WHERE target_id = t.id ORDER BY created_at DESC LIMIT 1
     ) p ON true
     ORDER BY t.created_at DESC`,
  );
  return res.status(200).json({ targets });
}

async function handlePost(req: NextApiRequest, res: NextApiResponse) {
  const domain = normalizeDomain(String(req.body?.domain ?? ""));
  if (!domain) return res.status(400).json({ error: "Invalid domain" });

  const maxPrice = req.body?.max_price != null && req.body?.max_price !== ""
    ? Number(req.body.max_price)
    : null;
  if (maxPrice !== null && (!Number.isFinite(maxPrice) || maxPrice <= 0)) {
    return res.status(400).json({ error: "max_price must be a positive number" });
  }

  // WHOIS-initialise: drop ETA from the expiry + lifecycle hold periods.
  let expiration: string | null = null;
  let epp: string[] = [];
  const whois = await Promise.race([
    lookupWhoisWithCache(domain),
    new Promise<null>((r) => setTimeout(() => r(null), 8000)),
  ]);
  if (whois?.result) {
    expiration = (() => {
      const raw = whois.result!.expirationDate;
      if (!raw || raw === "Unknown") return null;
      const d = new Date(raw);
      return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
    })();
    epp = (whois.result.status || [])
      .map((s) => (s as { status?: string }).status ?? "")
      .filter(Boolean);
  }

  let overrides: Record<string, unknown> = {};
  try { overrides = await loadLifecycleOverrides(); } catch { /* default lifecycle */ }

  const lc = computeLifecycle(domain, expiration, undefined, overrides as never);
  const dropEta = lc ? lc.dropDate.toISOString().slice(0, 10) : null;
  const base = dropEta ? new Date(dropEta + "T00:00:00Z") : new Date();
  const huntStart = new Date(base.getTime() - HUNT_PRE_DAYS * 86_400_000).toISOString();
  const huntEnd = new Date(base.getTime() + HUNT_POST_DAYS * 86_400_000).toISOString();

  const row = await one<any>(
    `INSERT INTO snipe_targets (domain, tld, max_price, expiration_date, drop_eta, hunt_start, hunt_end, last_epp)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (domain) DO NOTHING
     RETURNING *`,
    [domain, domain.split(".").pop() ?? "", maxPrice, expiration, dropEta, huntStart, huntEnd,
     epp.length ? JSON.stringify(epp) : null],
  );

  if (!row) {
    return res.status(409).json({ error: "Target already exists" });
  }
  return res.status(201).json({ target: row });
}

async function handlePatch(req: NextApiRequest, res: NextApiResponse) {
  const id = String(req.query.id ?? "");
  const action = String(req.body?.action ?? "");
  if (!id || !VALID_PATCH.has(action)) {
    return res.status(400).json({ error: "Missing id or invalid action" });
  }

  const current = await one<{ status: string }>(`SELECT status FROM snipe_targets WHERE id = $1`, [id]);
  if (!current) return res.status(404).json({ error: "Target not found" });

  switch (action) {
    case "pause": {
      if (["succeeded", "failed", "cancelled"].includes(current.status)) {
        return res.status(400).json({ error: "Cannot pause a finished target" });
      }
      await run(
        `UPDATE snipe_targets SET status = 'paused', probe_lock_at = NULL, updated_at = NOW() WHERE id = $1`,
        [id],
      );
      break;
    }
    case "resume": {
      if (current.status !== "paused") {
        return res.status(400).json({ error: "Only paused targets can be resumed" });
      }
      await run(
        `UPDATE snipe_targets SET status = 'watching', updated_at = NOW() WHERE id = $1`,
        [id],
      );
      break;
    }
    case "cancel": {
      await run(
        `UPDATE snipe_targets SET status = 'cancelled', probe_lock_at = NULL, updated_at = NOW() WHERE id = $1`,
        [id],
      );
      break;
    }
    case "max_price": {
      const v = req.body?.max_price;
      const maxPrice = v != null && v !== "" ? Number(v) : null;
      if (maxPrice !== null && (!Number.isFinite(maxPrice) || maxPrice <= 0)) {
        return res.status(400).json({ error: "max_price must be a positive number" });
      }
      await run(
        `UPDATE snipe_targets SET max_price = $2, updated_at = NOW() WHERE id = $1`,
        [id, maxPrice],
      );
      break;
    }
  }

  const updated = await one<any>(`SELECT * FROM snipe_targets WHERE id = $1`, [id]);
  return res.status(200).json({ target: updated });
}

async function handleDelete(req: NextApiRequest, res: NextApiResponse) {
  const id = String(req.query.id ?? "");
  if (!id) return res.status(400).json({ error: "Missing id" });

  const current = await one<{ status: string }>(`SELECT status FROM snipe_targets WHERE id = $1`, [id]);
  if (!current) return res.status(404).json({ error: "Target not found" });
  if (current.status !== "cancelled") {
    return res.status(400).json({ error: "Only cancelled targets can be deleted" });
  }

  await run(`DELETE FROM snipe_attempts WHERE target_id = $1`, [id]);
  await run(`DELETE FROM snipe_probes WHERE target_id = $1`, [id]);
  await run(`DELETE FROM snipe_targets WHERE id = $1`, [id]);
  return res.status(200).json({ ok: true });
}
