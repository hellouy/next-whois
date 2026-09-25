/**
 * GET /api/admin/ai-stats — AI usage audit (R11).
 *
 * Aggregates ai_call_log per provider over a window (default 7 days),
 * surfaces circuit-breaker states and recent circuit transitions.
 */
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { many } from "@/lib/db-query";
import { getCircuitStates } from "@/lib/server/ai-providers";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    return res.setHeader("Allow", "GET").status(405).json({ error: "Method not allowed" });
  }
  const session = await requireAdmin(req, res);
  if (!session) return;

  const rawWindow = parseInt(String(req.query.window ?? "7"), 10);
  const days = rawWindow === 30 ? 30 : 7;
  const sinceDaysAgo = (d: number) => `NOW() - INTERVAL '${d} days'`;

  // ── Per-provider aggregation (R11 AC2) ─────────────────────────────────────
  const providers = await many<{
    provider: string;
    model: string;
    calls: number;
    success: number;
    failed: number;
    avg_ms: number | null;
    max_ms: number | null;
    last_error: string | null;
    last_at: string | null;
  }>(
    `SELECT provider,
            MAX(model) AS model,
            COUNT(*) AS calls,
            COUNT(*) FILTER (WHERE ok) AS success,
            COUNT(*) FILTER (WHERE NOT ok) AS failed,
            ROUND(AVG(ms) FILTER (WHERE ms IS NOT NULL))::int AS avg_ms,
            MAX(ms) AS max_ms,
            (array_agg(error ORDER BY created_at DESC) FILTER (WHERE error IS NOT NULL))[1] AS last_error,
            MAX(created_at)::text AS last_at
     FROM ai_call_log
     WHERE kind <> 'circuit'
       AND created_at >= ${sinceDaysAgo(days)}
     GROUP BY provider
     ORDER BY calls DESC
     LIMIT 50`
  );

  // ── Recent circuit transitions (R11 AC4) ───────────────────────────────────
  const circuitTransitions = await many<{
    provider: string;
    model: string;
    error: string | null;
    created_at: string;
  }>(
    `SELECT provider, model, error, created_at::text
     FROM ai_call_log
     WHERE kind = 'circuit'
       AND created_at >= ${sinceDaysAgo(days)}
     ORDER BY created_at DESC
     LIMIT 20`
  );

  // ── Recent TLD extraction records (R11 AC3: model + latency per scrape) ────
  const recent = await many<{
    provider: string;
    model: string;
    tld: string | null;
    ok: boolean;
    ms: number | null;
    error: string | null;
    created_at: string;
  }>(
    `SELECT provider, model, tld, ok, ms, error, created_at::text
     FROM ai_call_log
     WHERE kind = 'tld_extract'
       AND created_at >= ${sinceDaysAgo(days)}
     ORDER BY created_at DESC
     LIMIT 100`
  );

  // ── Summary ────────────────────────────────────────────────────────────────
  const summary = await many<{
    total: number;
    success: number;
    failed: number;
    avg_ms: number | null;
  }>(
    `SELECT COUNT(*) AS total,
            COUNT(*) FILTER (WHERE ok) AS success,
            COUNT(*) FILTER (WHERE NOT ok) AS failed,
            ROUND(AVG(ms) FILTER (WHERE ms IS NOT NULL))::int AS avg_ms
     FROM ai_call_log
     WHERE kind <> 'circuit'
       AND created_at >= ${sinceDaysAgo(days)}`
  );

  return res.json({
    window_days: days,
    summary: summary[0] ?? { total: 0, success: 0, failed: 0, avg_ms: null },
    providers,
    circuit_states: getCircuitStates(),
    circuit_transitions: circuitTransitions,
    recent,
  });
}
