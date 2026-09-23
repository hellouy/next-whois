import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, isDbReady } from "@/lib/db-query";
import { computeLifecycle, formatDropTime, getTldLifecycle } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { getSetting } from "@/lib/server/site-settings-server";
import { createLogger } from "@/lib/logger";
import type {
  DateType,
  DropDayGroup,
  DropLeadView,
  DropSourceStatusView,
  DropStage,
  DropsResponse,
  DropStats,
  UserDropGroup,
} from "@/lib/drop-types";

const logger = createLogger("api/drops");

const ROW_LIMIT = 500;
const TOP_LIMIT = 10;
const STALE_HOURS = 48;

/** Stage each source primarily contributes (for the freshness strip). */
const SOURCE_STAGES: Record<string, DropStage> = {
  "expireddomains.net": "pending_delete",
  "whoisds.com": "deleted",
};

interface LeadRow {
  domain: string;
  tld: string;
  drop_date: string;
  date_type: string;
  source: string;
  stage: string;
  value_score: number | null;
  value_tier: string | null;
  value_reasons: unknown;
  bl: number | null;
  dp: number | null;
}

function parseReasons(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.map((r) => String(r));
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed.map((r) => String(r));
    } catch { /* ignore */ }
  }
  return [];
}

function toLead(row: LeadRow): DropLeadView {
  return {
    domain: row.domain,
    tld: row.tld,
    dropDate: row.drop_date,
    dropTime: formatDropTime(getTldLifecycle(row.domain)),
    dateType: (row.date_type === "derived" ? "derived" : "source") as DateType,
    source: row.source,
    valueScore: row.value_score ?? 0,
    valueTier: row.value_tier ?? "low",
    reasons: parseReasons(row.value_reasons),
  };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const days = Math.min(Math.max(parseInt(String(req.query.days ?? "30"), 10) || 30, 1), 90);
  const sortParam = String(req.query.sort ?? "value");
  const sort = ["value", "date", "bl"].includes(sortParam) ? sortParam : "value";
  const tlds = String(req.query.tld ?? "")
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
  const minLen = parseInt(String(req.query.minLen ?? "0"), 10) || 0;
  const maxLen = parseInt(String(req.query.maxLen ?? "0"), 10) || 0;
  const minScore = parseInt(String(req.query.minScore ?? "0"), 10) || 0;
  const source = String(req.query.source ?? "").trim().toLowerCase();
  const dateTypeParam = String(req.query.dateType ?? "").trim().toLowerCase();
  const dateType = ["source", "derived"].includes(dateTypeParam) ? dateTypeParam : "";

  const session = await getServerSession(req, res, authOptions);
  const email = session?.user?.email ?? null;
  const publicEnabled = (await getSetting("drop_calendar_public", "1").catch(() => "1")) !== "0";

  const todayStr = new Date().toISOString().slice(0, 10);
  const endStr = new Date(Date.parse(`${todayStr}T00:00:00Z`) + days * 86_400_000)
    .toISOString()
    .slice(0, 10);

  // ── Shared filter clause ───────────────────────────────────────────────────
  const conditions = ["drop_date IS NOT NULL", "drop_date >= $1", "drop_date <= $2"];
  const params: (string | number | string[])[] = [todayStr, endStr];
  if (tlds.length) { params.push(tlds); conditions.push(`tld = ANY($${params.length})`); }
  if (minLen > 0) { params.push(minLen); conditions.push(`char_count >= $${params.length}`); }
  if (maxLen > 0) { params.push(maxLen); conditions.push(`char_count <= $${params.length}`); }
  if (minScore > 0) { params.push(minScore); conditions.push(`value_score >= $${params.length}`); }
  if (source) { params.push(source); conditions.push(`LOWER(source) = $${params.length}`); }
  if (dateType) { params.push(dateType); conditions.push(`date_type = $${params.length}`); }
  const where = conditions.join(" AND ");

  const orderBy =
    sort === "date" ? "drop_date ASC, value_score DESC NULLS LAST"
    : sort === "bl" ? "bl DESC NULLS LAST, value_score DESC NULLS LAST"
    : "value_score DESC NULLS LAST, drop_date ASC";

  // ── Public part: upcoming drops ────────────────────────────────────────────
  let publicLocked = false;
  let drops: DropDayGroup[] = [];
  let stats: DropStats = { total: 0, today: 0, tlds: [], top: [] };
  let sources: DropSourceStatusView[] = [];

  if (publicEnabled || email) {
    try {
      const rows = await many<LeadRow>(
        `SELECT domain, tld, drop_date::text AS drop_date, date_type, source, stage,
                value_score, value_tier, value_reasons, bl, dp
         FROM expired_domain_leads
         WHERE ${where}
         ORDER BY ${orderBy}
         LIMIT ${ROW_LIMIT}`,
        params,
      );

      const byDate = new Map<string, DropLeadView[]>();
      for (const row of rows) {
        const lead = toLead(row);
        if (!byDate.has(lead.dropDate)) byDate.set(lead.dropDate, []);
        byDate.get(lead.dropDate)!.push(lead);
      }
      drops = [...byDate.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([date, domains]) => ({
          date,
          total: domains.length,
          topTier: domains.reduce((best, d) => (d.valueScore > best.valueScore ? d : best), domains[0]).valueTier,
          domains,
        }));

      const todayIdx = params.length + 1;
      const [agg, tldDist, topRows] = await Promise.all([
        many<{ total: number; today: number }>(
          `SELECT COUNT(*)::int AS total,
                  COUNT(*) FILTER (WHERE drop_date = $${todayIdx})::int AS today
           FROM expired_domain_leads WHERE ${where}`,
          [...params, todayStr],
        ),
        many<{ tld: string; count: number }>(
          `SELECT tld, COUNT(*)::int AS count
           FROM expired_domain_leads WHERE ${where}
           GROUP BY tld ORDER BY count DESC LIMIT ${TOP_LIMIT}`,
          params,
        ),
        many<LeadRow>(
          `SELECT domain, tld, drop_date::text AS drop_date, date_type, source, stage,
                  value_score, value_tier, value_reasons, bl, dp
           FROM expired_domain_leads WHERE ${where}
           ORDER BY value_score DESC NULLS LAST LIMIT ${TOP_LIMIT}`,
          params,
        ),
      ]);

      stats = {
        total: agg[0]?.total ?? 0,
        today: agg[0]?.today ?? 0,
        tlds: tldDist,
        top: topRows.map(toLead),
      };

      const statusRows = await many<{
        source: string; last_success_at: string | null; last_error: string | null;
      }>(
        `SELECT source, last_success_at, last_error FROM drop_source_status`,
      );
      const cutoff = Date.now() - STALE_HOURS * 3_600_000;
      sources = statusRows.map((r) => ({
        source: r.source,
        stage: SOURCE_STAGES[r.source] ?? "deleted",
        lastSuccessAt: r.last_success_at,
        stale: !r.last_success_at || Date.parse(r.last_success_at) < cutoff,
      }));
    } catch (err) {
      logger.error("[drops] public query error:", err instanceof Error ? err.message : String(err));
      drops = [];
      stats = { total: 0, today: 0, tlds: [], top: [] };
      sources = [];
    }
  } else {
    publicLocked = true;
  }

  // ── Private part: the user's own subscriptions with an upcoming drop ──────
  let userDrops: UserDropGroup[] = [];
  if (email) {
    try {
      const rows = await many<{
        id: string; domain: string; whois_expiry_date: string | null; expiration_date: string | null;
        last_epp_status: string | null;
      }>(
        `SELECT id, domain, whois_expiry_date, expiration_date, last_epp_status
         FROM reminders WHERE email = $1 AND active = true`,
        [email],
      );
      const overrides = await loadLifecycleOverrides().catch(() => ({}));
      const byDate = new Map<string, { domain: string; reminder_id: string }[]>();
      for (const r of rows) {
        const effectiveExpiry = r.whois_expiry_date ?? r.expiration_date;
        if (!effectiveExpiry) continue;
        let eppStatuses: string[] = [];
        try { if (r.last_epp_status) eppStatuses = JSON.parse(r.last_epp_status); } catch { /* ignore */ }
        // A registry that still reports hold/prohibited statuses (e.g. Registry
        // Hold) has frozen the name — the date-based drop estimate is not going
        // to happen on schedule. Do not advertise it as an upcoming drop.
        if (eppStatuses.some((s) => /(client|server)?hold|prohibited|disputed|suspicious/i.test(s))) continue;
        const lc = computeLifecycle(r.domain, effectiveExpiry, eppStatuses.length ? eppStatuses : undefined, overrides);
        if (!lc || lc.phase === "dropped") continue;
        const dropStr = lc.dropDate.toISOString().slice(0, 10);
        if (dropStr < todayStr || dropStr > endStr) continue;
        if (!byDate.has(dropStr)) byDate.set(dropStr, []);
        byDate.get(dropStr)!.push({ domain: r.domain, reminder_id: r.id });
      }
      userDrops = [...byDate.entries()].map(([date, domains]) => ({ date, domains }));
    } catch (err) {
      logger.error("[drops] user query error:", err instanceof Error ? err.message : String(err));
      userDrops = [];
    }
  }

  // A signed-in response carries the user's own subscriptions (user_drops) which
  // are personal data — it must never be shared through a public edge cache.
  // Only fully anonymous payloads may be cached.
  const cacheControl = email
    ? "private, no-store"
    : "public, max-age=300, stale-while-revalidate=600";
  res.setHeader("Cache-Control", cacheControl);

  const payload: DropsResponse = {
    today: todayStr,
    days,
    public_locked: publicLocked,
    sources,
    drops,
    stats,
    user_drops: userDrops,
  };
  return res.json(payload);
}
