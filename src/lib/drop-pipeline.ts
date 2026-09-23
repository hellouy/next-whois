/**
 * Drop-calendar ingestion pipeline: collect → enrich → score → upsert → status
 * → cache invalidation. Dependencies are injectable so the orchestration can be
 * unit-tested without a database.
 */

import { run } from "@/lib/db-query";
import { collectDropRows, type CollectedRows } from "@/lib/drop-sources/registry";
import type { SourceRunOutcome } from "@/lib/drop-sources/types";
import { enrichDropRow } from "@/lib/drop-lifecycle";
import { scoreDomainExtended, type ValueContext } from "@/lib/drop-value";
import { loadValueContext } from "@/lib/server/drop-value-context";
import { invalidateDropCache } from "@/lib/server/drop-cache";
import type { DateType, DropStage, RegStatus } from "@/lib/drop-types";

/** Map an adapter id to the `source` label persisted on leads. */
export const SOURCE_LABELS: Record<string, string> = {
  expireddomains: "expireddomains.net",
  whoisds: "whoisds.com",
};

export interface UpsertLeadInput {
  domain: string;
  tld: string;
  sld: string;
  charCount: number;
  bl: number | null;
  dp: number | null;
  dropDate: string;
  expiryDate: string | null;
  stage: DropStage;
  dateType: DateType;
  regStatus: RegStatus;
  valueScore: number;
  valueTier: string;
  valueReasons: string[];
  source: string;
}

export interface DropPipelineDeps {
  collect: () => Promise<CollectedRows>;
  loadContext: () => Promise<ValueContext>;
  upsertLead: (lead: UpsertLeadInput) => Promise<void>;
  recordSourceStatus: (outcome: SourceRunOutcome) => Promise<void>;
  invalidateCache: () => Promise<void>;
}

export interface DropPipelineResult {
  sources: SourceRunOutcome[];
  upserted: number;
  skipped: number;
}

async function defaultUpsertLead(lead: UpsertLeadInput): Promise<void> {
  await run(
    `INSERT INTO expired_domain_leads
       (domain, tld, sld, char_count, bl, dp, drop_date, expiry_date, stage, date_type,
        status, value_score, value_tier, value_reasons, source, crawled_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,NOW())
     ON CONFLICT (domain) DO UPDATE SET
       tld           = EXCLUDED.tld,
       sld           = EXCLUDED.sld,
       char_count    = EXCLUDED.char_count,
       bl            = COALESCE(EXCLUDED.bl, expired_domain_leads.bl),
       dp            = COALESCE(EXCLUDED.dp, expired_domain_leads.dp),
       drop_date     = EXCLUDED.drop_date,
       expiry_date   = EXCLUDED.expiry_date,
       stage         = EXCLUDED.stage,
       date_type     = EXCLUDED.date_type,
       status        = EXCLUDED.status,
       value_score   = EXCLUDED.value_score,
       value_tier    = EXCLUDED.value_tier,
       value_reasons = EXCLUDED.value_reasons,
       source        = EXCLUDED.source,
       crawled_at    = NOW()`,
    [
      lead.domain, lead.tld, lead.sld, lead.charCount, lead.bl, lead.dp,
      lead.dropDate, lead.expiryDate, lead.stage, lead.dateType,
      lead.regStatus, lead.valueScore, lead.valueTier, JSON.stringify(lead.valueReasons), lead.source,
    ],
  );
}

async function defaultRecordSourceStatus(o: SourceRunOutcome): Promise<void> {
  await run(
    `INSERT INTO drop_source_status
       (source, last_success_at, last_error, last_error_at, items_last_run)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (source) DO UPDATE SET
       last_success_at = COALESCE(EXCLUDED.last_success_at, drop_source_status.last_success_at),
       last_error      = EXCLUDED.last_error,
       last_error_at   = EXCLUDED.last_error_at,
       items_last_run  = EXCLUDED.items_last_run`,
    [
      SOURCE_LABELS[o.source] ?? o.source,
      o.ok ? new Date() : null,
      o.error,
      o.ok ? null : new Date(),
      o.items,
    ],
  ).catch(() => 0);
}

const DEFAULT_DEPS: DropPipelineDeps = {
  collect: () => collectDropRows(),
  loadContext: () => loadValueContext(),
  upsertLead: defaultUpsertLead,
  recordSourceStatus: defaultRecordSourceStatus,
  invalidateCache: () => invalidateDropCache(),
};

export async function runDropPipeline(
  deps: Partial<DropPipelineDeps> = {},
): Promise<DropPipelineResult> {
  const d = { ...DEFAULT_DEPS, ...deps };
  const { outcomes, rows } = await d.collect();
  const context = await d.loadContext();

  const seen = new Set<string>();
  let upserted = 0;
  let skipped = 0;

  for (const row of rows) {
    if (seen.has(row.domain)) {
      skipped++;
      continue;
    }
    seen.add(row.domain);

    const enriched = enrichDropRow(row);
    if (!enriched || !enriched.dropDate) {
      skipped++;
      continue;
    }

    const value = scoreDomainExtended(enriched.domain, {
      ...context,
      bl: enriched.bl,
      dp: enriched.dp,
    });

    const parts = enriched.domain.split(".");
    const tld = parts.pop() ?? "";
    const sld = parts.join(".");

    await d.upsertLead({
      domain: enriched.domain,
      tld,
      sld,
      charCount: sld.length,
      bl: enriched.bl,
      dp: enriched.dp,
      dropDate: enriched.dropDate,
      expiryDate: enriched.expiryDate,
      stage: enriched.stage,
      dateType: enriched.dateType,
      regStatus: enriched.regStatus,
      valueScore: value?.score ?? 0,
      valueTier: value?.tierEn ?? "low",
      valueReasons: value?.reasons ?? [],
      source: SOURCE_LABELS[row.source ?? ""] ?? row.source ?? "unknown",
    });
    upserted++;
  }

  for (const outcome of outcomes) {
    await d.recordSourceStatus(outcome);
  }

  await d.invalidateCache();

  return { sources: outcomes, upserted, skipped };
}
