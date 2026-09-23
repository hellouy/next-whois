/**
 * Lifecycle enrichment for drop-calendar leads.
 *
 * For `expiring` rows the drop date is derived from the expiry date through the
 * shared lifecycle engine, then reconciled with any source-provided date. Rows
 * carrying blocking EPP statuses are dropped from the future window.
 */

import {
  computeLifecycle,
  formatDropTime,
  getTldLifecycle,
  DEFAULT_LIFECYCLE,
  type TldLifecycle,
} from "@/lib/lifecycle";
import { resolveDropDate } from "@/lib/drop-normalize";
import type { DateType, DropStage } from "@/lib/drop-types";
import type { RawDropRow } from "@/lib/drop-sources/types";

const BLOCKING_EPP = ["hold", "prohibited", "disputed", "suspicious"];

/** Whether any EPP status marks the name as unavailable for a clean drop. */
export function hasBlockingEpp(eppStatuses?: string[] | null): boolean {
  if (!eppStatuses?.length) return false;
  return eppStatuses.some((s) => {
    const n = String(s).toLowerCase().replace(/[\s_-]/g, "");
    return BLOCKING_EPP.some((b) => n.includes(b));
  });
}

export interface EnrichedDropRow {
  domain: string;
  stage: DropStage;
  dropDate: string | null;
  dropTime: string | null;
  expiryDate: string | null;
  dateType: DateType;
  confidence: "high" | "low";
  deviationDays: number | null;
  bl: number | null;
  dp: number | null;
}

function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/**
 * Derive the drop date/time for a raw row and reconcile it with the source date.
 * Returns null when the row is blocked or carries no usable date.
 */
export function enrichDropRow(
  row: RawDropRow,
  eppStatuses?: string[] | null,
  overrides?: Record<string, TldLifecycle>,
): EnrichedDropRow | null {
  if (hasBlockingEpp(eppStatuses)) return null;

  const expiry = row.expiryDate ?? null;
  let derivedDate: string | null = null;
  let dropTime: string | null = null;
  let confidence: "high" | "low" = "low";

  if (expiry) {
    const lc = computeLifecycle(row.domain, expiry, eppStatuses ?? undefined, overrides);
    if (lc) {
      derivedDate = isoDate(lc.dropDate);
      dropTime = formatDropTime(lc.cfg);
      confidence = getTldLifecycle(row.domain, overrides) === DEFAULT_LIFECYCLE ? "low" : "high";
    }
  }

  // A source-provided date is always authoritative.
  if (row.dropDate) confidence = "high";

  const resolved = resolveDropDate(row.dropDate, derivedDate);
  if (!resolved.dropDate) return null;

  return {
    domain: row.domain,
    stage: row.stage,
    dropDate: resolved.dropDate,
    dropTime,
    expiryDate: expiry,
    dateType: resolved.dateType,
    confidence,
    deviationDays: resolved.deviationDays,
    bl: row.bl ?? null,
    dp: row.dp ?? null,
  };
}
