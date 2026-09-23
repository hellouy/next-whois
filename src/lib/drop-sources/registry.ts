/**
 * Drop-source registry: runs every adapter in order and isolates failures so a
 * single broken source never blocks the others.
 */

import { expiredDomainsAdapter } from "./expireddomains";
import { whoisdsAdapter } from "./whoisds";
import type { DropSourceAdapter, RawDropRow, SourceRunOutcome } from "./types";

export const DEFAULT_ADAPTERS: DropSourceAdapter[] = [expiredDomainsAdapter, whoisdsAdapter];

export interface CollectedRows {
  outcomes: SourceRunOutcome[];
  rows: RawDropRow[];
}

/**
 * Run every adapter, isolating failures, and return both the per-source
 * outcomes and the combined rows (each tagged with its adapter id).
 */
export async function collectDropRows(
  adapters: DropSourceAdapter[] = DEFAULT_ADAPTERS,
): Promise<CollectedRows> {
  const outcomes: SourceRunOutcome[] = [];
  const rows: RawDropRow[] = [];

  for (const adapter of adapters) {
    try {
      const result = await adapter.fetch();
      for (const row of result.rows) rows.push({ ...row, source: adapter.id });
      outcomes.push({
        source: adapter.id,
        ok: true,
        items: result.rows.length,
        skipped: result.skipped,
        error: null,
      });
    } catch (e: any) {
      outcomes.push({
        source: adapter.id,
        ok: false,
        items: 0,
        skipped: 0,
        error: e?.message ?? String(e),
      });
    }
  }

  return { outcomes, rows };
}

export async function runDropSources(
  adapters: DropSourceAdapter[] = DEFAULT_ADAPTERS,
): Promise<SourceRunOutcome[]> {
  return (await collectDropRows(adapters)).outcomes;
}
