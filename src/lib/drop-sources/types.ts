/**
 * Shared contracts for the drop-calendar source adapters.
 */

import type { DropStage, RegStatus } from "@/lib/drop-types";

/** One normalized row produced by a source adapter, before lifecycle/valuation. */
export interface RawDropRow {
  domain: string;
  stage: DropStage;
  /** Adapter id that produced the row (filled in by the registry). */
  source?: string;
  /** ISO date (YYYY-MM-DD) supplied by the source, if any. */
  dropDate?: string | null;
  /** Expiry date used to derive the drop date via lifecycle rules. */
  expiryDate?: string | null;
  /** Registration restriction reported by the source, if known. */
  regStatus?: RegStatus;
  bl?: number | null;
  dp?: number | null;
  sourceDateType: "source" | "derived";
}

export interface AdapterResult {
  rows: RawDropRow[];
  /** Rows that could not be parsed and were skipped. */
  skipped: number;
}

export interface DropSourceAdapter {
  id: string;
  stages: DropStage[];
  fetch(): Promise<AdapterResult>;
}

export interface SourceRunOutcome {
  source: string;
  ok: boolean;
  items: number;
  skipped: number;
  error: string | null;
}
