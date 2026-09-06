/**
 * Failure event persistence — the diagnostic fact source for the admin TLD
 * failure dashboard. Each failed query writes one row to tld_failure_events;
 * query_logs remains the metric fact source (totals / success rate / latency).
 *
 * All writes are best-effort and fire-and-forget: they never throw into the
 * query path and never block response delivery.
 */

import { run } from "@/lib/db-query";
import { classifyFailure, type FailureReason } from "./classify-failure";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/failure-events");

export interface FailureEventInput {
  tld: string;
  /** New enum value or a legacy reason string; classified on the way in. */
  reason?: string;
  domain?: string;
  errorMsg?: string;
  /** Query phase: lookup / whois / rdap / api */
  context?: string;
}

/** Mirror the guards used by the old counter so junk labels never enter. */
function isValidTld(tld: string): boolean {
  if (!tld || tld.length < 2 || tld.length > 24) return false;
  return /^[a-zA-Z]/.test(tld) && !/^\d+$/.test(tld) && !tld.includes(".");
}

export function normalizeTld(raw: string): string {
  return raw.toLowerCase().replace(/^\./, "");
}

export function isValidFailureTld(raw: string): boolean {
  return isValidTld(normalizeTld(raw));
}

/** INSERT a single failure event. Resolves normally even on DB failure. */
export async function recordFailureEvent(input: FailureEventInput): Promise<void> {
  const tld = normalizeTld(input.tld || "");
  if (!isValidTld(tld)) return;

  const reason: FailureReason = classifyFailure(input.errorMsg, input.reason);
  const detail = (input.errorMsg ?? "").slice(0, 300);
  const domain = (input.domain ?? "").slice(0, 253) || null;

  try {
    await run(
      `INSERT INTO tld_failure_events (tld, fail_reason, reason_detail, domain, context)
       VALUES ($1, $2, $3, $4, $5)`,
      [tld, reason, detail || null, domain, (input.context ?? "").slice(0, 40) || null],
    );
  } catch (e) {
    logger.warn(`[failure-events] write failed for .${tld}:`, (e as Error).message);
  }
}

/** Best-effort prune of events older than `days`. Returns nothing. */
export async function pruneFailureEvents(days = 90): Promise<void> {
  try {
    await run(`DELETE FROM tld_failure_events WHERE created_at < NOW() - ($1 || ' days')::interval`, [
      String(days),
    ]);
  } catch (e) {
    logger.warn(`[failure-events] prune failed:`, (e as Error).message);
  }
}