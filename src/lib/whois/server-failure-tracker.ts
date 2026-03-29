/**
 * Tracks TLDs whose native WHOIS/RDAP lookup consistently returns "no server
 * available" (IANA fallback or connection failure).  Records are written
 * fire-and-forget so they never slow down a live lookup.
 *
 * The repair-servers script reads this table and attempts to discover the
 * correct server via IANA referral + RDAP bootstrap + AI, then saves the
 * result to custom_whois_servers.
 */
import { run, isDbReady } from "@/lib/db-query";

export type FailureErrorType =
  | "iana_fallback"    // IANA returned its own referral page (no whois: line)
  | "no_server"        // getLookupWhois threw "No WHOIS server responded"
  | "tcp_timeout"      // TCP connect timed out on the primary WHOIS server
  | "empty_result";    // Server responded but with completely empty data

/**
 * Record a lookup failure for a TLD.
 * - Uses upsert so repeat failures just increment the counter.
 * - Skips if DB is not ready (graceful degradation).
 * - Non-blocking: caller must NOT await this — use `.catch(() => {})`.
 */
export async function recordTldServerFailure(
  tld: string,
  errorType: FailureErrorType = "iana_fallback",
): Promise<void> {
  if (!(await isDbReady())) return;
  const normalized = tld.toLowerCase().replace(/^\./, "");
  if (!normalized || normalized.length > 63) return;

  await run(
    `INSERT INTO tld_server_failures (tld, fail_count, error_type, last_failed_at, repair_status)
     VALUES ($1, 1, $2, NOW(), 'pending')
     ON CONFLICT (tld) DO UPDATE
       SET fail_count     = tld_server_failures.fail_count + 1,
           error_type     = $2,
           last_failed_at = NOW(),
           -- Only reset to 'pending' if previously marked 'not_found'
           -- (so found/ignored entries aren't repeatedly re-queued)
           repair_status  = CASE
             WHEN tld_server_failures.repair_status = 'not_found' THEN 'pending'
             ELSE tld_server_failures.repair_status
           END`,
    [normalized, errorType],
  );
}

/**
 * Mark a TLD repair as complete (called by the repair script after saving
 * the discovered server to custom_whois_servers).
 *
 * Also resets tld_fallback_stats so the next lookup tries the native server
 * immediately instead of continuing to route through the external fallback.
 */
export async function markTldRepaired(
  tld: string,
  foundServer: string,
  notes?: string,
): Promise<void> {
  if (!(await isDbReady())) return;
  const normalized = tld.toLowerCase().replace(/^\./, "");
  await run(
    `UPDATE tld_server_failures
     SET repair_status = 'found',
         found_server  = $2,
         ai_notes      = $3,
         repaired_at   = NOW()
     WHERE tld = $1`,
    [normalized, foundServer, notes ?? null],
  );
  // Reset fallback gate so the next query goes to the native server,
  // not the external fallback (yisi/tianhu).
  await run(
    `UPDATE tld_fallback_stats
     SET fail_count = 0, use_fallback = false
     WHERE tld = $1`,
    [normalized],
  ).catch(() => {}); // non-critical — row may not exist
}

/**
 * Mark a TLD as unrepairable — no server found after exhaustive search.
 */
export async function markTldNotFound(
  tld: string,
  notes?: string,
): Promise<void> {
  if (!(await isDbReady())) return;
  const normalized = tld.toLowerCase().replace(/^\./, "");
  await run(
    `UPDATE tld_server_failures
     SET repair_status = 'not_found',
         ai_notes      = $2,
         repaired_at   = NOW()
     WHERE tld = $1`,
    [normalized, notes ?? null],
  );
}

/**
 * Mark a TLD as intentionally ignored (e.g., it's in STATIC_ALWAYS_FALLBACK
 * and should never get a custom server entry).
 */
export async function markTldIgnored(tld: string): Promise<void> {
  if (!(await isDbReady())) return;
  const normalized = tld.toLowerCase().replace(/^\./, "");
  await run(
    `UPDATE tld_server_failures SET repair_status = 'ignored' WHERE tld = $1`,
    [normalized],
  );
}
