/**
 * snipe-balance.ts — hold/settle/release of user funds for domain preorders.
 *
 * Guards honestly: a target may only be armed (and only ever registered) after
 * its full service price has been frozen. Freezing debits available balance
 * into a frozen pool; settling converts it into an actual charge; releasing
 * returns it. Every movement produces a balance_transactions row, deduped by a
 * held key (hold_keys on snipe_targets) so retries are idempotent.
 */

import { randomBytes } from "crypto";
import type { TxClient } from "@/lib/db-query";
import { one, many, run, withTransaction } from "@/lib/db-query";
import { sendEmail } from "@/lib/email";
import { snipeArmedHtml } from "@/lib/email";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/snipe-balance");

export const HOLD_TYPE = "hold";
export const UNHOLD_TYPE = "unhold";
export const SNIPE_TYPE = "snipe";

export interface HoldResult {
  ok: boolean;
  insufficient: boolean;
  frozenCents: number;
  balanceCents: number;
  holdKey?: string;
}

function holdKey(targetId: string, kind: string): string {
  return `${targetId}:${kind}`;
}

/** Best-effort lookup of a user id by email (null when no account exists). */
async function userIdForEmail(tx: TxClient, email: string): Promise<string | null> {
  const row = await tx.one<{ id: string }>("SELECT id FROM users WHERE email = $1", [email]);
  return row?.id ?? null;
}

/**
 * Freeze `amountCents` of the user's available balance for a preorder target.
 * Debits balance_cents into frozen_cents in one atomic conditional UPDATE, so
 * a concurrent charge can never overspend. Writes a `hold` transaction row and
 * records the dedup key on the target. Idempotent: if the target already holds
 * `amountCents`, it returns ok without moving money twice.
 */
export async function freezeForSnipe(
  tx: TxClient,
  targetId: string,
  userEmail: string,
  amountCents: number,
): Promise<HoldResult> {
  const key = holdKey(targetId, SNIPE_TYPE);
  const target = await tx.one<{ frozen_cents: number }>(
    `SELECT frozen_cents FROM snipe_targets WHERE id = $1`,
    [targetId],
  );

  const already = target?.frozen_cents ?? 0;
  // Full amount already frozen (previous freeze / partial top-up) — nothing to move.
  if (already >= amountCents) {
    return { ok: true, insufficient: false, frozenCents: already, balanceCents: 0, holdKey: key };
  }

  const diff = amountCents - already;

  const uid = await userIdForEmail(tx, userEmail);
  if (!uid) {
    return { ok: false, insufficient: true, frozenCents: already, balanceCents: 0 };
  }

  // Attempt to freeze only the outstanding shortfall so a prior partial top-up
  // is never double-debited. Atomic conditional debit keeps balance >= 0.
  const updated = await tx.one<{ balance_cents: number }>(
    `UPDATE users
       SET balance_cents = balance_cents - $2,
           frozen_cents  = frozen_cents + $2,
           updated_at    = NOW()
     WHERE id = $1 AND balance_cents >= $2
     RETURNING balance_cents`,
    [uid, diff],
  );

  if (!updated) {
    const row = await tx.one<{ balance_cents: number }>(
      `SELECT balance_cents FROM users WHERE id = $1`,
      [uid],
    );
    return { ok: false, insufficient: true, frozenCents: already, balanceCents: row?.balance_cents ?? 0 };
  }

  await tx.run(
    `INSERT INTO balance_transactions (user_id, amount_cents, type, description, target_id)
     VALUES ($1, $2, $3, $4, $5)`,
    [uid, diff, HOLD_TYPE, `抢注预定冻结（${targetId}）`, targetId],
  );
  await tx.run(
    `UPDATE snipe_targets
       SET frozen_cents = $2, hold_keys = $3, updated_at = NOW()
     WHERE id = $1`,
    [targetId, amountCents, JSON.stringify({ hold: key })],
  );
  return { ok: true, insufficient: false, frozenCents: amountCents, balanceCents: updated.balance_cents, holdKey: key };
}

/**
 * Convert a frozen hold into a real charge after a successful registration.
 * Idempotent: skip when the target already has a `snipe` transaction.
 */
export async function settleSnipeCharge(
  tx: TxClient,
  targetId: string,
  userEmail: string,
  amountCents: number,
): Promise<void> {
  const uid = await userIdForEmail(tx, userEmail);
  if (!uid) return;

  // Idempotency guard: a `snipe` transaction for this target already exists.
  const already = await tx.one<{ id: number }>(
    `SELECT id FROM balance_transactions WHERE target_id = $1 AND type = '${SNIPE_TYPE}' LIMIT 1`,
    [targetId],
  );
  if (already) return;

  await tx.run(
    `UPDATE users SET frozen_cents = frozen_cents - $2, updated_at = NOW() WHERE id = $1`,
    [uid, amountCents],
  );
  await tx.run(
    `INSERT INTO balance_transactions (user_id, amount_cents, type, description, target_id)
     VALUES ($1, $2, $3, $4, $5)`,
    [uid, amountCents, SNIPE_TYPE, `抢注成功扣费（${targetId}）`, targetId],
  );
  const row = await tx.one<{ hold_keys: string | null }>(
    `SELECT hold_keys FROM snipe_targets WHERE id = $1`,
    [targetId],
  );
  const keys = row?.hold_keys ? JSON.parse(row.hold_keys) : {};
  await tx.run(
    `UPDATE snipe_targets SET frozen_cents = 0, hold_keys = $2, updated_at = NOW() WHERE id = $1`,
    [targetId, JSON.stringify({ ...keys, charge: `${targetId}:${SNIPE_TYPE}` })],
  );
}

/**
 * Release a hold back to the user's available balance. Dedupes on the `unhold`
 * key so neither user funds nor audit rows are duplicated on a retry.
 */
export async function releaseSnipeHold(
  tx: TxClient,
  targetId: string,
  userEmail: string,
  amountCents: number,
): Promise<void> {
  const uid = await userIdForEmail(tx, userEmail);
  if (!uid) return;

  const row = await tx.one<{ frozen_cents: number; hold_keys: string | null }>(
    `SELECT frozen_cents, hold_keys FROM snipe_targets WHERE id = $1`,
    [targetId],
  );
  if (!row) return;
  const keys = row.hold_keys ? JSON.parse(row.hold_keys) : {};

  // Already released — hold_keys carries an `unhold` marker for this target.
  if (keys.unhold === holdKey(targetId, UNHOLD_TYPE)) return;

  const amount = Math.min(amountCents, row.frozen_cents);
  if (amount <= 0) return;

  await tx.run(
    `UPDATE users SET frozen_cents = frozen_cents - $2, balance_cents = balance_cents + $2, updated_at = NOW() WHERE id = $1`,
    [uid, amount],
  );
  await tx.run(
    `INSERT INTO balance_transactions (user_id, amount_cents, type, description, target_id)
     VALUES ($1, $2, $3, $4, $5)`,
    [uid, amount, UNHOLD_TYPE, `抢注未成功，解冻退还（${targetId}）`, targetId],
  );
  await tx.run(
    `UPDATE snipe_targets
       SET frozen_cents = 0, hold_keys = $2, updated_at = NOW()
     WHERE id = $1`,
    [targetId, JSON.stringify({ ...keys, [UNHOLD_TYPE]: holdKey(targetId, UNHOLD_TYPE) })],
  );
}

// ── User-target CRUD ──────────────────────────────────────────────────────────

/** Active statuses that occupy a domain preorder (first-come-first-served). */
export const SNIPE_OCCUPIED_STATUSES = [
  "watching", "armed", "blocked_balance", "sniping", "paused", "succeeded",
];

export class SnipeTakenError extends Error {
  constructor(public readonly domain: string) {
    super(`domain already preordered: ${domain}`);
    this.name = "SnipeTakenError";
  }
}

/**
 * Create (or re-activate) a user preorder target for a domain. Fails with
 * SnipeTakenError when another user already holds the active preorder.
 * A previously `cancelled`/`failed` row owned by the same email is reused.
 * Returns the target id.
 */
export async function createUserSnipeTarget(tx: TxClient, params: {
  domain: string;
  tld: string;
  userEmail: string;
  serviceCents: number;
  expirationDate: string | null;
}): Promise<string> {
  const { domain, tld, userEmail, serviceCents, expirationDate } = params;

  const existing = await tx.one<{ id: string; status: string; user_email: string | null }>(
    `SELECT id, status, user_email FROM snipe_targets WHERE domain = $1`,
    [domain],
  );
  if (existing) {
    const occupied =
      !existing.user_email ||
      existing.user_email !== userEmail ||
      SNIPE_OCCUPIED_STATUSES.includes(existing.status);
    if (occupied) throw new SnipeTakenError(domain);

    // Reuse the orphaned row owned by this user (cancelled/failed).
    await tx.run(
      `UPDATE snipe_targets
         SET status = 'watching', user_email = $2, tld = $3,
             service_price_cents = $4, frozen_cents = 0, hold_keys = NULL,
             expiration_date = $5, fail_reason = NULL, updated_at = NOW(),
             probe_lock_at = NULL, netim_ope_id = NULL, registered_at = NULL,
             final_price = NULL, hunt_start = NULL, hunt_end = NULL,
             drop_eta = NULL, est_price = NULL, is_premium = NULL,
             last_epp = NULL, last_whois_at = NULL, whois_fails = 0,
             recharge_alerted_at = NULL, stale_alerted_at = NULL
       WHERE id = $1`,
      [existing.id, userEmail, tld, serviceCents, expirationDate],
    );
    return existing.id;
  }

  const id = randomBytes(12).toString("hex");
  const inserted = await tx.run(
    `INSERT INTO snipe_targets
       (id, domain, tld, status, user_email, service_price_cents, frozen_cents, expiration_date)
     VALUES ($1, $2, $3, 'watching', $4, $5, 0, $6)`,
    [id, domain, tld, userEmail, serviceCents, expirationDate],
  );
  if (inserted !== 1) throw new SnipeTakenError(domain);
  return id;
}

/**
 * Cancel a user preorder target and release any frozen hold. No-op when the
 * target does not belong to the caller. Returns the released amount (cents).
 */
export async function cancelUserSnipeTarget(tx: TxClient, params: {
  domain: string;
  userEmail: string;
}): Promise<number> {
  const { domain, userEmail } = params;
  const row = await tx.one<{ id: string; status: string; frozen_cents: number }>(
    `SELECT id, status, frozen_cents FROM snipe_targets WHERE domain = $1 AND user_email = $2`,
    [domain, userEmail],
  );
  if (!row) return 0;

  // Refund the frozen service price before soft-cancelling.
  if (row.frozen_cents > 0) {
    await releaseSnipeHold(tx, row.id, userEmail, row.frozen_cents);
  }
  await tx.run(
    `UPDATE snipe_targets
       SET status = 'cancelled', fail_reason = NULL, updated_at = NOW(),
           probe_lock_at = NULL
     WHERE id = $1 AND status NOT IN ('succeeded','cancelled')`,
    [row.id],
  );
  return row.frozen_cents;
}

/**
 * Called after a recharge lands. For every preorder of this user that is
 * stuck on `blocked_balance`, try to complete the freeze; the ones that now
 * have enough funds move to `armed` and the user is told the hunt is on.
 * Idempotent: insufficient targets stay blocked, frozen ones never re-freeze.
 */
export async function autoArmBlockedTargets(userEmail: string): Promise<number> {
  const blocked = await many<{
    id: string;
    domain: string;
    user_email: string;
    service_price_cents: number | null;
    frozen_cents: number;
  }>(
    `SELECT id, domain, user_email, service_price_cents, frozen_cents
     FROM snipe_targets
     WHERE user_email = $1 AND status = 'blocked_balance'`,
    [userEmail],
  );

  let armed = 0;
  for (const target of blocked) {
    const service = target.service_price_cents ?? target.frozen_cents;
    if (service == null || service <= 0) continue;

    try {
      const outcome = await withTransaction((tx) =>
        freezeForSnipe(tx, target.id, userEmail, service),
      );
      if (outcome.insufficient) continue;

      await run(
        `UPDATE snipe_targets SET status = 'armed', updated_at = NOW()
         WHERE id = $1 AND status = 'blocked_balance'`,
        [target.id],
      );
      armed += 1;
      void sendEmail({
        to: userEmail,
        subject: `[抢注预定] ${target.domain} 已进入竞速`,
        html: snipeArmedHtml({ domain: target.domain, serviceCents: service }),
      }).catch((e) => logger.error(`[snipe-balance] armed email failed: ${e.message}`));
    } catch (e) {
      logger.error(`[snipe-balance] auto-arm failed for ${target.domain}: ${(e as Error).message}`);
    }
  }
  return armed;
}