/**
 * snipe-engine.ts — domain-drop sniping business logic.
 *
 * The state machine and orchestration behind /api/cron/snipe-probe:
 *
 *   watching ──(precheck ok)──▶ armed ──(domainCheck AVAILABLE)──▶ sniping
 *   watching ──(balance low)──▶ blocked_balance ──▶ armed (after top-up)
 *   armed / sniping ──(create ok)──▶ succeeded
 *   armed / sniping ──(deterministic fail)──▶ failed
 *   watching / armed ──(admin)──▶ paused; paused ──▶ watching
 *   any ──(admin)──▶ cancelled
 *
 * Two entry points share one probe pipeline:
 *   - runDailyProbe()  — Vercel cron, every active target once/day + ETA
 *                        refresh + arming precheck.
 *   - runHuntProbe()   — GitHub Actions, only targets inside their hunt
 *                        window (drop_eta−1d … drop_eta+2d).
 *
 * Correctness guarantees (enforced here):
 *   1. Single-flight registration — probe_lock_at claim + armed→sniping CAS.
 *   2. Verdict→action atomicity — a snipe_attempts row is written whenever a
 *      create is issued, whatever its outcome.
 *   3. cancelled/paused targets never reach the registration path.
 *   4. Budget: live price > max_price, or balance < price, skips the create
 *      and records why.
 *   5. Credentials never appear in logs, HTTP responses or audit bodies.
 *   6. SNIPE_DRY_RUN=1 runs the whole pipeline up to domainCreate and still
 *      writes the audit trail.
 */

import { many, one, run } from "@/lib/db-query";
import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import type { WhoisResult } from "@/lib/whois/types";
import {
  netimDomainCheck,
  netimDomainCreate,
  netimQueryDomainPrice,
  netimQueryOpe,
  netimQueryResellerAccount,
} from "@/lib/server/netim-client";
import { computeLifecycle } from "@/lib/lifecycle";
import { loadLifecycleOverrides } from "@/lib/server/lifecycle-overrides";
import { sendEmail } from "@/lib/email";
import { snipeNotifyHtml } from "@/lib/email";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/snipe-engine");

export function isDryRun(): boolean {
  return process.env.SNIPE_DRY_RUN === "1";
}

export const HUNT_PRE_DAYS = 1;    // hunt starts 24h before the drop ETA
export const HUNT_POST_DAYS = 2;   // hunt ends 48h after the drop ETA
export const CLAIM_LOCK_SECONDS = 120;
export const WHOIS_TIMEOUT_MS = 8000;
export const MAX_WHOIS_FAILS = 3;
export const RECHARGE_ALERT_INTERVAL_MS = 24 * 3600 * 1000;

export const CREATE_RETRY_BACKOFFS_MS = [1_000, 4_000, 16_000];
const OPE_POLLS = 3;
const OPE_POLL_INTERVAL_MS = 5_000;

// ── Types ────────────────────────────────────────────────────────────────────

export interface SnipeTargetRow {
  id: string;
  domain: string;
  tld: string;
  status: string;
  max_price: number | null;
  est_price: number | null;
  is_premium: boolean | null;
  expiration_date: string | null;
  drop_eta: string | null;
  hunt_start: string | null;
  hunt_end: string | null;
  last_epp: string | null;
  last_whois_at: string | null;
  whois_fails: number;
  probe_lock_at: string | null;
  registered_at: string | null;
  netim_ope_id: string | null;
  final_price: number | null;
  fail_reason: string | null;
  notes: string | null;
  recharge_alerted_at: string | null;
  created_at: string;
  updated_at: string;
}

export type TargetOutcome =
  | "claimed_skipped"
  | "error"
  | "still_registered"
  | "not_available"
  | "budget_skip"
  | "armed"
  | "blocked_balance"
  | "succeeded"
  | "failed_permanent"
  | "failed_transient"
  | "unknown_pending"
  | "dry_run";

export interface ProbeResultEntry {
  id: string;
  outcome: TargetOutcome;
}

export interface ProbeSummary {
  mode: "daily" | "hunt";
  checked: number;
  results: ProbeResultEntry[];
  dryRun: boolean;
}

const ACTIVE_STATUSES = ["watching", "armed", "blocked_balance"];

// ── Small helpers ────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | null> {
  return Promise.race([
    p,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), ms)),
  ]);
}

const toDate = (v: string | null | undefined): string | null => {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
};

/**
 * A WHOIS reply "looks like a drop" when the registry reports no match for the
 * name. A successful WHOIS hit (EPP status list present) means it is still
 * registered/reserved/premium — not a release.
 */
export function isSuspectRelease(r: WhoisResult | null): boolean {
  if (!r) return false;
  if (r.status && r.result) {
    const codes = (r.result.status || []).map((s) => (s.status ?? "").toLowerCase());
    if (codes.some((c) => c.includes("available"))) return true;
    return false;
  }
  if (!r.status) {
    const err = `${r.error ?? ""} ${r.dnsProbe?.registrationStatus ?? ""}`.toLowerCase();
    return /domain not found|no match|not registered|unregistered/.test(err);
  }
  return false;
}

// ── DB helpers ───────────────────────────────────────────────────────────────

/** Atomic per-target claim: only one concurrent probe owns the row. */
async function claimTarget(id: string): Promise<SnipeTargetRow | null> {
  return one<SnipeTargetRow>(
    `UPDATE snipe_targets
       SET probe_lock_at = NOW(), updated_at = NOW()
     WHERE id = $1
       AND (probe_lock_at IS NULL OR probe_lock_at < NOW() - make_interval(secs => $2))
     RETURNING *`,
    [id, CLAIM_LOCK_SECONDS],
  );
}

async function releaseLock(id: string): Promise<void> {
  await run(`UPDATE snipe_targets SET probe_lock_at = NULL, updated_at = NOW() WHERE id = $1`, [id]);
}

async function recordProbe(
  targetId: string,
  channel: string,
  result: string,
  detail?: string | null,
  latencyMs?: number | null,
): Promise<void> {
  await run(
    `INSERT INTO snipe_probes (target_id, channel, result, detail, latency_ms) VALUES ($1,$2,$3,$4,$5)`,
    [targetId, channel, result, detail ?? null, latencyMs ?? null],
  ).catch((e) => logger.warn(`[snipe] probe log failed: ${e.message}`));
}

async function recordAttempt(params: {
  targetId: string;
  checkAvailable: boolean;
  paramsSnapshot: Record<string, unknown>;
  netimResponse?: string | null;
  opeId?: string | null;
  outcome: string;
  price?: number | null;
}): Promise<void> {
  await run(
    `INSERT INTO snipe_attempts (target_id, check_available, params_snapshot, netim_response, ope_id, outcome, price)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [
      params.targetId,
      params.checkAvailable,
      JSON.stringify(params.paramsSnapshot),
      params.netimResponse ?? null,
      params.opeId ?? null,
      params.outcome,
      params.price ?? null,
    ],
  ).catch((e) => logger.warn(`[snipe] attempt log failed: ${e.message}`));
}

/** Snapshot of registrar-side defaults used for a create (no credentials). */
async function defaultsSnapshot(): Promise<Record<string, unknown>> {
  const acc = await netimQueryResellerAccount();
  return {
    owner: acc?.defaultOwner ?? null,
    admin: acc?.defaultAdmin ?? null,
    tech: acc?.defaultTech ?? null,
    billing: acc?.defaultBilling ?? null,
    dns1: acc?.defaultDns1 ?? null,
    dns2: acc?.defaultDns2 ?? null,
    durationYears: 1,
  };
}

// ── ETA / hunt window ────────────────────────────────────────────────────────

/** drop_eta = expiration + lifecycle hold periods (grace/redemption/pending). */
async function computeDropEta(domain: string, expirationDate: string | null): Promise<string | null> {
  if (!expirationDate) return null;
  let overrides: Record<string, unknown>;
  try {
    overrides = await loadLifecycleOverrides();
  } catch {
    overrides = {};
  }
  const lc = computeLifecycle(domain, expirationDate, undefined, overrides as never);
  return lc ? lc.dropDate.toISOString().slice(0, 10) : null;
}

function makeHuntWindow(eta: string | null): { huntStart: string; huntEnd: string } {
  const base = eta ? new Date(eta + "T00:00:00Z") : new Date();
  if (isNaN(base.getTime())) {
    return {
      huntStart: new Date(Date.now() - HUNT_PRE_DAYS * 86_400_000).toISOString(),
      huntEnd: new Date(Date.now() + HUNT_POST_DAYS * 86_400_000).toISOString(),
    };
  }
  return {
    huntStart: new Date(base.getTime() - HUNT_PRE_DAYS * 86_400_000).toISOString(),
    huntEnd: new Date(base.getTime() + HUNT_POST_DAYS * 86_400_000).toISOString(),
  };
}

// ── Notifications ────────────────────────────────────────────────────────────

async function notifySuccess(t: SnipeTargetRow, opeId: string | undefined, price: number | null): Promise<void> {
  if (!ADMIN_EMAIL) return;
  await sendEmail({
    to: ADMIN_EMAIL,
    subject: `[抢注成功] ${t.domain}`,
    html: snipeNotifyHtml("success", {
      title: "域名抢注成功",
      domain: t.domain,
      lines: [
        ["状态", "已注册"],
        ["注册价", price != null ? `€ ${price}` : "未知"],
        ["操作号", opeId ?? "—"],
        ["目标状态", "succeeded"],
      ],
    }),
  }).catch((e) => logger.error(`[snipe] success email failed: ${e.message}`));
}

async function notifyFailed(t: SnipeTargetRow, reason: string | null, outcome: string): Promise<void> {
  if (!ADMIN_EMAIL) return;
  await sendEmail({
    to: ADMIN_EMAIL,
    subject: `[抢注失败] ${t.domain}`,
    html: snipeNotifyHtml("danger", {
      title: "域名抢注失败",
      domain: t.domain,
      lines: [
        ["原因", reason ?? outcome],
        ["操作号", t.netim_ope_id ?? "—"],
        ["目标状态", t.status],
      ],
    }),
  }).catch((e) => logger.error(`[snipe] failure email failed: ${e.message}`));
}

async function notifyUnknownPending(t: SnipeTargetRow, opeId: string | undefined): Promise<void> {
  if (!ADMIN_EMAIL) return;
  await sendEmail({
    to: ADMIN_EMAIL,
    subject: `[抢注待确认] ${t.domain}`,
    html: snipeNotifyHtml("warning", {
      title: "抢注结果待人工确认",
      domain: t.domain,
      lines: [
        ["状态", "domainCreate 已提交但操作结果未知"],
        ["操作号", opeId ?? "—"],
        ["处理方式", "请在 Netim 后台确认该操作号，必要时手动完成注册"],
      ],
    }),
  }).catch((e) => logger.error(`[snipe] unknown email failed: ${e.message}`));
}

async function notifyRecharge(t: SnipeTargetRow, balance: number, needed: number): Promise<void> {
  if (!ADMIN_EMAIL) return;
  if (
    t.recharge_alerted_at &&
    Date.now() - new Date(t.recharge_alerted_at).getTime() < RECHARGE_ALERT_INTERVAL_MS
  ) {
    return;
  }
  await sendEmail({
    to: ADMIN_EMAIL,
    subject: `[余额不足] 抢注目标 ${t.domain}`,
    html: snipeNotifyHtml("warning", {
      title: "账户余额不足以抢注",
      domain: t.domain,
      lines: [
        ["账户余额", `€ ${balance.toFixed(2)}`],
        ["注册预估", `€ ${needed.toFixed(2)}`],
        ["缺口", `€ ${(needed - balance).toFixed(2)}`],
        ["提示", "请为 Netim 账户充值后，目标将自动恢复 armed 状态"],
      ],
    }),
  }).catch((e) => logger.error(`[snipe] recharge email failed: ${e.message}`));
  await run(`UPDATE snipe_targets SET recharge_alerted_at = NOW() WHERE id = $1`, [t.id]);
}

// ── Precheck (arming) ────────────────────────────────────────────────────────

/**
 * Re-check balance + live price and move the target between watching,
 * armed and blocked_balance. Runs in daily mode for every active target.
 */
async function armPrecheck(t: SnipeTargetRow): Promise<TargetOutcome> {
  const account = await netimQueryResellerAccount();
  const price = await netimQueryDomainPrice(t.domain);

  const estPrice = price?.price ?? null;
  const premium = price?.isPremium ?? null;

  let notes = t.notes;
  if (premium === true) {
    notes = `${notes ? notes + "\n" : ""}premium 域名，注册价 € ${estPrice ?? "?"}`;
  }

  if (account && estPrice !== null && account.balance < estPrice) {
    await run(
      `UPDATE snipe_targets
         SET status = 'blocked_balance', est_price = $2, is_premium = $3, notes = $4, updated_at = NOW()
       WHERE id = $1`,
      [t.id, estPrice, premium, notes],
    );
    await notifyRecharge(t, account.balance, estPrice);
    return "blocked_balance";
  }

  if (estPrice !== null && t.max_price !== null && estPrice > t.max_price) {
    notes = `${notes ? notes + "\n" : ""}预估价 € ${estPrice} 超出上限 € ${t.max_price}`;
  }

  await run(
    `UPDATE snipe_targets
       SET status = 'armed', est_price = $2, is_premium = $3, notes = $4, updated_at = NOW()
     WHERE id = $1 AND status IN ('watching','blocked_balance')`,
    [t.id, estPrice, premium, notes],
  );
  return "armed";
}

// ── WHOIS refresh ────────────────────────────────────────────────────────────

async function refreshWhois(t: SnipeTargetRow): Promise<{
  release: boolean;
  epp: string[];
  expiration: string | null;
  whoisFails: number;
}> {
  const started = Date.now();
  const res = await withTimeout(lookupWhoisWithCache(t.domain), WHOIS_TIMEOUT_MS);

  const epp: string[] = res?.result?.status
    ? res.result.status.map((s) => (s as { status?: string }).status ?? "").filter(Boolean)
    : [];
  const expiration = toDate(res?.result?.expirationDate ?? null);
  const elapsed = Date.now() - started;

  if (!res) {
    const fails = t.whois_fails + 1;
    await run(
      `UPDATE snipe_targets SET whois_fails = $2, updated_at = NOW() WHERE id = $1`,
      [t.id, fails],
    );
    await recordProbe(t.id, "whois", "error", "timeout/network", elapsed);
    return { release: false, epp, expiration, whoisFails: fails };
  }

  const release = isSuspectRelease(res);
  const fails = release ? 0 : 0;
  const eppJson = epp.length ? JSON.stringify(epp) : null;

  await run(
    `UPDATE snipe_targets
       SET last_epp = $2, last_whois_at = NOW(), whois_fails = $3, expiration_date = $4, updated_at = NOW()
     WHERE id = $1`,
    [t.id, eppJson, fails, expiration],
  );

  if (release) {
    await recordProbe(t.id, "whois", "maybe_free", `epp=${epp.length} codes`, elapsed);
  } else if (epp.length) {
    await recordProbe(t.id, "whois", "registered", `epp=${epp.join(",")}`, elapsed);
  } else {
    await recordProbe(t.id, "whois", "registered", "lookup ok, no release signal", elapsed);
  }

  return { release, epp, expiration, whoisFails: fails };
}

// ── Create + settle ──────────────────────────────────────────────────────────

async function settleCreate(
  t: SnipeTargetRow,
  opeId: string | undefined,
  price: number | null,
  snapshot: Record<string, unknown>,
): Promise<TargetOutcome> {
  if (!opeId) {
    await recordAttempt({
      targetId: t.id,
      checkAvailable: true,
      paramsSnapshot: snapshot,
      outcome: "unknown_pending",
      price,
    });
    await run(
      `UPDATE snipe_targets SET status = 'failed', fail_reason = 'create returned no ope id', updated_at = NOW() WHERE id = $1`,
      [t.id],
    );
    await notifyUnknownPending(t, undefined);
    return "unknown_pending";
  }

  await run(`UPDATE snipe_targets SET netim_ope_id = $2, updated_at = NOW() WHERE id = $1`, [t.id, opeId]);

  // Poll the operation to confirm the final outcome.
  let status: "done" | "pending" | "error" = "pending";
  for (let i = 0; i < OPE_POLLS; i++) {
    if (i > 0) await sleep(OPE_POLL_INTERVAL_MS);
    const st = await netimQueryOpe(opeId);
    if (!st) continue;
    status = st.status;
    if (status !== "pending") break;
  }

  if (status === "done") {
    await recordAttempt({
      targetId: t.id,
      checkAvailable: true,
      paramsSnapshot: snapshot,
      netimResponse: opeId,
      opeId,
      outcome: "succeeded",
      price,
    });
    await run(
      `UPDATE snipe_targets
         SET status = 'succeeded', registered_at = NOW(), final_price = $2, updated_at = NOW()
       WHERE id = $1`,
      [t.id, price],
    );
    await notifySuccess(t, opeId, price);
    return "succeeded";
  }

  if (status === "error") {
    await recordAttempt({
      targetId: t.id,
      checkAvailable: true,
      paramsSnapshot: snapshot,
      netimResponse: opeId,
      opeId,
      outcome: "failed_permanent",
      price,
    });
    await run(
      `UPDATE snipe_targets SET status = 'failed', fail_reason = 'netim operation failed', updated_at = NOW() WHERE id = $1`,
      [t.id],
    );
    await notifyFailed(t, "Netim 操作失败（queryOpe）", "failed_permanent");
    return "failed_permanent";
  }

  // Still pending after all polls → unknown; flag for manual review.
  await recordAttempt({
    targetId: t.id,
    checkAvailable: true,
    paramsSnapshot: snapshot,
    netimResponse: opeId,
    opeId,
    outcome: "unknown_pending",
    price,
  });
  await run(
    `UPDATE snipe_targets SET status = 'failed', fail_reason = 'ope_unknown', updated_at = NOW() WHERE id = $1`,
    [t.id],
  );
  await notifyUnknownPending(t, opeId);
  return "unknown_pending";
}

// ── Probe pipeline ───────────────────────────────────────────────────────────

async function probeTarget(t: SnipeTargetRow): Promise<TargetOutcome> {
  // 1. WHOIS quick check + ETA refresh.
  const whois = await refreshWhois(t);

  // A target that has gone back to "registered" after a release (someone beat
  // us to it) stays armed and waits for the next probe.
  if (!whois.release) {
    if (whois.whoisFails >= MAX_WHOIS_FAILS) {
      // Warn once via a failed-outcome attempt (no create involved).
      logger.warn(`[snipe] ${t.domain}: whois failing ${whois.whoisFails}× in a row`);
    }
    return "still_registered";
  }

  // 2. Authoritative availability from Netim.
  const started = Date.now();
  const check = await netimDomainCheck(t.domain);
  const checkLatency = Date.now() - started;

  if (!check) {
    await recordProbe(t.id, "netim_check", "error", "netim unavailable", checkLatency);
    return "error";
  }

  await recordProbe(
    t.id,
    "netim_check",
    check.available ? "available" : "not_available",
    check.reason || null,
    checkLatency,
  );

  if (!check.available) return "not_available";

  // 3. Pre-registration budget guard: live price + balance.
  const price = await netimQueryDomainPrice(t.domain);
  const account = await netimQueryResellerAccount();
  const livePrice = price?.price ?? null;

  if (t.max_price !== null && livePrice !== null && livePrice > t.max_price) {
    await run(
      `UPDATE snipe_targets SET notes = COALESCE(notes || E'\n', '') || $2, updated_at = NOW() WHERE id = $1`,
      [t.id, `budget_skip: 注册价 € ${livePrice} > 上限 € ${t.max_price}`],
    );
    await recordProbe(t.id, "netim_check", "available", "budget_skip", null);
    return "budget_skip";
  }

  if (account && livePrice !== null && account.balance < livePrice) {
    await run(
      `UPDATE snipe_targets SET status = 'blocked_balance', est_price = $2, updated_at = NOW() WHERE id = $1`,
      [t.id, livePrice],
    );
    await notifyRecharge(t, account.balance, livePrice);
    return "blocked_balance";
  }

  // 4. CAS: armed → sniping. Only one process may pass this gate.
  const claimed = await one<SnipeTargetRow>(
    `UPDATE snipe_targets SET status = 'sniping', updated_at = NOW()
     WHERE id = $1 AND status = 'armed' RETURNING *`,
    [t.id],
  );
  if (!claimed) {
    await recordProbe(t.id, "netim_check", "available", "cas_lost (concurrent)", null);
    return "claimed_skipped";
  }

  // 5. Snapshot registrar defaults (no credentials) for the audit trail.
  const snapshot = await defaultsSnapshot();

  if (isDryRun()) {
    await recordAttempt({
      targetId: t.id,
      checkAvailable: true,
      paramsSnapshot: snapshot,
      netimResponse: "[dry_run] domainCreate not issued",
      outcome: "dry_run",
      price: livePrice,
    });
    await run(
      `UPDATE snipe_targets SET status = 'armed', updated_at = NOW() WHERE id = $1`,
      [t.id],
    );
    logger.info(`[snipe] DRY-RUN would create ${t.domain} (~€ ${livePrice ?? "?"})`);
    return "dry_run";
  }

  // 6. Create with transient-failure backoff.
  let createResult: Awaited<ReturnType<typeof netimDomainCreate>> = null;
  for (let attempt = 0; attempt <= CREATE_RETRY_BACKOFFS_MS.length; attempt++) {
    createResult = await netimDomainCreate(t.domain, 1);
    if (!createResult) break; // total network failure → treated as transient
    if (createResult.ok) break;
    if (createResult.transient && attempt < CREATE_RETRY_BACKOFFS_MS.length) {
      await sleep(CREATE_RETRY_BACKOFFS_MS[attempt]);
      continue;
    }
    break;
  }

  // 7. Settle outcome.
  if (!createResult || (!createResult.ok && createResult.transient)) {
    const reason = createResult?.reason ?? "network/timeout";
    await recordAttempt({
      targetId: t.id,
      checkAvailable: true,
      paramsSnapshot: snapshot,
      netimResponse: reason,
      outcome: "failed_transient",
      price: livePrice,
    });
    await run(
      `UPDATE snipe_targets SET status = 'armed', fail_reason = $2, updated_at = NOW() WHERE id = $1`,
      [t.id, `transient: ${reason}`],
    );
    logger.warn(`[snipe] ${t.domain}: transient create failure (${reason}), back to armed`);
    return "failed_transient";
  }

  if (!createResult.ok) {
    await recordAttempt({
      targetId: t.id,
      checkAvailable: true,
      paramsSnapshot: snapshot,
      netimResponse: createResult.reason ?? "refused",
      outcome: "failed_permanent",
      price: livePrice,
    });
    await run(
      `UPDATE snipe_targets SET status = 'failed', fail_reason = $2, updated_at = NOW() WHERE id = $1`,
      [t.id, createResult.reason ?? "refused"],
    );
    await notifyFailed(t, createResult.reason ?? "refused", "failed_permanent");
    return "failed_permanent";
  }

  // createResult.ok — settle via ope polling.
  return settleCreate(t, createResult.opeId, livePrice, snapshot);
}

// ── Entry points ─────────────────────────────────────────────────────────────

async function runProbe(mode: "daily" | "hunt"): Promise<ProbeSummary> {
  let rows: SnipeTargetRow[];
  if (mode === "hunt") {
    const now = new Date().toISOString();
    rows = await many<SnipeTargetRow>(
      `SELECT * FROM snipe_targets
       WHERE status IN ('armed','blocked_balance')
         AND hunt_start IS NOT NULL AND hunt_start <= $1
         AND hunt_end IS NOT NULL AND hunt_end >= $1
       ORDER BY created_at ASC`,
      [now],
    );
  } else {
    rows = await many<SnipeTargetRow>(
      `SELECT * FROM snipe_targets WHERE status = ANY($1::text[]) ORDER BY created_at ASC`,
      [ACTIVE_STATUSES],
    );
  }

  const results: ProbeResultEntry[] = [];

  for (const row of rows) {
    // Daily mode refreshes ETA before probing; hunt window targets keep theirs.
    if (mode === "daily") {
      const eta = await computeDropEta(row.domain, row.expiration_date);
      const win = makeHuntWindow(eta);
      await run(
        `UPDATE snipe_targets
           SET drop_eta = $2, hunt_start = $3, hunt_end = $4, updated_at = NOW()
         WHERE id = $1`,
        [row.id, eta, win.huntStart, win.huntEnd],
      );
    }

    // Try to claim; skip when another process owns this target right now.
    const claimed = await claimTarget(row.id);
    if (!claimed) {
      results.push({ id: row.id, outcome: "claimed_skipped" });
      continue;
    }

    try {
      // Daily mode re-arms (balance/price) before the release check so the
      // target is ready the moment the hunt window opens. A target that stays
      // blocked on balance is reported here and skipped for this run.
      if (mode === "daily" && ["watching", "blocked_balance"].includes(claimed.status)) {
        const precheck = await armPrecheck(claimed);
        if (precheck === "blocked_balance") {
          results.push({ id: row.id, outcome: "blocked_balance" });
          continue;
        }
      }
      const outcome = await probeTarget(claimed);
      results.push({ id: row.id, outcome });
    } catch (e) {
      logger.error(`[snipe] ${claimed.domain} probe error:`, (e as Error).message);
      results.push({ id: row.id, outcome: "error" });
    } finally {
      await releaseLock(row.id);
    }
  }

  return { mode, checked: results.length, results, dryRun: isDryRun() };
}

export async function runDailyProbe(): Promise<ProbeSummary> {
  return runProbe("daily");
}

export async function runHuntProbe(): Promise<ProbeSummary> {
  return runProbe("hunt");
}
