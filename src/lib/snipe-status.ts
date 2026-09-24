/**
 * Canonical Chinese labels for snipe-target statuses.
 *
 * Shared by the server (email copy in snipe-engine) and the dashboard/admin
 * UIs so every surface renders identical wording instead of raw enum values
 * such as `blocked_balance`.
 */
export const SNIPE_STATUS_LABELS: Record<string, string> = {
  watching: "观察中",
  armed: "已就绪",
  blocked_balance: "余额不足",
  sniping: "抢注中",
  succeeded: "已注册",
  failed: "失败",
  cancelled: "已取消",
  paused: "已暂停",
};

export function snipeStatusLabel(status: string): string {
  return SNIPE_STATUS_LABELS[status] ?? status;
}

/**
 * Human-readable Chinese explanation for a snipe target's `fail_reason`.
 * The engine stores raw technical markers (e.g. `netim operation failed`,
 * `transient: timeout`); users should never see those directly.
 */
const SNIPE_FAIL_REASON_LABELS: Array<[RegExp, string]> = [
  [/no ope id/i, "注册接口未返回受理编号，抢注未成功"],
  [/netim operation failed/i, "注册商受理失败，抢注未成功"],
  [/ope_unknown/i, "注册结果未知，请留意后续通知"],
  [/hold_short/i, "余额不足，冻结失败"],
  [/^transient:/i, "网络波动导致抢注中断，系统将自动重试"],
  [/refused|rejected|denied/i, "注册商拒绝了本次注册"],
  [/already regist|unavailable|taken/i, "域名已被他人注册"],
  [/timeout|network/i, "网络超时，系统将自动重试"],
];

export function snipeFailReasonLabel(reason: string | null | undefined): string | null {
  if (!reason) return null;
  // Already a human message (contains CJK) — show as-is.
  if (/[\u4e00-\u9fff]/.test(reason)) return reason;
  for (const [re, label] of SNIPE_FAIL_REASON_LABELS) {
    if (re.test(reason)) return label;
  }
  return "抢注未成功，如已扣费将自动解冻";
}

