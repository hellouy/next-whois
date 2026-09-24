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
