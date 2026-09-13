/**
 * Shared user-facing snipe target status visuals. Mirrors the admin badge set
 * (STATUS_META) so list and detail views render identical Chinese labels.
 */

export const SNIPE_STATUS_META: Record<string, { label: string; cls: string; dot: string }> = {
  watching:        { label: "观察中",       cls: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300", dot: "bg-gray-400" },
  armed:           { label: "已就绪",       cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300", dot: "bg-emerald-500" },
  blocked_balance: { label: "余额不足",     cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300", dot: "bg-amber-500" },
  sniping:         { label: "抢注中",       cls: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300", dot: "bg-blue-500" },
  succeeded:       { label: "已注册",       cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300", dot: "bg-emerald-500" },
  failed:          { label: "失败",         cls: "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300", dot: "bg-rose-500" },
  cancelled:       { label: "已取消",       cls: "bg-gray-200 text-gray-600 dark:bg-gray-800 dark:text-gray-400", dot: "bg-gray-400" },
  paused:          { label: "已暂停",       cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300", dot: "bg-amber-500" },
};

export const SNIPE_ACTIVE_STATUSES = ["armed", "blocked_balance", "sniping"];

export type SnipeFilter = "all" | "armed" | "blocked_balance" | "sniping" | "ended";

export const SNIPE_FILTERS: { key: SnipeFilter; label: string }[] = [
  { key: "all", label: "全部" },
  { key: "armed", label: "竞速中" },
  { key: "blocked_balance", label: "待充值" },
  { key: "sniping", label: "抢注中" },
  { key: "ended", label: "已结束" },
];

export const SNIPE_BALANCE_SYM = "¥";

export function getSnipeStatusMeta(status: string): { label: string; cls: string; dot: string } {
  return SNIPE_STATUS_META[status] ?? {
    label: status,
    cls: "bg-muted text-muted-foreground border-border/50",
    dot: "bg-muted",
  };
}

export function isSnipeActive(status: string): boolean {
  return SNIPE_ACTIVE_STATUSES.includes(status);
}