/**
 * Shared user-facing snipe target status visuals. Labels come from the
 * canonical map in @/lib/snipe-status so list, detail, admin and email views
 * render identical Chinese wording.
 */
import { SNIPE_STATUS_LABELS } from "@/lib/snipe-status";

export const SNIPE_STATUS_META: Record<string, { label: string; cls: string; dot: string }> = {
  watching:        { label: SNIPE_STATUS_LABELS.watching,        cls: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300", dot: "bg-gray-400" },
  armed:           { label: SNIPE_STATUS_LABELS.armed,           cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300", dot: "bg-emerald-500" },
  blocked_balance: { label: SNIPE_STATUS_LABELS.blocked_balance, cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300", dot: "bg-amber-500" },
  sniping:         { label: SNIPE_STATUS_LABELS.sniping,         cls: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300", dot: "bg-blue-500" },
  succeeded:       { label: SNIPE_STATUS_LABELS.succeeded,       cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300", dot: "bg-emerald-500" },
  failed:          { label: SNIPE_STATUS_LABELS.failed,          cls: "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300", dot: "bg-rose-500" },
  cancelled:       { label: SNIPE_STATUS_LABELS.cancelled,       cls: "bg-gray-200 text-gray-600 dark:bg-gray-800 dark:text-gray-400", dot: "bg-gray-400" },
  paused:          { label: SNIPE_STATUS_LABELS.paused,          cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300", dot: "bg-amber-500" },
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