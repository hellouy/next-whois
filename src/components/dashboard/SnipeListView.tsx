import React from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine, RiCloseLine,
  RiArrowRightSLine, RiLink, RiScanLine, RiWalletLine,
  RiCheckboxCircleLine, RiCloseCircleLine, RiArrowDownSLine,
} from "@remixicon/react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import type { UserSnipeTargetDto } from "@/pages/api/user/snipe-targets";
import {
  SNIPE_STATUS_META, SNIPE_FILTERS, SNIPE_BALANCE_SYM,
  type SnipeFilter,
} from "./snipe-status";

export type SnipeListViewProps = {
  targets: UserSnipeTargetDto[];
  loadingTargets: boolean;
  errorTargets: boolean;
  filter: SnipeFilter;
  search: string;
  onRefresh: () => void;
  onFilterChange: (f: SnipeFilter) => void;
  onSearch: (q: string) => void;
  onDisable: (domain: string) => void;
};

function formatCents(cents: number | null | undefined): string {
  return ((cents ?? 0) / 100).toFixed(2);
}

export function SnipeListView({
  targets, loadingTargets, errorTargets, filter, search,
  onRefresh, onFilterChange, onSearch, onDisable,
}: SnipeListViewProps) {
  const router = useRouter();

  const openDetail = (domain: string) => {
    router.push(`/snipe/${encodeURIComponent(domain)}`);
  };

  return (
    <div className="space-y-3">
      {/* Filter chips + search + refresh */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex flex-wrap gap-1.5">
            {SNIPE_FILTERS.map(f => (
              <button
                key={f.key}
                type="button"
                onClick={() => onFilterChange(f.key)}
                className={cn(
                  "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-colors min-h-[24px]",
                  filter === f.key
                    ? "bg-violet-100 dark:bg-violet-900/50 text-violet-800 dark:text-violet-300 border-violet-400/60"
                    : "bg-muted/40 text-muted-foreground border-border hover:border-violet-300/50 hover:text-foreground"
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={onRefresh}
            disabled={loadingTargets}
            className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground transition-colors disabled:opacity-50 min-h-[32px] min-w-[32px] flex items-center justify-center"
            title="刷新"
          >
            <RiLoader4Line className={cn("w-3.5 h-3.5", loadingTargets && "animate-spin")} />
          </button>
        </div>

        {/* Search */}
        <div className="relative">
          <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
          <input
            type="text"
            value={search}
            onChange={e => onSearch(e.target.value)}
            placeholder="搜索域名..."
            className="w-full h-9 pl-9 pr-8 rounded-xl border border-border bg-muted/30 text-xs focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition"
          />
          {search && (
            <button onClick={() => onSearch("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground">
              <RiCloseLine className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Loading skeletons */}
      {loadingTargets && (
        <div className="space-y-2">
          {[1, 2, 3].map(i => (
            <div key={i} className="glass-panel border border-border rounded-2xl p-3.5 space-y-2 animate-pulse">
              <div className="h-4 w-1/2 rounded bg-muted/40" />
              <div className="h-3 w-3/4 rounded bg-muted/40" />
              <div className="h-1.5 w-full rounded bg-muted/30" />
            </div>
          ))}
        </div>
      )}

      {/* Error state */}
      {!loadingTargets && errorTargets && (
        <div className="glass-panel border border-red-200/60 dark:border-red-800/40 rounded-2xl p-6 text-center space-y-3">
          <RiCloseCircleLine className="w-8 h-8 text-red-400 mx-auto" />
          <p className="text-xs text-muted-foreground">抢注列表加载失败，请重试</p>
          <Button size="sm" onClick={onRefresh} className="h-9 rounded-xl text-xs">
            <RiRefreshLine className="w-3.5 h-3.5" />重试
          </Button>
        </div>
      )}

      {/* Empty state */}
      {!loadingTargets && !errorTargets && targets.length === 0 && (
        <div className="glass-panel border border-border rounded-2xl p-8 text-center space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-violet-50 dark:bg-violet-950/30 border border-violet-200/60 dark:border-violet-700/40 flex items-center justify-center mx-auto">
            <RiScanLine className="w-5 h-5 text-violet-500" />
          </div>
          <div className="space-y-1">
            <p className="text-sm font-bold">还没有抢注预定</p>
            <p className="text-xs text-muted-foreground leading-relaxed max-w-[240px] mx-auto">
              在查询页设置到期提醒并勾选"同时预定抢注"，即可冻结余额抢占域名
            </p>
          </div>
          <Link href="/">
            <Button size="sm" className="h-9 rounded-xl text-xs gap-1.5">
              <RiScanLine className="w-3.5 h-3.5" />去查询页抢注
            </Button>
          </Link>
        </div>
      )}

      {/* Target cards */}
      {!loadingTargets && !errorTargets && targets.map(target => {
        const meta = SNIPE_STATUS_META[target.status] ?? { label: target.status, cls: "bg-muted text-muted-foreground", dot: "bg-muted" };
        const frozenPct = target.serviceCents
          ? Math.min(100, Math.round((target.frozenCents / target.serviceCents) * 100))
          : 0;
        const shortfall = (target.serviceCents ?? 0) - target.frozenCents;
        const isBlocked = target.status === "blocked_balance";

        return (
          <div
            key={target.id}
            role="button"
            tabIndex={0}
            onClick={() => openDetail(target.domain)}
            onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDetail(target.domain); } }}
            className="glass-panel border border-border rounded-2xl overflow-hidden transition-all hover:border-primary/40 active:scale-[0.99] cursor-pointer"
          >
            <div className="p-3.5 space-y-2.5">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-violet-100 dark:bg-violet-950/40 flex items-center justify-center shrink-0">
                  <RiScanLine className="w-3.5 h-3.5 text-violet-600 dark:text-violet-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-sm font-semibold truncate">{target.domain}</span>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded flex items-center gap-1 font-semibold border", meta.cls)}>
                      <span className={cn("w-1 h-1 rounded-full", meta.dot)} />
                      {meta.label}
                    </span>
                    {target.hasSubscription && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400 font-semibold border border-sky-300/50 flex items-center gap-0.5">
                        <RiLink className="w-2.5 h-2.5" />有关联订阅
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  {target.hasSubscription && (
                    <Link
                      href="/dashboard?tab=subscriptions"
                      onClick={e => e.stopPropagation()}
                      className="p-1.5 min-w-[36px] min-h-[36px] flex items-center justify-center rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-primary"
                      title="管理订阅"
                    >
                      <RiLink className="w-3.5 h-3.5" />
                    </Link>
                  )}
                </div>
              </div>

              {/* Freeze progress */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-muted-foreground">
                    冻结 {SNIPE_BALANCE_SYM}{formatCents(target.frozenCents)}
                    <span className="text-muted-foreground/50"> / 服务价 {SNIPE_BALANCE_SYM}{formatCents(target.serviceCents)}</span>
                  </span>
                  <span className="text-muted-foreground tabular-nums">{frozenPct}%</span>
                </div>
                <div className="w-full h-1 rounded-full bg-muted overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all",
                      isBlocked ? "bg-amber-500" : frozenPct >= 100 ? "bg-emerald-500" : "bg-violet-500")}
                    style={{ width: `${frozenPct}%` }}
                  />
                </div>
              </div>

              {/* Status caption */}
              {isBlocked ? (
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] text-amber-600 dark:text-amber-400 flex items-center gap-1">
                    <RiWalletLine className="w-3 h-3 shrink-0" />
                    需充值 {SNIPE_BALANCE_SYM}{formatCents(Math.max(0, shortfall))} 后开始抢占
                  </p>
                  <Link href="/payment/checkout" onClick={e => e.stopPropagation()}>
                    <Button size="sm" className="h-7 rounded-lg px-2 text-[11px] bg-amber-500 hover:bg-amber-600 text-white">
                      去充值
                    </Button>
                  </Link>
                </div>
              ) : (
                <p className="text-[11px] text-muted-foreground">
                  {target.status === "armed" && "冻结完成 · 等待竞速期开始"}
                  {target.status === "watching" && "正在等待参与竞速"}
                  {target.status === "sniping" && "竞速进行中 · 系统正在抢注"}
                  {target.status === "succeeded" && "抢注成功 · 域名已注册"}
                  {target.status === "failed" && (target.failReason ? `抢注失败 · ${target.failReason}` : "抢注失败")}
                  {target.status === "cancelled" && "已取消 · 冻结金额已退还"}
                  {target.status === "paused" && "已暂停"}
                </p>
              )}

              {/* Footer row */}
              <div className="flex items-center justify-between pt-0.5">
                <span className="text-[10px] text-muted-foreground/60">
                  预定于 {new Date(target.createdAt).toLocaleDateString()}
                </span>
                {target.status === "armed" || target.status === "blocked_balance" || target.status === "sniping" ? (
                  <button
                    type="button"
                    onClick={e => { e.stopPropagation(); onDisable(target.domain); }}
                    className="text-[10px] text-muted-foreground hover:text-red-500 px-1.5 py-1 min-h-[28px] rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors"
                  >
                    停用
                  </button>
                ) : (
                  <span className="text-[10px] text-muted-foreground/50 flex items-center gap-0.5">
                    查看详情 <RiArrowRightSLine className="w-3 h-3" />
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}