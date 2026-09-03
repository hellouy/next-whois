import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiCheckLine, RiErrorWarningLine,
  RiFilterLine, RiDatabase2Line, RiSignalWifiLine,
  RiDeleteBin2Line, RiUserLine, RiGhostLine,
} from "@remixicon/react";
import type { QueryLogRow, QueryLogResponse, QueryLogStats } from "@/pages/api/admin/query-logs";

const STATUS_OPTIONS = [
  { value: "all",  label: "全部" },
  { value: "ok",   label: "成功" },
  { value: "fail", label: "失败" },
];
const USER_TYPE_OPTIONS = [
  { value: "all",    label: "全部用户" },
  { value: "anon",   label: "匿名用户" },
  { value: "logged", label: "登录用户" },
];
const HOURS_OPTIONS = [
  { value: "1",   label: "过去 1 小时" },
  { value: "6",   label: "过去 6 小时" },
  { value: "24",  label: "过去 24 小时" },
  { value: "72",  label: "过去 3 天" },
  { value: "168", label: "过去 7 天" },
];

function fmtAge(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const secs  = Math.floor(diff / 1000);
  const mins  = Math.floor(secs / 60);
  const hours = Math.floor(mins / 60);
  if (secs < 60)   return `${secs}s 前`;
  if (mins < 60)   return `${mins}m 前`;
  if (hours < 24)  return `${hours}h 前`;
  return new Date(iso).toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function fmtDuration(ms: number): string {
  if (ms < 1000)  return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="glass-panel rounded-xl border border-border/50 p-4">
      <p className="text-[11px] text-muted-foreground mb-1 tracking-wide">{label}</p>
      <p className={cn("text-2xl font-semibold tabular-nums", accent)}>{value}</p>
      {sub && <p className="text-[11px] text-muted-foreground mt-0.5">{sub}</p>}
    </div>
  );
}

function ErrorCodeBadge({ code }: { code: string | null }) {
  if (!code) return null;
  const short = code.length > 30 ? code.slice(0, 30) + "…" : code;
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 border border-red-200/40 dark:border-red-800/40 max-w-[180px] truncate" title={code}>
      {short}
    </span>
  );
}

export default function QueryLogsPage() {
  const [rows, setRows]         = React.useState<QueryLogRow[]>([]);
  const [stats, setStats]       = React.useState<QueryLogStats | null>(null);
  const [totalCount, setTotal]  = React.useState(0);
  const [loading, setLoading]   = React.useState(false);
  const [autoRefresh, setAuto]  = React.useState(false);
  const [tldFilter, setTld]     = React.useState("");
  const [statusFilter, setStatus] = React.useState("all");
  const [userTypeFilter, setUserType] = React.useState("all");
  const [hoursFilter, setHours] = React.useState("24");
  const [page, setPage]         = React.useState(1);
  const timerRef                = React.useRef<ReturnType<typeof setInterval> | null>(null);

  const load = React.useCallback(async (pg = page) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        tld: tldFilter.trim(),
        status: statusFilter,
        user_type: userTypeFilter,
        hours: hoursFilter,
        page: String(pg),
        limit: "100",
      });
      const r = await fetch(`/api/admin/query-logs?${params}`);
      if (!r.ok) throw new Error(await r.text());
      const data: QueryLogResponse = await r.json();
      setRows(data.rows);
      setStats(data.stats);
      setTotal(data.total_count);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [tldFilter, statusFilter, userTypeFilter, hoursFilter, page]);

  React.useEffect(() => { load(1); setPage(1); }, [tldFilter, statusFilter, userTypeFilter, hoursFilter]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => { load(page); }, [page]); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (autoRefresh) timerRef.current = setInterval(() => load(page), 15_000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoRefresh, load, page]);

  const totalPages = Math.max(1, Math.ceil(totalCount / 100));

  return (
    <AdminLayout title="查询日志">
      <div className="space-y-5">

        {/* Stats bar */}
        {stats && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatCard label="总查询数" value={stats.total.toLocaleString()} />
            <StatCard
              label="登录用户查询"
              value={stats.logged.toLocaleString()}
              sub={stats.total > 0 ? `占比 ${Math.round(stats.logged / stats.total * 100)}%` : undefined}
              accent="text-primary"
            />
            <StatCard
              label="匿名用户查询"
              value={stats.anonymous.toLocaleString()}
              sub={stats.total > 0 ? `占比 ${Math.round(stats.anonymous / stats.total * 100)}%` : undefined}
              accent="text-muted-foreground"
            />
            <StatCard
              label="失败次数"
              value={stats.errors.toLocaleString()}
              sub={`错误率 ${stats.error_rate}%`}
              accent={stats.errors > 0 ? "text-red-500" : undefined}
            />
            <StatCard
              label="缓存命中"
              value={stats.cached.toLocaleString()}
              sub={stats.total > 0 ? `命中率 ${Math.round(stats.cached / stats.total * 100)}%` : undefined}
              accent="text-blue-500"
            />
            <StatCard
              label="平均耗时"
              value={fmtDuration(stats.avg_duration_ms)}
              accent={stats.avg_duration_ms > 5000 ? "text-amber-500" : undefined}
            />
          </div>
        )}

        {/* Filter bar */}
        <div className="glass-panel rounded-xl border border-border/50 p-4 flex flex-wrap items-end gap-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <RiFilterLine className="w-3.5 h-3.5" />
            <span>筛选</span>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-muted-foreground">TLD</label>
            <input
              value={tldFilter}
              onChange={e => setTld(e.target.value)}
              placeholder="com, net, org…"
              className="h-8 px-2.5 text-xs rounded-lg border border-border/60 bg-background w-28 focus:outline-none focus:ring-1 focus:ring-primary/40"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-muted-foreground">状态</label>
            <select
              value={statusFilter}
              onChange={e => setStatus(e.target.value)}
              className="h-8 px-2 text-xs rounded-lg border border-border/60 bg-background focus:outline-none focus:ring-1 focus:ring-primary/40"
            >
              {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-muted-foreground">用户类型</label>
            <select
              value={userTypeFilter}
              onChange={e => setUserType(e.target.value)}
              className="h-8 px-2 text-xs rounded-lg border border-border/60 bg-background focus:outline-none focus:ring-1 focus:ring-primary/40"
            >
              {USER_TYPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-muted-foreground">时间范围</label>
            <select
              value={hoursFilter}
              onChange={e => setHours(e.target.value)}
              className="h-8 px-2 text-xs rounded-lg border border-border/60 bg-background focus:outline-none focus:ring-1 focus:ring-primary/40"
            >
              {HOURS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="flex items-center gap-2 ml-auto">
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer select-none">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={e => setAuto(e.target.checked)}
                className="accent-primary"
              />
              自动刷新 (15s)
            </label>
            <button
              onClick={() => load(page)}
              disabled={loading}
              className="h-8 px-3 text-xs rounded-lg border border-border/60 bg-background hover:bg-muted/50 transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              {loading
                ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                : <RiRefreshLine className="w-3.5 h-3.5" />}
              刷新
            </button>
          </div>
        </div>

        {/* Log table */}
        <div className="glass-panel rounded-xl border border-border/50 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium w-8">#</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">域名</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">查询者</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">TLD</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">状态</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">耗时</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">来源</th>
                  <th className="px-4 py-2.5 text-left text-[10px] text-muted-foreground font-medium">错误码</th>
                  <th className="px-4 py-2.5 text-right text-[10px] text-muted-foreground font-medium">时间</th>
                </tr>
              </thead>
              <tbody>
                {loading && rows.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="text-center py-12 text-muted-foreground">
                      <RiLoader4Line className="w-5 h-5 animate-spin mx-auto mb-2" />
                      <p className="text-xs">加载中…</p>
                    </td>
                  </tr>
                ) : rows.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="text-center py-12 text-muted-foreground">
                      <RiDatabase2Line className="w-5 h-5 mx-auto mb-2 opacity-40" />
                      <p className="text-xs">暂无查询日志</p>
                      <p className="text-[10px] mt-1 opacity-60">进行一次域名查询后数据将显示在这里</p>
                    </td>
                  </tr>
                ) : (
                  rows.map((row, i) => (
                    <tr
                      key={row.id}
                      className={cn(
                        "border-b border-border/20 transition-colors hover:bg-muted/20",
                        !row.success && "bg-red-50/30 dark:bg-red-950/10",
                      )}
                    >
                      <td className="px-4 py-2 text-muted-foreground/40 tabular-nums">
                        {(page - 1) * 100 + i + 1}
                      </td>
                      <td className="px-4 py-2 font-mono text-foreground/80 max-w-[180px] truncate" title={row.domain}>
                        {row.domain}
                      </td>
                      <td className="px-4 py-2 max-w-[180px] truncate">
                        {row.user_email ? (
                          <span className="inline-flex items-center gap-1 text-[11px] text-foreground/80" title={row.user_email}>
                            <RiUserLine className="w-3 h-3 shrink-0 text-primary/70" />
                            <span className="truncate">{row.user_email}</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground" title={row.ip ? `IP ${row.ip}` : undefined}>
                            <RiGhostLine className="w-3 h-3 shrink-0" />
                            匿名{row.ip ? ` · ${row.ip.slice(0, 40)}` : ""}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <span className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-mono bg-muted/60 text-muted-foreground">
                          .{row.tld}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <span className={cn(
                          "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium",
                          row.success
                            ? "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400"
                            : "bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400",
                        )}>
                          {row.success
                            ? <><RiCheckLine className="w-3 h-3" />{row.cached ? "缓存" : "成功"}</>
                            : <><RiErrorWarningLine className="w-3 h-3" />失败</>}
                        </span>
                      </td>
                      <td className="px-4 py-2 tabular-nums text-muted-foreground">
                        <span className={cn(
                          row.duration_ms > 5000 ? "text-amber-500" :
                          row.duration_ms > 2000 ? "text-yellow-500/80" :
                          "text-muted-foreground"
                        )}>
                          {fmtDuration(row.duration_ms)}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        {row.source ? (
                          <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground">
                            <RiSignalWifiLine className="w-3 h-3" />
                            {row.source}
                          </span>
                        ) : <span className="text-muted-foreground/30">—</span>}
                      </td>
                      <td className="px-4 py-2">
                        <ErrorCodeBadge code={row.error_code} />
                      </td>
                      <td className="px-4 py-2 text-right text-muted-foreground/60 whitespace-nowrap">
                        <span title={new Date(row.created_at).toLocaleString("zh-CN")}>
                          {fmtAge(row.created_at)}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border/30 bg-muted/10">
              <span className="text-[11px] text-muted-foreground">
                共 {totalCount.toLocaleString()} 条 · 第 {page}/{totalPages} 页
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page <= 1 || loading}
                  className="h-7 px-2.5 text-xs rounded border border-border/50 hover:bg-muted/50 disabled:opacity-40 transition-colors"
                >
                  上一页
                </button>
                <button
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages || loading}
                  className="h-7 px-2.5 text-xs rounded border border-border/50 hover:bg-muted/50 disabled:opacity-40 transition-colors"
                >
                  下一页
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer note */}
        <p className="text-[11px] text-muted-foreground/50 text-center">
          <RiDeleteBin2Line className="w-3 h-3 inline mr-1" />
          日志自动保留最近 30 天（写入时抽样清理过期记录）。记录在响应返回前落库，单查、流式与批量接口的匿名及登录查询均包含在内；历史遗留行无查询者信息，归入匿名统计。
        </p>

      </div>
    </AdminLayout>
  );
}
