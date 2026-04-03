import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine, RiDeleteBin2Line,
  RiGlobalLine, RiCheckboxCircleLine, RiTimeLine, RiBarChartLine,
  RiCalendarLine, RiArrowLeftLine, RiArrowRightLine, RiUserLine,
  RiFireLine, RiAlertLine, RiFlashlightLine, RiExternalLinkLine,
  RiGhostLine, RiDeleteBinLine, RiCloseLine, RiGroupLine, RiDatabase2Line,
  RiRepeatLine,
} from "@remixicon/react";

// One row = one UNIQUE domain (deduplicated across all users)
type SearchRecord = {
  query: string;
  queryType: string;
  regStatus: string;
  expirationDate: string | null;
  remainingDays: number | null;
  valueTier: string;
  lastSearchedAt: string;
  searchCount: number;        // total times any user searched this domain
  uniqueLoggedUsers: number;  // distinct logged-in users
  lastWasAnon: boolean;       // most recent search was anonymous
  lastUserEmail: string | null;
  lastUserName: string | null;
};

type PageData = {
  records: SearchRecord[];
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
  stats: {
    all: number;        // unique domains
    today: number;      // unique domains searched today
    totalEvents: number; // raw event count (all inserts)
    available: number; expiring: number; highValue: number;
    registered: number; anonymous: number; logged: number;
    uniqueUsers: number;
  };
  dailyStats: { day: string; count: number; available: number; registered: number; anon: number; logged: number }[];
  topByType: { type: string; count: number }[];
  topQueries: { query: string; type: string; count: number }[];
  topUsers: { email: string; name: string | null; count: number }[];
  topTlds: { tld: string; count: number }[];
};

type FilterType = "all" | "available" | "expiring" | "high_value" | "anonymous" | "logged";

const FILTERS: { key: FilterType; label: string; icon: React.ElementType; color: string }[] = [
  { key: "all",        label: "所有域名",   icon: RiSearchLine,          color: "text-blue-500" },
  { key: "logged",     label: "登录用户查询", icon: RiUserLine,           color: "text-primary" },
  { key: "anonymous",  label: "匿名查询",    icon: RiGhostLine,          color: "text-muted-foreground" },
  { key: "available",  label: "可注册",      icon: RiCheckboxCircleLine,  color: "text-emerald-500" },
  { key: "expiring",   label: "即将到期",    icon: RiAlertLine,           color: "text-orange-500" },
  { key: "high_value", label: "高价值",      icon: RiFireLine,            color: "text-violet-500" },
];

const DELETE_PERIODS: { key: string; label: string }[] = [
  { key: "yesterday",  label: "删除昨天记录" },
  { key: "day_before", label: "删除前天记录" },
  { key: "week",       label: "删除7天前记录" },
  { key: "month",      label: "删除30天前记录" },
  { key: "anonymous",  label: "清空匿名记录" },
  { key: "all",        label: "清空全部记录" },
];

function fmt(d: string) {
  const date = new Date(d);
  const now  = new Date();
  const diff = now.getTime() - date.getTime();
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (mins  < 1)  return "刚刚";
  if (mins  < 60) return `${mins}分钟前`;
  if (hours < 24) return `${hours}小时前`;
  if (days  < 7)  return `${days}天前`;
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

function regStatusBadge(status: string, remainingDays: number | null) {
  if (status === "unregistered") return (
    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold">可注册</span>
  );
  if (status === "registered") {
    if (remainingDays !== null && remainingDays <= 30)
      return <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-100 dark:bg-red-950/30 text-red-600 dark:text-red-400 font-semibold">{remainingDays}天到期</span>;
    if (remainingDays !== null && remainingDays <= 90)
      return <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 font-semibold">{remainingDays}天到期</span>;
    return <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-100 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 font-semibold">已注册</span>;
  }
  if (status === "reserved") return (
    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/30 text-amber-600 dark:text-amber-400 font-semibold">保留</span>
  );
  return <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground font-semibold">未知</span>;
}

function ValueTierBadge({ tier }: { tier: string }) {
  if (tier === "high") return (
    <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold border bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900 inline-flex items-center gap-0.5">
      <RiFlashlightLine className="w-2.5 h-2.5" />高价值
    </span>
  );
  if (tier === "valuable") return (
    <span className="text-[10px] px-1.5 py-0.5 rounded-full font-bold border bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400 border-violet-200 dark:border-violet-900">
      有价值
    </span>
  );
  return null;
}

export default function AdminSearchRecordsPage() {
  const [data, setData]               = React.useState<PageData | null>(null);
  const [loading, setLoading]         = React.useState(true);
  const [filter, setFilter]           = React.useState<FilterType>("all");
  const [page, setPage]               = React.useState(1);
  const [search, setSearch]           = React.useState("");
  const [searchInput, setSearchInput] = React.useState("");
  const [deleting, setDeleting]       = React.useState<string | null>(null);
  const [deletingRow, setDeletingRow] = React.useState<string | null>(null);
  const [showStats, setShowStats]     = React.useState(true);

  function load(f = filter, p = page, s = search) {
    setLoading(true);
    const params = new URLSearchParams({ filter: f, page: String(p) });
    if (s) params.set("search", s);
    fetch(`/api/admin/search-records?${params}`)
      .then(r => r.json())
      .then(d => { if (d.error) { toast.error(d.error); return; } setData(d); })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load(); }, []);

  function changeFilter(f: FilterType) { setFilter(f); setPage(1); load(f, 1, search); }
  function changePage(p: number)        { setPage(p); load(filter, p, search); }

  function submitSearch(e: React.FormEvent) {
    e.preventDefault();
    const s = searchInput.trim();
    setSearch(s); setPage(1); load(filter, 1, s);
  }
  function clearSearch() {
    setSearchInput(""); setSearch(""); setPage(1); load(filter, 1, "");
  }

  async function deletePeriod(period: string, label: string) {
    const confirmMsg = period === "all"
      ? "确定要清空全部查询记录吗？此操作不可撤销！"
      : period === "anonymous"
        ? "确定要清空所有匿名查询记录吗？此操作不可撤销！"
        : `确定要删除"${label}"的查询记录吗？`;
    if (!confirm(confirmMsg)) return;
    setDeleting(period);
    try {
      const res = await fetch("/api/admin/search-records", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ period }),
      });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "删除失败");
      toast.success(`已删除 ${d.deleted ?? ""} 条原始记录`);
      setPage(1); load(filter, 1, search);
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setDeleting(null);
    }
  }

  // Delete ALL records for a given domain (grouped delete)
  async function deleteRecordByQuery(query: string) {
    if (!confirm(`确定要删除"${query}"的所有查询记录吗？`)) return;
    setDeletingRow(query);
    try {
      const res = await fetch(`/api/admin/search-records?query=${encodeURIComponent(query)}`, { method: "DELETE" });
      const d = await res.json();
      if (!res.ok) throw new Error(d.error || "删除失败");
      toast.success(`已删除 ${d.deleted ?? ""} 条记录`);
      setData(prev => prev ? {
        ...prev,
        records: prev.records.filter(r => r.query !== query),
        pagination: { ...prev.pagination, total: Math.max(0, prev.pagination.total - 1) },
        stats: { ...prev.stats, all: Math.max(0, prev.stats.all - 1) },
      } : prev);
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setDeletingRow(null);
    }
  }

  const maxDaily = data?.dailyStats.length
    ? Math.max(...data.dailyStats.map(d => d.count), 1)
    : 1;

  return (
    <AdminLayout title="查询记录">
      <div className="space-y-5">

        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">查询记录管理</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              每条记录代表一个唯一域名，显示所有用户的查询汇总（用户端不可见）
              {data && (
                <span className="ml-2 text-muted-foreground/60">
                  · 独立用户 {data.stats.uniqueUsers} · 总搜索次数 {data.stats.totalEvents.toLocaleString()}
                </span>
              )}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setShowStats(s => !s)} className="rounded-xl h-9 gap-2">
              <RiBarChartLine className="w-3.5 h-3.5" />
              {showStats ? "收起统计" : "展开统计"}
            </Button>
            <Button variant="outline" size="sm" onClick={() => load()} disabled={loading} className="rounded-xl h-9 gap-2">
              {loading ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiRefreshLine className="w-3.5 h-3.5" />}
              刷新
            </Button>
          </div>
        </div>

        {/* Stats summary cards */}
        {data && (
          <div className="grid grid-cols-4 sm:grid-cols-9 gap-2">
            {[
              { label: "独立域名", value: data.stats.all,         color: "text-foreground",        title: "不同域名数量（去重）" },
              { label: "今日新增", value: data.stats.today,       color: "text-blue-500",           title: "今日搜索过的独立域名数" },
              { label: "总搜索次",  value: data.stats.totalEvents, color: "text-cyan-500",          title: "所有用户历史总搜索次数" },
              { label: "独立用户", value: data.stats.uniqueUsers, color: "text-primary",            title: "已登录的独立用户数" },
              { label: "可注册",   value: data.stats.available,   color: "text-emerald-500",        title: "当前可注册的域名数" },
              { label: "即将到期", value: data.stats.expiring,    color: "text-orange-500",         title: "90天内到期的域名数" },
              { label: "高价值",   value: data.stats.highValue,   color: "text-violet-500",         title: "高价值可用域名数" },
              { label: "匿名查询", value: data.stats.anonymous,   color: "text-muted-foreground/70", title: "匿名用户的总查询次数（每次查询均计入）" },
              { label: "已登录",   value: data.stats.logged,      color: "text-primary/70",         title: "已登录用户的总查询次数（每次查询均计入）" },
            ].map(({ label, value, color, title }) => (
              <div key={label} className="glass-panel border border-border rounded-xl p-2.5 text-center" title={title}>
                <p className={cn("text-lg font-bold tabular-nums leading-tight", color)}>{value.toLocaleString()}</p>
                <p className="text-[9px] text-muted-foreground mt-0.5 leading-tight">{label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Search bar */}
        <form onSubmit={submitSearch} className="flex gap-2">
          <div className="relative flex-1">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
            <input
              type="text"
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              placeholder="搜索域名关键词…"
              className="w-full pl-9 pr-8 h-9 rounded-xl border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary/40"
            />
            {searchInput && (
              <button type="button" onClick={clearSearch} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                <RiCloseLine className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
          <Button type="submit" size="sm" className="rounded-xl h-9 px-4 gap-1.5" disabled={loading}>
            <RiSearchLine className="w-3.5 h-3.5" />搜索
          </Button>
          {search && (
            <Button type="button" variant="outline" size="sm" className="rounded-xl h-9 gap-1.5" onClick={clearSearch}>
              <RiCloseLine className="w-3.5 h-3.5" />清除
            </Button>
          )}
        </form>
        {search && (
          <p className="text-xs text-muted-foreground -mt-2">
            搜索「{search}」，共 {data?.pagination.total ?? 0} 个匹配域名
          </p>
        )}

        {/* Statistics panel */}
        {showStats && data && (
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
              <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400">
                <RiBarChartLine className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-sm font-bold">统计图表</h3>
              <span className="ml-auto text-xs text-muted-foreground">最近 30 天（原始事件）</span>
            </div>
            <div className="p-4 space-y-4">
              {/* Daily chart */}
              {data.dailyStats.length > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                    <RiCalendarLine className="w-3 h-3" />每日搜索次数（蓝=总量 · 绿=可注册 · 灰=匿名）
                  </p>
                  <div className="flex items-end gap-0.5 h-20">
                    {data.dailyStats.map(d => (
                      <div
                        key={d.day}
                        className="flex-1 flex flex-col-reverse gap-0.5 group relative"
                        title={`${d.day}: 共${d.count}次 可注册${d.available} 注册${d.registered} 匿名${d.anon} 登录${d.logged}`}
                      >
                        <div
                          className="w-full rounded-sm bg-primary/60 hover:bg-primary transition-colors"
                          style={{ height: `${Math.max(2, Math.round((d.count / maxDaily) * 70))}px` }}
                        />
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-between text-[9px] text-muted-foreground/50 mt-1">
                    <span>{data.dailyStats[0]?.day?.slice(5)}</span>
                    <span>{data.dailyStats[data.dailyStats.length - 1]?.day?.slice(5)}</span>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* Type breakdown */}
                {data.topByType.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                      <RiDatabase2Line className="w-3 h-3" />查询类型分布（独立域名数）
                    </p>
                    <div className="space-y-1.5">
                      {data.topByType.map(t => {
                        const total = data.topByType.reduce((s, x) => s + x.count, 0);
                        const pct   = total > 0 ? Math.round((t.count / total) * 100) : 0;
                        return (
                          <div key={t.type} className="flex items-center gap-2">
                            <span className="text-[10px] font-mono w-12 text-muted-foreground uppercase">{t.type}</span>
                            <div className="flex-1 bg-muted rounded-full h-1.5">
                              <div className="bg-primary h-1.5 rounded-full" style={{ width: `${pct}%` }} />
                            </div>
                            <span className="text-[10px] text-muted-foreground tabular-nums w-16 text-right">{t.count.toLocaleString()} ({pct}%)</span>
                          </div>
                        );
                      })}
                    </div>
                    <div className="mt-3 pt-3 border-t border-border/50">
                      <p className="text-xs text-muted-foreground mb-2">用户类型（最后搜索来源）</p>
                      <div className="space-y-1.5">
                        {[
                          { label: "登录用户", value: data.stats.logged,   color: "bg-primary" },
                          { label: "匿名",     value: data.stats.anonymous, color: "bg-muted-foreground/40" },
                        ].map(item => {
                          const total = data.stats.all || 1;
                          const pct   = Math.round((item.value / total) * 100);
                          return (
                            <div key={item.label} className="flex items-center gap-2">
                              <span className="text-[10px] w-14 text-muted-foreground">{item.label}</span>
                              <div className="flex-1 bg-muted rounded-full h-1.5">
                                <div className={cn("h-1.5 rounded-full", item.color)} style={{ width: `${pct}%` }} />
                              </div>
                              <span className="text-[10px] text-muted-foreground tabular-nums w-16 text-right">{item.value.toLocaleString()} ({pct}%)</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}

                {/* Top queries */}
                {data.topQueries.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                      <RiFireLine className="w-3 h-3" />热门查询（30天 Top 10）
                    </p>
                    <div className="space-y-1">
                      {data.topQueries.slice(0, 10).map((q, i) => (
                        <div key={`${q.query}-${i}`} className="flex items-center gap-2">
                          <span className={cn(
                            "w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0",
                            i === 0 ? "bg-amber-400 text-white" : i === 1 ? "bg-zinc-300 dark:bg-zinc-600 text-zinc-700 dark:text-zinc-200" : i === 2 ? "bg-orange-400 text-white" : "bg-muted text-muted-foreground"
                          )}>{i + 1}</span>
                          <a href={`/${q.query}`} target="_blank" rel="noopener noreferrer"
                            className="flex-1 text-xs font-mono truncate hover:text-primary hover:underline">
                            {q.query}
                          </a>
                          <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">{q.count}次</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Top active users */}
                {data.topUsers && data.topUsers.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                      <RiGroupLine className="w-3 h-3" />活跃用户（30天 Top 10）
                    </p>
                    <div className="space-y-1">
                      {data.topUsers.slice(0, 10).map((u, i) => (
                        <div key={u.email} className="flex items-center gap-2">
                          <span className={cn(
                            "w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0",
                            i === 0 ? "bg-amber-400 text-white" : i === 1 ? "bg-zinc-300 dark:bg-zinc-600 text-zinc-700 dark:text-zinc-200" : i === 2 ? "bg-orange-400 text-white" : "bg-muted text-muted-foreground"
                          )}>{i + 1}</span>
                          <span className="flex-1 text-xs truncate text-muted-foreground" title={u.email}>{u.name || u.email}</span>
                          <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">{u.count}次</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Top TLDs */}
                {data.topTlds && data.topTlds.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                      <RiGlobalLine className="w-3 h-3" />热门后缀（域名查询 Top 12，已过滤无效后缀）
                    </p>
                    <div className="space-y-1.5">
                      {data.topTlds.map(t => {
                        const maxCount = data.topTlds[0]?.count ?? 1;
                        const pct = maxCount > 0 ? Math.round((t.count / maxCount) * 100) : 0;
                        return (
                          <div key={t.tld} className="flex items-center gap-2">
                            <span className="text-[10px] font-mono w-14 text-muted-foreground">.{t.tld}</span>
                            <div className="flex-1 bg-muted rounded-full h-1.5">
                              <div className="bg-sky-500/60 h-1.5 rounded-full" style={{ width: `${pct}%` }} />
                            </div>
                            <span className="text-[10px] text-muted-foreground tabular-nums w-12 text-right">{t.count.toLocaleString()}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Delete by period */}
        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
            <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400">
              <RiDeleteBin2Line className="w-3.5 h-3.5" />
            </div>
            <h3 className="text-sm font-bold">批量删除记录</h3>
          </div>
          <div className="p-4 flex flex-wrap gap-2">
            {DELETE_PERIODS.map(({ key, label }) => (
              <Button
                key={key}
                variant={key === "all" ? "destructive" : "outline"}
                size="sm"
                disabled={!!deleting}
                onClick={() => deletePeriod(key, label)}
                className={cn(
                  "rounded-xl h-8 text-xs gap-1.5",
                  key === "anonymous" && "border-orange-200 dark:border-orange-800 text-orange-600 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-950/30"
                )}
              >
                {deleting === key
                  ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                  : key === "anonymous" ? <RiGhostLine className="w-3 h-3" /> : <RiDeleteBin2Line className="w-3 h-3" />
                }
                {label}
              </Button>
            ))}
          </div>
        </div>

        {/* Filter tabs + Record list */}
        <div className="glass-panel border border-border rounded-2xl overflow-hidden">
          <div className="flex border-b border-border overflow-x-auto">
            {FILTERS.map(({ key, label, icon: Icon, color }) => (
              <button
                key={key}
                onClick={() => changeFilter(key)}
                className={cn(
                  "flex items-center gap-1.5 px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors border-b-2 -mb-px",
                  filter === key
                    ? "border-primary text-primary bg-primary/5"
                    : "border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/50"
                )}
              >
                <Icon className={cn("w-3.5 h-3.5", filter === key ? color : "")} />
                {label}
                {data && (
                  <span className={cn(
                    "text-[10px] px-1.5 py-0.5 rounded-full font-semibold ml-0.5",
                    filter === key ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
                  )}>
                    {key === "all"       ? data.stats.all :
                     key === "logged"    ? data.stats.logged :
                     key === "anonymous" ? data.stats.anonymous :
                     key === "available" ? data.stats.available :
                     key === "expiring"  ? data.stats.expiring :
                     data.stats.highValue}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Notice about deduplication */}
          <div className="px-4 py-2 bg-muted/20 border-b border-border/50 flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <RiRepeatLine className="w-3 h-3 shrink-0" />
            每行代表一个唯一域名（跨用户去重）— 搜索次数为所有用户该域名的累计查询数
          </div>

          {/* Record list */}
          {loading && !data ? (
            <div className="flex justify-center py-12">
              <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : data && data.records.length > 0 ? (
            <>
              <div className="divide-y divide-border/50">
                {data.records.map(r => (
                  <div key={r.query} className="flex items-start gap-3 px-4 py-3 hover:bg-muted/30 transition-colors group">
                    {/* Icon */}
                    <div className={cn(
                      "w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5",
                      r.lastWasAnon ? "bg-muted/60" : "bg-muted"
                    )}>
                      {r.lastWasAnon
                        ? <RiGhostLine className="w-3.5 h-3.5 text-muted-foreground/50" />
                        : <RiGlobalLine className="w-3.5 h-3.5 text-muted-foreground" />
                      }
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <a
                          href={`/${r.query}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm font-mono font-semibold truncate hover:text-primary hover:underline inline-flex items-center gap-0.5"
                        >
                          {r.query}
                          <RiExternalLinkLine className="w-2.5 h-2.5 opacity-50 shrink-0" />
                        </a>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground uppercase">{r.queryType}</span>
                        {regStatusBadge(r.regStatus, r.remainingDays)}
                        {r.queryType === "domain" && r.valueTier !== "normal" && (
                          <ValueTierBadge tier={r.valueTier} />
                        )}
                        {/* Search count badge */}
                        {r.searchCount > 1 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400 font-semibold inline-flex items-center gap-0.5">
                            <RiRepeatLine className="w-2.5 h-2.5" />{r.searchCount}次
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-1 flex-wrap">
                        {/* Last searcher */}
                        {!r.lastWasAnon && r.lastUserEmail ? (
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                            <RiUserLine className="w-2.5 h-2.5" />
                            最后：{r.lastUserName || r.lastUserEmail}
                          </span>
                        ) : (
                          <span className="text-[10px] text-muted-foreground/50 flex items-center gap-0.5">
                            <RiGhostLine className="w-2.5 h-2.5" />最后：匿名
                          </span>
                        )}
                        {/* Unique logged users */}
                        {r.uniqueLoggedUsers > 0 && (
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                            <RiGroupLine className="w-2.5 h-2.5" />{r.uniqueLoggedUsers} 位用户
                          </span>
                        )}
                        {/* Expiry */}
                        {r.expirationDate && r.expirationDate !== "Unknown" && (
                          <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                            <RiTimeLine className="w-2.5 h-2.5" />到期：{r.expirationDate}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0 mt-0.5">
                      <span className="text-[10px] text-muted-foreground">{fmt(r.lastSearchedAt)}</span>
                      <button
                        onClick={() => deleteRecordByQuery(r.query)}
                        disabled={deletingRow === r.query}
                        className="p-1.5 rounded-lg opacity-0 group-hover:opacity-100 transition-all text-muted-foreground hover:bg-red-50 dark:hover:bg-red-950/30 hover:text-red-500 ml-1"
                        title="删除此域名的所有查询记录"
                      >
                        {deletingRow === r.query
                          ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                          : <RiDeleteBinLine className="w-3 h-3" />
                        }
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Pagination */}
              {data.pagination.totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-border/50">
                  <span className="text-xs text-muted-foreground">
                    第 {data.pagination.page} / {data.pagination.totalPages} 页 · 共 {data.pagination.total} 个域名
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="outline" size="sm"
                      disabled={data.pagination.page <= 1 || loading}
                      onClick={() => changePage(data.pagination.page - 1)}
                      className="rounded-lg h-8 w-8 p-0"
                    >
                      <RiArrowLeftLine className="w-3.5 h-3.5" />
                    </Button>
                    <Button
                      variant="outline" size="sm"
                      disabled={data.pagination.page >= data.pagination.totalPages || loading}
                      onClick={() => changePage(data.pagination.page + 1)}
                      className="rounded-lg h-8 w-8 p-0"
                    >
                      <RiArrowRightLine className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="py-12 text-center text-muted-foreground text-sm">
              {search ? `未找到包含"${search}"的域名` : "暂无查询记录"}
            </div>
          )}
        </div>
      </div>
    </AdminLayout>
  );
}
