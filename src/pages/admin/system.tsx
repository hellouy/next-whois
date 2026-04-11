import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import {
  RiLoader4Line, RiRefreshLine, RiDatabase2Line, RiSearchLine,
  RiShieldCheckLine, RiBellLine, RiUserLine, RiCheckLine,
  RiErrorWarningLine, RiFeedbackLine, RiBarChartLine,
  RiCalendarLine, RiServerLine, RiMoneyDollarCircleLine,
  RiDeleteBinLine, RiTimeLine, RiShieldLine, RiFlashlightLine,
  RiToolsLine, RiSparklingLine, RiGitBranchLine, RiUploadCloud2Line,
  RiSettings3Line, RiLockLine,
} from "@remixicon/react";

type SystemData = {
  ok: boolean;
  db: { ok: boolean; latencyMs?: number | null };
  redis: { ok: boolean; configured: boolean; latencyMs: number | null };
  adminEmail?: string;
  stats: {
    users: { total: number; disabled: number; subscribed: number };
    stamps: { total: number; verified: number; pending: number };
    reminders: { total: number; active: number };
    searches: { total: number; today: number };
    feedback: { total: number; recent: number };
    orders: { total: number; paid: number; revenue: number };
    rateLimits: { active: number };
  };
  topSearches: { query: string; type: string; count: number }[];
  dailySearches: { day: string; count: number }[];
  settings: { allow_registration: string };
};

type OptimizeItem = { op: string; label: string; count?: number; deleted?: number; status?: string; error?: string };

function StatItem({ label, value, sub, color }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="text-center p-3">
      <p className={cn("text-2xl font-bold tabular-nums", color || "text-foreground")}>{typeof value === "number" ? value.toLocaleString() : value}</p>
      <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
      {sub && <p className="text-[10px] text-muted-foreground/60 mt-0.5">{sub}</p>}
    </div>
  );
}

export default function AdminSystemPage() {
  const [data, setData] = React.useState<SystemData | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [triggering, setTriggering] = React.useState(false);
  const [clearingRateLimit, setClearingRateLimit] = React.useState(false);

  const [optPreview, setOptPreview] = React.useState<OptimizeItem[] | null>(null);
  const [optPreviewLoading, setOptPreviewLoading] = React.useState(false);
  const [optimizing, setOptimizing] = React.useState(false);
  const [optReport, setOptReport] = React.useState<OptimizeItem[] | null>(null);
  const [confirmTrigger, setConfirmTrigger] = React.useState(false);
  const [confirmClear, setConfirmClear] = React.useState(false);

  const [gitPushing, setGitPushing] = React.useState(false);
  const [gitResult, setGitResult] = React.useState<{ sha?: string; files?: number } | null>(null);
  const [confirmGitPush, setConfirmGitPush] = React.useState(false);
  const [gitStatus, setGitStatus] = React.useState<{ hasToken: boolean; repo: string | null; latestSha: string | null } | null>(null);
  const [gitStatusLoading, setGitStatusLoading] = React.useState(false);
  const [gitToken, setGitToken] = React.useState("");
  const [gitRepo, setGitRepo] = React.useState("");
  const [savingGitConfig, setSavingGitConfig] = React.useState(false);
  const [showGitConfig, setShowGitConfig] = React.useState(false);

  function load() {
    setLoading(true);
    fetch("/api/admin/system")
      .then(r => r.json())
      .then(d => {
        if (d.error) { toast.error(d.error); return; }
        setData(d);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load(); }, []);

  async function triggerReminder() {
    setConfirmTrigger(false);
    setTriggering(true);
    try {
      const r = await fetch("/api/remind/process", { method: "POST" });
      const d = await r.json();
      if (d.error) toast.error(d.error);
      else toast.success("提醒处理完成：已处理 " + (d.processed ?? 0) + " 条");
    } catch {
      toast.error("触发失败");
    } finally {
      setTriggering(false);
    }
  }

  async function clearRateLimits() {
    setConfirmClear(false);
    setClearingRateLimit(true);
    try {
      const r = await fetch("/api/admin/system", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "clear_rate_limits" }),
      });
      const d = await r.json();
      if (d.error) toast.error(d.error);
      else { toast.success("已清理过期频率限制记录"); load(); }
    } catch {
      toast.error("操作失败");
    } finally {
      setClearingRateLimit(false);
    }
  }

  async function loadGitStatus() {
    setGitStatusLoading(true);
    try {
      const r = await fetch("/api/admin/git-force-push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "status" }),
      });
      const d = await r.json();
      setGitStatus(d);
      if (!d.hasToken) setShowGitConfig(true);
    } catch { /* ignore */ }
    finally { setGitStatusLoading(false); }
  }

  async function saveGitConfig() {
    setSavingGitConfig(true);
    try {
      const r = await fetch("/api/admin/git-force-push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "save_config", token: gitToken || undefined, repo: gitRepo || undefined }),
      });
      const d = await r.json();
      if (d.error) toast.error(d.error);
      else {
        toast.success("配置已保存");
        setGitToken("");
        setShowGitConfig(false);
        loadGitStatus();
      }
    } catch { toast.error("保存失败"); }
    finally { setSavingGitConfig(false); }
  }

  async function gitForcePush() {
    setConfirmGitPush(false);
    setGitPushing(true);
    setGitResult(null);
    try {
      const r = await fetch("/api/admin/git-force-push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "push", message: "chore: sync from Replit admin" }),
      });
      const d = await r.json();
      if (d.error) {
        toast.error(d.error);
        if (d.error.includes("Token") || d.error.includes("token")) setShowGitConfig(true);
      } else {
        setGitResult({ sha: d.sha, files: d.files });
        toast.success(`已推送 ${d.files} 个文件到 GitHub（${d.sha}）`);
        loadGitStatus();
      }
    } catch {
      toast.error("推送失败");
    } finally {
      setGitPushing(false);
    }
  }

  React.useEffect(() => { loadGitStatus(); }, []);

  async function loadOptPreview() {
    setOptPreviewLoading(true);
    setOptReport(null);
    try {
      const r = await fetch("/api/admin/system", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "db_optimize_preview" }),
      });
      const d = await r.json();
      if (d.error) toast.error(d.error);
      else setOptPreview(d.preview);
    } catch {
      toast.error("预扫描失败");
    } finally {
      setOptPreviewLoading(false);
    }
  }

  async function runOptimize() {
    setOptimizing(true);
    setOptPreview(null);
    setOptReport(null);
    try {
      const r = await fetch("/api/admin/system", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "db_optimize" }),
      });
      const d = await r.json();
      if (d.error) toast.error(d.error);
      else {
        setOptReport(d.report);
        const total = (d.report as OptimizeItem[])
          .filter(x => typeof x.deleted === "number" && x.deleted > 0)
          .reduce((s, x) => s + (x.deleted ?? 0), 0);
        toast.success(`优化完成，共清理 ${total} 条数据`);
        load();
      }
    } catch {
      toast.error("优化失败");
    } finally {
      setOptimizing(false);
    }
  }

  const maxCount = data?.dailySearches?.length
    ? Math.max(...data.dailySearches.map(d => d.count), 1)
    : 1;

  return (
    <AdminLayout title="系统状态">
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">系统状态</h2>
            <p className="text-xs text-muted-foreground mt-0.5">数据库健康检查、运行统计与管理员工具</p>
          </div>
          <Button variant="outline" onClick={load} disabled={loading} className="rounded-xl h-9 gap-2 text-sm">
            {loading ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiRefreshLine className="w-4 h-4" />}
            刷新
          </Button>
        </div>

        {loading ? (
          <div className="flex justify-center py-20">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : !data ? (
          <div className="flex flex-col items-center gap-3 py-20 text-muted-foreground">
            <RiErrorWarningLine className="w-8 h-8" />
            <p className="text-sm">加载失败，请刷新重试</p>
          </div>
        ) : (
          <div className="space-y-4">
            {/* DB / Redis / Admin status row */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="glass-panel border border-border rounded-2xl p-4 flex items-start gap-3">
                <div className={cn(
                  "w-8 h-8 rounded-xl flex items-center justify-center shrink-0",
                  data.db.ok ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600" : "bg-red-100 dark:bg-red-950/40 text-red-600"
                )}>
                  {data.db.ok ? <RiCheckLine className="w-4 h-4" /> : <RiErrorWarningLine className="w-4 h-4" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold">Supabase 数据库</p>
                  <p className={cn("text-xs mt-0.5", data.db.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600")}>
                    {data.db.ok
                      ? `连接正常${data.db.latencyMs != null ? ` · ${data.db.latencyMs}ms` : ""}`
                      : "连接异常"}
                  </p>
                </div>
              </div>

              <div className="glass-panel border border-border rounded-2xl p-4 flex items-start gap-3">
                <div className={cn(
                  "w-8 h-8 rounded-xl flex items-center justify-center shrink-0",
                  !data.redis?.configured
                    ? "bg-muted text-muted-foreground"
                    : data.redis.ok
                    ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600"
                    : "bg-red-100 dark:bg-red-950/40 text-red-600"
                )}>
                  <RiFlashlightLine className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold">Redis 缓存</p>
                  <p className={cn("text-xs mt-0.5",
                    !data.redis?.configured ? "text-muted-foreground" :
                    data.redis.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600"
                  )}>
                    {!data.redis?.configured
                      ? "未配置（降级为 DB 限速）"
                      : data.redis.ok
                      ? `连接正常 · ${data.redis.latencyMs ?? "-"}ms`
                      : "连接异常"}
                  </p>
                </div>
              </div>

              <div className="glass-panel border border-border rounded-2xl p-4 flex items-start gap-3">
                <div className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0 bg-violet-100 dark:bg-violet-950/40 text-violet-600">
                  <RiShieldLine className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold">管理员账号</p>
                  <p className="text-xs text-muted-foreground mt-0.5 font-mono truncate">{data.adminEmail || "（系统默认）"}</p>
                  <p className="text-[10px] text-muted-foreground/60 mt-0.5">可在设置→功能开关中修改</p>
                </div>
              </div>
            </div>

            {/* User stats */}
            <div className="glass-panel border border-border rounded-2xl overflow-hidden">
              <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400">
                  <RiUserLine className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-sm font-bold">用户数据</h3>
              </div>
              <div className="grid grid-cols-3 divide-x divide-border">
                <StatItem label="注册用户" value={data.stats.users.total} sub={`${data.stats.users.disabled} 已禁用`} />
                <StatItem label="订阅用户" value={data.stats.users.subscribed} color="text-emerald-600 dark:text-emerald-400" />
                <StatItem label="认证邮箱" value={data.stats.stamps.verified} sub={`${data.stats.stamps.pending} 待认证`} />
              </div>
            </div>

            {/* Payment stats */}
            <div className="glass-panel border border-border rounded-2xl overflow-hidden">
              <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400">
                  <RiMoneyDollarCircleLine className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-sm font-bold">支付数据</h3>
              </div>
              <div className="grid grid-cols-3 divide-x divide-border">
                <StatItem label="总订单" value={data.stats.orders.total} />
                <StatItem label="已完成" value={data.stats.orders.paid} color="text-emerald-600 dark:text-emerald-400" />
                <StatItem label="总收入" value={`¥${data.stats.orders.revenue.toFixed(2)}`} color="text-emerald-600 dark:text-emerald-400" />
              </div>
            </div>

            {/* Activity stats */}
            <div className="glass-panel border border-border rounded-2xl overflow-hidden">
              <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400">
                  <RiBarChartLine className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-sm font-bold">活动统计</h3>
              </div>
              <div className="grid grid-cols-4 divide-x divide-border">
                <StatItem label="查询记录" value={data.stats.searches.total} sub={`今日 ${data.stats.searches.today}`} />
                <StatItem label="监控提醒" value={data.stats.reminders.active} sub={`共 ${data.stats.reminders.total}`} />
                <StatItem label="用户反馈" value={data.stats.feedback.total} sub={`近7天 ${data.stats.feedback.recent}`} />
                <StatItem label="频率限制" value={data.stats.rateLimits.active} sub="活跃记录" color={data.stats.rateLimits.active > 0 ? "text-amber-600" : undefined} />
              </div>
            </div>

            {/* Search trends */}
            {data.dailySearches.length > 0 && (
              <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                  <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400">
                    <RiCalendarLine className="w-3.5 h-3.5" />
                  </div>
                  <h3 className="text-sm font-bold">近7天查询趋势</h3>
                </div>
                <div className="p-5">
                  <div className="flex items-end gap-1.5 h-24">
                    {data.dailySearches.map(d => (
                      <div key={d.day} className="flex-1 flex flex-col items-center gap-1">
                        <div
                          className="w-full rounded-sm bg-primary/30 hover:bg-primary/50 transition-colors cursor-default"
                          style={{ height: `${Math.round((d.count / maxCount) * 80)}px`, minHeight: "2px" }}
                          title={`${d.day}: ${d.count} 次`}
                        />
                        <span className="text-[9px] text-muted-foreground/60 tabular-nums">
                          {new Date(d.day).toLocaleDateString("zh-CN", { month: "numeric", day: "numeric" })}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Top searches */}
            {data.topSearches.length > 0 && (
              <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                  <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-slate-100 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400">
                    <RiSearchLine className="w-3.5 h-3.5" />
                  </div>
                  <h3 className="text-sm font-bold">热门查询（近7天）</h3>
                </div>
                <div className="divide-y divide-border">
                  {data.topSearches.map((s, i) => (
                    <div key={i} className="px-5 py-2.5 flex items-center gap-3">
                      <span className="text-xs font-mono tabular-nums text-muted-foreground w-5 text-right">{i + 1}</span>
                      <span className="flex-1 text-sm font-mono truncate">{s.query}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground">{s.type}</span>
                      <span className="text-xs text-muted-foreground tabular-nums">{s.count} 次</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Admin tools */}
            <div className="glass-panel border border-border rounded-2xl overflow-hidden">
              <div className="px-5 py-3 flex items-center gap-2.5 border-b border-border bg-muted/30">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center bg-slate-100 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400">
                  <RiServerLine className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-sm font-bold">管理工具</h3>
              </div>
              <div className="p-4 grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Trigger reminders */}
                <div className="border border-border rounded-xl p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <RiBellLine className="w-4 h-4 text-muted-foreground" />
                    <p className="text-sm font-semibold">手动触发提醒</p>
                  </div>
                  <p className="text-xs text-muted-foreground">立即执行今日域名到期提醒任务，发送邮件通知给所有监控用户</p>
                  {confirmTrigger ? (
                    <div className="flex items-center gap-2 flex-wrap pt-1">
                      <span className="text-xs text-amber-600 dark:text-amber-400">确认触发？将立即发送邮件通知</span>
                      <Button size="sm" variant="outline" onClick={triggerReminder} disabled={triggering}
                        className="h-7 px-2.5 rounded-lg text-xs text-amber-600 dark:text-amber-400 border-amber-300 dark:border-amber-700">
                        {triggering ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : "确认"}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setConfirmTrigger(false)} disabled={triggering}
                        className="h-7 px-2.5 rounded-lg text-xs">取消</Button>
                    </div>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => setConfirmTrigger(true)} disabled={triggering}
                      className="w-full h-8 rounded-lg text-xs gap-2 mt-1">
                      {triggering ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiBellLine className="w-3.5 h-3.5" />}
                      {triggering ? "执行中…" : "立即触发"}
                    </Button>
                  )}
                </div>

                {/* Clear rate limits */}
                <div className="border border-border rounded-xl p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <RiTimeLine className="w-4 h-4 text-muted-foreground" />
                    <p className="text-sm font-semibold">清理频率限制</p>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    删除已过期的频率限制记录（当前活跃 {data.stats.rateLimits.active} 条）
                  </p>
                  {confirmClear ? (
                    <div className="flex items-center gap-2 flex-wrap pt-1">
                      <span className="text-xs text-amber-600 dark:text-amber-400">确认清理？不影响冷却中的限制</span>
                      <Button size="sm" variant="outline" onClick={clearRateLimits} disabled={clearingRateLimit}
                        className="h-7 px-2.5 rounded-lg text-xs text-amber-600 dark:text-amber-400 border-amber-300 dark:border-amber-700">
                        {clearingRateLimit ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : "确认"}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setConfirmClear(false)} disabled={clearingRateLimit}
                        className="h-7 px-2.5 rounded-lg text-xs">取消</Button>
                    </div>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => setConfirmClear(true)} disabled={clearingRateLimit}
                      className="w-full h-8 rounded-lg text-xs gap-2 mt-1">
                      {clearingRateLimit ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                      {clearingRateLimit ? "清理中…" : "清理过期记录"}
                    </Button>
                  )}
                </div>

                {/* GitHub Force Push */}
                <div className="border border-border rounded-xl p-4 space-y-2 sm:col-span-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <RiGitBranchLine className="w-4 h-4 text-muted-foreground" />
                      <p className="text-sm font-semibold">同步推送到 GitHub</p>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {gitStatusLoading ? (
                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin text-muted-foreground" />
                      ) : gitStatus ? (
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full border font-medium",
                          gitStatus.hasToken
                            ? "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border-emerald-200/60 dark:border-emerald-800/40"
                            : "bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 border-red-200/60 dark:border-red-800/40"
                        )}>
                          {gitStatus.hasToken ? `已配置 · ${gitStatus.repo ?? ""}` : "未配置 Token"}
                        </span>
                      ) : null}
                      <Button size="sm" variant="ghost" onClick={() => setShowGitConfig(v => !v)}
                        className="h-6 w-6 p-0 rounded-lg">
                        <RiSettings3Line className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground">
                    Git 面板卡住时，通过 GitHub API 直接将本地文件推送到远程仓库
                  </p>

                  {/* Config panel */}
                  {showGitConfig && (
                    <div className="rounded-lg bg-muted/40 border border-border p-3 space-y-2">
                      <p className="text-xs font-medium text-muted-foreground">GitHub 配置</p>
                      <div className="space-y-1.5">
                        <Input
                          type="password"
                          placeholder="GitHub Token（ghp_...）留空则不修改"
                          value={gitToken}
                          onChange={e => setGitToken(e.target.value)}
                          className="h-8 text-xs font-mono"
                        />
                        <Input
                          type="text"
                          placeholder={`仓库（${gitStatus?.repo ?? "owner/repo"}）留空则不修改`}
                          value={gitRepo}
                          onChange={e => setGitRepo(e.target.value)}
                          className="h-8 text-xs font-mono"
                        />
                      </div>
                      <Button size="sm" onClick={saveGitConfig} disabled={savingGitConfig || (!gitToken && !gitRepo)}
                        className="w-full h-7 rounded-lg text-xs gap-1.5">
                        {savingGitConfig ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : null}
                        保存配置
                      </Button>
                    </div>
                  )}

                  {/* Git lock warning */}
                  <div className="rounded-lg bg-amber-50 dark:bg-amber-950/20 border border-amber-200/60 dark:border-amber-800/40 px-2.5 py-2 space-y-1">
                    <div className="flex items-center gap-1.5">
                      <RiLockLine className="w-3 h-3 text-amber-600 dark:text-amber-400 shrink-0" />
                      <p className="text-xs font-medium text-amber-700 dark:text-amber-400">Git 面板锁定？在 Shell 执行以下命令解锁：</p>
                    </div>
                    <code className="block text-[10px] font-mono text-amber-800 dark:text-amber-300 bg-amber-100/60 dark:bg-amber-900/20 rounded px-2 py-1 break-all select-all">
                      rm -f .git/index.lock .git/MERGE_HEAD .git/MERGE_MODE .git/MERGE_MSG
                    </code>
                  </div>

                  {gitResult && (
                    <div className="rounded-lg bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200/60 dark:border-emerald-800/40 px-2.5 py-2 text-xs text-emerald-700 dark:text-emerald-400 font-mono">
                      ✓ 已推送 {gitResult.files} 个文件 · commit {gitResult.sha}
                      {gitStatus?.latestSha && <span className="ml-2 text-muted-foreground">（GitHub: {gitStatus.latestSha}）</span>}
                    </div>
                  )}

                  {confirmGitPush ? (
                    <div className="flex items-center gap-2 flex-wrap pt-1">
                      <span className="text-xs text-amber-600 dark:text-amber-400">将创建新提交同步到 GitHub</span>
                      <Button size="sm" variant="outline" onClick={gitForcePush} disabled={gitPushing}
                        className="h-7 px-2.5 rounded-lg text-xs text-amber-600 dark:text-amber-400 border-amber-300 dark:border-amber-700">
                        {gitPushing ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : "确认推送"}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setConfirmGitPush(false)} disabled={gitPushing}
                        className="h-7 px-2.5 rounded-lg text-xs">取消</Button>
                    </div>
                  ) : (
                    <Button size="sm" variant="outline" onClick={() => setConfirmGitPush(true)}
                      disabled={gitPushing || !gitStatus?.hasToken}
                      className="w-full h-8 rounded-lg text-xs gap-2">
                      {gitPushing
                        ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />推送中…</>
                        : <><RiUploadCloud2Line className="w-3.5 h-3.5" />推送到 GitHub</>}
                    </Button>
                  )}
                </div>

                {/* DB one-click optimize */}
                <div className="border border-border rounded-xl p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <RiToolsLine className="w-4 h-4 text-muted-foreground" />
                    <p className="text-sm font-semibold">一键优化数据库</p>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    清理过期令牌、孤立日志、匿名历史等垃圾数据，并刷新查询统计信息
                  </p>

                  {/* Preview list */}
                  {optPreview && !optReport && (
                    <div className="rounded-lg bg-muted/40 border border-border divide-y divide-border text-xs mt-1">
                      {optPreview.map(item => (
                        <div key={item.op} className="flex items-center justify-between px-2.5 py-1.5 gap-2">
                          <span className="text-muted-foreground truncate flex-1">{item.label}</span>
                          {item.count === -1 ? (
                            <span className="text-blue-500 shrink-0">—</span>
                          ) : item.count === 0 ? (
                            <span className="text-muted-foreground/50 shrink-0">已整洁</span>
                          ) : (
                            <span className="text-amber-600 dark:text-amber-400 font-semibold tabular-nums shrink-0">{item.count}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Report list (after run) */}
                  {optReport && (
                    <div className="rounded-lg bg-muted/40 border border-border divide-y divide-border text-xs mt-1">
                      {optReport.map(item => (
                        <div key={item.op} className="flex items-center justify-between px-2.5 py-1.5 gap-2">
                          <span className="text-muted-foreground truncate flex-1">{item.label}</span>
                          {item.error ? (
                            <span className="text-red-500 shrink-0" title={item.error}>失败</span>
                          ) : item.status === "triggered" || item.status === "skipped" ? (
                            <span className={cn("shrink-0", item.status === "triggered" ? "text-blue-500" : "text-muted-foreground/50")}>
                              {item.status === "triggered" ? "已触发" : "已跳过"}
                            </span>
                          ) : (item.deleted ?? 0) === 0 ? (
                            <span className="text-muted-foreground/50 shrink-0">+0</span>
                          ) : (
                            <span className="text-emerald-600 dark:text-emerald-400 font-semibold tabular-nums shrink-0">-{item.deleted}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex gap-2 mt-1">
                    {!optReport && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={loadOptPreview}
                        disabled={optPreviewLoading || optimizing}
                        className="flex-1 h-8 rounded-lg text-xs gap-1.5"
                      >
                        {optPreviewLoading
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : <RiSearchLine className="w-3.5 h-3.5" />}
                        {optPreviewLoading ? "扫描中…" : "预扫描"}
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant={optReport ? "outline" : "default"}
                      onClick={optReport ? () => { setOptReport(null); setOptPreview(null); } : runOptimize}
                      disabled={optimizing}
                      className={cn(
                        "h-8 rounded-lg text-xs gap-1.5",
                        optReport ? "flex-1" : optPreview ? "flex-1" : "w-full"
                      )}
                    >
                      {optimizing
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : optReport
                        ? <RiRefreshLine className="w-3.5 h-3.5" />
                        : <RiSparklingLine className="w-3.5 h-3.5" />}
                      {optimizing ? "优化中…" : optReport ? "重置" : "开始优化"}
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
