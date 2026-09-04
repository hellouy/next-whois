import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiSearchLine, RiDeleteBinLine,
  RiBellLine, RiCalendarLine, RiMailLine,
  RiFilterLine, RiTimeLine, RiCloseLine,
  RiEditLine, RiSendPlaneLine, RiCheckLine,
  RiHistoryLine,
} from "@remixicon/react";

type TldQuality = "high" | "medium" | "low" | "ai" | null;
type TldScrapeStatus = "ok" | "warn_defaults" | "failed" | "pending" | "no_data" | null;

type Reminder = {
  id: string;
  domain: string;
  email: string;
  active: boolean;
  expiration_date: string | null;
  whois_expiry_date: string | null;
  whois_synced_at: string | null;
  days_before: number | null;
  cancel_reason: string | null;
  cancelled_at: string | null;
  phase_flags: string | null;
  created_at: string;
  tld_confidence: TldQuality;
  tld_scrape_status: TldScrapeStatus;
  tld_needs_review: boolean | null;
  tld_manually_edited: boolean | null;
  tld_scrape_attempts: number | null;
};

type FilterTab = "all" | "active" | "inactive" | "review";
type PageTab = "reminders" | "log";

type ReminderLog = {
  id: string;
  domain: string;
  user_email: string;
  days_before: number;
  sent_at: string;
};

const EMPTY_EDIT = { domain: "", email: "", expiration_date: "", days_before: "" };

export default function AdminRemindersPage() {
  const [reminders, setReminders] = React.useState<Reminder[]>([]);
  const [total, setTotal] = React.useState(0);
  const [activeCount, setActiveCount] = React.useState(0);
  const [inactiveCount, setInactiveCount] = React.useState(0);
  const [reviewCount, setReviewCount] = React.useState(0);
  const [search, setSearch] = React.useState("");
  const [activeFilter, setActiveFilter] = React.useState<FilterTab>("all");
  const [loading, setLoading] = React.useState(false);
  const [acting, setActing] = React.useState<string | null>(null);
  const [offset, setOffset] = React.useState(0);
  const [editingId, setEditingId] = React.useState<string | null>(null);
  const [editForm, setEditForm] = React.useState(EMPTY_EDIT);
  const [savingEdit, setSavingEdit] = React.useState(false);
  const [sendingEmailId, setSendingEmailId] = React.useState<string | null>(null);
  const [pageTab, setPageTab] = React.useState<PageTab>("reminders");
  const [logs, setLogs] = React.useState<ReminderLog[]>([]);
  const [logsLoading, setLogsLoading] = React.useState(false);
  const LIMIT = 50;

  function load(q: string, filter: FilterTab, off = 0) {
    setLoading(true);
    fetch(`/api/admin/reminders?search=${encodeURIComponent(q)}&filter=${filter}&limit=${LIMIT}&offset=${off}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) { toast.error(data.error); return; }
        setReminders(off === 0 ? data.reminders || [] : prev => [...prev, ...(data.reminders || [])]);
        setTotal(data.total || 0);
        setActiveCount(data.activeCount || 0);
        setInactiveCount(data.inactiveCount || 0);
        if (data.reviewCount != null) setReviewCount(data.reviewCount);
        setOffset(off);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  function loadLogs() {
    setLogsLoading(true);
    fetch("/api/admin/reminders?tab=log")
      .then(r => r.json())
      .then(data => {
        if (data.error) { toast.error(data.error); return; }
        setLogs(data.logs || []);
      })
      .catch(() => toast.error("加载日志失败"))
      .finally(() => setLogsLoading(false));
  }

  function handlePageTab(tab: PageTab) {
    setPageTab(tab);
    if (tab === "log" && logs.length === 0) loadLogs();
  }

  React.useEffect(() => { load("", "all", 0); }, []);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setOffset(0);
    load(search, activeFilter, 0);
  }

  function handleFilter(f: FilterTab) {
    setActiveFilter(f);
    setOffset(0);
    load(search, f, 0);
  }

  function openEdit(reminder: Reminder) {
    setEditingId(reminder.id);
    const expDate = reminder.expiration_date
      ? new Date(reminder.expiration_date).toISOString().split("T")[0]
      : "";
    setEditForm({
      domain: reminder.domain,
      email: reminder.email,
      expiration_date: expDate,
      days_before: reminder.days_before != null ? String(reminder.days_before) : "",
    });
  }

  function cancelEdit() {
    setEditingId(null);
    setEditForm(EMPTY_EDIT);
  }

  async function handleSaveEdit(id: string) {
    setSavingEdit(true);
    try {
      const body: Record<string, any> = {
        domain: editForm.domain.trim(),
        email: editForm.email.trim(),
        expiration_date: editForm.expiration_date || null,
        days_before: editForm.days_before ? parseInt(editForm.days_before) : null,
      };
      if (!body.domain) { toast.error("域名不能为空"); return; }
      if (!body.email) { toast.error("邮箱不能为空"); return; }

      const res = await fetch(`/api/admin/reminders?id=${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setReminders(prev => prev.map(r => r.id === id ? { ...r, ...data.reminder } : r));
      toast.success("已保存修改");
      cancelEdit();
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setSavingEdit(false);
    }
  }

  async function handleSendEmail(id: string) {
    setSendingEmailId(id);
    try {
      const res = await fetch(`/api/admin/reminders?id=${id}&action=send-email`, {
        method: "POST",
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(`提醒邮件已发送至 ${data.to}`);
    } catch (e: any) {
      toast.error(e.message || "发送失败");
    } finally {
      setSendingEmailId(null);
    }
  }

  async function toggleActive(reminder: Reminder) {
    setActing(reminder.id);
    try {
      const res = await fetch(`/api/admin/reminders?id=${reminder.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active: !reminder.active }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setReminders(prev => prev.map(r => r.id === reminder.id ? { ...r, ...data.reminder } : r));
      if (reminder.active) {
        setActiveCount(v => v - 1); setInactiveCount(v => v + 1);
      } else {
        setActiveCount(v => v + 1); setInactiveCount(v => v - 1);
      }
      toast.success(reminder.active ? "订阅已停用" : "订阅已恢复");
    } catch (e: any) {
      toast.error(e.message || "操作失败");
    } finally {
      setActing(null);
    }
  }

  async function hardDelete(id: string, domain: string) {
    if (!confirm(`确定要永久删除 ${domain} 的订阅记录吗？此操作不可撤销。`)) return;
    setActing(id);
    try {
      const res = await fetch(`/api/admin/reminders?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error((await res.json()).error);
      setReminders(prev => prev.filter(r => r.id !== id));
      setTotal(prev => prev - 1);
      toast.success("已永久删除");
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setActing(null);
    }
  }

  function fmt(d: string | null) {
    if (!d) return "未设置";
    return new Date(d).toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
  }

  function fmtRelative(d: string) {
    const diff = Date.now() - new Date(d).getTime();
    const days = Math.floor(diff / 86400000);
    if (days === 0) return "今天";
    if (days < 30) return `${days} 天前`;
    if (days < 365) return `${Math.floor(days / 30)} 个月前`;
    return `${Math.floor(days / 365)} 年前`;
  }

  const FILTERS: { key: FilterTab; label: string; count: number; color?: string }[] = [
    { key: "all",      label: "全部",     count: activeCount + inactiveCount },
    { key: "active",   label: "活跃",     count: activeCount,  color: "emerald" },
    { key: "inactive", label: "已停用",   count: inactiveCount },
    { key: "review",   label: "需要核查", count: reviewCount,  color: "amber" },
  ];

  return (
    <AdminLayout title="订阅提醒">
      <Head><title>订阅提醒 · Admin</title></Head>
      <div className="space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">订阅提醒</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              共 {total.toLocaleString()} 条 · 活跃 {activeCount} · 停用 {inactiveCount}
            </p>
          </div>
          {pageTab === "reminders" && (
            <form onSubmit={handleSearch} className="flex items-center gap-2">
              <div className="relative">
                <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
                <Input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="搜索域名或邮箱…"
                  className="pl-8 h-9 rounded-xl text-sm w-52"
                />
              </div>
              <Button type="submit" size="sm" className="h-9 rounded-xl px-4">搜索</Button>
            </form>
          )}
        </div>

        {/* Page tabs */}
        <div className="flex items-center gap-1 p-1 glass-panel border border-border rounded-xl w-fit">
          <button
            onClick={() => handlePageTab("reminders")}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5",
              pageTab === "reminders"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-muted"
            )}
          >
            <RiBellLine className="w-3.5 h-3.5" />提醒列表
          </button>
          <button
            onClick={() => handlePageTab("log")}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5",
              pageTab === "log"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-muted"
            )}
          >
            <RiHistoryLine className="w-3.5 h-3.5" />执行日志
          </button>
        </div>

        {/* Log tab */}
        {pageTab === "log" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">最近 50 条发送记录</p>
              <button
                onClick={loadLogs}
                disabled={logsLoading}
                className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
              >
                <RiLoader4Line className={cn("w-3 h-3", logsLoading && "animate-spin")} />
                刷新
              </button>
            </div>
            {logsLoading ? (
              <div className="flex justify-center py-12">
                <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
              </div>
            ) : logs.length === 0 ? (
              <div className="text-center py-12 space-y-2">
                <RiHistoryLine className="w-10 h-10 text-muted-foreground/30 mx-auto" />
                <p className="text-sm text-muted-foreground">暂无发送记录</p>
              </div>
            ) : (
              <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                <div className="grid grid-cols-[1fr_1fr_auto_auto] text-[10px] font-semibold text-muted-foreground uppercase tracking-wider px-4 py-2 border-b border-border bg-muted/30 gap-3">
                  <span>域名</span>
                  <span className="hidden sm:block">用户</span>
                  <span>提前天数</span>
                  <span>发送时间</span>
                </div>
                <div className="divide-y divide-border">
                  {logs.map(log => (
                    <div key={log.id} className="grid grid-cols-[1fr_auto_auto] sm:grid-cols-[1fr_1fr_auto_auto] px-4 py-2.5 gap-3 text-[11px] items-center hover:bg-muted/20 transition-colors">
                      <span className="font-mono font-semibold truncate">{log.domain}</span>
                      <span className="text-muted-foreground truncate hidden sm:block">{log.user_email}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-950/30 text-blue-700 dark:text-blue-300 font-semibold shrink-0 text-center">
                        {log.days_before === 0 || log.days_before <= -100000
                          ? "手动"
                          : log.days_before < 0
                          ? (log.days_before === -4 ? "即将删除" : log.days_before === -5 ? "已释放" : `阶段${log.days_before}`)
                          : `${log.days_before}天`}
                      </span>
                      <span className="text-muted-foreground text-[10px] shrink-0 whitespace-nowrap">
                        {new Date(log.sent_at).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Filter tabs — only show for reminders list */}
        {pageTab === "reminders" && (
        <div className="flex items-center gap-1.5 p-1 glass-panel border border-border rounded-xl flex-wrap">
          <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground ml-1" />
          {FILTERS.map(f => (
            <button
              key={f.key}
              onClick={() => handleFilter(f.key)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all",
                activeFilter === f.key
                  ? "bg-primary text-primary-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              {f.label}
              {f.count > 0 && (
                <span className={cn(
                  "ml-1.5 text-[10px] px-1 py-0.5 rounded",
                  activeFilter === f.key ? "bg-white/20" : "bg-muted-foreground/10"
                )}>{f.count}</span>
              )}
            </button>
          ))}
        </div>
        )}

        {pageTab === "reminders" && (loading && offset === 0 ? (
          <div className="flex justify-center py-12">
            <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : reminders.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <RiBellLine className="w-10 h-10 text-muted-foreground/30 mx-auto" />
            <p className="text-sm text-muted-foreground">没有找到记录</p>
          </div>
        ) : (
          <div className="space-y-2">
            {reminders.map(reminder => (
              <div key={reminder.id}
                className={cn(
                  "glass-panel border rounded-xl overflow-hidden transition-colors",
                  reminder.active ? "border-border" : "border-border/40 bg-muted/10"
                )}>
                <div className="p-4 flex items-start gap-3 group">
                  <div className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-0.5",
                    reminder.active ? "bg-primary/10" : "bg-muted"
                  )}>
                    <RiBellLine className={cn(
                      "w-4 h-4",
                      reminder.active ? "text-primary" : "text-muted-foreground opacity-40"
                    )} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-semibold font-mono">{reminder.domain}</p>
                      {reminder.active
                        ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold">活跃</span>
                        : <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-medium">已停用</span>
                      }
                      {reminder.days_before != null && reminder.days_before > 0 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400">
                          提前 {reminder.days_before} 天
                        </span>
                      )}
                      {/* TLD data quality badge */}
                      {(() => {
                        const st = reminder.tld_scrape_status;
                        const cf = reminder.tld_confidence;
                        const me = reminder.tld_manually_edited;
                        if (me) return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-950/30 text-blue-700 dark:text-blue-300 font-medium" title="管理员已手动设置此TLD规则">TLD人工设置</span>
                        );
                        if (cf === "high") return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-teal-100 dark:bg-teal-950/30 text-teal-700 dark:text-teal-300 font-medium" title="来自官方注册局规范数据库">TLD可靠</span>
                        );
                        if (st === "ok" && cf === "medium") return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-100 dark:bg-green-950/30 text-green-700 dark:text-green-300 font-medium" title="AI从官方政策页面提取到具体数据">TLD AI核实</span>
                        );
                        if (st === "warn_defaults") return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-100 dark:bg-yellow-950/30 text-yellow-700 dark:text-yellow-300 font-medium" title="AI未找到官方政策，使用行业默认值估算">TLD估算</span>
                        );
                        if (st === "no_data") return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-100 dark:bg-orange-950/30 text-orange-700 dark:text-orange-300 font-medium" title="多次抓取均无法获得数据，需人工核查">TLD待核查</span>
                        );
                        if (st === "failed") return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-950/30 text-red-700 dark:text-red-300 font-medium" title="TLD抓取失败，数据不可靠">TLD失败</span>
                        );
                        if (!st) return (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400 font-medium" title="尚未抓取此TLD的生命周期规则">TLD未知</span>
                        );
                        return null;
                      })()}
                    </div>

                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                        <RiMailLine className="w-3 h-3" />{reminder.email}
                      </span>
                      <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                        <RiCalendarLine className="w-3 h-3" />到期：{fmt(reminder.expiration_date)}
                        {reminder.whois_synced_at && (
                          <span className="ml-1 text-[9px] px-1 py-0.5 rounded bg-green-100 dark:bg-green-950/30 text-green-700 dark:text-green-300 font-medium"
                            title={`WHOIS核验：${fmt(reminder.whois_synced_at)}`}>
                            WHOIS ✓
                          </span>
                        )}
                      </span>
                      <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                        <RiTimeLine className="w-3 h-3" />订阅于 {fmtRelative(reminder.created_at)}
                      </span>
                    </div>

                    {!reminder.active && reminder.cancel_reason && (
                      <p className="text-[10px] text-muted-foreground/70 mt-1">
                        停用原因：{reminder.cancel_reason}
                        {reminder.cancelled_at && ` · ${fmt(reminder.cancelled_at)}`}
                      </p>
                    )}

                    {reminder.phase_flags && (() => {
                      let flags: Record<string, boolean> = {};
                      try { flags = JSON.parse(reminder.phase_flags); } catch { return null; }
                      const LABEL: Record<string, string> = {
                        grace: "宽限期", redemption: "赎回期",
                        pendingDelete: "待删除", dropSoon: "即将释放", dropped: "已释放",
                      };
                      const active = Object.entries(flags).filter(([, v]) => v).map(([k]) => k);
                      if (!active.length) return null;
                      return (
                        <div className="flex gap-1 mt-1 flex-wrap">
                          {active.map(k => (
                            <span key={k} className="text-[9px] px-1.5 py-0.5 rounded bg-violet-100 dark:bg-violet-950/30 text-violet-700 dark:text-violet-300 font-medium">
                              {LABEL[k] ?? k}
                            </span>
                          ))}
                        </div>
                      );
                    })()}
                  </div>

                  <div className="flex items-center gap-1 shrink-0 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity mt-0.5">
                    <button
                      onClick={() => editingId === reminder.id ? cancelEdit() : openEdit(reminder)}
                      className={cn(
                        "p-1.5 rounded-lg transition-colors text-muted-foreground",
                        editingId === reminder.id
                          ? "bg-primary/10 text-primary"
                          : "hover:bg-muted hover:text-foreground"
                      )}
                      title="编辑"
                    >
                      <RiEditLine className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleSendEmail(reminder.id)}
                      disabled={sendingEmailId === reminder.id}
                      className="p-1.5 rounded-lg text-muted-foreground hover:bg-blue-50 dark:hover:bg-blue-950/30 hover:text-blue-500 transition-colors"
                      title="立即发送提醒邮件"
                    >
                      {sendingEmailId === reminder.id
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : <RiSendPlaneLine className="w-3.5 h-3.5" />
                      }
                    </button>
                    <button
                      onClick={() => toggleActive(reminder)}
                      disabled={acting === reminder.id}
                      className={cn(
                        "px-2.5 py-1.5 rounded-lg text-[11px] font-semibold transition-colors",
                        reminder.active
                          ? "bg-muted text-muted-foreground hover:bg-orange-50 dark:hover:bg-orange-950/30 hover:text-orange-600"
                          : "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-100"
                      )}
                      title={reminder.active ? "停用订阅" : "恢复订阅"}
                    >
                      {acting === reminder.id
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : reminder.active ? <RiCloseLine className="w-3.5 h-3.5" /> : <RiBellLine className="w-3.5 h-3.5" />
                      }
                    </button>
                    <button
                      onClick={() => hardDelete(reminder.id, reminder.domain)}
                      disabled={acting === reminder.id}
                      className="p-1.5 rounded-lg text-muted-foreground hover:bg-red-50 dark:hover:bg-red-950/30 hover:text-red-500 transition-colors"
                      title="永久删除"
                    >
                      <RiDeleteBinLine className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Inline edit panel */}
                {editingId === reminder.id && (
                  <div className="border-t border-border bg-muted/20 px-4 py-3 space-y-3">
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">编辑订阅信息</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <Label className="text-xs font-semibold">域名</Label>
                        <Input
                          value={editForm.domain}
                          onChange={e => setEditForm(f => ({ ...f, domain: e.target.value }))}
                          className="h-8 text-sm rounded-lg font-mono"
                          placeholder="example.com"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs font-semibold">邮箱</Label>
                        <Input
                          value={editForm.email}
                          onChange={e => setEditForm(f => ({ ...f, email: e.target.value }))}
                          className="h-8 text-sm rounded-lg"
                          type="email"
                          placeholder="user@example.com"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs font-semibold">到期日期</Label>
                        <Input
                          value={editForm.expiration_date}
                          onChange={e => setEditForm(f => ({ ...f, expiration_date: e.target.value }))}
                          className="h-8 text-sm rounded-lg"
                          type="date"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-xs font-semibold">提前提醒天数</Label>
                        <Input
                          value={editForm.days_before}
                          onChange={e => setEditForm(f => ({ ...f, days_before: e.target.value }))}
                          className="h-8 text-sm rounded-lg"
                          type="number"
                          min="1"
                          max="365"
                          placeholder="30"
                        />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        className="h-8 rounded-lg gap-1.5 text-xs"
                        onClick={() => handleSaveEdit(reminder.id)}
                        disabled={savingEdit}
                      >
                        {savingEdit
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : <RiCheckLine className="w-3.5 h-3.5" />
                        }
                        保存修改
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8 rounded-lg text-xs"
                        onClick={cancelEdit}
                        disabled={savingEdit}
                      >
                        取消
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}

            {/* Load more */}
            {reminders.length < total && (
              <div className="text-center py-3">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={loading}
                  onClick={() => load(search, activeFilter, offset + LIMIT)}
                  className="rounded-xl h-9 gap-2"
                >
                  {loading ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : null}
                  加载更多（还有 {total - reminders.length} 条）
                </Button>
              </div>
            )}
          </div>
        ))}
      </div>
    </AdminLayout>
  );
}
