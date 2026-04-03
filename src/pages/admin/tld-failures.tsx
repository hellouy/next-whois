import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine, RiAlertLine,
  RiCheckLine, RiServerLine,
  RiErrorWarningLine, RiDeleteBinLine,
  RiInformationLine, RiEdit2Line, RiGlobalLine,
  RiProhibitedLine,
} from "@remixicon/react";
import type { TldFailureRow } from "@/pages/api/admin/tld-failures";

const REASON_COLORS: Record<string, { label: string; cls: string }> = {
  iana_fallback:  { label: "无服务器", cls: "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" },
  no_server:      { label: "无可达服务器", cls: "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400" },
  timeout:        { label: "超时", cls: "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" },
  parse_error:    { label: "解析失败", cls: "bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400" },
  rate_limited:   { label: "速率限制", cls: "bg-purple-100 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400" },
};

const REPAIR_STATUS: Record<string, { label: string; cls: string }> = {
  pending:    { label: "待处理", cls: "bg-muted text-muted-foreground" },
  in_progress:{ label: "处理中", cls: "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400" },
  fixed:      { label: "已修复", cls: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400" },
  wont_fix:   { label: "忽略", cls: "bg-zinc-100 dark:bg-zinc-800 text-zinc-500" },
};

function fmt(d: string | null) {
  if (!d) return "—";
  const date = new Date(d);
  const diff = Date.now() - date.getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return "刚刚";
  if (mins < 60) return `${mins}分钟前`;
  if (hours < 24) return `${hours}小时前`;
  if (days < 7) return `${days}天前`;
  return date.toLocaleDateString("zh-CN", { year: "2-digit", month: "2-digit", day: "2-digit" });
}

type Summary = { reason: string | null; count: string };

export default function TldFailuresPage() {
  const [rows, setRows] = React.useState<TldFailureRow[]>([]);
  const [summary, setSummary] = React.useState<Summary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [search, setSearch] = React.useState("");
  const [minFails, setMinFails] = React.useState(1);
  const [reasonFilter, setReasonFilter] = React.useState<string>("");
  const [editingNotes, setEditingNotes] = React.useState<string | null>(null);
  const [notesDraft, setNotesDraft] = React.useState("");
  const [savingNotes, setSavingNotes] = React.useState(false);
  const [clearing, setClearing] = React.useState<string | null>(null);
  const [clearingAll, setClearingAll] = React.useState(false);
  const [patchingStatus, setPatchingStatus] = React.useState<string | null>(null);
  const [resettingBypass, setResettingBypass] = React.useState<string | null>(null);
  const [resettingAllBypasses, setResettingAllBypasses] = React.useState(false);

  function load() {
    setLoading(true);
    const params = new URLSearchParams({ min_fails: String(minFails) });
    if (reasonFilter) params.set("reason", reasonFilter);
    if (search) params.set("search", search);
    fetch(`/api/admin/tld-failures?${params}`)
      .then(r => r.json())
      .then(d => { setRows(d.rows ?? []); setSummary(d.summary ?? []); })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load(); }, [minFails, reasonFilter]);

  async function clearTld(tld: string) {
    if (!confirm(`清零 .${tld} 的失败计数？`)) return;
    setClearing(tld);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      if (r.ok) { toast.success(`.${tld} 失败计数已清零`); load(); }
      else toast.error("操作失败");
    } finally { setClearing(null); }
  }

  async function clearAll() {
    const total = summary.reduce((s, r) => s + parseInt(r.count), 0);
    if (!confirm(`确认清零全部 ${total} 条失败记录？此操作不可撤销。`)) return;
    setClearingAll(true);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clear_all: true, reason: reasonFilter || undefined }),
      });
      const d = await r.json();
      if (r.ok) { toast.success(`已清零 ${d.cleared ?? 0} 条失败记录`); load(); }
      else toast.error("操作失败");
    } finally { setClearingAll(false); }
  }

  async function resetAllBypasses() {
    if (!confirm("重置所有 TLD 的 whoiser 旁路标记？此操作不可撤销。")) return;
    setResettingAllBypasses(true);
    try {
      const r = await fetch("/api/admin/whoiser-bypass", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clear_all: true }),
      });
      if (r.ok) { toast.success("所有旁路已重置"); load(); }
      else toast.error("重置失败");
    } finally { setResettingAllBypasses(false); }
  }

  async function resetBypass(tld: string) {
    if (!confirm(`重置 .${tld} 的 whoiser 旁路标记？重置后查询将再次尝试 whoiser。`)) return;
    setResettingBypass(tld);
    try {
      const r = await fetch("/api/admin/whoiser-bypass", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      if (r.ok) { toast.success(`.${tld} 旁路已重置`); load(); }
      else toast.error("重置失败");
    } finally { setResettingBypass(null); }
  }

  async function patchStatus(tld: string, repair_status: string) {
    setPatchingStatus(tld + repair_status);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, repair_status }),
      });
      if (r.ok) { toast.success("状态已更新"); load(); }
      else toast.error("更新失败");
    } finally { setPatchingStatus(null); }
  }

  async function saveNotes(tld: string) {
    setSavingNotes(true);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, admin_notes: notesDraft }),
      });
      if (r.ok) { toast.success("备注已保存"); setEditingNotes(null); load(); }
      else toast.error("保存失败");
    } finally { setSavingNotes(false); }
  }

  const total = summary.reduce((s, r) => s + parseInt(r.count), 0);

  return (
    <AdminLayout title="查询失败统计">
      <div className="space-y-5">

        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold flex items-center gap-2">
              <RiAlertLine className="w-5 h-5 text-amber-500" />
              域名后缀查询失败统计
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              记录 WHOIS/RDAP 查询失败的后缀 — 帮助管理员添加正确服务器或排查原因
            </p>
          </div>
          <div className="flex items-center gap-2">
            {rows.some(r => r.whoiser_bypass) && (
              <button
                onClick={resetAllBypasses}
                disabled={resettingAllBypasses}
                className="flex items-center gap-1.5 h-8 px-3 rounded-xl bg-orange-50 dark:bg-orange-950/30 border border-orange-200/60 dark:border-orange-800/40 text-orange-600 dark:text-orange-400 text-xs font-semibold hover:bg-orange-100 dark:hover:bg-orange-950/50 transition-colors"
              >
                {resettingAllBypasses ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiProhibitedLine className="w-3.5 h-3.5" />}
                全部重置旁路
              </button>
            )}
            {rows.length > 0 && (
              <button
                onClick={clearAll}
                disabled={clearingAll}
                className="flex items-center gap-1.5 h-8 px-3 rounded-xl bg-red-50 dark:bg-red-950/30 border border-red-200/60 dark:border-red-800/40 text-red-600 dark:text-red-400 text-xs font-semibold hover:bg-red-100 dark:hover:bg-red-950/50 transition-colors"
              >
                {clearingAll ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                清除全部失败记录
              </button>
            )}
            <button
              onClick={load}
              disabled={loading}
              className="p-2 rounded-xl hover:bg-muted transition-colors text-muted-foreground"
            >
              <RiRefreshLine className={cn("w-4 h-4", loading && "animate-spin")} />
            </button>
          </div>
        </div>

        {/* Summary pills */}
        {summary.length > 0 && (
          <div className="flex flex-wrap gap-2 items-center">
            <button
              onClick={() => setReasonFilter("")}
              className={cn(
                "px-3 py-1 rounded-full text-xs font-semibold border transition-all",
                !reasonFilter
                  ? "bg-primary text-primary-foreground border-primary"
                  : "bg-background border-border text-muted-foreground hover:border-primary/50"
              )}
            >
              全部 ({total})
            </button>
            {summary.map(s => {
              const r = REASON_COLORS[s.reason ?? ""] ?? { label: s.reason ?? "未知", cls: "bg-muted text-muted-foreground" };
              return (
                <button
                  key={s.reason ?? "null"}
                  onClick={() => setReasonFilter(reasonFilter === (s.reason ?? "") ? "" : (s.reason ?? ""))}
                  className={cn(
                    "px-3 py-1 rounded-full text-xs font-semibold border transition-all",
                    reasonFilter === (s.reason ?? "")
                      ? "bg-primary text-primary-foreground border-primary"
                      : `border-transparent ${r.cls} hover:opacity-80`
                  )}
                >
                  {r.label} ({s.count})
                </button>
              );
            })}
          </div>
        )}

        {/* Search + min-fails filter */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[160px] max-w-xs">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
            <Input
              placeholder="搜索后缀…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              onKeyDown={e => e.key === "Enter" && load()}
              className="pl-8 h-8 text-xs rounded-xl"
            />
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-muted-foreground whitespace-nowrap">最少失败次数</span>
            {[1, 3, 5, 10, 20].map(n => (
              <button
                key={n}
                onClick={() => setMinFails(n)}
                className={cn(
                  "w-8 h-8 rounded-lg text-xs font-semibold border transition-all",
                  minFails === n ? "bg-primary text-primary-foreground border-primary" : "bg-background border-border text-muted-foreground hover:border-primary/50"
                )}
              >{n}</button>
            ))}
          </div>
          <button onClick={load} className="h-8 px-3 rounded-xl bg-muted text-xs font-semibold hover:bg-muted/80 transition-colors">
            搜索
          </button>
        </div>

        {/* Tip */}
        <div className="flex items-start gap-2 bg-sky-50/50 dark:bg-sky-950/20 border border-sky-200/50 dark:border-sky-800/30 rounded-xl px-4 py-3">
          <RiInformationLine className="w-4 h-4 text-sky-500 shrink-0 mt-0.5" />
          <div className="text-xs text-sky-700 dark:text-sky-400 space-y-0.5">
            <p><strong>失败原因说明：</strong>无服务器 = IANA未收录该后缀的WHOIS服务器；超时 = 服务器有记录但无法连接；解析失败 = 响应内容无法识别；速率限制 = 服务器拒绝过频访问</p>
            <p>点击 <strong>配置服务器</strong> 可跳转到域名管理页面为该后缀添加自定义WHOIS服务器，保存后立即生效</p>
          </div>
        </div>

        {/* Table */}
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : rows.length === 0 ? (
          <div className="text-center py-16 text-muted-foreground text-sm">
            <RiCheckLine className="w-8 h-8 mx-auto mb-3 text-emerald-500" />
            暂无满足条件的失败记录
          </div>
        ) : (
          <div className="space-y-2">
            <p className="text-[11px] text-muted-foreground">共 {rows.length} 条 · 按失败次数排序</p>
            {rows.map(row => {
              const reasonInfo = REASON_COLORS[row.fail_reason ?? ""] ?? { label: row.fail_reason ?? "未知", cls: "bg-muted text-muted-foreground" };
              const repairInfo = REPAIR_STATUS[row.repair_status ?? "pending"] ?? REPAIR_STATUS.pending;
              const isEditing = editingNotes === row.tld;
              return (
                <div key={row.tld} className="glass-panel border border-border rounded-2xl p-4 space-y-2.5">
                  {/* Row 1: TLD + counts + badges */}
                  <div className="flex items-start gap-3 flex-wrap">
                    <div className="flex items-center gap-2 min-w-0 flex-1">
                      <code className="text-sm font-bold font-mono bg-muted/60 px-2 py-0.5 rounded-lg">.{row.tld}</code>
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0", reasonInfo.cls)}>{reasonInfo.label}</span>
                      {row.has_custom_server && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold shrink-0">已配置服务器</span>
                      )}
                      {row.whoiser_bypass && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 font-semibold shrink-0 flex items-center gap-0.5">
                          <RiProhibitedLine className="w-2.5 h-2.5" />
                          whoiser 已旁路
                        </span>
                      )}
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0", repairInfo.cls)}>{repairInfo.label}</span>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <span className="text-[11px] font-bold text-red-500">{row.fail_count.toLocaleString()}</span>
                      <span className="text-[10px] text-muted-foreground">次失败</span>
                      <span className="text-[10px] text-muted-foreground ml-2">{fmt(row.last_fail_at)}</span>
                    </div>
                  </div>

                  {/* Row 2: last domain + sample error */}
                  {(row.last_domain || row.sample_error) && (
                    <div className="space-y-1">
                      {row.last_domain && (
                        <div className="flex items-center gap-1.5">
                          <RiGlobalLine className="w-3 h-3 text-muted-foreground/60 shrink-0" />
                          <span className="text-[10px] text-muted-foreground">最近查询：</span>
                          <code className="text-[10px] font-mono text-foreground/80">{row.last_domain}</code>
                        </div>
                      )}
                      {row.sample_error && (
                        <div className="flex items-start gap-1.5">
                          <RiErrorWarningLine className="w-3 h-3 text-amber-500 shrink-0 mt-0.5" />
                          <p className="text-[10px] text-muted-foreground leading-relaxed break-all">{row.sample_error}</p>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Admin notes */}
                  {isEditing ? (
                    <div className="space-y-1.5">
                      <textarea
                        value={notesDraft}
                        onChange={e => setNotesDraft(e.target.value)}
                        placeholder="填写处理备注、发现的服务器地址等…"
                        rows={2}
                        className="w-full text-xs border border-border rounded-xl px-3 py-2 bg-background resize-none focus:outline-none focus:ring-2 focus:ring-primary/30"
                      />
                      <div className="flex items-center gap-2">
                        <Button size="sm" className="h-7 text-[11px] px-3 rounded-lg" disabled={savingNotes} onClick={() => saveNotes(row.tld)}>
                          {savingNotes ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiCheckLine className="w-3 h-3" />}
                          保存备注
                        </Button>
                        <button onClick={() => setEditingNotes(null)} className="text-[11px] text-muted-foreground hover:text-foreground">
                          取消
                        </button>
                      </div>
                    </div>
                  ) : row.admin_notes ? (
                    <div className="flex items-start gap-1.5 bg-muted/40 rounded-xl px-3 py-2">
                      <RiInformationLine className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
                      <p className="text-[10px] text-muted-foreground flex-1">{row.admin_notes}</p>
                      <button onClick={() => { setEditingNotes(row.tld); setNotesDraft(row.admin_notes ?? ""); }} className="text-muted-foreground/60 hover:text-foreground">
                        <RiEdit2Line className="w-3 h-3" />
                      </button>
                    </div>
                  ) : null}

                  {/* Actions row */}
                  <div className="flex items-center gap-1.5 flex-wrap pt-0.5 border-t border-border/40">
                    {/* Repair status controls */}
                    {(["in_progress", "fixed", "wont_fix"] as const).map(status => {
                      const info = REPAIR_STATUS[status];
                      const isActive = row.repair_status === status;
                      const isPending = patchingStatus === row.tld + status;
                      return (
                        <button
                          key={status}
                          onClick={() => patchStatus(row.tld, status)}
                          disabled={isActive || !!patchingStatus}
                          className={cn(
                            "text-[10px] px-2 py-1 rounded-lg border font-semibold transition-all",
                            isActive
                              ? cn(info.cls, "border-current/30")
                              : "border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary bg-background"
                          )}
                        >
                          {isPending ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin inline" /> : info.label}
                        </button>
                      );
                    })}

                    <div className="flex-1" />

                    {/* Notes */}
                    {!isEditing && (
                      <button
                        onClick={() => { setEditingNotes(row.tld); setNotesDraft(row.admin_notes ?? ""); }}
                        className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary flex items-center gap-1"
                      >
                        <RiEdit2Line className="w-2.5 h-2.5" />
                        {row.admin_notes ? "编辑备注" : "添加备注"}
                      </button>
                    )}

                    {/* Configure server */}
                    <a
                      href={`/admin/domains?tab=failures`}
                      className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-sky-600 dark:text-sky-400 hover:border-sky-400/60 flex items-center gap-1"
                    >
                      <RiServerLine className="w-2.5 h-2.5" />
                      配置服务器
                    </a>

                    {/* Reset whoiser bypass */}
                    {row.whoiser_bypass && (
                      <button
                        onClick={() => resetBypass(row.tld)}
                        disabled={resettingBypass === row.tld}
                        className="text-[10px] px-2 py-1 rounded-lg border border-red-200/60 dark:border-red-800/40 text-red-600 dark:text-red-400 hover:border-red-400/60 flex items-center gap-1"
                      >
                        {resettingBypass === row.tld
                          ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" />
                          : <RiProhibitedLine className="w-2.5 h-2.5" />
                        }
                        重置旁路
                      </button>
                    )}

                    {/* Reset count */}
                    <button
                      onClick={() => clearTld(row.tld)}
                      disabled={clearing === row.tld}
                      className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-red-500 hover:border-red-400/60 flex items-center gap-1"
                    >
                      {clearing === row.tld
                        ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" />
                        : <RiDeleteBinLine className="w-2.5 h-2.5" />
                      }
                      清零
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}

