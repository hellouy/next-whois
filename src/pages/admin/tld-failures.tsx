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
  RiProhibitedLine, RiWifiLine, RiCloseLine,
  RiArrowLeftLine, RiArrowRightLine,
  RiCheckboxLine, RiCheckboxBlankLine, RiEyeOffLine,
  RiExternalLinkLine,
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
  pending:     { label: "待处理",  cls: "bg-muted text-muted-foreground" },
  in_progress: { label: "处理中",  cls: "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400" },
  fixed:       { label: "已修复",  cls: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400" },
  wont_fix:    { label: "忽略",    cls: "bg-zinc-100 dark:bg-zinc-800 text-zinc-500" },
};

const PER_PAGE_OPTIONS = [20, 50, 100];

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

type TestResult = {
  ok: boolean;
  method: string;
  output?: string;
  statusCode?: number;
  error?: string;
  elapsedMs: number;
};

type TestPanel = {
  type: "tcp" | "http";
  host: string;
  port: string;
  url: string;
  result: TestResult | null;
  loading: boolean;
};

type ApiPanelResult = {
  ok: boolean;
  details?: string;
  error?: string;
  raw?: string;
};

type ApiPanel = {
  service: "tianhu" | "nazhumi" | "miqingju" | "yisi";
  result: ApiPanelResult | null;
  loading: boolean;
};

export default function TldFailuresPage() {
  const [rows, setRows]           = React.useState<TldFailureRow[]>([]);
  const [summary, setSummary]     = React.useState<Summary[]>([]);
  const [loading, setLoading]     = React.useState(true);
  const [search, setSearch]       = React.useState("");
  const [minFails, setMinFails]   = React.useState(1);
  const [reasonFilter, setReasonFilter] = React.useState<string>("");
  const [hideManual, setHideManual]     = React.useState(false);

  // Pagination
  const [page, setPage]           = React.useState(1);
  const [perPage, setPerPage]     = React.useState(50);
  const [total, setTotal]         = React.useState(0);
  const [totalPages, setTotalPages] = React.useState(0);

  // Selection for bulk delete
  const [selected, setSelected]   = React.useState<Set<string>>(new Set());

  // Editing
  const [editingNotes, setEditingNotes]   = React.useState<string | null>(null);
  const [notesDraft, setNotesDraft]       = React.useState("");
  const [savingNotes, setSavingNotes]     = React.useState(false);
  const [clearing, setClearing]           = React.useState<string | null>(null);
  const [clearingAll, setClearingAll]     = React.useState(false);
  const [bulkDeleting, setBulkDeleting]   = React.useState(false);
  const [patchingStatus, setPatchingStatus]       = React.useState<string | null>(null);
  const [resettingBypass, setResettingBypass]     = React.useState<string | null>(null);
  const [resettingAllBypasses, setResettingAllBypasses] = React.useState(false);
  const [testPanels, setTestPanels] = React.useState<Record<string, TestPanel>>({});
  const [apiPanels, setApiPanels]   = React.useState<Record<string, ApiPanel>>({});
  const [settingApiSource, setSettingApiSource] = React.useState<string | null>(null);

  function buildParams(overrides: Record<string, string | number> = {}) {
    const p: Record<string, string> = {
      min_fails: String(minFails),
      page:      String(page),
      per_page:  String(perPage),
      period_compare: "1",
    };
    if (reasonFilter) p.reason     = reasonFilter;
    if (search.trim()) p.search    = search.trim();
    if (hideManual)    p.hide_manual = "1";
    Object.entries(overrides).forEach(([k, v]) => { p[k] = String(v); });
    return new URLSearchParams(p).toString();
  }

  function load(pageOverride?: number) {
    setLoading(true);
    setSelected(new Set());
    const qs = buildParams(pageOverride ? { page: pageOverride } : {});
    fetch(`/api/admin/tld-failures?${qs}`)
      .then(r => r.json())
      .then(d => {
        setRows(d.rows ?? []);
        setSummary(d.summary ?? []);
        setTotal(d.total ?? 0);
        setTotalPages(d.total_pages ?? 1);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => {
    setPage(1);
    load(1);
  }, [minFails, reasonFilter, hideManual]); // eslint-disable-line react-hooks/exhaustive-deps

  function goPage(p: number) {
    const np = Math.max(1, Math.min(totalPages, p));
    setPage(np);
    load(np);
  }

  // ── Actions ─────────────────────────────────────────────────────────────
  async function clearTld(tld: string) {
    if (!confirm(`清零 .${tld} 的失败计数？`)) return;
    setClearing(tld);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      if (r.ok) { toast.success(`.${tld} 失败计数已清零`); load(page); }
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
      if (r.ok) { toast.success(`已清零 ${d.cleared ?? 0} 条失败记录`); load(1); setPage(1); }
      else toast.error("操作失败");
    } finally { setClearingAll(false); }
  }

  async function bulkDelete() {
    if (selected.size === 0) return;
    if (!confirm(`确认清零已勾选的 ${selected.size} 条失败记录？`)) return;
    setBulkDeleting(true);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tlds: Array.from(selected) }),
      });
      const d = await r.json();
      if (r.ok) { toast.success(`已清零 ${d.cleared ?? 0} 条`); load(page); }
      else toast.error("操作失败");
    } finally { setBulkDeleting(false); }
  }

  async function resetAllBypasses() {
    if (!confirm("重置所有 TLD 的 whoiser 旁路标记？")) return;
    setResettingAllBypasses(true);
    try {
      const r = await fetch("/api/admin/whoiser-bypass", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clear_all: true }),
      });
      if (r.ok) { toast.success("所有旁路已重置"); load(page); }
      else toast.error("重置失败");
    } finally { setResettingAllBypasses(false); }
  }

  async function resetBypass(tld: string) {
    if (!confirm(`重置 .${tld} 的 whoiser 旁路标记？`)) return;
    setResettingBypass(tld);
    try {
      const r = await fetch("/api/admin/whoiser-bypass", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      if (r.ok) { toast.success(`.${tld} 旁路已重置`); load(page); }
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
      if (r.ok) { toast.success("状态已更新"); load(page); }
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
      if (r.ok) { toast.success("备注已保存"); setEditingNotes(null); load(page); }
      else toast.error("保存失败");
    } finally { setSavingNotes(false); }
  }

  function openTestPanel(tld: string) {
    setTestPanels(prev => ({
      ...prev,
      [tld]: prev[tld] ?? {
        type: "tcp", host: `whois.nic.${tld}`, port: "",
        url: `https://rdap.nic.${tld}/domain/`, result: null, loading: false,
      },
    }));
  }

  function closeTestPanel(tld: string) {
    setTestPanels(prev => { const n = { ...prev }; delete n[tld]; return n; });
  }

  function updateTestPanel(tld: string, patch: Partial<TestPanel>) {
    setTestPanels(prev => ({ ...prev, [tld]: { ...prev[tld], ...patch } }));
  }

  async function runTest(tld: string) {
    const panel = testPanels[tld];
    if (!panel) return;
    updateTestPanel(tld, { loading: true, result: null });
    let entry: object;
    if (panel.type === "tcp") {
      const portNum = panel.port.trim() ? parseInt(panel.port.trim(), 10) : undefined;
      entry = { type: "tcp", host: panel.host.trim(), ...(portNum ? { port: portNum } : {}) };
    } else {
      entry = { type: "http", url: panel.url.trim(), method: "GET" };
    }
    try {
      const r = await fetch("/api/admin/test-server", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, entry }),
      });
      const data: TestResult = await r.json();
      updateTestPanel(tld, { result: data, loading: false });
    } catch (e: any) {
      updateTestPanel(tld, {
        loading: false,
        result: { ok: false, method: "?", error: e?.message || "网络错误", elapsedMs: 0 },
      });
    }
  }

  // ── Third-party API panel ────────────────────────────────────────────────
  function openApiPanel(tld: string) {
    setApiPanels(prev => ({
      ...prev,
      [tld]: prev[tld] ?? { service: "tianhu", result: null, loading: false },
    }));
  }

  function closeApiPanel(tld: string) {
    setApiPanels(prev => { const n = { ...prev }; delete n[tld]; return n; });
  }

  function updateApiPanel(tld: string, patch: Partial<ApiPanel>) {
    setApiPanels(prev => ({ ...prev, [tld]: { ...prev[tld], ...patch } }));
  }

  async function runApiLookup(tld: string) {
    const panel = apiPanels[tld];
    if (!panel) return;
    updateApiPanel(tld, { loading: true, result: null });
    try {
      const r = await fetch("/api/admin/third-party-lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, service: panel.service }),
      });
      const data: ApiPanelResult = await r.json();
      updateApiPanel(tld, { result: data, loading: false });
    } catch (e: any) {
      updateApiPanel(tld, {
        loading: false,
        result: { ok: false, error: e?.message || "网络错误" },
      });
    }
  }

  // ── Per-TLD API source management ───────────────────────────────────────
  async function applyTldApiSource(tld: string, source: string | null) {
    setSettingApiSource(tld);
    try {
      const r = await fetch("/api/admin/tld-api-source", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, source }),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setRows(prev => prev.map(row =>
        row.tld === tld ? { ...row, tld_api_source: source } : row,
      ));
      toast.success(source ? `已将 .${tld} 设为默认 ${source === "tianhu" ? "天虎" : "亿思云"} API 查询` : `已清除 .${tld} 的第三方 API 设置`);
    } catch {
      toast.error("操作失败，请重试");
    } finally {
      setSettingApiSource(null);
    }
  }

  // ── Selection helpers ────────────────────────────────────────────────────
  function toggleSelect(tld: string) {
    setSelected(prev => {
      const n = new Set(prev);
      if (n.has(tld)) n.delete(tld); else n.add(tld);
      return n;
    });
  }

  function toggleSelectAll() {
    if (selected.size === rows.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(rows.map(r => r.tld)));
    }
  }

  const summaryTotal = summary.reduce((s, r) => s + parseInt(r.count), 0);
  const allSelected  = rows.length > 0 && selected.size === rows.length;

  return (
    <AdminLayout title="查询失败统计">
      <div className="space-y-4">

        {/* ── Header ── */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold flex items-center gap-2">
              <RiAlertLine className="w-5 h-5 text-amber-500" />
              域名后缀查询失败统计
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              共 <strong>{total}</strong> 条 · 每页 {perPage}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Hide manually filled toggle */}
            <button
              onClick={() => setHideManual(v => !v)}
              className={cn(
                "flex items-center gap-1.5 h-8 px-3 rounded-xl border text-xs font-semibold transition-colors",
                hideManual
                  ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-400"
                  : "bg-background border-border text-muted-foreground hover:border-primary/50",
              )}
            >
              <RiEyeOffLine className="w-3.5 h-3.5" />
              {hideManual ? "已隐藏手动填写" : "隐藏手动填写"}
            </button>

            {/* Bulk delete selected */}
            {selected.size > 0 && (
              <button
                onClick={bulkDelete}
                disabled={bulkDeleting}
                className="flex items-center gap-1.5 h-8 px-3 rounded-xl bg-orange-50 dark:bg-orange-950/30 border border-orange-200/60 dark:border-orange-800/40 text-orange-600 dark:text-orange-400 text-xs font-semibold hover:bg-orange-100 transition-colors"
              >
                {bulkDeleting ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                清零已选 ({selected.size})
              </button>
            )}

            {rows.some(r => r.whoiser_bypass) && (
              <button
                onClick={resetAllBypasses}
                disabled={resettingAllBypasses}
                className="flex items-center gap-1.5 h-8 px-3 rounded-xl bg-orange-50 dark:bg-orange-950/30 border border-orange-200/60 dark:border-orange-800/40 text-orange-600 dark:text-orange-400 text-xs font-semibold hover:bg-orange-100 transition-colors"
              >
                {resettingAllBypasses ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiProhibitedLine className="w-3.5 h-3.5" />}
                全部重置旁路
              </button>
            )}

            <button
              onClick={clearAll}
              disabled={clearingAll || total === 0}
              className="flex items-center gap-1.5 h-8 px-3 rounded-xl bg-red-50 dark:bg-red-950/30 border border-red-200/60 dark:border-red-800/40 text-red-600 dark:text-red-400 text-xs font-semibold hover:bg-red-100 transition-colors disabled:opacity-40"
            >
              {clearingAll ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
              清除全部
            </button>

            <button onClick={() => load(page)} disabled={loading} className="p-2 rounded-xl hover:bg-muted transition-colors text-muted-foreground">
              <RiRefreshLine className={cn("w-4 h-4", loading && "animate-spin")} />
            </button>
          </div>
        </div>

        {/* ── Summary pills ── */}
        {summary.length > 0 && (
          <div className="flex flex-wrap gap-2 items-center">
            <button
              onClick={() => setReasonFilter("")}
              className={cn(
                "px-3 py-1 rounded-full text-xs font-semibold border transition-all",
                !reasonFilter
                  ? "bg-primary text-primary-foreground border-primary"
                  : "bg-background border-border text-muted-foreground hover:border-primary/50",
              )}
            >
              全部 ({summaryTotal})
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
                      : `border-transparent ${r.cls} hover:opacity-80`,
                  )}
                >
                  {r.label} ({s.count})
                </button>
              );
            })}
          </div>
        )}

        {/* ── Search + filters ── */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[160px] max-w-xs">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
            <Input
              placeholder="搜索后缀…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") { setPage(1); load(1); } }}
              className="pl-8 h-8 text-xs rounded-xl"
            />
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-muted-foreground whitespace-nowrap">最少失败</span>
            {[1, 3, 5, 10, 20].map(n => (
              <button
                key={n}
                onClick={() => setMinFails(n)}
                className={cn(
                  "w-8 h-8 rounded-lg text-xs font-semibold border transition-all",
                  minFails === n ? "bg-primary text-primary-foreground border-primary" : "bg-background border-border text-muted-foreground hover:border-primary/50",
                )}
              >{n}</button>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-muted-foreground">每页</span>
            {PER_PAGE_OPTIONS.map(n => (
              <button
                key={n}
                onClick={() => { setPerPage(n); setPage(1); load(1); }}
                className={cn(
                  "w-8 h-8 rounded-lg text-xs font-semibold border transition-all",
                  perPage === n ? "bg-primary text-primary-foreground border-primary" : "bg-background border-border text-muted-foreground hover:border-primary/50",
                )}
              >{n}</button>
            ))}
          </div>
          <button onClick={() => { setPage(1); load(1); }} className="h-8 px-3 rounded-xl bg-muted text-xs font-semibold hover:bg-muted/80 transition-colors">
            搜索
          </button>
        </div>

        {/* ── Tip ── */}
        <div className="flex items-start gap-2 bg-sky-50/50 dark:bg-sky-950/20 border border-sky-200/50 dark:border-sky-800/30 rounded-xl px-4 py-3">
          <RiInformationLine className="w-4 h-4 text-sky-500 shrink-0 mt-0.5" />
          <div className="text-xs text-sky-700 dark:text-sky-400 space-y-0.5">
            <p><strong>失败原因：</strong>无服务器 = IANA未收录；超时 = 无法连接；解析失败 = 响应无法识别；速率限制 = 被拒绝</p>
            <p>勾选多行后点「清零已选」可批量清除。手动填写后的条目可用「隐藏手动填写」过滤。</p>
          </div>
        </div>

        {/* ── Table ── */}
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
          <>
            {/* Select-all bar */}
            <div className="flex items-center gap-3 px-1">
              <button onClick={toggleSelectAll} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                {allSelected
                  ? <RiCheckboxLine className="w-4 h-4 text-primary" />
                  : <RiCheckboxBlankLine className="w-4 h-4" />}
                {allSelected ? "取消全选" : `全选本页 (${rows.length})`}
              </button>
              {selected.size > 0 && (
                <span className="text-xs text-primary font-medium">已选 {selected.size} 条</span>
              )}
              <span className="ml-auto text-[11px] text-muted-foreground">
                第 {page} / {totalPages} 页 · 共 {total} 条
              </span>
            </div>

            <div className="space-y-2">
              {rows.map(row => {
                const reasonInfo = REASON_COLORS[row.fail_reason ?? ""] ?? { label: row.fail_reason ?? "未知", cls: "bg-muted text-muted-foreground" };
                const repairInfo = REPAIR_STATUS[row.repair_status ?? "pending"] ?? REPAIR_STATUS.pending;
                const isEditing  = editingNotes === row.tld;
                const testPanel  = testPanels[row.tld];
                const apiPanel   = apiPanels[row.tld];
                const isSelected = selected.has(row.tld);

                return (
                  <div
                    key={row.tld}
                    className={cn(
                      "glass-panel border rounded-2xl p-4 space-y-2.5 transition-colors",
                      isSelected ? "border-primary/50 bg-primary/5" : "border-border",
                    )}
                  >
                    {/* Row 1 */}
                    <div className="flex items-start gap-2 flex-wrap">
                      {/* Checkbox */}
                      <button
                        onClick={() => toggleSelect(row.tld)}
                        className="mt-0.5 shrink-0 text-muted-foreground hover:text-primary transition-colors"
                      >
                        {isSelected
                          ? <RiCheckboxLine className="w-4 h-4 text-primary" />
                          : <RiCheckboxBlankLine className="w-4 h-4" />}
                      </button>

                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        <code className="text-sm font-bold font-mono bg-muted/60 px-2 py-0.5 rounded-lg">.{row.tld}</code>
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0", reasonInfo.cls)}>{reasonInfo.label}</span>
                        {row.has_custom_server && (
                          <span className={cn(
                            "text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0",
                            row.custom_server_source === "manual"
                              ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400"
                              : "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400",
                          )}>
                            {row.custom_server_source === "manual" ? "已手动填写" : "已配置服务器"}
                          </span>
                        )}
                        {row.whoiser_bypass && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 font-semibold shrink-0 flex items-center gap-0.5">
                            <RiProhibitedLine className="w-2.5 h-2.5" />whoiser 旁路
                          </span>
                        )}
                        {row.tld_api_source && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400 font-semibold shrink-0 flex items-center gap-0.5">
                            <RiExternalLinkLine className="w-2.5 h-2.5" />
                            {row.tld_api_source === "tianhu" ? "天虎 API" : row.tld_api_source === "yisi" ? "亿思云 API" : row.tld_api_source}
                          </span>
                        )}
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0", repairInfo.cls)}>{repairInfo.label}</span>
                      </div>

                      <div className="flex items-center gap-1 shrink-0">
                        <span className="text-[11px] font-bold text-red-500">{row.fail_count.toLocaleString()}</span>
                        <span className="text-[10px] text-muted-foreground">次失败</span>
                        {row.this_week_count !== undefined && row.prev_week_count !== undefined && (row.this_week_count > 0 || row.prev_week_count > 0) && (() => {
                          const delta = row.this_week_count - row.prev_week_count;
                          if (delta === 0) return (
                            <span className="text-[9px] px-1.5 py-0.5 rounded-full font-semibold bg-muted text-muted-foreground ml-1" title={`本周 ${row.this_week_count} / 上周 ${row.prev_week_count}`}>→{row.this_week_count}</span>
                          );
                          return (
                            <span className={cn(
                              "text-[9px] px-1.5 py-0.5 rounded-full font-semibold ml-1",
                              delta > 0 ? "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" : "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400",
                            )} title={`本周 ${row.this_week_count} / 上周 ${row.prev_week_count}`}>
                              {delta > 0 ? `↑${delta}` : `↓${Math.abs(delta)}`}
                            </span>
                          );
                        })()}
                        <span className="text-[10px] text-muted-foreground ml-2">{fmt(row.last_fail_at)}</span>
                      </div>
                    </div>

                    {/* Row 2 */}
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
                          <button onClick={() => setEditingNotes(null)} className="text-[11px] text-muted-foreground hover:text-foreground">取消</button>
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

                    {/* Inline test panel */}
                    {testPanel && (
                      <div className="border border-border/60 rounded-xl bg-muted/20 p-3 space-y-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-semibold text-foreground/80 flex items-center gap-1.5">
                            <RiWifiLine className="w-3.5 h-3.5 text-sky-500" />
                            测试 WHOIS 服务器连通性
                          </span>
                          <button onClick={() => closeTestPanel(row.tld)} className="text-muted-foreground/60 hover:text-foreground transition-colors">
                            <RiCloseLine className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <div className="flex gap-1">
                          {(["tcp", "http"] as const).map(t => (
                            <button
                              key={t}
                              onClick={() => updateTestPanel(row.tld, { type: t, result: null })}
                              className={cn(
                                "px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                                testPanel.type === t
                                  ? "bg-primary text-primary-foreground border-primary"
                                  : "border-border/60 text-muted-foreground hover:border-primary/40 bg-background",
                              )}
                            >
                              {t === "tcp" ? "WHOIS TCP" : "RDAP / HTTP"}
                            </button>
                          ))}
                        </div>
                        {testPanel.type === "tcp" ? (
                          <div className="flex gap-2">
                            <Input value={testPanel.host} onChange={e => updateTestPanel(row.tld, { host: e.target.value })} placeholder={`whois.nic.${row.tld}`} className="h-7 text-[11px] rounded-lg flex-1 font-mono" />
                            <Input value={testPanel.port} onChange={e => updateTestPanel(row.tld, { port: e.target.value })} placeholder="43" className="h-7 text-[11px] rounded-lg w-16 font-mono" />
                          </div>
                        ) : (
                          <Input value={testPanel.url} onChange={e => updateTestPanel(row.tld, { url: e.target.value })} placeholder={`https://rdap.nic.${row.tld}/domain/`} className="h-7 text-[11px] rounded-lg font-mono" />
                        )}
                        <button
                          onClick={() => runTest(row.tld)}
                          disabled={testPanel.loading || (testPanel.type === "tcp" ? !testPanel.host.trim() : !testPanel.url.trim())}
                          className="flex items-center gap-1.5 h-7 px-3 rounded-lg bg-sky-500 hover:bg-sky-600 disabled:opacity-50 text-white text-[11px] font-semibold transition-colors"
                        >
                          {testPanel.loading ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiWifiLine className="w-3 h-3" />}
                          {testPanel.loading ? "测试中…" : "开始测试"}
                        </button>
                        {testPanel.result && (
                          <div className={cn(
                            "rounded-xl border p-3 space-y-1.5",
                            testPanel.result.ok
                              ? "bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200/60 dark:border-emerald-800/30"
                              : "bg-red-50/50 dark:bg-red-950/20 border-red-200/60 dark:border-red-800/30",
                          )}>
                            <div className="flex items-center gap-2 flex-wrap">
                              {testPanel.result.ok ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500 shrink-0" /> : <RiErrorWarningLine className="w-3.5 h-3.5 text-red-500 shrink-0" />}
                              <span className={cn("text-[11px] font-semibold", testPanel.result.ok ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400")}>
                                {testPanel.result.ok ? "连接成功" : "连接失败"}
                              </span>
                              <span className="text-[10px] text-muted-foreground">{testPanel.result.method}</span>
                              {testPanel.result.statusCode !== undefined && <span className="text-[10px] text-muted-foreground">HTTP {testPanel.result.statusCode}</span>}
                              <span className="text-[10px] text-muted-foreground ml-auto">{testPanel.result.elapsedMs} ms</span>
                            </div>
                            {testPanel.result.error && <p className="text-[10px] text-red-600 dark:text-red-400 break-all">{testPanel.result.error}</p>}
                            {testPanel.result.output && (
                              <pre className="text-[10px] font-mono text-foreground/70 bg-black/5 dark:bg-white/5 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-all max-h-40 leading-relaxed">
                                {testPanel.result.output}
                              </pre>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Third-party API lookup panel */}
                    {apiPanel && (
                      <div className="border border-border/60 rounded-xl bg-muted/20 p-3 space-y-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-semibold text-foreground/80 flex items-center gap-1.5">
                            <RiExternalLinkLine className="w-3.5 h-3.5 text-violet-500" />
                            第三方 API 查询 · example.{row.tld}
                          </span>
                          <button onClick={() => closeApiPanel(row.tld)} className="text-muted-foreground/60 hover:text-foreground transition-colors">
                            <RiCloseLine className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <div className="flex gap-1 flex-wrap">
                          {(["tianhu", "nazhumi", "miqingju", "yisi"] as const).map(svc => {
                            const labels: Record<string, string> = { tianhu: "天虎", nazhumi: "哪煮米", miqingju: "米情局", yisi: "亿思云" };
                            return (
                              <button
                                key={svc}
                                onClick={() => updateApiPanel(row.tld, { service: svc, result: null })}
                                className={cn(
                                  "px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                                  apiPanel.service === svc
                                    ? "bg-violet-500 text-white border-violet-500"
                                    : "border-border/60 text-muted-foreground hover:border-violet-400/60 bg-background",
                                )}
                              >
                                {labels[svc]}
                              </button>
                            );
                          })}
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <button
                            onClick={() => runApiLookup(row.tld)}
                            disabled={apiPanel.loading}
                            className="flex items-center gap-1.5 h-7 px-3 rounded-lg bg-violet-500 hover:bg-violet-600 disabled:opacity-50 text-white text-[11px] font-semibold transition-colors"
                          >
                            {apiPanel.loading ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiExternalLinkLine className="w-3 h-3" />}
                            {apiPanel.loading ? "查询中…" : "发起查询"}
                          </button>
                          {/* Quick-set buttons: only for tianhu and yisi (WHOIS APIs) */}
                          {(["tianhu", "yisi"] as const).includes(apiPanel.service) && (() => {
                            const isActive = row.tld_api_source === apiPanel.service;
                            const isBusy   = settingApiSource === row.tld;
                            const labels: Record<string, string> = { tianhu: "天虎", yisi: "亿思云" };
                            return isActive ? (
                              <button
                                onClick={() => applyTldApiSource(row.tld, null)}
                                disabled={isBusy}
                                className="flex items-center gap-1 h-7 px-2.5 rounded-lg border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 text-[10px] font-semibold disabled:opacity-50 transition-colors hover:bg-red-100 dark:hover:bg-red-950/50"
                              >
                                {isBusy ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiCloseLine className="w-2.5 h-2.5" />}
                                取消 {labels[apiPanel.service]} 默认
                              </button>
                            ) : (
                              <button
                                onClick={() => applyTldApiSource(row.tld, apiPanel.service)}
                                disabled={isBusy}
                                className="flex items-center gap-1 h-7 px-2.5 rounded-lg border border-violet-300 dark:border-violet-700 bg-violet-50 dark:bg-violet-950/30 text-violet-600 dark:text-violet-400 text-[10px] font-semibold disabled:opacity-50 transition-colors hover:bg-violet-100 dark:hover:bg-violet-950/50"
                              >
                                {isBusy ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiExternalLinkLine className="w-2.5 h-2.5" />}
                                设为 {labels[apiPanel.service]} 默认
                              </button>
                            );
                          })()}
                        </div>
                        {apiPanel.result && (
                          <div className={cn(
                            "rounded-xl border p-3 space-y-1.5",
                            apiPanel.result.ok
                              ? "bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200/60 dark:border-emerald-800/30"
                              : "bg-red-50/50 dark:bg-red-950/20 border-red-200/60 dark:border-red-800/30",
                          )}>
                            <div className="flex items-center gap-2">
                              {apiPanel.result.ok
                                ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                                : <RiErrorWarningLine className="w-3.5 h-3.5 text-red-500 shrink-0" />}
                              <span className={cn("text-[11px] font-semibold", apiPanel.result.ok ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400")}>
                                {apiPanel.result.ok ? "查询成功" : "查询失败"}
                              </span>
                            </div>
                            {apiPanel.result.details && <p className="text-[10px] text-foreground/70 leading-relaxed">{apiPanel.result.details}</p>}
                            {apiPanel.result.error && <p className="text-[10px] text-red-600 dark:text-red-400 break-all">{apiPanel.result.error}</p>}
                            {apiPanel.result.raw && (
                              <pre className="text-[10px] font-mono text-foreground/70 bg-black/5 dark:bg-white/5 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-all max-h-32 leading-relaxed">
                                {apiPanel.result.raw}
                              </pre>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex items-center gap-1.5 flex-wrap pt-0.5 border-t border-border/40">
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
                                : "border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary bg-background",
                            )}
                          >
                            {isPending ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin inline" /> : info.label}
                          </button>
                        );
                      })}

                      {/* ── Per-TLD API source quick-set ─────────────────── */}
                      <div className="h-3 w-px bg-border/60 mx-0.5 shrink-0" />
                      {(["tianhu", "yisi"] as const).map(src => {
                        const label = src === "tianhu" ? "天虎" : "亿思云";
                        const isActive = row.tld_api_source === src;
                        const isBusy   = settingApiSource === row.tld;
                        return (
                          <button
                            key={src}
                            onClick={() => applyTldApiSource(row.tld, isActive ? null : src)}
                            disabled={isBusy}
                            title={isActive ? `取消 ${label} API 路由，点击清除` : `将 .${row.tld} 的所有查询路由至 ${label} API`}
                            className={cn(
                              "text-[10px] px-2 py-1 rounded-lg border font-semibold flex items-center gap-0.5 transition-all disabled:opacity-50",
                              isActive
                                ? "bg-violet-100 dark:bg-violet-950/40 border-violet-300 dark:border-violet-700 text-violet-700 dark:text-violet-300"
                                : "border-border/60 text-muted-foreground hover:border-violet-400/60 hover:text-violet-600 bg-background",
                            )}
                          >
                            {isBusy ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiExternalLinkLine className="w-2.5 h-2.5" />}
                            {label}{isActive ? " ✓" : ""}
                          </button>
                        );
                      })}
                      {row.tld_api_source && (
                        <button
                          onClick={() => applyTldApiSource(row.tld, null)}
                          disabled={settingApiSource === row.tld}
                          title="清除第三方 API 路由设置"
                          className="text-[10px] px-1.5 py-1 rounded-lg border border-border/60 text-muted-foreground hover:border-red-400/60 hover:text-red-500 flex items-center gap-0.5 transition-all disabled:opacity-50 bg-background"
                        >
                          <RiCloseLine className="w-2.5 h-2.5" />清除
                        </button>
                      )}

                      <div className="flex-1" />
                      {!isEditing && (
                        <button
                          onClick={() => { setEditingNotes(row.tld); setNotesDraft(row.admin_notes ?? ""); }}
                          className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary flex items-center gap-1"
                        >
                          <RiEdit2Line className="w-2.5 h-2.5" />
                          {row.admin_notes ? "编辑备注" : "添加备注"}
                        </button>
                      )}
                      <button
                        onClick={() => apiPanel ? closeApiPanel(row.tld) : openApiPanel(row.tld)}
                        className={cn(
                          "text-[10px] px-2 py-1 rounded-lg border flex items-center gap-1 transition-all",
                          apiPanel
                            ? "border-violet-400/60 bg-violet-50 dark:bg-violet-950/30 text-violet-600 dark:text-violet-400"
                            : "border-border/60 text-muted-foreground hover:border-violet-400/60 hover:text-violet-600",
                        )}
                      >
                        <RiExternalLinkLine className="w-2.5 h-2.5" />第三方查询
                      </button>
                      <button
                        onClick={() => testPanel ? closeTestPanel(row.tld) : openTestPanel(row.tld)}
                        className={cn(
                          "text-[10px] px-2 py-1 rounded-lg border flex items-center gap-1 transition-all",
                          testPanel
                            ? "border-sky-400/60 bg-sky-50 dark:bg-sky-950/30 text-sky-600 dark:text-sky-400"
                            : "border-border/60 text-muted-foreground hover:border-sky-400/60 hover:text-sky-600",
                        )}
                      >
                        <RiWifiLine className="w-2.5 h-2.5" />测试连接
                      </button>
                      <a href="/admin/domains?tab=failures" className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-sky-600 dark:text-sky-400 hover:border-sky-400/60 flex items-center gap-1">
                        <RiServerLine className="w-2.5 h-2.5" />配置服务器
                      </a>
                      {row.whoiser_bypass && (
                        <button
                          onClick={() => resetBypass(row.tld)}
                          disabled={resettingBypass === row.tld}
                          className="text-[10px] px-2 py-1 rounded-lg border border-red-200/60 dark:border-red-800/40 text-red-600 dark:text-red-400 hover:border-red-400/60 flex items-center gap-1"
                        >
                          {resettingBypass === row.tld ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiProhibitedLine className="w-2.5 h-2.5" />}
                          重置旁路
                        </button>
                      )}
                      <button
                        onClick={() => clearTld(row.tld)}
                        disabled={clearing === row.tld}
                        className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-red-500 hover:border-red-400/60 flex items-center gap-1"
                      >
                        {clearing === row.tld ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiDeleteBinLine className="w-2.5 h-2.5" />}
                        清零
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* ── Pagination ── */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-2 pt-2 pb-4">
                <button
                  onClick={() => goPage(page - 1)}
                  disabled={page <= 1 || loading}
                  className="flex items-center gap-1 h-8 px-3 rounded-xl border border-border text-xs text-muted-foreground hover:border-primary/50 hover:text-primary disabled:opacity-40 transition-all"
                >
                  <RiArrowLeftLine className="w-3.5 h-3.5" />上一页
                </button>

                {/* Page number buttons — show up to 7 around current */}
                {(() => {
                  const pages: (number | "…")[] = [];
                  const start = Math.max(1, page - 2);
                  const end   = Math.min(totalPages, page + 2);
                  if (start > 1) { pages.push(1); if (start > 2) pages.push("…"); }
                  for (let i = start; i <= end; i++) pages.push(i);
                  if (end < totalPages) { if (end < totalPages - 1) pages.push("…"); pages.push(totalPages); }
                  return pages.map((p, i) =>
                    p === "…" ? (
                      <span key={`e${i}`} className="text-xs text-muted-foreground px-1">…</span>
                    ) : (
                      <button
                        key={p}
                        onClick={() => goPage(p as number)}
                        className={cn(
                          "w-8 h-8 rounded-xl text-xs font-semibold border transition-all",
                          p === page
                            ? "bg-primary text-primary-foreground border-primary"
                            : "border-border text-muted-foreground hover:border-primary/50",
                        )}
                      >{p}</button>
                    )
                  );
                })()}

                <button
                  onClick={() => goPage(page + 1)}
                  disabled={page >= totalPages || loading}
                  className="flex items-center gap-1 h-8 px-3 rounded-xl border border-border text-xs text-muted-foreground hover:border-primary/50 hover:text-primary disabled:opacity-40 transition-all"
                >
                  下一页<RiArrowRightLine className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </AdminLayout>
  );
}
