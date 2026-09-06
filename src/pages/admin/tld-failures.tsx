import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import * as BatchRunner from "@/lib/batch-runner";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine, RiAlertLine,
  RiCheckLine, RiServerLine,
  RiErrorWarningLine, RiDeleteBinLine,
  RiInformationLine, RiEdit2Line, RiGlobalLine,
  RiProhibitedLine, RiWifiLine, RiCloseLine,
  RiArrowLeftLine, RiArrowRightLine,
  RiCheckboxLine, RiCheckboxBlankLine, RiEyeOffLine,
  RiExternalLinkLine, RiSettings3Line, RiFlashlightLine,
  RiStopCircleLine, RiPlayCircleLine, RiScanLine,
  RiBarChartLine, RiTimerLine, RiArrowUpDownLine,
} from "@remixicon/react";
import type { TldFailureRow, TldFailureEventRow } from "@/pages/api/admin/tld-failures";

type ScanResult = {
  tld: string;
  status: "ok" | "fail";
  method: string | null;
  server: string | null;
  elapsed_ms: number;
  error: string | null;
  saved: boolean;
};
type ScanSummary = { total: number; found: number; saved: number; failed: number };

const REASON_COLORS: Record<string, { label: string; cls: string }> = {
  // 旧枚举（兼容 tld_fallback_stats 历史值）
  iana_fallback:   { label: "IANA 兜底", cls: "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" },
  no_server:       { label: "无可达服务器", cls: "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400" },
  timeout:         { label: "超时", cls: "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" },
  parse_error:     { label: "解析失败", cls: "bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400" },
  rate_limited:    { label: "速率限制", cls: "bg-purple-100 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400" },
  // 新 13 类枚举（tld_failure_events）
  dns_failure:     { label: "DNS 解析失败", cls: "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400" },
  connect_timeout: { label: "连接超时", cls: "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" },
  socket_error:    { label: "连接错误", cls: "bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400" },
  http_blocked:    { label: "被拦截 403", cls: "bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400" },
  http_not_found:  { label: "404 未上线", cls: "bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400" },
  http_server_error: { label: "服务器错误 5xx", cls: "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" },
  rdap_error:      { label: "RDAP 错误", cls: "bg-cyan-100 dark:bg-cyan-950/40 text-cyan-700 dark:text-cyan-400" },
  empty_response:  { label: "空响应", cls: "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" },
  third_party_failed: { label: "第三方兜底失败", cls: "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400" },
  unknown:         { label: "未归类", cls: "bg-muted text-muted-foreground" },
};

const FAILURE_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(REASON_COLORS).map(([k, v]) => [k, v.label]),
) as Record<string, string>;

type DashboardMetrics = {
  window_days: number;
  total_queries: number | null;
  success: number | null;
  fail: number | null;
  success_rate: number | null;
  prev_fail: number | null;
  fail_delta_pct: number | null;
};
type ReasonDist = { reason: string; count: string };
type TrendItem = { date: string; count: string };
type TopFailed = {
  tld: string;
  fail_count: string;
  last_reason: string | null;
  last_domain: string | null;
  last_fail_at: string | null;
  success_rate: string | null;
};

const REPAIR_STATUS: Record<string, { label: string; cls: string }> = {
  pending:     { label: "待处理",  cls: "bg-muted text-muted-foreground" },
  in_progress: { label: "处理中",  cls: "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400" },
  fixed:       { label: "已修复",  cls: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400" },
  wont_fix:    { label: "忽略",    cls: "bg-zinc-100 dark:bg-zinc-800 text-zinc-500" },
};

const PER_PAGE_OPTIONS = [20, 50, 100];

/** Third-party API source display names (single source of truth). */
const API_SOURCE_LABELS: Record<string, string> = {
  tianhu: "天虎",
  nazhumi: "哪煮米",
  miqingju: "米情局",
  yisi: "亿思云",
  ph_web: "NIC.PH",
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

/** Localized absolute timestamp (e.g. 09-06 15:30) for event panels. */
function fmtTs(d: string | null) {
  if (!d) return "—";
  const date = new Date(d);
  if (isNaN(date.getTime())) return d;
  return date.toLocaleString("zh-CN", {
    month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hour12: false,
  });
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
  service: "tianhu" | "nazhumi" | "miqingju" | "yisi" | "ph_web";
  result: ApiPanelResult | null;
  loading: boolean;
};

type EventPanel = {
  events: TldFailureEventRow[] | null;
  loading: boolean;
};

type CfgPanel = {
  type: "tcp" | "http";
  host: string;
  port: string;
  url: string;
  saving: boolean;
  saved: boolean;
  error: string | null;
};

function DashboardSection(props: {
  windowDays: number;
  onWindowChange: (d: number) => void;
  metrics: DashboardMetrics | null;
  reasonDist: ReasonDist[];
  trend: TrendItem[];
  topFailed: TopFailed[];
  loading: boolean;
}) {
  const { windowDays, onWindowChange, metrics, reasonDist, trend, topFailed, loading } = props;
  const totalEvents = trend.reduce((s, t) => s + parseInt(t.count || "0", 10), 0);
  const maxReason = Math.max(1, ...reasonDist.map(r => parseInt(r.count, 10)));
  const maxTrend = Math.max(1, ...trend.map(t => parseInt(t.count, 10)));

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-bold flex items-center gap-2 text-muted-foreground">
          <RiBarChartLine className="w-4 h-4" />
          失败统计仪表盘
        </h3>
        <div className="flex items-center gap-1 rounded-xl border border-border p-0.5">
          {[7, 30].map(d => (
            <button
              key={d}
              onClick={() => onWindowChange(d)}
              className={cn(
                "h-6 px-3 rounded-lg text-xs font-semibold transition-colors",
                windowDays === d
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-muted",
              )}
            >
              近{d}天
            </button>
          ))}
        </div>
      </div>

      {loading && !metrics ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground py-6">
          <RiLoader4Line className="w-4 h-4 animate-spin" /> 加载统计中…
        </div>
      ) : (
        <>
          {/* Metric cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                <RiErrorWarningLine className="w-3.5 h-3.5" /> 窗口失败事件
              </div>
              <div className="text-2xl font-bold mt-1 tabular-nums">{totalEvents}</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">诊断事件明细</div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                <RiCheckboxLine className="w-3.5 h-3.5" /> 查询成功率
              </div>
              <div className={cn(
                "text-2xl font-bold mt-1 tabular-nums",
                (metrics?.success_rate ?? 100) >= 98 ? "text-emerald-600 dark:text-emerald-400"
                  : (metrics?.success_rate ?? 100) >= 95 ? "text-amber-600 dark:text-amber-400"
                    : "text-red-600 dark:text-red-400",
              )}>
                {metrics?.success_rate == null ? "—" : `${metrics.success_rate}%`}
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                共 {metrics?.total_queries ?? 0} 次 · 失败 {metrics?.fail ?? 0}
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                <RiTimerLine className="w-3.5 h-3.5" /> 较上期
              </div>
              <div className={cn(
                "text-2xl font-bold mt-1 tabular-nums",
                metrics?.fail_delta_pct == null ? "text-muted-foreground"
                  : metrics.fail_delta_pct > 5 ? "text-red-600 dark:text-red-400"
                    : metrics.fail_delta_pct < -5 ? "text-emerald-600 dark:text-emerald-400"
                      : "text-amber-600 dark:text-amber-400",
              )}>
                {metrics?.fail_delta_pct == null ? "—" : `${metrics.fail_delta_pct > 0 ? "+" : ""}${metrics.fail_delta_pct}%`}
              </div>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                上期 {metrics?.prev_fail ?? 0} 次失败
              </div>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                <RiArrowUpDownLine className="w-3.5 h-3.5" /> Top 失败 TLD
              </div>
              <div className="text-2xl font-bold mt-1 tabular-nums">{topFailed.length}</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">
                诊断明细覆盖 {topFailed.length} 个后缀
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Reason distribution */}
            <div className="rounded-xl border border-border bg-card p-4 md:col-span-1">
              <h4 className="text-xs font-semibold text-muted-foreground mb-3">失败原因分布</h4>
              {reasonDist.length === 0 ? (
                <div className="text-xs text-muted-foreground py-6 text-center">窗口内无诊断事件</div>
              ) : (
                <div className="space-y-2">
                  {reasonDist.map(r => (
                    <div key={r.reason} className="flex items-center gap-2 text-xs">
                      <span className="w-20 shrink-0 truncate text-muted-foreground" title={FAILURE_LABELS[r.reason] ?? r.reason}>
                        {FAILURE_LABELS[r.reason] ?? r.reason}
                      </span>
                      <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-primary/70"
                          style={{ width: `${(parseInt(r.count, 10) / maxReason) * 100}%` }}
                        />
                      </div>
                      <span className="w-8 text-right tabular-nums text-muted-foreground">{r.count}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Trend */}
            <div className="rounded-xl border border-border bg-card p-4 md:col-span-2">
              <h4 className="text-xs font-semibold text-muted-foreground mb-3">每日失败趋势</h4>
              {trend.length === 0 ? (
                <div className="text-xs text-muted-foreground py-6 text-center">窗口内无诊断事件</div>
              ) : (
                <div className="flex items-end gap-1 h-24">
                  {trend.map(t => (
                    <div key={t.date} className="flex-1 flex flex-col items-center gap-1 group" title={`${t.date} · ${t.count} 次`}>
                      <span className="text-[10px] text-muted-foreground tabular-nums opacity-0 group-hover:opacity-100 transition-opacity">
                        {t.count}
                      </span>
                      <div
                        className={cn(
                          "w-full rounded-t bg-gradient-to-t rounded-sm",
                          parseInt(t.count, 10) > 0 ? "from-red-500/30 to-red-500/80" : "bg-muted/40",
                        )}
                        style={{ height: `${Math.max(6, (parseInt(t.count, 10) / maxTrend) * 70)}px` }}
                      />
                    </div>
                  ))}
                </div>
              )}
              <div className="flex justify-between text-[10px] text-muted-foreground mt-1.5">
                <span>{trend[0]?.date ?? "—"}</span>
                <span>{trend[trend.length - 1]?.date ?? "—"}</span>
              </div>
            </div>
          </div>

          {/* Top failed TLDs */}
          {topFailed.length > 0 && (
            <div className="rounded-xl border border-border bg-card overflow-hidden">
              <h4 className="text-xs font-semibold text-muted-foreground px-4 py-3 border-b border-border/60">
                Top 失败 TLD（含成功率）
              </h4>
              <div className="divide-y divide-border/50">
                {topFailed.slice(0, 10).map(t => {
                  const color = REASON_COLORS[t.last_reason ?? ""] ?? { label: FAILURE_LABELS[t.last_reason ?? ""] ?? "未知", cls: "bg-muted text-muted-foreground" };
                  return (
                    <div key={t.tld} className="flex items-center gap-3 px-4 py-2 text-xs">
                      <span className="font-mono font-semibold w-24 shrink-0">.{t.tld}</span>
                      <span className="text-red-600 dark:text-red-400 font-semibold tabular-nums w-12 shrink-0">{t.fail_count} 次</span>
                      <span className={cn("px-1.5 py-0.5 rounded text-[11px] font-semibold shrink-0", color.cls)}>
                        {color.label}
                      </span>
                      <span className="text-muted-foreground shrink-0 w-16 tabular-nums">
                        {t.success_rate == null ? "—" : `成功 ${t.success_rate}%`}
                      </span>
                      <span className="text-muted-foreground truncate flex-1 min-w-0" title={t.last_domain ?? ""}>
                        {t.last_domain ? `最近 ${t.last_domain}` : "—"}
                      </span>
                      <span className="text-muted-foreground shrink-0">{fmt(t.last_fail_at)}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/**
 * Shared WHOIS server endpoint editor used by both the connectivity-test panel
 * and the server-config panel. Renders the TCP/HTTP type toggle plus the
 * host/port (or URL) inputs for the chosen mode.
 */
function ServerEndpointFields(props: {
  tld: string;
  type: "tcp" | "http";
  host: string;
  port: string;
  url: string;
  onChange: (patch: { type?: "tcp" | "http"; host?: string; port?: string; url?: string }) => void;
}) {
  const { tld, type, host, port, url, onChange } = props;
  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        {(["tcp", "http"] as const).map(t => (
          <button
            key={t}
            onClick={() => onChange({ type: t })}
            className={cn(
              "px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
              type === t
                ? "bg-primary text-primary-foreground border-primary"
                : "border-border/60 text-muted-foreground hover:border-primary/40 bg-background",
            )}
          >
            {t === "tcp" ? "WHOIS TCP" : "RDAP / HTTP"}
          </button>
        ))}
      </div>
      {type === "tcp" ? (
        <div className="flex gap-2">
          <Input value={host} onChange={e => onChange({ host: e.target.value })} placeholder={`whois.nic.${tld}`} className="h-7 text-[11px] rounded-lg flex-1 font-mono" />
          <Input value={port} onChange={e => onChange({ port: e.target.value })} placeholder="43" className="h-7 text-[11px] rounded-lg w-16 font-mono" />
        </div>
      ) : (
        <Input value={url} onChange={e => onChange({ url: e.target.value })} placeholder={`https://rdap.nic.${tld}/domain/`} className="h-7 text-[11px] rounded-lg font-mono" />
      )}
    </div>
  );
}

export default function TldFailuresPage() {
  const [rows, setRows]           = React.useState<TldFailureRow[]>([]);
  const [summary, setSummary]     = React.useState<Summary[]>([]);
  const [loading, setLoading]     = React.useState(true);
  const [search, setSearch]       = React.useState("");
  const [minFails, setMinFails]   = React.useState(1);
  const [reasonFilter, setReasonFilter] = React.useState<string>("");
  const [hideManual, setHideManual]     = React.useState(false);

  // Dashboard window
  const [windowDays, setWindowDays] = React.useState(7);
  const [metrics, setMetrics]       = React.useState<DashboardMetrics | null>(null);
  const [reasonDist, setReasonDist] = React.useState<ReasonDist[]>([]);
  const [trend, setTrend]           = React.useState<TrendItem[]>([]);
  const [topFailed, setTopFailed]   = React.useState<TopFailed[]>([]);

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
  const [eventPanels, setEventPanels] = React.useState<Record<string, EventPanel>>({});
  const [cfgPanels, setCfgPanels]   = React.useState<Record<string, CfgPanel>>({});
  const [settingApiSource, setSettingApiSource] = React.useState<string | null>(null);
  const [lookingUp, setLookingUp]   = React.useState<string | null>(null);

  // Per-TLD request sequence to ignore stale event-panel responses.
  const eventSeq = React.useRef<Record<string, number>>({});

  // ── Batch auto-scan state ────────────────────────────────────────────────
  const [scanning, setScanning]         = React.useState(false);
  const [scanResults, setScanResults]   = React.useState<ScanResult[] | null>(null);
  const [scanSummary, setScanSummary]   = React.useState<ScanSummary | null>(null);
  const [showScanPanel, setShowScanPanel] = React.useState(false);

  // ── Batch runner status (cross-page visibility) ──────────────────────────
  const [, batchTick] = React.useReducer(n => n + 1, 0);
  React.useEffect(() => BatchRunner.subscribe(batchTick), []);
  const batch = BatchRunner.getState();
  const batchRunning = batch.status === "running";

  function buildParams(overrides: Record<string, string | number> = {}) {
    const p: Record<string, string> = {
      min_fails: String(minFails),
      page:      String(page),
      per_page:  String(perPage),
      period_compare: "1",
      window:    String(windowDays),
    };
    if (reasonFilter) p.repair    = reasonFilter;
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
        setMetrics(d.metrics ?? null);
        setReasonDist(d.reason_dist ?? []);
        setTrend(d.trend ?? []);
        setTopFailed(d.top_failed ?? []);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  // Debounce the free-text search so typing doesn't spam the API.
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);
  React.useEffect(() => {
    setPage(1);
    load(1);
  }, [minFails, reasonFilter, hideManual, windowDays, debouncedSearch]); // eslint-disable-line react-hooks/exhaustive-deps

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
    if (!confirm(`确认清零全部 ${summaryTotal} 条失败记录？此操作不可撤销。`)) return;
    setClearingAll(true);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clear_all: true }),
      });
      const d = await r.json();
      if (r.ok) { toast.success(`已清零 ${d.cleared ?? 0} 条失败记录`); load(1); setPage(1); }
      else toast.error("操作失败");
    } catch (e: any) {
      toast.error(`操作失败: ${e?.message || "网络错误"}`);
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
    } catch (e: any) {
      toast.error(`操作失败: ${e?.message || "网络错误"}`);
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

  /** Shared defaults for the WHOIS test / config server panels. */
  function makeServerPanelDefaults(tld: string) {
    return {
      type: "tcp" as const,
      host: `whois.nic.${tld}`,
      port: "",
      url: `https://rdap.nic.${tld}/domain/`,
    };
  }

  function openTestPanel(tld: string) {
    setTestPanels(prev => ({
      ...prev,
      [tld]: prev[tld] ?? { ...makeServerPanelDefaults(tld), result: null, loading: false },
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

  // ── Per-TLD failure events detail panel ─────────────────────────────────
  function closeEventPanel(tld: string) {
    setEventPanels(prev => { const n = { ...prev }; delete n[tld]; return n; });
  }

  function updateEventPanel(tld: string, patch: Partial<EventPanel>) {
    setEventPanels(prev => ({ ...prev, [tld]: { ...prev[tld], ...patch } }));
  }

  async function loadEventPanel(tld: string) {
    const seq = (eventSeq.current[tld] ?? 0) + 1;
    eventSeq.current[tld] = seq;
    updateEventPanel(tld, { loading: true, events: null });
    try {
      const r = await fetch(`/api/admin/tld-failures?events_for=${encodeURIComponent(tld)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      if (eventSeq.current[tld] === seq) {
        updateEventPanel(tld, { loading: false, events: d.events ?? [] });
      }
    } catch (e: any) {
      if (eventSeq.current[tld] === seq) {
        updateEventPanel(tld, { loading: false, events: [] });
        toast.error(`加载事件失败: ${e?.message || "网络错误"}`);
      }
    }
  }

  function toggleEventPanel(tld: string) {
    if (eventPanels[tld]) { closeEventPanel(tld); return; }
    eventSeq.current[tld] = (eventSeq.current[tld] ?? 0) + 1;
    setEventPanels(prev => ({ ...prev, [tld]: { events: null, loading: true } }));
    loadEventPanel(tld);
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
      toast.success(source ? `已将 .${tld} 设为默认 ${API_SOURCE_LABELS[source] ?? source} 查询` : `已清除 .${tld} 的第三方 API 设置`);
    } catch {
      toast.error("操作失败，请重试");
    } finally {
      setSettingApiSource(null);
    }
  }

  // ── Server config panel ──────────────────────────────────────────────────
  function openCfgPanel(tld: string) {
    setCfgPanels(prev => ({
      ...prev,
      [tld]: prev[tld] ?? {
        ...makeServerPanelDefaults(tld), saving: false, saved: false, error: null,
      },
    }));
  }

  function closeCfgPanel(tld: string) {
    setCfgPanels(prev => { const n = { ...prev }; delete n[tld]; return n; });
  }

  function updateCfgPanel(tld: string, patch: Partial<CfgPanel>) {
    setCfgPanels(prev => ({ ...prev, [tld]: { ...prev[tld], ...patch } }));
  }

  async function saveCfgPanel(tld: string) {
    const panel = cfgPanels[tld];
    if (!panel) return;
    updateCfgPanel(tld, { saving: true, saved: false, error: null });
    try {
      let entry: object;
      if (panel.type === "tcp") {
        const portNum = panel.port.trim() ? parseInt(panel.port.trim(), 10) : undefined;
        entry = portNum ? { type: "tcp", host: panel.host.trim(), port: portNum } : { type: "tcp", host: panel.host.trim() };
      } else {
        entry = { type: "http", url: panel.url.trim(), method: "GET" };
      }
      const r = await fetch("/api/admin/tld-servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, entry }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message || `HTTP ${r.status}`);
      updateCfgPanel(tld, { saving: false, saved: true });
      toast.success(`已保存 .${tld} 的 WHOIS 服务器配置`);
      load(page);
    } catch (e: any) {
      updateCfgPanel(tld, { saving: false, error: e?.message || "保存失败" });
    }
  }

  // ── 查询并移除 ───────────────────────────────────────────────────────────
  async function lookupAndRemove(tld: string) {
    setLookingUp(tld);
    try {
      const domain = `example.${tld}`;
      const r = await fetch(`/api/lookup?query=${encodeURIComponent(domain)}&nocache=1`);
      const d = await r.json();
      if (d.status === true || d.status === "true") {
        toast.success(`.${tld} 查询成功，已自动从失败列表中移除`);
        const dr = await fetch("/api/admin/tld-failures", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tld }),
        });
        if (!dr.ok) toast.error("移除失败列表条目失败，请重试");
        load(page);
      } else {
        toast.error(`.${tld} 查询仍然失败: ${d.error || "无法获取结果"}`);
      }
    } catch (e: any) {
      toast.error(`查询失败: ${e?.message || "网络错误"}`);
    } finally {
      setLookingUp(null);
    }
  }

  // ── Batch auto-scan ──────────────────────────────────────────────────────
  async function startBatchScan(mode: "current" | "db" | "uncovered") {
    setScanning(true);
    setScanResults(null);
    setScanSummary(null);
    setShowScanPanel(true);
    try {
      const body = mode === "current"
        ? { tlds: rows.map(r => r.tld), timeout_ms: 8000 }
        : mode === "uncovered"
        ? { source: "uncovered", limit: 100, timeout_ms: 8000 }
        : { limit: 100, timeout_ms: 8000 };
      const r = await fetch("/api/admin/tld-batch-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) { toast.error(`扫描失败: HTTP ${r.status}`); return; }
      const d = await r.json();
      setScanResults(d.results ?? []);
      setScanSummary(d.summary ?? null);
      if ((d.summary?.found ?? 0) > 0) {
        toast.success(`扫描完成：发现 ${d.summary.found} 个可用服务器，已保存 ${d.summary.saved} 个`);
        load(page);
      } else {
        toast.info(`扫描完成：共扫描 ${d.summary?.total ?? 0} 个，未发现新服务器`);
      }
    } catch (e: any) {
      toast.error(`扫描失败: ${e?.message || "网络错误"}`);
    } finally {
      setScanning(false);
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

        {/* ── Batch-scraper running banner ── */}
        {batchRunning && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl border border-amber-200/70 dark:border-amber-800/40 bg-amber-50/80 dark:bg-amber-950/30">
            <RiLoader4Line className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 animate-spin" />
            <div className="flex-1 min-w-0">
              <span className="text-sm font-semibold text-amber-700 dark:text-amber-400">AI 批量爬取正在运行</span>
              <span className="text-xs text-amber-600/80 dark:text-amber-500 ml-2">
                ({batch.items.filter(i => i.status === "ok").length}/{batch.items.length} 完成)
                — 删除或修改失败记录前，建议先停止爬取，否则被删记录会立即被重新写入
              </span>
            </div>
            <button
              onClick={() => { BatchRunner.stop(); toast.info("批量爬取已停止"); }}
              className="flex items-center gap-1.5 h-7 px-3 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-100 dark:bg-amber-950/50 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-950/70 text-xs font-semibold shrink-0 transition-colors"
            >
              <RiStopCircleLine className="w-3.5 h-3.5" />停止爬取
            </button>
          </div>
        )}

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

            {/* Batch scan buttons */}
            <div className="flex items-center gap-1">
              <button
                onClick={() => startBatchScan("db")}
                disabled={scanning}
                title="从数据库取出最多100个失败TLD，自动发现RDAP/WHOIS服务器并保存"
                className={cn(
                  "flex items-center gap-1.5 h-8 px-3 rounded-l-xl border text-xs font-semibold transition-colors",
                  scanning
                    ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-300 dark:border-emerald-700 text-emerald-600 dark:text-emerald-400"
                    : "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200/60 dark:border-emerald-800/40 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-100 dark:hover:bg-emerald-950/50",
                )}
              >
                {scanning ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiScanLine className="w-3.5 h-3.5" />}
                批量扫描修复
              </button>
              <button
                onClick={() => startBatchScan("current")}
                disabled={scanning || rows.length === 0}
                title="仅扫描当前页显示的TLD"
                className="flex items-center gap-1.5 h-8 px-2 border-y border-r-0 border-emerald-200/60 dark:border-emerald-800/40 text-emerald-700 dark:text-emerald-400 text-xs hover:bg-emerald-50 dark:hover:bg-emerald-950/30 transition-colors disabled:opacity-40"
              >
                当前页
              </button>
              <button
                onClick={() => startBatchScan("uncovered")}
                disabled={scanning}
                title="从TLD规则库中找出从未查询过的TLD并扫描"
                className="flex items-center gap-1.5 h-8 px-2 rounded-r-xl border border-l-0 border-emerald-200/60 dark:border-emerald-800/40 text-sky-600 dark:text-sky-400 text-xs hover:bg-sky-50 dark:hover:bg-sky-950/20 transition-colors disabled:opacity-40"
              >
                未查询
              </button>
            </div>
            {scanResults !== null && (
              <button
                onClick={() => setShowScanPanel(v => !v)}
                className="flex items-center gap-1.5 h-8 px-3 rounded-xl border border-border/60 text-xs font-semibold text-muted-foreground hover:border-primary/50 transition-colors"
              >
                <RiServerLine className="w-3.5 h-3.5" />
                {showScanPanel ? "隐藏扫描结果" : "查看扫描结果"}
                {scanSummary && <span className="ml-1 text-emerald-600 dark:text-emerald-400">({scanSummary.found}/{scanSummary.total})</span>}
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

        {/* ── Failure statistics dashboard ── */}
        <DashboardSection
          windowDays={windowDays}
          onWindowChange={setWindowDays}
          metrics={metrics}
          reasonDist={reasonDist}
          trend={trend}
          topFailed={topFailed}
          loading={loading}
        />

        {/* ── Batch scan progress / results panel ── */}
        {(scanning || (showScanPanel && scanResults !== null)) && (
          <div className="rounded-xl border border-emerald-200/60 dark:border-emerald-800/40 bg-emerald-50/60 dark:bg-emerald-950/20 overflow-hidden">
            <div className="flex items-center gap-3 px-4 py-3 border-b border-emerald-200/60 dark:border-emerald-800/30">
              {scanning
                ? <RiLoader4Line className="w-4 h-4 text-emerald-600 dark:text-emerald-400 animate-spin shrink-0" />
                : <RiScanLine className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />}
              <span className="text-sm font-semibold text-emerald-700 dark:text-emerald-400 flex-1">
                {scanning ? "批量扫描进行中，请稍候…" : "批量扫描结果"}
              </span>
              {scanSummary && !scanning && (
                <div className="flex items-center gap-3 text-xs">
                  <span className="text-muted-foreground">共 {scanSummary.total}</span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold">✓ 发现 {scanSummary.found}</span>
                  <span className="text-sky-600 dark:text-sky-400 font-semibold">已保存 {scanSummary.saved}</span>
                  <span className="text-muted-foreground">失败 {scanSummary.failed}</span>
                </div>
              )}
              {!scanning && (
                <button onClick={() => setShowScanPanel(false)} className="ml-2 p-1 rounded-lg hover:bg-emerald-100 dark:hover:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400">
                  <RiCloseLine className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
            {scanResults && scanResults.length > 0 && (
              <div className="divide-y divide-emerald-100 dark:divide-emerald-900/30 max-h-64 overflow-y-auto">
                {scanResults.map(r => (
                  <div key={r.tld} className="flex items-center gap-3 px-4 py-2 text-xs">
                    <span className={cn(
                      "font-mono font-semibold w-20 shrink-0",
                      r.status === "ok" ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground",
                    )}>.{r.tld}</span>
                    {r.status === "ok" ? (
                      <>
                        <span className="text-emerald-600 dark:text-emerald-400 font-semibold">✓</span>
                        <span className="text-muted-foreground truncate flex-1">{r.method} — {r.server}</span>
                        {r.saved && <span className="text-sky-600 dark:text-sky-400 shrink-0">已保存</span>}
                        <span className="text-muted-foreground shrink-0">{r.elapsed_ms}ms</span>
                      </>
                    ) : (
                      <>
                        <span className="text-red-500">✗</span>
                        <span className="text-muted-foreground truncate flex-1">{r.error || "未找到可用服务器"}</span>
                      </>
                    )}
                  </div>
                ))}
              </div>
            )}
            {scanning && (
              <div className="px-4 py-3 text-xs text-emerald-600/80 dark:text-emerald-500">
                正在通过 IANA RDAP、IANA WHOIS 转介、常见 URL 规律和 TCP 探测逐一扫描，每批 3 个并发，请等待…
              </div>
            )}
          </div>
        )}

        {/* ── Summary pills (grouped by repair status) ── */}
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
              const r = REPAIR_STATUS[s.reason ?? "pending"] ?? { label: s.reason ?? "待处理", cls: "bg-muted text-muted-foreground" };
              return (
                <button
                  key={s.reason ?? "pending"}
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
            <span className="text-[10px] text-muted-foreground whitespace-nowrap">修复状态</span>
            {[
              { v: "", label: "全部" },
              { v: "pending", label: "待处理" },
              { v: "fixed", label: "已修复" },
              { v: "wont_fix", label: "忽略" },
            ].map(o => (
              <button
                key={o.v}
                onClick={() => setReasonFilter(o.v)}
                className={cn(
                  "h-8 px-2.5 rounded-lg text-xs font-semibold border transition-all",
                  reasonFilter === o.v ? "bg-primary text-primary-foreground border-primary" : "bg-background border-border text-muted-foreground hover:border-primary/50",
                )}
              >{o.label}</button>
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
            <p><strong>本页结构：</strong>顶部仪表盘统计近窗口失败事件（查询成功率来自查询日志，原因/趋势/Top 列表来自诊断事件表）；下方列表为各后缀的服务器配置与修复状态。</p>
            <p><strong>批量扫描修复：</strong>自动通过 IANA RDAP 引导、IANA WHOIS 转介、常见 URL 规律、TCP 探测等策略发现服务器并保存。「未查询」扫描 TLD 规则库中从未查询过的后缀。</p>
            <p>「清零」操作删除诊断事件记录，不影响服务器配置与修复状态。手动填写后的条目可用「隐藏手动填写」过滤。</p>
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
                const evPanel    = eventPanels[row.tld];
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

                      <div className="flex items-center gap-2 min-w-0 flex-1 flex-wrap">
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
                            {API_SOURCE_LABELS[row.tld_api_source] ?? row.tld_api_source}
                          </span>
                        )}
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0", repairInfo.cls)}>{repairInfo.label}</span>
                      </div>

                      <div className="flex items-center gap-1 shrink-0">
                        <span className={cn(
                          "text-[11px] font-bold tabular-nums",
                          (row.this_week_count ?? 0) > 0 ? "text-red-500" : "text-muted-foreground",
                        )}>{row.this_week_count ?? 0}</span>
                        <span className="text-[10px] text-muted-foreground">次失败/近7天</span>
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
                        <ServerEndpointFields
                          tld={row.tld}
                          type={testPanel.type}
                          host={testPanel.host}
                          port={testPanel.port}
                          url={testPanel.url}
                          onChange={patch => updateTestPanel(row.tld, { ...patch, result: null })}
                        />
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
                          {(["tianhu", "nazhumi", "miqingju", "yisi", "ph_web"] as const).map(svc => {
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
                                {API_SOURCE_LABELS[svc]}
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
                          {/* Quick-set buttons: for API sources that can be set as default */}
                          {(apiPanel.service === "tianhu" || apiPanel.service === "yisi" || apiPanel.service === "ph_web") && (() => {
                            const svc    = apiPanel.service as "tianhu" | "yisi" | "ph_web";
                            const isActive = row.tld_api_source === svc;
                            const isBusy   = settingApiSource === row.tld;
                            const labels   = API_SOURCE_LABELS;
                            return isActive ? (
                              <button
                                onClick={() => applyTldApiSource(row.tld, null)}
                                disabled={isBusy}
                                className="flex items-center gap-1 h-7 px-2.5 rounded-lg border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400 text-[10px] font-semibold disabled:opacity-50 transition-colors hover:bg-red-100 dark:hover:bg-red-950/50"
                              >
                                {isBusy ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiCloseLine className="w-2.5 h-2.5" />}
                                取消 {labels[svc]} 默认
                              </button>
                            ) : (
                              <button
                                onClick={() => applyTldApiSource(row.tld, svc)}
                                disabled={isBusy}
                                className="flex items-center gap-1 h-7 px-2.5 rounded-lg border border-violet-300 dark:border-violet-700 bg-violet-50 dark:bg-violet-950/30 text-violet-600 dark:text-violet-400 text-[10px] font-semibold disabled:opacity-50 transition-colors hover:bg-violet-100 dark:hover:bg-violet-950/50"
                              >
                                {isBusy ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiExternalLinkLine className="w-2.5 h-2.5" />}
                                设为 {labels[svc]} 默认
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

                    {/* Inline server config panel */}
                    {cfgPanels[row.tld] && (() => {
                      const cfgPanel = cfgPanels[row.tld];
                      return (
                        <div className="border border-border/60 rounded-xl bg-muted/20 p-3 space-y-2.5">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[11px] font-semibold text-foreground/80 flex items-center gap-1.5">
                              <RiSettings3Line className="w-3.5 h-3.5 text-sky-500" />
                              配置 WHOIS 服务器 · .{row.tld}
                            </span>
                            <button onClick={() => closeCfgPanel(row.tld)} className="text-muted-foreground/60 hover:text-foreground transition-colors">
                              <RiCloseLine className="w-3.5 h-3.5" />
                            </button>
                          </div>
                          <ServerEndpointFields
                            tld={row.tld}
                            type={cfgPanel.type}
                            host={cfgPanel.host}
                            port={cfgPanel.port}
                            url={cfgPanel.url}
                            onChange={patch => updateCfgPanel(row.tld, patch)}
                          />
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => saveCfgPanel(row.tld)}
                              disabled={cfgPanel.saving || (cfgPanel.type === "tcp" ? !cfgPanel.host.trim() : !cfgPanel.url.trim())}
                              className="flex items-center gap-1.5 h-7 px-3 rounded-lg bg-sky-500 hover:bg-sky-600 disabled:opacity-50 text-white text-[11px] font-semibold transition-colors"
                            >
                              {cfgPanel.saving ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiServerLine className="w-3 h-3" />}
                              {cfgPanel.saving ? "保存中…" : "保存配置"}
                            </button>
                            {cfgPanel.saved && (
                              <span className="text-[10px] text-emerald-600 dark:text-emerald-400 flex items-center gap-0.5">
                                <RiCheckLine className="w-3 h-3" />已保存
                              </span>
                            )}
                            {cfgPanel.error && (
                              <span className="text-[10px] text-red-600 dark:text-red-400">{cfgPanel.error}</span>
                            )}
                          </div>
                        </div>
                      );
                    })()}

                    {/* Per-TLD failure events detail */}
                    {evPanel && (
                      <div className="border border-border/60 rounded-xl bg-muted/20 p-3 space-y-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-semibold text-foreground/80 flex items-center gap-1.5">
                            <RiErrorWarningLine className="w-3.5 h-3.5 text-red-500" />
                            失败事件明细 · .{row.tld}
                            {!evPanel.loading && evPanel.events && (
                              <span className="text-[10px] font-normal text-muted-foreground">共 {evPanel.events.length} 条（最新 50）</span>
                            )}
                          </span>
                          <div className="flex items-center gap-1">
                            {evPanel.events && !evPanel.loading && (
                              <button onClick={() => loadEventPanel(row.tld)} className="p-1 rounded-lg hover:bg-muted text-muted-foreground transition-colors" title="刷新">
                                <RiRefreshLine className="w-3 h-3" />
                              </button>
                            )}
                            <button onClick={() => closeEventPanel(row.tld)} className="text-muted-foreground/60 hover:text-foreground transition-colors">
                              <RiCloseLine className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                        {evPanel.loading ? (
                          <div className="flex items-center gap-2 text-xs text-muted-foreground py-3">
                            <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> 加载事件中…
                          </div>
                        ) : !evPanel.events || evPanel.events.length === 0 ? (
                          <div className="text-xs text-muted-foreground py-3">窗口内无诊断事件记录</div>
                        ) : (
                          <div className="space-y-1.5 max-h-64 overflow-y-auto">
                            {evPanel.events.map(ev => {
                              const c = REASON_COLORS[ev.fail_reason ?? ""] ?? { label: FAILURE_LABELS[ev.fail_reason ?? ""] ?? "未知", cls: "bg-muted text-muted-foreground" };
                              return (
                                <div key={ev.id} className="rounded-lg bg-background/60 border border-border/40 px-3 py-2 space-y-1">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full font-semibold shrink-0", c.cls)}>{c.label}</span>
                                    {ev.domain && <code className="text-[10px] font-mono text-foreground/70 truncate max-w-[200px]">{ev.domain}</code>}
                                    <span className="text-[10px] text-muted-foreground ml-auto shrink-0 tabular-nums" title={ev.created_at}>{fmtTs(ev.created_at)}</span>
                                    {ev.context && <span className="text-[9px] px-1 py-0.5 rounded bg-muted text-muted-foreground shrink-0">{ev.context}</span>}
                                  </div>
                                  {ev.reason_detail && (
                                    <p className="text-[10px] text-muted-foreground/90 leading-relaxed break-all">{ev.reason_detail}</p>
                                  )}
                                </div>
                              );
                            })}
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
                        const label = API_SOURCE_LABELS[src];
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
                      {/* ph_web quick-set — only for .ph domains */}
                      {(row.tld === "ph" || row.tld.endsWith(".ph")) && (() => {
                        const isActive = row.tld_api_source === "ph_web";
                        const isBusy   = settingApiSource === row.tld;
                        return (
                          <button
                            onClick={() => applyTldApiSource(row.tld, isActive ? null : "ph_web")}
                            disabled={isBusy}
                            title={isActive ? "取消 NIC.PH 路由，点击清除" : "将 .ph 查询路由至 NIC.PH 网页爬虫"}
                            className={cn(
                              "text-[10px] px-2 py-1 rounded-lg border font-semibold flex items-center gap-0.5 transition-all disabled:opacity-50",
                              isActive
                                ? "bg-sky-100 dark:bg-sky-950/40 border-sky-300 dark:border-sky-700 text-sky-700 dark:text-sky-300"
                                : "border-border/60 text-muted-foreground hover:border-sky-400/60 hover:text-sky-600 bg-background",
                            )}
                          >
                            {isBusy ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiGlobalLine className="w-2.5 h-2.5" />}
                            NIC.PH{isActive ? " ✓" : ""}
                          </button>
                        );
                      })()}
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
                        onClick={() => lookupAndRemove(row.tld)}
                        disabled={lookingUp === row.tld}
                        title={`查询 example.${row.tld}，若成功则自动从失败列表移除`}
                        className="text-[10px] px-2 py-1 rounded-lg border border-border/60 text-emerald-600 dark:text-emerald-400 hover:border-emerald-400/60 flex items-center gap-1 disabled:opacity-50"
                      >
                        {lookingUp === row.tld ? <RiLoader4Line className="w-2.5 h-2.5 animate-spin" /> : <RiFlashlightLine className="w-2.5 h-2.5" />}
                        查询并移除
                      </button>
                      <button
                        onClick={() => toggleEventPanel(row.tld)}
                        title={`查看 .${row.tld} 的失败事件明细`}
                        className={cn(
                          "text-[10px] px-2 py-1 rounded-lg border flex items-center gap-1 transition-all",
                          evPanel
                            ? "border-red-400/60 bg-red-50 dark:bg-red-950/30 text-red-600 dark:text-red-400"
                            : "border-border/60 text-muted-foreground hover:border-red-400/60 hover:text-red-500",
                        )}
                      >
                        <RiErrorWarningLine className="w-2.5 h-2.5" />事件明细
                        {(row.window_events ?? 0) > 0 && (
                          <span className={cn("text-[9px] px-1 rounded-full font-semibold", evPanel ? "bg-red-100 dark:bg-red-950/50" : "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400")}>
                            {row.window_events}
                          </span>
                        )}
                      </button>
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
                      <button
                        onClick={() => cfgPanels[row.tld] ? closeCfgPanel(row.tld) : openCfgPanel(row.tld)}
                        className={cn(
                          "text-[10px] px-2 py-1 rounded-lg border flex items-center gap-1 transition-all",
                          cfgPanels[row.tld]
                            ? "border-sky-400/60 bg-sky-50 dark:bg-sky-950/30 text-sky-600 dark:text-sky-400"
                            : "border-border/60 text-muted-foreground hover:border-sky-400/60 hover:text-sky-600",
                        )}
                      >
                        <RiSettings3Line className="w-2.5 h-2.5" />配置服务器
                      </button>
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
