import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  RiGlobalLine, RiLoader4Line, RiStopCircleLine, RiRefreshLine,
  RiSearchLine, RiExternalLinkLine, RiDeleteBin7Line, RiCheckboxCircleLine,
  RiCloseCircleLine, RiQuestionLine, RiArrowDownSLine, RiArrowUpSLine,
  RiDatabase2Line, RiWifiLine, RiTimeLine, RiShieldCheckLine,
  RiAlertLine, RiDownloadLine,
} from "@remixicon/react";

// ── Types ─────────────────────────────────────────────────────────────────────
interface TldRecord {
  tld: string;
  tld_type: string | null;
  status: string | null;
  manager: string | null;
  registry_url: string | null;
  whois_server: string | null;
  country: string | null;
  address: string | null;
  nameservers: string | null;
  created_date: string | null;
  changed_date: string | null;
  iana_url: string | null;
  probe_result: string | null;
  probe_method: string | null;
  probe_latency_ms: number | null;
  scan_error: string | null;
  scraped_at: string | null;
  done?: number;
  total?: number;
  errors?: number;
}

interface DbStats {
  total: string;
  cc: string;
  generic: string;
  sponsored: string;
  with_registry: string;
  with_whois: string;
  last_scan: string | null;
}

// ── Type badge config ─────────────────────────────────────────────────────────
const TYPE_META: Record<string, { label: string; color: string }> = {
  "country-code":       { label: "ccTLD",       color: "bg-blue-100 text-blue-700 dark:bg-blue-950/50 dark:text-blue-300 border-blue-200 dark:border-blue-800" },
  "generic":            { label: "gTLD",         color: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800" },
  "generic-restricted": { label: "受限 gTLD",    color: "bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200 dark:border-amber-800" },
  "sponsored":          { label: "sTLD",         color: "bg-violet-100 text-violet-700 dark:bg-violet-950/50 dark:text-violet-300 border-violet-200 dark:border-violet-800" },
  "infrastructure":     { label: "基础设施",     color: "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300 border-red-200 dark:border-red-800" },
  "not-assigned":       { label: "未分配",       color: "bg-gray-100 text-gray-500 dark:bg-gray-900/50 dark:text-gray-400 border-gray-200 dark:border-gray-700" },
  "test":               { label: "测试",         color: "bg-orange-100 text-orange-600 dark:bg-orange-950/50 dark:text-orange-300 border-orange-200 dark:border-orange-800" },
};

const STATUS_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  "active":        { label: "活跃", icon: <RiCheckboxCircleLine className="w-3 h-3" />, color: "text-emerald-600" },
  "not-delegated": { label: "未委托", icon: <RiCloseCircleLine className="w-3 h-3" />, color: "text-red-500" },
  "terminated":    { label: "已终止", icon: <RiCloseCircleLine className="w-3 h-3" />, color: "text-gray-400" },
};

const PROBE_META: Record<string, { label: string; color: string }> = {
  "rdap":            { label: "RDAP",    color: "text-emerald-600" },
  "whois":           { label: "WHOIS",   color: "text-blue-600" },
  "static_fallback": { label: "Fallback",color: "text-violet-600" },
  "none":            { label: "无响应",  color: "text-orange-500" },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function TypeBadge({ type }: { type: string | null }) {
  const t = type || "generic";
  const meta = TYPE_META[t] || { label: t, color: "bg-muted text-muted-foreground border-border" };
  return (
    <span className={cn("inline-block text-[10px] font-medium px-1.5 py-0.5 rounded border", meta.color)}>
      {meta.label}
    </span>
  );
}

function StatusIcon({ status }: { status: string | null }) {
  const s = status || "";
  const meta = STATUS_META[s];
  if (!meta) return <RiQuestionLine className="w-3.5 h-3.5 text-muted-foreground" />;
  return <span className={cn("flex items-center gap-0.5 text-xs", meta.color)}>{meta.icon}{meta.label}</span>;
}

function fmtDate(d: string | null): string {
  if (!d) return "—";
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return d;
  return dt.toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="rounded-xl border border-border bg-muted/20 px-4 py-3">
      <p className="text-xs text-muted-foreground mb-0.5">{label}</p>
      <p className={cn("text-2xl font-bold", color || "")}>{value}</p>
      {sub && <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{sub}</p>}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function TldRegistryPage() {
  const [records, setRecords] = React.useState<TldRecord[]>([]);
  const [dbStats, setDbStats] = React.useState<DbStats | null>(null);
  const [loading, setLoading] = React.useState(true);

  // Scan state
  const [scanning, setScanning] = React.useState(false);
  const [scanType, setScanType] = React.useState("cc");
  const [scanForce, setScanForce] = React.useState(false);
  const [concur, setConcur] = React.useState(15);
  const [customTlds, setCustomTlds] = React.useState("");
  const [progress, setProgress] = React.useState({ done: 0, total: 0, errors: 0 });
  const [scanLog, setScanLog] = React.useState<string[]>([]);
  const esRef = React.useRef<EventSource | null>(null);

  // Table state
  const [search, setSearch] = React.useState("");
  const [filterType, setFilterType] = React.useState("all");
  const [filterStatus, setFilterStatus] = React.useState("all");
  const [filterRegistry, setFilterRegistry] = React.useState("all");
  const [sortKey, setSortKey] = React.useState<keyof TldRecord>("tld");
  const [sortAsc, setSortAsc] = React.useState(true);
  const [expandedTld, setExpandedTld] = React.useState<string | null>(null);

  // Load DB records on mount
  React.useEffect(() => {
    loadRecords();
  }, []);

  async function loadRecords() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/tld-registry");
      const d = await r.json();
      if (r.ok) {
        setRecords(d.records ?? []);
        setDbStats(d.stats ?? null);
      } else {
        toast.error(d.error ?? "加载失败");
      }
    } catch {
      toast.error("网络错误");
    } finally {
      setLoading(false);
    }
  }

  function startScan() {
    if (scanning) return;
    setScanning(true);
    setProgress({ done: 0, total: 0, errors: 0 });
    setScanLog([]);

    const params = new URLSearchParams({
      stream: "1",
      type: scanType,
      force: scanForce ? "1" : "0",
      concur: String(concur),
    });
    if (scanType === "custom" && customTlds.trim()) {
      params.set("tlds", customTlds.trim());
    }

    const es = new EventSource(`/api/admin/tld-registry?${params}`);
    esRef.current = es;

    es.addEventListener("start", (e) => {
      const d = JSON.parse(e.data);
      setProgress(p => ({ ...p, total: d.total }));
      setScanLog(l => [...l, `▶ 开始扫描 ${d.total} 个 TLD（类型：${d.type}，强制刷新：${d.force ? "是" : "否"}）`]);
    });

    es.addEventListener("result", (e) => {
      const d: TldRecord = JSON.parse(e.data);
      setProgress({ done: d.done ?? 0, total: d.total ?? 0, errors: d.errors ?? 0 });

      // Update or add record in table
      setRecords(prev => {
        const idx = prev.findIndex(r => r.tld === d.tld);
        if (idx >= 0) {
          const next = [...prev];
          next[idx] = d;
          return next;
        }
        return [...prev, d];
      });

      if (d.scan_error) {
        setScanLog(l => [...l.slice(-99), `  ❌ .${d.tld}  ${d.scan_error}`]);
      } else if (d.registry_url) {
        setScanLog(l => [...l.slice(-99), `  ✅ .${d.tld}  ${d.tld_type || "?"}  ${d.registry_url}`]);
      } else {
        setScanLog(l => [...l.slice(-99), `  ⚠️  .${d.tld}  ${d.tld_type || "?"}  无注册局 URL`]);
      }
    });

    es.addEventListener("done", (e) => {
      const d = JSON.parse(e.data);
      setProgress({ done: d.done, total: d.total, errors: d.errors });
      setScanLog(l => [...l, `✅ 扫描完成：${d.done} 个 TLD，${d.errors} 个失败`]);
      setScanning(false);
      esRef.current?.close();
      esRef.current = null;
      loadRecords();
    });

    es.addEventListener("error", () => {
      if (scanning) {
        setScanLog(l => [...l, "❌ 连接中断"]);
        setScanning(false);
        esRef.current?.close();
        esRef.current = null;
      }
    });
  }

  function stopScan() {
    esRef.current?.close();
    esRef.current = null;
    setScanning(false);
    setScanLog(l => [...l, "⏹ 已手动停止"]);
  }

  async function deleteRecord(tld: string) {
    if (!confirm(`确认删除 .${tld} 的记录？`)) return;
    await fetch(`/api/admin/tld-registry?tld=${tld}`, { method: "DELETE" });
    setRecords(prev => prev.filter(r => r.tld !== tld));
    toast.success(`.${tld} 已删除`);
  }

  async function deleteAll() {
    if (!confirm("确认清空所有 TLD 注册局记录？")) return;
    await fetch("/api/admin/tld-registry?tld=__all", { method: "DELETE" });
    setRecords([]);
    setDbStats(null);
    toast.success("已清空所有记录");
  }

  function toggleSort(key: keyof TldRecord) {
    if (sortKey === key) setSortAsc(a => !a);
    else { setSortKey(key); setSortAsc(true); }
  }

  // ── Filtered + sorted records ─────────────────────────────────────────────
  const filtered = React.useMemo(() => {
    let data = [...records];
    if (filterType !== "all") data = data.filter(r => (r.tld_type || "generic") === filterType);
    if (filterStatus !== "all") data = data.filter(r => (r.status || "") === filterStatus);
    if (filterRegistry === "yes") data = data.filter(r => !!r.registry_url);
    if (filterRegistry === "no")  data = data.filter(r => !r.registry_url);
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(r =>
        r.tld.includes(q) ||
        (r.manager || "").toLowerCase().includes(q) ||
        (r.registry_url || "").toLowerCase().includes(q) ||
        (r.whois_server || "").toLowerCase().includes(q) ||
        (r.country || "").toLowerCase().includes(q)
      );
    }
    data.sort((a, b) => {
      const av = String(a[sortKey] ?? "").toLowerCase();
      const bv = String(b[sortKey] ?? "").toLowerCase();
      return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    return data;
  }, [records, filterType, filterStatus, filterRegistry, search, sortKey, sortAsc]);

  const typeCounts = React.useMemo(() => {
    const c: Record<string, number> = { all: records.length };
    for (const r of records) c[r.tld_type || "generic"] = (c[r.tld_type || "generic"] || 0) + 1;
    return c;
  }, [records]);

  const SortTh = ({ label, skey, className }: { label: string; skey: keyof TldRecord; className?: string }) => (
    <th
      className={cn("px-3 py-2 text-left text-xs font-medium text-muted-foreground cursor-pointer select-none hover:text-foreground transition-colors whitespace-nowrap", className)}
      onClick={() => toggleSort(skey)}
    >
      <span className="inline-flex items-center gap-0.5">
        {label}
        {sortKey === skey
          ? (sortAsc ? <RiArrowUpSLine className="w-3 h-3" /> : <RiArrowDownSLine className="w-3 h-3" />)
          : <RiArrowDownSLine className="w-3 h-3 opacity-30" />}
      </span>
    </th>
  );

  const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiGlobalLine className="w-5 h-5 text-primary" />
              TLD 注册局数据库
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              从 IANA 根域名数据库自动抓取各 TLD 的注册局官网、WHOIS 服务器、所属机构等元数据。支持流式抓取，实时更新，永久存储。
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <Button variant="outline" size="sm" onClick={loadRecords} disabled={loading} className="h-8 text-xs">
              <RiRefreshLine className={cn("w-3.5 h-3.5 mr-1", loading && "animate-spin")} />
              刷新
            </Button>
            {records.length > 0 && (
              <Button variant="outline" size="sm" onClick={deleteAll} className="h-8 text-xs text-destructive border-destructive/30 hover:bg-destructive/10">
                <RiDeleteBin7Line className="w-3.5 h-3.5 mr-1" />
                清空
              </Button>
            )}
          </div>
        </div>

        {/* Stats cards */}
        {dbStats && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatCard label="总计 TLD" value={dbStats.total} />
            <StatCard label="ccTLD" value={dbStats.cc} color="text-blue-600" />
            <StatCard label="gTLD" value={dbStats.generic} color="text-emerald-600" />
            <StatCard label="sTLD" value={dbStats.sponsored} color="text-violet-600" />
            <StatCard label="有注册局 URL" value={dbStats.with_registry} color="text-amber-600" />
            <StatCard label="最近扫描" value={dbStats.last_scan ? fmtDate(dbStats.last_scan) : "—"} />
          </div>
        )}

        {/* Scan panel */}
        <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-4">
          <p className="text-sm font-semibold">IANA 元数据扫描</p>

          <div className="flex flex-wrap gap-3 items-end">
            {/* Type selector */}
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">TLD 类型</label>
              <div className="flex gap-1.5 flex-wrap">
                {[
                  { k: "cc",     l: "ccTLD (国家)" },
                  { k: "gtld",   l: "gTLD (通用)" },
                  { k: "all",    l: "全部" },
                  { k: "custom", l: "自定义" },
                ].map(({ k, l }) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setScanType(k)}
                    className={cn(
                      "text-xs px-2.5 py-1 rounded-full border transition-colors",
                      scanType === k
                        ? "bg-foreground text-background border-transparent"
                        : "bg-muted/40 border-border text-muted-foreground hover:bg-muted/60"
                    )}
                  >
                    {l}
                  </button>
                ))}
              </div>
            </div>

            {/* Concurrency */}
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">并发数</label>
              <Input
                type="number" min={1} max={30} value={concur}
                onChange={e => setConcur(Math.min(30, Math.max(1, parseInt(e.target.value) || 10)))}
                className="h-8 w-20 text-sm"
              />
            </div>

            {/* Force */}
            <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
              <input type="checkbox" checked={scanForce} onChange={e => setScanForce(e.target.checked)} className="w-3.5 h-3.5" />
              强制重新扫描
            </label>

            {/* Action button */}
            <Button
              onClick={scanning ? stopScan : startScan}
              size="sm"
              variant={scanning ? "destructive" : "default"}
              className="h-8 text-xs"
            >
              {scanning
                ? <><RiStopCircleLine className="w-3.5 h-3.5 mr-1" />停止</>
                : <><RiGlobalLine className="w-3.5 h-3.5 mr-1" />开始扫描</>}
            </Button>
          </div>

          {/* Custom TLD input */}
          {scanType === "custom" && (
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">自定义 TLD（空格或逗号分隔）</label>
              <textarea
                value={customTlds}
                onChange={e => setCustomTlds(e.target.value)}
                rows={2}
                placeholder="例：gw jp cn us uk de fr"
                className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
          )}

          {/* Progress */}
          {(scanning || progress.total > 0) && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>
                  {scanning ? <><RiLoader4Line className="inline w-3 h-3 animate-spin mr-1" />扫描中…</> : "已完成"}
                  {" "}{progress.done}/{progress.total}（{pct}%）{progress.errors > 0 && <span className="text-destructive ml-1">{progress.errors} 个错误</span>}
                </span>
                <span>{pct}%</span>
              </div>
              <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all duration-300 rounded-full"
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          )}

          {/* Scan log */}
          {scanLog.length > 0 && (
            <div className="rounded-lg bg-muted/30 border border-border p-2 max-h-32 overflow-y-auto font-mono text-[11px] text-muted-foreground space-y-0.5">
              {scanLog.map((l, i) => <div key={i}>{l}</div>)}
            </div>
          )}
        </div>

        {/* Results table */}
        {(records.length > 0 || loading) && (
          <div className="space-y-3">
            {/* Filter + search bar */}
            <div className="flex flex-wrap gap-2 items-center">
              {/* Type filter chips */}
              {[
                { k: "all", l: `全部 (${records.length})` },
                { k: "country-code", l: `ccTLD (${typeCounts["country-code"] || 0})` },
                { k: "generic", l: `gTLD (${typeCounts["generic"] || 0})` },
                { k: "generic-restricted", l: `受限 (${typeCounts["generic-restricted"] || 0})` },
                { k: "sponsored", l: `sTLD (${typeCounts["sponsored"] || 0})` },
              ].map(({ k, l }) => {
                const count = k === "all" ? records.length : (typeCounts[k] ?? 0);
                if (k !== "all" && count === 0) return null;
                return (
                  <button key={k} onClick={() => setFilterType(k)}
                    className={cn("text-xs px-2.5 py-1 rounded-full border transition-colors",
                      filterType === k
                        ? "bg-foreground text-background border-transparent"
                        : "bg-muted/30 border-border text-muted-foreground hover:bg-muted/50"
                    )}>
                    {l}
                  </button>
                );
              })}

              {/* Registry URL filter */}
              <div className="flex gap-1 ml-1 border border-border rounded-full overflow-hidden text-xs">
                {[["all","全部"],["yes","有官网"],["no","无官网"]].map(([k,l]) => (
                  <button key={k} onClick={() => setFilterRegistry(k)}
                    className={cn("px-2.5 py-1 transition-colors",
                      filterRegistry === k ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground"
                    )}>{l}</button>
                ))}
              </div>

              {/* Search */}
              <div className="ml-auto flex items-center gap-1.5 border border-input rounded-lg px-2.5 h-7 bg-background">
                <RiSearchLine className="w-3 h-3 text-muted-foreground shrink-0" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="搜索 TLD / 机构 / 网址"
                  className="text-xs bg-transparent outline-none w-36 text-foreground placeholder:text-muted-foreground"
                />
              </div>

              <span className="text-xs text-muted-foreground">{filtered.length} 条</span>
            </div>

            {/* Table */}
            <div className="rounded-xl border border-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-muted/40 border-b border-border">
                      <SortTh label="TLD" skey="tld" className="w-16" />
                      <SortTh label="类型" skey="tld_type" className="w-24" />
                      <SortTh label="状态" skey="status" className="w-20 hidden sm:table-cell" />
                      <SortTh label="注册局机构" skey="manager" />
                      <SortTh label="官方网站" skey="registry_url" className="hidden md:table-cell" />
                      <SortTh label="WHOIS 服务器" skey="whois_server" className="hidden lg:table-cell" />
                      <SortTh label="国家/地区" skey="country" className="w-24 hidden xl:table-cell" />
                      <th className="px-3 py-2 text-right text-xs font-medium text-muted-foreground w-20">操作</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filtered.map(row => {
                      const isExpanded = expandedTld === row.tld;
                      return (
                        <React.Fragment key={row.tld}>
                          <tr
                            className={cn(
                              "hover:bg-muted/20 transition-colors cursor-pointer",
                              row.scan_error ? "opacity-60" : "",
                              isExpanded ? "bg-muted/30" : ""
                            )}
                            onClick={() => setExpandedTld(isExpanded ? null : row.tld)}
                          >
                            <td className="px-3 py-2.5">
                              <span className="font-mono font-semibold text-sm">.{row.tld}</span>
                            </td>
                            <td className="px-3 py-2.5">
                              <TypeBadge type={row.tld_type} />
                            </td>
                            <td className="px-3 py-2.5 hidden sm:table-cell">
                              {row.scan_error
                                ? <span className="flex items-center gap-1 text-xs text-destructive"><RiAlertLine className="w-3 h-3" />错误</span>
                                : <StatusIcon status={row.status} />
                              }
                            </td>
                            <td className="px-3 py-2.5 text-xs text-muted-foreground max-w-[180px] truncate">
                              {row.manager || <span className="text-muted-foreground/40">—</span>}
                            </td>
                            <td className="px-3 py-2.5 hidden md:table-cell">
                              {row.registry_url
                                ? (
                                  <a
                                    href={row.registry_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={e => e.stopPropagation()}
                                    className="text-xs text-primary hover:underline inline-flex items-center gap-1 max-w-[180px] truncate"
                                  >
                                    {row.registry_url.replace(/^https?:\/\//, "")}
                                    <RiExternalLinkLine className="w-2.5 h-2.5 shrink-0 opacity-60" />
                                  </a>
                                )
                                : <span className="text-muted-foreground/40 text-xs">—</span>
                              }
                            </td>
                            <td className="px-3 py-2.5 hidden lg:table-cell text-xs text-muted-foreground font-mono">
                              {row.whois_server || <span className="opacity-40">—</span>}
                            </td>
                            <td className="px-3 py-2.5 hidden xl:table-cell text-xs text-muted-foreground">
                              {row.country || "—"}
                            </td>
                            <td className="px-3 py-2.5 text-right">
                              <div className="flex items-center justify-end gap-1">
                                {row.iana_url && (
                                  <a
                                    href={row.iana_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={e => e.stopPropagation()}
                                    className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                                    title="查看 IANA 页面"
                                  >
                                    <RiExternalLinkLine className="w-3.5 h-3.5" />
                                  </a>
                                )}
                                <button
                                  onClick={e => { e.stopPropagation(); deleteRecord(row.tld); }}
                                  className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-destructive transition-colors"
                                  title="删除记录"
                                >
                                  <RiDeleteBin7Line className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>

                          {/* Expanded detail row */}
                          {isExpanded && (
                            <tr className="bg-muted/10 border-t border-border">
                              <td colSpan={8} className="px-4 py-4">
                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
                                  <div className="space-y-1.5">
                                    <p className="font-semibold text-foreground/80 uppercase tracking-wider text-[10px]">注册局信息</p>
                                    <DetailRow label="TLD" value={`.${row.tld}`} />
                                    <DetailRow label="类型" value={<TypeBadge type={row.tld_type} />} />
                                    <DetailRow label="状态" value={<StatusIcon status={row.status} />} />
                                    <DetailRow label="机构" value={row.manager} />
                                    <DetailRow label="国家/地区" value={row.country} />
                                    <DetailRow label="地址" value={row.address} wrap />
                                  </div>
                                  <div className="space-y-1.5">
                                    <p className="font-semibold text-foreground/80 uppercase tracking-wider text-[10px]">网络服务</p>
                                    <DetailRow label="官方网站" value={
                                      row.registry_url
                                        ? <a href={row.registry_url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">{row.registry_url}<RiExternalLinkLine className="w-3 h-3" /></a>
                                        : null
                                    } />
                                    <DetailRow label="WHOIS 服务器" value={row.whois_server ? <span className="font-mono">{row.whois_server}</span> : null} />
                                    <DetailRow label="域名服务器" value={row.nameservers} wrap />
                                    <DetailRow label="IANA 页面" value={
                                      row.iana_url
                                        ? <a href={row.iana_url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">{row.iana_url}<RiExternalLinkLine className="w-3 h-3" /></a>
                                        : null
                                    } />
                                  </div>
                                  <div className="space-y-1.5">
                                    <p className="font-semibold text-foreground/80 uppercase tracking-wider text-[10px]">时间信息</p>
                                    <DetailRow label="创建日期" value={row.created_date} />
                                    <DetailRow label="最后变更" value={row.changed_date} />
                                    <DetailRow label="扫描时间" value={row.scraped_at ? fmtDate(row.scraped_at) : null} />
                                    {row.probe_result && (
                                      <>
                                        <DetailRow label="探测结果" value={
                                          <span className={cn("font-medium", PROBE_META[row.probe_result]?.color || "")}>
                                            {PROBE_META[row.probe_result]?.label || row.probe_result}
                                          </span>
                                        } />
                                        <DetailRow label="探测服务器" value={row.probe_method ? <span className="font-mono">{row.probe_method}</span> : null} />
                                        <DetailRow label="延迟" value={row.probe_latency_ms ? `${row.probe_latency_ms}ms` : null} />
                                      </>
                                    )}
                                    {row.scan_error && (
                                      <DetailRow label="扫描错误" value={<span className="text-destructive">{row.scan_error}</span>} />
                                    )}
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}

                    {filtered.length === 0 && !loading && (
                      <tr>
                        <td colSpan={8} className="px-3 py-12 text-center text-sm text-muted-foreground">
                          <RiDatabase2Line className="w-8 h-8 mx-auto mb-3 opacity-30" />
                          {records.length === 0
                            ? "尚未扫描任何数据，请点击「开始扫描」从 IANA 抓取 TLD 元数据"
                            : "无匹配结果"}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Empty state before first scan */}
        {records.length === 0 && !loading && (
          <div className="rounded-xl border border-border bg-muted/10 py-16 text-center space-y-3">
            <RiGlobalLine className="w-12 h-12 mx-auto text-muted-foreground/30" />
            <p className="text-sm font-medium text-muted-foreground">还没有任何 TLD 注册局数据</p>
            <p className="text-xs text-muted-foreground/70 max-w-sm mx-auto">
              点击「开始扫描」，系统将自动访问 IANA 根域名数据库，抓取每个 TLD 的官方注册局网站、WHOIS 服务器及元数据，并永久保存到数据库。
            </p>
            <Button size="sm" onClick={startScan} className="text-xs" disabled={scanning}>
              <RiGlobalLine className="w-3.5 h-3.5 mr-1.5" />
              立即扫描 ccTLD
            </Button>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}

function DetailRow({ label, value, wrap }: { label: string; value: React.ReactNode; wrap?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex gap-2">
      <span className="text-muted-foreground shrink-0 w-20 text-[11px]">{label}</span>
      <span className={cn("text-foreground/90 flex-1", wrap ? "break-words" : "truncate")}>{value}</span>
    </div>
  );
}
