import React, { useState, useEffect, useCallback, useRef } from "react";
import { getCached, setCached } from "@/lib/client-cache";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiSearchLine,
  RiTimeLine, RiCheckLine, RiAlertLine,
  RiSignalWifi3Line, RiServerLine, RiGlobalLine,
} from "@remixicon/react";
import type { TldSpeedStats, TldSpeedRow } from "@/pages/api/admin/tld-speed-stats";
import type { TldScanResult } from "@/pages/api/admin/tld-batch-scan";

const SPEED_CACHE_TTL = 2 * 60_000; // 2 min per parameter set
const HOURS_OPTIONS = [1, 6, 24, 72, 168];
const SORT_OPTIONS: { value: string; label: string }[] = [
  { value: "avg_ms",   label: "平均耗时" },
  { value: "p95_ms",   label: "P95 耗时" },
  { value: "fail_pct", label: "失败率" },
  { value: "total",    label: "查询量" },
];

function durationBadge(ms: number) {
  if (!ms) return "bg-muted text-muted-foreground";
  if (ms < 1000)  return "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400";
  if (ms < 3000)  return "bg-yellow-100 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-400";
  if (ms < 6000)  return "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400";
  return "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400";
}
function failBadge(pct: number) {
  if (pct === 0)  return "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400";
  if (pct < 10)   return "bg-yellow-100 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-400";
  if (pct < 40)   return "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400";
  return "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400";
}
function ms(v: number | null | undefined) {
  if (!v) return "—";
  if (v >= 1000) return `${(v / 1000).toFixed(1)}s`;
  return `${v}ms`;
}

export default function TldSpeedPage() {
  const [hours, setHours]   = useState(24);
  const [sort, setSort]     = useState("avg_ms");
  const [search, setSearch] = useState("");
  const [minQry, setMinQry] = useState(3);

  const cacheKey = `admin:tld-speed:${hours}:${sort}:${minQry}`;

  const [data, setData]       = useState<TldSpeedStats | null>(
    () => getCached<TldSpeedStats>(cacheKey, SPEED_CACHE_TTL)
  );
  const [loading, setLoading] = useState(
    () => !getCached<TldSpeedStats>(cacheKey, SPEED_CACHE_TTL)
  );
  const fetchRef = useRef(0);

  const loadStats = useCallback(() => {
    const key = `admin:tld-speed:${hours}:${sort}:${minQry}`;
    const cached = getCached<TldSpeedStats>(key, SPEED_CACHE_TTL);
    if (cached) {
      setData(cached);   // instant cache hit
      setLoading(false);
    } else {
      setLoading(true);
    }
    const id = ++fetchRef.current;
    fetch(`/api/admin/tld-speed-stats?hours=${hours}&sort=${sort}&min_queries=${minQry}&limit=200`)
      .then(r => r.json())
      .then((d: TldSpeedStats & { error?: string }) => {
        if (fetchRef.current !== id) return;
        if (d.error || !d.rows) {
          toast.error(d.error || "加载 TLD 测速统计失败");
          setLoading(false);
          return;
        }
        setCached(key, d);
        setData(d);
        setLoading(false);
      })
      .catch(() => {
        if (fetchRef.current === id) {
          toast.error("加载 TLD 测速统计失败");
          setLoading(false);
        }
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hours, sort, minQry]);

  useEffect(() => { loadStats(); }, [loadStats]);

  const [scanning, setScanning]       = useState(false);
  const [scanResults, setScanResults] = useState<TldScanResult[] | null>(null);
  const [scanSummary, setScanSummary] = useState<Record<string, number> | null>(null);
  const [scanTlds, setScanTlds]       = useState("");
  const [scanTimeout, setScanTimeout] = useState(5000);
  const [scanLimit, setScanLimit]     = useState(30);

  const runScan = useCallback(async () => {
    setScanning(true);
    setScanResults(null);
    setScanSummary(null);
    try {
      const tlds = scanTlds.trim()
        ? scanTlds.split(/[\s,;]+/).map(t => t.trim().toLowerCase().replace(/^\./, "")).filter(Boolean)
        : [];
      const res = await fetch("/api/admin/tld-batch-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tlds, limit: scanLimit, timeout_ms: scanTimeout }),
      });
      if (!res.ok) {
        const e = await res.json().catch(() => ({ error: "请求失败" }));
        toast.error(e.error ?? "扫描失败");
        return;
      }
      const json = await res.json();
      setScanResults(json.results ?? []);
      setScanSummary(json.summary ?? null);
      const found = (json.summary?.found ?? 0) as number;
      if (found > 0) {
        toast.success(`发现 ${found} 个可用服务器，已自动保存！`);
      } else {
        toast.info("未发现可用服务器");
      }
    } catch (e) {
      toast.error(String(e));
    } finally {
      setScanning(false);
    }
  }, [scanTlds, scanLimit, scanTimeout]);

  const rows = (data?.rows ?? []).filter(r =>
    !search || r.tld.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <AdminLayout title="TLD 速度统计">
      {/* ── 顶部概览卡片 ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {[
          { label: "总查询量", value: data?.total_queries?.toLocaleString() ?? "—", icon: RiGlobalLine, cls: "text-blue-600 dark:text-blue-400" },
          { label: "成功",     value: data?.total_success?.toLocaleString() ?? "—", icon: RiCheckLine,  cls: "text-emerald-600 dark:text-emerald-400" },
          { label: "失败",     value: data?.total_fail?.toLocaleString() ?? "—",    icon: RiAlertLine,  cls: "text-red-500 dark:text-red-400" },
          { label: "平均耗时", value: ms(data?.overall_avg_ms),                     icon: RiTimeLine,   cls: "text-amber-600 dark:text-amber-400" },
        ].map(({ label, value, icon: Icon, cls }) => (
          <div key={label} className="bg-card border rounded-xl p-4 flex items-center gap-3">
            <Icon className={cn("h-5 w-5 flex-shrink-0", cls)} />
            <div>
              <div className="text-xs text-muted-foreground">{label}</div>
              <div className="text-xl font-semibold">{value}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── TLD 速度表格 ── */}
      <div className="bg-card border rounded-xl mb-8 overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 p-4 border-b">
          <span className="font-semibold text-sm mr-1">TLD 响应速度</span>
          <div className="flex items-center gap-1 ml-auto">
            {HOURS_OPTIONS.map(h => (
              <button
                key={h}
                onClick={() => setHours(h)}
                className={cn(
                  "px-2 py-0.5 rounded text-xs font-medium transition-colors",
                  hours === h
                    ? "bg-primary text-primary-foreground"
                    : "hover:bg-muted text-muted-foreground",
                )}
              >
                {h < 24 ? `${h}h` : `${h / 24}d`}
              </button>
            ))}
          </div>
          <select
            value={sort}
            onChange={e => setSort(e.target.value)}
            className="ml-2 text-xs border rounded px-2 py-1 bg-background"
          >
            {SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label} 排序</option>)}
          </select>
          <div className="flex items-center gap-1">
            <label className="text-xs text-muted-foreground">最少查询:</label>
            <input
              type="number" min={1} max={100} value={minQry}
              onChange={e => setMinQry(Math.max(1, parseInt(e.target.value) || 1))}
              className="w-14 text-xs border rounded px-2 py-1 bg-background"
            />
          </div>
          <div className="relative">
            <RiSearchLine className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              className="pl-7 h-7 text-xs w-36"
              placeholder="筛选 TLD…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <Button variant="ghost" size="icon" onClick={loadStats} className="h-7 w-7">
            {loading ? <RiLoader4Line className="h-4 w-4 animate-spin" /> : <RiRefreshLine className="h-4 w-4" />}
          </Button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-xs text-muted-foreground">
                {["TLD", "查询量", "成功率", "平均", "P50", "P95", "最大", "缓存率", "最后活跃"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-muted-foreground text-sm">
                    <RiLoader4Line className="h-5 w-5 animate-spin inline mr-2" />加载中…
                  </td>
                </tr>
              )}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-muted-foreground text-sm">暂无数据</td>
                </tr>
              )}
              {rows.map((row: TldSpeedRow) => {
                const successPct = row.total > 0 ? Math.round((row.successes / row.total) * 100) : 0;
                return (
                  <tr key={row.tld} className="border-b last:border-0 hover:bg-muted/40 transition-colors">
                    <td className="px-3 py-2 font-mono font-medium">.{row.tld}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{row.total.toLocaleString()}</td>
                    <td className="px-3 py-2">
                      <span className={cn("px-2 py-0.5 rounded text-xs font-medium", failBadge(row.fail_pct))}>
                        {successPct}%
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={cn("px-2 py-0.5 rounded text-xs font-mono font-medium", durationBadge(row.avg_ms))}>
                        {ms(row.avg_ms)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground text-xs tabular-nums">{ms(row.p50_ms)}</td>
                    <td className="px-3 py-2 text-muted-foreground text-xs tabular-nums">{ms(row.p95_ms)}</td>
                    <td className="px-3 py-2 text-muted-foreground text-xs tabular-nums">{ms(row.max_ms)}</td>
                    <td className="px-3 py-2 text-xs tabular-nums text-muted-foreground">{row.cached_pct ?? 0}%</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">
                      {row.last_seen
                        ? new Date(row.last_seen).toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {rows.length > 0 && (
          <div className="px-4 py-2 border-t text-xs text-muted-foreground">
            显示 {rows.length} 个 TLD（过去 {hours < 24 ? `${hours}小时` : `${hours / 24}天`} / 最少 {minQry} 次查询）
          </div>
        )}
      </div>

      {/* ── 批量服务器扫描 ── */}
      <div className="bg-card border rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 p-4 border-b">
          <RiServerLine className="h-4 w-4 text-muted-foreground" />
          <span className="font-semibold text-sm">批量 WHOIS/RDAP 服务器探测</span>
          <span className="text-xs text-muted-foreground ml-1">— 自动发现并保存可用服务器</span>
        </div>
        <div className="p-4 space-y-3">
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex-1 min-w-48">
              <label className="text-xs text-muted-foreground mb-1 block">指定 TLD（留空自动从失败记录取）</label>
              <Input
                placeholder="hm, aq, bv, sj … 或留空"
                value={scanTlds}
                onChange={e => setScanTlds(e.target.value)}
                className="text-sm font-mono"
              />
            </div>
            <div className="w-28">
              <label className="text-xs text-muted-foreground mb-1 block">自动最多扫描</label>
              <input
                type="number" min={1} max={100} value={scanLimit}
                onChange={e => setScanLimit(Math.min(100, Math.max(1, parseInt(e.target.value) || 30)))}
                className="w-full text-sm border rounded px-3 py-2 bg-background"
              />
            </div>
            <div className="w-32">
              <label className="text-xs text-muted-foreground mb-1 block">每个超时 (ms)</label>
              <input
                type="number" min={2000} max={10000} step={500} value={scanTimeout}
                onChange={e => setScanTimeout(Math.min(10000, Math.max(2000, parseInt(e.target.value) || 5000)))}
                className="w-full text-sm border rounded px-3 py-2 bg-background"
              />
            </div>
            <Button onClick={runScan} disabled={scanning} className="gap-1.5">
              {scanning
                ? <><RiLoader4Line className="h-4 w-4 animate-spin" />扫描中…</>
                : <><RiSignalWifi3Line className="h-4 w-4" />开始扫描</>}
            </Button>
          </div>

          {scanSummary && (
            <div className="flex flex-wrap gap-4 text-sm">
              <span className="text-muted-foreground">共扫描 {scanSummary.total} 个</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-medium">发现 {scanSummary.found} 个可用</span>
              <span className="text-blue-600 dark:text-blue-400 font-medium">已保存 {scanSummary.saved} 个</span>
              <span className="text-muted-foreground">失败 {scanSummary.failed} 个</span>
            </div>
          )}

          {scanResults && scanResults.length > 0 && (
            <div className="overflow-x-auto mt-2">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-muted-foreground border-b">
                    {["TLD", "状态", "方式", "服务器", "耗时", "已保存"].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scanResults.map((r: TldScanResult) => (
                    <tr key={r.tld} className="border-b last:border-0 hover:bg-muted/40">
                      <td className="px-3 py-2 font-mono font-medium">.{r.tld}</td>
                      <td className="px-3 py-2">
                        <span className={cn(
                          "px-2 py-0.5 rounded text-xs font-medium",
                          r.status === "ok"
                            ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400"
                            : "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400",
                        )}>
                          {r.status === "ok" ? "可达" : "不可达"}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-xs text-muted-foreground">{r.method ?? "—"}</td>
                      <td className="px-3 py-2 font-mono text-xs truncate max-w-[200px]" title={r.server ?? ""}>
                        {r.server ?? r.error ?? "—"}
                      </td>
                      <td className="px-3 py-2 text-xs tabular-nums">{r.elapsed_ms ? `${r.elapsed_ms}ms` : "—"}</td>
                      <td className="px-3 py-2">
                        {r.saved
                          ? <RiCheckLine className="h-4 w-4 text-emerald-500" />
                          : <span className="text-muted-foreground text-xs">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </AdminLayout>
  );
}
