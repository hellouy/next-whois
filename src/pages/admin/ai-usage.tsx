import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRefreshLine, RiRobot2Line, RiTimerLine,
  RiCheckLine, RiCloseCircleLine, RiBarChartLine, RiGlobalLine,
} from "@remixicon/react";

type Summary = { total: number; success: number; failed: number; avg_ms: number | null };
type ProviderRow = {
  provider: string; model: string; calls: number; success: number; failed: number;
  avg_ms: number | null; max_ms: number | null; last_error: string | null; last_at: string | null;
};
type CircuitState = {
  id: string; name: string; state: "closed" | "open" | "half_open";
  consecutiveFails: number; firstFailTs: number; openUntil: number; transitionTs: number; transitions: number;
};
type TransitionRow = { provider: string; model: string; error: string | null; created_at: string };
type RecentRow = {
  provider: string; model: string; tld: string | null; ok: boolean;
  ms: number | null; error: string | null; created_at: string;
};

const CIRCUIT_LABELS: Record<string, { label: string; cls: string }> = {
  closed:    { label: "正常", cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" },
  half_open: { label: "半开", cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400" },
  open:      { label: "熔断", cls: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" },
};

export default function AiUsagePage() {
  const [window, setWindow] = React.useState<7 | 30>(7);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [summary, setSummary] = React.useState<Summary | null>(null);
  const [providers, setProviders] = React.useState<ProviderRow[]>([]);
  const [circuits, setCircuits] = React.useState<CircuitState[]>([]);
  const [transitions, setTransitions] = React.useState<TransitionRow[]>([]);
  const [recent, setRecent] = React.useState<RecentRow[]>([]);

  const load = React.useCallback(async (days: 7 | 30) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/admin/ai-stats?window=${days}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSummary(data.summary ?? null);
      setProviders(data.providers ?? []);
      setCircuits(data.circuit_states ?? []);
      setTransitions(data.circuit_transitions ?? []);
      setRecent(data.recent ?? []);
    } catch (e: any) {
      setError(e.message ?? "加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    load(window);
  }, [window, load]);

  const fmtMs = (ms: number | null) => (ms == null ? "—" : `${ms} ms`);
  const pct = (a: number, b: number) => (b > 0 ? `${Math.round((a / b) * 100)}%` : "—");

  return (
    <AdminLayout title="AI 用量审计">
      <div className="space-y-4 p-4">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <RiRobot2Line className="w-5 h-5 text-primary" />
            <h1 className="text-lg font-semibold">AI 用量统计与熔断状态</h1>
          </div>
          <div className="flex items-center gap-2">
            {([7, 30] as const).map(d => (
              <Button
                key={d}
                size="sm"
                variant={window === d ? "default" : "outline"}
                onClick={() => setWindow(d)}
              >
                最近 {d} 天
              </Button>
            ))}
            <Button size="sm" variant="ghost" onClick={() => load(window)}>
              <RiRefreshLine className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16 text-muted-foreground">
            <RiLoader4Line className="w-5 h-5 animate-spin mr-2" /> 加载中…
          </div>
        ) : error ? (
          <div className="p-6 text-center text-red-600 dark:text-red-400">{error}</div>
        ) : (
          <>
            {/* Summary cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {[
                { label: "总调用", value: summary?.total ?? 0, icon: <RiGlobalLine className="w-4 h-4" />, cls: "text-primary" },
                { label: "成功", value: summary?.success ?? 0, icon: <RiCheckLine className="w-4 h-4" />, cls: "text-emerald-600 dark:text-emerald-400" },
                { label: "失败", value: summary?.failed ?? 0, icon: <RiCloseCircleLine className="w-4 h-4" />, cls: "text-red-600 dark:text-red-400" },
                { label: "平均耗时", value: fmtMs(summary?.avg_ms ?? null), icon: <RiTimerLine className="w-4 h-4" />, cls: "text-muted-foreground" },
              ].map((c, i) => (
                <div key={i} className="rounded-xl border bg-card p-4">
                  <div className="flex items-center gap-2 text-muted-foreground text-xs">{c.icon}{c.label}</div>
                  <div className={cn("mt-1 text-2xl font-bold", c.cls)}>{c.value}</div>
                </div>
              ))}
            </div>

            {/* Per-provider table */}
            <div className="rounded-xl border bg-card overflow-hidden">
              <div className="px-4 py-3 border-b flex items-center gap-2 text-sm font-semibold">
                <RiBarChartLine className="w-4 h-4 text-primary" /> 各 Provider 用量
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50 text-muted-foreground text-xs">
                    <tr>
                      <th className="px-4 py-2 text-left">Provider</th>
                      <th className="px-4 py-2 text-left">模型</th>
                      <th className="px-4 py-2 text-right">调用</th>
                      <th className="px-4 py-2 text-right">成功</th>
                      <th className="px-4 py-2 text-right">失败</th>
                      <th className="px-4 py-2 text-right">成功率</th>
                      <th className="px-4 py-2 text-right">平均耗时</th>
                      <th className="px-4 py-2 text-right">熔断</th>
                      <th className="px-4 py-2 text-left">最近错误</th>
                    </tr>
                  </thead>
                  <tbody>
                    {providers.length === 0 && (
                      <tr><td colSpan={9} className="px-4 py-6 text-center text-muted-foreground">当前窗口无 AI 调用记录</td></tr>
                    )}
                    {providers.map((p, i) => {
                      const circ = circuits.find(c => c.name === p.provider);
                      const cl = CIRCUIT_LABELS[circ?.state ?? "closed"];
                      return (
                        <tr key={i} className="border-t">
                          <td className="px-4 py-2 font-medium">{p.provider}</td>
                          <td className="px-4 py-2 text-muted-foreground">{p.model}</td>
                          <td className="px-4 py-2 text-right">{p.calls}</td>
                          <td className="px-4 py-2 text-right text-emerald-600 dark:text-emerald-400">{p.success}</td>
                          <td className="px-4 py-2 text-right text-red-600 dark:text-red-400">{p.failed}</td>
                          <td className="px-4 py-2 text-right">{pct(p.success, p.calls)}</td>
                          <td className="px-4 py-2 text-right">{fmtMs(p.avg_ms)}</td>
                          <td className="px-4 py-2 text-right">
                            <span className={cn("inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded-full font-medium", cl.cls)}>
                              {cl.label}{circ && circ.transitions > 0 ? ` ×${circ.transitions}` : ""}
                            </span>
                          </td>
                          <td className="px-4 py-2 text-xs text-muted-foreground max-w-[220px] truncate" title={p.last_error ?? ""}>
                            {p.last_error ?? "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="grid lg:grid-cols-2 gap-4">
              {/* Recent extraction records */}
              <div className="rounded-xl border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b text-sm font-semibold">最近 TLD 抓取（模型 + 耗时）</div>
                <div className="max-h-[360px] overflow-y-auto">
                  {recent.length === 0 ? (
                    <div className="p-6 text-center text-muted-foreground text-sm">暂无抓取记录</div>
                  ) : (
                    <table className="w-full text-xs">
                      <tbody>
                        {recent.map((r, i) => (
                          <tr key={i} className="border-t">
                            <td className="px-4 py-2 font-medium">.{r.tld ?? "—"}</td>
                            <td className="px-4 py-2 text-muted-foreground">{r.model}</td>
                            <td className="px-4 py-2 text-right">{fmtMs(r.ms)}</td>
                            <td className="px-4 py-2 text-right">
                              {r.ok
                                ? <span className="text-emerald-600 dark:text-emerald-400">成功</span>
                                : <span className="text-red-600 dark:text-red-400">失败</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>

              {/* Circuit transitions */}
              <div className="rounded-xl border bg-card overflow-hidden">
                <div className="px-4 py-3 border-b text-sm font-semibold">熔断状态转移审计</div>
                <div className="max-h-[360px] overflow-y-auto divide-y">
                  {transitions.length === 0 ? (
                    <div className="p-6 text-center text-muted-foreground text-sm">当前窗口无熔断事件</div>
                  ) : (
                    transitions.map((t, i) => (
                      <div key={i} className="px-4 py-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">{t.provider}</span>
                          <span className="text-muted-foreground">{t.created_at?.slice(0, 19).replace("T", " ")}</span>
                        </div>
                        <div className="text-muted-foreground mt-0.5">{t.error ?? t.model}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </AdminLayout>
  );
}
