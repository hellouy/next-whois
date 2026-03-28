import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiRadarFill, RiCheckboxCircleLine,
  RiCloseCircleLine, RiQuestionLine, RiShieldCheckLine,
  RiSearchLine, RiRefreshLine,
} from "@remixicon/react";

type ProbeResult = {
  tld: string;
  domain: string;
  result: "rdap" | "whois" | "none" | "static_fallback";
  method: string | null;
  latencyMs: number;
  note: string | null;
};

type StaticInfo = {
  static_always_fallback: string[];
  rdap_overrides_known: string[];
  whois_known: string[];
};

const RESULT_META: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  rdap:           { label: "RDAP", color: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800", icon: <RiCheckboxCircleLine className="w-3.5 h-3.5" /> },
  whois:          { label: "WHOIS TCP", color: "text-blue-600 bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-800", icon: <RiCheckboxCircleLine className="w-3.5 h-3.5" /> },
  none:           { label: "无响应 → Fallback", color: "text-orange-600 bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-800", icon: <RiCloseCircleLine className="w-3.5 h-3.5" /> },
  static_fallback:{ label: "静态 Fallback", color: "text-violet-600 bg-violet-50 dark:bg-violet-950/40 border-violet-200 dark:border-violet-800", icon: <RiShieldCheckLine className="w-3.5 h-3.5" /> },
};

export default function TldProbePage() {
  const [staticInfo, setStaticInfo] = React.useState<StaticInfo | null>(null);
  const [tldInput, setTldInput] = React.useState("");
  const [timeout, setTimeout_] = React.useState("5000");
  const [results, setResults] = React.useState<ProbeResult[]>([]);
  const [running, setRunning] = React.useState(false);
  const [filterResult, setFilterResult] = React.useState<string>("all");
  const [search, setSearch] = React.useState("");

  React.useEffect(() => {
    fetch("/api/admin/tld-probe")
      .then(r => r.json())
      .then(d => setStaticInfo(d))
      .catch(() => {});
  }, []);

  async function runProbe() {
    const tlds = tldInput.split(/[\s,，]+/).map(t => t.trim().toLowerCase().replace(/^\./, "")).filter(Boolean);
    if (tlds.length === 0) { toast.error("请输入至少一个 TLD"); return; }
    if (tlds.length > 30) { toast.error("每次最多探测 30 个 TLD"); return; }

    setRunning(true);
    setResults([]);
    try {
      const r = await fetch("/api/admin/tld-probe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tlds, timeout: parseInt(timeout) || 5000 }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "探测失败");
      setResults(d.results ?? []);
      toast.success(`探测完成，共 ${d.results?.length ?? 0} 个 TLD`);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setRunning(false);
    }
  }

  const presets = [
    { label: "非洲 ccTLD", tlds: "ao,bw,cm,cg,et,gh,gm,ke,lr,mw,mz,ne,ng,rw,sd,sl,sn,so,ss,sz,td,tz,ug,za,zm,zw" },
    { label: "Fallback 已知", tlds: "bd,cg,er,gw,lr,ne,sz,kp,cu,gm,gu,mh,va,fk" },
    { label: "RDAP 已知", tlds: "al,am,ba,bw,et,jm,mm,np,zw,gh,ke,ng,ug,rw,cm,so,sd,ss,tz,za" },
  ];

  const filtered = results.filter(r => {
    if (filterResult !== "all" && r.result !== filterResult) return false;
    if (search && !r.tld.includes(search.toLowerCase()) && !(r.method ?? "").toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const counts = results.reduce((acc, r) => { acc[r.result] = (acc[r.result] ?? 0) + 1; return acc; }, {} as Record<string, number>);

  return (
    <AdminLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <RiRadarFill className="w-5 h-5 text-primary" />
            TLD 探测工具
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            探测各 TLD 是否支持原生 WHOIS TCP 或 RDAP 查询，辅助判断是否需要降级至 yisi/tianhu 备用方案。
          </p>
        </div>

        {/* Static info cards */}
        {staticInfo && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="rounded-xl border border-border bg-muted/30 px-4 py-3">
              <p className="text-xs text-muted-foreground mb-1">静态 Fallback TLD</p>
              <p className="text-2xl font-bold">{staticInfo.static_always_fallback.length}</p>
              <p className="text-[11px] text-muted-foreground mt-1 truncate">{staticInfo.static_always_fallback.slice(0,10).join(", ")}{staticInfo.static_always_fallback.length > 10 ? "…" : ""}</p>
            </div>
            <div className="rounded-xl border border-border bg-muted/30 px-4 py-3">
              <p className="text-xs text-muted-foreground mb-1">已知 RDAP 服务器</p>
              <p className="text-2xl font-bold">{staticInfo.rdap_overrides_known.length}</p>
              <p className="text-[11px] text-muted-foreground mt-1 truncate">{staticInfo.rdap_overrides_known.slice(0,10).join(", ")}{staticInfo.rdap_overrides_known.length > 10 ? "…" : ""}</p>
            </div>
            <div className="rounded-xl border border-border bg-muted/30 px-4 py-3">
              <p className="text-xs text-muted-foreground mb-1">已知 WHOIS 服务器</p>
              <p className="text-2xl font-bold">{staticInfo.whois_known.length}</p>
              <p className="text-[11px] text-muted-foreground mt-1 truncate">{staticInfo.whois_known.slice(0,10).join(", ")}{staticInfo.whois_known.length > 10 ? "…" : ""}</p>
            </div>
          </div>
        )}

        {/* Probe form */}
        <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">输入 TLD（空格或逗号分隔，最多 30 个）</label>
            <textarea
              value={tldInput}
              onChange={e => setTldInput(e.target.value)}
              rows={3}
              placeholder="例：cn jp kr us uk de fr it es au ca br mx in"
              className="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <div className="flex flex-wrap gap-2">
              {presets.map(p => (
                <button key={p.label} type="button" onClick={() => setTldInput(p.tlds)}
                  className="text-xs px-2.5 py-1 rounded-full bg-muted hover:bg-muted/80 border border-border text-muted-foreground">
                  {p.label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-3 items-end">
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">超时（ms）</label>
              <Input value={timeout} onChange={e => setTimeout_(e.target.value)} className="h-8 w-28 text-sm" type="number" min="2000" max="10000" step="500" />
            </div>
            <Button onClick={runProbe} disabled={running} className="h-8 text-xs">
              {running ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <RiRadarFill className="w-3.5 h-3.5 mr-1.5" />}
              {running ? "探测中…" : "开始探测"}
            </Button>
          </div>
        </div>

        {/* Results */}
        {results.length > 0 && (
          <div className="space-y-3">
            {/* Summary chips */}
            <div className="flex flex-wrap gap-2 items-center">
              {(["all", "rdap", "whois", "none", "static_fallback"] as const).map(k => {
                const count = k === "all" ? results.length : (counts[k] ?? 0);
                if (k !== "all" && count === 0) return null;
                const meta = RESULT_META[k];
                return (
                  <button key={k} onClick={() => setFilterResult(k)}
                    className={cn("text-xs px-2.5 py-1 rounded-full border transition-colors",
                      filterResult === k
                        ? "bg-foreground text-background border-transparent"
                        : "bg-muted/30 border-border text-muted-foreground hover:bg-muted/50"
                    )}>
                    {k === "all" ? `全部 (${count})` : `${meta?.label} (${count})`}
                  </button>
                );
              })}
              <div className="ml-auto flex items-center gap-1.5 border border-input rounded-lg px-2 h-7 bg-background">
                <RiSearchLine className="w-3 h-3 text-muted-foreground" />
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="搜索 TLD / 服务器"
                  className="text-xs bg-transparent outline-none w-32 text-foreground placeholder:text-muted-foreground" />
              </div>
            </div>

            {/* Table */}
            <div className="rounded-xl border border-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-muted/40 border-b border-border text-xs text-muted-foreground">
                      <th className="text-left px-3 py-2 font-medium w-16">TLD</th>
                      <th className="text-left px-3 py-2 font-medium">测试域名</th>
                      <th className="text-left px-3 py-2 font-medium">结果</th>
                      <th className="text-left px-3 py-2 font-medium hidden sm:table-cell">服务器 / 方法</th>
                      <th className="text-right px-3 py-2 font-medium w-20">延迟</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filtered.map(row => {
                      const meta = RESULT_META[row.result];
                      return (
                        <tr key={row.tld} className="hover:bg-muted/20 transition-colors">
                          <td className="px-3 py-2.5 font-mono font-semibold">.{row.tld}</td>
                          <td className="px-3 py-2.5 text-muted-foreground text-xs">{row.domain}</td>
                          <td className="px-3 py-2.5">
                            <span className={cn("inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border font-medium", meta?.color)}>
                              {meta?.icon}
                              {meta?.label}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground hidden sm:table-cell font-mono truncate max-w-xs">
                            {row.method ?? (row.note ?? "—")}
                          </td>
                          <td className="px-3 py-2.5 text-right text-xs text-muted-foreground">
                            {row.result === "static_fallback" ? (
                              <span className="text-violet-500 font-medium">本地</span>
                            ) : row.latencyMs > 0 ? `${row.latencyMs}ms` : "—"}
                          </td>
                        </tr>
                      );
                    })}
                    {filtered.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-3 py-8 text-center text-sm text-muted-foreground">
                          <RiQuestionLine className="w-5 h-5 mx-auto mb-2 opacity-40" />
                          无匹配结果
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
