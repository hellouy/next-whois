import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageTabs } from "@/components/page-tabs";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiServerLine, RiAddLine, RiDeleteBin7Line, RiSearchLine,
  RiRefreshLine, RiLoader4Line, RiCheckboxCircleLine,
  RiDatabase2Line, RiFileLine, RiGlobalLine, RiCodeLine,
  RiCloseLine, RiSave3Line, RiAlertLine,
} from "@remixicon/react";

const TLD_TABS = [
  { href: "/admin/tld-lifecycle",          label: "生命周期" },
  { href: "/admin/tld-rules",              label: "TLD 规则" },
  { href: "/admin/tld-fallback",           label: "查询兜底" },
  { href: "/admin/tld-lifecycle-feedback", label: "纠错反馈" },
  { href: "/admin/repair-queue",           label: "服务器修复" },
  { href: "/admin/custom-servers",         label: "自定义服务器" },
  { href: "/admin/tld-probe",              label: "TLD 探测" },
  { href: "/admin/tld-registry",           label: "注册局信息" },
];

type Source = "builtin" | "db" | "registry" | "cctld";

interface ServerRow {
  tld: string;
  server: string;
  rawEntry: unknown;
  source: Source;
}

const SOURCE_META: Record<Source, { label: string; color: string; icon: React.ReactNode; desc: string }> = {
  builtin:  { label: "内置",     color: "text-violet-600 bg-violet-50 dark:bg-violet-950/40 border-violet-200 dark:border-violet-800",   icon: <RiCodeLine   className="w-3 h-3" />, desc: "代码中内置，最高优先级" },
  db:       { label: "数据库",   color: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800", icon: <RiDatabase2Line className="w-3 h-3" />, desc: "手动添加或修复队列保存，可编辑" },
  registry: { label: "注册局",   color: "text-blue-600 bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-800",               icon: <RiGlobalLine className="w-3 h-3" />, desc: "从 IANA 注册局信息抓取，自动生效" },
  cctld:    { label: "ccTLD 文件", color: "text-orange-600 bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-800",  icon: <RiFileLine   className="w-3 h-3" />, desc: "cctld-whois-servers.json 静态文件" },
};

function entryLabel(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object") {
    const e = raw as Record<string, unknown>;
    if (e.type === "tcp") return `TCP ${e.host}${e.port ? `:${e.port}` : ""}`;
    if (e.type === "http") return `HTTP ${e.url}`;
    if (e.type === "scraper") return `Scraper: ${e.name}`;
  }
  return String(raw);
}

export default function CustomServersPage() {
  const [rows, setRows] = React.useState<ServerRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [sourceFilter, setSourceFilter] = React.useState<Source | "all">("all");
  const [showAdd, setShowAdd] = React.useState(false);
  const [addTld, setAddTld] = React.useState("");
  const [addServer, setAddServer] = React.useState("");
  const [adding, setAdding] = React.useState(false);
  const [deletingTld, setDeletingTld] = React.useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/tld-servers");
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "加载失败");

      const builtinSet = new Set<string>(d.builtinTlds ?? []);
      const userMap: Record<string, unknown> = d.userServers ?? {};
      const registryMap: Record<string, unknown> = d.registryServers ?? {};
      const allMap: Record<string, unknown> = d.servers ?? {};

      const built: ServerRow[] = Object.entries(allMap).map(([tld, raw]) => {
        let source: Source;
        if (builtinSet.has(tld))       source = "builtin";
        else if (tld in userMap)        source = "db";
        else if (tld in registryMap)    source = "registry";
        else                            source = "cctld";
        return { tld, server: entryLabel(raw), rawEntry: raw, source };
      });

      built.sort((a, b) => {
        const order: Record<Source, number> = { db: 0, builtin: 1, registry: 2, cctld: 3 };
        const so = order[a.source] - order[b.source];
        if (so !== 0) return so;
        return a.tld.localeCompare(b.tld);
      });

      setRows(built);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);

  async function addServer_() {
    const tld = addTld.trim().toLowerCase().replace(/^\./, "");
    const server = addServer.trim();
    if (!tld || !server) { toast.error("TLD 和服务器地址都是必填项"); return; }
    setAdding(true);
    try {
      const r = await fetch("/api/admin/tld-servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, server }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "添加失败");
      toast.success(d.message ?? "已添加");
      setAddTld(""); setAddServer(""); setShowAdd(false);
      await load();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setAdding(false);
    }
  }

  async function deleteRow(tld: string) {
    if (!confirm(`确认要删除 .${tld} 的自定义服务器？（只能删除"数据库"来源的条目）`)) return;
    setDeletingTld(tld);
    try {
      const r = await fetch("/api/admin/tld-servers", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "删除失败");
      toast.success(d.message ?? "已删除");
      await load();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setDeletingTld(null);
    }
  }

  const filtered = rows.filter(r => {
    if (sourceFilter !== "all" && r.source !== sourceFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return r.tld.includes(q) || r.server.toLowerCase().includes(q);
    }
    return true;
  });

  const counts = rows.reduce((acc, r) => {
    acc[r.source] = (acc[r.source] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <AdminLayout>
      <div className="space-y-6">
        <PageTabs tabs={TLD_TABS} />

        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiServerLine className="w-5 h-5 text-primary" />
              自定义 WHOIS 服务器
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              查询时使用的 WHOIS 服务器列表，按优先级排序：数据库 &gt; 内置 &gt; ccTLD 文件 &gt; 注册局信息。
              数据库条目可以增删，其余来源为只读。
            </p>
          </div>
          <Button onClick={() => setShowAdd(true)} size="sm" className="h-8 text-xs shrink-0">
            <RiAddLine className="w-3.5 h-3.5 mr-1" />
            添加服务器
          </Button>
        </div>

        {/* Stats cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {(["db", "builtin", "cctld", "registry"] as Source[]).map(src => {
            const meta = SOURCE_META[src];
            const count = counts[src] ?? 0;
            return (
              <button key={src}
                onClick={() => setSourceFilter(sourceFilter === src ? "all" : src)}
                className={cn(
                  "rounded-xl border p-3 text-left transition-colors hover:bg-muted/40",
                  sourceFilter === src ? "ring-2 ring-ring" : "border-border bg-muted/20"
                )}
              >
                <p className="text-xs text-muted-foreground flex items-center gap-1 mb-1">
                  {meta.icon} {meta.label}
                </p>
                <p className="text-2xl font-bold">{count}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">{meta.desc}</p>
              </button>
            );
          })}
        </div>

        {/* Priority explanation banner */}
        <div className="rounded-xl border border-border bg-muted/20 p-3 text-xs text-muted-foreground flex items-start gap-2">
          <RiAlertLine className="w-4 h-4 mt-0.5 shrink-0 text-amber-500" />
          <span>
            <strong className="text-foreground">优先级说明：</strong>
            同一 TLD 存在多个来源时，优先级由高到低为：<strong>数据库</strong>（可编辑）→ <strong>内置</strong>（代码硬写）→ <strong>ccTLD 文件</strong> → <strong>注册局信息</strong>。
            "注册局信息"来源的服务器是从 IANA 抓取的，已自动参与查询，无需手动保存。
          </span>
        </div>

        {/* Add form */}
        {showAdd && (
          <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">添加自定义服务器</h3>
              <button onClick={() => setShowAdd(false)} className="text-muted-foreground hover:text-foreground">
                <RiCloseLine className="w-4 h-4" />
              </button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">TLD（不带点）</label>
                <Input
                  value={addTld}
                  onChange={e => setAddTld(e.target.value)}
                  placeholder="例：rw, ai, xyz"
                  className="h-8 text-sm font-mono"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">WHOIS 服务器（TCP 主机名）</label>
                <Input
                  value={addServer}
                  onChange={e => setAddServer(e.target.value)}
                  placeholder="例：whois.nic.rw"
                  className="h-8 text-sm font-mono"
                />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={() => setShowAdd(false)} className="h-8 text-xs">取消</Button>
              <Button size="sm" onClick={addServer_} disabled={adding} className="h-8 text-xs">
                {adding ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiSave3Line className="w-3.5 h-3.5 mr-1" />}
                保存
              </Button>
            </div>
          </div>
        )}

        {/* Filter / search bar */}
        <div className="flex flex-wrap items-center gap-2">
          {(["all", "db", "builtin", "cctld", "registry"] as const).map(k => {
            const count = k === "all" ? rows.length : (counts[k] ?? 0);
            if (k !== "all" && count === 0) return null;
            return (
              <button key={k} onClick={() => setSourceFilter(k)}
                className={cn(
                  "text-xs px-2.5 py-1 rounded-full border transition-colors",
                  sourceFilter === k
                    ? "bg-foreground text-background border-transparent"
                    : "bg-muted/30 border-border text-muted-foreground hover:bg-muted/50"
                )}>
                {k === "all" ? `全部 (${count})` : `${SOURCE_META[k].label} (${count})`}
              </button>
            );
          })}
          <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={loading} className="h-7 text-xs">
              <RiRefreshLine className={cn("w-3 h-3 mr-1", loading && "animate-spin")} />
              刷新
            </Button>
            <div className="flex items-center gap-1.5 border border-input rounded-lg px-2 h-7 bg-background">
              <RiSearchLine className="w-3 h-3 text-muted-foreground" />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="搜索 TLD / 服务器"
                className="text-xs bg-transparent outline-none w-36 text-foreground placeholder:text-muted-foreground" />
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="rounded-xl border border-border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 border-b border-border text-xs text-muted-foreground">
                  <th className="text-left px-3 py-2 font-medium w-20">TLD</th>
                  <th className="text-left px-3 py-2 font-medium">服务器</th>
                  <th className="text-left px-3 py-2 font-medium w-28">来源</th>
                  <th className="text-right px-3 py-2 font-medium w-16">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading && rows.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-3 py-8 text-center text-sm text-muted-foreground">
                      <RiLoader4Line className="w-5 h-5 mx-auto mb-2 animate-spin opacity-40" />
                      加载中…
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-3 py-8 text-center text-sm text-muted-foreground">
                      暂无匹配记录
                    </td>
                  </tr>
                ) : filtered.map(row => {
                  const meta = SOURCE_META[row.source];
                  const canDelete = row.source === "db";
                  const isDeleting = deletingTld === row.tld;
                  return (
                    <tr key={row.tld} className="hover:bg-muted/20 transition-colors">
                      <td className="px-3 py-2.5 font-mono font-semibold">.{row.tld}</td>
                      <td className="px-3 py-2.5 text-xs text-muted-foreground font-mono truncate max-w-xs">
                        {row.server}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={cn(
                          "inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border font-medium",
                          meta.color
                        )}>
                          {meta.icon}
                          {meta.label}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        {canDelete ? (
                          <button
                            onClick={() => deleteRow(row.tld)}
                            disabled={isDeleting}
                            className="text-xs text-destructive hover:text-destructive/80 disabled:opacity-50"
                            title={`删除 .${row.tld}`}
                          >
                            {isDeleting
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiDeleteBin7Line className="w-3.5 h-3.5" />}
                          </button>
                        ) : (
                          <span className="text-xs text-muted-foreground/40">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {!loading && filtered.length > 0 && (
            <div className="px-3 py-2 border-t border-border bg-muted/20 text-xs text-muted-foreground">
              共 {filtered.length} 条{filtered.length !== rows.length ? `（已筛选，总计 ${rows.length} 条）` : ""}
            </div>
          )}
        </div>
      </div>
    </AdminLayout>
  );
}
