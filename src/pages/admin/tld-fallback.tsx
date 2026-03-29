import React from "react";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiDeleteBinLine, RiRefreshLine,
  RiToggleLine, RiAlertLine, RiCheckLine, RiServerLine,
  RiAddLine, RiPencilLine, RiCloseLine, RiSaveLine,
} from "@remixicon/react";

const TLD_TABS = [
  { href: "/admin/domains",      label: "TLD 管理" },
  { href: "/admin/tld-rules",   label: "TLD 规则" },
  { href: "/admin/tld-fallback", label: "查询兜底" },
];

type FallbackRow = {
  tld: string;
  fail_count: number;
  use_fallback: boolean;
  last_fail_at: string | null;
};

function fmt(d: string | null) {
  if (!d) return "—";
  const date = new Date(d);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return "刚刚";
  if (mins < 60) return `${mins}分钟前`;
  if (hours < 24) return `${hours}小时前`;
  if (days < 7) return `${days}天前`;
  return date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

export default function AdminTldFallbackPage() {
  const [rows, setRows] = React.useState<FallbackRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [actionId, setActionId] = React.useState<string | null>(null);

  // ── Add-TLD form state ────────────────────────────────────────────────────
  const [showAddForm, setShowAddForm] = React.useState(false);
  const [addTldInput, setAddTldInput] = React.useState("");
  const [addFailCount, setAddFailCount] = React.useState("0");
  const [addUseFallback, setAddUseFallback] = React.useState(false);
  const [adding, setAdding] = React.useState(false);

  // ── Inline fail_count edit state ─────────────────────────────────────────
  const [editingTld, setEditingTld] = React.useState<string | null>(null);
  const [editFailCount, setEditFailCount] = React.useState("");

  function load() {
    setLoading(true);
    fetch("/api/admin/tld-fallback")
      .then(r => r.json())
      .then(data => {
        if (data.error) toast.error(data.error);
        else setRows(data.rows || []);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => { load(); }, []);

  async function addTld() {
    const tld = addTldInput.trim().toLowerCase().replace(/^\./, "");
    if (!tld) { toast.error("请输入 TLD"); return; }
    setAdding(true);
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, fail_count: Number(addFailCount) || 0, use_fallback: addUseFallback }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "添加失败");
      toast.success(`已添加 .${tld}`);
      if (data.row) {
        setRows(prev => {
          const exists = prev.find(r => r.tld === tld);
          return exists
            ? prev.map(r => r.tld === tld ? data.row : r)
            : [data.row, ...prev];
        });
      }
      setAddTldInput("");
      setAddFailCount("0");
      setAddUseFallback(false);
      setShowAddForm(false);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setAdding(false);
    }
  }

  async function saveFailCount(tld: string) {
    const fc = parseInt(editFailCount, 10);
    if (isNaN(fc) || fc < 0) { toast.error("失败次数必须为非负整数"); return; }
    setActionId(tld + "-fc");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, fail_count: fc }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "保存失败");
      const uf = fc >= 3;
      setRows(prev => prev.map(r => r.tld === tld ? { ...r, fail_count: fc, use_fallback: uf } : r));
      toast.success(`已更新 .${tld} 失败次数为 ${fc}`);
      setEditingTld(null);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function toggleFallback(tld: string, current: boolean) {
    setActionId(tld + "-toggle");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, use_fallback: !current }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "操作失败");
      toast.success(`已${!current ? "启用" : "关闭"} .${tld} 兜底`);
      setRows(prev => prev.map(r => r.tld === tld ? { ...r, use_fallback: !current } : r));
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function deleteTld(tld: string) {
    if (!confirm(`确认清除 .${tld} 的兜底记录？`)) return;
    setActionId(tld + "-del");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "删除失败");
      toast.success(`已清除 .${tld}`);
      setRows(prev => prev.filter(r => r.tld !== tld));
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  async function clearAll() {
    if (!confirm("确认清空全部 TLD 兜底记录？")) return;
    setActionId("clear-all");
    try {
      const res = await fetch("/api/admin/tld-fallback", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || "清空失败");
      toast.success("已清空全部记录");
      setRows([]);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setActionId(null);
    }
  }

  const enabledCount = rows.filter(r => r.use_fallback).length;

  return (
    <AdminLayout title="TLD 管理">
      <div className="space-y-5">
        <PageTabs tabs={TLD_TABS} />

        {/* ── Header ── */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="text-lg font-bold">TLD 兜底查询统计</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              追踪各 TLD 原生 WHOIS/RDAP 失败次数，失败 ≥3 次自动启用第三方备用查询
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm"
              onClick={() => setShowAddForm(v => !v)}
              className="gap-1.5">
              <RiAddLine className="w-4 h-4" />手动添加
            </Button>
            <Button variant="outline" size="sm" onClick={load} disabled={loading}>
              <RiRefreshLine className={cn("w-4 h-4 mr-1.5", loading && "animate-spin")} />
              刷新
            </Button>
            {rows.length > 0 && (
              <Button variant="outline" size="sm" onClick={clearAll}
                disabled={actionId === "clear-all"}
                className="text-destructive border-destructive/30 hover:bg-destructive/10">
                {actionId === "clear-all"
                  ? <RiLoader4Line className="w-4 h-4 mr-1.5 animate-spin" />
                  : <RiDeleteBinLine className="w-4 h-4 mr-1.5" />}
                清空全部
              </Button>
            )}
          </div>
        </div>

        {/* ── Add TLD form ── */}
        {showAddForm && (
          <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <RiAddLine className="w-4 h-4 text-violet-500" />
              手动添加 / 覆盖 TLD 兜底记录
            </h3>
            <div className="flex flex-wrap gap-3 items-end">
              <div className="flex-1 min-w-[120px]">
                <label className="text-xs text-muted-foreground mb-1 block">TLD（不含点）</label>
                <Input
                  value={addTldInput}
                  onChange={e => setAddTldInput(e.target.value)}
                  placeholder="例如 bf 或 bn"
                  className="h-8 text-sm font-mono"
                  onKeyDown={e => e.key === "Enter" && addTld()}
                />
              </div>
              <div className="w-28">
                <label className="text-xs text-muted-foreground mb-1 block">失败次数</label>
                <Input
                  type="number" min="0"
                  value={addFailCount}
                  onChange={e => setAddFailCount(e.target.value)}
                  className="h-8 text-sm"
                />
              </div>
              <div className="flex items-center gap-2 pb-1">
                <input
                  type="checkbox"
                  id="add-use-fallback"
                  checked={addUseFallback}
                  onChange={e => setAddUseFallback(e.target.checked)}
                  className="w-4 h-4"
                />
                <label htmlFor="add-use-fallback" className="text-sm cursor-pointer">立即启用兜底</label>
              </div>
              <Button size="sm" onClick={addTld} disabled={adding} className="gap-1.5">
                {adding ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSaveLine className="w-4 h-4" />}
                提交
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setShowAddForm(false)}>
                <RiCloseLine className="w-4 h-4" />
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              若该 TLD 已有记录则覆盖更新。失败次数 ≥3 时会自动勾选启用兜底。
            </p>
          </div>
        )}

        {/* ── Stats cards ── */}
        <div className="grid grid-cols-3 gap-3">
          <div className="glass-panel border border-border rounded-2xl p-4 text-center">
            <p className="text-2xl font-bold">{rows.length}</p>
            <p className="text-xs text-muted-foreground mt-1">已追踪 TLD</p>
          </div>
          <div className="glass-panel border border-border rounded-2xl p-4 text-center">
            <p className="text-2xl font-bold text-amber-500">{enabledCount}</p>
            <p className="text-xs text-muted-foreground mt-1">已启用兜底</p>
          </div>
          <div className="glass-panel border border-border rounded-2xl p-4 text-center">
            <p className="text-2xl font-bold text-muted-foreground">{rows.length - enabledCount}</p>
            <p className="text-xs text-muted-foreground mt-1">观察中</p>
          </div>
        </div>

        {/* ── Table ── */}
        {loading && rows.length === 0 ? (
          <div className="flex items-center justify-center py-16">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : rows.length === 0 ? (
          <div className="glass-panel border border-border rounded-2xl p-10 text-center">
            <RiServerLine className="w-8 h-8 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">暂无记录，查询失败时自动生成统计，或点击"手动添加"</p>
          </div>
        ) : (
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground text-xs">TLD</th>
                  <th className="text-center px-3 py-3 font-medium text-muted-foreground text-xs">失败次数</th>
                  <th className="text-center px-3 py-3 font-medium text-muted-foreground text-xs">状态</th>
                  <th className="text-left px-3 py-3 font-medium text-muted-foreground text-xs">最后失败</th>
                  <th className="text-right px-4 py-3 font-medium text-muted-foreground text-xs">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map(row => {
                  const isEditingThis = editingTld === row.tld;
                  return (
                    <tr key={row.tld} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-3 font-mono font-semibold">.{row.tld}</td>

                      {/* ── Fail count cell — click pencil to edit inline ── */}
                      <td className="px-3 py-3 text-center">
                        {isEditingThis ? (
                          <div className="flex items-center justify-center gap-1">
                            <Input
                              type="number" min="0"
                              value={editFailCount}
                              onChange={e => setEditFailCount(e.target.value)}
                              className="h-6 w-16 text-xs text-center px-1"
                              onKeyDown={e => {
                                if (e.key === "Enter") saveFailCount(row.tld);
                                if (e.key === "Escape") setEditingTld(null);
                              }}
                              autoFocus
                            />
                            <Button variant="ghost" size="icon" className="h-6 w-6"
                              title="保存"
                              disabled={actionId === row.tld + "-fc"}
                              onClick={() => saveFailCount(row.tld)}>
                              {actionId === row.tld + "-fc"
                                ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                                : <RiSaveLine className="w-3 h-3 text-green-600" />}
                            </Button>
                            <Button variant="ghost" size="icon" className="h-6 w-6"
                              title="取消" onClick={() => setEditingTld(null)}>
                              <RiCloseLine className="w-3 h-3" />
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center justify-center gap-1 group">
                            <span className={cn(
                              "inline-flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold",
                              row.fail_count >= 3
                                ? "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400"
                                : row.fail_count >= 1
                                ? "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400"
                                : "bg-muted text-muted-foreground",
                            )}>
                              {row.fail_count}
                            </span>
                            <Button variant="ghost" size="icon"
                              className="h-5 w-5 opacity-0 group-hover:opacity-100 transition-opacity"
                              title="编辑失败次数"
                              onClick={() => { setEditingTld(row.tld); setEditFailCount(String(row.fail_count)); }}>
                              <RiPencilLine className="w-3 h-3" />
                            </Button>
                          </div>
                        )}
                      </td>

                      <td className="px-3 py-3 text-center">
                        {row.use_fallback ? (
                          <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-semibold">
                            <RiAlertLine className="w-3 h-3" />兜底中
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold">
                            <RiCheckLine className="w-3 h-3" />正常
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-3 text-xs text-muted-foreground">{fmt(row.last_fail_at)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            variant="ghost" size="icon"
                            className="w-7 h-7"
                            title={row.use_fallback ? "关闭兜底" : "启用兜底"}
                            disabled={actionId === row.tld + "-toggle"}
                            onClick={() => toggleFallback(row.tld, row.use_fallback)}
                          >
                            {actionId === row.tld + "-toggle"
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiToggleLine className="w-3.5 h-3.5" />}
                          </Button>
                          <Button
                            variant="ghost" size="icon"
                            className="w-7 h-7 text-destructive hover:text-destructive"
                            title="清除记录"
                            disabled={actionId === row.tld + "-del"}
                            onClick={() => deleteTld(row.tld)}
                          >
                            {actionId === row.tld + "-del"
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
