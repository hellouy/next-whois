/**
 * Admin: Hot Prefix Watchlist Management
 * /admin/hot-prefixes
 *
 * CRUD interface for managing the list of domain name prefixes that trigger
 * high-value available domain email alerts.
 */

import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  RiLoader4Line,
  RiSearchLine,
  RiDeleteBinLine,
  RiRefreshLine,
  RiAddLine,
  RiEditLine,
  RiSaveLine,
  RiCloseLine,
  RiFireLine,
  RiCheckboxCircleLine,
  RiErrorWarningLine,
  RiPriceTag3Line,
  RiBarChartLine,
  RiDownloadLine,
  RiToggleLine,
  RiToggleFill,
  RiRobot2Line,
  RiCheckLine,
} from "@remixicon/react";
import type { AiPrefixSuggestion } from "@/pages/api/admin/hot-prefixes";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface HotPrefix {
  id: number;
  prefix: string;
  category: string;
  weight: number;
  source: string;
  sale_examples: string | null;
  notes: string | null;
  enabled: boolean;
  hit_count: number;
  recent_hits: string;
  created_at: string;
  updated_at: string;
}

const CATEGORIES = [
  { value: "all",     label: "全部分类" },
  { value: "ai",      label: "🤖 AI/LLM" },
  { value: "web3",    label: "⛓ Web3/Crypto" },
  { value: "finance", label: "💰 Finance" },
  { value: "saas",    label: "🛠 SaaS/Dev" },
  { value: "short",   label: "✂️ Short/Premium" },
  { value: "cn",      label: "🇨🇳 Chinese Market" },
  { value: "general", label: "📦 General" },
];

const CATEGORY_COLORS: Record<string, string> = {
  ai:      "bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300",
  web3:    "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300",
  finance: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300",
  saas:    "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300",
  short:   "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300",
  cn:      "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300",
  general: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
};

const WEIGHT_COLOR = (w: number) =>
  w >= 25 ? "text-red-600 dark:text-red-400" :
  w >= 20 ? "text-orange-600 dark:text-orange-400" :
  w >= 15 ? "text-amber-600 dark:text-amber-400" :
  "text-gray-500";

interface FormState {
  prefix: string;
  category: string;
  weight: string;
  source: string;
  sale_examples: string;
  notes: string;
  enabled: boolean;
}

const DEFAULT_FORM: FormState = {
  prefix: "",
  category: "ai",
  weight: "15",
  source: "manual",
  sale_examples: "",
  notes: "",
  enabled: true,
};

export default function AdminHotPrefixesPage() {
  const [prefixes, setPrefixes] = React.useState<HotPrefix[]>([]);
  const [total, setTotal] = React.useState(0);
  const [categories, setCategories] = React.useState<{ category: string; cnt: string }[]>([]);
  const [loading, setLoading] = React.useState(true);

  const [search, setSearch] = React.useState("");
  const [filterCategory, setFilterCategory] = React.useState("all");

  const [editingId, setEditingId] = React.useState<number | null>(null);
  const [editForm, setEditForm] = React.useState<FormState>(DEFAULT_FORM);

  const [showAddForm, setShowAddForm] = React.useState(false);
  const [addForm, setAddForm] = React.useState<FormState>(DEFAULT_FORM);
  const [addSaving, setAddSaving] = React.useState(false);

  const [seeding, setSeeding] = React.useState(false);
  const [deletingId, setDeletingId] = React.useState<number | null>(null);
  const [savingId, setSavingId] = React.useState<number | null>(null);

  // ── AI discover state ────────────────────────────────────────────────────
  const [showAiDiscover, setShowAiDiscover] = React.useState(false);
  const [aiDiscovering, setAiDiscovering] = React.useState(false);
  const [aiSuggestions, setAiSuggestions] = React.useState<AiPrefixSuggestion[]>([]);
  const [aiSelected, setAiSelected] = React.useState<Set<string>>(new Set());
  const [aiImporting, setAiImporting] = React.useState(false);
  const [aiLog, setAiLog] = React.useState<string>("");

  const searchRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  async function fetchPrefixes() {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search.trim()) params.set("search", search.trim());
      if (filterCategory !== "all") params.set("category", filterCategory);
      const res = await fetch(`/api/admin/hot-prefixes?${params}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "加载失败");
      setPrefixes(data.prefixes ?? []);
      setTotal(data.total ?? 0);
      setCategories(data.categories ?? []);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    fetchPrefixes();
  }, [filterCategory]);

  React.useEffect(() => {
    if (searchRef.current) clearTimeout(searchRef.current);
    searchRef.current = setTimeout(() => fetchPrefixes(), 350);
    return () => { if (searchRef.current) clearTimeout(searchRef.current); };
  }, [search]);

  async function handleSeed() {
    if (!confirm("将插入内置热门前缀列表（已存在的不会重复添加）。继续？")) return;
    setSeeding(true);
    try {
      const res = await fetch("/api/admin/hot-prefixes?action=seed");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Seed failed");
      toast.success(`已导入 ${data.seeded} 个前缀`);
      fetchPrefixes();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setSeeding(false);
    }
  }

  async function handleAdd() {
    if (!addForm.prefix.trim()) { toast.error("前缀不能为空"); return; }
    setAddSaving(true);
    try {
      const res = await fetch("/api/admin/hot-prefixes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...addForm,
          prefix: addForm.prefix.toLowerCase().trim(),
          weight: parseInt(addForm.weight) || 10,
          sale_examples: addForm.sale_examples || null,
          notes: addForm.notes || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "添加失败");
      toast.success(`前缀 "${addForm.prefix}" 已添加`);
      setAddForm(DEFAULT_FORM);
      setShowAddForm(false);
      fetchPrefixes();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setAddSaving(false);
    }
  }

  async function handleSaveEdit(id: number) {
    setSavingId(id);
    try {
      const res = await fetch(`/api/admin/hot-prefixes?id=${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...editForm,
          weight: parseInt(editForm.weight) || 10,
          sale_examples: editForm.sale_examples || null,
          notes: editForm.notes || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "保存失败");
      toast.success("已保存");
      setEditingId(null);
      fetchPrefixes();
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setSavingId(null);
    }
  }

  async function handleToggleEnabled(p: HotPrefix) {
    try {
      const res = await fetch(`/api/admin/hot-prefixes?id=${p.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !p.enabled }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "更新失败");
      setPrefixes(prev => prev.map(x => x.id === p.id ? { ...x, enabled: !p.enabled } : x));
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  async function handleDelete(id: number, prefix: string) {
    if (!confirm(`确定要删除前缀 "${prefix}" 吗？`)) return;
    setDeletingId(id);
    try {
      const res = await fetch(`/api/admin/hot-prefixes?id=${id}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "删除失败");
      toast.success(`前缀 "${prefix}" 已删除`);
      setPrefixes(prev => prev.filter(p => p.id !== id));
      setTotal(t => t - 1);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setDeletingId(null);
    }
  }

  function startEdit(p: HotPrefix) {
    setEditingId(p.id);
    setEditForm({
      prefix: p.prefix,
      category: p.category,
      weight: String(p.weight),
      source: p.source,
      sale_examples: p.sale_examples ?? "",
      notes: p.notes ?? "",
      enabled: p.enabled,
    });
  }

  function runAiDiscover() {
    setAiSuggestions([]);
    setAiSelected(new Set());
    setAiLog("🤖 正在调用 AI 分析当前热门趋势…");
    setAiDiscovering(true);

    fetch("/api/admin/hot-prefixes?action=ai-discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "ai-discover" }),
    }).then(async res => {
      if (!res.ok || !res.body) { toast.error("请求失败"); setAiDiscovering(false); return; }
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      let curEvt = "message";
      const found: AiPrefixSuggestion[] = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (line.startsWith("event: ")) { curEvt = line.slice(7).trim(); }
          else if (line.startsWith("data: ")) {
            try {
              const d = JSON.parse(line.slice(6));
              if (curEvt === "start") {
                setAiLog(`🔍 已有 ${d.existing} 个前缀，正在发现新前缀…`);
              } else if (curEvt === "item") {
                const item = d as AiPrefixSuggestion;
                found.push(item);
                setAiSuggestions([...found]);
                setAiSelected(prev => { const s = new Set(prev); s.add(item.prefix); return s; });
                setAiLog(`✅ 发现 ${found.length} 个新前缀…`);
              } else if (curEvt === "done") {
                setAiLog(`🎉 发现完成，共 ${d.total} 个新前缀`);
              } else if (curEvt === "error") {
                setAiLog(`❌ ${String(d.message)}`);
              }
              curEvt = "message";
            } catch {}
          }
        }
      }
      setAiDiscovering(false);
    }).catch(e => { toast.error((e as Error).message); setAiDiscovering(false); });
  }

  async function importSelected() {
    const toImport = aiSuggestions.filter(s => aiSelected.has(s.prefix));
    if (toImport.length === 0) { toast.error("请先选择要导入的前缀"); return; }
    setAiImporting(true);
    try {
      const r = await fetch("/api/admin/hot-prefixes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          toImport.map(item => ({
            prefix: item.prefix,
            category: item.category,
            weight: item.weight,
            source: "ai",
            notes: item.reason,
            sale_examples: item.sale_examples || null,
          }))
        ),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "保存失败");
      await invalidateCacheClient();
      toast.success(`已导入 ${d.imported ?? toImport.length} 个前缀`);
      setShowAiDiscover(false);
      fetchPrefixes();
    } catch (e: any) {
      toast.error(e.message ?? "导入失败，请重试");
    } finally {
      setAiImporting(false);
    }
  }

  async function invalidateCacheClient() {
    // fire-and-forget cache bust
    try { await fetch("/api/admin/hot-prefixes?action=seed", { method: "HEAD" }); } catch {}
  }

  return (
    <>
      <Head><title>热门前缀管理 — Admin</title></Head>
      <AdminLayout>
        <div className="max-w-6xl mx-auto px-4 py-6 space-y-6">

          {/* Header */}
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold flex items-center gap-2">
                <RiFireLine className="w-6 h-6 text-orange-500" />
                热门前缀监控
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                当用户查询到匹配前缀的可注册域名时，发送邮件告警至管理员。共 {total} 个前缀。
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline" size="sm"
                onClick={handleSeed}
                disabled={seeding}
                className="gap-1.5"
              >
                {seeding ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiDownloadLine className="w-4 h-4" />}
                导入内置列表
              </Button>
              <Button
                variant="outline" size="sm"
                onClick={() => { setShowAiDiscover(v => !v); if (!showAiDiscover) { setAiSuggestions([]); setAiLog(""); } }}
                className="gap-1.5 border-violet-300 text-violet-700 hover:bg-violet-50 dark:border-violet-700 dark:text-violet-400 dark:hover:bg-violet-950/30"
              >
                <RiRobot2Line className="w-4 h-4" />
                AI 发现
              </Button>
              <Button
                size="sm"
                onClick={() => { setShowAddForm(v => !v); setAddForm(DEFAULT_FORM); }}
                className="gap-1.5 bg-orange-600 hover:bg-orange-700 text-white"
              >
                <RiAddLine className="w-4 h-4" />
                添加前缀
              </Button>
            </div>
          </div>

          {/* AI Discover Panel */}
          {showAiDiscover && (
            <div className="rounded-2xl border border-violet-200 dark:border-violet-800 bg-violet-50/50 dark:bg-violet-950/20 overflow-hidden">
              <div className="flex items-center justify-between px-5 py-4 border-b border-violet-200/60 dark:border-violet-800/40">
                <div>
                  <h2 className="font-bold text-sm flex items-center gap-1.5">
                    <RiRobot2Line className="w-4 h-4 text-violet-600 dark:text-violet-400" />
                    AI 智能发现热门前缀
                  </h2>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    基于当前 AI/Web3/科技/流行文化趋势，发现尚未录入的高价值域名前缀
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {!aiDiscovering && (
                    <Button
                      size="sm"
                      onClick={runAiDiscover}
                      className="gap-1.5 bg-violet-600 hover:bg-violet-700 text-white text-xs h-8"
                    >
                      <RiRobot2Line className="w-3.5 h-3.5" />
                      {aiSuggestions.length > 0 ? "重新发现" : "开始发现"}
                    </Button>
                  )}
                  {aiDiscovering && (
                    <div className="flex items-center gap-1.5 text-xs text-violet-600 dark:text-violet-400">
                      <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                      AI 分析中…
                    </div>
                  )}
                </div>
              </div>

              {/* Status log */}
              {aiLog && (
                <div className="px-5 py-2.5 text-xs text-muted-foreground border-b border-violet-200/40 dark:border-violet-800/30 font-mono">
                  {aiLog}
                </div>
              )}

              {/* Suggestions list */}
              {aiSuggestions.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-violet-200/40 dark:border-violet-800/30 bg-violet-100/30 dark:bg-violet-950/30">
                        <th className="text-left text-[10px] font-semibold text-muted-foreground px-4 py-2.5 w-10">
                          <button
                            onClick={() => {
                              if (aiSelected.size === aiSuggestions.length) {
                                setAiSelected(new Set());
                              } else {
                                setAiSelected(new Set(aiSuggestions.map(s => s.prefix)));
                              }
                            }}
                            className="hover:text-foreground transition-colors"
                          >
                            {aiSelected.size === aiSuggestions.length ? "取消" : "全选"}
                          </button>
                        </th>
                        {["前缀", "分类", "权重", "原因", "销售案例"].map(h => (
                          <th key={h} className="text-left text-[10px] font-semibold text-muted-foreground px-3 py-2.5 whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {aiSuggestions.map((s, i) => (
                        <tr
                          key={s.prefix}
                          className={cn(
                            "border-t border-violet-200/30 dark:border-violet-800/20 hover:bg-violet-100/30 dark:hover:bg-violet-950/30 cursor-pointer transition-colors",
                            aiSelected.has(s.prefix) ? "bg-violet-50/70 dark:bg-violet-950/10" : (i % 2 === 0 ? "" : "bg-muted/5")
                          )}
                          onClick={() => setAiSelected(prev => {
                            const s2 = new Set(prev);
                            if (s2.has(s.prefix)) s2.delete(s.prefix); else s2.add(s.prefix);
                            return s2;
                          })}
                        >
                          <td className="px-4 py-2.5">
                            <div className={cn(
                              "w-4 h-4 rounded border-2 flex items-center justify-center flex-shrink-0 transition-colors",
                              aiSelected.has(s.prefix)
                                ? "bg-violet-600 border-violet-600"
                                : "border-border bg-background"
                            )}>
                              {aiSelected.has(s.prefix) && <RiCheckLine className="w-2.5 h-2.5 text-white" />}
                            </div>
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="font-mono font-bold text-sm">{s.prefix}</span>
                          </td>
                          <td className="px-3 py-2.5">
                            <span className={cn("text-[10px] font-medium px-1.5 py-0.5 rounded border", CATEGORY_COLORS[s.category] ?? CATEGORY_COLORS.general)}>
                              {s.category}
                            </span>
                          </td>
                          <td className="px-3 py-2.5">
                            <span className={cn("text-xs font-semibold tabular-nums", WEIGHT_COLOR(s.weight))}>{s.weight}</span>
                          </td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground max-w-[240px]" title={s.reason}>{s.reason}</td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground max-w-[160px] truncate" title={s.sale_examples}>{s.sale_examples || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Footer with import button */}
              {aiSuggestions.length > 0 && (
                <div className="flex items-center justify-between px-5 py-3.5 border-t border-violet-200/40 dark:border-violet-800/30 bg-violet-50/30 dark:bg-violet-950/10">
                  <span className="text-xs text-muted-foreground">
                    已选 {aiSelected.size} / {aiSuggestions.length} 个前缀
                  </span>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowAiDiscover(false)}
                      className="h-7 text-xs"
                    >
                      关闭
                    </Button>
                    <Button
                      size="sm"
                      onClick={importSelected}
                      disabled={aiImporting || aiSelected.size === 0}
                      className="h-7 text-xs bg-violet-600 hover:bg-violet-700 text-white gap-1"
                    >
                      {aiImporting
                        ? <><RiLoader4Line className="w-3 h-3 animate-spin" />导入中…</>
                        : <><RiCheckLine className="w-3 h-3" />导入 {aiSelected.size} 个</>}
                    </Button>
                  </div>
                </div>
              )}

              {/* Empty state */}
              {!aiDiscovering && aiSuggestions.length === 0 && !aiLog && (
                <div className="py-12 text-center text-sm text-muted-foreground">
                  <RiRobot2Line className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  点击「开始发现」，AI 将分析最新趋势并推荐高价值前缀
                </div>
              )}
            </div>
          )}

          {/* Category stat pills */}
          {categories.length > 0 && (
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setFilterCategory("all")}
                className={cn(
                  "text-xs px-3 py-1 rounded-full border transition-colors",
                  filterCategory === "all"
                    ? "bg-foreground text-background border-transparent"
                    : "bg-muted/50 hover:bg-muted border-border"
                )}
              >
                全部 ({total})
              </button>
              {categories.map(c => (
                <button
                  key={c.category}
                  onClick={() => setFilterCategory(c.category)}
                  className={cn(
                    "text-xs px-3 py-1 rounded-full border transition-colors",
                    filterCategory === c.category
                      ? "bg-foreground text-background border-transparent"
                      : "bg-muted/50 hover:bg-muted border-border",
                    CATEGORY_COLORS[c.category] && filterCategory !== c.category && CATEGORY_COLORS[c.category]
                  )}
                >
                  {CATEGORIES.find(x => x.value === c.category)?.label ?? c.category} ({c.cnt})
                </button>
              ))}
            </div>
          )}

          {/* Add prefix form */}
          {showAddForm && (
            <div className="rounded-xl border border-orange-200 dark:border-orange-800/50 bg-orange-50/50 dark:bg-orange-950/10 p-5">
              <h3 className="font-semibold text-sm mb-4 flex items-center gap-2">
                <RiAddLine className="w-4 h-4 text-orange-600" />
                新增热门前缀
              </h3>
              <PrefixForm
                form={addForm}
                onChange={setAddForm}
                onSave={handleAdd}
                onCancel={() => setShowAddForm(false)}
                saving={addSaving}
                isAdd
              />
            </div>
          )}

          {/* Search */}
          <div className="relative">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              className="pl-9"
              placeholder="搜索前缀…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          {/* Table */}
          {loading ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
              <RiLoader4Line className="w-5 h-5 animate-spin" />
              <span>加载中…</span>
            </div>
          ) : prefixes.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground">
              <RiFireLine className="w-10 h-10 mx-auto mb-3 opacity-20" />
              <p className="font-medium">暂无热门前缀</p>
              <p className="text-sm mt-1">点击「导入内置列表」快速添加 100+ 个预设前缀</p>
            </div>
          ) : (
            <div className="rounded-xl border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40">
                    <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide w-32">前缀</th>
                    <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide w-28">分类</th>
                    <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide w-20">权重</th>
                    <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide">备注 / 参考成交</th>
                    <th className="text-center px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide w-20">30天</th>
                    <th className="text-center px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide w-20">启用</th>
                    <th className="text-right px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wide w-28">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {prefixes.map((p, idx) => (
                    editingId === p.id ? (
                      <tr key={p.id} className="border-b border-border bg-muted/20">
                        <td colSpan={7} className="px-4 py-4">
                          <PrefixForm
                            form={editForm}
                            onChange={setEditForm}
                            onSave={() => handleSaveEdit(p.id)}
                            onCancel={() => setEditingId(null)}
                            saving={savingId === p.id}
                          />
                        </td>
                      </tr>
                    ) : (
                      <tr
                        key={p.id}
                        className={cn(
                          "border-b border-border transition-colors hover:bg-muted/20",
                          idx % 2 === 0 ? "" : "bg-muted/10",
                          !p.enabled && "opacity-50",
                        )}
                      >
                        <td className="px-4 py-3">
                          <span className="font-mono font-bold text-foreground">{p.prefix}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={cn(
                            "text-xs px-2 py-0.5 rounded-full font-medium",
                            CATEGORY_COLORS[p.category] ?? CATEGORY_COLORS.general
                          )}>
                            {CATEGORIES.find(c => c.value === p.category)?.label?.replace(/^[^\s]+ /, "") ?? p.category}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={cn("font-bold tabular-nums", WEIGHT_COLOR(p.weight))}>
                            {p.weight}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-xs">
                          {p.notes && (
                            <p className="text-xs text-muted-foreground truncate">{p.notes}</p>
                          )}
                          {p.sale_examples && (
                            <p className="text-xs text-emerald-600 dark:text-emerald-400 truncate font-medium mt-0.5">
                              💰 {p.sale_examples}
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className={cn(
                            "text-xs font-bold tabular-nums",
                            parseInt(p.recent_hits ?? "0") > 0 ? "text-orange-600" : "text-muted-foreground"
                          )}>
                            {p.recent_hits ?? 0}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <button
                            onClick={() => handleToggleEnabled(p)}
                            className="transition-colors"
                            title={p.enabled ? "点击禁用" : "点击启用"}
                          >
                            {p.enabled
                              ? <RiToggleFill className="w-5 h-5 text-emerald-500" />
                              : <RiToggleLine className="w-5 h-5 text-muted-foreground" />
                            }
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              size="icon" variant="ghost"
                              className="h-7 w-7 text-muted-foreground hover:text-foreground"
                              onClick={() => startEdit(p)}
                              title="编辑"
                            >
                              <RiEditLine className="w-3.5 h-3.5" />
                            </Button>
                            <Button
                              size="icon" variant="ghost"
                              className="h-7 w-7 text-muted-foreground hover:text-red-500"
                              onClick={() => handleDelete(p.id, p.prefix)}
                              disabled={deletingId === p.id}
                              title="删除"
                            >
                              {deletingId === p.id
                                ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                                : <RiDeleteBinLine className="w-3.5 h-3.5" />
                              }
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Info note */}
          <div className="rounded-lg bg-muted/30 border border-border px-4 py-3 text-xs text-muted-foreground space-y-1">
            <p><strong>告警逻辑：</strong>当用户查询某域名并确认为「未注册」状态时，若其 SLD（点前部分）与任意启用前缀精确匹配或以该前缀开头（前缀长度≥3），则触发管理员邮件告警。</p>
            <p><strong>权重说明：</strong>权重影响分数加成和优先级，满分 30。热门前缀精确匹配加 weight 分；前缀匹配（contains）加 weight×0.6 分。</p>
            <p><strong>30天命中：</strong>最近 30 天内被用户查询到的次数（仅统计域名类查询）。</p>
          </div>
        </div>
      </AdminLayout>
    </>
  );
}

function PrefixForm({
  form, onChange, onSave, onCancel, saving, isAdd,
}: {
  form: FormState;
  onChange: (f: FormState) => void;
  onSave: () => void;
  onCancel: () => void;
  saving?: boolean;
  isAdd?: boolean;
}) {
  const set = (k: keyof FormState) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) =>
    onChange({ ...form, [k]: e.target.value });
  const setB = (k: keyof FormState) => (v: boolean) =>
    onChange({ ...form, [k]: v });

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
      {/* Prefix */}
      {isAdd && (
        <div>
          <Label className="text-xs font-medium mb-1.5 block">前缀 <span className="text-red-500">*</span></Label>
          <Input
            value={form.prefix}
            onChange={set("prefix")}
            placeholder="agent"
            className="font-mono lowercase"
          />
        </div>
      )}

      {/* Category */}
      <div>
        <Label className="text-xs font-medium mb-1.5 block">分类</Label>
        <select
          value={form.category}
          onChange={set("category")}
          className="w-full h-9 px-3 rounded-md border border-input bg-background text-sm"
        >
          {CATEGORIES.filter(c => c.value !== "all").map(c => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
      </div>

      {/* Weight */}
      <div>
        <Label className="text-xs font-medium mb-1.5 block">权重 (1–30)</Label>
        <Input
          type="number" min={1} max={30}
          value={form.weight}
          onChange={set("weight")}
        />
      </div>

      {/* Source */}
      <div>
        <Label className="text-xs font-medium mb-1.5 block">来源</Label>
        <Input value={form.source} onChange={set("source")} placeholder="manual" />
      </div>

      {/* Sale examples */}
      <div className="sm:col-span-2">
        <Label className="text-xs font-medium mb-1.5 block">参考成交（可选）</Label>
        <Input
          value={form.sale_examples}
          onChange={set("sale_examples")}
          placeholder="ai.com ~$1.5M"
        />
      </div>

      {/* Notes */}
      <div className="sm:col-span-2 lg:col-span-3">
        <Label className="text-xs font-medium mb-1.5 block">备注</Label>
        <Input
          value={form.notes}
          onChange={set("notes")}
          placeholder="AI agent 趋势词，2024-2025 热门"
        />
      </div>

      {/* Actions */}
      <div className="sm:col-span-2 lg:col-span-3 flex gap-2">
        <Button
          size="sm"
          onClick={onSave}
          disabled={saving}
          className="gap-1.5 bg-orange-600 hover:bg-orange-700 text-white"
        >
          {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiSaveLine className="w-3.5 h-3.5" />}
          {isAdd ? "添加" : "保存"}
        </Button>
        <Button size="sm" variant="outline" onClick={onCancel} className="gap-1.5">
          <RiCloseLine className="w-3.5 h-3.5" />
          取消
        </Button>
      </div>
    </div>
  );
}
