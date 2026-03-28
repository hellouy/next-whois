import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TextArea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  RiAddLine, RiEditLine, RiDeleteBinLine, RiLoader4Line, RiRefreshLine,
  RiAddCircleLine, RiStarLine, RiFlashlightLine, RiBugLine, RiToolsLine,
  RiDownloadLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { VERSION } from "@/lib/env";

type ChangeType = "new" | "feature" | "improve" | "fix";

type Entry = {
  id: string; entry_date: string; type: ChangeType;
  zh: string; en: string; version: string | null; created_at: string;
};

const TYPE_OPTIONS: { value: ChangeType; label: string; icon: typeof RiAddCircleLine; color: string }[] = [
  { value: "new",     label: "新增",  icon: RiAddCircleLine,  color: "text-emerald-500" },
  { value: "feature", label: "功能",  icon: RiStarLine,       color: "text-blue-500" },
  { value: "improve", label: "优化",  icon: RiFlashlightLine, color: "text-amber-500" },
  { value: "fix",     label: "修复",  icon: RiBugLine,        color: "text-red-500" },
];

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function groupByMonth(entries: Entry[]): { monthKey: string; monthLabel: string; days: { date: string; label: string; items: Entry[] }[] }[] {
  const months: Map<string, Map<string, Entry[]>> = new Map();
  for (const e of entries) {
    const [y, m, d] = e.entry_date.split("-");
    const mk = `${y}-${m}`;
    const dk = e.entry_date;
    if (!months.has(mk)) months.set(mk, new Map());
    const days = months.get(mk)!;
    if (!days.has(dk)) days.set(dk, []);
    days.get(dk)!.push(e);
  }
  return Array.from(months.entries()).map(([mk, days]) => {
    const [y, m] = mk.split("-");
    return {
      monthKey: mk,
      monthLabel: `${y}年${parseInt(m)}月`,
      days: Array.from(days.entries()).map(([dk, items]) => {
        const day = parseInt(dk.split("-")[2]);
        return { date: dk, label: `${parseInt(m)}月${day}日`, items };
      }).sort((a, b) => b.date.localeCompare(a.date)),
    };
  }).sort((a, b) => b.monthKey.localeCompare(a.monthKey));
}

const EMPTY_FORM = { entry_date: todayStr(), type: "new" as ChangeType, zh: "", en: "", version: VERSION };

export default function AdminChangelogPage() {
  const [entries, setEntries] = React.useState<Entry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [quickType, setQuickType] = React.useState<ChangeType>("new");
  const [quickZh, setQuickZh] = React.useState("");
  const [quickEn, setQuickEn] = React.useState("");
  const [quickDate, setQuickDate] = React.useState(todayStr());
  const [quickAdding, setQuickAdding] = React.useState(false);
  const [editing, setEditing] = React.useState<Entry | null>(null);
  const [form, setForm] = React.useState(EMPTY_FORM);
  const [saving, setSaving] = React.useState(false);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const [syncing, setSyncing] = React.useState(false);
  const zhInputRef = React.useRef<HTMLInputElement>(null);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/changelog");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setEntries(data.entries);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);

  // Quick-add: minimal friction — just type + date + text, press Enter or button
  async function handleQuickAdd(e?: React.FormEvent) {
    e?.preventDefault();
    if (!quickZh.trim()) { zhInputRef.current?.focus(); return; }
    setQuickAdding(true);
    try {
      const res = await fetch("/api/admin/changelog", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entry_date: quickDate,
          type: quickType,
          zh: quickZh.trim(),
          en: quickEn.trim(),
          version: VERSION,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success("已添加");
      setQuickZh("");
      setQuickEn("");
      setQuickDate(todayStr());
      await load();
      zhInputRef.current?.focus();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "添加失败");
    } finally {
      setQuickAdding(false);
    }
  }

  async function handleSave() {
    if (!editing) return;
    if (!form.zh.trim()) return toast.error("内容不能为空");
    setSaving(true);
    try {
      const res = await fetch(`/api/admin/changelog?id=${editing.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entry_date: form.entry_date,
          type: form.type,
          zh: form.zh.trim(),
          en: form.en.trim(),
          version: form.version?.trim() || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success("已保存");
      setEditing(null);
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function handleSync() {
    setSyncing(true);
    try {
      const res = await fetch("/api/admin/changelog-sync", { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      if (data.inserted > 0) {
        toast.success(`已同步 ${data.inserted} 条版本记录（跳过 ${data.skipped} 条已存在）`);
        await load();
      } else {
        toast.info(`所有版本记录已是最新，无需同步`);
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "同步失败");
    } finally {
      setSyncing(false);
    }
  }

  async function handleDelete(id: string, zh: string) {
    if (!confirm(`确认删除：「${zh.slice(0, 30)}」？`)) return;
    setDeleting(id);
    try {
      const res = await fetch(`/api/admin/changelog?id=${id}`, { method: "DELETE" });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error); }
      toast.success("已删除");
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    } finally {
      setDeleting(null);
    }
  }

  const grouped = groupByMonth(entries);

  return (
    <AdminLayout title="更新日志">
      <Head><title>更新记录管理 · 管理</title></Head>
      <div className="space-y-5 p-4 md:p-6 max-w-3xl">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h1 className="text-xl font-bold">更新记录管理</h1>
            <p className="text-sm text-muted-foreground mt-0.5">每次部署后快速添加一条，按月/日自动归档展示</p>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={handleSync} disabled={syncing} title="根据版本历史自动导入缺失条目">
              {syncing
                ? <RiLoader4Line className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                : <RiDownloadLine className="w-3.5 h-3.5 mr-1.5" />}
              同步版本历史
            </Button>
            <Button size="sm" variant="outline" onClick={load} disabled={loading}>
              <RiRefreshLine className={cn("w-3.5 h-3.5 mr-1.5", loading && "animate-spin")} />刷新
            </Button>
          </div>
        </div>

        {/* ── Quick-add form ── */}
        <form onSubmit={handleQuickAdd} className="glass-panel border border-primary/30 rounded-xl p-4 space-y-3 bg-primary/[0.02]">
          <p className="text-xs font-semibold text-primary/80 flex items-center gap-1.5">
            <RiAddLine className="w-3.5 h-3.5" />快速添加今日更新
          </p>
          <div className="flex gap-2 flex-wrap">
            {TYPE_OPTIONS.map(t => (
              <button
                key={t.value}
                type="button"
                onClick={() => setQuickType(t.value)}
                className={cn(
                  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border transition-all",
                  quickType === t.value
                    ? "border-primary/40 bg-primary/10 text-primary"
                    : "border-border/60 bg-muted/40 text-muted-foreground hover:border-border",
                )}>
                <t.icon className={cn("w-3 h-3", quickType === t.value ? "text-primary" : t.color)} />
                {t.label}
              </button>
            ))}
            <Input
              type="date"
              className="h-7 text-xs px-2 w-36 ml-auto"
              value={quickDate}
              onChange={e => setQuickDate(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <Input
              ref={zhInputRef}
              className="flex-1 text-sm"
              placeholder="更新内容（中文）……按 Enter 快速添加"
              value={quickZh}
              onChange={e => setQuickZh(e.target.value)}
              disabled={quickAdding}
              autoFocus
            />
            <Button type="submit" size="sm" disabled={quickAdding || !quickZh.trim()}>
              {quickAdding
                ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                : <RiAddLine className="w-3.5 h-3.5" />}
            </Button>
          </div>
          <Input
            className="text-sm text-muted-foreground"
            placeholder="English description (optional)"
            value={quickEn}
            onChange={e => setQuickEn(e.target.value)}
            disabled={quickAdding}
          />
        </form>

        {/* ── Grouped entries ── */}
        {loading ? (
          <div className="flex justify-center py-10 text-muted-foreground">
            <RiLoader4Line className="w-5 h-5 animate-spin" />
          </div>
        ) : entries.length === 0 ? (
          <div className="text-center py-10 text-sm text-muted-foreground border border-dashed rounded-xl">
            暂无记录，添加第一条更新吧 ↑
          </div>
        ) : (
          <div className="space-y-5">
            {grouped.map(month => (
              <div key={month.monthKey}>
                <div className="flex items-center gap-2 mb-3">
                  <RiToolsLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                  <h2 className="text-sm font-bold">{month.monthLabel}</h2>
                  <div className="flex-1 h-px bg-border/40" />
                  <span className="text-[10px] text-muted-foreground">
                    {month.days.reduce((n, d) => n + d.items.length, 0)} 条
                  </span>
                </div>
                <div className="space-y-3 pl-5 border-l border-border/40">
                  {month.days.map(day => (
                    <div key={day.date}>
                      <p className="text-[11px] font-semibold text-muted-foreground mb-1.5">{day.label}</p>
                      <div className="space-y-1.5">
                        {day.items.map(entry => {
                          const tc = TYPE_OPTIONS.find(t => t.value === entry.type) ?? TYPE_OPTIONS[0];
                          return (
                            <div key={entry.id} className="flex items-start gap-2.5 group">
                              <tc.icon className={cn("w-3.5 h-3.5 shrink-0 mt-0.5", tc.color)} />
                              <div className="flex-1 min-w-0">
                                <p className="text-xs text-foreground/80 leading-snug">{entry.zh}</p>
                                {entry.en && <p className="text-[10px] text-muted-foreground mt-0.5 leading-snug">{entry.en}</p>}
                              </div>
                              <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                                {entry.version && (
                                  <span className="text-[9px] font-mono text-muted-foreground bg-muted/60 px-1.5 py-0.5 rounded">
                                    v{entry.version}
                                  </span>
                                )}
                                <button
                                  onClick={() => {
                                    setEditing(entry);
                                    setForm({
                                      entry_date: entry.entry_date,
                                      type: entry.type,
                                      zh: entry.zh,
                                      en: entry.en,
                                      version: entry.version ?? "",
                                    });
                                  }}
                                  className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                                  <RiEditLine className="w-3 h-3" />
                                </button>
                                <button
                                  onClick={() => handleDelete(entry.id, entry.zh)}
                                  disabled={deleting === entry.id}
                                  className="p-1 rounded hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors">
                                  {deleting === entry.id
                                    ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                                    : <RiDeleteBinLine className="w-3 h-3" />}
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Edit dialog */}
      {editing && (
        <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>编辑更新记录</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="flex gap-3">
                <div className="flex-1">
                  <Label className="text-xs font-semibold">日期</Label>
                  <Input type="date" className="mt-1.5" value={form.entry_date}
                    onChange={e => setForm(f => ({ ...f, entry_date: e.target.value }))} />
                </div>
                <div>
                  <Label className="text-xs font-semibold">类型</Label>
                  <div className="flex gap-1.5 mt-1.5">
                    {TYPE_OPTIONS.map(t => (
                      <button key={t.value} type="button"
                        onClick={() => setForm(f => ({ ...f, type: t.value }))}
                        className={cn(
                          "px-2 py-1.5 rounded-lg text-xs font-semibold border transition-all",
                          form.type === t.value ? "border-primary/40 bg-primary/10 text-primary" : "border-border/60 bg-muted/40 text-muted-foreground",
                        )}>
                        {t.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div>
                <Label className="text-xs font-semibold">内容（中文）</Label>
                <TextArea className="mt-1.5 text-sm" rows={3} value={form.zh}
                  onChange={e => setForm(f => ({ ...f, zh: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs font-semibold">内容（英文，可选）</Label>
                <TextArea className="mt-1.5 text-sm" rows={2} value={form.en}
                  onChange={e => setForm(f => ({ ...f, en: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs font-semibold">版本号（可选）</Label>
                <Input className="mt-1.5" placeholder="2.0" value={form.version}
                  onChange={e => setForm(f => ({ ...f, version: e.target.value }))} />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setEditing(null)} disabled={saving}>取消</Button>
              <Button onClick={handleSave} disabled={saving}>
                {saving && <RiLoader4Line className="w-4 h-4 animate-spin mr-1.5" />}
                保存修改
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </AdminLayout>
  );
}
