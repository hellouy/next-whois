import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TextArea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  RiEditLine, RiDeleteBinLine, RiLoader4Line, RiSearchLine, RiRefreshLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { LIFECYCLE_TABLE } from "@/lib/lifecycle";
import { cn } from "@/lib/utils";

const TLD_TABS = [
  { href: "/admin/tld-lifecycle",          label: "生命周期" },
  { href: "/admin/tld-rules",              label: "TLD 规则" },
  { href: "/admin/tld-fallback",           label: "查询兜底" },
  { href: "/admin/tld-lifecycle-feedback", label: "纠错反馈" },
];

type DbOverride = {
  id: string; tld: string;
  grace: number; redemption: number; pending_delete: number;
  registry: string | null; notes: string | null;
};

type TldRow = {
  tld: string;
  grace: number;
  redemption: number;
  pendingDelete: number;
  registry: string | null;
  notes: string | null;
  modified: boolean;
  dbId: string | null;
};

export default function AdminTldLifecyclePage() {
  const [overrides, setOverrides] = React.useState<DbOverride[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [search, setSearch] = React.useState("");
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editingRow, setEditingRow] = React.useState<TldRow | null>(null);
  const [form, setForm] = React.useState({ grace: "0", redemption: "0", pending_delete: "0", registry: "", notes: "" });
  const [saving, setSaving] = React.useState(false);
  const [resetting, setResetting] = React.useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/tld-lifecycle");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "加载失败");
      setOverrides(data.overrides ?? []);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);

  const allTlds: TldRow[] = React.useMemo(() => {
    const map: Record<string, DbOverride> = {};
    for (const ov of overrides) map[ov.tld] = ov;

    const result: TldRow[] = Object.entries(LIFECYCLE_TABLE).map(([tld, entry]) => {
      const ov = map[tld];
      return {
        tld,
        grace:       ov ? ov.grace         : entry.grace,
        redemption:  ov ? ov.redemption     : entry.redemption,
        pendingDelete: ov ? ov.pending_delete : entry.pendingDelete,
        registry:    ov ? (ov.registry ?? entry.registry ?? null) : (entry.registry ?? null),
        notes:       ov?.notes ?? null,
        modified:    !!ov,
        dbId:        ov?.id ?? null,
      };
    });

    for (const ov of overrides) {
      if (!LIFECYCLE_TABLE[ov.tld]) {
        result.push({
          tld: ov.tld,
          grace: ov.grace,
          redemption: ov.redemption,
          pendingDelete: ov.pending_delete,
          registry: ov.registry,
          notes: ov.notes,
          modified: true,
          dbId: ov.id,
        });
      }
    }

    return result.sort((a, b) => a.tld.localeCompare(b.tld));
  }, [overrides]);

  const filtered = React.useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return allTlds;
    return allTlds.filter(r =>
      r.tld.startsWith(q) ||
      r.tld.includes(q) ||
      (r.registry ?? "").toLowerCase().includes(q)
    );
  }, [allTlds, search]);

  function openEdit(row: TldRow) {
    setEditingRow(row);
    setForm({
      grace:        String(row.grace),
      redemption:   String(row.redemption),
      pending_delete: String(row.pendingDelete),
      registry:     row.registry ?? "",
      notes:        row.notes ?? "",
    });
    setDialogOpen(true);
  }

  async function handleSave() {
    if (!editingRow) return;
    setSaving(true);
    try {
      const body = {
        tld:          editingRow.tld,
        grace:        Number(form.grace) || 0,
        redemption:   Number(form.redemption) || 0,
        pending_delete: Number(form.pending_delete) || 0,
        registry:     form.registry || null,
        notes:        form.notes || null,
      };
      const res = editingRow.dbId
        ? await fetch(`/api/admin/tld-lifecycle?id=${editingRow.dbId}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          })
        : await fetch("/api/admin/tld-lifecycle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
          });
      if (!res.ok) {
        const d = await res.json();
        throw new Error(d.error || "保存失败");
      }
      toast.success(`.${editingRow.tld} 已保存`);
      setDialogOpen(false);
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally {
      setSaving(false);
    }
  }

  async function handleReset(row: TldRow) {
    if (!row.dbId) return;
    if (!confirm(`确认将 .${row.tld} 重置为系统内置默认值？`)) return;
    setResetting(row.tld);
    try {
      const res = await fetch(`/api/admin/tld-lifecycle?id=${row.dbId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("重置失败");
      toast.success(`.${row.tld} 已重置为内置默认值`);
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "重置失败");
    } finally {
      setResetting(null);
    }
  }

  const th = "py-2.5 px-3 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wide";
  const td = "py-2.5 px-3 text-sm";

  return (
    <AdminLayout title="TLD 管理">
      <Head><title>TLD 生命周期规则 · 管理</title></Head>
      <div className="space-y-4 p-4 md:p-6">
        <PageTabs tabs={TLD_TABS} />
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h1 className="text-xl font-bold">TLD 生命周期规则</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              点击编辑任意 TLD，保存后立即同步到数据库生效
            </p>
          </div>
          <Button size="sm" variant="outline" onClick={load} disabled={loading}>
            <RiRefreshLine className={cn("w-3.5 h-3.5 mr-1.5", loading && "animate-spin")} />
            刷新
          </Button>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-xs">
            <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              className="pl-9 h-8 text-sm"
              placeholder="搜索 TLD 或注册局..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <p className="text-xs text-muted-foreground shrink-0">
            {search
              ? `${filtered.length} / ${allTlds.length} 个`
              : `共 ${allTlds.length} 个`}
            {overrides.length > 0 && (
              <span className="ml-1.5 text-emerald-600 dark:text-emerald-400 font-medium">
                · 已修正 {overrides.length} 个
              </span>
            )}
          </p>
        </div>

        <div className="border rounded-xl overflow-hidden">
          <div className="overflow-x-auto" style={{ maxHeight: "65vh", overflowY: "auto" }}>
            <table className="w-full">
              <thead className="bg-muted/30 border-b sticky top-0 z-10 backdrop-blur-sm">
                <tr>
                  <th className={th}>TLD</th>
                  <th className={cn(th, "text-center")}>宽限期</th>
                  <th className={cn(th, "text-center")}>赎回期</th>
                  <th className={cn(th, "text-center")}>待删除</th>
                  <th className={th}>注册局</th>
                  <th className={cn(th, "text-right")}>操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="text-center py-10 text-muted-foreground">
                      <RiLoader4Line className="w-5 h-5 animate-spin mx-auto mb-2" />
                      <span className="text-sm">加载中...</span>
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-10 text-muted-foreground text-sm">
                      未找到匹配「{search}」的 TLD
                    </td>
                  </tr>
                ) : filtered.map(row => (
                  <tr
                    key={row.tld}
                    className={cn(
                      "hover:bg-muted/20 transition-colors",
                      row.modified && "bg-emerald-50/40 dark:bg-emerald-950/10"
                    )}
                  >
                    <td className={cn(td, "font-mono font-semibold")}>
                      .{row.tld}
                      {row.modified && (
                        <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 font-semibold align-middle">
                          已修正
                        </span>
                      )}
                    </td>
                    <td className={cn(td, "text-center tabular-nums text-muted-foreground")}>{row.grace}d</td>
                    <td className={cn(td, "text-center tabular-nums text-muted-foreground")}>{row.redemption}d</td>
                    <td className={cn(td, "text-center tabular-nums text-muted-foreground")}>{row.pendingDelete}d</td>
                    <td className={cn(td, "text-xs text-muted-foreground")}>{row.registry ?? "—"}</td>
                    <td className={cn(td, "text-right")}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEdit(row)}
                          title="编辑"
                          className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                        >
                          <RiEditLine className="w-3.5 h-3.5" />
                        </button>
                        {row.modified && (
                          <button
                            onClick={() => handleReset(row)}
                            disabled={resetting === row.tld}
                            title="重置为内置默认值"
                            className="p-1.5 rounded hover:bg-amber-50 dark:hover:bg-amber-950/30 text-muted-foreground hover:text-amber-500 transition-colors"
                          >
                            {resetting === row.tld
                              ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                              : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>修正 .{editingRow?.tld}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label className="text-xs font-semibold">宽限期（天）</Label>
                <Input
                  className="mt-1.5 text-center"
                  type="number" min="0" max="365"
                  value={form.grace}
                  onChange={e => setForm(f => ({ ...f, grace: e.target.value }))}
                />
              </div>
              <div>
                <Label className="text-xs font-semibold">赎回期（天）</Label>
                <Input
                  className="mt-1.5 text-center"
                  type="number" min="0" max="365"
                  value={form.redemption}
                  onChange={e => setForm(f => ({ ...f, redemption: e.target.value }))}
                />
              </div>
              <div>
                <Label className="text-xs font-semibold">待删除（天）</Label>
                <Input
                  className="mt-1.5 text-center"
                  type="number" min="0" max="30"
                  value={form.pending_delete}
                  onChange={e => setForm(f => ({ ...f, pending_delete: e.target.value }))}
                />
              </div>
            </div>
            <div>
              <Label className="text-xs font-semibold">注册局（可选）</Label>
              <Input
                className="mt-1.5"
                placeholder="Verisign / CNNIC / Nominet"
                value={form.registry}
                onChange={e => setForm(f => ({ ...f, registry: e.target.value }))}
              />
            </div>
            <div>
              <Label className="text-xs font-semibold">备注（可选）</Label>
              <TextArea
                className="mt-1.5 text-sm"
                rows={2}
                placeholder="数据来源、修正原因等"
                value={form.notes}
                onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={saving}>
              取消
            </Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <RiLoader4Line className="w-4 h-4 animate-spin mr-1.5" /> : null}
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AdminLayout>
  );
}
