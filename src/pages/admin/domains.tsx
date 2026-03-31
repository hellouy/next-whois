import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TextArea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { LIFECYCLE_TABLE } from "@/lib/lifecycle";
import {
  RiTimeLine, RiServerLine, RiGlobalLine,
  RiEditLine, RiDeleteBinLine, RiLoader4Line, RiRefreshLine, RiSearchLine,
  RiAddLine, RiCloseLine, RiSave3Line, RiCheckboxCircleLine,
  RiExternalLinkLine, RiArrowUpSLine, RiArrowDownSLine,
  RiStopCircleLine, RiInformationLine,
  RiCheckLine, RiDatabase2Line, RiCodeLine, RiFileLine,
  RiDeleteBin7Line, RiRobot2Line,
} from "@remixicon/react";

type MainTab = "lifecycle" | "servers" | "iana";

/* ── Shared Helpers ─────────────────────────────────────────────────────── */
function fmtRel(d: string | null): string {
  if (!d) return "—";
  const diff = Date.now() - new Date(d).getTime();
  const m = Math.floor(diff / 60000), h = Math.floor(diff / 3600000), dy = Math.floor(diff / 86400000);
  if (m < 1) return "刚刚";
  if (m < 60) return `${m}分前`;
  if (h < 24) return `${h}时前`;
  if (dy < 7) return `${dy}天前`;
  return new Date(d).toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}
function fmtDate(s: string | null) {
  if (!s) return "—";
  const dt = new Date(s);
  if (isNaN(dt.getTime())) return s;
  return dt.toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}

/* ═══════════════════════════════════════════════════════════════════════════
   TAB 1: 生命周期
══════════════════════════════════════════════════════════════════════════════ */
type DbOverride = {
  id: string; tld: string;
  grace: number; redemption: number; pending_delete: number;
  registry: string | null; notes: string | null;
};
type TldRow = {
  tld: string; grace: number; redemption: number; pendingDelete: number;
  registry: string | null; notes: string | null; modified: boolean; dbId: string | null;
};

type FeedbackItem = {
  id: string; tld: string; status: "pending" | "approved" | "rejected";
  current_grace: number | null; current_redemption: number | null; current_pending_delete: number | null;
  suggested_grace: number; suggested_redemption: number; suggested_pending_delete: number;
  notes: string | null; source_url: string | null; submitter_email: string | null;
  reviewed_by: string | null; reviewed_at: string | null; created_at: string;
};

function DayBadge({ label, current, suggested }: { label: string; current: number | null; suggested: number }) {
  const changed = current !== null && current !== suggested;
  return (
    <div className="flex flex-col items-center gap-0.5 min-w-[52px]">
      <span className="text-[9px] font-bold uppercase tracking-wide text-muted-foreground/60">{label}</span>
      {current !== null && changed && (
        <span className="text-[10px] line-through text-muted-foreground/40 font-mono">{current}d</span>
      )}
      <span className={cn("text-[13px] font-bold font-mono", changed ? "text-amber-600 dark:text-amber-400" : "text-foreground")}>
        {suggested}d
      </span>
    </div>
  );
}

function LifecycleTab() {
  const [overrides, setOverrides] = React.useState<DbOverride[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [search, setSearch] = React.useState("");
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editingRow, setEditingRow] = React.useState<TldRow | null>(null);
  const [form, setForm] = React.useState({ grace: "0", redemption: "0", pending_delete: "0", registry: "", notes: "" });
  const [saving, setSaving] = React.useState(false);
  const [resetting, setResetting] = React.useState<string | null>(null);

  const [fbItems, setFbItems] = React.useState<FeedbackItem[]>([]);
  const [fbLoading, setFbLoading] = React.useState(true);
  const [fbFilter, setFbFilter] = React.useState<"pending" | "approved" | "rejected" | "all">("pending");
  const [fbActing, setFbActing] = React.useState<string | null>(null);

  async function loadFb(status = fbFilter) {
    setFbLoading(true);
    try {
      const res = await fetch(`/api/admin/tld-lifecycle-feedback?status=${status}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "加载失败");
      setFbItems(data.items ?? []);
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "加载失败"); }
    finally { setFbLoading(false); }
  }
  React.useEffect(() => { loadFb(fbFilter); }, [fbFilter]);

  async function handleFbAction(id: string, action: "approve" | "reject") {
    setFbActing(id + action);
    try {
      const res = await fetch(`/api/admin/tld-lifecycle-feedback?id=${id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "操作失败");
      toast.success(action === "approve" ? "已采纳并写入 TLD 规则" : "已拒绝");
      loadFb(fbFilter); load();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "操作失败"); }
    finally { setFbActing(null); }
  }

  async function handleFbDelete(id: string) {
    if (!confirm("确认删除该条反馈记录？")) return;
    setFbActing(id + "delete");
    try {
      const res = await fetch(`/api/admin/tld-lifecycle-feedback?id=${id}`, { method: "DELETE" });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error || "删除失败"); }
      toast.success("已删除");
      loadFb(fbFilter);
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "删除失败"); }
    finally { setFbActing(null); }
  }

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/tld-lifecycle");
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "加载失败");
      setOverrides(data.overrides ?? []);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally { setLoading(false); }
  }
  React.useEffect(() => { load(); }, []);

  const allTlds: TldRow[] = React.useMemo(() => {
    const map: Record<string, DbOverride> = {};
    for (const ov of overrides) map[ov.tld] = ov;
    const result: TldRow[] = Object.entries(LIFECYCLE_TABLE).map(([tld, entry]) => {
      const ov = map[tld];
      return {
        tld, grace: ov ? ov.grace : entry.grace,
        redemption: ov ? ov.redemption : entry.redemption,
        pendingDelete: ov ? ov.pending_delete : entry.pendingDelete,
        registry: ov ? (ov.registry ?? entry.registry ?? null) : (entry.registry ?? null),
        notes: ov?.notes ?? null, modified: !!ov, dbId: ov?.id ?? null,
      };
    });
    for (const ov of overrides) {
      if (!LIFECYCLE_TABLE[ov.tld]) {
        result.push({ tld: ov.tld, grace: ov.grace, redemption: ov.redemption, pendingDelete: ov.pending_delete,
          registry: ov.registry, notes: ov.notes, modified: true, dbId: ov.id });
      }
    }
    return result.sort((a, b) => a.tld.localeCompare(b.tld));
  }, [overrides]);

  const filtered = React.useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return allTlds;
    return allTlds.filter(r => r.tld.startsWith(q) || r.tld.includes(q) ||
      (r.registry ?? "").toLowerCase().includes(q) || (r.notes ?? "").toLowerCase().includes(q));
  }, [allTlds, search]);

  function openEdit(row: TldRow) {
    setEditingRow(row);
    setForm({ grace: String(row.grace), redemption: String(row.redemption),
      pending_delete: String(row.pendingDelete), registry: row.registry ?? "", notes: row.notes ?? "" });
    setDialogOpen(true);
  }

  async function handleSave() {
    if (!editingRow) return;
    setSaving(true);
    try {
      const body = { tld: editingRow.tld, grace: Number(form.grace) || 0,
        redemption: Number(form.redemption) || 0, pending_delete: Number(form.pending_delete) || 0,
        registry: form.registry || null, notes: form.notes || null };
      const res = editingRow.dbId
        ? await fetch(`/api/admin/tld-lifecycle?id=${editingRow.dbId}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
        : await fetch("/api/admin/tld-lifecycle", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error || "保存失败"); }
      toast.success(`.${editingRow.tld} 已保存`);
      setDialogOpen(false);
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "保存失败");
    } finally { setSaving(false); }
  }

  async function handleReset(row: TldRow) {
    if (!row.dbId) return;
    if (!confirm(`确认将 .${row.tld} 重置为系统内置默认值？`)) return;
    setResetting(row.tld);
    try {
      const res = await fetch(`/api/admin/tld-lifecycle?id=${row.dbId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("重置失败");
      toast.success(`.${row.tld} 已重置`);
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "重置失败");
    } finally { setResetting(null); }
  }

  const th = "py-2.5 px-3 text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wide";
  const td = "py-2.5 px-3 text-sm";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <p className="text-xs text-muted-foreground">
            点击编辑任意 TLD，保存后立即同步到数据库生效
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={load} disabled={loading} className="h-8 rounded-xl">
          <RiRefreshLine className={cn("w-3.5 h-3.5 mr-1.5", loading && "animate-spin")} />刷新
        </Button>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input className="pl-9 h-8 text-sm" placeholder="搜索 TLD 或注册局..." value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <p className="text-xs text-muted-foreground shrink-0">
          {search ? `${filtered.length} / ${allTlds.length} 个` : `共 ${allTlds.length} 个`}
          {overrides.length > 0 && <span className="ml-1.5 text-emerald-600 dark:text-emerald-400 font-medium">· 已修正 {overrides.length} 个</span>}
        </p>
      </div>

      <div className="border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto" style={{ maxHeight: "60vh", overflowY: "auto" }}>
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
                <tr><td colSpan={6} className="text-center py-10 text-muted-foreground">
                  <RiLoader4Line className="w-5 h-5 animate-spin mx-auto mb-2" />
                  <span className="text-sm">加载中...</span>
                </td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={6} className="text-center py-10 text-muted-foreground text-sm">未找到匹配的 TLD</td></tr>
              ) : filtered.map(row => (
                <tr key={row.tld} className={cn("hover:bg-muted/20 transition-colors", row.modified && "bg-emerald-50/40 dark:bg-emerald-950/10")}>
                  <td className={cn(td, "font-mono font-semibold")}>
                    .{row.tld}
                    {row.modified && <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 font-semibold align-middle">已修正</span>}
                  </td>
                  <td className={cn(td, "text-center tabular-nums text-muted-foreground")}>{row.grace}d</td>
                  <td className={cn(td, "text-center tabular-nums text-muted-foreground")}>{row.redemption}d</td>
                  <td className={cn(td, "text-center tabular-nums text-muted-foreground")}>{row.pendingDelete}d</td>
                  <td className={cn(td, "text-xs text-muted-foreground")}>{row.registry ?? "—"}</td>
                  <td className={cn(td, "text-right")}>
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={() => openEdit(row)} title="编辑" className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                        <RiEditLine className="w-3.5 h-3.5" />
                      </button>
                      {row.modified && (
                        <button onClick={() => handleReset(row)} disabled={resetting === row.tld} title="重置为内置默认值"
                          className="p-1.5 rounded hover:bg-amber-50 dark:hover:bg-amber-950/30 text-muted-foreground hover:text-amber-500 transition-colors">
                          {resetting === row.tld ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
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

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>修正 .{editingRow?.tld}</DialogTitle></DialogHeader>
          <div className="space-y-4 py-2">
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label className="text-xs font-semibold">宽限期（天）</Label>
                <Input className="mt-1.5 text-center" type="number" min="0" max="365" value={form.grace}
                  onChange={e => setForm(f => ({ ...f, grace: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs font-semibold">赎回期（天）</Label>
                <Input className="mt-1.5 text-center" type="number" min="0" max="365" value={form.redemption}
                  onChange={e => setForm(f => ({ ...f, redemption: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs font-semibold">待删除（天）</Label>
                <Input className="mt-1.5 text-center" type="number" min="0" max="30" value={form.pending_delete}
                  onChange={e => setForm(f => ({ ...f, pending_delete: e.target.value }))} />
              </div>
            </div>
            <div>
              <Label className="text-xs font-semibold">注册局（可选）</Label>
              <Input className="mt-1.5" placeholder="Verisign / CNNIC / Nominet" value={form.registry}
                onChange={e => setForm(f => ({ ...f, registry: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs font-semibold">备注（可选）</Label>
              <TextArea className="mt-1.5 text-sm" rows={2} placeholder="数据来源、修正原因等" value={form.notes}
                onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={saving}>取消</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <RiLoader4Line className="w-4 h-4 animate-spin mr-1.5" /> : null}保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── 用户纠错反馈 ── */}
      <div className="mt-8 space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold flex items-center gap-2">
              <RiTimeLine className="w-4 h-4 text-amber-500" />
              用户纠错反馈
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">用户提交的宽限期 / 赎回期 / 待删除期纠正建议，采纳后立即写入覆盖规则</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => loadFb(fbFilter)} disabled={fbLoading}>
            <RiRefreshLine className={cn("w-4 h-4 mr-1.5", fbLoading && "animate-spin")} />刷新
          </Button>
        </div>

        <div className="flex gap-2 flex-wrap">
          {(["pending", "approved", "rejected", "all"] as const).map(s => (
            <button key={s} onClick={() => setFbFilter(s)}
              className={cn(
                "px-3 py-1 rounded-full text-xs font-semibold border transition-colors",
                fbFilter === s ? "bg-foreground text-background border-foreground" : "bg-muted/30 border-border/50 text-muted-foreground hover:bg-muted/60",
              )}>
              {{ pending: "待审核", approved: "已采纳", rejected: "已拒绝", all: "全部" }[s]}
              {s === "pending" && fbFilter === "pending" && fbItems.length > 0 && (
                <span className="ml-1 bg-amber-500 text-white rounded-full text-[9px] px-1.5 font-bold">{fbItems.length}</span>
              )}
            </button>
          ))}
        </div>

        {fbLoading ? (
          <div className="flex items-center justify-center py-10">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : fbItems.length === 0 ? (
          <div className="text-center py-10 text-muted-foreground text-sm">
            {fbFilter === "pending" ? "暂无待审核的纠错反馈" : "无记录"}
          </div>
        ) : (
          <div className="space-y-3">
            {fbItems.map(item => (
              <div key={item.id} className={cn(
                "rounded-xl border bg-card p-4 space-y-3",
                item.status === "pending" && "border-amber-400/30",
                item.status === "approved" && "border-emerald-400/30 bg-emerald-500/5",
                item.status === "rejected" && "border-border/40 opacity-60",
              )}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-lg font-bold font-mono">.{item.tld}</span>
                    <span className={cn(
                      "px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide border",
                      item.status === "pending" && "bg-amber-500/10 border-amber-400/30 text-amber-600 dark:text-amber-400",
                      item.status === "approved" && "bg-emerald-500/10 border-emerald-400/30 text-emerald-600 dark:text-emerald-400",
                      item.status === "rejected" && "bg-muted/40 border-border/30 text-muted-foreground",
                    )}>
                      {{ pending: "待审核", approved: "已采纳", rejected: "已拒绝" }[item.status]}
                    </span>
                  </div>
                  <span className="text-[10px] text-muted-foreground/60 font-mono shrink-0">
                    {new Date(item.created_at).toLocaleString("zh-CN", { dateStyle: "short", timeStyle: "short" })}
                  </span>
                </div>

                <div className="flex gap-6 px-1">
                  <DayBadge label="宽限期" current={item.current_grace} suggested={item.suggested_grace} />
                  <DayBadge label="赎回期" current={item.current_redemption} suggested={item.suggested_redemption} />
                  <DayBadge label="待删除" current={item.current_pending_delete} suggested={item.suggested_pending_delete} />
                </div>

                {(item.notes || item.source_url || item.submitter_email) && (
                  <div className="space-y-1.5 rounded-lg bg-muted/30 px-3 py-2.5 text-xs text-muted-foreground">
                    {item.notes && <p><span className="font-semibold text-foreground/70">备注：</span>{item.notes}</p>}
                    {item.source_url && (
                      <p className="flex items-center gap-1">
                        <span className="font-semibold text-foreground/70">来源：</span>
                        <a href={item.source_url} target="_blank" rel="noopener noreferrer"
                          className="text-sky-500 hover:underline flex items-center gap-0.5 break-all">
                          {item.source_url.length > 60 ? item.source_url.slice(0, 60) + "…" : item.source_url}
                          <RiExternalLinkLine className="w-2.5 h-2.5 shrink-0" />
                        </a>
                      </p>
                    )}
                    {item.submitter_email && <p><span className="font-semibold text-foreground/70">提交者：</span>{item.submitter_email}</p>}
                  </div>
                )}

                {item.reviewed_by && item.status !== "pending" && (
                  <p className="text-[10px] text-muted-foreground/50">
                    由 {item.reviewed_by} {item.status === "approved" ? "采纳" : "拒绝"}于{" "}
                    {new Date(item.reviewed_at!).toLocaleString("zh-CN", { dateStyle: "short", timeStyle: "short" })}
                  </p>
                )}

                {item.status === "pending" ? (
                  <div className="flex items-center gap-2 pt-1">
                    <Button size="sm" className="h-7 text-xs bg-emerald-500 hover:bg-emerald-600 text-white"
                      onClick={() => handleFbAction(item.id, "approve")} disabled={!!fbActing}>
                      {fbActing === item.id + "approve"
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : <RiCheckLine className="w-3.5 h-3.5 mr-1" />}
                      采纳并写入规则
                    </Button>
                    <Button variant="outline" size="sm" className="h-7 text-xs border-red-300/50 text-red-500 hover:bg-red-500/10"
                      onClick={() => handleFbAction(item.id, "reject")} disabled={!!fbActing}>
                      {fbActing === item.id + "reject"
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : <RiCloseLine className="w-3.5 h-3.5 mr-1" />}
                      拒绝
                    </Button>
                    <Button variant="ghost" size="sm" className="h-7 text-xs text-muted-foreground hover:text-red-500 ml-auto"
                      onClick={() => handleFbDelete(item.id)} disabled={!!fbActing}>
                      <RiDeleteBinLine className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                ) : (
                  <div className="flex justify-end">
                    <Button variant="ghost" size="sm" className="h-7 text-xs text-muted-foreground hover:text-red-500"
                      onClick={() => handleFbDelete(item.id)} disabled={!!fbActing}>
                      <RiDeleteBinLine className="w-3.5 h-3.5 mr-1" />删除记录
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   TAB 2: 服务器管理 (Custom Servers + Repair Queue)
══════════════════════════════════════════════════════════════════════════════ */
type Source = "builtin" | "manual" | "iana" | "repair" | "registry" | "cctld";
const SOURCE_META: Record<Source, { label: string; color: string; icon: React.ReactNode; desc: string }> = {
  builtin:  { label: "内置",       color: "text-violet-600 bg-violet-50 dark:bg-violet-950/40 border-violet-200 dark:border-violet-800",   icon: <RiCodeLine className="w-3 h-3" />,     desc: "代码内置，最高优先级" },
  manual:   { label: "手动配置",   color: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800", icon: <RiDatabase2Line className="w-3 h-3" />, desc: "管理员手动添加，可编辑删除" },
  repair:   { label: "AI修复",     color: "text-teal-600 bg-teal-50 dark:bg-teal-950/40 border-teal-200 dark:border-teal-800",             icon: <RiRobot2Line className="w-3 h-3" />,   desc: "AI修复队列自动发现并验证" },
  iana:     { label: "IANA自动",   color: "text-sky-600 bg-sky-50 dark:bg-sky-950/40 border-sky-200 dark:border-sky-800",                 icon: <RiGlobalLine className="w-3 h-3" />,   desc: "查询时从 IANA 动态发现并持久化" },
  registry: { label: "注册局",     color: "text-blue-600 bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-800",             icon: <RiGlobalLine className="w-3 h-3" />,   desc: "从 IANA 注册局信息抓取" },
  cctld:    { label: "ccTLD 文件", color: "text-orange-600 bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-800",   icon: <RiFileLine className="w-3 h-3" />,     desc: "静态文件" },
};

interface ServerRow { tld: string; server: string; rawEntry: unknown; source: Source; }


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

function ServersTab() {
  const [rows, setRows] = React.useState<ServerRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [sourceFilter, setSourceFilter] = React.useState<Source | "all">("all");
  const [showAdd, setShowAdd] = React.useState(false);
  const [addTld, setAddTld] = React.useState("");
  const [addServer, setAddServer] = React.useState("");
  const [adding, setAdding] = React.useState(false);
  const [deletingTld, setDeletingTld] = React.useState<string | null>(null);


  async function loadServers() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/tld-servers");
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "加载失败");
      const builtinSet = new Set<string>(d.builtinTlds ?? []);
      const dbMap: Record<string, { entry: unknown; source: string }> = d.dbServers ?? {};
      const registryMap: Record<string, unknown> = d.registryServers ?? {};
      const allMap: Record<string, unknown> = d.servers ?? {};
      const built: ServerRow[] = Object.entries(allMap).map(([tld, raw]) => {
        let source: Source;
        if (builtinSet.has(tld))      source = "builtin";
        else if (tld in dbMap) {
          const s = dbMap[tld].source;
          source = (s === "iana" || s === "repair") ? s : "manual";
        }
        else if (tld in registryMap)   source = "registry";
        else                           source = "cctld";
        return { tld, server: entryLabel(raw), rawEntry: raw, source };
      });
      built.sort((a, b) => {
        const order: Record<Source, number> = { manual: 0, repair: 1, iana: 2, builtin: 3, registry: 4, cctld: 5 };
        return order[a.source] - order[b.source] || a.tld.localeCompare(b.tld);
      });
      setRows(built);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally { setLoading(false); }
  }

  React.useEffect(() => {
    loadServers();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function addServer_() {
    const tld = addTld.trim().toLowerCase().replace(/^\./, "");
    const server = addServer.trim();
    if (!tld || !server) { toast.error("TLD 和服务器地址都是必填项"); return; }
    setAdding(true);
    try {
      const r = await fetch("/api/admin/tld-servers", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, server }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "添加失败");
      toast.success(d.message ?? "已添加");
      setAddTld(""); setAddServer(""); setShowAdd(false);
      await loadServers();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "操作失败");
    } finally { setAdding(false); }
  }

  async function deleteRow(tld: string) {
    if (!confirm(`确认删除 .${tld} 的自定义服务器？`)) return;
    setDeletingTld(tld);
    try {
      const r = await fetch("/api/admin/tld-servers", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tld }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "删除失败");
      toast.success(d.message ?? "已删除");
      await loadServers();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    } finally { setDeletingTld(null); }
  }

  const counts = rows.reduce((acc, r) => { acc[r.source] = (acc[r.source] ?? 0) + 1; return acc; }, {} as Record<string, number>);
  const filtered = rows.filter(r => {
    if (sourceFilter !== "all" && r.source !== sourceFilter) return false;
    if (search) { const q = search.toLowerCase(); return r.tld.includes(q) || r.server.toLowerCase().includes(q); }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Custom Servers Section */}
      <div className="space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-bold flex items-center gap-1.5"><RiServerLine className="w-4 h-4 text-primary" />自定义 WHOIS 服务器</h2>
            <p className="text-xs text-muted-foreground mt-0.5">优先级：数据库 &gt; 内置 &gt; ccTLD 文件 &gt; 注册局信息，数据库条目可增删</p>
          </div>
          <Button onClick={() => setShowAdd(true)} size="sm" className="h-8 text-xs shrink-0 rounded-xl">
            <RiAddLine className="w-3.5 h-3.5 mr-1" />添加服务器
          </Button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {(["manual", "repair", "iana", "builtin", "cctld", "registry"] as Source[]).map(src => {
            const meta = SOURCE_META[src];
            const count = counts[src] ?? 0;
            return (
              <button key={src} onClick={() => setSourceFilter(sourceFilter === src ? "all" : src)}
                className={cn("rounded-xl border p-3 text-left transition-colors hover:bg-muted/40",
                  sourceFilter === src ? "ring-2 ring-ring" : "border-border bg-muted/20")}>
                <p className="text-xs text-muted-foreground flex items-center gap-1 mb-1">{meta.icon} {meta.label}</p>
                <p className="text-xl font-bold">{count}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{meta.desc}</p>
              </button>
            );
          })}
        </div>

        {showAdd && (
          <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">添加自定义服务器</h3>
              <button onClick={() => setShowAdd(false)} className="text-muted-foreground hover:text-foreground"><RiCloseLine className="w-4 h-4" /></button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">TLD（不带点）</label>
                <Input value={addTld} onChange={e => setAddTld(e.target.value)} placeholder="例：rw, ai, xyz" className="h-8 text-sm font-mono" />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">WHOIS 服务器（TCP 主机名）</label>
                <Input value={addServer} onChange={e => setAddServer(e.target.value)} placeholder="例：whois.nic.rw" className="h-8 text-sm font-mono" />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={() => setShowAdd(false)} className="h-8 text-xs">取消</Button>
              <Button size="sm" onClick={addServer_} disabled={adding} className="h-8 text-xs">
                {adding ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiSave3Line className="w-3.5 h-3.5 mr-1" />}保存
              </Button>
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          {(["all", "manual", "repair", "iana", "builtin", "cctld", "registry"] as const).map(k => {
            const count = k === "all" ? rows.length : (counts[k] ?? 0);
            if (k !== "all" && count === 0) return null;
            return (
              <button key={k} onClick={() => setSourceFilter(k)}
                className={cn("text-xs px-2.5 py-1 rounded-full border transition-colors",
                  sourceFilter === k ? "bg-foreground text-background border-transparent" : "bg-muted/30 border-border text-muted-foreground hover:bg-muted/50")}>
                {k === "all" ? `全部 (${count})` : `${SOURCE_META[k as Source].label} (${count})`}
              </button>
            );
          })}
          <div className="ml-auto flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={loadServers} disabled={loading} className="h-7 text-xs">
              <RiRefreshLine className={cn("w-3 h-3 mr-1", loading && "animate-spin")} />刷新
            </Button>
            <div className="flex items-center gap-1.5 border border-input rounded-lg px-2 h-7 bg-background">
              <RiSearchLine className="w-3 h-3 text-muted-foreground" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="搜索 TLD / 服务器"
                className="text-xs bg-transparent outline-none w-32 text-foreground placeholder:text-muted-foreground" />
            </div>
          </div>
        </div>

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
                  <tr><td colSpan={4} className="px-3 py-8 text-center text-sm text-muted-foreground"><RiLoader4Line className="w-5 h-5 mx-auto mb-2 animate-spin opacity-40" />加载中…</td></tr>
                ) : filtered.length === 0 ? (
                  <tr><td colSpan={4} className="px-3 py-8 text-center text-sm text-muted-foreground">暂无匹配记录</td></tr>
                ) : filtered.map(row => {
                  const meta = SOURCE_META[row.source];
                  return (
                    <tr key={row.tld} className="hover:bg-muted/20 transition-colors">
                      <td className="px-3 py-2.5 font-mono font-semibold">.{row.tld}</td>
                      <td className="px-3 py-2.5 text-xs text-muted-foreground font-mono truncate max-w-xs">{row.server}</td>
                      <td className="px-3 py-2.5">
                        <span className={cn("inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border font-medium", meta.color)}>
                          {meta.icon}{meta.label}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-right">
                        {(row.source === "manual" || row.source === "iana" || row.source === "repair") ? (
                          <button onClick={() => deleteRow(row.tld)} disabled={deletingTld === row.tld}
                            className="text-xs text-destructive hover:text-destructive/80 disabled:opacity-50">
                            {deletingTld === row.tld ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBin7Line className="w-3.5 h-3.5" />}
                          </button>
                        ) : <span className="text-xs text-muted-foreground/40">—</span>}
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


    </div>
  );
}


/* ═══════════════════════════════════════════════════════════════════════════
   TAB 3: IANA 数据
══════════════════════════════════════════════════════════════════════════════ */
interface TldRecord {
  tld: string; tld_type: string | null; status: string | null; manager: string | null;
  registry_url: string | null; whois_server: string | null; country: string | null;
  address: string | null; nameservers: string | null; created_date: string | null;
  changed_date: string | null; iana_url: string | null; probe_result: string | null;
  probe_method: string | null; probe_latency_ms: number | null; scan_error: string | null;
  scraped_at: string | null; done?: number; total?: number; errors?: number;
}
interface DbStats { total: string; cc: string; generic: string; sponsored: string; with_registry: string; with_whois: string; last_scan: string | null; }

const TYPE_META: Record<string, { label: string; color: string }> = {
  "country-code":       { label: "ccTLD",    color: "bg-blue-100 text-blue-700 dark:bg-blue-950/50 dark:text-blue-300 border-blue-200 dark:border-blue-800" },
  "generic":            { label: "gTLD",     color: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800" },
  "generic-restricted": { label: "受限 gTLD", color: "bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200 dark:border-amber-800" },
  "sponsored":          { label: "sTLD",     color: "bg-violet-100 text-violet-700 dark:bg-violet-950/50 dark:text-violet-300 border-violet-200 dark:border-violet-800" },
  "infrastructure":     { label: "基础设施", color: "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300 border-red-200 dark:border-red-800" },
};

function TypeBadge({ type }: { type: string | null }) {
  const t = type || "generic";
  const meta = TYPE_META[t] || { label: t, color: "bg-muted text-muted-foreground border-border" };
  return <span className={cn("inline-block text-[10px] font-medium px-1.5 py-0.5 rounded border", meta.color)}>{meta.label}</span>;
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

function IanaTab() {
  const [records, setRecords] = React.useState<TldRecord[]>([]);
  const [dbStats, setDbStats] = React.useState<DbStats | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [savedWhois, setSavedWhois] = React.useState<Set<string>>(new Set());
  const [scanning, setScanning] = React.useState(false);
  const scanningRef = React.useRef(false);
  const [scanType, setScanType] = React.useState("cc");
  const [scanForce, setScanForce] = React.useState(false);
  const [syncServers, setSyncServers] = React.useState(true);
  const [concur, setConcur] = React.useState(15);
  const [customTlds, setCustomTlds] = React.useState("");
  const [progress, setProgress] = React.useState({ done: 0, total: 0, errors: 0 });
  const [serverSyncStats, setServerSyncStats] = React.useState({ added: 0, updated: 0, conflict: 0 });
  const [scanLog, setScanLog] = React.useState<string[]>([]);
  const esRef = React.useRef<EventSource | null>(null);
  const [search, setSearch] = React.useState("");
  const [filterType, setFilterType] = React.useState("all");
  const [filterRegistry, setFilterRegistry] = React.useState("all");
  const [sortKey, setSortKey] = React.useState<keyof TldRecord>("tld");
  const [sortAsc, setSortAsc] = React.useState(true);
  const [expandedTld, setExpandedTld] = React.useState<string | null>(null);

  async function loadRecords() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/tld-registry");
      const d = await r.json();
      if (r.ok) { setRecords(d.records ?? []); setDbStats(d.stats ?? null); }
      else toast.error(d.error ?? "加载失败");
    } catch { toast.error("网络错误"); }
    finally { setLoading(false); }
  }
  React.useEffect(() => { loadRecords(); }, []);

  async function saveWhoisServer(tld: string, server: string) {
    try {
      const r = await fetch("/api/admin/tld-servers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tld, server }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "保存失败");
      toast.success(`.${tld} WHOIS 已推送至自定义列表`);
      setSavedWhois(prev => new Set(prev).add(tld));
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "保存失败"); }
  }

  function startScan() {
    if (scanningRef.current) return;
    scanningRef.current = true;
    setScanning(true);
    setProgress({ done: 0, total: 0, errors: 0 });
    setServerSyncStats({ added: 0, updated: 0, conflict: 0 });
    setScanLog([]);
    const params = new URLSearchParams({
      stream: "1", type: scanType, force: scanForce ? "1" : "0",
      concur: String(concur), syncServers: syncServers ? "1" : "0",
    });
    if (scanType === "custom" && customTlds.trim()) params.set("tlds", customTlds.trim());
    const es = new EventSource(`/api/admin/tld-registry?${params}`);
    esRef.current = es;
    es.addEventListener("start", (e) => {
      const d = JSON.parse(e.data);
      setProgress(p => ({ ...p, total: d.total }));
      setScanLog(l => [...l, `▶ 开始扫描 ${d.total} 个 TLD${d.syncServers ? "（含服务器同步）" : ""}`]);
    });
    es.addEventListener("result", (e) => {
      const d: TldRecord = JSON.parse(e.data);
      setProgress({ done: d.done ?? 0, total: d.total ?? 0, errors: d.errors ?? 0 });
      setRecords(prev => { const idx = prev.findIndex(r => r.tld === d.tld); if (idx >= 0) { const next = [...prev]; next[idx] = d; return next; } return [...prev, d]; });
      if (d.scan_error) setScanLog(l => [...l.slice(-199), `  ❌ .${d.tld}  ${d.scan_error}`]);
      else if (d.registry_url) setScanLog(l => [...l.slice(-199), `  ✅ .${d.tld}  ${d.tld_type || "?"}  ${d.registry_url}`]);
      else setScanLog(l => [...l.slice(-199), `  ⚠️  .${d.tld}  无注册局 URL`]);
    });
    es.addEventListener("server_sync", (e) => {
      const d = JSON.parse(e.data);
      setServerSyncStats({ added: d.serverAdded ?? 0, updated: d.serverUpdated ?? 0, conflict: d.serverConflict ?? 0 });
      if (d.action === "added")    setScanLog(l => [...l.slice(-199), `  ➕ 服务器 .${d.tld}  新增 ${d.ianaServer}`]);
      if (d.action === "updated")  setScanLog(l => [...l.slice(-199), `  🔄 服务器 .${d.tld}  更新 ${d.ianaServer}`]);
      if (d.action === "conflict") setScanLog(l => [...l.slice(-199), `  ⚠️  服务器 .${d.tld}  冲突：手动=${typeof d.existingEntry === "string" ? d.existingEntry : JSON.stringify(d.existingEntry)}  IANA=${d.ianaServer}`]);
    });
    es.addEventListener("done", (e) => {
      const d = JSON.parse(e.data);
      setProgress({ done: d.done, total: d.total, errors: d.errors });
      const serverMsg = syncServers
        ? `  服务器同步：新增 ${d.serverAdded ?? 0}  更新 ${d.serverUpdated ?? 0}  冲突 ${d.serverConflict ?? 0}`
        : "";
      setScanLog(l => [...l, `✅ 扫描完成：${d.done} 个，${d.errors} 个失败${serverMsg ? "\n" + serverMsg : ""}`]);
      scanningRef.current = false; setScanning(false); esRef.current?.close(); esRef.current = null;
      loadRecords();
    });
    es.addEventListener("error", () => {
      if (scanningRef.current) { setScanLog(l => [...l, "❌ 连接中断，请重试"]); scanningRef.current = false; setScanning(false); esRef.current?.close(); esRef.current = null; }
    });
  }
  function stopScan() { scanningRef.current = false; esRef.current?.close(); esRef.current = null; setScanning(false); setScanLog(l => [...l, "⏹ 已手动停止"]); }
  async function deleteRecord(tld: string) { if (!confirm(`确认删除 .${tld} 的记录？`)) return; await fetch(`/api/admin/tld-registry?tld=${tld}`, { method: "DELETE" }); setRecords(prev => prev.filter(r => r.tld !== tld)); toast.success(`.${tld} 已删除`); }
  async function deleteAll() { if (!confirm("确认清空所有 TLD 注册局记录？")) return; await fetch("/api/admin/tld-registry?tld=__all", { method: "DELETE" }); setRecords([]); setDbStats(null); toast.success("已清空所有记录"); }
  function toggleSort(key: keyof TldRecord) { if (sortKey === key) setSortAsc(a => !a); else { setSortKey(key); setSortAsc(true); } }

  const typeCounts = React.useMemo(() => {
    const c: Record<string, number> = { all: records.length };
    for (const r of records) c[r.tld_type || "generic"] = (c[r.tld_type || "generic"] || 0) + 1;
    return c;
  }, [records]);

  const filtered = React.useMemo(() => {
    let data = [...records];
    if (filterType !== "all") data = data.filter(r => (r.tld_type || "generic") === filterType);
    if (filterRegistry === "yes") data = data.filter(r => !!r.registry_url);
    if (filterRegistry === "no")  data = data.filter(r => !r.registry_url);
    if (search) { const q = search.toLowerCase(); data = data.filter(r => r.tld.includes(q) || (r.manager || "").toLowerCase().includes(q) || (r.registry_url || "").toLowerCase().includes(q) || (r.whois_server || "").toLowerCase().includes(q)); }
    data.sort((a, b) => { const av = String(a[sortKey] ?? "").toLowerCase(), bv = String(b[sortKey] ?? "").toLowerCase(); return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av); });
    return data;
  }, [records, filterType, filterRegistry, search, sortKey, sortAsc]);

  const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  const SortTh = ({ label, skey, className }: { label: string; skey: keyof TldRecord; className?: string }) => (
    <th className={cn("px-3 py-2 text-left text-xs font-medium text-muted-foreground cursor-pointer select-none hover:text-foreground transition-colors whitespace-nowrap", className)}
      onClick={() => toggleSort(skey)}>
      <span className="inline-flex items-center gap-0.5">{label}
        {sortKey === skey ? (sortAsc ? <RiArrowUpSLine className="w-3 h-3" /> : <RiArrowDownSLine className="w-3 h-3" />) : <RiArrowDownSLine className="w-3 h-3 opacity-30" />}
      </span>
    </th>
  );

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs text-muted-foreground">从 IANA 根域名数据库抓取各 TLD 的注册局官网、WHOIS 服务器、所属机构等元数据，支持流式抓取，永久存储。</p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={loadRecords} disabled={loading} className="h-8 text-xs rounded-xl">
            <RiRefreshLine className={cn("w-3.5 h-3.5 mr-1", loading && "animate-spin")} />刷新
          </Button>
          {records.length > 0 && (
            <Button variant="outline" size="sm" onClick={deleteAll} className="h-8 text-xs text-destructive border-destructive/30 hover:bg-destructive/10 rounded-xl">
              <RiDeleteBin7Line className="w-3.5 h-3.5 mr-1" />清空
            </Button>
          )}
        </div>
      </div>

      {dbStats && (
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
          {[
            { label: "总计 TLD",   value: dbStats.total },
            { label: "ccTLD",      value: dbStats.cc,           color: "text-blue-600" },
            { label: "gTLD",       value: dbStats.generic,      color: "text-emerald-600" },
            { label: "sTLD",       value: dbStats.sponsored,    color: "text-violet-600" },
            { label: "有官网",     value: dbStats.with_registry, color: "text-amber-600" },
            { label: "最近扫描",   value: dbStats.last_scan ? fmtDate(dbStats.last_scan) : "—" },
          ].map(s => (
            <div key={s.label} className="rounded-xl border border-border bg-muted/20 px-3 py-2.5">
              <p className="text-xs text-muted-foreground mb-0.5">{s.label}</p>
              <p className={cn("text-xl font-bold", s.color || "")}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Scan panel */}
      <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-4">
        <p className="text-sm font-semibold">IANA 元数据扫描</p>
        <div className="flex flex-wrap gap-3 items-end">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">TLD 类型</label>
            <div className="flex gap-1.5 flex-wrap">
              {[{ k: "cc", l: "ccTLD" }, { k: "gtld", l: "gTLD" }, { k: "all", l: "全部" }, { k: "custom", l: "自定义" }].map(({ k, l }) => (
                <button key={k} type="button" onClick={() => setScanType(k)}
                  className={cn("text-xs px-2.5 py-1 rounded-full border transition-colors",
                    scanType === k ? "bg-foreground text-background border-transparent" : "bg-muted/40 border-border text-muted-foreground hover:bg-muted/60")}>
                  {l}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">并发数</label>
            <Input type="number" min={1} max={30} value={concur}
              onChange={e => setConcur(Math.min(30, Math.max(1, parseInt(e.target.value) || 10)))}
              className="h-8 w-20 text-sm" />
          </div>
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
            <input type="checkbox" checked={scanForce} onChange={e => setScanForce(e.target.checked)} className="w-3.5 h-3.5" />
            强制重新扫描
          </label>
          <label className="flex items-center gap-2 text-xs cursor-pointer select-none text-sky-700 dark:text-sky-400 font-medium" title="将 IANA 发现的 WHOIS 服务器自动同步到服务器管理列表，手动配置的不会被覆盖">
            <input type="checkbox" checked={syncServers} onChange={e => setSyncServers(e.target.checked)} className="w-3.5 h-3.5 accent-sky-600" />
            同步 WHOIS 服务器
          </label>
          <Button onClick={scanning ? stopScan : startScan} size="sm" variant={scanning ? "destructive" : "default"} className="h-8 text-xs">
            {scanning ? <><RiStopCircleLine className="w-3.5 h-3.5 mr-1" />停止</> : <><RiGlobalLine className="w-3.5 h-3.5 mr-1" />开始扫描</>}
          </Button>
        </div>
        {scanType === "custom" && (
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">自定义 TLD（空格或逗号分隔）</label>
            <textarea value={customTlds} onChange={e => setCustomTlds(e.target.value)} rows={2} placeholder="例：gw jp cn us"
              className="w-full rounded-lg border border-input bg-background px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-ring" />
          </div>
        )}
        {(scanning || progress.total > 0) && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>
                {scanning ? <><RiLoader4Line className="inline w-3 h-3 animate-spin mr-1" />扫描中…</> : "已完成"}
                {" "}{progress.done}/{progress.total}（{pct}%）
                {progress.errors > 0 && <span className="text-destructive ml-1">{progress.errors} 个错误</span>}
              </span>
              <span>{pct}%</span>
            </div>
            <div className="h-1.5 bg-muted rounded-full overflow-hidden">
              <div className="h-full bg-primary transition-all duration-300 rounded-full" style={{ width: `${pct}%` }} />
            </div>
            {syncServers && (serverSyncStats.added + serverSyncStats.updated + serverSyncStats.conflict > 0) && (
              <div className="flex gap-3 text-[11px] flex-wrap">
                {serverSyncStats.added   > 0 && <span className="text-green-600 dark:text-green-400">➕ 新增 {serverSyncStats.added} 个服务器</span>}
                {serverSyncStats.updated > 0 && <span className="text-sky-600 dark:text-sky-400">🔄 更新 {serverSyncStats.updated} 个服务器</span>}
                {serverSyncStats.conflict > 0 && <span className="text-amber-600 dark:text-amber-400">⚠️ {serverSyncStats.conflict} 个冲突（手动配置保留）</span>}
              </div>
            )}
          </div>
        )}
        {scanLog.length > 0 && (
          <div className="rounded-lg bg-muted/30 border border-border p-2 max-h-40 overflow-y-auto font-mono text-[11px] space-y-0.5">
            {scanLog.map((l, i) => (
              <div key={i} className={
                l.startsWith("  ➕") ? "text-green-600 dark:text-green-400" :
                l.startsWith("  🔄") ? "text-sky-600 dark:text-sky-400" :
                l.startsWith("  ⚠️  服务器") ? "text-amber-600 dark:text-amber-400" :
                l.startsWith("  ❌") ? "text-destructive" :
                l.startsWith("✅") ? "text-green-700 dark:text-green-300 font-medium" :
                "text-muted-foreground"
              }>{l}</div>
            ))}
          </div>
        )}
      </div>

      {/* Results table */}
      {records.length === 0 && !loading ? (
        <div className="rounded-xl border border-border bg-muted/10 py-16 text-center space-y-3">
          <RiGlobalLine className="w-12 h-12 mx-auto text-muted-foreground/30" />
          <p className="text-sm font-medium text-muted-foreground">还没有任何 TLD 注册局数据</p>
          <p className="text-xs text-muted-foreground/70 max-w-sm mx-auto">点击「开始扫描」，系统将自动访问 IANA 数据库抓取每个 TLD 的官方信息并永久存储。</p>
          <Button size="sm" onClick={startScan} className="text-xs" disabled={scanning}><RiGlobalLine className="w-3.5 h-3.5 mr-1.5" />立即扫描 ccTLD</Button>
        </div>
      ) : records.length > 0 && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2 items-center">
            {[{ k: "all", l: `全部 (${records.length})` }, { k: "country-code", l: `ccTLD (${typeCounts["country-code"] || 0})` }, { k: "generic", l: `gTLD (${typeCounts["generic"] || 0})` }, { k: "generic-restricted", l: `受限 (${typeCounts["generic-restricted"] || 0})` }, { k: "sponsored", l: `sTLD (${typeCounts["sponsored"] || 0})` }].map(({ k, l }) => {
              const cnt = k === "all" ? records.length : (typeCounts[k] ?? 0);
              if (k !== "all" && cnt === 0) return null;
              return (
                <button key={k} onClick={() => setFilterType(k)}
                  className={cn("text-xs px-2.5 py-1 rounded-full border transition-colors",
                    filterType === k ? "bg-foreground text-background border-transparent" : "bg-muted/30 border-border text-muted-foreground hover:bg-muted/50")}>
                  {l}
                </button>
              );
            })}
            <div className="flex gap-0 border border-border rounded-full overflow-hidden text-xs">
              {[["all","全部"],["yes","有官网"],["no","无官网"]].map(([k,l]) => (
                <button key={k} onClick={() => setFilterRegistry(k)}
                  className={cn("px-2.5 py-1 transition-colors", filterRegistry === k ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground")}>{l}</button>
              ))}
            </div>
            <div className="ml-auto flex items-center gap-1.5 border border-input rounded-lg px-2.5 h-7 bg-background">
              <RiSearchLine className="w-3 h-3 text-muted-foreground shrink-0" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="搜索 TLD / 机构 / 网址"
                className="text-xs bg-transparent outline-none w-32 text-foreground placeholder:text-muted-foreground" />
            </div>
            <span className="text-xs text-muted-foreground">{filtered.length} 条</span>
          </div>

          <div className="rounded-xl border border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-muted/40 border-b border-border">
                    <SortTh label="TLD" skey="tld" className="w-16" />
                    <SortTh label="类型" skey="tld_type" className="w-24" />
                    <SortTh label="注册局机构" skey="manager" />
                    <SortTh label="官方网站" skey="registry_url" className="hidden md:table-cell" />
                    <SortTh label="WHOIS 服务器" skey="whois_server" className="hidden lg:table-cell" />
                    <SortTh label="国家" skey="country" className="w-20 hidden xl:table-cell" />
                    <th className="px-3 py-2 text-right text-xs font-medium text-muted-foreground w-20">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filtered.map(row => {
                    const isExpanded = expandedTld === row.tld;
                    return (
                      <React.Fragment key={row.tld}>
                        <tr className={cn("hover:bg-muted/20 transition-colors cursor-pointer", row.scan_error ? "opacity-60" : "", isExpanded ? "bg-muted/30" : "")}
                          onClick={() => setExpandedTld(isExpanded ? null : row.tld)}>
                          <td className="px-3 py-2.5"><span className="font-mono font-semibold text-sm">.{row.tld}</span></td>
                          <td className="px-3 py-2.5"><TypeBadge type={row.tld_type} /></td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground max-w-[180px] truncate">{row.manager || <span className="opacity-40">—</span>}</td>
                          <td className="px-3 py-2.5 hidden md:table-cell">
                            {row.registry_url ? (
                              <a href={row.registry_url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                                className="text-xs text-primary hover:underline inline-flex items-center gap-1 max-w-[180px] truncate">
                                {row.registry_url.replace(/^https?:\/\//, "")}<RiExternalLinkLine className="w-2.5 h-2.5 shrink-0 opacity-60" />
                              </a>
                            ) : <span className="text-muted-foreground/40 text-xs">—</span>}
                          </td>
                          <td className="px-3 py-2.5 hidden lg:table-cell text-xs text-muted-foreground font-mono">
                            {row.whois_server ? (
                              <div className="flex items-center gap-1.5 group">
                                <span>{row.whois_server}</span>
                                {savedWhois.has(row.tld) ? <RiCheckboxCircleLine className="w-3 h-3 text-emerald-500 shrink-0" /> : (
                                  <button onClick={(e) => { e.stopPropagation(); saveWhoisServer(row.tld, row.whois_server!); }}
                                    title="保存到自定义服务器" className="opacity-0 group-hover:opacity-100 text-primary transition-opacity shrink-0">
                                    <RiSave3Line className="w-3 h-3" />
                                  </button>
                                )}
                              </div>
                            ) : <span className="opacity-40">—</span>}
                          </td>
                          <td className="px-3 py-2.5 hidden xl:table-cell text-xs text-muted-foreground">{row.country || "—"}</td>
                          <td className="px-3 py-2.5 text-right">
                            <div className="flex items-center justify-end gap-1">
                              {row.iana_url && (
                                <a href={row.iana_url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
                                  className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors" title="查看 IANA 页面">
                                  <RiExternalLinkLine className="w-3.5 h-3.5" />
                                </a>
                              )}
                              <button onClick={e => { e.stopPropagation(); deleteRecord(row.tld); }}
                                className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-destructive transition-colors" title="删除记录">
                                <RiDeleteBin7Line className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="bg-muted/10 border-t border-border">
                            <td colSpan={7} className="px-4 py-4">
                              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs">
                                <div className="space-y-1.5">
                                  <p className="font-semibold text-foreground/80 uppercase tracking-wider text-[10px]">注册局信息</p>
                                  <DetailRow label="TLD" value={`.${row.tld}`} />
                                  <DetailRow label="类型" value={<TypeBadge type={row.tld_type} />} />
                                  <DetailRow label="机构" value={row.manager} />
                                  <DetailRow label="国家" value={row.country} />
                                  <DetailRow label="地址" value={row.address} wrap />
                                </div>
                                <div className="space-y-1.5">
                                  <p className="font-semibold text-foreground/80 uppercase tracking-wider text-[10px]">网络服务</p>
                                  <DetailRow label="官方网站" value={row.registry_url ? <a href={row.registry_url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">{row.registry_url}<RiExternalLinkLine className="w-3 h-3" /></a> : null} />
                                  <DetailRow label="WHOIS 服务器" value={row.whois_server ? <span className="font-mono">{row.whois_server}</span> : null} />
                                  <DetailRow label="IANA 页面" value={row.iana_url ? <a href={row.iana_url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">{row.iana_url}<RiExternalLinkLine className="w-3 h-3" /></a> : null} />
                                </div>
                                <div className="space-y-1.5">
                                  <p className="font-semibold text-foreground/80 uppercase tracking-wider text-[10px]">时间信息</p>
                                  <DetailRow label="创建日期" value={row.created_date} />
                                  <DetailRow label="最后变更" value={row.changed_date} />
                                  <DetailRow label="扫描时间" value={row.scraped_at ? fmtDate(row.scraped_at) : null} />
                                  {row.scan_error && <DetailRow label="扫描错误" value={<span className="text-destructive">{row.scan_error}</span>} />}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                  {filtered.length === 0 && !loading && (
                    <tr><td colSpan={7} className="px-3 py-12 text-center text-sm text-muted-foreground">
                      <RiDatabase2Line className="w-8 h-8 mx-auto mb-3 opacity-30" />无匹配结果
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   Main Page
══════════════════════════════════════════════════════════════════════════════ */
export default function DomainsPage() {
  const router = useRouter();
  const tabParam = router.query.tab as string | undefined;
  const [activeTab, setActiveTab] = React.useState<MainTab>("lifecycle");

  React.useEffect(() => {
    if (tabParam === "servers") setActiveTab("servers");
    else if (tabParam === "iana") setActiveTab("iana");
    else setActiveTab("lifecycle");
  }, [tabParam]);

  const tabs: { key: MainTab; label: string; icon: React.ElementType; desc: string }[] = [
    { key: "lifecycle", label: "生命周期",  icon: RiTimeLine,    desc: "宽限期/赎回期规则" },
    { key: "servers",   label: "服务器管理", icon: RiServerLine,  desc: "WHOIS 服务器列表" },
    { key: "iana",      label: "IANA 数据", icon: RiGlobalLine,  desc: "注册局元数据" },
  ];

  return (
    <AdminLayout title="域名管理">
      <Head><title>域名管理 · Admin</title></Head>
      <div className="space-y-5">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2">
            <RiGlobalLine className="w-5 h-5 text-primary" />域名数据管理
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">TLD 生命周期规则、WHOIS/RDAP 服务器列表、IANA 注册局数据统一管理</p>
        </div>

        {/* Tab selector */}
        <div className="flex gap-1.5 p-1 rounded-2xl bg-muted/40 border border-border">
          {tabs.map(t => (
            <button key={t.key} onClick={() => setActiveTab(t.key)}
              className={cn(
                "flex-1 flex items-center justify-center gap-1.5 py-2.5 px-3 rounded-xl text-xs font-semibold transition-all",
                activeTab === t.key
                  ? "bg-background shadow-sm text-foreground border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}>
              <t.icon className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden sm:inline">{t.label}</span>
              <span className="sm:hidden">{t.label.split(" ")[0]}</span>
            </button>
          ))}
        </div>

        {/* Tab content */}
        {activeTab === "lifecycle" && <LifecycleTab />}
        {activeTab === "servers" && <ServersTab />}
        {activeTab === "iana" && <IanaTab />}
      </div>
    </AdminLayout>
  );
}
