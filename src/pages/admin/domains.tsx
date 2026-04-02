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
import IANA_TLDS from "@/data/iana-tlds.json";
import {
  RiTimeLine, RiGlobalLine,
  RiEditLine, RiDeleteBinLine, RiLoader4Line, RiRefreshLine, RiSearchLine,
  RiAddLine, RiCloseLine, RiSave3Line, RiCheckboxCircleLine,
  RiExternalLinkLine,
  RiCheckLine,
  RiDeleteBin7Line, RiAlertLine,
} from "@remixicon/react";
import type { TldFailureRow } from "@/pages/api/admin/tld-failures";

type MainTab = "lifecycle" | "failures";

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

    const seen = new Set<string>();
    const result: TldRow[] = [];

    // 1. TLDs with curated lifecycle data
    for (const [tld, entry] of Object.entries(LIFECYCLE_TABLE)) {
      seen.add(tld);
      const ov = map[tld];
      result.push({
        tld, grace: ov ? ov.grace : entry.grace,
        redemption: ov ? ov.redemption : entry.redemption,
        pendingDelete: ov ? ov.pending_delete : entry.pendingDelete,
        registry: ov ? (ov.registry ?? entry.registry ?? null) : (entry.registry ?? null),
        notes: ov?.notes ?? null, modified: !!ov, dbId: ov?.id ?? null,
      });
    }

    // 2. Remaining IANA TLDs (default 30/30/5 — ICANN standard)
    for (const tld of IANA_TLDS as string[]) {
      if (seen.has(tld)) continue;
      seen.add(tld);
      const ov = map[tld];
      result.push({
        tld, grace: ov ? ov.grace : 30,
        redemption: ov ? ov.redemption : 30,
        pendingDelete: ov ? ov.pending_delete : 5,
        registry: ov?.registry ?? null,
        notes: ov?.notes ?? null, modified: !!ov, dbId: ov?.id ?? null,
      });
    }

    // 3. DB overrides for TLDs not in either list
    for (const ov of overrides) {
      if (!seen.has(ov.tld)) {
        result.push({ tld: ov.tld, grace: ov.grace, redemption: ov.redemption,
          pendingDelete: ov.pending_delete, registry: ov.registry,
          notes: ov.notes, modified: true, dbId: ov.id });
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
   TAB 2: 失败记录
══════════════════════════════════════════════════════════════════════════════ */
const FAIL_REASON_META: Record<string, { label: string; color: string }> = {
  no_server:    { label: "无服务器",  color: "text-red-600    bg-red-50    dark:bg-red-950/40    border-red-200    dark:border-red-800"    },
  iana_fallback:{ label: "IANA兜底",  color: "text-orange-600 bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-800" },
  timeout:      { label: "超时",      color: "text-yellow-600 bg-yellow-50 dark:bg-yellow-950/40 border-yellow-200 dark:border-yellow-800" },
  rate_limited: { label: "限速",      color: "text-amber-600  bg-amber-50  dark:bg-amber-950/40  border-amber-200  dark:border-amber-800"  },
  parse_error:  { label: "解析失败",  color: "text-blue-600   bg-blue-50   dark:bg-blue-950/40   border-blue-200   dark:border-blue-800"   },
};

function FailuresTab() {
  const [rows, setRows] = React.useState<TldFailureRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [resettingTld, setResettingTld] = React.useState<string | null>(null);
  const [clearingAll, setClearingAll] = React.useState(false);

  // Add-server dialog state
  const [addOpen, setAddOpen] = React.useState(false);
  const [addTld, setAddTld] = React.useState("");
  const [addServer, setAddServer] = React.useState("");
  const [adding, setAdding] = React.useState(false);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/tld-failures");
      const d = await r.json();
      setRows(d.rows ?? []);
    } catch { toast.error("加载失败"); }
    finally { setLoading(false); }
  }

  React.useEffect(() => { load(); }, []);

  async function resetTld(tld: string) {
    if (!confirm(`确认重置 .${tld} 的失败记录？`)) return;
    setResettingTld(tld);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld }),
      });
      if (!r.ok) throw new Error("重置失败");
      toast.success(`.${tld} 记录已清零`);
      await load();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "操作失败"); }
    finally { setResettingTld(null); }
  }

  async function clearAllFailures() {
    if (!confirm(`确认清零全部 ${rows.length} 条失败记录？此操作不可撤销。`)) return;
    setClearingAll(true);
    try {
      const r = await fetch("/api/admin/tld-failures", {
        method: "DELETE", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clear_all: true }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error("操作失败");
      toast.success(`已清零 ${d.cleared ?? 0} 条失败记录`);
      await load();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "操作失败"); }
    finally { setClearingAll(false); }
  }

  function openAddServer(tld: string) {
    setAddTld(tld);
    setAddServer("");
    setAddOpen(true);
  }

  async function saveServer() {
    const tld = addTld.trim().toLowerCase().replace(/^\./, "");
    const server = addServer.trim();
    if (!tld || !server) { toast.error("TLD 和服务器地址都是必填项"); return; }
    setAdding(true);
    try {
      const r = await fetch("/api/admin/tld-servers", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tld, server }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.message ?? "添加失败");
      toast.success(d.message ?? "已添加");
      setAddOpen(false);
      await load();
    } catch (e: unknown) { toast.error(e instanceof Error ? e.message : "操作失败"); }
    finally { setAdding(false); }
  }

  const filtered = rows.filter(r => !search || r.tld.includes(search.toLowerCase()));
  const noServerCount = rows.filter(r => r.fail_reason === "no_server" || r.fail_reason === "iana_fallback").length;

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold flex items-center gap-1.5">
            <RiAlertLine className="w-4 h-4 text-primary" />查询失败记录
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            记录 WHOIS/RDAP 查询失败的后缀，选择对应后缀一键添加服务器来增强查询能力
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {noServerCount > 0 && (
            <span className="text-xs bg-red-50 dark:bg-red-950/40 text-red-600 border border-red-200 dark:border-red-800 rounded-lg px-2 py-1">
              {noServerCount} 个后缀无服务器
            </span>
          )}
          {rows.length > 0 && (
            <Button onClick={clearAllFailures} variant="outline" size="sm" className="h-8 text-xs rounded-xl border-red-200/60 text-red-500 hover:bg-red-50 dark:hover:bg-red-950/30" disabled={clearingAll}>
              {clearingAll ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiDeleteBin7Line className="w-3.5 h-3.5 mr-1" />}
              清除全部
            </Button>
          )}
          <Button onClick={load} variant="outline" size="sm" className="h-8 text-xs rounded-xl" disabled={loading}>
            {loading ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiRefreshLine className="w-3.5 h-3.5" />}
          </Button>
        </div>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <RiSearchLine className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="搜索 TLD…" className="pl-8 h-8 text-xs rounded-xl" />
        </div>
      </div>

      {loading && rows.length === 0 ? (
        <div className="flex items-center justify-center py-16 text-muted-foreground text-sm">
          <RiLoader4Line className="w-5 h-5 animate-spin mr-2" />加载中…
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-muted-foreground text-sm gap-2">
          <RiCheckboxCircleLine className="w-8 h-8 opacity-30" />
          <p>{search ? "无匹配结果" : "暂无失败记录，所有后缀查询正常"}</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-muted/40 text-muted-foreground border-b border-border">
                <th className="text-left py-2.5 px-3 font-semibold w-24">后缀</th>
                <th className="text-left py-2.5 px-3 font-semibold w-16">失败次数</th>
                <th className="text-left py-2.5 px-3 font-semibold w-24">原因</th>
                <th className="text-left py-2.5 px-3 font-semibold hidden sm:table-cell">最近域名</th>
                <th className="text-left py-2.5 px-3 font-semibold hidden lg:table-cell">错误详情</th>
                <th className="text-left py-2.5 px-3 font-semibold w-20 hidden md:table-cell">时间</th>
                <th className="text-right py-2.5 px-3 font-semibold w-40">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(row => {
                const meta = FAIL_REASON_META[row.fail_reason ?? "no_server"] ?? FAIL_REASON_META.no_server;
                return (
                  <tr key={row.tld} className="hover:bg-muted/20 transition-colors">
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <code className="font-mono font-bold text-foreground">.{row.tld}</code>
                        {row.has_custom_server && (
                          <span className="text-emerald-600" title="已有自定义服务器">
                            <RiCheckboxCircleLine className="w-3.5 h-3.5" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={cn(
                        "inline-flex items-center justify-center w-7 h-7 rounded-lg font-bold text-sm",
                        row.fail_count >= 10 ? "bg-red-100 dark:bg-red-950/40 text-red-700"
                          : row.fail_count >= 3 ? "bg-orange-100 dark:bg-orange-950/40 text-orange-700"
                          : "bg-muted text-muted-foreground"
                      )}>
                        {row.fail_count}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={cn(
                        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md text-xs border font-medium",
                        meta.color,
                      )}>
                        {meta.label}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 hidden sm:table-cell">
                      <span className="text-muted-foreground font-mono">{row.last_domain ?? "—"}</span>
                    </td>
                    <td className="py-2.5 px-3 hidden lg:table-cell max-w-xs">
                      <span className="text-muted-foreground truncate block" title={row.sample_error ?? ""}>
                        {row.sample_error ?? "—"}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 hidden md:table-cell text-muted-foreground">
                      {fmtRel(row.last_fail_at)}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center justify-end gap-1.5">
                        {!row.has_custom_server && (
                          <Button size="sm" onClick={() => openAddServer(row.tld)}
                            className="h-7 text-xs rounded-lg px-2">
                            <RiAddLine className="w-3 h-3 mr-0.5" />添加服务器
                          </Button>
                        )}
                        <button onClick={() => resetTld(row.tld)} disabled={resettingTld === row.tld}
                          title="重置计数" className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                          {resettingTld === row.tld
                            ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                            : <RiDeleteBin7Line className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Add Server Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="text-sm">为 .{addTld} 添加 WHOIS 服务器</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-1">
            <div className="space-y-1.5">
              <Label className="text-xs">后缀</Label>
              <Input value={addTld} onChange={e => setAddTld(e.target.value.replace(/^\./, ""))}
                placeholder="com" className="h-8 text-xs rounded-xl font-mono" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">WHOIS 服务器主机名</Label>
              <Input value={addServer} onChange={e => setAddServer(e.target.value)}
                placeholder="whois.example.com" className="h-8 text-xs rounded-xl font-mono" />
              <p className="text-xs text-muted-foreground">
                仅填写主机名（如 whois.nic.xxx），高级 JSON 格式请在"服务器管理"标签页配置
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)} className="h-8 text-xs rounded-xl">
              <RiCloseLine className="w-3.5 h-3.5 mr-1" />取消
            </Button>
            <Button onClick={saveServer} disabled={adding} className="h-8 text-xs rounded-xl">
              {adding ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiSave3Line className="w-3.5 h-3.5 mr-1" />}
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
    if (tabParam === "failures") setActiveTab("failures");
    else setActiveTab("lifecycle");
  }, [tabParam]);

  const tabs: { key: MainTab; label: string; icon: React.ElementType; desc: string }[] = [
    { key: "lifecycle", label: "生命周期", icon: RiTimeLine,  desc: "宽限期/赎回期规则" },
    { key: "failures",  label: "失败记录", icon: RiAlertLine, desc: "查询失败的后缀统计" },
  ];

  return (
    <AdminLayout title="域名管理">
      <Head><title>域名管理 · Admin</title></Head>
      <div className="space-y-5">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2">
            <RiGlobalLine className="w-5 h-5 text-primary" />域名数据管理
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">TLD 宽限期 / 赎回期规则管理，以及查询失败后缀的统计与补录</p>
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
        {activeTab === "failures" && <FailuresTab />}
      </div>
    </AdminLayout>
  );
}
