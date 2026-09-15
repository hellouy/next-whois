import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiExternalLinkLine, RiCheckLine, RiCloseLine,
  RiDeleteBinLine, RiTimeLine, RiRefreshLine,
} from "@remixicon/react";

interface Probe { url: string; found: boolean; error?: string; status?: number; }
interface Backlink { found: boolean; pages: Probe[]; checkedAt: string; }

type Application = {
  id: string;
  name: string;
  url: string;
  description: string | null;
  category: string | null;
  email: string;
  status: "review" | "approved" | "rejected";
  auto_approved: boolean;
  backlink_pages: Backlink | string | null;
  admin_note: string | null;
  link_id: number | null;
  created_at: string;
  reviewed_at: string | null;
};

const FILTERS = [
  { key: "all", label: "全部" },
  { key: "review", label: "待审核" },
  { key: "approved", label: "已通过" },
  { key: "rejected", label: "已拒绝" },
] as const;

function fmtTime(iso: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
}

export default function AdminLinkApplicationsPage() {
  const [apps, setApps] = React.useState<Application[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [filter, setFilter] = React.useState<string>("review");
  const [busyId, setBusyId] = React.useState<string>("");
  const [note, setNote] = React.useState<Record<string, string>>({});
  const [showBacklink, setShowBacklink] = React.useState<Record<string, boolean>>({});

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/links/applications");
      const data = await res.json();
      setApps(data.applications || []);
    } catch {
      toast.error("加载失败");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);

  async function act(id: string, action: "approve" | "reject") {
    setBusyId(id);
    try {
      const res = await fetch("/api/admin/links/applications", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, action, note: note[id] || null }),
      });
      const data = await res.json();
      if (!res.ok) { toast.error(data.error || "操作失败"); return; }
      toast.success(action === "approve" ? "已通过并上链" : "已拒绝");
      await load();
    } catch {
      toast.error("网络错误");
    } finally {
      setBusyId("");
    }
  }

  async function remove(id: string) {
    if (!window.confirm("确定删除该申请记录？此操作不可恢复。")) return;
    setBusyId(id);
    try {
      const res = await fetch("/api/admin/links/applications", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) { toast.error("删除失败"); return; }
      toast.success("已删除");
      await load();
    } catch {
      toast.error("网络错误");
    } finally {
      setBusyId("");
    }
  }

  const filtered = apps.filter(a => filter === "all" || a.status === filter);
  const pendingCount = apps.filter(a => a.status === "review").length;

  return (
    <>
      <Head><title>友链申请 — 管理后台</title></Head>
      <AdminLayout title="友链申请">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-1 bg-muted/50 rounded-lg p-1">
            {FILTERS.map(f => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                className={cn(
                  "px-3 py-1.5 text-xs font-semibold rounded-md transition-colors",
                  filter === f.key ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground",
                )}
              >
                {f.key === "review" ? `${f.label}${pendingCount ? ` (${pendingCount})` : ""}` : f.label}
              </button>
            ))}
          </div>
          <button
            onClick={load}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors"
          >
            <RiRefreshLine className="w-4 h-4" /> 刷新
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-24 text-muted-foreground">
            <RiLoader4Line className="w-6 h-6 animate-spin" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-24 text-center text-sm text-muted-foreground">
            {filter === "review" ? "没有待审核的友链申请" : "暂无记录"}
          </div>
        ) : (
          <div className="space-y-3">
            {filtered.map(a => (
              <div key={a.id} className="rounded-xl border border-border bg-card p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <a
                        href={a.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm font-bold hover:underline inline-flex items-center gap-1"
                      >
                        {a.name} <RiExternalLinkLine className="w-3 h-3 text-muted-foreground" />
                      </a>
                      <span
                        className={cn(
                          "text-[10px] font-semibold rounded-full px-2 py-0.5",
                          a.status === "approved" && "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300",
                          a.status === "rejected" && "bg-red-500/15 text-red-600 dark:text-red-300",
                          a.status === "review" && "bg-amber-500/15 text-amber-600 dark:text-amber-300",
                        )}
                      >
                        {a.status === "approved" ? (a.auto_approved ? "已自动通过" : "已通过") :
                          a.status === "rejected" ? "已拒绝" : "待审核"}
                      </span>
                      {a.auto_approved && (
                        <RiTimeLine className="w-3.5 h-3.5 text-muted-foreground" />
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1 space-y-0.5">
                      <p className="truncate">
                        <span className="font-mono">{a.url}</span>
                        {a.category ? <span className="ml-2 text-muted-foreground/60">分类：{a.category}</span> : null}
                      </p>
                      {a.description ? <p className="line-clamp-2">{a.description}</p> : null}
                      <p>
                        <a href={`mailto:${a.email}`} className="hover:underline">{a.email}</a>
                        <span className="ml-3 text-muted-foreground/60">提交：{fmtTime(a.created_at)}</span>
                        {a.reviewed_at ? <span className="ml-3 text-muted-foreground/60">审核：{fmtTime(a.reviewed_at)}</span> : null}
                      </p>
                    </div>
                  </div>
                  <div className="flex gap-1.5 shrink-0">
                    {a.status !== "approved" && (
                      <button
                        onClick={() => act(a.id, "approve")}
                        disabled={busyId === a.id}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-600 dark:text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50"
                      >
                        {busyId === a.id ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiCheckLine className="w-3.5 h-3.5" />}
                        通过
                      </button>
                    )}
                    {a.status !== "rejected" && (
                      <button
                        onClick={() => act(a.id, "reject")}
                        disabled={busyId === a.id}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 dark:text-red-300 bg-red-500/10 hover:bg-red-500/20 rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50"
                      >
                        <RiCloseLine className="w-3.5 h-3.5" />
                        拒绝
                      </button>
                    )}
                    <button
                      onClick={() => remove(a.id)}
                      disabled={busyId === a.id}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-muted-foreground hover:text-red-500 rounded-lg px-2.5 py-1.5 transition-colors disabled:opacity-50"
                    >
                      <RiDeleteBinLine className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-2">
                  {a.status !== "approved" && (
                    <input
                      value={note[a.id] || ""}
                      onChange={e => setNote(n => ({ ...n, [a.id]: e.target.value }))}
                      placeholder={a.status === "rejected" ? "拒绝原因（会发送给申请人）" : "备注（可选）"}
                      className="flex-1 min-w-0 rounded-lg border border-border bg-background px-3 py-2 text-xs outline-none focus:border-primary"
                    />
                  )}
                  {a.backlink_pages && (
                    <button
                      onClick={() => setShowBacklink(s => ({ ...s, [a.id]: !s[a.id] }))}
                      className="shrink-0 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors text-left"
                    >
                      {showBacklink[a.id] ? "收起反链摘要" : "查看反链摘要"}
                    </button>
                  )}
                </div>

                {showBacklink[a.id] && (
                  <div className="rounded-lg bg-muted/40 border border-border p-3 space-y-1.5">
                    {(() => {
                      const bk = a.backlink_pages;
                      const obj = bk && typeof bk !== "string" ? bk : null;
                      if (!obj) {
                        return <p className="text-xs text-muted-foreground">{typeof bk === "string" ? bk : "无检测记录"}</p>;
                      }
                      const pages = obj.pages;
                      if (pages.length === 0) {
                        return <p className="text-xs text-muted-foreground">未抓取到页面</p>;
                      }
                      return (
                        <>
                          <p className={cn("text-xs font-semibold", obj.found ? "text-emerald-600 dark:text-emerald-300" : "text-amber-600 dark:text-amber-300")}>
                            {obj.found ? "检出本站链接" : "未检出本站链接"}
                          </p>
                          <ul className="space-y-0.5">
                            {pages.map((p, i) => (
                              <li key={i} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                                <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", p.found ? "bg-emerald-500" : "bg-muted-foreground/40")} />
                                <span className="font-mono truncate">{p.url}</span>
                                <span className="ml-auto shrink-0">{p.found ? "命中" : (p.error || p.status || "")}</span>
                              </li>
                            ))}
                          </ul>
                        </>
                      );
                    })()}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </AdminLayout>
    </>
  );
}