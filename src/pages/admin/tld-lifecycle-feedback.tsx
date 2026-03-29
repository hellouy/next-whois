import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import {
  RiCheckLine, RiCloseLine, RiDeleteBinLine, RiLoader4Line,
  RiRefreshLine, RiExternalLinkLine, RiTimeLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

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

type FeedbackItem = {
  id: string;
  tld: string;
  current_grace: number | null;
  current_redemption: number | null;
  current_pending_delete: number | null;
  suggested_grace: number;
  suggested_redemption: number;
  suggested_pending_delete: number;
  source_url: string | null;
  notes: string | null;
  submitter_email: string | null;
  status: "pending" | "approved" | "rejected";
  created_at: string;
  reviewed_at: string | null;
  reviewed_by: string | null;
};

function DayBadge({ label, current, suggested }: { label: string; current: number | null; suggested: number }) {
  const changed = current !== null && current !== suggested;
  return (
    <div className="flex flex-col items-center gap-0.5 min-w-[52px]">
      <span className="text-[9px] font-bold uppercase tracking-wide text-muted-foreground/60">{label}</span>
      {current !== null && (
        <span className={cn("text-[10px] line-through text-muted-foreground/40 font-mono", !changed && "hidden")}>
          {current}d
        </span>
      )}
      <span className={cn(
        "text-[13px] font-bold font-mono",
        changed ? "text-amber-600 dark:text-amber-400" : "text-foreground",
      )}>
        {suggested}d
      </span>
    </div>
  );
}

export default function AdminTldLifecycleFeedbackPage() {
  const [items, setItems] = React.useState<FeedbackItem[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [filter, setFilter] = React.useState<"pending" | "approved" | "rejected" | "all">("pending");
  const [acting, setActing] = React.useState<string | null>(null);

  async function load(status = filter) {
    setLoading(true);
    try {
      const res = await fetch(`/api/admin/tld-lifecycle-feedback?status=${status}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "加载失败");
      setItems(data.items ?? []);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(filter); }, [filter]);

  async function handleAction(id: string, action: "approve" | "reject") {
    setActing(id + action);
    try {
      const res = await fetch(`/api/admin/tld-lifecycle-feedback?id=${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "操作失败");
      toast.success(action === "approve" ? "已采纳并写入 TLD 规则" : "已拒绝");
      load(filter);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "操作失败");
    } finally {
      setActing(null);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("确认删除该条反馈记录？")) return;
    setActing(id + "delete");
    try {
      const res = await fetch(`/api/admin/tld-lifecycle-feedback?id=${id}`, { method: "DELETE" });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "删除失败");
      }
      toast.success("已删除");
      load(filter);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    } finally {
      setActing(null);
    }
  }

  const pendingCount = filter === "pending" ? items.length : null;

  return (
    <AdminLayout title="TLD 管理">
      <Head><title>TLD 纠错反馈 — 管理后台</title></Head>

      <div className="max-w-4xl mx-auto px-4 py-6 space-y-5">
        <PageTabs tabs={TLD_TABS} />
        <div className="flex items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiTimeLine className="w-5 h-5 text-amber-500" />
              TLD 生命周期纠错
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              用户提交的宽限期 / 赎回期 / 待删除期纠正建议，采纳后立即写入覆盖规则
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => load(filter)} disabled={loading}>
            <RiRefreshLine className={cn("w-4 h-4 mr-1.5", loading && "animate-spin")} />
            刷新
          </Button>
        </div>

        <div className="flex gap-2 flex-wrap">
          {(["pending", "approved", "rejected", "all"] as const).map(s => (
            <button
              key={s}
              onClick={() => { setFilter(s); }}
              className={cn(
                "px-3 py-1 rounded-full text-xs font-semibold border transition-colors",
                filter === s
                  ? "bg-foreground text-background border-foreground"
                  : "bg-muted/30 border-border/50 text-muted-foreground hover:bg-muted/60",
              )}
            >
              {{ pending: "待审核", approved: "已采纳", rejected: "已拒绝", all: "全部" }[s]}
              {s === "pending" && pendingCount !== null && pendingCount > 0 && (
                <span className="ml-1 bg-amber-500 text-white rounded-full text-[9px] px-1.5 py-0 font-bold">
                  {pendingCount}
                </span>
              )}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : items.length === 0 ? (
          <div className="text-center py-16 text-muted-foreground text-sm">
            {filter === "pending" ? "暂无待审核的纠错反馈" : "无记录"}
          </div>
        ) : (
          <div className="space-y-3">
            {items.map(item => (
              <div
                key={item.id}
                className={cn(
                  "rounded-xl border bg-card p-4 space-y-3",
                  item.status === "pending" && "border-amber-400/30",
                  item.status === "approved" && "border-emerald-400/30 bg-emerald-500/5",
                  item.status === "rejected" && "border-border/40 opacity-60",
                )}
              >
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
                    {item.notes && (
                      <p><span className="font-semibold text-foreground/70">备注：</span>{item.notes}</p>
                    )}
                    {item.source_url && (
                      <p className="flex items-center gap-1">
                        <span className="font-semibold text-foreground/70">来源：</span>
                        <a
                          href={item.source_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sky-500 hover:underline flex items-center gap-0.5 break-all"
                        >
                          {item.source_url.length > 60 ? item.source_url.slice(0, 60) + "…" : item.source_url}
                          <RiExternalLinkLine className="w-2.5 h-2.5 shrink-0" />
                        </a>
                      </p>
                    )}
                    {item.submitter_email && (
                      <p><span className="font-semibold text-foreground/70">提交者：</span>{item.submitter_email}</p>
                    )}
                  </div>
                )}

                {item.status === "approved" && item.reviewed_by && (
                  <p className="text-[10px] text-muted-foreground/50">
                    由 {item.reviewed_by} 采纳于 {new Date(item.reviewed_at!).toLocaleString("zh-CN", { dateStyle: "short", timeStyle: "short" })}
                  </p>
                )}
                {item.status === "rejected" && item.reviewed_by && (
                  <p className="text-[10px] text-muted-foreground/50">
                    由 {item.reviewed_by} 拒绝于 {new Date(item.reviewed_at!).toLocaleString("zh-CN", { dateStyle: "short", timeStyle: "short" })}
                  </p>
                )}

                {item.status === "pending" && (
                  <div className="flex items-center gap-2 pt-1">
                    <Button
                      size="sm"
                      className="h-7 text-xs bg-emerald-500 hover:bg-emerald-600 text-white"
                      onClick={() => handleAction(item.id, "approve")}
                      disabled={!!acting}
                    >
                      {acting === item.id + "approve"
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : <RiCheckLine className="w-3.5 h-3.5 mr-1" />}
                      采纳并写入规则
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs border-red-300/50 text-red-500 hover:bg-red-500/10"
                      onClick={() => handleAction(item.id, "reject")}
                      disabled={!!acting}
                    >
                      {acting === item.id + "reject"
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : <RiCloseLine className="w-3.5 h-3.5 mr-1" />}
                      拒绝
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs text-muted-foreground hover:text-red-500 ml-auto"
                      onClick={() => handleDelete(item.id)}
                      disabled={!!acting}
                    >
                      <RiDeleteBinLine className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                )}

                {item.status !== "pending" && (
                  <div className="flex justify-end">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs text-muted-foreground hover:text-red-500"
                      onClick={() => handleDelete(item.id)}
                      disabled={!!acting}
                    >
                      <RiDeleteBinLine className="w-3.5 h-3.5 mr-1" />
                      删除记录
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
