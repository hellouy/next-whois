import React from "react";
import Head from "next/head";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

import {
  RiAddLine, RiDeleteBinLine, RiFileCopyLine,
  RiLoader4Line, RiGiftLine, RiCheckLine,
  RiFilterLine, RiTimeLine, RiVipCrownLine, RiCoinLine,
} from "@remixicon/react";

const CODES_TABS = [
  { href: "/admin/invite-codes",     label: "邀请码" },
  { href: "/admin/activation-codes", label: "激活码" },
];

type ActivationCode = {
  id: number;
  code: string;
  plan_name: string;
  duration_days: number | null;
  grants_subscription: boolean;
  balance_grant_cents: number;
  used: boolean;
  used_at: string | null;
  used_by_email: string | null;
  note: string | null;
  expires_at: string | null;
  created_at: string;
};

type FilterTab = "all" | "unused" | "used" | "expired";

const EXPIRY_OPTIONS = [
  { value: "permanent", label: "永久有效" },
  { value: "7d",  label: "7 天" },
  { value: "30d", label: "30 天" },
  { value: "365d", label: "1 年" },
];

function isExpired(c: ActivationCode) {
  return !!c.expires_at && !c.used && new Date(c.expires_at) < new Date();
}

function fmtDate(s: string | null) {
  if (!s) return "—";
  return new Date(s).toLocaleDateString("zh-CN");
}

export default function ActivationCodesPage() {
  const [codes, setCodes] = React.useState<ActivationCode[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [showCreate, setShowCreate] = React.useState(false);
  const [count, setCount] = React.useState("1");
  const [planName, setPlanName] = React.useState("年度会员");
  const [durationDays, setDurationDays] = React.useState("365");
  const [grantsSubscription, setGrantsSubscription] = React.useState(true);
  const [balanceCents, setBalanceCents] = React.useState("0");
  const [expiresIn, setExpiresIn] = React.useState("permanent");
  const [note, setNote] = React.useState("");
  const [creating, setCreating] = React.useState(false);
  const [copied, setCopied] = React.useState<string | null>(null);
  const [filterTab, setFilterTab] = React.useState<FilterTab>("all");
  const [deleting, setDeleting] = React.useState<number | null>(null);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/activation-codes");
      const d = await r.json();
      setCodes(d.codes ?? []);
    } catch { toast.error("加载失败"); }
    finally { setLoading(false); }
  }

  React.useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    const n = parseInt(count) || 1;
    if (n < 1 || n > 100) { toast.error("数量需在 1-100 之间"); return; }
    setCreating(true);
    try {
      const res = await fetch("/api/admin/activation-codes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          count: n,
          plan_name: planName.trim() || "会员套餐",
          duration_days: grantsSubscription ? (parseInt(durationDays) || null) : null,
          grants_subscription: grantsSubscription,
          balance_grant_cents: Math.max(0, parseInt(balanceCents) || 0),
          note: note.trim() || null,
          expires_in: expiresIn,
        }),
      });
      const d = await res.json();
      if (res.ok) {
        toast.success(`已生成 ${d.created.length} 个激活码`);
        setShowCreate(false);
        setNote("");
        load();
        if (d.created.length > 0) {
          await navigator.clipboard.writeText(d.created.join("\n")).catch(() => {});
          toast.success("激活码已复制到剪贴板");
        }
      } else {
        toast.error(d.error || "创建失败");
      }
    } catch { toast.error("网络错误"); }
    finally { setCreating(false); }
  }

  async function handleDelete(id: number) {
    if (!confirm("确认删除此激活码？已使用的无法删除。")) return;
    setDeleting(id);
    try {
      const res = await fetch("/api/admin/activation-codes", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const d = await res.json();
      if (res.ok) {
        setCodes(prev => prev.filter(c => c.id !== id));
        toast.success("已删除");
      } else {
        toast.error(d.error || "删除失败");
      }
    } catch { toast.error("网络错误"); }
    finally { setDeleting(null); }
  }

  async function copyCode(code: string) {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(code);
      setTimeout(() => setCopied(null), 1500);
    } catch { toast.error("复制失败"); }
  }

  const filtered = codes.filter(c => {
    if (filterTab === "unused")  return !c.used && !isExpired(c);
    if (filterTab === "used")    return c.used;
    if (filterTab === "expired") return isExpired(c);
    return true;
  });

  const FILTER_TABS: { key: FilterTab; label: string }[] = [
    { key: "all",     label: `全部 (${codes.length})` },
    { key: "unused",  label: `未使用 (${codes.filter(c => !c.used && !isExpired(c)).length})` },
    { key: "used",    label: `已使用 (${codes.filter(c => c.used).length})` },
    { key: "expired", label: `已过期 (${codes.filter(c => isExpired(c)).length})` },
  ];

  return (
    <AdminLayout title="激活码管理">
      <Head><title>激活码管理 · 管理后台</title></Head>
      <div className="space-y-4">
        <PageTabs tabs={CODES_TABS} />
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <RiGiftLine className="w-4 h-4 text-amber-500" />
            <h1 className="text-sm font-bold">激活码管理</h1>
          </div>
          <Button size="sm" className="h-8 rounded-xl text-xs gap-1" onClick={() => setShowCreate(v => !v)}>
            <RiAddLine className="w-3.5 h-3.5" /> 生成激活码
          </Button>
        </div>

        {/* Create form */}
        {showCreate && (
          <form onSubmit={handleCreate} className="glass-panel border border-border rounded-2xl p-4 space-y-3">
            <p className="text-xs font-semibold">生成新激活码</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-[11px]">数量</Label>
                <Input type="number" min="1" max="100" value={count} onChange={e => setCount(e.target.value)} className="h-8 rounded-xl text-sm" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-[11px]">套餐名称（显示用）</Label>
                <Input value={planName} onChange={e => setPlanName(e.target.value)} className="h-8 rounded-xl text-sm" placeholder="年度会员" />
              </div>
            </div>

            <div className="flex items-center gap-3 py-1">
              <label className="flex items-center gap-2 text-[11px] font-semibold cursor-pointer">
                <input type="checkbox" checked={grantsSubscription} onChange={e => setGrantsSubscription(e.target.checked)} className="rounded" />
                授予会员权限
              </label>
            </div>

            {grantsSubscription && (
              <div className="space-y-1.5">
                <Label className="text-[11px]">会员时长（天，留空=永久）</Label>
                <Input type="number" min="1" value={durationDays} onChange={e => setDurationDays(e.target.value)}
                  className="h-8 rounded-xl text-sm" placeholder="365 = 1年，留空 = 永久" />
              </div>
            )}

            <div className="space-y-1.5">
              <Label className="text-[11px]">赠送余额（分，100=¥1.00）</Label>
              <Input type="number" min="0" value={balanceCents} onChange={e => setBalanceCents(e.target.value)} className="h-8 rounded-xl text-sm" />
            </div>

            <div className="space-y-1.5">
              <Label className="text-[11px]">激活码有效期</Label>
              <div className="flex flex-wrap gap-1.5">
                {EXPIRY_OPTIONS.map(o => (
                  <button key={o.value} type="button" onClick={() => setExpiresIn(o.value)}
                    className={cn("px-2.5 py-1 rounded-lg text-[11px] font-medium border transition-all",
                      expiresIn === o.value ? "bg-primary text-primary-foreground border-primary" : "border-border hover:border-primary/50"
                    )}>
                    {o.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-[11px]">备注（可选）</Label>
              <Input value={note} onChange={e => setNote(e.target.value)} className="h-8 rounded-xl text-sm" placeholder="内部备注信息" />
            </div>

            <div className="flex gap-2 pt-1">
              <Button type="submit" disabled={creating} size="sm" className="h-8 rounded-xl text-xs gap-1">
                {creating ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiAddLine className="w-3.5 h-3.5" />}
                {creating ? "生成中…" : "生成"}
              </Button>
              <Button type="button" variant="outline" size="sm" className="h-8 rounded-xl text-xs" onClick={() => setShowCreate(false)}>
                取消
              </Button>
            </div>
          </form>
        )}

        {/* Filter tabs */}
        <div className="flex gap-1 flex-wrap">
          {FILTER_TABS.map(t => (
            <button key={t.key} onClick={() => setFilterTab(t.key)}
              className={cn("px-2.5 py-1 rounded-lg text-[11px] font-medium border transition-all",
                filterTab === t.key ? "bg-primary text-primary-foreground border-primary" : "border-border hover:border-primary/50"
              )}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Table */}
        {loading ? (
          <div className="space-y-2 animate-pulse">
            {[1,2,3].map(i => <div key={i} className="h-16 rounded-xl bg-muted/50" />)}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center text-sm text-muted-foreground">
            <RiGiftLine className="w-8 h-8 mx-auto mb-2 text-muted-foreground/30" />
            暂无激活码
          </div>
        ) : (
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <div className="divide-y divide-border/60">
              {filtered.map(c => {
                const expired = isExpired(c);
                return (
                  <div key={c.id} className="px-4 py-3 flex items-start gap-3">
                    {/* Status icon */}
                    <div className={cn(
                      "w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5",
                      c.used ? "bg-emerald-50 dark:bg-emerald-950/30" :
                        expired ? "bg-muted" : "bg-amber-50 dark:bg-amber-950/20"
                    )}>
                      {c.used
                        ? <RiCheckLine className="w-4 h-4 text-emerald-500" />
                        : expired
                          ? <RiTimeLine className="w-4 h-4 text-muted-foreground" />
                          : <RiGiftLine className="w-4 h-4 text-amber-500" />}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <code className="text-xs font-bold font-mono tracking-wider">{c.code}</code>
                        <span className={cn(
                          "text-[9px] font-bold px-1.5 py-0.5 rounded-full",
                          c.used ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300" :
                            expired ? "bg-muted text-muted-foreground" :
                              "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
                        )}>
                          {c.used ? "已使用" : expired ? "已过期" : "可用"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 mt-1 flex-wrap">
                        {c.grants_subscription && (
                          <span className="flex items-center gap-0.5 text-[10px] text-violet-600 dark:text-violet-400">
                            <RiVipCrownLine className="w-3 h-3" />
                            {c.plan_name}{c.duration_days ? ` (${c.duration_days}天)` : " (永久)"}
                          </span>
                        )}
                        {c.balance_grant_cents > 0 && (
                          <span className="flex items-center gap-0.5 text-[10px] text-emerald-600 dark:text-emerald-400">
                            <RiCoinLine className="w-3 h-3" />
                            +¥{(c.balance_grant_cents / 100).toFixed(2)}
                          </span>
                        )}
                        {c.used && c.used_by_email && (
                          <span className="text-[10px] text-muted-foreground">
                            使用者: {c.used_by_email} · {fmtDate(c.used_at)}
                          </span>
                        )}
                        {!c.used && c.expires_at && (
                          <span className="flex items-center gap-0.5 text-[10px] text-muted-foreground">
                            <RiTimeLine className="w-3 h-3" /> 至 {fmtDate(c.expires_at)}
                          </span>
                        )}
                        {c.note && (
                          <span className="text-[10px] text-muted-foreground italic truncate max-w-[120px]">{c.note}</span>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1 shrink-0">
                      <button onClick={() => copyCode(c.code)}
                        className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                        title="复制激活码">
                        {copied === c.code
                          ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500" />
                          : <RiFileCopyLine className="w-3.5 h-3.5" />}
                      </button>
                      {!c.used && (
                        <button onClick={() => handleDelete(c.id)} disabled={deleting === c.id}
                          className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors text-muted-foreground hover:text-red-500"
                          title="删除">
                          {deleting === c.id
                            ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                            : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
