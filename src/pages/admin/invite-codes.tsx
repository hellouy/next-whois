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
  RiKeyLine, RiAddLine, RiDeleteBinLine, RiFileCopyLine,
  RiToggleLine, RiToggleFill, RiLoader4Line, RiCloseLine,
  RiCheckLine, RiFilterLine, RiTimeLine,
} from "@remixicon/react";

const CODES_TABS = [
  { href: "/admin/invite-codes",     label: "邀请码" },
  { href: "/admin/activation-codes", label: "激活码" },
];

type InviteCode = {
  id: string;
  code: string;
  description: string | null;
  is_active: boolean;
  max_uses: number;
  use_count: number;
  created_at: string;
  expires_at: string | null;
};

type FilterTab = "all" | "active" | "disabled" | "exhausted" | "expired";

const FILTER_TABS: { key: FilterTab; label: string }[] = [
  { key: "all",      label: "全部" },
  { key: "active",   label: "可用" },
  { key: "disabled", label: "已停用" },
  { key: "exhausted",label: "已耗尽" },
  { key: "expired",  label: "已过期" },
];

const EXPIRY_OPTIONS = [
  { value: "permanent", label: "永久有效" },
  { value: "1d",        label: "1 天" },
  { value: "7d",        label: "1 周" },
  { value: "30d",       label: "1 个月" },
  { value: "365d",      label: "1 年" },
];

function isExpired(c: InviteCode)    { return !!c.expires_at && new Date(c.expires_at) < new Date(); }
function isExhausted(c: InviteCode)  { return c.use_count >= c.max_uses && !isExpired(c); }
function isActive(c: InviteCode)     { return c.is_active && !isExhausted(c) && !isExpired(c); }
function isDisabled(c: InviteCode)   { return !c.is_active && !isExhausted(c) && !isExpired(c); }

function fmtExpiry(expires_at: string | null): string {
  if (!expires_at) return "永久";
  const d = new Date(expires_at);
  const now = new Date();
  const diff = d.getTime() - now.getTime();
  if (diff < 0) return "已过期";
  const days = Math.ceil(diff / 86400000);
  if (days <= 1) return "< 1 天";
  if (days < 7) return `${days} 天`;
  if (days < 30) return `${Math.floor(days / 7)} 周`;
  if (days < 365) return `约 ${Math.floor(days / 30)} 月`;
  return `约 ${Math.floor(days / 365)} 年`;
}

export default function InviteCodesPage() {
  const [codes, setCodes] = React.useState<InviteCode[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [showCreate, setShowCreate] = React.useState(false);
  const [count, setCount] = React.useState("1");
  const [maxUses, setMaxUses] = React.useState("1");
  const [description, setDescription] = React.useState("");
  const [expiresIn, setExpiresIn] = React.useState("permanent");
  const [creating, setCreating] = React.useState(false);
  const [copied, setCopied] = React.useState<string | null>(null);
  const [activeFilter, setActiveFilter] = React.useState<FilterTab>("all");
  const [purgingExhausted, setPurgingExhausted] = React.useState(false);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/invite-codes");
      const d = await r.json();
      if (d.codes) setCodes(d.codes);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      const r = await fetch("/api/admin/invite-codes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          count: parseInt(count) || 1,
          max_uses: parseInt(maxUses) || 1,
          description,
          expires_in: expiresIn,
        }),
      });
      const d = await r.json();
      if (d.created) {
        toast.success(`生成 ${d.created.length} 个邀请码`);
        setShowCreate(false);
        setDescription("");
        setCount("1");
        setMaxUses("1");
        setExpiresIn("permanent");
        load();
      }
    } finally {
      setCreating(false);
    }
  }

  async function toggleActive(code: InviteCode) {
    await fetch("/api/admin/invite-codes", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: code.id, is_active: !code.is_active }),
    });
    setCodes(cs => cs.map(c => c.id === code.id ? { ...c, is_active: !c.is_active } : c));
    toast.success(code.is_active ? "已停用" : "已启用");
  }

  async function deleteCode(code: InviteCode) {
    if (!confirm(`确认删除邀请码 ${code.code}？`)) return;
    await fetch("/api/admin/invite-codes", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: code.id }),
    });
    setCodes(cs => cs.filter(c => c.id !== code.id));
    toast.success("已删除");
  }

  async function purgeExhausted() {
    const targets = codes.filter(c => isExhausted(c) || isExpired(c));
    if (targets.length === 0) return;
    if (!confirm(`确认删除全部 ${targets.length} 个已耗尽/已过期的邀请码？`)) return;
    setPurgingExhausted(true);
    try {
      await Promise.all(targets.map(c =>
        fetch("/api/admin/invite-codes", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: c.id }),
        })
      ));
      setCodes(cs => cs.filter(c => !isExhausted(c) && !isExpired(c)));
      toast.success(`已清除 ${targets.length} 个邀请码`);
      if (activeFilter === "exhausted" || activeFilter === "expired") setActiveFilter("all");
    } finally {
      setPurgingExhausted(false);
    }
  }

  function copy(code: string) {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(code);
      setTimeout(() => setCopied(null), 2000);
    });
  }

  const expiredCount   = codes.filter(isExpired).length;
  const exhaustedCount = codes.filter(isExhausted).length;
  const activeCount    = codes.filter(isActive).length;
  const disabledCount  = codes.filter(isDisabled).length;
  const totalUses      = codes.reduce((s, c) => s + c.use_count, 0);
  const canPurge       = exhaustedCount + expiredCount;

  const filtered = codes.filter(c => {
    if (activeFilter === "active")   return isActive(c);
    if (activeFilter === "disabled") return isDisabled(c);
    if (activeFilter === "exhausted") return isExhausted(c);
    if (activeFilter === "expired")  return isExpired(c);
    return true;
  });

  return (
    <AdminLayout title="邀请码管理">
      <Head><title>邀请码管理 · Admin</title></Head>

      <div className="space-y-5">
        <PageTabs tabs={CODES_TABS} />
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold flex items-center gap-2">
              <RiKeyLine className="w-5 h-5 text-primary" />邀请码管理
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              共 {codes.length} 个 · 累计使用 {totalUses} 次
            </p>
          </div>
          <div className="flex items-center gap-2">
            {canPurge > 0 && (
              <Button
                variant="outline" size="sm"
                className="gap-1.5 rounded-xl h-8 text-muted-foreground border-border/60"
                onClick={purgeExhausted}
                disabled={purgingExhausted}
              >
                {purgingExhausted
                  ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                  : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                清理无效 ({canPurge})
              </Button>
            )}
            <Button size="sm" className="gap-1.5 rounded-xl h-8" onClick={() => setShowCreate(true)}>
              <RiAddLine className="w-3.5 h-3.5" />生成邀请码
            </Button>
          </div>
        </div>

        {/* Stats */}
        {codes.length > 0 && (
          <div className="grid grid-cols-5 gap-2">
            {[
              { label: "全部",   value: codes.length,   color: "text-foreground" },
              { label: "可用",   value: activeCount,    color: "text-emerald-500" },
              { label: "已停用", value: disabledCount,  color: "text-muted-foreground" },
              { label: "已耗尽", value: exhaustedCount, color: "text-amber-500" },
              { label: "已过期", value: expiredCount,   color: "text-red-500" },
            ].map(s => (
              <div key={s.label} className="glass-panel border border-border rounded-xl p-3 text-center">
                <p className={cn("text-2xl font-bold tabular-nums", s.color)}>{s.value}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Filter tabs */}
        {codes.length > 0 && (
          <div className="flex items-center gap-1.5 flex-wrap">
            <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
            {FILTER_TABS.map(tab => {
              const cnt =
                tab.key === "all"      ? codes.length :
                tab.key === "active"   ? activeCount :
                tab.key === "disabled" ? disabledCount :
                tab.key === "exhausted"? exhaustedCount :
                expiredCount;
              return (
                <button
                  key={tab.key}
                  onClick={() => setActiveFilter(tab.key)}
                  className={cn(
                    "text-xs px-3 py-1.5 rounded-full font-medium transition-all",
                    activeFilter === tab.key
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
                  )}
                >
                  {tab.label}
                  <span className={cn("ml-1.5 text-[10px]", activeFilter === tab.key ? "opacity-70" : "opacity-60")}>{cnt}</span>
                </button>
              );
            })}
          </div>
        )}

        {/* Create modal */}
        {showCreate && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setShowCreate(false)}>
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm pointer-events-none" />
            <div className="relative z-10 w-full max-w-sm bg-background border border-border rounded-2xl shadow-2xl p-5 space-y-4" onClick={e => e.stopPropagation()}>
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold">生成邀请码</h2>
                <button onClick={() => setShowCreate(false)} className="p-1 rounded-lg hover:bg-muted">
                  <RiCloseLine className="w-4 h-4 text-muted-foreground" />
                </button>
              </div>
              <form onSubmit={handleCreate} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label className="text-xs">生成数量</Label>
                    <Input type="number" min="1" max="50" value={count} onChange={e => setCount(e.target.value)} className="h-9 rounded-xl" />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">最多使用次数</Label>
                    <Input type="number" min="1" value={maxUses} onChange={e => setMaxUses(e.target.value)} className="h-9 rounded-xl" />
                  </div>
                </div>

                {/* Expiry */}
                <div className="space-y-1.5">
                  <Label className="text-xs flex items-center gap-1.5">
                    <RiTimeLine className="w-3.5 h-3.5 text-muted-foreground/70" />
                    有效期
                  </Label>
                  <div className="flex flex-wrap gap-1.5">
                    {EXPIRY_OPTIONS.map(opt => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => setExpiresIn(opt.value)}
                        className={cn(
                          "text-xs px-3 py-1.5 rounded-full font-medium border transition-all",
                          expiresIn === opt.value
                            ? "bg-primary text-primary-foreground border-primary"
                            : "border-border text-muted-foreground hover:bg-muted hover:text-foreground"
                        )}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1">
                  <Label className="text-xs">备注 <span className="text-muted-foreground font-normal">（可选）</span></Label>
                  <Input value={description} onChange={e => setDescription(e.target.value)} placeholder="这批邀请码的用途" className="h-9 rounded-xl" maxLength={100} />
                </div>
                <Button type="submit" disabled={creating} className="w-full h-9 rounded-xl gap-1.5">
                  {creating ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />生成中…</> : <><RiKeyLine className="w-3.5 h-3.5" />生成</>}
                </Button>
              </form>
            </div>
          </div>
        )}

        {/* Table */}
        {loading ? (
          <div className="flex justify-center py-12">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-sm text-muted-foreground">
            {codes.length === 0 ? "暂无邀请码，点击右上角生成" : "该筛选条件下暂无邀请码"}
          </div>
        ) : (
          <div className="rounded-2xl border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 border-b border-border text-xs text-muted-foreground">
                  <th className="text-left px-4 py-2.5 font-semibold">邀请码</th>
                  <th className="text-left px-4 py-2.5 font-semibold hidden sm:table-cell">备注</th>
                  <th className="text-left px-4 py-2.5 font-semibold hidden md:table-cell">有效期</th>
                  <th className="text-left px-4 py-2.5 font-semibold">使用进度</th>
                  <th className="text-center px-3 py-2.5 font-semibold">状态</th>
                  <th className="text-right px-4 py-2.5 font-semibold">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {filtered.map(c => {
                  const expired   = isExpired(c);
                  const exhausted = isExhausted(c);
                  const pct = c.max_uses > 0 ? Math.round((c.use_count / c.max_uses) * 100) : 0;
                  const faded = (!c.is_active && !exhausted && !expired) || exhausted || expired;
                  return (
                    <tr key={c.id} className={cn("hover:bg-muted/20 transition-colors", faded && "opacity-50")}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold tracking-wider">{c.code}</span>
                          <button
                            onClick={() => copy(c.code)}
                            className="text-muted-foreground/50 hover:text-primary transition-colors"
                            title="复制"
                          >
                            {copied === c.code
                              ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500" />
                              : <RiFileCopyLine className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                        <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                          {new Date(c.created_at).toLocaleDateString("zh-CN")}
                        </p>
                      </td>
                      <td className="px-4 py-3 hidden sm:table-cell">
                        <span className="text-xs text-muted-foreground">{c.description || "—"}</span>
                      </td>
                      <td className="px-4 py-3 hidden md:table-cell">
                        <span className={cn(
                          "text-xs font-medium flex items-center gap-1",
                          expired ? "text-red-500" :
                          c.expires_at ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"
                        )}>
                          <RiTimeLine className="w-3 h-3" />
                          {fmtExpiry(c.expires_at)}
                        </span>
                        {c.expires_at && !expired && (
                          <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                            {new Date(c.expires_at).toLocaleDateString("zh-CN")}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5 min-w-[90px]">
                          <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                            <div
                              className={cn(
                                "h-full rounded-full transition-all",
                                exhausted || expired ? "bg-muted-foreground/40" :
                                pct >= 80 ? "bg-amber-500" : "bg-emerald-500"
                              )}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-xs font-semibold tabular-nums text-muted-foreground w-12 text-right shrink-0">
                            {c.use_count}/{c.max_uses}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-3 text-center">
                        <span className={cn(
                          "text-xs px-2 py-0.5 rounded-full font-medium",
                          expired    ? "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400" :
                          exhausted  ? "bg-muted text-muted-foreground" :
                          c.is_active? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400" :
                                       "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400"
                        )}>
                          {expired ? "已过期" : exhausted ? "已耗尽" : c.is_active ? "可用" : "已停用"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {!exhausted && !expired && (
                            <button
                              onClick={() => toggleActive(c)}
                              title={c.is_active ? "停用" : "启用"}
                              className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                            >
                              {c.is_active
                                ? <RiToggleFill className="w-4 h-4 text-emerald-500" />
                                : <RiToggleLine className="w-4 h-4" />}
                            </button>
                          )}
                          <button
                            onClick={() => deleteCode(c)}
                            title="删除"
                            className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/20 text-muted-foreground hover:text-red-500 transition-colors"
                          >
                            <RiDeleteBinLine className="w-4 h-4" />
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
      </div>
    </AdminLayout>
  );
}
