import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  RiShieldUserLine, RiKeyLine, RiGiftLine,
  RiAddLine, RiDeleteBinLine, RiFileCopyLine,
  RiToggleLine, RiToggleFill, RiLoader4Line, RiCloseLine,
  RiCheckLine, RiFilterLine, RiTimeLine, RiLockLine, RiLockUnlockLine,
  RiVipCrownLine, RiCoinLine,
} from "@remixicon/react";

type MainTab = "keys" | "invite" | "activation";

/* ── Access Keys ────────────────────────────────────────────────────────── */
type Scope = "api" | "subscription" | "all";
type AccessKey = {
  id: string; key: string; label: string | null; scope: Scope;
  is_active: boolean; created_at: string; expires_at: string | null;
  last_used_at: string | null; use_count: number;
};
const SCOPE_LABELS: Record<Scope, { label: string; color: string }> = {
  api:          { label: "API",      color: "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-400" },
  subscription: { label: "域名订阅", color: "bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400" },
  all:          { label: "全部权限", color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400" },
};

/* ── Invite Codes ───────────────────────────────────────────────────────── */
type InviteCode = {
  id: string; code: string; description: string | null;
  is_active: boolean; max_uses: number; use_count: number;
  created_at: string; expires_at: string | null;
};

/* ── Activation Codes ───────────────────────────────────────────────────── */
type ActivationCode = {
  id: number; code: string; plan_name: string;
  duration_days: number | null; grants_subscription: boolean;
  balance_grant_cents: number; used: boolean; used_at: string | null;
  used_by_email: string | null; note: string | null;
  expires_at: string | null; created_at: string;
};

/* ── Helpers ────────────────────────────────────────────────────────────── */
const EXPIRY_OPTIONS = [
  { value: "permanent", label: "永久" },
  { value: "7d",  label: "7 天" },
  { value: "30d", label: "30 天" },
  { value: "365d", label: "1 年" },
];
const BATCH_OPTIONS = [1, 5, 10, 20];

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
  return s ? new Date(s).toLocaleDateString("zh-CN") : "—";
}
function isKeyExpired(k: AccessKey) { return !!k.expires_at && new Date(k.expires_at) < new Date(); }
function isCodeExpired(c: InviteCode) { return !!c.expires_at && new Date(c.expires_at) < new Date(); }
function isCodeExhausted(c: InviteCode) { return c.use_count >= c.max_uses; }
function isActExpired(c: ActivationCode) { return !!c.expires_at && !c.used && new Date(c.expires_at) < new Date(); }

/* ── Modal wrapper ──────────────────────────────────────────────────────── */
function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm pointer-events-none" />
      <div className="relative z-10 w-full sm:max-w-sm bg-background border border-border rounded-t-3xl sm:rounded-2xl shadow-2xl p-5 space-y-4 max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold">{title}</h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted">
            <RiCloseLine className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

/* ── API Keys Tab ───────────────────────────────────────────────────────── */
function KeysTab() {
  const [keys, setKeys] = React.useState<AccessKey[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [requireApiKey, setRequireApiKey] = React.useState(false);
  const [togglingRequire, setTogglingRequire] = React.useState(false);
  const [showCreate, setShowCreate] = React.useState(false);
  const [label, setLabel] = React.useState("");
  const [scope, setScope] = React.useState<Scope>("api");
  const [expiresAt, setExpiresAt] = React.useState("");
  const [batchCount, setBatchCount] = React.useState(1);
  const [creating, setCreating] = React.useState(false);
  const [copied, setCopied] = React.useState<string | null>(null);
  const [newKeys, setNewKeys] = React.useState<string[]>([]);
  const [statusFilter, setStatusFilter] = React.useState<"all"|"active"|"disabled"|"expired">("all");

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/access-keys");
      const d = await r.json();
      if (d.keys) setKeys(d.keys);
      setRequireApiKey(!!d.require_api_key);
    } finally { setLoading(false); }
  }
  React.useEffect(() => { load(); }, []);

  async function toggleRequire() {
    setTogglingRequire(true);
    try {
      const next = !requireApiKey;
      await fetch("/api/admin/access-keys", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "toggle_require", enabled: next }) });
      setRequireApiKey(next);
      toast.success(next ? "已开启 API Key 验证" : "已关闭 API Key 验证");
    } finally { setTogglingRequire(false); }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      const r = await fetch("/api/admin/access-keys", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label, scope, expires_at: expiresAt || undefined, count: batchCount }) });
      const d = await r.json();
      if (d.ok && d.keys) {
        const keyValues = (d.keys as AccessKey[]).map((k: AccessKey) => k.key);
        setNewKeys(keyValues);
        setShowCreate(false);
        setLabel(""); setScope("api"); setExpiresAt(""); setBatchCount(1);
        load();
        toast.success(`已生成 ${d.count} 个 API Key`);
      } else { toast.error(d.error || "生成失败"); }
    } finally { setCreating(false); }
  }

  async function toggleActive(k: AccessKey) {
    await fetch("/api/admin/access-keys", { method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: k.id, is_active: !k.is_active }) });
    setKeys(ks => ks.map(x => x.id === k.id ? { ...x, is_active: !x.is_active } : x));
    toast.success(k.is_active ? "已停用" : "已启用");
  }

  async function deleteKey(k: AccessKey) {
    if (!confirm(`确认删除 Key "${k.label || k.key.slice(0, 12) + "…"}"？`)) return;
    await fetch("/api/admin/access-keys", { method: "DELETE", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: k.id }) });
    setKeys(ks => ks.filter(x => x.id !== k.id));
    toast.success("已删除");
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => { setCopied(text); setTimeout(() => setCopied(null), 2000); });
  }

  const filtered = keys.filter(k =>
    statusFilter === "active"   ? k.is_active && !isKeyExpired(k) :
    statusFilter === "disabled" ? !k.is_active && !isKeyExpired(k) :
    statusFilter === "expired"  ? isKeyExpired(k) : true
  );
  const expiredCount = keys.filter(isKeyExpired).length;
  const totalUses = keys.reduce((s, k) => s + k.use_count, 0);

  return (
    <div className="space-y-4">
      {/* Global toggle */}
      <div className="rounded-2xl border border-border bg-muted/20 p-4 flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-semibold flex items-center gap-1.5">
            {requireApiKey ? <RiLockLine className="w-4 h-4 text-amber-500" /> : <RiLockUnlockLine className="w-4 h-4 text-muted-foreground" />}
            API Key 验证
          </p>
          <p className="text-xs text-muted-foreground mt-0.5">
            {requireApiKey ? "已开启：所有 API 请求必须携带有效 Key" : "已关闭：API 无需 Key 即可访问"}
          </p>
        </div>
        <button onClick={toggleRequire} disabled={togglingRequire} className="shrink-0">
          {togglingRequire ? <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
            : requireApiKey ? <RiToggleFill className="w-8 h-8 text-emerald-500" /> : <RiToggleLine className="w-8 h-8 text-muted-foreground" />}
        </button>
      </div>

      {/* Header row */}
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">共 {keys.length} 个 · 累计调用 {totalUses.toLocaleString()} 次</p>
        <div className="flex gap-2">
          {expiredCount > 0 && (
            <Button variant="outline" size="sm" className="gap-1.5 h-8 rounded-xl text-xs text-muted-foreground"
              onClick={async () => {
                if (!confirm(`删除全部 ${expiredCount} 个已过期 Key？`)) return;
                const expired = keys.filter(isKeyExpired);
                await Promise.all(expired.map(k => fetch("/api/admin/access-keys", { method: "DELETE",
                  headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: k.id }) })));
                setKeys(ks => ks.filter(k => !isKeyExpired(k)));
                toast.success(`已清除 ${expiredCount} 个过期 Key`);
              }}>
              <RiDeleteBinLine className="w-3.5 h-3.5" />清理过期 ({expiredCount})
            </Button>
          )}
          <Button size="sm" className="gap-1.5 h-8 rounded-xl" onClick={() => setShowCreate(true)}>
            <RiAddLine className="w-3.5 h-3.5" />生成 Key
          </Button>
        </div>
      </div>

      {/* Stats */}
      {keys.length > 0 && (
        <div className="grid grid-cols-4 gap-2">
          {[
            { label: "全部",   value: keys.length,                                  color: "text-foreground" },
            { label: "启用中", value: keys.filter(k => k.is_active && !isKeyExpired(k)).length, color: "text-emerald-500" },
            { label: "已停用", value: keys.filter(k => !k.is_active && !isKeyExpired(k)).length, color: "text-muted-foreground" },
            { label: "已过期", value: expiredCount,                                  color: "text-red-500" },
          ].map(s => (
            <div key={s.label} className="glass-panel border border-border rounded-xl p-3 text-center">
              <p className={cn("text-xl font-bold tabular-nums", s.color)}>{s.value}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* New keys reveal */}
      {newKeys.length > 0 && (
        <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-2">
          <p className="text-xs font-semibold text-emerald-700 dark:text-emerald-400">
            ✓ 已生成 {newKeys.length} 个 Key，请立即复制 — 关闭后不再显示完整 Key
          </p>
          {newKeys.map(k => (
            <div key={k} className="flex items-center gap-2">
              <code className="flex-1 font-mono text-xs bg-background border border-border rounded-lg px-3 py-1.5 break-all">{k}</code>
              <button onClick={() => copy(k)} className="shrink-0 p-2 rounded-lg border border-border bg-background hover:bg-muted transition-colors">
                {copied === k ? <RiCheckLine className="w-4 h-4 text-emerald-500" /> : <RiFileCopyLine className="w-4 h-4 text-muted-foreground" />}
              </button>
            </div>
          ))}
          {newKeys.length > 1 && (
            <button onClick={() => { navigator.clipboard.writeText(newKeys.join("\n")); toast.success("已复制全部"); }}
              className="text-xs text-primary hover:underline">复制全部</button>
          )}
          <button onClick={() => setNewKeys([])} className="block text-xs text-muted-foreground hover:text-foreground transition-colors">
            我已保存，关闭提示
          </button>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
        {(["all","active","disabled","expired"] as const).map(f => (
          <button key={f} onClick={() => setStatusFilter(f)}
            className={cn("text-xs px-3 py-1.5 rounded-full font-medium transition-all",
              statusFilter === f ? "bg-primary text-primary-foreground" : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground")}>
            {f === "all" ? "全部" : f === "active" ? "启用" : f === "disabled" ? "停用" : "过期"}
          </button>
        ))}
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex justify-center py-12"><RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" /></div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12 text-sm text-muted-foreground">
          {keys.length === 0 ? "暂无 API Key，点击右上角生成" : "该筛选条件下暂无 Key"}
        </div>
      ) : (
        <div className="rounded-2xl border border-border overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/40 border-b border-border text-xs text-muted-foreground">
                <th className="text-left px-4 py-2.5 font-semibold">Key / 备注</th>
                <th className="text-left px-3 py-2.5 font-semibold hidden sm:table-cell">范围</th>
                <th className="text-center px-3 py-2.5 font-semibold hidden md:table-cell">调用</th>
                <th className="text-center px-3 py-2.5 font-semibold">状态</th>
                <th className="text-right px-4 py-2.5 font-semibold">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(k => {
                const expired = isKeyExpired(k);
                const sc = SCOPE_LABELS[k.scope] ?? SCOPE_LABELS.api;
                return (
                  <tr key={k.id} className={cn("hover:bg-muted/20 transition-colors", (!k.is_active || expired) && "opacity-50")}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold tracking-wider text-muted-foreground">
                          {k.key.slice(0, 8)}••••{k.key.slice(-6)}
                        </span>
                        <button onClick={() => copy(k.key)} className="text-muted-foreground/50 hover:text-primary transition-colors">
                          {copied === k.key ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                      <p className="text-[10px] text-muted-foreground/70 mt-0.5">
                        {k.label ? <span className="font-medium">{k.label}</span> : <span className="italic">无备注</span>}
                        {" · "}{fmtDate(k.created_at)}
                        {k.expires_at && <span className={cn("ml-1", expired ? "text-red-500" : "")}>· {expired ? "已过期" : "至"} {fmtDate(k.expires_at)}</span>}
                      </p>
                    </td>
                    <td className="px-3 py-3 hidden sm:table-cell">
                      <span className={cn("text-xs font-medium px-2 py-0.5 rounded-full", sc.color)}>{sc.label}</span>
                    </td>
                    <td className="px-3 py-3 text-center hidden md:table-cell">
                      <p className="text-xs font-semibold tabular-nums">{k.use_count.toLocaleString()}</p>
                      <p className="text-[10px] text-muted-foreground/60 mt-0.5 flex items-center justify-center gap-0.5">
                        <RiTimeLine className="w-3 h-3" />{k.last_used_at ? fmtRel(k.last_used_at) : "从未"}
                      </p>
                    </td>
                    <td className="px-3 py-3 text-center">
                      <span className={cn("text-xs px-2 py-0.5 rounded-full font-medium",
                        expired ? "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400"
                          : k.is_active ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400"
                            : "bg-muted text-muted-foreground")}>
                        {expired ? "过期" : k.is_active ? "启用" : "停用"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        {!expired && (
                          <button onClick={() => toggleActive(k)} className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                            {k.is_active ? <RiToggleFill className="w-4 h-4 text-emerald-500" /> : <RiToggleLine className="w-4 h-4" />}
                          </button>
                        )}
                        <button onClick={() => deleteKey(k)} className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/20 text-muted-foreground hover:text-red-500 transition-colors">
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
        </div>
      )}

      {/* Create Modal */}
      {showCreate && (
        <Modal title="生成 API Key" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleCreate} className="space-y-3">
            <div className="space-y-1">
              <Label className="text-xs">批量数量</Label>
              <div className="flex gap-1.5">
                {BATCH_OPTIONS.map(n => (
                  <button key={n} type="button" onClick={() => setBatchCount(n)}
                    className={cn("flex-1 py-2 rounded-xl border text-xs font-semibold transition-all",
                      batchCount === n ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-muted")}>
                    {n}
                  </button>
                ))}
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">备注 <span className="text-muted-foreground font-normal">（可选）</span></Label>
              <Input value={label} onChange={e => setLabel(e.target.value)} placeholder="如：生产环境、测试用途" className="h-9 rounded-xl" maxLength={80} />
            </div>
            <div className="space-y-1">
              <Label className="text-xs">权限范围</Label>
              <div className="grid grid-cols-3 gap-2">
                {(["api", "subscription", "all"] as Scope[]).map(s => (
                  <button key={s} type="button" onClick={() => setScope(s)}
                    className={cn("py-2 rounded-xl border text-xs font-medium transition-all",
                      scope === s ? "border-primary bg-primary/10 text-primary" : "border-border bg-muted/30 text-muted-foreground hover:bg-muted")}>
                    {SCOPE_LABELS[s].label}
                  </button>
                ))}
              </div>
              <p className="text-[10px] text-muted-foreground">
                {scope === "api" && "仅 WHOIS / DNS / SSL / IP 查询 API"}
                {scope === "subscription" && "仅域名到期订阅提醒"}
                {scope === "all" && "全部 API 功能及订阅提醒"}
              </p>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">过期时间 <span className="text-muted-foreground font-normal">（留空为永久）</span></Label>
              <Input type="date" value={expiresAt} onChange={e => setExpiresAt(e.target.value)} className="h-9 rounded-xl" min={new Date().toISOString().slice(0, 10)} />
            </div>
            <Button type="submit" disabled={creating} className="w-full h-9 rounded-xl gap-1.5">
              {creating ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />生成中…</> : <><RiShieldUserLine className="w-3.5 h-3.5" />生成 {batchCount} 个</>}
            </Button>
          </form>
        </Modal>
      )}
    </div>
  );
}

/* ── Invite Codes Tab ───────────────────────────────────────────────────── */
function InviteTab() {
  const [codes, setCodes] = React.useState<InviteCode[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [showCreate, setShowCreate] = React.useState(false);
  const [count, setCount] = React.useState("1");
  const [maxUses, setMaxUses] = React.useState("1");
  const [description, setDescription] = React.useState("");
  const [expiresIn, setExpiresIn] = React.useState("permanent");
  const [creating, setCreating] = React.useState(false);
  const [copied, setCopied] = React.useState<string | null>(null);
  const [activeFilter, setActiveFilter] = React.useState<"all"|"active"|"disabled"|"exhausted"|"expired">("all");

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/invite-codes");
      const d = await r.json();
      if (d.codes) setCodes(d.codes);
    } finally { setLoading(false); }
  }
  React.useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      const r = await fetch("/api/admin/invite-codes", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: parseInt(count) || 1, max_uses: parseInt(maxUses) || 1, description, expires_in: expiresIn }) });
      const d = await r.json();
      if (d.created) {
        toast.success(`已生成 ${d.created.length} 个邀请码`);
        setShowCreate(false); setDescription(""); setCount("1"); setMaxUses("1"); setExpiresIn("permanent");
        load();
      }
    } finally { setCreating(false); }
  }

  async function toggleActive(code: InviteCode) {
    await fetch("/api/admin/invite-codes", { method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: code.id, is_active: !code.is_active }) });
    setCodes(cs => cs.map(c => c.id === code.id ? { ...c, is_active: !c.is_active } : c));
    toast.success(code.is_active ? "已停用" : "已启用");
  }

  async function deleteCode(code: InviteCode) {
    if (!confirm(`确认删除邀请码 ${code.code}？`)) return;
    await fetch("/api/admin/invite-codes", { method: "DELETE", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: code.id }) });
    setCodes(cs => cs.filter(c => c.id !== code.id));
    toast.success("已删除");
  }

  function copy(code: string) {
    navigator.clipboard.writeText(code).then(() => { setCopied(code); setTimeout(() => setCopied(null), 2000); });
  }

  const expiredCount = codes.filter(isCodeExpired).length;
  const exhaustedCount = codes.filter(isCodeExhausted).length;
  const activeCount = codes.filter(c => c.is_active && !isCodeExhausted(c) && !isCodeExpired(c)).length;
  const canPurge = expiredCount + exhaustedCount;

  const filtered = codes.filter(c =>
    activeFilter === "active"   ? c.is_active && !isCodeExhausted(c) && !isCodeExpired(c) :
    activeFilter === "disabled" ? !c.is_active && !isCodeExhausted(c) && !isCodeExpired(c) :
    activeFilter === "exhausted"? isCodeExhausted(c) :
    activeFilter === "expired"  ? isCodeExpired(c) : true
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">共 {codes.length} 个 · 累计使用 {codes.reduce((s,c) => s + c.use_count, 0)} 次</p>
        <div className="flex gap-2">
          {canPurge > 0 && (
            <Button variant="outline" size="sm" className="gap-1.5 h-8 rounded-xl text-xs text-muted-foreground"
              onClick={async () => {
                const targets = codes.filter(c => isCodeExhausted(c) || isCodeExpired(c));
                if (!confirm(`删除全部 ${targets.length} 个已耗尽/已过期邀请码？`)) return;
                await Promise.all(targets.map(c => fetch("/api/admin/invite-codes", { method: "DELETE",
                  headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: c.id }) })));
                setCodes(cs => cs.filter(c => !isCodeExhausted(c) && !isCodeExpired(c)));
                toast.success(`已清除 ${targets.length} 个邀请码`);
              }}>
              <RiDeleteBinLine className="w-3.5 h-3.5" />清理无效 ({canPurge})
            </Button>
          )}
          <Button size="sm" className="gap-1.5 h-8 rounded-xl" onClick={() => setShowCreate(true)}>
            <RiAddLine className="w-3.5 h-3.5" />生成邀请码
          </Button>
        </div>
      </div>

      {codes.length > 0 && (
        <div className="grid grid-cols-5 gap-2">
          {[
            { label: "全部",   value: codes.length,   color: "text-foreground" },
            { label: "可用",   value: activeCount,    color: "text-emerald-500" },
            { label: "已停用", value: codes.filter(c => !c.is_active && !isCodeExhausted(c) && !isCodeExpired(c)).length, color: "text-muted-foreground" },
            { label: "已耗尽", value: exhaustedCount, color: "text-amber-500" },
            { label: "已过期", value: expiredCount,   color: "text-red-500" },
          ].map(s => (
            <div key={s.label} className="glass-panel border border-border rounded-xl p-2.5 text-center">
              <p className={cn("text-lg font-bold tabular-nums", s.color)}>{s.value}</p>
              <p className="text-[10px] text-muted-foreground">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-1.5 flex-wrap">
        <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
        {(["all","active","disabled","exhausted","expired"] as const).map(f => (
          <button key={f} onClick={() => setActiveFilter(f)}
            className={cn("text-xs px-3 py-1.5 rounded-full font-medium transition-all",
              activeFilter === f ? "bg-primary text-primary-foreground" : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground")}>
            {f === "all" ? "全部" : f === "active" ? "可用" : f === "disabled" ? "停用" : f === "exhausted" ? "已耗尽" : "已过期"}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12"><RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" /></div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12 text-sm text-muted-foreground">{codes.length === 0 ? "暂无邀请码，点击右上角生成" : "该筛选条件下暂无记录"}</div>
      ) : (
        <div className="rounded-2xl border border-border overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/40 border-b border-border text-xs text-muted-foreground">
                <th className="text-left px-4 py-2.5 font-semibold">邀请码</th>
                <th className="text-left px-3 py-2.5 font-semibold hidden sm:table-cell">备注</th>
                <th className="text-center px-3 py-2.5 font-semibold">使用进度</th>
                <th className="text-center px-3 py-2.5 font-semibold">状态</th>
                <th className="text-right px-4 py-2.5 font-semibold">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(c => {
                const expired = isCodeExpired(c);
                const exhausted = isCodeExhausted(c);
                const pct = c.max_uses > 0 ? Math.round((c.use_count / c.max_uses) * 100) : 0;
                return (
                  <tr key={c.id} className={cn("hover:bg-muted/20 transition-colors", (expired || exhausted || !c.is_active) && "opacity-50")}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold tracking-wider">{c.code}</span>
                        <button onClick={() => copy(c.code)} className="text-muted-foreground/50 hover:text-primary transition-colors">
                          {copied === c.code ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                      <p className="text-[10px] text-muted-foreground/50 mt-0.5">{fmtDate(c.created_at)}{c.expires_at && ` · 至 ${fmtDate(c.expires_at)}`}</p>
                    </td>
                    <td className="px-3 py-3 hidden sm:table-cell"><span className="text-xs text-muted-foreground">{c.description || "—"}</span></td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2 min-w-[80px]">
                        <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                          <div className={cn("h-full rounded-full", exhausted || expired ? "bg-muted-foreground/40" : pct >= 80 ? "bg-amber-500" : "bg-emerald-500")} style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-xs tabular-nums text-muted-foreground shrink-0">{c.use_count}/{c.max_uses}</span>
                      </div>
                    </td>
                    <td className="px-3 py-3 text-center">
                      <span className={cn("text-xs px-2 py-0.5 rounded-full font-medium",
                        expired ? "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400"
                          : exhausted ? "bg-muted text-muted-foreground"
                            : c.is_active ? "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400"
                              : "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400")}>
                        {expired ? "过期" : exhausted ? "耗尽" : c.is_active ? "可用" : "停用"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        {!exhausted && !expired && (
                          <button onClick={() => toggleActive(c)} className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                            {c.is_active ? <RiToggleFill className="w-4 h-4 text-emerald-500" /> : <RiToggleLine className="w-4 h-4" />}
                          </button>
                        )}
                        <button onClick={() => deleteCode(c)} className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/20 text-muted-foreground hover:text-red-500 transition-colors">
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
        </div>
      )}

      {showCreate && (
        <Modal title="生成邀请码" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleCreate} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-xs">批量数量</Label>
                <div className="flex gap-1.5">
                  {BATCH_OPTIONS.slice(0, 4).map(n => (
                    <button key={n} type="button" onClick={() => setCount(String(n))}
                      className={cn("flex-1 py-2 rounded-xl border text-xs font-semibold transition-all",
                        count === String(n) ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-muted")}>
                      {n}
                    </button>
                  ))}
                </div>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">最多使用次数</Label>
                <Input type="number" min="1" value={maxUses} onChange={e => setMaxUses(e.target.value)} className="h-9 rounded-xl" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">有效期</Label>
              <div className="flex flex-wrap gap-1.5">
                {EXPIRY_OPTIONS.map(opt => (
                  <button key={opt.value} type="button" onClick={() => setExpiresIn(opt.value)}
                    className={cn("text-xs px-3 py-1.5 rounded-full font-medium border transition-all",
                      expiresIn === opt.value ? "bg-primary text-primary-foreground border-primary" : "border-border text-muted-foreground hover:bg-muted")}>
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
              {creating ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />生成中…</> : <><RiKeyLine className="w-3.5 h-3.5" />生成 {parseInt(count)||1} 个</>}
            </Button>
          </form>
        </Modal>
      )}
    </div>
  );
}

/* ── Activation Codes Tab ───────────────────────────────────────────────── */
function ActivationTab() {
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
  const [filterTab, setFilterTab] = React.useState<"all"|"unused"|"used"|"expired">("all");
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
    setCreating(true);
    try {
      const res = await fetch("/api/admin/activation-codes", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ count: n, plan_name: planName.trim() || "会员套餐",
          duration_days: grantsSubscription ? (parseInt(durationDays) || null) : null,
          grants_subscription: grantsSubscription,
          balance_grant_cents: Math.max(0, parseInt(balanceCents) || 0),
          note: note.trim() || null, expires_in: expiresIn }) });
      const d = await res.json();
      if (res.ok) {
        toast.success(`已生成 ${d.created.length} 个激活码`);
        setShowCreate(false); setNote(""); load();
        if (d.created.length > 0) {
          await navigator.clipboard.writeText(d.created.join("\n")).catch(() => {});
          toast.success("激活码已复制到剪贴板");
        }
      } else { toast.error(d.error || "创建失败"); }
    } catch { toast.error("网络错误"); }
    finally { setCreating(false); }
  }

  async function handleDelete(id: number) {
    if (!confirm("确认删除此激活码？")) return;
    setDeleting(id);
    try {
      const res = await fetch("/api/admin/activation-codes", { method: "DELETE", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }) });
      if (res.ok) { setCodes(prev => prev.filter(c => c.id !== id)); toast.success("已删除"); }
      else { const d = await res.json(); toast.error(d.error || "删除失败"); }
    } catch { toast.error("网络错误"); }
    finally { setDeleting(null); }
  }

  const filtered = codes.filter(c =>
    filterTab === "unused"  ? !c.used && !isActExpired(c) :
    filterTab === "used"    ? c.used :
    filterTab === "expired" ? isActExpired(c) : true
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">共 {codes.length} 个 · 已使用 {codes.filter(c => c.used).length} 个</p>
        <Button size="sm" className="h-8 rounded-xl text-xs gap-1" onClick={() => setShowCreate(v => !v)}>
          <RiAddLine className="w-3.5 h-3.5" />生成激活码
        </Button>
      </div>

      <div className="flex gap-1.5 flex-wrap">
        {(["all","unused","used","expired"] as const).map(f => (
          <button key={f} onClick={() => setFilterTab(f)}
            className={cn("px-3 py-1.5 rounded-full text-xs font-medium border transition-all",
              filterTab === f ? "bg-primary text-primary-foreground border-primary" : "border-border hover:border-primary/50")}>
            {f === "all" ? `全部 (${codes.length})` : f === "unused" ? `未使用 (${codes.filter(c => !c.used && !isActExpired(c)).length})` : f === "used" ? `已使用 (${codes.filter(c => c.used).length})` : `已过期 (${codes.filter(isActExpired).length})`}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12"><RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" /></div>
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-sm text-muted-foreground"><RiGiftLine className="w-8 h-8 mx-auto mb-2 opacity-30" />暂无激活码</div>
      ) : (
        <div className="glass-panel border border-border rounded-2xl overflow-hidden divide-y divide-border/60">
          {filtered.map(c => {
            const expired = isActExpired(c);
            return (
              <div key={c.id} className="px-4 py-3 flex items-start gap-3">
                <div className={cn("w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5",
                  c.used ? "bg-emerald-50 dark:bg-emerald-950/30" : expired ? "bg-muted" : "bg-amber-50 dark:bg-amber-950/20")}>
                  {c.used ? <RiCheckLine className="w-4 h-4 text-emerald-500" />
                    : expired ? <RiTimeLine className="w-4 h-4 text-muted-foreground" />
                      : <RiGiftLine className="w-4 h-4 text-amber-500" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="text-xs font-bold font-mono tracking-wider">{c.code}</code>
                    <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded-full",
                      c.used ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
                        : expired ? "bg-muted text-muted-foreground"
                          : "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300")}>
                      {c.used ? "已使用" : expired ? "已过期" : "可用"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {c.grants_subscription && (
                      <span className="flex items-center gap-0.5 text-[10px] text-violet-600 dark:text-violet-400">
                        <RiVipCrownLine className="w-3 h-3" />{c.plan_name}{c.duration_days ? ` (${c.duration_days}天)` : " (永久)"}
                      </span>
                    )}
                    {c.balance_grant_cents > 0 && (
                      <span className="flex items-center gap-0.5 text-[10px] text-emerald-600 dark:text-emerald-400">
                        <RiCoinLine className="w-3 h-3" />+¥{(c.balance_grant_cents / 100).toFixed(2)}
                      </span>
                    )}
                    {c.used && c.used_by_email && <span className="text-[10px] text-muted-foreground">使用者: {c.used_by_email} · {fmtDate(c.used_at)}</span>}
                    {!c.used && c.expires_at && <span className="text-[10px] text-muted-foreground flex items-center gap-0.5"><RiTimeLine className="w-3 h-3" />至 {fmtDate(c.expires_at)}</span>}
                    {c.note && <span className="text-[10px] text-muted-foreground italic truncate max-w-[120px]">{c.note}</span>}
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button onClick={() => { navigator.clipboard.writeText(c.code); setCopied(c.code); setTimeout(() => setCopied(null), 1500); }}
                    className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                    {copied === c.code ? <RiCheckLine className="w-3.5 h-3.5 text-emerald-500" /> : <RiFileCopyLine className="w-3.5 h-3.5" />}
                  </button>
                  {!c.used && (
                    <button onClick={() => handleDelete(c.id)} disabled={deleting === c.id}
                      className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors text-muted-foreground hover:text-red-500">
                      {deleting === c.id ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {showCreate && (
        <Modal title="生成激活码" onClose={() => setShowCreate(false)}>
          <form onSubmit={handleCreate} className="space-y-3">
            <div className="space-y-1">
              <Label className="text-xs">批量数量</Label>
              <div className="flex gap-1.5">
                {BATCH_OPTIONS.map(n => (
                  <button key={n} type="button" onClick={() => setCount(String(n))}
                    className={cn("flex-1 py-2 rounded-xl border text-xs font-semibold transition-all",
                      count === String(n) ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-muted")}>
                    {n}
                  </button>
                ))}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-xs">套餐名称</Label>
                <Input value={planName} onChange={e => setPlanName(e.target.value)} className="h-8 rounded-xl text-sm" placeholder="年度会员" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">赠送余额（分）</Label>
                <Input type="number" min="0" value={balanceCents} onChange={e => setBalanceCents(e.target.value)} className="h-8 rounded-xl text-sm" />
              </div>
            </div>
            <label className="flex items-center gap-2 text-xs font-medium cursor-pointer">
              <input type="checkbox" checked={grantsSubscription} onChange={e => setGrantsSubscription(e.target.checked)} className="rounded" />
              授予会员权限
            </label>
            {grantsSubscription && (
              <div className="space-y-1">
                <Label className="text-xs">会员时长（天，留空=永久）</Label>
                <Input type="number" min="1" value={durationDays} onChange={e => setDurationDays(e.target.value)} className="h-8 rounded-xl text-sm" />
              </div>
            )}
            <div className="space-y-1.5">
              <Label className="text-xs">激活码有效期</Label>
              <div className="flex flex-wrap gap-1.5">
                {EXPIRY_OPTIONS.map(o => (
                  <button key={o.value} type="button" onClick={() => setExpiresIn(o.value)}
                    className={cn("px-3 py-1.5 rounded-full text-xs font-medium border transition-all",
                      expiresIn === o.value ? "bg-primary text-primary-foreground border-primary" : "border-border hover:border-primary/50")}>
                    {o.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="space-y-1">
              <Label className="text-xs">备注（可选）</Label>
              <Input value={note} onChange={e => setNote(e.target.value)} className="h-8 rounded-xl text-sm" placeholder="内部备注信息" />
            </div>
            <Button type="submit" disabled={creating} className="w-full h-9 rounded-xl gap-1.5">
              {creating ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />生成中…</> : <><RiGiftLine className="w-3.5 h-3.5" />生成 {parseInt(count)||1} 个</>}
            </Button>
          </form>
        </Modal>
      )}
    </div>
  );
}

/* ── Main Page ──────────────────────────────────────────────────────────── */
export default function AccessControlPage() {
  const router = useRouter();
  const tabParam = router.query.tab as string | undefined;
  const [activeTab, setActiveTab] = React.useState<MainTab>("keys");

  React.useEffect(() => {
    if (tabParam === "invite") setActiveTab("invite");
    else if (tabParam === "activation") setActiveTab("activation");
    else setActiveTab("keys");
  }, [tabParam]);

  const tabs: { key: MainTab; label: string; icon: React.ElementType; desc: string }[] = [
    { key: "keys",       label: "API 密钥",  icon: RiShieldUserLine, desc: "访问控制密钥" },
    { key: "invite",     label: "邀请码",    icon: RiKeyLine,         desc: "注册邀请码" },
    { key: "activation", label: "激活码",    icon: RiGiftLine,        desc: "付费激活码" },
  ];

  return (
    <AdminLayout title="访问控制">
      <Head><title>访问控制 · Admin</title></Head>
      <div className="space-y-5">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2">
            <RiShieldUserLine className="w-5 h-5 text-primary" />访问控制
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">API 密钥、注册邀请码、付费激活码统一管理</p>
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
        {activeTab === "keys" && <KeysTab />}
        {activeTab === "invite" && <InviteTab />}
        {activeTab === "activation" && <ActivationTab />}
      </div>
    </AdminLayout>
  );
}
