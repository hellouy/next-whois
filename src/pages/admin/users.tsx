import React from "react";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import {
  RiLoader4Line, RiSearchLine, RiDeleteBinLine,
  RiUserLine, RiMailLine, RiCalendarLine, RiPencilLine,
  RiUserForbidLine, RiUserFollowLine, RiCloseLine,
  RiSaveLine, RiShieldUserLine, RiFileTextLine,
  RiFilterLine, RiCheckboxCircleLine, RiVipCrownLine,
  RiHistoryLine, RiStarLine, RiBellLine,
  RiDownloadLine, RiAlertLine, RiBankCardLine,
} from "@remixicon/react";

type User = {
  id: string;
  email: string;
  name: string | null;
  created_at: string;
  updated_at: string;
  disabled: boolean;
  admin_notes: string | null;
  subscription_access: boolean;
  email_verified: boolean;
  search_count: number;
  stamp_count: number;
  reminder_count: number;
};

type FilterTab = "all" | "active" | "disabled" | "subscribed" | "verified";

function Toggle({ checked, onChange, label, desc, color }: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  desc?: string;
  color?: string;
}) {
  return (
    <div className="flex items-center justify-between glass-panel border border-border rounded-xl px-4 py-3">
      <div>
        <p className="text-sm font-medium">{label}</p>
        {desc && <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>}
      </div>
      <button
        type="button"
        onClick={() => onChange(!checked)}
        className={cn(
          "w-10 h-6 rounded-full transition-colors relative shrink-0",
          checked ? (color || "bg-primary") : "bg-muted"
        )}
        aria-label={label}
      >
        <span className={cn(
          "absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform",
          checked ? "translate-x-4" : "translate-x-0.5"
        )} />
      </button>
    </div>
  );
}

function EditModal({ user, onClose, onSaved, onViewOrders }: {
  user: User;
  onClose: () => void;
  onSaved: (updated: User) => void;
  onViewOrders: (email: string) => void;
}) {
  const [name, setName] = React.useState(user.name || "");
  const [email, setEmail] = React.useState(user.email);
  const [notes, setNotes] = React.useState(user.admin_notes || "");
  const [disabled, setDisabled] = React.useState(user.disabled);
  const [subscriptionAccess, setSubscriptionAccess] = React.useState(user.subscription_access);
  const [emailVerified, setEmailVerified] = React.useState(user.email_verified);
  const [saving, setSaving] = React.useState(false);

  async function handleSave() {
    if (!email.trim()) { toast.error("邮箱不能为空"); return; }
    setSaving(true);
    try {
      const res = await fetch(`/api/admin/users?id=${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim() || null,
          email: email.trim(),
          admin_notes: notes.trim() || null,
          disabled,
          subscription_access: subscriptionAccess,
          email_verified: emailVerified,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success("用户信息已更新");
      onSaved(data.user);
      onClose();
    } catch (e: any) {
      toast.error(e.message || "保存失败");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-background border border-border rounded-2xl shadow-xl w-full max-w-md p-6 space-y-5 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold">编辑用户</h3>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono">{user.id}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-4 h-4" />
          </button>
        </div>

        {/* User stats summary */}
        <div className="grid grid-cols-3 gap-2">
          {[
            { icon: RiHistoryLine, label: "查询", value: user.search_count, color: "text-blue-500" },
            { icon: RiStarLine,    label: "品牌", value: user.stamp_count,  color: "text-violet-500" },
            { icon: RiBellLine,    label: "订阅", value: user.reminder_count, color: "text-emerald-500" },
          ].map(({ icon: Icon, label, value, color }) => (
            <div key={label} className="glass-panel border border-border rounded-xl p-2 text-center">
              <Icon className={cn("w-3.5 h-3.5 mx-auto mb-0.5", color)} />
              <p className="text-base font-bold tabular-nums">{value}</p>
              <p className="text-[10px] text-muted-foreground">{label}</p>
            </div>
          ))}
        </div>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label className="text-sm font-medium flex items-center gap-1.5">
              <RiUserLine className="w-3.5 h-3.5 text-muted-foreground" />昵称
            </Label>
            <Input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="用户昵称（可选）"
              className="h-10 rounded-xl"
            />
          </div>

          <div className="space-y-1.5">
            <Label className="text-sm font-medium flex items-center gap-1.5">
              <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />邮箱地址
            </Label>
            <Input
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="user@example.com"
              type="email"
              className="h-10 rounded-xl"
            />
          </div>

          <div className="space-y-1.5">
            <Label className="text-sm font-medium flex items-center gap-1.5">
              <RiFileTextLine className="w-3.5 h-3.5 text-muted-foreground" />管理员备注
              <span className="text-[10px] text-muted-foreground/60 ml-auto">仅管理员可见</span>
            </Label>
            <textarea
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="内部备注…"
              rows={2}
              className="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          <Toggle
            checked={subscriptionAccess}
            onChange={setSubscriptionAccess}
            label="订阅访问权限"
            desc="开启后用户可享受订阅会员功能"
            color="bg-amber-500"
          />

          <Toggle
            checked={emailVerified}
            onChange={setEmailVerified}
            label="邮箱已验证"
            desc="手动标记邮箱验证状态"
            color="bg-emerald-500"
          />

          <Toggle
            checked={disabled}
            onChange={setDisabled}
            label="停用账户"
            desc="停用后用户无法登录"
            color="bg-red-500"
          />
        </div>

        <div className="flex items-center gap-3 pt-1">
          <Button onClick={handleSave} disabled={saving} className="flex-1 rounded-xl h-10 gap-2">
            {saving ? <><RiLoader4Line className="w-4 h-4 animate-spin" />保存中…</> : <><RiSaveLine className="w-4 h-4" />保存更改</>}
          </Button>
          <Button
            variant="outline"
            onClick={() => { onClose(); onViewOrders(user.email); }}
            disabled={saving}
            className="rounded-xl h-10 gap-1.5"
            title="查看该用户的全部订单"
          >
            <RiBankCardLine className="w-3.5 h-3.5" />订单
          </Button>
          <Button variant="outline" onClick={onClose} disabled={saving} className="rounded-xl h-10">取消</Button>
        </div>
      </div>
    </div>
  );
}

export default function AdminUsersPage() {
  const router = useRouter();
  const [users, setUsers] = React.useState<User[]>([]);
  const [total, setTotal] = React.useState(0);
  const [disabledCount, setDisabledCount] = React.useState(0);
  const [activeCount, setActiveCount] = React.useState(0);
  const [subscribedCount, setSubscribedCount] = React.useState(0);
  const [verifiedCount, setVerifiedCount] = React.useState(0);
  const [search, setSearch] = React.useState("");
  const [activeFilter, setActiveFilter] = React.useState<FilterTab>("all");
  const [loading, setLoading] = React.useState(false);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const [toggling, setToggling] = React.useState<string | null>(null);
  const [editUser, setEditUser] = React.useState<User | null>(null);
  const [offset, setOffset] = React.useState(0);
  const [pendingDelete, setPendingDelete] = React.useState<string | null>(null);
  const pendingDeleteTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const LIMIT = 50;

  function load(q: string, filter: FilterTab, off = 0) {
    setLoading(true);
    fetch(`/api/admin/users?search=${encodeURIComponent(q)}&filter=${filter}&limit=${LIMIT}&offset=${off}`)
      .then(r => r.json())
      .then(data => {
        if (data.error) { toast.error(data.error); return; }
        setUsers(off === 0 ? data.users || [] : prev => [...prev, ...(data.users || [])]);
        setTotal(data.total || 0);
        setDisabledCount(data.disabled || 0);
        setActiveCount(data.activeCount || 0);
        setSubscribedCount(data.subscribedCount || 0);
        setVerifiedCount(data.verifiedCount || 0);
        setOffset(off);
      })
      .catch(() => toast.error("加载失败"))
      .finally(() => setLoading(false));
  }

  React.useEffect(() => {
    const q = typeof router.query.search === "string" ? router.query.search : "";
    if (q) setSearch(q);
    load(q, "all", 0);
  }, []);

  function exportCsv() {
    if (users.length === 0) { toast.error("没有数据可导出"); return; }
    const headers = ["邮箱", "昵称", "注册时间", "邮箱已验证", "已订阅", "已停用", "查询数", "品牌数", "提醒数", "备注"];
    const rows = users.map(u => [
      u.email,
      u.name || "",
      new Date(u.created_at).toLocaleString("zh-CN"),
      u.email_verified ? "是" : "否",
      u.subscription_access ? "是" : "否",
      u.disabled ? "是" : "否",
      u.search_count,
      u.stamp_count,
      u.reminder_count,
      u.admin_notes || "",
    ]);
    const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `users_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`已导出 ${users.length} 名用户`);
  }

  function goToOrders(email: string) {
    router.push(`/admin/payment/orders?search=${encodeURIComponent(email)}`, undefined, { locale: false });
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setOffset(0);
    load(search, activeFilter, 0);
  }

  function handleFilter(f: FilterTab) {
    setActiveFilter(f);
    setOffset(0);
    load(search, f, 0);
  }

  function requestDelete(id: string) {
    if (pendingDelete === id) {
      if (pendingDeleteTimer.current) clearTimeout(pendingDeleteTimer.current);
      setPendingDelete(null);
      executeDelete(id);
    } else {
      setPendingDelete(id);
      if (pendingDeleteTimer.current) clearTimeout(pendingDeleteTimer.current);
      pendingDeleteTimer.current = setTimeout(() => setPendingDelete(null), 4000);
    }
  }

  async function executeDelete(id: string) {
    setDeleting(id);
    try {
      const res = await fetch(`/api/admin/users?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error((await res.json()).error);
      setUsers(prev => prev.filter(u => u.id !== id));
      setTotal(prev => prev - 1);
      toast.success("用户已永久删除");
    } catch (e: any) {
      toast.error(e.message || "删除失败");
    } finally {
      setDeleting(null);
    }
  }

  async function toggleDisabled(user: User) {
    setToggling(user.id);
    try {
      const res = await fetch(`/api/admin/users?id=${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ disabled: !user.disabled }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, ...data.user } : u));
      if (user.disabled) { setDisabledCount(v => v - 1); setActiveCount(v => v + 1); }
      else { setDisabledCount(v => v + 1); setActiveCount(v => v - 1); }
      toast.success(user.disabled ? "账户已恢复正常" : "账户已停用，用户无法登录");
    } catch (e: any) {
      toast.error(e.message || "操作失败");
    } finally {
      setToggling(null);
    }
  }

  async function toggleSubscription(user: User) {
    setToggling(user.id);
    try {
      const res = await fetch(`/api/admin/users?id=${user.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subscription_access: !user.subscription_access }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, ...data.user } : u));
      if (user.subscription_access) setSubscribedCount(v => Math.max(0, v - 1));
      else setSubscribedCount(v => v + 1);
      toast.success(user.subscription_access ? "已取消订阅权限" : "已授予订阅权限");
    } catch (e: any) {
      toast.error(e.message || "操作失败");
    } finally {
      setToggling(null);
    }
  }

  function fmt(d: string) {
    return new Date(d).toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
  }

  const FILTERS: { key: FilterTab; label: string; count: number }[] = [
    { key: "all",       label: "全部",   count: activeCount + disabledCount },
    { key: "active",    label: "正常",   count: activeCount },
    { key: "disabled",  label: "已停用", count: disabledCount },
    { key: "subscribed",label: "已订阅", count: subscribedCount },
    { key: "verified",  label: "已验证", count: verifiedCount },
  ];

  return (
    <AdminLayout title="用户管理">
      {editUser && (
        <EditModal
          user={editUser}
          onClose={() => setEditUser(null)}
          onViewOrders={goToOrders}
          onSaved={updated => {
            setUsers(prev => prev.map(u => u.id === updated.id ? updated : u));
            if (!editUser.disabled && updated.disabled) {
              setDisabledCount(v => v + 1); setActiveCount(v => v - 1);
            } else if (editUser.disabled && !updated.disabled) {
              setDisabledCount(v => v - 1); setActiveCount(v => v + 1);
            }
            if (!editUser.subscription_access && updated.subscription_access) setSubscribedCount(v => v + 1);
            else if (editUser.subscription_access && !updated.subscription_access) setSubscribedCount(v => Math.max(0, v - 1));
          }}
        />
      )}

      <div className="space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-bold">用户管理</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              共 {(activeCount + disabledCount).toLocaleString()} 名用户
              {disabledCount > 0 && <span className="ml-1.5 text-red-500">· {disabledCount} 已停用</span>}
              {subscribedCount > 0 && <span className="ml-1.5 text-amber-500">· {subscribedCount} 已订阅</span>}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={exportCsv}
              disabled={users.length === 0}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-border text-xs font-medium text-muted-foreground hover:text-foreground hover:border-primary/30 hover:bg-muted/40 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              title="导出当前列表为 CSV"
            >
              <RiDownloadLine className="w-3.5 h-3.5" />导出 CSV
            </button>
            <form onSubmit={handleSearch} className="flex items-center gap-2">
              <div className="relative">
                <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
                <Input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="搜索邮箱或昵称…"
                  className="pl-8 h-9 rounded-xl text-sm w-48"
                />
              </div>
              <Button type="submit" size="sm" className="h-9 rounded-xl px-4">搜索</Button>
            </form>
          </div>
        </div>

        {/* Filter tabs */}
        <div className="flex items-center gap-1 p-1 glass-panel border border-border rounded-xl w-fit flex-wrap">
          <RiFilterLine className="w-3.5 h-3.5 text-muted-foreground ml-1 shrink-0" />
          {FILTERS.map(f => (
            <button
              key={f.key}
              onClick={() => handleFilter(f.key)}
              className={cn(
                "px-3 py-1.5 rounded-lg text-xs font-semibold transition-all",
                activeFilter === f.key
                  ? "bg-primary text-primary-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              )}
            >
              {f.label}
              {f.count > 0 && (
                <span className={cn(
                  "ml-1.5 text-[10px] px-1 py-0.5 rounded",
                  activeFilter === f.key ? "bg-white/20" : "bg-muted-foreground/10"
                )}>{f.count}</span>
              )}
            </button>
          ))}
        </div>

        {loading && offset === 0 ? (
          <div className="flex justify-center py-12">
            <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <RiUserLine className="w-10 h-10 text-muted-foreground/30 mx-auto" />
            <p className="text-sm text-muted-foreground">没有找到用户</p>
          </div>
        ) : (
          <div className="space-y-2">
            {users.map(user => (
              <div key={user.id}
                className={cn(
                  "glass-panel border rounded-xl p-4 flex items-center gap-3 group transition-colors",
                  user.disabled
                    ? "border-red-200/50 dark:border-red-800/30 bg-red-50/20 dark:bg-red-950/10"
                    : "border-border"
                )}>
                <div className={cn(
                  "w-8 h-8 rounded-full flex items-center justify-center shrink-0",
                  user.email === ADMIN_EMAIL
                    ? "bg-gradient-to-br from-violet-500 to-indigo-600"
                    : user.disabled
                      ? "bg-red-100 dark:bg-red-950/40"
                      : user.subscription_access
                        ? "bg-gradient-to-br from-amber-400/30 to-orange-500/30"
                        : "bg-gradient-to-br from-primary/20 to-violet-500/20"
                )}>
                  {user.email === ADMIN_EMAIL
                    ? <RiShieldUserLine className="w-4 h-4 text-white" />
                    : user.disabled
                      ? <RiUserForbidLine className="w-4 h-4 text-red-500" />
                      : user.subscription_access
                        ? <RiVipCrownLine className="w-4 h-4 text-amber-600" />
                        : <RiUserLine className="w-4 h-4 text-primary" />
                  }
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <p className="text-sm font-semibold truncate">{user.name || "未设置昵称"}</p>
                    {user.email === ADMIN_EMAIL && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-gradient-to-r from-violet-500/20 to-indigo-500/20 text-violet-700 dark:text-violet-300 font-semibold border border-violet-200/50 dark:border-violet-700/30 shrink-0">
                        创始人
                      </span>
                    )}
                    {user.subscription_access && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-amber-100 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 font-semibold shrink-0">
                        订阅
                      </span>
                    )}
                    {user.email_verified && (
                      <span className="text-[9px] px-1 py-0.5 rounded-md bg-emerald-100 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 font-semibold shrink-0 flex items-center gap-0.5">
                        <RiCheckboxCircleLine className="w-2.5 h-2.5" />已验证
                      </span>
                    )}
                    {user.disabled && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded-md bg-red-100 dark:bg-red-950/30 text-red-600 dark:text-red-400 font-semibold shrink-0">
                        已停用
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                    <span className="text-[11px] text-muted-foreground flex items-center gap-1 truncate max-w-[200px]">
                      <RiMailLine className="w-3 h-3 shrink-0" />{user.email}
                    </span>
                    <span className="text-[11px] text-muted-foreground flex items-center gap-1 shrink-0">
                      <RiCalendarLine className="w-3 h-3" />{fmt(user.created_at)}
                    </span>
                    {/* Per-user stats mini */}
                    <span className="text-[10px] text-muted-foreground/60 flex items-center gap-2 shrink-0">
                      {user.search_count > 0 && <span className="flex items-center gap-0.5"><RiHistoryLine className="w-2.5 h-2.5" />{user.search_count}</span>}
                      {user.stamp_count > 0 && <span className="flex items-center gap-0.5"><RiStarLine className="w-2.5 h-2.5" />{user.stamp_count}</span>}
                      {user.reminder_count > 0 && <span className="flex items-center gap-0.5"><RiBellLine className="w-2.5 h-2.5" />{user.reminder_count}</span>}
                    </span>
                  </div>
                  {user.admin_notes && (
                    <p className="text-[10px] text-amber-600 dark:text-amber-400 mt-1 truncate">
                      备注：{user.admin_notes}
                    </p>
                  )}
                </div>

                {user.email !== ADMIN_EMAIL && (
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                    {/* Edit */}
                    <button
                      onClick={() => setEditUser(user)}
                      className="p-2 rounded-lg transition-colors text-muted-foreground hover:bg-blue-50 dark:hover:bg-blue-950/30 hover:text-blue-500"
                      title="编辑用户"
                    >
                      <RiPencilLine className="w-3.5 h-3.5" />
                    </button>
                    {/* Subscription toggle */}
                    <button
                      onClick={() => toggleSubscription(user)}
                      disabled={toggling === user.id}
                      className={cn(
                        "p-2 rounded-lg transition-colors text-muted-foreground",
                        user.subscription_access
                          ? "hover:bg-amber-50 dark:hover:bg-amber-950/30 hover:text-amber-500"
                          : "hover:bg-amber-50 dark:hover:bg-amber-950/30 hover:text-amber-500"
                      )}
                      title={user.subscription_access ? "取消订阅权限" : "授予订阅权限"}
                    >
                      {toggling === `sub_${user.id}`
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : <RiVipCrownLine className={cn("w-3.5 h-3.5", user.subscription_access ? "text-amber-500" : "")} />
                      }
                    </button>
                    {/* Disable/enable toggle */}
                    <button
                      onClick={() => toggleDisabled(user)}
                      disabled={toggling === user.id}
                      className={cn(
                        "p-2 rounded-lg transition-colors text-muted-foreground",
                        user.disabled
                          ? "hover:bg-emerald-50 dark:hover:bg-emerald-950/30 hover:text-emerald-500"
                          : "hover:bg-orange-50 dark:hover:bg-orange-950/30 hover:text-orange-500"
                      )}
                      title={user.disabled ? "恢复账户" : "停用账户"}
                    >
                      {toggling === user.id
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                        : user.disabled
                          ? <RiUserFollowLine className="w-3.5 h-3.5" />
                          : <RiUserForbidLine className="w-3.5 h-3.5" />
                      }
                    </button>
                    {/* Delete */}
                    {pendingDelete === user.id ? (
                      <div className="flex items-center gap-1 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 rounded-lg px-1.5 py-1">
                        <RiAlertLine className="w-3 h-3 text-red-500 shrink-0" />
                        <button
                          onClick={() => requestDelete(user.id)}
                          disabled={deleting === user.id}
                          className="text-[10px] text-red-600 dark:text-red-400 font-semibold whitespace-nowrap hover:underline"
                        >
                          确认删除
                        </button>
                        <button
                          onClick={() => setPendingDelete(null)}
                          className="ml-0.5 text-red-300 hover:text-red-500"
                        >
                          <RiCloseLine className="w-3 h-3" />
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => requestDelete(user.id)}
                        disabled={deleting === user.id}
                        className="p-2 rounded-lg transition-colors text-muted-foreground hover:bg-red-50 dark:hover:bg-red-950/30 hover:text-red-500"
                        title="永久删除"
                      >
                        {deleting === user.id
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : <RiDeleteBinLine className="w-3.5 h-3.5" />
                        }
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}

            {/* Load more */}
            {users.length < total && (
              <div className="text-center py-3">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={loading}
                  onClick={() => load(search, activeFilter, offset + LIMIT)}
                  className="rounded-xl h-9 gap-2"
                >
                  {loading ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : null}
                  加载更多（还有 {total - users.length} 名用户）
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
