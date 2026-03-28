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
  RiPriceTag3Line, RiAddLine, RiDeleteBinLine, RiPencilLine,
  RiCheckLine, RiCloseLine, RiLoader4Line, RiToggleLine, RiToggleFill,
  RiMoneyDollarCircleLine, RiCalendarLine, RiStarLine,
} from "@remixicon/react";

const PAYMENT_TABS = [
  { href: "/admin/payment/plans",  label: "套餐管理" },
  { href: "/admin/payment/orders", label: "订单管理" },
];

type Plan = {
  id: string;
  name: string;
  description: string | null;
  price: number;
  currency: string;
  duration_days: number | null;
  is_recurring: boolean;
  grants_subscription: boolean;
  balance_grant_cents: number;
  is_active: boolean;
  sort_order: number;
  created_at: string;
};

const CURRENCIES = ["CNY", "USD", "EUR", "HKD"];
const DURATION_OPTIONS = [
  { value: "", label: "永久（不过期）" },
  { value: "30",  label: "30 天（1 个月）" },
  { value: "90",  label: "90 天（3 个月）" },
  { value: "180", label: "180 天（半年）" },
  { value: "365", label: "365 天（1 年）" },
  { value: "custom", label: "自定义天数" },
];

const EMPTY_FORM = {
  name: "", description: "", price: "", currency: "CNY",
  duration_days: "", is_recurring: false, grants_subscription: true, sort_order: "0",
};

function PlanForm({ initial, onSave, onCancel, saving }: {
  initial?: Partial<Plan>;
  onSave: (data: any) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const [form, setForm] = React.useState({
    name: initial?.name ?? "",
    description: initial?.description ?? "",
    price: initial?.price?.toString() ?? "",
    currency: initial?.currency ?? "CNY",
    duration_days: initial?.duration_days?.toString() ?? "",
    duration_preset: initial?.duration_days ? (
      ["30","90","180","365"].includes(String(initial.duration_days)) ? String(initial.duration_days) : "custom"
    ) : "",
    is_recurring: initial?.is_recurring ?? false,
    grants_subscription: initial?.grants_subscription ?? true,
    balance_grant_cents: initial?.balance_grant_cents?.toString() ?? "0",
    sort_order: initial?.sort_order?.toString() ?? "0",
  });

  function set(k: string, v: any) { setForm(f => ({ ...f, [k]: v })); }

  return (
    <div className="space-y-4 p-4 rounded-xl border border-border bg-muted/20">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <Label className="text-xs mb-1.5 block">套餐名称 *</Label>
          <Input value={form.name} onChange={e => set("name", e.target.value)} placeholder="如：月度会员、年度订阅" className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1.5 block">价格 *</Label>
          <div className="flex gap-2">
            <Input value={form.price} onChange={e => set("price", e.target.value)} placeholder="29.00" className="h-8 text-sm flex-1" type="number" min="0" step="0.01" />
            <select value={form.currency} onChange={e => set("currency", e.target.value)} className="h-8 text-sm rounded-md border border-input bg-background px-2 focus:outline-none">
              {CURRENCIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
        </div>
        <div className="sm:col-span-2">
          <Label className="text-xs mb-1.5 block">套餐说明</Label>
          <Input value={form.description} onChange={e => set("description", e.target.value)} placeholder="简短描述，展示在支付页面" className="h-8 text-sm" />
        </div>
        <div>
          <Label className="text-xs mb-1.5 block">有效期</Label>
          <select
            value={form.duration_preset}
            onChange={e => { set("duration_preset", e.target.value); if (e.target.value !== "custom") set("duration_days", e.target.value); }}
            className="w-full h-8 text-sm rounded-md border border-input bg-background px-2 focus:outline-none"
          >
            {DURATION_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          {form.duration_preset === "custom" && (
            <Input value={form.duration_days} onChange={e => set("duration_days", e.target.value)} placeholder="天数，如 60" className="h-8 text-sm mt-1.5" type="number" min="1" />
          )}
        </div>
        <div>
          <Label className="text-xs mb-1.5 block">展示排序（数字越小越靠前）</Label>
          <Input value={form.sort_order} onChange={e => set("sort_order", e.target.value)} className="h-8 text-sm" type="number" />
        </div>
        <div>
          <Label className="text-xs mb-1.5 block">充值余额（分）<span className="text-muted-foreground ml-1">付款后自动到账，0 = 不充值</span></Label>
          <Input value={form.balance_grant_cents} onChange={e => set("balance_grant_cents", e.target.value)} className="h-8 text-sm" type="number" min="0" placeholder="如 5000 = ¥50.00" />
        </div>
      </div>

      <div className="flex flex-wrap gap-4 pt-1">
        <label className="flex items-center gap-2 cursor-pointer text-sm">
          <input type="checkbox" checked={form.grants_subscription} onChange={e => set("grants_subscription", e.target.checked)} className="rounded" />
          <span>付款后自动开通订阅权限</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer text-sm">
          <input type="checkbox" checked={form.is_recurring} onChange={e => set("is_recurring", e.target.checked)} className="rounded" />
          <span>周期性订阅（标注）</span>
        </label>
      </div>

      <div className="flex gap-2 pt-1">
        <Button size="sm" onClick={() => onSave(form)} disabled={saving} className="h-8 text-xs">
          {saving ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiCheckLine className="w-3.5 h-3.5 mr-1" />}
          保存
        </Button>
        <Button size="sm" variant="outline" onClick={onCancel} className="h-8 text-xs">
          <RiCloseLine className="w-3.5 h-3.5 mr-1" />取消
        </Button>
      </div>
    </div>
  );
}

export default function PaymentPlansAdmin() {
  const [plans, setPlans] = React.useState<Plan[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [showCreate, setShowCreate] = React.useState(false);
  const [editId, setEditId] = React.useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/payment/plans");
      const d = await r.json();
      setPlans(d.plans ?? []);
    } catch { toast.error("加载失败"); }
    finally { setLoading(false); }
  }

  React.useEffect(() => { load(); }, []);

  async function handleCreate(form: any) {
    setSaving(true);
    try {
      const r = await fetch("/api/admin/payment/plans", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...form,
          price: parseFloat(form.price),
          duration_days: form.duration_days ? parseInt(form.duration_days) : null,
          sort_order: parseInt(form.sort_order) || 0,
        }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);
      toast.success("套餐已创建");
      setShowCreate(false);
      load();
    } catch (e: any) { toast.error(e.message); }
    finally { setSaving(false); }
  }

  async function handleEdit(form: any) {
    if (!editId) return;
    setSaving(true);
    try {
      const r = await fetch("/api/admin/payment/plans", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: editId, ...form,
          price: parseFloat(form.price),
          duration_days: form.duration_days ? parseInt(form.duration_days) : null,
          sort_order: parseInt(form.sort_order) || 0,
          is_active: plans.find(p => p.id === editId)?.is_active ?? true,
        }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);
      toast.success("套餐已更新");
      setEditId(null);
      load();
    } catch (e: any) { toast.error(e.message); }
    finally { setSaving(false); }
  }

  async function toggleActive(plan: Plan) {
    try {
      const r = await fetch("/api/admin/payment/plans", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...plan, is_active: !plan.is_active }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);
      setPlans(ps => ps.map(p => p.id === plan.id ? { ...p, is_active: !p.is_active } : p));
    } catch (e: any) { toast.error(e.message); }
  }

  async function deletePlan(plan: Plan) {
    if (!confirm(`确认删除套餐「${plan.name}」？有付费订单的套餐不可删除。`)) return;
    try {
      const r = await fetch("/api/admin/payment/plans", {
        method: "DELETE", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: plan.id }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);
      toast.success("套餐已删除");
      setPlans(ps => ps.filter(p => p.id !== plan.id));
    } catch (e: any) { toast.error(e.message); }
  }

  return (
    <AdminLayout title="支付管理">
      <Head><title>套餐管理 · 后台</title></Head>
      <div className="space-y-4">
        <PageTabs tabs={PAYMENT_TABS} />
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-violet-500/10 text-violet-500">
              <RiPriceTag3Line className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold">支付套餐管理</h2>
              <p className="text-[11px] text-muted-foreground">{plans.length} 个套餐</p>
            </div>
          </div>
          <Button size="sm" onClick={() => { setShowCreate(true); setEditId(null); }} className="h-8 text-xs gap-1">
            <RiAddLine className="w-3.5 h-3.5" />新建套餐
          </Button>
        </div>

        {showCreate && (
          <PlanForm onSave={handleCreate} onCancel={() => setShowCreate(false)} saving={saving} />
        )}

        {loading ? (
          <div className="flex justify-center py-10"><RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" /></div>
        ) : plans.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground text-sm">
            <RiPriceTag3Line className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>暂无套餐，点击「新建套餐」创建第一个</p>
          </div>
        ) : (
          <div className="space-y-3">
            {plans.map(plan => (
              <div key={plan.id} className={cn(
                "border rounded-xl overflow-hidden",
                plan.is_active ? "border-border" : "border-border/40 opacity-60"
              )}>
                {editId === plan.id ? (
                  <div className="p-4">
                    <PlanForm initial={plan} onSave={handleEdit} onCancel={() => setEditId(null)} saving={saving} />
                  </div>
                ) : (
                  <div className="p-4 flex items-start gap-3">
                    <div className={cn(
                      "w-10 h-10 rounded-xl flex items-center justify-center shrink-0",
                      plan.is_active ? "bg-violet-500/10 text-violet-500" : "bg-muted text-muted-foreground"
                    )}>
                      <RiMoneyDollarCircleLine className="w-5 h-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-sm">{plan.name}</span>
                        {!plan.is_active && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border/50">已下线</span>
                        )}
                        {plan.grants_subscription && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-300 border border-violet-200 dark:border-violet-800">订阅权限</span>
                        )}
                        {plan.is_recurring && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800">周期性</span>
                        )}
                        {(plan.balance_grant_cents ?? 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">+¥{(plan.balance_grant_cents / 100).toFixed(0)} 余额</span>
                        )}
                      </div>
                      {plan.description && (
                        <p className="text-xs text-muted-foreground mt-0.5">{plan.description}</p>
                      )}
                      <div className="flex items-center gap-3 mt-1.5 text-[11px] text-muted-foreground">
                        <span className="font-bold text-sm text-foreground">
                          {plan.currency === "CNY" ? "¥" : plan.currency === "USD" ? "$" : plan.currency}
                          {plan.price.toFixed(2)}
                        </span>
                        <span className="flex items-center gap-1">
                          <RiCalendarLine className="w-3 h-3" />
                          {plan.duration_days ? `${plan.duration_days} 天` : "永久"}
                        </span>
                        <span>排序 {plan.sort_order}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button onClick={() => toggleActive(plan)} className="p-1.5 rounded-lg hover:bg-muted transition-colors" title={plan.is_active ? "点击下线" : "点击上线"}>
                        {plan.is_active ? <RiToggleFill className="w-4 h-4 text-emerald-500" /> : <RiToggleLine className="w-4 h-4 text-muted-foreground" />}
                      </button>
                      <button onClick={() => { setEditId(plan.id); setShowCreate(false); }} className="p-1.5 rounded-lg hover:bg-muted transition-colors" title="编辑">
                        <RiPencilLine className="w-3.5 h-3.5 text-muted-foreground" />
                      </button>
                      <button onClick={() => deletePlan(plan)} className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors" title="删除">
                        <RiDeleteBinLine className="w-3.5 h-3.5 text-red-500" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="rounded-xl border border-border/50 bg-muted/20 p-4 space-y-2">
          <h3 className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
            <RiStarLine className="w-3.5 h-3.5" />支付渠道配置
          </h3>
          <p className="text-xs text-muted-foreground">在「设置」页面的「支付网关」区块中配置各渠道的 API Key 和 Secret，并选择开启的渠道。</p>
          <p className="text-xs text-muted-foreground">Webhook 地址：</p>
          <div className="flex flex-wrap gap-1.5 mt-1">
            {["/api/payment/webhook/stripe", "/api/payment/webhook/xunhupay", "/api/payment/webhook/alipay", "/api/payment/webhook/paypal"].map(url => (
              <code key={url} className="bg-muted px-1.5 py-0.5 rounded text-[11px] break-all">{url}</code>
            ))}
          </div>
        </div>
      </div>
    </AdminLayout>
  );
}
