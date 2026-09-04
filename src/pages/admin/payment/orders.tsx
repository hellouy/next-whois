import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { AdminLayout } from "@/components/admin-layout";
import { PageTabs } from "@/components/page-tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

import {
  RiBankCardLine, RiLoader4Line, RiCheckDoubleLine, RiRefundLine,
  RiSearchLine, RiMoneyDollarCircleLine, RiUserLine, RiAlertLine,
  RiRefreshLine, RiCloseLine,
} from "@remixicon/react";

const PAYMENT_TABS = [
  { href: "/admin/payment/plans",  label: "套餐管理" },
  { href: "/admin/payment/orders", label: "订单管理" },
];

type Order = {
  id: string;
  user_email: string;
  user_name: string | null;
  plan_name: string;
  amount: number;
  currency: string;
  provider: string;
  status: string;
  paid_at: string | null;
  created_at: string;
  provider_order_id: string | null;
};

type CurrencyBreakdown = { currency: string; revenue: number; count: number };
type Stats = { total: number; paid: number; refunded: number; revenue: number; byCurrency: CurrencyBreakdown[] };

const STATUS_TABS = [
  { key: "all",     label: "全部" },
  { key: "paid",    label: "已付款" },
  { key: "pending", label: "待付款" },
  { key: "failed",  label: "失败" },
  { key: "expired", label: "已过期" },
  { key: "refunded",label: "已退款" },
];

const PROVIDER_LABELS: Record<string, string> = {
  stripe: "Stripe", xunhupay: "虎皮椒", alipay: "支付宝", paypal: "PayPal",
};

const STATUS_STYLE: Record<string, string> = {
  paid:     "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800",
  pending:  "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800",
  failed:   "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800",
  expired:  "bg-muted text-muted-foreground border-border/50",
  refunded: "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800",
};

const STATUS_LABEL: Record<string, string> = {
  paid: "已付款", pending: "待付款", failed: "失败", expired: "已过期", refunded: "已退款",
};

const EMPTY_STATS: Stats = { total: 0, paid: 0, refunded: 0, revenue: 0, byCurrency: [] };

function fmt(date: string) {
  return new Date(date).toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function currencySymbol(c: string) {
  return { CNY: "¥", USD: "$", EUR: "€", HKD: "HK$" }[c] ?? c + " ";
}

export default function PaymentOrdersAdmin() {
  const router = useRouter();
  const [orders, setOrders] = React.useState<Order[]>([]);
  const [stats, setStats] = React.useState<Stats>(EMPTY_STATS);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [loadingMore, setLoadingMore] = React.useState(false);
  const [status, setStatus] = React.useState("all");
  const [search, setSearch] = React.useState("");
  const [acting, setActing] = React.useState<string | null>(null);
  const [pendingAction, setPendingAction] = React.useState<{ id: string; action: string; label: string } | null>(null);
  const pendingTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const PAGE_SIZE = 50;

  async function load(append = false, offsetOverride?: number, searchOverride?: string) {
    const currentOffset = append ? (offsetOverride ?? orders.length) : 0;
    if (append) setLoadingMore(true); else setLoading(true);
    try {
      const params = new URLSearchParams({ status, search: searchOverride ?? search, limit: String(PAGE_SIZE), offset: String(currentOffset) });
      const r = await fetch(`/api/admin/payment/orders?${params}`);
      const d = await r.json();
      if (d.error) { toast.error(d.error); return; }
      if (append) {
        setOrders(prev => [...prev, ...(d.orders ?? [])]);
      } else {
        setOrders(d.orders ?? []);
        setStats(d.stats ?? EMPTY_STATS);
      }
      setTotal(d.total ?? 0);
    } catch { toast.error("加载失败"); }
    finally { if (append) setLoadingMore(false); else setLoading(false); }
  }

  React.useEffect(() => {
    const q = typeof router.query.search === "string" ? router.query.search : "";
    if (q) setSearch(q);
  }, [router.query.search]);

  React.useEffect(() => { load(); }, [status]);

  function requestAction(orderId: string, action: string, label: string) {
    if (pendingAction?.id === orderId && pendingAction.action === action) {
      if (pendingTimer.current) clearTimeout(pendingTimer.current);
      setPendingAction(null);
      executeAction(orderId, action, label);
    } else {
      setPendingAction({ id: orderId, action, label });
      if (pendingTimer.current) clearTimeout(pendingTimer.current);
      pendingTimer.current = setTimeout(() => setPendingAction(null), 4000);
    }
  }

  async function executeAction(orderId: string, action: string, label: string) {
    setActing(orderId);
    try {
      const r = await fetch("/api/admin/payment/orders", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, orderId }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);
      if (action === "mark_refunded" && d.subscriptionRevoked) {
        toast.success("订单已标记退款，用户订阅权限已撤销");
      } else {
        toast.success(`订单已${label}`);
      }
      load();
    } catch (e: any) { toast.error(e.message); }
    finally { setActing(null); }
  }

  function goToUser(email: string) {
    router.push(`/admin/users?search=${encodeURIComponent(email)}`, undefined, { locale: false });
  }

  return (
    <AdminLayout title="支付管理">
      <Head><title>订单管理 · 后台</title></Head>
      <div className="space-y-4">
        <PageTabs tabs={PAYMENT_TABS} />
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">
              <RiBankCardLine className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold">支付订单管理</h2>
              <p className="text-[11px] text-muted-foreground">共 {stats.total} 笔订单</p>
            </div>
          </div>
          <button
            onClick={() => load()}
            disabled={loading}
            className="p-2 rounded-xl hover:bg-muted transition-colors text-muted-foreground"
            title="刷新"
          >
            <RiRefreshLine className={cn("w-4 h-4", loading && "animate-spin")} />
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="rounded-xl border border-border bg-card p-3 text-center">
            <div className="text-lg font-black">{stats.total}</div>
            <div className="text-[11px] text-muted-foreground">总订单</div>
          </div>
          <div className="rounded-xl border border-border bg-card p-3 text-center">
            <div className="text-lg font-black text-emerald-600 dark:text-emerald-400">{stats.paid}</div>
            <div className="text-[11px] text-muted-foreground">已付款</div>
          </div>
          <div className="rounded-xl border border-border bg-card p-3 text-center">
            <div className="text-lg font-black text-blue-600 dark:text-blue-400">{stats.refunded}</div>
            <div className="text-[11px] text-muted-foreground">已退款</div>
          </div>
          <div className="rounded-xl border border-border bg-card p-3 text-center">
            {stats.byCurrency.length <= 1 ? (
              <>
                <div className="text-lg font-black text-violet-600 dark:text-violet-400">
                  {stats.byCurrency[0] ? `${currencySymbol(stats.byCurrency[0].currency)}${stats.byCurrency[0].revenue.toFixed(2)}` : "—"}
                </div>
                <div className="text-[11px] text-muted-foreground">总收入</div>
              </>
            ) : (
              <>
                <div className="space-y-0.5">
                  {stats.byCurrency.map(bc => (
                    <div key={bc.currency} className="flex items-center justify-between text-[11px]">
                      <span className="text-muted-foreground">{bc.currency}</span>
                      <span className="font-bold text-violet-600 dark:text-violet-400">{currencySymbol(bc.currency)}{bc.revenue.toFixed(2)}</span>
                    </div>
                  ))}
                </div>
                <div className="text-[10px] text-muted-foreground mt-1">多币种收入</div>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <form onSubmit={e => { e.preventDefault(); load(); }} className="relative flex-1 min-w-[200px] flex gap-2">
            <div className="relative flex-1">
              <RiSearchLine className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                value={search}
                onChange={e => setSearch(e.target.value)}
                onKeyDown={e => e.key === "Escape" && (setSearch(""), load(false, 0, ""))}
                placeholder="邮箱 / 订单号 / 套餐名"
                className="pl-8 h-8 text-sm"
              />
            </div>
            <button type="submit" className="h-8 px-3 text-xs rounded-lg border border-border bg-muted hover:bg-accent transition-colors">搜索</button>
          </form>
          <div className="flex gap-1 flex-wrap">
            {STATUS_TABS.map(t => (
              <button key={t.key} onClick={() => setStatus(t.key)} className={cn(
                "text-[11px] px-2.5 py-1 rounded-lg border transition-all",
                status === t.key
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border text-muted-foreground hover:text-foreground"
              )}>{t.label}</button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-10"><RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" /></div>
        ) : orders.length === 0 ? (
          <div className="text-center py-10 text-muted-foreground text-sm">暂无订单</div>
        ) : (
          <div className="space-y-2">
            {orders.map(order => {
              const isPending = pendingAction?.id === order.id;
              return (
                <div key={order.id} className="border border-border rounded-xl p-3.5 flex items-start gap-3 hover:bg-muted/20 transition-colors group">
                  <div className={cn(
                    "w-9 h-9 rounded-lg flex items-center justify-center shrink-0",
                    order.status === "paid" ? "bg-emerald-500/10 text-emerald-500" : "bg-muted text-muted-foreground"
                  )}>
                    <RiMoneyDollarCircleLine className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold">{order.plan_name}</span>
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium", STATUS_STYLE[order.status] ?? STATUS_STYLE.pending)}>
                        {STATUS_LABEL[order.status] ?? order.status}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border/50">
                        {PROVIDER_LABELS[order.provider] ?? order.provider}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1 text-[11px] text-muted-foreground">
                      <button
                        onClick={() => goToUser(order.user_email)}
                        className="flex items-center gap-1 hover:text-primary hover:underline transition-colors"
                        title="查看该用户"
                      >
                        <RiUserLine className="w-2.5 h-2.5 shrink-0" />
                        {order.user_name ? `${order.user_name} (${order.user_email})` : order.user_email}
                      </button>
                      <span className="font-semibold text-foreground">{currencySymbol(order.currency)}{order.amount.toFixed(2)}</span>
                      <span>{fmt(order.created_at)}</span>
                      {order.paid_at && <span className="text-emerald-600 dark:text-emerald-400">付款 {fmt(order.paid_at)}</span>}
                    </div>
                    <div className="text-[10px] text-muted-foreground/60 mt-0.5 font-mono truncate">{order.id}</div>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    {isPending && (
                      <div className="flex items-center gap-1 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-lg px-2 py-1">
                        <RiAlertLine className="w-3 h-3 text-amber-500 shrink-0" />
                        <span className="text-[10px] text-amber-700 dark:text-amber-300 font-medium whitespace-nowrap">
                          再次点击确认{pendingAction.label}
                        </span>
                        <button
                          onClick={() => setPendingAction(null)}
                          className="ml-1 text-amber-400 hover:text-amber-600"
                        >
                          <RiCloseLine className="w-3 h-3" />
                        </button>
                      </div>
                    )}
                    {order.status === "pending" && (
                      <button
                        onClick={() => requestAction(order.id, "mark_paid", "标记为已付款")}
                        disabled={acting === order.id}
                        className={cn(
                          "p-1.5 rounded-lg transition-colors",
                          isPending && pendingAction?.action === "mark_paid"
                            ? "bg-emerald-100 dark:bg-emerald-950/30 text-emerald-600"
                            : "hover:bg-emerald-50 dark:hover:bg-emerald-950/20 text-emerald-600 dark:text-emerald-400"
                        )}
                        title="手动标记为已付款"
                      >
                        {acting === order.id ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiCheckDoubleLine className="w-3.5 h-3.5" />}
                      </button>
                    )}
                    {order.status === "paid" && (
                      <button
                        onClick={() => requestAction(order.id, "mark_refunded", "标记退款")}
                        disabled={acting === order.id}
                        className={cn(
                          "p-1.5 rounded-lg transition-colors",
                          isPending && pendingAction?.action === "mark_refunded"
                            ? "bg-blue-100 dark:bg-blue-950/30 text-blue-600"
                            : "hover:bg-blue-50 dark:hover:bg-blue-950/20 text-blue-500"
                        )}
                        title="标记为已退款（同时撤销订阅权限）"
                      >
                        {acting === order.id ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiRefundLine className="w-3.5 h-3.5" />}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
            {orders.length < total && (
              <button
                onClick={() => load(true)}
                disabled={loadingMore}
                className="w-full py-2.5 text-sm text-muted-foreground border border-dashed border-border rounded-xl hover:bg-muted/40 transition-colors flex items-center justify-center gap-2"
              >
                {loadingMore ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : null}
                {loadingMore ? "加载中…" : `加载更多（已显示 ${orders.length} / ${total}）`}
              </button>
            )}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
