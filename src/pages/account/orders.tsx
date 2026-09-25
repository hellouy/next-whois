import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { cn } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiLoader4Line, RiArrowLeftSLine, RiCoinLine, RiRefreshLine,
  RiCheckboxCircleLine, RiFileTextLine, RiWalletLine,
} from "@remixicon/react";
import type { Order, BalanceTx } from "@/components/dashboard/types";

const CURRENCY_SYM: Record<string, string> = { CNY: "¥", USD: "$", EUR: "€", HKD: "HK$" };
const STATUS_CLS: Record<string, string> = {
  paid: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200/60 dark:border-emerald-700/40",
  pending: "text-amber-600 bg-amber-50 dark:bg-amber-950/30 border-amber-200/60 dark:border-amber-700/40",
  failed: "text-red-600 bg-red-50 dark:bg-red-950/30 border-red-200/60 dark:border-red-700/40",
  expired: "text-muted-foreground bg-muted border-border",
};

const TX_TYPE_LABEL: Record<string, string> = {
  hold: "抢注冻结",
  unhold: "抢注解冻",
  snipe: "抢注扣费",
};

export default function AccountOrders() {
  const router = useRouter();
  const { status: authStatus } = useSession();
  const settings = useSiteSettings();
  const { t } = useTranslation();

  const [orders, setOrders] = React.useState<Order[]>([]);
  const [loadingOrders, setLoadingOrders] = React.useState(true);
  const [balanceCents, setBalanceCents] = React.useState(0);
  const [balanceTxs, setBalanceTxs] = React.useState<BalanceTx[]>([]);
  const [loadingBalance, setLoadingBalance] = React.useState(true);

  const currency = (settings.payment_currency || "CNY").toUpperCase();
  const balanceSym = CURRENCY_SYM[currency] ?? currency + " ";

  const PROVIDER_LABEL: Record<string, string> = {
    stripe: t("dashboard.provider_stripe"),
    xunhupay: t("dashboard.provider_xunhupay"),
    alipay: t("dashboard.provider_alipay"),
    paypal: "PayPal",
  };

  const load = React.useCallback(async () => {
    setLoadingOrders(true);
    try {
      const d = await fetch("/api/user/orders").then(r => r.json());
      if (d.orders) setOrders(d.orders);
    } catch { /* ignore */ }
    setLoadingOrders(false);
  }, []);

  React.useEffect(() => {
    if (authStatus !== "authenticated") return;
    void load();
    fetch("/api/user/balance-transactions")
      .then(r => r.json())
      .then(d => {
        if (d.transactions) setBalanceTxs(d.transactions);
        if (typeof d.balanceCents === "number") setBalanceCents(d.balanceCents);
      })
      .catch(() => {})
      .finally(() => setLoadingBalance(false));
  }, [authStatus, load]);

  if (authStatus === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (authStatus === "unauthenticated") {
    router.push(`/login?callbackUrl=${encodeURIComponent("/account/orders")}`);
    return null;
  }

  const statusText = (o: Order) =>
    o.status === "paid" ? t("dashboard.order_paid")
    : o.status === "pending" ? t("dashboard.order_pending")
    : o.status === "failed" ? t("dashboard.order_failed")
    : t("dashboard.order_expired");

  return (
    <>
      <Head>
        <title>{`${t("dashboard.order_history")} · ${settings.site_title}`}</title>
        <meta name="robots" content="noindex" />
      </Head>

      <div className="min-h-screen bg-background">
        <div className="max-w-lg mx-auto px-4 py-6 space-y-5">
          <div className="flex items-center gap-3">
            <Link href="/dashboard?tab=account" className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div>
              <h1 className="text-base font-bold">{t("dashboard.order_history")}</h1>
              <p className="text-[11px] text-muted-foreground">{t("dashboard.order_history")}</p>
            </div>
          </div>

          {/* Balance summary */}
          <div className="glass-panel border border-border rounded-2xl p-4">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                <RiWalletLine className="w-3.5 h-3.5 text-primary" />
                {t("dashboard.balance")}
              </span>
              <span className="text-sm font-bold font-mono tabular-nums">
                {balanceSym}{(balanceCents / 100).toFixed(2)}
              </span>
            </div>
            <Link
              href="/account/recharge"
              className="mt-3 flex items-center justify-center gap-1.5 h-8 rounded-xl text-[11px] font-medium border border-primary/30 text-primary hover:bg-primary/10 transition-colors"
            >
              <RiWalletLine className="w-3.5 h-3.5" /> {t("payment.balance_credit")}
            </Link>
          </div>

          {/* Order history */}
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border/60 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <RiFileTextLine className="w-3.5 h-3.5 text-muted-foreground" />
                <p className="text-xs font-semibold">{t("dashboard.order_history")}</p>
              </div>
              <button
                onClick={() => void load()}
                className="text-[10px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
              >
                <RiRefreshLine className={cn("w-3 h-3", loadingOrders && "animate-spin")} />
                {t("dashboard.refresh")}
              </button>
            </div>

            {loadingOrders ? (
              <div className="p-4 space-y-3 animate-pulse">
                {[1, 2].map(i => <div key={i} className="h-14 rounded-xl bg-muted/50" />)}
              </div>
            ) : orders.length === 0 ? (
              <div className="px-4 py-8 text-center text-[11px] text-muted-foreground">
                <RiCoinLine className="w-7 h-7 mx-auto mb-2 text-muted-foreground/30" />
                {t("dashboard.no_orders")}
              </div>
            ) : (
              <div className="divide-y divide-border/50">
                {orders.map(o => (
                  <div key={o.id} className="px-4 py-3 flex items-center gap-3">
                    <div className={cn(
                      "w-7 h-7 rounded-lg flex items-center justify-center shrink-0",
                      o.status === "paid" ? "bg-emerald-50 dark:bg-emerald-950/30" : "bg-muted"
                    )}>
                      {o.status === "paid"
                        ? <RiCheckboxCircleLine className="w-4 h-4 text-emerald-500" />
                        : <RiCoinLine className="w-4 h-4 text-muted-foreground" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold truncate">{o.plan_name}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {PROVIDER_LABEL[o.provider] ?? o.provider} · {new Date(o.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-xs font-bold font-mono">{CURRENCY_SYM[o.currency] ?? ""}{o.amount.toFixed(2)}</p>
                      <span className={cn(
                        "inline-block text-[9px] font-semibold px-1.5 py-0.5 rounded-full border",
                        STATUS_CLS[o.status] ?? STATUS_CLS.expired
                      )}>
                        {statusText(o)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Balance transactions */}
          <div className="glass-panel border border-border rounded-2xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border/60 flex items-center gap-2">
              <RiWalletLine className="w-3.5 h-3.5 text-muted-foreground" />
              <p className="text-xs font-semibold">{t("dashboard.balance")}</p>
            </div>
            {loadingBalance ? (
              <div className="p-4 space-y-2 animate-pulse">
                {[1, 2, 3].map(i => <div key={i} className="h-8 rounded bg-muted/40" />)}
              </div>
            ) : balanceTxs.length === 0 ? (
              <div className="px-4 py-5 text-center text-[11px] text-muted-foreground/60">
                {t("dashboard.no_balance_history")}
              </div>
            ) : (
              <div className="divide-y divide-border/40 max-h-60 overflow-y-auto">
                {balanceTxs.map(tx => (
                  <div key={tx.id} className="px-4 py-2 flex items-center gap-2">
                    <div className={cn(
                      "w-5 h-5 rounded-full flex items-center justify-center shrink-0",
                      tx.amount_cents >= 0 ? "bg-emerald-50 dark:bg-emerald-950/30" : "bg-red-50 dark:bg-red-950/30"
                    )}>
                      {tx.amount_cents >= 0
                        ? <span className="text-emerald-600 text-xs font-bold">+</span>
                        : <span className="text-red-500 text-xs font-bold">−</span>}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] text-muted-foreground truncate">
                        {TX_TYPE_LABEL[tx.type] ?? tx.description ?? tx.type}
                      </p>
                      <p className="text-[9px] text-muted-foreground/50">
                        {new Date(tx.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <span className={cn(
                      "text-[11px] font-bold font-mono tabular-nums shrink-0",
                      tx.amount_cents >= 0 ? "text-emerald-600" : "text-red-500"
                    )}>
                      {tx.amount_cents >= 0 ? "+" : ""}{balanceSym}{(tx.amount_cents / 100).toFixed(2)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}