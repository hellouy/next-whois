import React from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiVipCrownLine, RiWalletLine, RiArrowDownSLine,
  RiAddLine, RiSubtractLine, RiStarLine, RiCoinLine, RiGiftLine,
  RiCoupon2Line, RiFileTextLine, RiRefreshLine, RiCheckboxCircleLine,
  RiArrowRightLine,
} from "@remixicon/react";
import type { Order, BalanceTx, Plan, TFunction } from "./types";
import type { SiteSettings } from "@/lib/site-settings";

export type MembershipTabProps = {
  subscriptionAccessDB: boolean | null;
  subscriptionExpiresAt: string | null;
  loadingData: boolean;
  balanceCents: number;
  membershipPlan: string | null;
  orders: Order[];
  loadingOrders: boolean;
  balanceTxs: BalanceTx[];
  showBalanceTxs: boolean;
  loadingBalanceTxs: boolean;
  plans: Plan[];
  loadingPlans: boolean;
  redeemCode: string;
  redeeming: boolean;
  paymentEnabled: boolean;
  siteSettings: SiteSettings;
  t: TFunction;
  setShowBalanceTxs: (v: boolean) => void;
  setLoadingBalanceTxs: (v: boolean) => void;
  setBalanceTxs: (txs: BalanceTx[]) => void;
  setBalanceCents: (n: number) => void;
  setOrders: (orders: Order[]) => void;
  setLoadingOrders: (v: boolean) => void;
  onRedeemCode: (e: React.FormEvent) => void;
  setRedeemCode: (v: string) => void;
};

const CURRENCY_SYM: Record<string, string> = { CNY: "¥", USD: "$", EUR: "€", HKD: "HK$" };
const STATUS_CLS: Record<string, string> = {
  paid: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200/60 dark:border-emerald-700/40",
  pending: "text-amber-600 bg-amber-50 dark:bg-amber-950/30 border-amber-200/60 dark:border-amber-700/40",
  failed: "text-red-600 bg-red-50 dark:bg-red-950/30 border-red-200/60 dark:border-red-700/40",
  expired: "text-muted-foreground bg-muted border-border",
};

export function MembershipTab({
  subscriptionAccessDB, subscriptionExpiresAt, loadingData,
  balanceCents, membershipPlan, orders, loadingOrders,
  balanceTxs, showBalanceTxs, loadingBalanceTxs,
  plans, loadingPlans, redeemCode, redeeming,
  paymentEnabled, siteSettings, t,
  setShowBalanceTxs, setLoadingBalanceTxs, setBalanceTxs, setBalanceCents,
  setOrders, setLoadingOrders, onRedeemCode, setRedeemCode,
}: MembershipTabProps) {
  if (subscriptionAccessDB === null && loadingData) {
    return (
      <motion.div key="membership-loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4 animate-pulse">
        <div className="h-28 rounded-2xl bg-muted/50" />
        <div className="h-36 rounded-2xl bg-muted/50" />
        <div className="h-24 rounded-2xl bg-muted/50" />
      </motion.div>
    );
  }

  const isLifetime = subscriptionAccessDB && !subscriptionExpiresAt;
  const expiresDate = subscriptionExpiresAt ? new Date(subscriptionExpiresAt) : null;
  const remainingDays = expiresDate ? Math.ceil((expiresDate.getTime() - Date.now()) / 86_400_000) : null;
  const currencyCode = ((siteSettings.payment_currency as string) || "CNY").toUpperCase();
  const balanceSym = CURRENCY_SYM[currencyCode] ?? currencyCode + " ";
  const PROVIDER_LABEL: Record<string, string> = {
    stripe: t("dashboard.provider_stripe"), xunhupay: t("dashboard.provider_xunhupay"), alipay: t("dashboard.provider_alipay"), paypal: "PayPal",
  };

  return (
    <motion.div key="membership" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }} className="space-y-4">

      {/* Membership status card */}
      <div className={cn(
        "glass-panel border rounded-2xl overflow-hidden",
        subscriptionAccessDB ? "border-violet-200/60 dark:border-violet-700/30" : "border-border"
      )}>
        <div className={cn(
          "px-4 pt-4 pb-3 flex items-center gap-3",
          subscriptionAccessDB ? "bg-violet-50/60 dark:bg-violet-950/10" : ""
        )}>
          <div className={cn(
            "w-10 h-10 rounded-xl flex items-center justify-center shrink-0",
            subscriptionAccessDB ? "bg-violet-100 dark:bg-violet-900/30" : "bg-muted"
          )}>
            <RiVipCrownLine className={cn("w-5 h-5", subscriptionAccessDB ? "text-violet-600 dark:text-violet-400" : "text-muted-foreground")} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-bold">
              {subscriptionAccessDB
                ? (membershipPlan || t("dashboard.member_active_label"))
                : t("dashboard.non_member")}
            </p>
            {subscriptionAccessDB ? (
              <p className="text-[10px] text-muted-foreground">
                {isLifetime ? t("dashboard.lifetime_member") : expiresDate
                  ? t("dashboard.valid_until_details", { date: expiresDate.toLocaleDateString(), days: remainingDays ?? 0 })
                  : t("dashboard.in_membership")}
              </p>
            ) : (
              <p className="text-[10px] text-muted-foreground">{t("dashboard.upgrade_sub_desc")}</p>
            )}
          </div>
          {subscriptionAccessDB && (
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-300 shrink-0">
              {isLifetime ? t("dashboard.lifetime_badge") : t("dashboard.active_badge")}
            </span>
          )}
        </div>

        {/* Balance row */}
        <button
          type="button"
          onClick={() => {
            const next = !showBalanceTxs;
            setShowBalanceTxs(next);
            if (next && balanceTxs.length === 0) {
              setLoadingBalanceTxs(true);
              fetch("/api/user/balance-transactions")
                .then(r => r.json())
                .then(d => {
                  if (d.transactions) setBalanceTxs(d.transactions);
                  if (typeof d.balanceCents === "number") setBalanceCents(d.balanceCents);
                })
                .catch(() => {})
                .finally(() => setLoadingBalanceTxs(false));
            }
          }}
          className="px-4 py-3 border-t border-border/60 flex items-center justify-between w-full hover:bg-muted/30 transition-colors group"
        >
          <span className="text-[11px] text-muted-foreground flex items-center gap-1.5">
            <RiWalletLine className="w-3.5 h-3.5" /> {t("dashboard.balance")}
          </span>
          <div className="flex items-center gap-1.5">
            <span className="text-sm font-bold font-mono">
              {balanceSym}{(balanceCents / 100).toFixed(2)}
            </span>
            <RiArrowDownSLine className={cn(
              "w-3.5 h-3.5 text-muted-foreground/50 transition-transform",
              showBalanceTxs ? "rotate-180" : ""
            )} />
          </div>
        </button>

        {/* Balance transaction history */}
        {showBalanceTxs && (
          <div className="border-t border-border/60">
            {loadingBalanceTxs ? (
              <div className="px-4 py-3 space-y-2 animate-pulse">
                {[1,2,3].map(i => <div key={i} className="h-8 rounded bg-muted/40" />)}
              </div>
            ) : balanceTxs.length === 0 ? (
              <div className="px-4 py-5 text-center text-[11px] text-muted-foreground/60">
                {t("dashboard.no_balance_history")}
              </div>
            ) : (
              <div className="divide-y divide-border/40 max-h-48 overflow-y-auto">
                {balanceTxs.map(tx => (
                  <div key={tx.id} className="px-4 py-2 flex items-center gap-2">
                    <div className={cn(
                      "w-5 h-5 rounded-full flex items-center justify-center shrink-0",
                      tx.amount_cents >= 0 ? "bg-emerald-50 dark:bg-emerald-950/30" : "bg-red-50 dark:bg-red-950/30"
                    )}>
                      {tx.amount_cents >= 0
                        ? <RiAddLine className="w-3 h-3 text-emerald-600" />
                        : <RiSubtractLine className="w-3 h-3 text-red-500" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] text-muted-foreground truncate">
                        {tx.description || tx.type}
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
        )}
      </div>

      {/* Member benefits */}
      {!subscriptionAccessDB && (
        <div className="glass-panel border border-violet-200/50 dark:border-violet-800/30 rounded-2xl overflow-hidden">
          <div className="px-4 pt-3 pb-2 bg-violet-50/50 dark:bg-violet-950/10 flex items-center gap-2 border-b border-violet-100/60 dark:border-violet-800/20">
            <RiVipCrownLine className="w-3.5 h-3.5 text-violet-500" />
            <p className="text-xs font-bold">{t("dashboard.upgrade_title")}</p>
          </div>
          <div className="px-4 py-3 grid grid-cols-1 gap-1.5">
            {[
              { icon: "bell",         text: t("dashboard.benefit_subs") },
              { icon: "shield",       text: t("dashboard.benefit_styles") },
              { icon: "link",         text: t("dashboard.benefit_links") },
              { icon: "edit",         text: t("dashboard.benefit_tag_len") },
              { icon: "chart",        text: t("dashboard.benefit_history") },
              { icon: "flash",        text: t("dashboard.benefit_priority") },
            ].map((item, i) => (
              <div key={i} className="flex items-start gap-2.5">
                <RiVipCrownLine className="w-3.5 h-3.5 text-violet-500 mt-0.5 shrink-0" />
                <p className="text-[11px] text-muted-foreground leading-snug">{item.text}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Purchase membership */}
      <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
        <div className="flex items-center gap-2">
          <RiStarLine className="w-3.5 h-3.5 text-violet-500" />
          <p className="text-xs font-semibold">{t("dashboard.buy_membership")}</p>
          {plans.length > 0 && !paymentEnabled && (
            <span className="text-[10px] text-muted-foreground/60 ml-auto">{t("dashboard.activation_code_redeemable")}</span>
          )}
        </div>

        {loadingPlans ? (
          <div className="grid grid-cols-3 gap-2 animate-pulse">
            {[1, 2, 3].map(i => <div key={i} className="h-[72px] rounded-xl bg-muted/50" />)}
          </div>
        ) : plans.length > 0 ? (() => {
          const totalPlans = plans.length;
          const getBadge = (idx: number) => {
            if (totalPlans >= 3 && idx === totalPlans - 1) return t("dashboard.plan_badge_best_value");
            if (totalPlans >= 3 && idx === totalPlans - 2) return t("dashboard.plan_badge_recommended");
            if (totalPlans === 2 && idx === 1) return t("dashboard.plan_badge_best_value");
            return null;
          };
          const fmtDur = (p: Plan) => {
            if (!p.duration_days) return t("dashboard.plan_lifetime_period");
            return `${p.duration_days}天`;
          };
          const fmtPrice = (p: Plan) => {
            const sym = p.currency?.toUpperCase() === "CNY" ? "¥" : p.currency?.toUpperCase() === "USD" ? "$" : (p.currency ?? "¥");
            return `${sym}${p.price.toFixed(2).replace(/\.00$/, "")}`;
          };
          const cols = totalPlans <= 2 ? "grid-cols-2" : totalPlans === 4 ? "grid-cols-2" : "grid-cols-3";
          return (
            <div className={cn("grid gap-2", cols)}>
              {plans.map((p, idx) => {
                const badge = getBadge(idx);
                const isHighlight = !!badge;
                return (
                  <Link
                    key={p.id}
                    href={`/payment/checkout?plan=${p.id}`}
                    className={cn(
                      "relative flex flex-col items-center gap-1 px-2 py-3 rounded-xl border text-center transition-all group hover:border-violet-400/60 hover:bg-violet-50/50 dark:hover:bg-violet-950/10",
                      isHighlight ? "border-violet-300/70 dark:border-violet-700/40 bg-violet-50/30 dark:bg-violet-950/10" : "border-border"
                    )}
                  >
                    {badge && (
                      <span className="absolute -top-2 left-1/2 -translate-x-1/2 text-[8px] font-bold px-1.5 py-0.5 rounded-full bg-violet-500 text-white whitespace-nowrap">
                        {badge}
                      </span>
                    )}
                    {p.balance_grant_cents > 0 && !p.grants_subscription
                      ? <RiCoinLine className={cn("w-4 h-4", isHighlight ? "text-amber-500" : "text-muted-foreground group-hover:text-amber-500")} />
                      : <RiVipCrownLine className={cn("w-4 h-4", isHighlight ? "text-violet-500" : "text-muted-foreground group-hover:text-violet-500")} />}
                    <p className="text-[10px] font-semibold leading-tight line-clamp-1">{p.name}</p>
                    {p.balance_grant_cents > 0 ? (
                      <p className="text-[9px] text-amber-600 dark:text-amber-400 font-medium">+¥{(p.balance_grant_cents / 100).toFixed(0)} 余额</p>
                    ) : (
                      <p className="text-[9px] text-muted-foreground">{fmtDur(p)}</p>
                    )}
                    <p className="text-[10px] font-bold text-violet-600 dark:text-violet-400 mt-0.5">{fmtPrice(p)}</p>
                  </Link>
                );
              })}
            </div>
          );
        })() : (
          <div className="grid grid-cols-3 gap-2 opacity-40 pointer-events-none">
            {[
              { label: t("dashboard.plan_monthly"), sub: t("dashboard.plan_monthly_period"), badge: null },
              { label: t("dashboard.plan_yearly"), sub: t("dashboard.plan_yearly_period"), badge: t("dashboard.plan_badge_recommended") },
              { label: t("dashboard.plan_lifetime"), sub: t("dashboard.plan_lifetime_period"), badge: t("dashboard.plan_badge_best_value") },
            ].map(p => (
              <div key={p.label} className={cn(
                "relative flex flex-col items-center gap-1 px-2 py-3 rounded-xl border text-center",
                p.badge === t("dashboard.plan_badge_recommended") ? "border-violet-300/70 dark:border-violet-700/40 bg-violet-50/30 dark:bg-violet-950/10" : "border-border"
              )}>
                {p.badge && (
                  <span className="absolute -top-2 left-1/2 -translate-x-1/2 text-[8px] font-bold px-1.5 py-0.5 rounded-full bg-violet-500 text-white whitespace-nowrap">
                    {p.badge}
                  </span>
                )}
                <RiVipCrownLine className="w-4 h-4 text-muted-foreground" />
                <p className="text-[10px] font-semibold leading-tight">{p.label}</p>
                <p className="text-[9px] text-muted-foreground">{p.sub}</p>
              </div>
            ))}
          </div>
        )}

        <Link href="/payment/checkout" className="flex items-center justify-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground transition-colors py-1">
          {t("dashboard.view_all_plans")} <RiArrowRightLine className="w-3 h-3" />
        </Link>
        {!paymentEnabled && (
          <p className="text-[10px] text-muted-foreground/60 text-center -mt-1">{t("dashboard.payment_note")}</p>
        )}
      </div>

      {/* Activation code */}
      <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
        <div className="flex items-center gap-2">
          <RiCoupon2Line className="w-3.5 h-3.5 text-amber-500" />
          <p className="text-xs font-semibold">{t("dashboard.activation_code")}</p>
        </div>
        <form onSubmit={onRedeemCode} className="flex gap-2">
          <Input
            value={redeemCode}
            onChange={e => setRedeemCode(e.target.value.toUpperCase())}
            placeholder={t("dashboard.activation_placeholder")}
            className="h-9 rounded-xl text-sm font-mono flex-1"
          />
          <Button type="submit" disabled={redeeming || !redeemCode.trim()} size="sm" className="h-9 rounded-xl px-3 shrink-0">
            {redeeming ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiGiftLine className="w-4 h-4" />}
          </Button>
        </form>
        <p className="text-[10px] text-muted-foreground">{t("dashboard.activation_note")}</p>
      </div>

      {/* Order history */}
      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border/60 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <RiFileTextLine className="w-3.5 h-3.5 text-muted-foreground" />
            <p className="text-xs font-semibold">{t("dashboard.order_history")}</p>
          </div>
          <button
            onClick={() => {
              setLoadingOrders(true);
              fetch("/api/user/orders").then(r => r.json()).then(d => {
                if (d.orders) setOrders(d.orders);
              }).catch(() => {}).finally(() => setLoadingOrders(false));
            }}
            className="text-[10px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
          >
            <RiRefreshLine className={cn("w-3 h-3", loadingOrders && "animate-spin")} />
            {t("dashboard.refresh")}
          </button>
        </div>

        {loadingOrders ? (
          <div className="p-4 space-y-3 animate-pulse">
            {[1,2].map(i => <div key={i} className="h-14 rounded-xl bg-muted/50" />)}
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
                    {o.status === "paid" ? t("dashboard.order_paid") : o.status === "pending" ? t("dashboard.order_pending") : o.status === "failed" ? t("dashboard.order_failed") : t("dashboard.order_expired")}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Payment note */}
      <div className="px-1 text-[10px] text-muted-foreground/60 text-center leading-relaxed">
        {t("dashboard.payment_methods")}
      </div>
    </motion.div>
  );
}
