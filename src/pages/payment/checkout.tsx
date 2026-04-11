import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { cn, CURRENCY_SYMBOL } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiLoader4Line, RiBankCardLine, RiAlipayLine, RiArrowLeftSLine,
  RiCheckLine, RiShieldCheckLine, RiPriceTag3Line, RiCalendarLine,
  RiLockLine, RiExternalLinkLine, RiPaypalLine, RiQrCodeLine,
} from "@remixicon/react";

type Plan = {
  id: string; name: string; description: string | null;
  price: number; currency: string; duration_days: number | null;
  is_recurring: boolean; grants_subscription: boolean;
  balance_grant_cents: number;
};

export default function PaymentCheckout() {
  const router = useRouter();
  const { data: session, status: authStatus } = useSession();
  const settings = useSiteSettings();
  const { t } = useTranslation();

  const PROVIDER_INFO = {
    stripe:   { label: t("payment.provider_stripe_label"),   icon: RiBankCardLine, color: "text-indigo-600 dark:text-indigo-400", hint: t("payment.provider_stripe_hint") },
    xunhupay: { label: t("payment.provider_xunhupay_label"), icon: RiAlipayLine,   color: "text-blue-600 dark:text-blue-400",   hint: t("payment.provider_xunhupay_hint") },
    alipay:   { label: t("payment.provider_alipay_label"),   icon: RiAlipayLine,   color: "text-sky-600 dark:text-sky-400",     hint: t("payment.provider_alipay_hint") },
    paypal:   { label: t("payment.provider_paypal_label"),   icon: RiPaypalLine,   color: "text-[#003087] dark:text-blue-400",  hint: t("payment.provider_paypal_hint") },
    wechat:   { label: "微信支付",                           icon: RiQrCodeLine,   color: "text-green-600 dark:text-green-400", hint: "微信扫码支付" },
  };

  const planFromUrl = typeof router.query.plan === "string" ? router.query.plan : null;

  const [plans, setPlans] = React.useState<Plan[]>([]);
  const [selectedPlan, setSelectedPlan] = React.useState<string | null>(planFromUrl);
  const [selectedProvider, setSelectedProvider] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [paying, setPaying] = React.useState(false);
  const [xunhupayForm, setXunhupayForm] = React.useState<{ params: Record<string, string>; endpoint: string } | null>(null);
  const xunhupayRef = React.useRef<HTMLFormElement>(null);

  const enabledProviders = React.useMemo(() => {
    const p: string[] = [];
    if (settings.payment_stripe_enabled) p.push("stripe");
    if (settings.payment_xunhupay_enabled) p.push("xunhupay");
    if (settings.payment_alipay_enabled) p.push("alipay");
    if (settings.payment_paypal_enabled) p.push("paypal");
    if (settings.payment_wechat_enabled) p.push("wechat");
    return p;
  }, [settings]);

  React.useEffect(() => {
    fetch("/api/payment/plans")
      .then(r => r.json())
      .then(d => { setPlans(d.plans ?? []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    if (enabledProviders.length === 1) setSelectedProvider(enabledProviders[0]);
  }, [enabledProviders]);

  React.useEffect(() => {
    if (xunhupayForm && xunhupayRef.current) {
      xunhupayRef.current.submit();
    }
  }, [xunhupayForm]);

  async function handlePay() {
    if (!selectedPlan || !selectedProvider) {
      toast.error(t("payment.checkout_err_select"));
      return;
    }
    if (authStatus !== "authenticated") {
      router.push(`/login?callbackUrl=${encodeURIComponent("/payment/checkout")}`);
      return;
    }
    setPaying(true);
    try {
      const r = await fetch("/api/payment/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ planId: selectedPlan, provider: selectedProvider }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);

      if (d.provider === "stripe" || d.provider === "alipay") {
        window.location.href = d.url;
      } else if (d.provider === "xunhupay" || d.provider === "wechat") {
        setXunhupayForm({ params: d.params, endpoint: d.endpoint });
      } else if (d.provider === "paypal") {
        window.location.href = d.url;
      }
    } catch (e: unknown) {
      toast.error((e as Error).message || t("payment.checkout_err_failed"));
      setPaying(false);
    }
  }

  const plan = plans.find(p => p.id === selectedPlan);
  const sym = plan ? (CURRENCY_SYMBOL[plan.currency] ?? plan.currency) : "¥";

  if (authStatus === "loading" || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (authStatus === "unauthenticated") {
    router.push(`/login?callbackUrl=${encodeURIComponent("/payment/checkout")}`);
    return null;
  }

  if (plans.length === 0) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 text-center px-4">
        <RiPriceTag3Line className="w-10 h-10 text-muted-foreground/30" />
        <p className="text-sm text-muted-foreground">{t("payment.checkout_no_plans")}</p>
        <Link href="/dashboard" className="text-xs text-primary hover:underline">{t("payment.checkout_back_dashboard")}</Link>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title>{`${t("payment.checkout_title")} · ${settings.site_title}`}</title>
        <meta name="robots" content="noindex" />
      </Head>

      {xunhupayForm && (
        <form ref={xunhupayRef} action={xunhupayForm.endpoint} method="POST" style={{ display: "none" }}>
          {Object.entries(xunhupayForm.params).map(([k, v]) => (
            <input key={k} type="hidden" name={k} value={v} />
          ))}
        </form>
      )}

      <div className="min-h-screen bg-background">
        <div className="max-w-lg mx-auto px-4 py-6 space-y-5">
          <div className="flex items-center gap-3">
            <Link href="/dashboard" className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div>
              <h1 className="text-base font-bold">{t("payment.checkout_title")}</h1>
              <p className="text-[11px] text-muted-foreground">{t("payment.checkout_subtitle")}</p>
            </div>
          </div>

          <div className="space-y-2">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
              {t("payment.checkout_select_plan")}
            </h2>
            {plans.map(p => {
              const selected = selectedPlan === p.id;
              return (
                <motion.button
                  key={p.id}
                  onClick={() => setSelectedPlan(p.id)}
                  whileTap={{ scale: 0.99 }}
                  className={cn(
                    "w-full text-left p-4 rounded-2xl border-2 transition-all",
                    selected
                      ? "border-primary bg-primary/5"
                      : "border-border hover:border-primary/40 bg-card"
                  )}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-sm">{p.name}</span>
                        {p.grants_subscription && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-300 border border-violet-200 dark:border-violet-800 font-medium">
                            {t("payment.checkout_includes_access")}
                          </span>
                        )}
                        {(p.balance_grant_cents ?? 0) > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800 font-medium">
                            +{sym}{(p.balance_grant_cents / 100).toFixed(0)} {t("payment.balance_credit")}
                          </span>
                        )}
                      </div>
                      {p.description && (
                        <p className="text-xs text-muted-foreground mt-0.5">{p.description}</p>
                      )}
                      <div className="flex items-center gap-2 mt-1.5 text-[11px] text-muted-foreground">
                        <RiCalendarLine className="w-3 h-3" />
                        {p.duration_days
                          ? t("payment.checkout_days").replace("{{n}}", String(p.duration_days))
                          : t("payment.checkout_lifetime")
                        }
                        {p.is_recurring && <span className="text-blue-500">{t("payment.checkout_recurring")}</span>}
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-xl font-black">{sym}{p.price.toFixed(0)}</span>
                      <div className="text-[10px] text-muted-foreground">{p.currency}</div>
                    </div>
                  </div>
                  {selected && (
                    <div className="mt-2 flex items-center gap-1 text-[11px] text-primary">
                      <RiCheckLine className="w-3.5 h-3.5" />
                      {t("payment.checkout_selected")}
                    </div>
                  )}
                </motion.button>
              );
            })}
          </div>

          {enabledProviders.length > 0 && (
            <div className="space-y-2">
              <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                {t("payment.checkout_payment_method")}
              </h2>
              {enabledProviders.map(provider => {
                const info = PROVIDER_INFO[provider as keyof typeof PROVIDER_INFO];
                if (!info) return null;
                const Icon = info.icon;
                const sel = selectedProvider === provider;
                return (
                  <button
                    key={provider}
                    onClick={() => setSelectedProvider(provider)}
                    className={cn(
                      "w-full text-left p-3.5 rounded-xl border-2 transition-all flex items-start gap-3",
                      sel ? "border-primary bg-primary/5" : "border-border hover:border-primary/30 bg-card"
                    )}
                  >
                    <Icon className={cn("w-5 h-5 mt-0.5 shrink-0", info.color)} />
                    <div className="flex-1">
                      <div className="text-sm font-medium">{info.label}</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">{info.hint}</div>
                    </div>
                    {sel && <RiCheckLine className="w-4 h-4 text-primary shrink-0 mt-0.5" />}
                  </button>
                );
              })}
            </div>
          )}

          {enabledProviders.length === 0 && (
            <div className="rounded-xl border border-amber-200/50 dark:border-amber-700/30 bg-amber-50 dark:bg-amber-950/20 p-4 text-sm text-amber-700 dark:text-amber-400">
              {t("payment.checkout_no_providers")}
            </div>
          )}

          {plan && selectedProvider && (
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-2xl border border-border bg-card p-4 space-y-2"
              >
                <h3 className="text-xs font-semibold text-muted-foreground">{t("payment.checkout_order_summary")}</h3>
                <div className="flex justify-between text-sm">
                  <span>{plan.name}</span>
                  <span className="font-bold">{sym}{plan.price.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-[11px] text-muted-foreground">
                  <span>{t("payment.checkout_validity")}</span>
                  <span>{plan.duration_days
                    ? t("payment.checkout_days").replace("{{n}}", String(plan.duration_days))
                    : t("payment.checkout_lifetime")
                  }</span>
                </div>
                {(plan.balance_grant_cents ?? 0) > 0 && (
                  <div className="flex justify-between text-[11px] text-amber-600 dark:text-amber-400">
                    <span>{t("payment.balance_credit")}</span>
                    <span className="font-medium">+{sym}{(plan.balance_grant_cents / 100).toFixed(2)}</span>
                  </div>
                )}
                <div className="border-t border-border/40 pt-2 flex justify-between font-bold">
                  <span>{t("payment.checkout_total")}</span>
                  <span className="text-primary">{sym}{plan.price.toFixed(2)}</span>
                </div>
              </motion.div>
            </AnimatePresence>
          )}

          <Button
            className="w-full h-11 font-semibold text-base rounded-2xl"
            onClick={handlePay}
            disabled={!selectedPlan || !selectedProvider || paying || enabledProviders.length === 0}
          >
            {paying ? (
              <><RiLoader4Line className="w-4 h-4 animate-spin mr-2" />{t("payment.checkout_paying")}</>
            ) : (
              <><RiLockLine className="w-4 h-4 mr-2" />
                {plan
                  ? t("payment.checkout_pay_amount").replace("{{amount}}", `${sym}${plan.price.toFixed(2)}`)
                  : t("payment.checkout_pay_now")}
              </>
            )}
          </Button>

          <div className="flex items-center justify-center gap-1.5 text-[11px] text-muted-foreground/60">
            <RiShieldCheckLine className="w-3.5 h-3.5" />
            <span>{t("payment.checkout_secure")}</span>
          </div>
        </div>
      </div>
    </>
  );
}
