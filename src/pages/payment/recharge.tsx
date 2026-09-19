import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { cn, CURRENCY_SYMBOL } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import { motion } from "framer-motion";
import {
  RiLoader4Line, RiBankCardLine, RiAlipayLine, RiArrowLeftSLine,
  RiCheckLine, RiShieldCheckLine, RiWalletLine, RiPaypalLine, RiQrCodeLine,
  RiCoinLine,
} from "@remixicon/react";

const MIN_CENTS = 100;
const MAX_CENTS = 5_000_000;
const QUICK_AMOUNTS = [10, 30, 50, 100, 200, 500];

export default function PaymentRecharge() {
  const router = useRouter();
  const { status: authStatus } = useSession();
  const settings = useSiteSettings();
  const { t } = useTranslation();

  const currency = settings.payment_currency || "CNY";
  const sym = CURRENCY_SYMBOL[currency] ?? currency;

  const PROVIDER_INFO = {
    stripe:   { label: t("payment.provider_stripe_label"),   icon: RiBankCardLine, color: "text-indigo-600 dark:text-indigo-400", hint: t("payment.provider_stripe_hint") },
    xunhupay: { label: t("payment.provider_xunhupay_label"), icon: RiAlipayLine,   color: "text-blue-600 dark:text-blue-400",   hint: t("payment.provider_xunhupay_hint") },
    alipay:   { label: t("payment.provider_alipay_label"),   icon: RiAlipayLine,   color: "text-sky-600 dark:text-sky-400",     hint: t("payment.provider_alipay_hint") },
    paypal:   { label: t("payment.provider_paypal_label"),   icon: RiPaypalLine,   color: "text-[#003087] dark:text-blue-400",  hint: t("payment.provider_paypal_hint") },
    wechat:   { label: "微信支付",                           icon: RiQrCodeLine,   color: "text-green-600 dark:text-green-400", hint: "微信扫码支付" },
  };

  const [amountText, setAmountText] = React.useState("");
  const [selectedProvider, setSelectedProvider] = React.useState<string | null>(null);
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
    if (enabledProviders.length === 1) setSelectedProvider(enabledProviders[0]);
  }, [enabledProviders]);

  React.useEffect(() => {
    if (xunhupayForm && xunhupayRef.current) {
      xunhupayRef.current.submit();
    }
  }, [xunhupayForm]);

  const amountCents = React.useMemo(() => {
    const n = Number(amountText);
    if (!Number.isFinite(n) || n <= 0) return 0;
    return Math.round(n * 100);
  }, [amountText]);

  const amountValid = amountCents >= MIN_CENTS && amountCents <= MAX_CENTS;

  async function handlePay() {
    if (!amountValid) {
      toast.error(t("payment.recharge_min_hint", { min: `${sym}${(MIN_CENTS / 100).toFixed(0)}` }));
      return;
    }
    if (!selectedProvider) {
      toast.error(t("payment.checkout_err_select"));
      return;
    }
    setPaying(true);
    try {
      const r = await fetch("/api/payment/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ amountCents, provider: selectedProvider }),
      });
      const d = await r.json();
      if (!d.ok) throw new Error(d.error);

      if (d.provider === "stripe" || d.provider === "alipay" || d.provider === "paypal") {
        window.location.href = d.url;
      } else if (d.provider === "xunhupay" || d.provider === "wechat") {
        setXunhupayForm({ params: d.params, endpoint: d.endpoint });
      }
    } catch (e: unknown) {
      toast.error((e as Error).message || t("payment.checkout_err_failed"));
      setPaying(false);
    }
  }

  if (authStatus === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (authStatus === "unauthenticated") {
    router.push(`/login?callbackUrl=${encodeURIComponent("/payment/recharge")}`);
    return null;
  }

  return (
    <>
      <Head>
        <title>{`${t("payment.recharge_title")} · ${settings.site_title}`}</title>
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
            <Link href="/dashboard?tab=account" className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div>
              <h1 className="text-base font-bold">{t("payment.recharge_title")}</h1>
              <p className="text-[11px] text-muted-foreground">{t("payment.recharge_subtitle")}</p>
            </div>
          </div>

          {/* Amount input */}
          <div className="space-y-2">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
              {t("payment.recharge_amount_label")}
            </h2>
            <div className="relative">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-xl font-bold text-muted-foreground">{sym}</span>
              <Input
                type="number"
                inputMode="decimal"
                min={MIN_CENTS / 100}
                max={MAX_CENTS / 100}
                step="0.01"
                value={amountText}
                onChange={e => setAmountText(e.target.value)}
                placeholder={t("payment.recharge_amount_placeholder")}
                className="h-14 pl-11 text-xl font-bold rounded-2xl"
                disabled={paying}
              />
            </div>
            <div className="flex items-center justify-between text-[11px] text-muted-foreground px-1">
              <span>{t("payment.recharge_min_hint", { min: `${sym}${(MIN_CENTS / 100).toFixed(0)}` })}</span>
              <span>{t("payment.recharge_max_hint", { max: `${sym}${(MAX_CENTS / 100).toFixed(0)}` })}</span>
            </div>
          </div>

          {/* Quick amounts */}
          <div className="space-y-2">
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
              {t("payment.recharge_quick_amounts")}
            </h2>
            <div className="grid grid-cols-3 gap-2">
              {QUICK_AMOUNTS.map(a => {
                const active = amountCents === a * 100;
                return (
                  <motion.button
                    key={a}
                    type="button"
                    whileTap={{ scale: 0.97 }}
                    onClick={() => setAmountText(String(a))}
                    disabled={paying}
                    className={cn(
                      "h-11 rounded-xl border-2 font-bold text-sm transition-all",
                      active
                        ? "border-primary bg-primary/5 text-primary"
                        : "border-border hover:border-primary/40 text-foreground"
                    )}
                  >
                    {sym}{a}
                  </motion.button>
                );
              })}
            </div>
          </div>

          {/* Payment methods */}
          {enabledProviders.length > 0 ? (
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
                    type="button"
                    onClick={() => setSelectedProvider(provider)}
                    disabled={paying}
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
          ) : (
            <div className="rounded-xl border border-amber-200/50 dark:border-amber-700/30 bg-amber-50 dark:bg-amber-950/20 p-4 text-sm text-amber-700 dark:text-amber-400">
              {t("payment.checkout_no_providers")}
            </div>
          )}

          {/* Order summary */}
          {amountValid && (
            <div className="rounded-2xl border border-border bg-card p-4 space-y-2">
              <h3 className="text-xs font-semibold text-muted-foreground">{t("payment.checkout_order_summary")}</h3>
              <div className="flex justify-between text-sm">
                <span className="flex items-center gap-1.5"><RiWalletLine className="w-3.5 h-3.5" />{t("payment.recharge_title")}</span>
                <span className="font-bold">{sym}{(amountCents / 100).toFixed(2)}</span>
              </div>
              <div className="border-t border-border/40 pt-2 flex justify-between font-bold">
                <span>{t("payment.checkout_total")}</span>
                <span className="text-primary">{sym}{(amountCents / 100).toFixed(2)}</span>
              </div>
            </div>
          )}

          <Button
            className="w-full h-11 font-semibold text-base rounded-2xl gap-2"
            onClick={handlePay}
            disabled={!amountValid || !selectedProvider || paying || enabledProviders.length === 0}
          >
            {paying ? (
              <><RiLoader4Line className="w-4 h-4 animate-spin" />{t("payment.checkout_paying")}</>
            ) : (
              <><RiCoinLine className="w-4 h-4" />
                {amountValid
                  ? t("payment.recharge_pay_amount", { amount: `${sym}${(amountCents / 100).toFixed(2)}` })
                  : t("payment.recharge_amount_label")}
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
