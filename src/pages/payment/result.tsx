import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import { motion } from "framer-motion";
import {
  RiLoader4Line, RiCheckLine, RiCloseLine, RiArrowRightLine,
  RiShieldCheckLine, RiRefreshLine,
} from "@remixicon/react";

type Order = {
  id: string; status: string; amount: number; currency: string;
  plan_name: string; provider: string; paid_at: string | null;
};

const CURRENCY_SYMBOL: Record<string, string> = { CNY: "¥", USD: "$", EUR: "€", HKD: "HK$", GBP: "£", JPY: "¥" };

export default function PaymentResult() {
  const router = useRouter();
  const { status: authStatus, update: updateSession } = useSession();
  const settings = useSiteSettings();
  const { t } = useTranslation();

  const orderId = typeof router.query.order === "string" ? router.query.order : null;
  const urlStatus = typeof router.query.status === "string" ? router.query.status : null;

  const [order, setOrder] = React.useState<Order | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [pollCount, setPollCount] = React.useState(0);
  const sessionHealedRef = React.useRef(false);

  React.useEffect(() => {
    if (!orderId || authStatus !== "authenticated") {
      if (authStatus !== "loading") setLoading(false);
      return;
    }

    async function fetchOrder() {
      try {
        const r = await fetch(`/api/payment/status?order=${orderId}`);
        const d = await r.json();
        if (d.order) {
          setOrder(d.order);
          if (d.order.status === "paid") { setLoading(false); return; }
        }
      } catch {}
      setLoading(false);
    }

    fetchOrder();
  }, [orderId, authStatus]);

  // Poll for payment confirmation (max 16 × 2.5s = 40s)
  React.useEffect(() => {
    if (!order || order.status === "paid" || urlStatus === "cancel") return;
    if (pollCount >= 16) return;
    const timer = setTimeout(async () => {
      try {
        const r = await fetch(`/api/payment/status?order=${orderId}`);
        const d = await r.json();
        if (d.order) setOrder(d.order);
      } catch {}
      setPollCount(c => c + 1);
    }, 2500);
    return () => clearTimeout(timer);
  }, [order, pollCount, orderId, urlStatus]);

  // Heal the JWT subscription status when payment is confirmed paid
  React.useEffect(() => {
    if (order?.status === "paid" && !sessionHealedRef.current && updateSession) {
      sessionHealedRef.current = true;
      updateSession({ refreshSubscription: true }).catch(() => {});
    }
  }, [order?.status, updateSession]);

  if (authStatus === "loading" || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const isPaid = order?.status === "paid";
  const isCancelled = urlStatus === "cancel";
  const sym = order ? (CURRENCY_SYMBOL[order.currency] ?? order.currency) : "¥";

  const pageTitle = isPaid
    ? t("payment.result_title_paid")
    : isCancelled
    ? t("payment.result_title_cancelled")
    : t("payment.result_title_result");

  return (
    <>
      <Head>
        <title>{`${pageTitle} · ${settings.site_title}`}</title>
        <meta name="robots" content="noindex" />
      </Head>

      <div className="min-h-screen bg-background flex items-center justify-center px-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.96, y: 16 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
          className="w-full max-w-sm text-center space-y-5 py-10"
        >
          {isPaid ? (
            <>
              <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center mx-auto">
                <RiCheckLine className="w-8 h-8 text-emerald-500" />
              </div>
              <div>
                <h1 className="text-xl font-black">{t("payment.result_paid_title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                  {t("payment.result_paid_desc")}
                </p>
              </div>
              {order && (
                <div className="rounded-2xl border border-emerald-200/50 dark:border-emerald-700/30 bg-emerald-50 dark:bg-emerald-950/20 p-4 text-sm space-y-1.5 text-left">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t("payment.result_plan_label")}</span>
                    <span className="font-semibold">{order.plan_name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t("payment.result_amount_label")}</span>
                    <span className="font-bold text-emerald-600 dark:text-emerald-400">{sym}{order.amount.toFixed(2)}</span>
                  </div>
                  {order.paid_at && (
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">{t("payment.result_paid_at_label")}</span>
                      <span>{new Date(order.paid_at).toLocaleString()}</span>
                    </div>
                  )}
                  <div className="flex justify-between text-[11px]">
                    <span className="text-muted-foreground">{t("payment.result_order_id_label") || "Order ID"}</span>
                    <span className="font-mono text-[10px] bg-muted px-1.5 py-0.5 rounded">{order.id}</span>
                  </div>
                </div>
              )}
              <div className="flex flex-col gap-2">
                <Link href="/dashboard">
                  <Button className="w-full rounded-xl h-10 font-semibold">
                    <RiArrowRightLine className="w-4 h-4 mr-2" />
                    {t("payment.result_go_dashboard")}
                  </Button>
                </Link>
                <div className="flex items-center justify-center gap-1 text-[11px] text-muted-foreground/50 mt-1">
                  <RiShieldCheckLine className="w-3.5 h-3.5" />
                  {t("payment.result_encrypted")}
                </div>
              </div>
            </>
          ) : isCancelled ? (
            <>
              <div className="w-16 h-16 rounded-full bg-muted flex items-center justify-center mx-auto">
                <RiCloseLine className="w-8 h-8 text-muted-foreground" />
              </div>
              <div>
                <h1 className="text-xl font-black">{t("payment.result_cancelled_title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                  {t("payment.result_cancelled_desc")}
                </p>
              </div>
              <Link href="/payment/checkout">
                <Button variant="outline" className="w-full rounded-xl h-10">
                  {t("payment.result_choose_plan")}
                </Button>
              </Link>
            </>
          ) : (
            <>
              <div className="w-16 h-16 rounded-full bg-amber-500/10 flex items-center justify-center mx-auto">
                <RiLoader4Line className="w-8 h-8 text-amber-500 animate-spin" />
              </div>
              <div>
                <h1 className="text-xl font-black">{t("payment.result_waiting_title")}</h1>
                <p className="text-sm text-muted-foreground mt-1">
                  {t("payment.result_waiting_desc")}
                </p>
              </div>
              {pollCount >= 16 && (
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground">
                    {t("payment.result_timeout_hint")}
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full rounded-xl text-xs gap-1.5"
                    onClick={async () => {
                      try {
                        const r = await fetch(`/api/payment/status?order=${orderId}`);
                        const d = await r.json();
                        if (d.order) setOrder(d.order);
                      } catch {}
                      setPollCount(0);
                    }}
                  >
                    <RiRefreshLine className="w-3.5 h-3.5" />
                    {t("payment.result_refresh_status")}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    {t("payment.result_contact_support")}
                  </p>
                  <code className="block font-mono text-[10px] bg-muted px-2 py-1 rounded text-center">{orderId}</code>
                  <Link href="/dashboard">
                    <Button variant="outline" size="sm" className="w-full rounded-xl text-xs">
                      {t("payment.result_go_dashboard")}
                    </Button>
                  </Link>
                </div>
              )}
            </>
          )}
        </motion.div>
      </div>
    </>
  );
}
