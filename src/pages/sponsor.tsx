import React from "react";
import Head from "next/head";
import Link from "next/link";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import { useRouter } from "next/router";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  RiHeart3Line, RiHeart3Fill, RiGithubLine, RiAlipayLine,
  RiWechatLine, RiExternalLinkLine, RiStarLine, RiStarFill,
  RiCalendarLine, RiMessage2Line, RiCopperCoinLine,
  RiPaypalLine, RiBitCoinLine, RiSparkling2Line,
  RiCheckLine, RiLoader4Line, RiFileCopyLine, RiUser3Line,
  RiQuillPenLine, RiArrowRightLine, RiShieldLine,
  RiBankCardLine, RiPriceTag3Line, RiLockLine, RiGiftLine,
  RiShieldCheckLine, RiAlertLine, RiCloseLine, RiQrCodeLine,
} from "@remixicon/react";
import { motion, AnimatePresence } from "framer-motion";
import { useSession } from "next-auth/react";

type Sponsor = {
  id: string;
  name: string;
  avatar_url: string | null;
  amount: string | null;
  currency: string;
  message: string | null;
  sponsor_date: string | null;
  is_anonymous: boolean;
  platform: string | null;
};

type Plan = {
  id: string;
  name: string;
  description: string | null;
  price: number;
  currency: string;
  duration_days: number | null;
  is_recurring: boolean;
  grants_subscription: boolean;
};

const CURRENCY_SYMBOL: Record<string, string> = {
  CNY: "¥", USD: "$", EUR: "€", JPY: "¥", GBP: "£", HKD: "HK$",
};

function CopyButton({ text, label }: { text: string; label?: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className={cn(
        "flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border transition-all touch-manipulation",
        copied
          ? "border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400"
          : "border-border text-muted-foreground hover:text-foreground hover:border-foreground/30"
      )}
    >
      {copied ? <RiCheckLine className="w-3 h-3" /> : <RiFileCopyLine className="w-3 h-3" />}
      {copied ? t("sponsor.copied") : (label || t("sponsor.copy"))}
    </button>
  );
}

function SponsorCard({ s, index }: { s: Sponsor; index: number }) {
  const { t } = useTranslation();
  const symbol = CURRENCY_SYMBOL[s.currency] || s.currency;
  const displayName = s.is_anonymous ? t("sponsor.anonymous_name") : s.name;
  const initial = s.is_anonymous ? "?" : displayName.charAt(0).toUpperCase();

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      className="flex items-start gap-3 p-4 rounded-2xl border border-border bg-card hover:bg-muted/30 transition-colors"
    >
      <div className={cn(
        "flex-shrink-0 w-10 h-10 rounded-full overflow-hidden flex items-center justify-center text-white text-sm font-bold shadow-sm",
        s.is_anonymous ? "bg-gradient-to-br from-slate-400 to-slate-600" : "bg-gradient-to-br from-rose-400 to-pink-600"
      )}>
        {s.avatar_url ? (
          <img src={s.avatar_url} alt={displayName} className="w-full h-full object-cover" />
        ) : (
          <span>{initial}</span>
        )}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-sm truncate">{displayName}</span>
          {s.platform && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-muted text-muted-foreground font-mono border border-border/50">{s.platform}</span>
          )}
          {s.amount && (
            <span className="text-xs font-bold text-rose-500 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/30 px-2 py-0.5 rounded-full border border-rose-200 dark:border-rose-800">
              {symbol}{parseFloat(s.amount).toFixed(0)}
            </span>
          )}
        </div>
        {s.message && (
          <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed line-clamp-2">
            <RiQuillPenLine className="inline w-3 h-3 mr-0.5 opacity-50" />
            {s.message}
          </p>
        )}
        {s.sponsor_date && (
          <div className="flex items-center gap-1 mt-1.5 text-[11px] text-muted-foreground/60">
            <RiCalendarLine className="w-3 h-3" />
            <span>{s.sponsor_date.slice(0, 10)}</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function QrModal({ title, url, icon, accentBg, onClose }: {
  title: string; url: string; icon: React.ReactNode; accentBg: string; onClose: () => void;
}) {
  const { t } = useTranslation();
  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);
  return (
    <div className="fixed inset-0 z-[70] flex items-end sm:items-center justify-center p-4 pb-8 sm:p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <motion.div
        initial={{ opacity: 0, y: 40, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 20, scale: 0.97 }}
        transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-10 w-full max-w-xs bg-background border border-border rounded-2xl shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className={cn("flex items-center justify-between px-4 py-3", accentBg)}>
          <div className="flex items-center gap-2">
            {icon}
            <span className="font-semibold text-sm">{title}</span>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-black/10 dark:hover:bg-white/10 transition-colors">
            <RiCloseLine className="w-4 h-4" />
          </button>
        </div>
        {/* QR */}
        <div className="p-5 flex flex-col items-center gap-3">
          <div className="w-52 h-52 rounded-xl border border-border bg-white flex items-center justify-center overflow-hidden shadow-sm">
            <img src={url} alt={title} className="w-full h-full object-contain p-2"
              onError={(e) => {
                const el = e.target as HTMLImageElement;
                el.style.display = "none";
                if (el.parentElement) el.parentElement.innerHTML = `<p class="text-xs text-center text-gray-400 px-4">${t("sponsor.qr_missing")}</p>`;
              }}
            />
          </div>
          <p className="text-[12px] text-muted-foreground text-center">{t("sponsor.scan_hint")}</p>
        </div>
      </motion.div>
    </div>
  );
}

/**
 * Auto-detect the likely USDT network from the wallet address format.
 * Tron addresses: start with "T" and are 34 characters.
 * Ethereum-compatible: start with "0x" and are 42 characters.
 */
function detectCryptoNetwork(address: string): string | null {
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)) return "TRC20 (Tron)";
  if (/^0x[0-9a-fA-F]{40}$/.test(address)) return "ERC20 (Ethereum)";
  return null;
}

function CryptoCard({ symbol, name, address, icon, color, network }: {
  symbol: string; name: string; address: string; icon: React.ReactNode; color: string;
  network?: string;
}) {
  const displayNetwork = network || (symbol === "USDT" ? detectCryptoNetwork(address) : null);

  return (
    <div className={cn("rounded-2xl border bg-card p-4 space-y-3", color)}>
      <div className="flex items-center gap-2 flex-wrap">
        {icon}
        <span className="font-semibold text-sm">{name}</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted font-mono border border-border/50">{symbol}</span>
        {displayNetwork && (
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/50 text-amber-700 dark:text-amber-400 font-semibold border border-amber-300/60 dark:border-amber-700/50">
            {displayNetwork}
          </span>
        )}
      </div>
      <div className="flex items-center gap-2 bg-muted/40 rounded-xl px-3 py-2 border border-border/40">
        <code className="text-[11px] font-mono text-muted-foreground flex-1 truncate">{address}</code>
        <CopyButton text={address} />
      </div>
      {displayNetwork && (
        <div className="flex items-start gap-2 rounded-xl bg-red-50 dark:bg-red-950/30 border border-red-200/70 dark:border-red-800/40 px-3 py-2.5">
          <RiAlertLine className="w-3.5 h-3.5 text-red-500 dark:text-red-400 mt-0.5 shrink-0" />
          <p className="text-[11px] text-red-700 dark:text-red-400 leading-snug">
            <span className="font-bold">仅支持 {displayNetwork} 网络转账。</span>
            <span className="opacity-90"> 请勿使用其他网络（如 ERC20、BEP20、Polygon 等），否则资产将永久丢失且无法追回。</span>
          </p>
        </div>
      )}
    </div>
  );
}

type SubmitForm = {
  name: string;
  message: string;
  amount: string;
  currency: string;
  platform: string;
  is_anonymous: boolean;
};

function PostPaymentForm({ defaultPlatform, onDone }: { defaultPlatform?: string; onDone: () => void }) {
  const { t, locale } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const [form, setForm] = React.useState<SubmitForm>({
    name: "", message: "", amount: "", currency: "CNY", platform: defaultPlatform || "", is_anonymous: false,
  });
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);

  const platforms = [
    t("sponsor.platform_alipay"),
    t("sponsor.platform_wechat"),
    "PayPal",
    t("sponsor.crypto_section"),
    "GitHub Sponsors",
    t("sponsor.platform_other"),
  ];

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name.trim() && !form.is_anonymous) {
      toast.error(t("sponsor.err_name"));
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/sponsors/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error);
      setDone(true);
      setTimeout(onDone, 3000);
    } catch (e: any) {
      toast.error(e.message || t("sponsor.err_submit"));
    } finally {
      setSubmitting(false);
    }
  }

  if (done) {
    return (
      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="text-center py-8 space-y-3">
        <div className="text-5xl">🎉</div>
        <p className="font-bold text-lg">{t("sponsor.done_title")}</p>
        <p className="text-sm text-muted-foreground">{t("sponsor.done_body")}</p>
        <p className="text-xs text-muted-foreground/60">{t("sponsor.done_motivate")}</p>
      </motion.div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={form.is_anonymous}
            onChange={e => setForm(f => ({ ...f, is_anonymous: e.target.checked, name: e.target.checked ? "" : f.name }))}
            className="rounded"
          />
          <span className="text-sm text-muted-foreground">{t("sponsor.anonymous_check")}</span>
        </label>
      </div>

      {!form.is_anonymous && (
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">{t("sponsor.name_label")}</label>
          <div className="relative">
            <RiUser3Line className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
            <Input
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder={t("sponsor.name_placeholder")}
              className="pl-9 h-9 text-sm rounded-xl"
              maxLength={50}
            />
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground">{t("sponsor.message_label")}</label>
        <textarea
          value={form.message}
          onChange={e => setForm(f => ({ ...f, message: e.target.value }))}
          placeholder={t("sponsor.message_placeholder")}
          className="w-full text-sm rounded-xl border border-input bg-background px-3 py-2 resize-none min-h-[80px] focus:outline-none focus:ring-1 focus:ring-ring"
          maxLength={200}
        />
        <p className="text-[10px] text-muted-foreground text-right">{form.message.length}/200</p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">{t("sponsor.amount_label")}</label>
          <Input
            value={form.amount}
            onChange={e => setForm(f => ({ ...f, amount: e.target.value }))}
            placeholder={t("sponsor.amount_placeholder")}
            type="number"
            min="0"
            step="0.01"
            className="h-9 text-sm rounded-xl"
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">{t("sponsor.currency_label")}</label>
          <select
            value={form.currency}
            onChange={e => setForm(f => ({ ...f, currency: e.target.value }))}
            className="w-full h-9 rounded-xl border border-input bg-background text-sm px-3 focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="CNY">{isChinese ? "CNY 人民币" : "CNY (Yuan)"}</option>
            <option value="USD">{isChinese ? "USD 美元" : "USD (Dollar)"}</option>
            <option value="EUR">{isChinese ? "EUR 欧元" : "EUR (Euro)"}</option>
            <option value="GBP">{isChinese ? "GBP 英镑" : "GBP (Pound)"}</option>
            <option value="JPY">{isChinese ? "JPY 日元" : "JPY (Yen)"}</option>
            <option value="USDT">USDT</option>
            <option value="BTC">BTC</option>
            <option value="ETH">ETH</option>
          </select>
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground">{t("sponsor.platform_label")}</label>
        <div className="flex flex-wrap gap-1.5">
          {platforms.map(p => (
            <button
              key={p}
              type="button"
              onClick={() => setForm(f => ({ ...f, platform: p }))}
              className={cn(
                "text-xs px-2.5 py-1 rounded-lg border transition-colors touch-manipulation",
                form.platform === p
                  ? "bg-primary text-primary-foreground border-primary"
                  : "border-border text-muted-foreground hover:text-foreground"
              )}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <Button type="submit" disabled={submitting} className="w-full gap-2 h-10 rounded-xl">
        {submitting ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiHeart3Fill className="w-4 h-4" />}
        {submitting ? t("sponsor.submitting") : t("sponsor.submit")}
      </Button>
      <p className="text-[10px] text-muted-foreground/50 text-center">
        {t("sponsor.form_note")}
      </p>
    </form>
  );
}

// Plan card for the checkout section
function PlanCard({ plan, onClick }: { plan: Plan; onClick: () => void }) {
  const { t } = useTranslation();
  const sym = CURRENCY_SYMBOL[plan.currency] ?? plan.currency;
  return (
    <motion.button
      onClick={onClick}
      whileTap={{ scale: 0.98 }}
      className="w-full text-left p-4 rounded-2xl border-2 border-border hover:border-primary/50 bg-card hover:bg-primary/5 transition-all group"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm group-hover:text-primary transition-colors">{plan.name}</span>
            {plan.grants_subscription && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-300 border border-violet-200 dark:border-violet-800 font-medium">{t("sponsor.subscription_access")}</span>
            )}
          </div>
          {plan.description && (
            <p className="text-xs text-muted-foreground mt-0.5">{plan.description}</p>
          )}
          <div className="flex items-center gap-2 mt-1.5 text-[11px] text-muted-foreground">
            <RiCalendarLine className="w-3 h-3" />
            <span>{plan.duration_days ? t("sponsor.validity_days").replace("{{days}}", String(plan.duration_days)) : t("sponsor.permanent")}</span>
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-xl font-black">{sym}{plan.price.toFixed(0)}</div>
          <div className="text-[10px] text-muted-foreground">{plan.currency}</div>
        </div>
      </div>
    </motion.button>
  );
}

export default function SponsorPage() {
  const settings = useSiteSettings();
  const { t, locale } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const router = useRouter();
  const { data: session } = useSession();
  const siteName = settings.site_title || "X.RW · RDAP+WHOIS";

  const [sponsors, setSponsors] = React.useState<Sponsor[]>([]);
  const [sponsorLoading, setSponsorLoading] = React.useState(true);
  const [plans, setPlans] = React.useState<Plan[]>([]);
  const [showAll, setShowAll] = React.useState(false);
  const [showPostPayment, setShowPostPayment] = React.useState(false);
  const [postPaymentPlatform, setPostPaymentPlatform] = React.useState<string>("");
  const [floatingHearts, setFloatingHearts] = React.useState<{ id: number; x: number }[]>([]);
  const [activeQr, setActiveQr] = React.useState<"alipay" | "wechat" | null>(null);

  React.useEffect(() => {
    fetch("/api/admin/sponsors?visible_only=1")
      .then(r => r.json())
      .then(d => { if (d.sponsors) setSponsors(d.sponsors); })
      .catch(() => {})
      .finally(() => setSponsorLoading(false));
    fetch("/api/payment/plans")
      .then(r => r.json())
      .then(d => { if (d.plans) setPlans(d.plans); })
      .catch(() => {});
  }, []);

  function spawnHearts() {
    const id = Date.now();
    const x = 40 + Math.random() * 20;
    setFloatingHearts(prev => [...prev, { id, x }]);
    setTimeout(() => setFloatingHearts(prev => prev.filter(h => h.id !== id)), 1800);
  }

  const pageTitle = settings.sponsor_page_title || t("sponsor.page_title_default");
  const pageDesc = settings.sponsor_page_desc || t("sponsor.page_desc_default");
  const alipayQr = settings.sponsor_alipay_qr;
  const wechatQr = settings.sponsor_wechat_qr;
  const githubUrl = settings.sponsor_github_url;
  const paypalUrl = settings.sponsor_paypal_url;
  const btcAddr = settings.sponsor_crypto_btc;
  const ethAddr = settings.sponsor_crypto_eth;
  const usdtAddr = settings.sponsor_crypto_usdt;
  const usdtNetwork = settings.sponsor_crypto_usdt_network;
  const okxAddr = settings.sponsor_crypto_okx;

  const paymentEnabled = !!(
    settings.payment_stripe_enabled ||
    settings.payment_xunhupay_enabled ||
    settings.payment_alipay_enabled ||
    settings.payment_paypal_enabled
  );

  const hasQrPayment = alipayQr || wechatQr;
  const hasLinkPayment = githubUrl || paypalUrl;
  const hasCrypto = btcAddr || ethAddr || usdtAddr || okxAddr;
  const hasManualPayment = hasQrPayment || hasLinkPayment || hasCrypto;
  const hasAnyPayment = hasManualPayment || (plans.length > 0 && paymentEnabled);

  const visibleSponsors = showAll ? sponsors : sponsors.slice(0, 12);
  const totalAmount = sponsors.reduce((s, sp) => s + (sp.amount ? parseFloat(sp.amount) : 0), 0);

  function handlePlanClick(plan: Plan) {
    if (!session) {
      router.push(`/login?callbackUrl=${encodeURIComponent("/payment/checkout?plan=" + plan.id)}`);
      return;
    }
    router.push(`/payment/checkout?plan=${plan.id}`);
  }

  return (
    <>
      <Head>
        <title>{`${pageTitle} — ${siteName}`}</title>
        <meta name="description" content={pageDesc} />
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-8 pb-24">

          {/* Hero */}
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }} className="text-center mb-10 relative">
            <div className="relative inline-block mb-4">
              <button
                onClick={spawnHearts}
                className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-rose-100 dark:bg-rose-950/40 border border-rose-200/50 dark:border-rose-700/30 shadow-sm hover:scale-110 active:scale-95 transition-transform touch-manipulation"
              >
                <RiHeart3Fill className="w-8 h-8 text-rose-500" />
              </button>
              <AnimatePresence>
                {floatingHearts.map(h => (
                  <motion.div
                    key={h.id}
                    initial={{ opacity: 1, y: 0, scale: 0.8 }}
                    animate={{ opacity: 0, y: -60, scale: 1.4 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 1.6, ease: "easeOut" }}
                    className="absolute pointer-events-none text-rose-400"
                    style={{ left: `${h.x}%`, bottom: "100%" }}
                  >
                    ❤️
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>

            <h1 className="text-2xl font-bold mb-2">{pageTitle}</h1>
            <p className="text-muted-foreground text-sm max-w-md mx-auto leading-relaxed">{pageDesc}</p>

            {sponsors.length > 0 && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.2 }}
                className="mt-5 inline-flex items-center gap-3 text-sm font-medium text-rose-500 bg-rose-50 dark:bg-rose-950/30 px-5 py-2 rounded-full border border-rose-100 dark:border-rose-800/30"
              >
                <RiSparkling2Line className="w-4 h-4" />
                {t("sponsor.count").replace("{{count}}", String(sponsors.length))}
                {totalAmount > 0 && <span>· {t("sponsor.total")} ¥{totalAmount.toFixed(0)}</span>}
                <RiSparkling2Line className="w-4 h-4" />
              </motion.div>
            )}
          </motion.div>

          {/* ── Online Payment Plans (checkout system) ── */}
          {plans.length > 0 && paymentEnabled && (
            <motion.section
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.08, duration: 0.3 }}
              className="mb-8 space-y-4"
            >
              <div className="flex items-center gap-2 mb-2">
                <div className="h-px flex-1 bg-border/60" />
                <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground px-2 flex items-center gap-1.5">
                  <RiBankCardLine className="w-3.5 h-3.5" />{t("sponsor.online_payment")}
                </p>
                <div className="h-px flex-1 bg-border/60" />
              </div>

              <div className="rounded-2xl border border-border bg-gradient-to-br from-violet-50 to-background dark:from-violet-950/10 dark:to-background p-4 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <RiGiftLine className="w-4 h-4 text-violet-500" />
                  <span className="text-sm font-semibold">{t("sponsor.choose_plan")}</span>
                  <span className="text-[10px] text-muted-foreground ml-auto">{t("sponsor.payment_methods_hint")}</span>
                </div>

                <div className="space-y-2">
                  {plans.map(plan => (
                    <PlanCard key={plan.id} plan={plan} onClick={() => handlePlanClick(plan)} />
                  ))}
                </div>

                {!session && (
                  <p className="text-[11px] text-muted-foreground flex items-center gap-1 pt-1">
                    <RiLockLine className="w-3.5 h-3.5" />
                    {isChinese
                      ? <>需要<Link href="/login?callbackUrl=%2Fpayment%2Fcheckout" className="text-primary hover:underline">登录</Link>才能在线支付</>
                      : <><Link href="/login?callbackUrl=%2Fpayment%2Fcheckout" className="text-primary hover:underline">Login</Link> required to pay online</>}
                  </p>
                )}

                <div className="flex items-center gap-1 text-[10px] text-muted-foreground/50 pt-1">
                  <RiShieldCheckLine className="w-3 h-3" />
                  <span>{t("sponsor.secure_payment")}</span>
                </div>

                <Link href="/payment/checkout" className="block">
                  <Button className="w-full h-10 rounded-xl gap-2 font-semibold text-sm">
                    <RiBankCardLine className="w-4 h-4" />{t("sponsor.go_to_checkout")}
                    <RiArrowRightLine className="w-4 h-4" />
                  </Button>
                </Link>
              </div>
            </motion.section>
          )}

          {/* ── Manual / Donation methods ── */}
          {hasManualPayment && (
            <motion.section initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.12, duration: 0.3 }} className="mb-8 space-y-5">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-px flex-1 bg-border/60" />
                <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground px-2">
                  {plans.length > 0 && paymentEnabled ? t("sponsor.other_methods") : t("sponsor.methods_section")}
                </p>
                <div className="h-px flex-1 bg-border/60" />
              </div>

              {/* All donation buttons in a unified grid */}
              {(hasQrPayment || hasLinkPayment) && (
                <div className={cn(
                  "grid gap-3",
                  [alipayQr, wechatQr, paypalUrl, githubUrl].filter(Boolean).length === 1
                    ? "grid-cols-1"
                    : [alipayQr, wechatQr, paypalUrl, githubUrl].filter(Boolean).length <= 3
                    ? "grid-cols-2 sm:grid-cols-3"
                    : "grid-cols-2"
                )}>
                  {alipayQr && (
                    <button
                      onClick={() => { setActiveQr("alipay"); setPostPaymentPlatform(t("sponsor.platform_alipay")); }}
                      className="flex items-center justify-center gap-2.5 px-4 py-3.5 rounded-2xl bg-[#1677FF] text-white font-semibold hover:bg-[#0d6aee] active:scale-[0.98] transition-all shadow-sm touch-manipulation"
                    >
                      <RiAlipayLine className="w-5 h-5" />
                      <span className="text-sm">{t("sponsor.alipay_title")}</span>
                      <RiQrCodeLine className="w-3.5 h-3.5 opacity-70" />
                    </button>
                  )}
                  {wechatQr && (
                    <button
                      onClick={() => { setActiveQr("wechat"); setPostPaymentPlatform(t("sponsor.platform_wechat")); }}
                      className="flex items-center justify-center gap-2.5 px-4 py-3.5 rounded-2xl bg-[#07C160] text-white font-semibold hover:bg-[#06ad56] active:scale-[0.98] transition-all shadow-sm touch-manipulation"
                    >
                      <RiWechatLine className="w-5 h-5" />
                      <span className="text-sm">{t("sponsor.wechat_title")}</span>
                      <RiQrCodeLine className="w-3.5 h-3.5 opacity-70" />
                    </button>
                  )}
                  {paypalUrl && (
                    <a
                      href={paypalUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2.5 px-4 py-3.5 rounded-2xl bg-[#003087] text-white font-semibold hover:bg-[#002070] active:scale-[0.98] transition-all shadow-sm touch-manipulation"
                    >
                      <RiPaypalLine className="w-5 h-5" />
                      <span className="text-sm">{t("sponsor.paypal_btn")}</span>
                      <RiExternalLinkLine className="w-3.5 h-3.5 opacity-70" />
                    </a>
                  )}
                  {githubUrl && (
                    <a
                      href={githubUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2.5 px-4 py-3.5 rounded-2xl border border-border bg-card font-semibold hover:bg-muted/50 active:scale-[0.98] transition-all shadow-sm touch-manipulation"
                    >
                      <RiGithubLine className="w-5 h-5" />
                      <span className="text-sm">GitHub Sponsors</span>
                      <RiExternalLinkLine className="w-3.5 h-3.5 opacity-70" />
                    </a>
                  )}
                </div>
              )}

              {/* QR modals */}
              <AnimatePresence>
                {activeQr === "alipay" && alipayQr && (
                  <QrModal
                    title={t("sponsor.alipay_title")}
                    url={alipayQr}
                    accentBg="bg-[#e8f0fe] dark:bg-[#1677FF]/20 text-[#1677FF]"
                    icon={<RiAlipayLine className="w-5 h-5 text-[#1677FF]" />}
                    onClose={() => setActiveQr(null)}
                  />
                )}
                {activeQr === "wechat" && wechatQr && (
                  <QrModal
                    title={t("sponsor.wechat_title")}
                    url={wechatQr}
                    accentBg="bg-[#e8f8ef] dark:bg-[#07C160]/20 text-[#07C160]"
                    icon={<RiWechatLine className="w-5 h-5 text-[#07C160]" />}
                    onClose={() => setActiveQr(null)}
                  />
                )}
              </AnimatePresence>

              {/* Crypto */}
              {hasCrypto && (
                <div className="space-y-3">
                  <p className="text-xs font-semibold text-muted-foreground flex items-center gap-2">
                    <RiBitCoinLine className="w-4 h-4" />{t("sponsor.crypto_section")}
                  </p>
                  <div className="grid gap-2.5">
                    {btcAddr && <CryptoCard symbol="BTC" name="Bitcoin" address={btcAddr} color="hover:border-amber-200 dark:hover:border-amber-800/40" icon={<RiBitCoinLine className="w-5 h-5 text-amber-500" />} />}
                    {ethAddr && <CryptoCard symbol="ETH" name="Ethereum" address={ethAddr} color="hover:border-indigo-200 dark:hover:border-indigo-800/40" icon={<RiBitCoinLine className="w-5 h-5 text-indigo-500" />} />}
                    {usdtAddr && <CryptoCard symbol="USDT" name="Tether" address={usdtAddr} color="hover:border-teal-200 dark:hover:border-teal-800/40" icon={<RiBitCoinLine className="w-5 h-5 text-teal-500" />} network={usdtNetwork || undefined} />}
                    {okxAddr && <CryptoCard symbol="OKX" name={`OKX / ${t("sponsor.wallet")}`} address={okxAddr} color="hover:border-slate-300 dark:hover:border-slate-600" icon={<RiBitCoinLine className="w-5 h-5 text-slate-500" />} />}
                  </div>
                </div>
              )}

              {/* Post-payment form trigger */}
              <AnimatePresence mode="wait">
                {!showPostPayment ? (
                  <motion.div key="cta" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.15 }}>
                    <button
                      onClick={() => setShowPostPayment(true)}
                      className="w-full flex items-center justify-center gap-2 py-3.5 rounded-2xl border-2 border-dashed border-rose-200 dark:border-rose-800/50 text-rose-500 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-950/20 transition-colors font-medium text-sm touch-manipulation"
                    >
                      <RiHeart3Line className="w-4 h-4" />
                      {t("sponsor.cta_done")}
                      <RiArrowRightLine className="w-4 h-4" />
                    </button>
                  </motion.div>
                ) : (
                  <motion.div
                    key="form"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                    style={{ overflow: "hidden" }}
                  >
                    <div className="rounded-2xl border border-rose-200 dark:border-rose-800/50 bg-rose-50/50 dark:bg-rose-950/10 p-5">
                      <div className="flex items-center gap-2 mb-5">
                        <RiHeart3Fill className="w-4 h-4 text-rose-500" />
                        <h3 className="text-sm font-bold">{t("sponsor.form_title")}</h3>
                      </div>
                      <PostPaymentForm
                        defaultPlatform={postPaymentPlatform}
                        onDone={() => setShowPostPayment(false)}
                      />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.section>
          )}

          {/* If no payment methods configured at all */}
          {!hasAnyPayment && (
            <div className="text-center py-12 text-muted-foreground text-sm space-y-2">
              <RiHeart3Line className="w-8 h-8 mx-auto opacity-30" />
              <p>{t("sponsor.no_payment_configured")}</p>
            </div>
          )}

          {/* ── Sponsor Wall ── */}
          {(sponsorLoading || sponsors.length > 0) && (
            <motion.section initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
              <div className="flex items-center gap-2 mb-4">
                <div className="h-px flex-1 bg-border/60" />
                <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground px-2">{t("sponsor.wall_section")}</p>
                <div className="h-px flex-1 bg-border/60" />
              </div>

              {sponsorLoading ? (
                <div className="flex justify-center py-8">
                  <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <>
                  <div className="grid gap-3">
                    {visibleSponsors.map((s, i) => <SponsorCard key={s.id} s={s} index={i} />)}
                  </div>
                  {sponsors.length > 12 && (
                    <button
                      onClick={() => setShowAll(v => !v)}
                      className="w-full mt-4 py-2.5 rounded-xl border border-dashed border-border text-xs text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors"
                    >
                      {showAll ? t("sponsor.show_less") : t("sponsor.show_more").replace("{{n}}", String(sponsors.length - 12))}
                    </button>
                  )}
                </>
              )}
            </motion.section>
          )}

        </main>
      </ScrollArea>
    </>
  );
}
