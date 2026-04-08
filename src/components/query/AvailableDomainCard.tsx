import React from "react";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  RiCheckLine,
  RiFileCopyLine,
  RiSearchLine,
  RiShoppingCartLine,
  RiLoopLeftLine,
  RiVipCrownLine,
  RiInformationLine,
  RiExternalLinkLine,
  RiGlobalLine,
} from "@remixicon/react";
import { motion, AnimatePresence } from "framer-motion";
import { DomainPricing } from "@/lib/pricing/client";

function RegistrarIcon({ faviconDomain, name }: { faviconDomain: string | null; name: string }) {
  const [imgFailed, setImgFailed] = React.useState(false);
  return (
    <div className="shrink-0 w-9 h-9 rounded-xl flex items-center justify-center overflow-hidden bg-muted/40 border border-border/30">
      {faviconDomain && !imgFailed ? (
        <img
          src={`/api/favicon?domain=${encodeURIComponent(faviconDomain)}`}
          alt={name}
          className="w-6 h-6 object-contain"
          onError={() => setImgFailed(true)}
        />
      ) : (
        <span className="text-xs font-bold text-muted-foreground select-none">
          {name.charAt(0).toUpperCase()}
        </span>
      )}
    </div>
  );
}

export function DomainFavicon({
  domain,
  size = 20,
  className = "",
  fallback,
}: {
  domain: string;
  size?: number;
  className?: string;
  fallback: React.ReactNode;
}) {
  const [failed, setFailed] = React.useState(false);
  if (!domain || failed) return <>{fallback}</>;
  return (
    <img
      src={`/api/favicon?domain=${encodeURIComponent(domain)}`}
      alt=""
      width={size}
      height={size}
      className={`object-contain rounded-sm ${className}`}
      onError={() => setFailed(true)}
    />
  );
}

interface AvailableDomainCardProps {
  domain: string;
  locale: string;
  isPremiumByWhois?: boolean;
}

const cardVariants = {
  hidden: { opacity: 0, y: 16, scale: 0.98 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] },
  },
};

const staggerChildren = {
  hidden: { opacity: 1 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06, delayChildren: 0.15 } },
};

const fadeUp = {
  hidden: { opacity: 0, y: 10 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.35, ease: [0.22, 1, 0.36, 1] } },
};

export function AvailableDomainCard({ domain, locale, isPremiumByWhois = false }: AvailableDomainCardProps) {
  const [rawPrices, setRawPrices] = React.useState<DomainPricing[]>([]);
  const [registrars, setRegistrars] = React.useState<DomainPricing[]>([]);
  const [renewRegistrars, setRenewRegistrars] = React.useState<DomainPricing[]>([]);
  const [loadingPrices, setLoadingPrices] = React.useState(true);
  const [anyApiPremium, setAnyApiPremium] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const CARD_FALLBACK_RATES: Record<string, number> = {
    AUD: 1.65, CAD: 1.49, CHF: 0.94, CNY: 7.82, DKK: 7.46,
    GBP: 0.85, HKD: 8.50, JPY: 162, KRW: 1520, NOK: 11.7,
    NZD: 1.80, SEK: 11.3, SGD: 1.46, TWD: 34.8, USD: 1.09,
  };
  const [eurRates, setEurRates] = React.useState<Record<string, number>>(CARD_FALLBACK_RATES);
  const isZh = locale.startsWith("zh");

  React.useEffect(() => {
    const tld = domain.substring(domain.lastIndexOf(".") + 1).toLowerCase();
    const ctrl = new AbortController();
    fetch(`/api/pricing?tld=${encodeURIComponent(tld)}&type=new`, { signal: ctrl.signal })
      .then((r) => r.json())
      .then((data) => {
        if (data.anyPremium) setAnyApiPremium(true);
        const prices: DomainPricing[] = (data.price || [])
          .filter((r: { new: unknown }) => typeof r.new === "number")
          .map((r: { isPremium?: boolean; currencytype?: string; new: number; currency?: string; registrarweb?: string; [key: string]: unknown }) => ({
            ...r,
            isPremium: r.isPremium ?? (
              (r.currencytype && r.currencytype.toLowerCase().includes("premium")) ||
              (typeof r.new === "number" && (() => {
                const cur = (r.currency || "").toLowerCase();
                const t: Record<string, number> = { usd: 60, eur: 55, cad: 80, gbp: 50, aud: 90, cny: 420, hkd: 470, sgd: 80, jpy: 9000 };
                return t[cur] !== undefined && r.new > t[cur];
              })())
            ),
            externalLink: `https://www.nazhumi.com/domain/${tld}/new`,
          }));
        setRawPrices(prices);
      })
      .catch(() => {})
      .finally(() => setLoadingPrices(false));
    return () => ctrl.abort();
  }, [domain]);

  React.useEffect(() => {
    fetch("https://api.frankfurter.dev/v1/latest")
      .then((r) => r.json())
      .then((data) => { if (data?.rates) setEurRates(data.rates); })
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    if (rawPrices.length === 0) return;
    const toEur = (amount: number, currency: string) => {
      const cur = currency.toUpperCase();
      if (cur === "EUR") return amount;
      return amount / (eurRates[cur] ?? 1);
    };
    const sortedNew = [...rawPrices]
      .sort((a, b) => {
        if (anyApiPremium) {
          if (a.isPremium !== b.isPremium) return a.isPremium ? -1 : 1;
        } else {
          if (a.isPremium !== b.isPremium) return a.isPremium ? 1 : -1;
        }
        return toEur(a.new as number, a.currency) - toEur(b.new as number, b.currency);
      })
      .slice(0, 5);
    setRegistrars(sortedNew);
    const sortedRenew = [...rawPrices]
      .filter((r) => typeof r.renew === "number" && r.renew !== -1)
      .sort((a, b) => {
        if (a.isPremium !== b.isPremium) return a.isPremium ? 1 : -1;
        return toEur(a.renew as number, a.currency) - toEur(b.renew as number, b.currency);
      })
      .slice(0, 5);
    setRenewRegistrars(sortedRenew);
  }, [rawPrices, eurRates, anyApiPremium]);

  function formatPrice(amount: number, currency: string): string {
    const cur = (currency ?? "").toUpperCase();
    if (isZh) {
      if (cur === "CNY") return `¥${amount.toFixed(2)}`;
      const cnyRate = eurRates["CNY"] ?? 7.82;
      const eurAmount = cur === "EUR" ? amount : amount / (eurRates[cur] ?? 1);
      return `¥${(eurAmount * cnyRate).toFixed(2)}`;
    }
    const SYMBOLS: Record<string, string> = {
      USD: "$", EUR: "€", CNY: "¥", GBP: "£",
      CAD: "CA$", AUD: "A$", HKD: "HK$", SGD: "S$",
      NZD: "NZ$", TWD: "NT$", KRW: "₩", JPY: "¥",
    };
    const sym = SYMBOLS[cur] ?? (cur + "\u00a0");
    const decimals = ["JPY", "KRW"].includes(cur) ? 0 : 2;
    return `${sym}${amount.toFixed(decimals)}`;
  }

  function handleCopy() {
    navigator.clipboard.writeText(domain).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }

  const tldForDisplay = domain.substring(domain.lastIndexOf(".")).toLowerCase();
  const sldForDisplay = domain.substring(0, domain.lastIndexOf("."));
  const isPremium = anyApiPremium || isPremiumByWhois || registrars.some((r) => r.isPremium);
  const premiumRegistrars = registrars.filter((r) => r.isPremium);
  const bestRegistrar = (isPremium && premiumRegistrars.length > 0)
    ? premiumRegistrars[0]
    : (registrars.find((r) => !r.isPremium) ?? registrars[0] ?? null);

  function RegistrarRow({ r, idx, priceField, colorFirst }: { r: DomainPricing; idx: number; priceField: "new" | "renew"; colorFirst: boolean }) {
    const faviconDomain = (() => { try { return new URL(r.registrarweb).hostname; } catch { return null; } })();
    const rowIsPremium = r.isPremium;
    const isFirst = idx === 0;
    const price = r[priceField];
    return (
      <motion.a
        href={r.registrarweb}
        target="_blank"
        rel="noopener noreferrer"
        className={cn(
          "flex items-center gap-3 px-4 sm:px-5 py-2.5 transition-colors duration-150 group hover:bg-muted/40",
          isFirst && colorFirst && "bg-muted/20",
        )}
        whileHover={{ x: 2 }}
        transition={{ type: "spring", stiffness: 400, damping: 30 }}
      >
        <RegistrarIcon faviconDomain={faviconDomain} name={r.registrarname} />
        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="shrink-0 text-[11px] font-bold text-muted-foreground/25 w-4 text-right tabular-nums">{idx + 1}</span>
          <p className={cn("text-sm truncate", isFirst ? "font-semibold text-foreground" : "font-medium text-foreground/70")}>
            {r.registrarname}
          </p>
          {isFirst && !rowIsPremium && !isPremium && colorFirst && (
            <span className="shrink-0 text-[9px] font-bold text-primary/80 bg-primary/10 border border-primary/20 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "最低价" : "BEST"}
            </span>
          )}
          {rowIsPremium && (
            <span className="shrink-0 text-[9px] font-bold text-amber-600 dark:text-amber-400 bg-amber-500/8 border border-amber-400/25 dark:border-amber-500/25 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "溢价" : "PREMIUM"}
            </span>
          )}
          {!rowIsPremium && anyApiPremium && (
            <span className="shrink-0 text-[9px] font-bold text-muted-foreground/50 bg-muted/50 border border-border/50 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "参考价" : "STD"}
            </span>
          )}
        </div>
        <div className="shrink-0 text-right flex items-center gap-1.5">
          <div className="flex items-baseline gap-0.5">
            <span className={cn(
              "font-bold tabular-nums",
              rowIsPremium
                ? (isFirst ? "text-base text-amber-600 dark:text-amber-400" : "text-sm text-amber-500/60 dark:text-amber-500/50")
                : (isFirst && colorFirst ? "text-base text-primary" : "text-sm text-foreground/60"),
            )}>
              {typeof price === "number" ? formatPrice(price, r.currency) : "N/A"}
            </span>
            <span className="text-xs text-muted-foreground/40">/{isZh ? "年" : "yr"}</span>
          </div>
          <svg className="w-3.5 h-3.5 text-muted-foreground/25 group-hover:text-muted-foreground/50 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      </motion.a>
    );
  }

  return (
    <motion.div
      variants={cardVariants}
      initial="hidden"
      animate="visible"
      className="glass-panel rounded-xl overflow-hidden border border-border/60 relative"
    >
      {/* Accent bar — animates between green-primary and amber */}
      <div className="h-1 w-full relative overflow-hidden">
        <div className={cn(
          "absolute inset-0 transition-opacity duration-700",
          isPremium ? "opacity-100" : "opacity-0",
          "bg-gradient-to-r from-amber-400 via-amber-500 to-amber-400"
        )} />
        <div className={cn(
          "absolute inset-0 transition-opacity duration-700",
          isPremium ? "opacity-0" : "opacity-100",
          "bg-gradient-to-r from-primary/70 via-primary to-primary/70"
        )} />
      </div>

      {/* Subtle background glow */}
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top_left,hsl(var(--primary)/0.04)_0%,transparent_60%)]" />

      {/* ── Hero ── */}
      <div className="relative overflow-hidden">
        {/* Tinted hero background — transitions between states */}
        <div className={cn(
          "absolute inset-0 transition-colors duration-700",
          isPremium ? "bg-amber-500/[0.07] dark:bg-amber-950/20" : "bg-primary/[0.06] dark:bg-primary/[0.10]"
        )} />

        <motion.div
          variants={staggerChildren}
          initial="hidden"
          animate="visible"
          className="relative px-5 sm:px-8 pt-6 pb-5"
        >
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div className="flex items-start gap-4">
              {/* Icon — crossfades between check and crown */}
              <motion.div
                variants={fadeUp}
                className={cn(
                  "shrink-0 w-12 h-12 rounded-xl flex items-center justify-center border shadow-sm transition-colors duration-700",
                  isPremium
                    ? "bg-amber-500/12 border-amber-400/35 dark:border-amber-500/35"
                    : "bg-primary/[0.12] border-primary/25"
                )}
                whileHover={{ scale: 1.08, rotate: isPremium ? 5 : -5 }}
                transition={{ type: "spring", stiffness: 400, damping: 20 }}
              >
                <AnimatePresence mode="wait" initial={false}>
                  {isPremium ? (
                    <motion.span
                      key="crown"
                      initial={{ scale: 0.5, opacity: 0, rotate: -20 }}
                      animate={{ scale: 1, opacity: 1, rotate: 0 }}
                      exit={{ scale: 0.5, opacity: 0, rotate: 20 }}
                      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                    >
                      <RiVipCrownLine className="w-5 h-5 text-amber-500 dark:text-amber-400" />
                    </motion.span>
                  ) : (
                    <motion.span
                      key="check"
                      initial={{ scale: 0.5, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      exit={{ scale: 0.5, opacity: 0 }}
                      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                    >
                      <RiCheckLine className="w-6 h-6 text-primary" />
                    </motion.span>
                  )}
                </AnimatePresence>
              </motion.div>

              <div className="min-w-0 flex-1">
                {/* Domain name */}
                <motion.div variants={fadeUp} className="mb-1.5 leading-tight">
                  <span className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground break-all">{sldForDisplay}</span>
                  <span className={cn(
                    "text-2xl sm:text-3xl font-bold tracking-tight transition-colors duration-700",
                    isPremium ? "text-amber-500 dark:text-amber-400" : "text-primary"
                  )}>{tldForDisplay}</span>
                </motion.div>
                {/* Description */}
                <motion.p variants={fadeUp} className="text-sm text-muted-foreground leading-relaxed">
                  <AnimatePresence mode="wait" initial={false}>
                    <motion.span
                      key={isPremium ? "premium-desc" : "available-desc"}
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.25 }}
                    >
                      {isPremium
                        ? (anyApiPremium && premiumRegistrars.length > 0
                            ? (isZh
                                ? `溢价域名，注册费约 ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/年起，实际以注册商报价为准。`
                                : `Premium domain — starting from ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/yr. Confirm price with registrar.`)
                            : (isZh
                                ? "溢价域名，注册价格高于普通域名，请以注册商实时报价为准。"
                                : "Premium domain — registration costs above standard rates. Confirm with registrar."))
                        : (isZh
                            ? "该域名目前可注册，抓紧时间抢注吧！"
                            : "This domain is available. Grab it before someone else does.")}
                    </motion.span>
                  </AnimatePresence>
                </motion.p>
              </div>
            </div>

            {/* Status badge */}
            <motion.div variants={fadeUp} className="shrink-0 flex flex-row sm:flex-col items-center sm:items-end gap-2">
              <motion.span
                className={cn(
                  "inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full border transition-colors duration-700",
                  isPremium
                    ? "text-amber-700 dark:text-amber-300 bg-amber-500/12 border-amber-400/35 dark:border-amber-500/35"
                    : "text-primary bg-primary/12 border-primary/30"
                )}
                initial={{ scale: 0.85, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.25, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
              >
                <motion.span
                  className={cn(
                    "w-1.5 h-1.5 rounded-full transition-colors duration-700",
                    isPremium ? "bg-amber-500" : "bg-primary"
                  )}
                  animate={{ scale: [1, 1.4, 1], opacity: [1, 0.6, 1] }}
                  transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                />
                <AnimatePresence mode="wait" initial={false}>
                  <motion.span
                    key={isPremium ? "lbl-premium" : "lbl-available"}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    {isPremium ? (isZh ? "溢价域名" : "Premium") : (isZh ? "可注册" : "Available")}
                  </motion.span>
                </AnimatePresence>
              </motion.span>
            </motion.div>
          </div>
        </motion.div>
      </div>

      {/* ── Action buttons ── */}
      <motion.div
        variants={fadeUp}
        initial="hidden"
        animate="visible"
        transition={{ delay: 0.2 }}
        className="px-5 sm:px-8 py-4 border-t border-border/40"
      >
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-2.5">
          {loadingPrices ? (
            <div className="h-9 w-44 rounded-lg bg-muted/40 animate-pulse mx-auto" />
          ) : bestRegistrar ? (
            <motion.a
              href={bestRegistrar.registrarweb}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "inline-flex items-center justify-center gap-2 font-semibold text-sm px-5 py-2.5 rounded-lg border transition-colors duration-500 active:scale-[0.97]",
                isPremium
                  ? "border-amber-400/40 dark:border-amber-500/35 text-amber-700 dark:text-amber-300 bg-amber-500/10 dark:bg-amber-500/12 hover:bg-amber-500/18 dark:hover:bg-amber-500/20"
                  : "border-primary/30 text-primary bg-primary/10 hover:bg-primary/18"
              )}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.97 }}
              transition={{ type: "spring", stiffness: 400, damping: 25 }}
            >
              <RiShoppingCartLine className="w-4 h-4 shrink-0" />
              <span>
                {isZh
                  ? `${isPremium ? "查看价格" : "立即注册"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/首年起`
                  : `${isPremium ? "Check Price" : "Register Now"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/yr`}
              </span>
            </motion.a>
          ) : null}
          <motion.button
            onClick={handleCopy}
            className="inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.97]"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
            transition={{ type: "spring", stiffness: 400, damping: 25 }}
          >
            <AnimatePresence mode="wait" initial={false}>
              {copied ? (
                <motion.span
                  key="copied"
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  exit={{ scale: 0, opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="inline-flex items-center gap-2"
                >
                  <RiCheckLine className="w-4 h-4 shrink-0 text-primary" />
                  {isZh ? "已复制" : "Copied!"}
                </motion.span>
              ) : (
                <motion.span
                  key="copy"
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  exit={{ scale: 0, opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="inline-flex items-center gap-2"
                >
                  <RiFileCopyLine className="w-4 h-4 shrink-0" />
                  {isZh ? "复制域名" : "Copy Domain"}
                </motion.span>
              )}
            </AnimatePresence>
          </motion.button>
          <motion.div
            className="w-full sm:w-auto"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.97 }}
            transition={{ type: "spring", stiffness: 400, damping: 25 }}
          >
            <Link
              href="/"
              className="inline-flex items-center justify-center gap-2 w-full text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150"
            >
              <RiSearchLine className="w-4 h-4 shrink-0" />
              {isZh ? "新查询" : "New Search"}
            </Link>
          </motion.div>
        </div>
      </motion.div>

      {/* ── Registration tips ── */}
      <motion.div
        variants={fadeUp}
        initial="hidden"
        animate="visible"
        transition={{ delay: 0.3 }}
        className="border-t border-border/50 px-5 py-4"
      >
        <p className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground/60 mb-3 flex items-center gap-1.5">
          <RiInformationLine className="w-3.5 h-3.5" />
          {isZh ? "注册建议" : "Tips"}
        </p>
        <ul className="space-y-2">
          {[
            isZh ? "建议尽快通过正规注册商完成注册" : "Register through an accredited registrar promptly",
            isZh ? "注册前请确认域名用途符合相关法规" : "Confirm your intended use complies with relevant regulations",
            isZh ? "建议同时注册常见后缀以保护品牌" : "Consider registering common TLD variants to protect your brand",
          ].map((tip, i) => (
            <motion.li
              key={i}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.35 + i * 0.08, duration: 0.3, ease: "easeOut" }}
              className="flex items-start gap-2 text-sm text-muted-foreground leading-snug"
            >
              <span className={cn(
                "mt-1 w-1.5 h-1.5 rounded-full shrink-0 transition-colors duration-700",
                isPremium ? "bg-amber-400" : "bg-primary/60"
              )} />
              {tip}
            </motion.li>
          ))}
        </ul>
      </motion.div>

      {/* ── Price section ── */}
      <div className="border-t border-border/50">
        {/* Premium notice */}
        {isPremium && !loadingPrices && (
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.3 }}
            className="mx-4 sm:mx-5 mt-4 flex items-start gap-2 rounded-lg border border-amber-400/20 bg-amber-500/5 dark:bg-amber-950/20 px-3 py-2.5"
          >
            <RiInformationLine className="w-3.5 h-3.5 text-amber-500/70 mt-0.5 shrink-0" />
            <p className="text-[11px] text-muted-foreground leading-snug">
              {anyApiPremium && premiumRegistrars.length > 0
                ? (isZh
                    ? "溢价注册商报价（标注「溢价」）为域名真实价格，其余为参考标准价，实际价格以注册商报价为准。"
                    : "Entries marked \"Premium\" reflect the actual premium fee. Others show standard TLD reference prices — always confirm with the registrar.")
                : (isZh
                    ? "以下为该 TLD 标准/参考价，实际溢价金额可能显著更高，以注册商报价为准。"
                    : "Prices shown are standard/reference rates. Actual premium cost may be significantly higher — confirm with the registrar.")}
            </p>
          </motion.div>
        )}

        {/* Registration prices */}
        <div className="px-4 sm:px-5 pt-4 pb-1 flex items-center justify-between">
          <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 font-bold uppercase tracking-wider">
            <RiShoppingCartLine className="w-3 h-3" />
            {isZh ? "注册价格" : "Registration"}
          </p>
          {registrars.length > 0 && (
            <span className="text-[10px] text-muted-foreground/40">{isZh ? "以官网为准" : "Reference only"}</span>
          )}
        </div>

        {loadingPrices ? (
          <div className="px-4 sm:px-5 pb-4 pt-2 space-y-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-3 py-1.5">
                <div className="w-8 h-8 rounded-lg bg-muted/50 animate-pulse shrink-0" />
                <div className="flex-1 h-3.5 rounded bg-muted/40 animate-pulse" />
                <div className="w-16 h-4 rounded bg-muted/40 animate-pulse shrink-0" />
              </div>
            ))}
          </div>
        ) : registrars.length > 0 ? (
          <motion.div
            className="pb-1"
            initial="hidden"
            animate="visible"
            variants={staggerChildren}
          >
            {registrars.map((r, idx) => (
              <RegistrarRow key={r.registrar} r={r} idx={idx} priceField="new" colorFirst={true} />
            ))}
          </motion.div>
        ) : (
          <div className="px-4 sm:px-5 pb-4 pt-1">
            <p className="text-[10px] text-muted-foreground/40 mb-3 text-center">
              {isZh ? "暂无聚合价格数据，可直接前往以下注册商查询" : "No aggregated price data — search directly on these registrars"}
            </p>
            <div className="grid grid-cols-2 gap-2">
              {[
                { name: "Namecheap", color: "#de3723", logo: "namecheap.com", url: `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(domain)}` },
                { name: "GoDaddy",   color: "#1bdbdb", logo: "godaddy.com",   url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(domain)}` },
                { name: "Porkbun",   color: "#f76b8a", logo: "porkbun.com",   url: `https://porkbun.com/checkout/search?q=${encodeURIComponent(domain)}` },
                { name: "Dynadot",   color: "#4e2998", logo: "dynadot.com",   url: `https://www.dynadot.com/domain/search.html?domain=${encodeURIComponent(domain)}` },
                { name: "Cloudflare",color: "#f48120", logo: "cloudflare.com",url: `https://www.cloudflare.com/products/registrar/` },
                { name: "Name.com",  color: "#0066cc", logo: "name.com",      url: `https://www.name.com/domain/search?search=${encodeURIComponent(domain)}` },
              ].map(reg => (
                <motion.a
                  key={reg.name}
                  href={reg.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-2.5 py-2 rounded-lg border border-border/50 hover:border-primary/30 hover:bg-muted/40 transition-all group"
                  whileHover={{ scale: 1.02, x: 1 }}
                  transition={{ type: "spring", stiffness: 400, damping: 25 }}
                >
                  <DomainFavicon
                    domain={reg.logo}
                    size={16}
                    className="w-4 h-4 rounded-sm shrink-0"
                    fallback={<RiGlobalLine className="w-4 h-4 text-muted-foreground/50 shrink-0" />}
                  />
                  <span className="text-xs font-medium text-foreground/80 group-hover:text-foreground transition-colors truncate flex-1">{reg.name}</span>
                  <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/30 group-hover:text-muted-foreground/60 shrink-0 transition-colors" />
                </motion.a>
              ))}
            </div>
          </div>
        )}

        {/* Renewal prices */}
        {!loadingPrices && renewRegistrars.length > 0 && (
          <>
            <div className="border-t border-border/40 px-4 sm:px-5 pt-4 pb-1 flex items-center justify-between">
              <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 font-bold uppercase tracking-wider">
                <RiLoopLeftLine className="w-3 h-3" />
                {isZh ? "续费价格" : "Renewal"}
              </p>
            </div>
            <div className="pb-1">
              {renewRegistrars.map((r, idx) => (
                <RegistrarRow key={`renew-${r.registrar}`} r={r} idx={idx} priceField="renew" colorFirst={false} />
              ))}
            </div>
          </>
        )}

        {/* Footer note */}
        {!loadingPrices && registrars.length > 0 && (
          <p className="text-[10px] text-muted-foreground/30 px-4 sm:px-5 pt-2.5 pb-3">
            {isZh ? "数据来源：nazhumi.com & miqingju.com · 价格仅供参考" : "Source: nazhumi.com & miqingju.com · Reference only"}
          </p>
        )}
      </div>
    </motion.div>
  );
}
