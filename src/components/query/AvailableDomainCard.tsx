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
  RiPriceTag3Line,
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
  hidden: { opacity: 0, y: 14, scale: 0.98 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { duration: 0.4, ease: [0.22, 1, 0.36, 1] },
  },
};

const fadeUp = {
  hidden: { opacity: 0, y: 6 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.28, ease: [0.22, 1, 0.36, 1] } },
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

  // ── Label logic ──────────────────────────────────────────────────────────────
  // "高价值域名": only when WHOIS explicitly marks this domain as premium
  //   (registry-level premium — the most reliable signal).
  // "高注册费":  price-based detection (API fee threshold / anyApiPremium).
  //   Accurate description: the registration fee is above average, but it is
  //   NOT necessarily a "premium" name in the registry-reserved sense.
  // "可注册":    regular available domain.
  const labelType: "available" | "high_value" | "high_fee" =
    !isPremium ? "available" :
    isPremiumByWhois ? "high_value" :
    "high_fee";

  const LABELS = {
    available:  { zh: "可注册",    en: "Available" },
    high_value: { zh: "高价值域名", en: "Premium Name" },
    high_fee:   { zh: "高注册费",   en: "High Reg. Fee" },
  };
  const labelText = isZh ? LABELS[labelType].zh : LABELS[labelType].en;

  const ICON_MAP = {
    available:  <RiCheckLine  className="w-5 h-5 text-primary" />,
    high_value: <RiVipCrownLine className="w-5 h-5 text-amber-500 dark:text-amber-400" />,
    high_fee:   <RiPriceTag3Line className="w-5 h-5 text-orange-500 dark:text-orange-400" />,
  };

  const BADGE_CLASS = {
    available:  "text-primary  bg-primary/8    border-primary/25",
    high_value: "text-amber-600 dark:text-amber-400 bg-muted/60 border-border/60",
    high_fee:   "text-orange-600 dark:text-orange-400 bg-muted/60 border-border/60",
  };

  const DOT_CLASS = {
    available:  "bg-primary",
    high_value: "bg-amber-500",
    high_fee:   "bg-orange-500",
  };

  const ACCENT_CLASS = {
    available:  "bg-gradient-to-r from-primary/60 via-primary to-primary/60",
    high_value: "bg-gradient-to-r from-amber-400/50 via-amber-500/70 to-amber-400/50",
    high_fee:   "bg-gradient-to-r from-orange-400/40 via-orange-500/60 to-orange-400/40",
  };

  function getDescription(): string {
    if (labelType === "available") {
      return isZh ? "该域名目前可注册，抓紧时间抢注吧！" : "This domain is available. Grab it before someone else does.";
    }
    if (labelType === "high_value") {
      return isZh
        ? "该域名为注册局标注的高价值精品域名，注册价格通常显著高于普通域名。"
        : "This is a registry-level premium name. Registration costs significantly above standard rates.";
    }
    // high_fee
    if (anyApiPremium && premiumRegistrars.length > 0) {
      return isZh
        ? `注册费约 ${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/年起，高于该后缀普通注册价，以注册商实时报价为准。`
        : `Registration fee starts at ~${formatPrice(premiumRegistrars[0].new as number, premiumRegistrars[0].currency)}/yr — above standard rates for this TLD. Confirm with registrar.`;
    }
    return isZh
      ? "该域名注册费高于普通域名，请以注册商实时报价为准。"
      : "Registration fee is above average for this TLD. Confirm current pricing with your registrar.";
  }

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
            <span className="shrink-0 text-[9px] font-bold text-orange-600 dark:text-orange-400 bg-orange-500/8 border border-orange-400/25 px-1.5 py-0.5 rounded uppercase tracking-wide">
              {isZh ? "高价" : "HIGH"}
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
                ? (isFirst ? "text-base text-orange-600 dark:text-orange-400" : "text-sm text-orange-500/60 dark:text-orange-500/50")
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
      {/* Accent line */}
      <div className={cn("h-[3px] w-full", ACCENT_CLASS[labelType])} />

      {/* ── Hero ── */}
      <motion.div
        initial="hidden"
        animate="visible"
        variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.07 } } }}
        className="px-5 sm:px-7 pt-5 pb-5"
      >
        {/* Row 1: Icon + Domain name (domain is the hero) */}
        <motion.div variants={fadeUp} className="flex items-center gap-3 mb-3">
          {/* Status icon */}
          <div className="shrink-0 w-10 h-10 rounded-xl flex items-center justify-center border bg-muted/50 border-border/60">
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={labelType}
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                exit={{ scale: 0.6, opacity: 0 }}
                transition={{ duration: 0.22 }}
              >
                {ICON_MAP[labelType]}
              </motion.span>
            </AnimatePresence>
          </div>

          {/* Domain name — prominent, full remaining width */}
          <h1 className="flex-1 min-w-0 text-2xl sm:text-3xl font-bold tracking-tight leading-tight break-all">
            <span className="text-foreground">{sldForDisplay}</span>
            <span className="text-primary">{tldForDisplay}</span>
          </h1>
        </motion.div>

        {/* Row 2: Status badge + description */}
        <motion.div variants={fadeUp} className="pl-[52px]">
          {/* Badge */}
          <motion.span
            className={cn(
              "inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border mb-2",
              BADGE_CLASS[labelType]
            )}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.18, duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
          >
            <motion.span
              className={cn("w-1.5 h-1.5 rounded-full", DOT_CLASS[labelType])}
              animate={{ scale: [1, 1.45, 1], opacity: [1, 0.45, 1] }}
              transition={{ duration: 2.5, repeat: Infinity, ease: "easeInOut" }}
            />
            {labelText}
          </motion.span>

          {/* Description */}
          <p className="text-sm text-muted-foreground leading-relaxed">
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={labelType}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2 }}
              >
                {getDescription()}
              </motion.span>
            </AnimatePresence>
          </p>
        </motion.div>
      </motion.div>

      {/* ── Action buttons ── */}
      <motion.div
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.18, duration: 0.28 }}
        className="px-5 sm:px-7 pb-4 border-t border-border/40 pt-4"
      >
        <div className="flex flex-col gap-2">
          {loadingPrices ? (
            <div className="h-9 rounded-lg bg-muted/40 animate-pulse" />
          ) : bestRegistrar ? (
            <motion.a
              href={bestRegistrar.registrarweb}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center gap-2 font-semibold text-sm px-5 py-2.5 rounded-lg border border-primary/30 text-primary bg-primary/8 hover:bg-primary/14 transition-colors duration-200 active:scale-[0.97] w-full"
              whileTap={{ scale: 0.97 }}
              transition={{ type: "spring", stiffness: 400, damping: 25 }}
            >
              <RiShoppingCartLine className="w-4 h-4 shrink-0" />
              <span>
                {isZh
                  ? `${labelType === "available" ? "立即注册" : "查看价格"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/首年起`
                  : `${labelType === "available" ? "Register Now" : "Check Price"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/yr`}
              </span>
            </motion.a>
          ) : null}
          <div className="flex gap-2">
            <motion.button
              onClick={handleCopy}
              className="flex-1 inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.97]"
              whileTap={{ scale: 0.97 }}
              transition={{ type: "spring", stiffness: 400, damping: 25 }}
            >
              <AnimatePresence mode="wait" initial={false}>
                {copied ? (
                  <motion.span
                    key="copied"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.1 }}
                    className="inline-flex items-center gap-2"
                  >
                    <RiCheckLine className="w-4 h-4 shrink-0 text-primary" />
                    {isZh ? "已复制" : "Copied!"}
                  </motion.span>
                ) : (
                  <motion.span
                    key="copy"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.1 }}
                    className="inline-flex items-center gap-2"
                  >
                    <RiFileCopyLine className="w-4 h-4 shrink-0" />
                    {isZh ? "复制域名" : "Copy Domain"}
                  </motion.span>
                )}
              </AnimatePresence>
            </motion.button>
            <Link
              href="/"
              className="flex-1 inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150"
            >
              <RiSearchLine className="w-4 h-4 shrink-0" />
              {isZh ? "新查询" : "New Search"}
            </Link>
          </div>
        </div>
      </motion.div>

      {/* ── Registration tips ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.28, duration: 0.3 }}
        className="border-t border-border/50 px-5 sm:px-7 py-4"
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
              initial={{ opacity: 0, x: -5 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.32 + i * 0.06, duration: 0.22 }}
              className="flex items-start gap-2 text-sm text-muted-foreground leading-snug"
            >
              <span className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 bg-primary/45" />
              {tip}
            </motion.li>
          ))}
        </ul>
      </motion.div>

      {/* ── Price section ── */}
      <div className="border-t border-border/50">
        {/* High-fee / high-value notice */}
        {isPremium && !loadingPrices && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35, duration: 0.28 }}
            className="mx-4 sm:mx-5 mt-4 flex items-start gap-2 rounded-lg border border-border/50 bg-muted/30 px-3 py-2.5"
          >
            <RiInformationLine className="w-3.5 h-3.5 text-muted-foreground/60 mt-0.5 shrink-0" />
            <p className="text-[11px] text-muted-foreground leading-snug">
              {labelType === "high_value"
                ? (isZh
                    ? "此域名为注册局高价值精品域名，注册价格以注册商最终报价为准，各家价格可能存在差异。"
                    : "This is a registry-level premium name. Final pricing may vary across registrars — always confirm before purchasing.")
                : anyApiPremium && premiumRegistrars.length > 0
                  ? (isZh
                      ? "标注「高价」的报价为该域名的实际高价格，其余为该后缀标准参考价，实际以注册商报价为准。"
                      : "Entries marked \"High\" show the elevated fee for this domain. Others are standard TLD reference prices — confirm with your registrar.")
                  : (isZh
                      ? "以下为该后缀标准/参考价，部分域名实际注册价可能更高，以注册商报价为准。"
                      : "Prices shown are standard/reference rates. Actual cost may be higher — confirm with your registrar.")}
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
            variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.05 } } }}
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
                { name: "Namecheap", logo: "namecheap.com", url: `https://www.namecheap.com/domains/registration/results/?domain=${encodeURIComponent(domain)}` },
                { name: "GoDaddy",   logo: "godaddy.com",   url: `https://www.godaddy.com/domainsearch/find?domainToCheck=${encodeURIComponent(domain)}` },
                { name: "Porkbun",   logo: "porkbun.com",   url: `https://porkbun.com/checkout/search?q=${encodeURIComponent(domain)}` },
                { name: "Dynadot",   logo: "dynadot.com",   url: `https://www.dynadot.com/domain/search.html?domain=${encodeURIComponent(domain)}` },
                { name: "Cloudflare",logo: "cloudflare.com",url: `https://www.cloudflare.com/products/registrar/` },
                { name: "Name.com",  logo: "name.com",      url: `https://www.name.com/domain/search?search=${encodeURIComponent(domain)}` },
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
