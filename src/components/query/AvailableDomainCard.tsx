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
      <a
        href={r.registrarweb}
        target="_blank"
        rel="noopener noreferrer"
        className={cn(
          "flex items-center gap-3 px-4 sm:px-5 py-2.5 transition-colors duration-150 group hover:bg-muted/40",
          isFirst && colorFirst && "bg-muted/20",
        )}
      >
        <RegistrarIcon faviconDomain={faviconDomain} name={r.registrarname} />
        <div className="flex-1 min-w-0 flex items-center gap-2">
          <span className="shrink-0 text-[11px] font-bold text-muted-foreground/25 w-4 text-right tabular-nums">{idx + 1}</span>
          <p className={cn("text-sm truncate", isFirst ? "font-semibold text-foreground" : "font-medium text-foreground/70")}>
            {r.registrarname}
          </p>
          {isFirst && !rowIsPremium && !isPremium && colorFirst && (
            <span className="shrink-0 text-[9px] font-bold text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border border-emerald-400/30 dark:border-emerald-500/30 px-1.5 py-0.5 rounded uppercase tracking-wide">
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
                : (isFirst && colorFirst ? "text-base text-emerald-600 dark:text-emerald-400" : "text-sm text-foreground/60"),
            )}>
              {typeof price === "number" ? formatPrice(price, r.currency) : "N/A"}
            </span>
            <span className="text-xs text-muted-foreground/40">/{isZh ? "年" : "yr"}</span>
          </div>
          <svg className="w-3.5 h-3.5 text-muted-foreground/25 group-hover:text-muted-foreground/50 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </div>
      </a>
    );
  }

  return (
    <div className="glass-panel rounded-xl overflow-hidden border border-border/60">
      {/* Accent bar */}
      <div className={cn("h-1 w-full", isPremium ? "bg-gradient-to-r from-amber-400 to-amber-500" : "bg-gradient-to-r from-emerald-400 to-emerald-500")} />

      {/* ── Hero ── */}
      <div className={cn(
        "px-5 sm:px-8 pt-6 pb-5",
        isPremium ? "bg-amber-500/5 dark:bg-amber-950/15" : "bg-emerald-500/5 dark:bg-emerald-950/15"
      )}>
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            {/* Icon */}
            <div className={cn(
              "shrink-0 w-11 h-11 rounded-xl flex items-center justify-center border",
              isPremium
                ? "bg-amber-500/10 border-amber-400/30 dark:border-amber-500/30"
                : "bg-emerald-500/10 border-emerald-400/30 dark:border-emerald-500/30"
            )}>
              {isPremium
                ? <RiVipCrownLine className="w-5 h-5 text-amber-500 dark:text-amber-400" />
                : <RiCheckLine className="w-6 h-6 text-emerald-500 dark:text-emerald-400" />}
            </div>
            <div className="min-w-0">
              {/* Domain name */}
              <div className="mb-1 leading-tight">
                <span className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground break-all">{sldForDisplay}</span>
                <span className={cn(
                  "text-2xl sm:text-3xl font-bold tracking-tight",
                  isPremium ? "text-amber-500 dark:text-amber-400" : "text-emerald-500 dark:text-emerald-400"
                )}>{tldForDisplay}</span>
              </div>
              {/* Description */}
              <p className="text-sm text-muted-foreground leading-relaxed">
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
              </p>
            </div>
          </div>
          {/* Badge */}
          <div className="shrink-0 flex flex-row sm:flex-col items-center sm:items-end gap-2">
            <span className={cn(
              "inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border",
              isPremium
                ? "text-amber-700 dark:text-amber-300 bg-amber-500/10 border-amber-400/30 dark:border-amber-500/30"
                : "text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border-emerald-400/30 dark:border-emerald-500/30"
            )}>
              <span className={cn("w-1.5 h-1.5 rounded-full animate-pulse", isPremium ? "bg-amber-500" : "bg-emerald-500")} />
              {isPremium ? (isZh ? "溢价域名" : "Premium") : (isZh ? "可注册" : "Available")}
            </span>
          </div>
        </div>
      </div>

      {/* ── Action buttons ── */}
      <div className="px-5 sm:px-8 py-4 border-t border-border/40">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-center gap-2.5">
          {loadingPrices ? (
            <div className="h-9 w-44 rounded-lg bg-muted/40 animate-pulse mx-auto" />
          ) : bestRegistrar ? (
            <a
              href={bestRegistrar.registrarweb}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "inline-flex items-center justify-center gap-2 font-semibold text-sm px-5 py-2.5 rounded-lg border transition-all duration-150 active:scale-[0.98]",
                isPremium
                  ? "border-amber-400/40 dark:border-amber-500/35 text-amber-700 dark:text-amber-300 bg-amber-500/10 dark:bg-amber-500/12 hover:bg-amber-500/18 dark:hover:bg-amber-500/20"
                  : "border-emerald-400/40 dark:border-emerald-500/35 text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 dark:bg-emerald-500/12 hover:bg-emerald-500/18 dark:hover:bg-emerald-500/20"
              )}
            >
              <RiShoppingCartLine className="w-4 h-4 shrink-0" />
              <span>
                {isZh
                  ? `${isPremium ? "查看价格" : "立即注册"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/首年起`
                  : `${isPremium ? "Check Price" : "Register Now"} · ${formatPrice(bestRegistrar.new as number, bestRegistrar.currency)}/yr`}
              </span>
            </a>
          ) : null}
          <button
            onClick={handleCopy}
            className="inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.98]"
          >
            {copied
              ? <RiCheckLine className="w-4 h-4 shrink-0 text-emerald-500" />
              : <RiFileCopyLine className="w-4 h-4 shrink-0" />}
            {isZh ? (copied ? "已复制" : "复制域名") : (copied ? "Copied!" : "Copy Domain")}
          </button>
          <Link href="/">
            <button className="w-full sm:w-auto inline-flex items-center justify-center gap-2 text-sm font-medium px-4 py-2.5 rounded-lg border border-border/60 text-foreground/70 hover:bg-muted/50 hover:text-foreground transition-all duration-150 active:scale-[0.98]">
              <RiSearchLine className="w-4 h-4 shrink-0" />
              {isZh ? "新查询" : "New Search"}
            </button>
          </Link>
        </div>
      </div>

      {/* ── Registration tips ── */}
      <div className="border-t border-border/50 px-5 py-4">
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
            <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground leading-snug">
              <span className={cn("mt-1 w-1.5 h-1.5 rounded-full shrink-0", isPremium ? "bg-amber-400" : "bg-emerald-400")} />
              {tip}
            </li>
          ))}
        </ul>
      </div>

      {/* ── Price section ── */}
      <div className="border-t border-border/50">
        {/* Premium notice */}
        {isPremium && !loadingPrices && (
          <div className="mx-4 sm:mx-5 mt-4 flex items-start gap-2 rounded-lg border border-border/60 bg-muted/30 px-3 py-2.5">
            <RiInformationLine className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
            <p className="text-[11px] text-muted-foreground leading-snug">
              {anyApiPremium && premiumRegistrars.length > 0
                ? (isZh
                    ? "溢价注册商报价（标注「溢价」）为域名真实价格，其余为参考标准价，实际价格以注册商报价为准。"
                    : "Entries marked \"Premium\" reflect the actual premium fee. Others show standard TLD reference prices — always confirm with the registrar.")
                : (isZh
                    ? "以下为该 TLD 标准/参考价，实际溢价金额可能显著更高，以注册商报价为准。"
                    : "Prices shown are standard/reference rates. Actual premium cost may be significantly higher — confirm with the registrar.")}
            </p>
          </div>
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
          <div className="pb-1">
            {registrars.map((r, idx) => (
              <RegistrarRow key={r.registrar} r={r} idx={idx} priceField="new" colorFirst={true} />
            ))}
          </div>
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
                <a
                  key={reg.name}
                  href={reg.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-2.5 py-2 rounded-lg border border-border/50 hover:border-primary/30 hover:bg-muted/40 transition-all group"
                >
                  <DomainFavicon
                    domain={reg.logo}
                    size={16}
                    className="w-4 h-4 rounded-sm shrink-0"
                    fallback={<RiGlobalLine className="w-4 h-4 text-muted-foreground/50 shrink-0" />}
                  />
                  <span className="text-xs font-medium text-foreground/80 group-hover:text-foreground transition-colors truncate flex-1">{reg.name}</span>
                  <RiExternalLinkLine className="w-3 h-3 text-muted-foreground/30 group-hover:text-muted-foreground/60 shrink-0 transition-colors" />
                </a>
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
    </div>
  );
}
