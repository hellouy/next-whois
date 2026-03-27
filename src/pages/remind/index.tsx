import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import {
  RiCalendarLine, RiMailLine, RiSearchLine, RiShieldCheckLine,
  RiArrowRightLine, RiGlobalLine, RiTimeLine, RiTimerLine,
  RiLoader4Line, RiDeleteBinLine, RiExternalLinkLine,
  RiArrowLeftLine, RiBellLine, RiAlertLine, RiLockLine,
  RiCheckLine, RiRefreshLine, RiInformationLine,
  RiCheckboxCircleLine,
} from "@remixicon/react";

type Subscription = {
  id: string;
  domain: string;
  expiration_date: string | null;
  active: boolean;
  created_at: string;
  days_before: number | null;
  phase: string | null;
  days_to_expiry: number | null;
  days_to_drop: number | null;
  sent_keys: number[];
  last_reminded_at: string | null;
  next_reminder_at: string | null;
  next_reminder_days: number | null;
  tld_confidence: string | null;
  drop_date: string | null;
  grace_end: string | null;
  redemption_end: string | null;
};

type FilterKey = "all" | "expiring" | "expired" | "inactive";

function getSteps(t: (k: string) => string) {
  return [
    {
      icon: RiSearchLine,
      color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
      title: t("remind.step1_title"),
      desc: t("remind.step1_desc"),
    },
    {
      icon: RiBellLine,
      color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
      title: t("remind.step2_title"),
      desc: t("remind.step2_desc"),
    },
    {
      icon: RiMailLine,
      color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
      title: t("remind.step3_title"),
      desc: t("remind.step3_desc"),
    },
  ];
}

function fmt(d: Date, locale: string) {
  return d.toLocaleDateString(locale, { year: "numeric", month: "2-digit", day: "2-digit" });
}

function fmtShort(d: Date, locale: string) {
  return d.toLocaleDateString(locale, { month: "2-digit", day: "2-digit" });
}

function getDaysLeft(expDate: string | null): number | null {
  if (!expDate) return null;
  const diff = new Date(expDate).getTime() - Date.now();
  return Math.ceil(diff / 86400000);
}

function PhaseChip({ phase }: { phase: string | null }) {
  const { t } = useTranslation();
  if (!phase || phase === "active") return null;
  const map: Record<string, { label: string; cls: string }> = {
    grace:      { label: t("remind.phase_grace"),      cls: "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400" },
    redemption: { label: t("remind.phase_redemption"), cls: "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400" },
    pending:    { label: t("remind.phase_pending"),    cls: "bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400" },
    dropped:    { label: t("remind.phase_dropped"),    cls: "bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400" },
  };
  const info = map[phase];
  if (!info) return null;
  return (
    <span className={cn("inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold", info.cls)}>
      {info.label}
    </span>
  );
}

function UrgencyBar({ daysLeft, phase }: { daysLeft: number | null; phase: string | null }) {
  if (daysLeft === null) return null;
  if (daysLeft > 90) return null;
  const pct = Math.max(0, Math.min(100, (daysLeft / 90) * 100));
  const color =
    daysLeft <= 7  ? "bg-red-500" :
    daysLeft <= 30 ? "bg-orange-500" :
    daysLeft <= 60 ? "bg-amber-400" :
                     "bg-emerald-500";
  return (
    <div className="h-1 w-full rounded-full bg-muted/50 overflow-hidden mt-1.5">
      <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${pct}%` }} />
    </div>
  );
}

const ALL_THRESHOLDS = [60, 30, 10, 5, 1];

// ── Direct-subscribe form (shown when ?domain= is in the URL) ──────────────
type WhoisInfo = {
  creationDate: string | null;
  updatedDate: string | null;
  expirationDate: string | null;
  remainingDays: number | null;
  domainAge: number | null;
  registrar: string | null;
  nameServers: string[];
  statusFlags: string[];
  dnssec: string | null;
  regStatus: "registered" | "unregistered" | "reserved" | "unknown";
  hasData: boolean;
};

function fmtDate(raw: string | null, locale: string): string {
  if (!raw || raw === "Unknown") return "—";
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  return d.toLocaleDateString(locale, { year: "numeric", month: "2-digit", day: "2-digit" });
}

function fmtRelative(raw: string | null, t: (k: string) => string): string | null {
  if (!raw || raw === "Unknown") return null;
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  const diffDays = Math.round((Date.now() - d.getTime()) / 86_400_000);
  if (diffDays < 1) return t("remind.today");
  if (diffDays < 30) return t("remind.days_ago").replace("{{n}}", String(diffDays));
  const months = Math.round(diffDays / 30);
  if (months < 12) return t("remind.months_ago").replace("{{n}}", String(months));
  const years = Math.floor(diffDays / 365);
  const remMonths = Math.round((diffDays % 365) / 30);
  return remMonths > 0
    ? t("remind.years_months_ago").replace("{{n}}", String(years)).replace("{{m}}", String(remMonths))
    : t("remind.years_ago").replace("{{n}}", String(years));
}

function fmtDaysRemaining(days: number, t: (k: string) => string): string {
  if (days <= 0) return t("remind.expired_n_days").replace("{{n}}", String(Math.abs(days)));
  if (days < 30) return t("remind.expires_in_days").replace("{{n}}", String(days));
  if (days < 365) {
    const months = Math.floor(days / 30);
    const rem = days % 30;
    return rem > 0
      ? t("remind.expires_in_months_days").replace("{{n}}", String(months)).replace("{{d}}", String(rem))
      : t("remind.expires_in_months").replace("{{n}}", String(months));
  }
  const years = Math.floor(days / 365);
  const remDays = days % 365;
  const months = Math.floor(remDays / 30);
  if (months > 0) return t("remind.expires_in_years_months").replace("{{n}}", String(years)).replace("{{m}}", String(months));
  return t("remind.expires_in_years").replace("{{n}}", String(years));
}

function DaysRemainingBar({ days }: { days: number }) {
  const { t } = useTranslation();
  const expired = days <= 0;
  const urgent  = days > 0 && days <= 30;
  const warning = days > 30 && days <= 90;
  const pct     = expired ? 100 : Math.min(100, Math.max(2, (1 - days / 365) * 100));

  return (
    <div className={cn(
      "rounded-2xl px-4 py-3 space-y-2",
      expired ? "bg-red-50/80 dark:bg-red-950/20 border border-red-200/60 dark:border-red-800/40"
        : urgent ? "bg-red-50/60 dark:bg-red-950/15 border border-red-200/50 dark:border-red-800/30"
        : warning ? "bg-amber-50/60 dark:bg-amber-950/15 border border-amber-200/50 dark:border-amber-800/30"
        : "bg-emerald-50/50 dark:bg-emerald-950/10 border border-emerald-200/50 dark:border-emerald-800/30"
    )}>
      <div className="flex items-center justify-between">
        <span className={cn(
          "text-[10px] font-semibold flex items-center gap-1",
          expired ? "text-red-600 dark:text-red-400"
            : urgent ? "text-red-600 dark:text-red-400"
            : warning ? "text-amber-600 dark:text-amber-400"
            : "text-emerald-700 dark:text-emerald-400"
        )}>
          <RiTimerLine className="w-3 h-3" />
          {fmtDaysRemaining(days, t as (k: string) => string)}
        </span>
        <span className={cn(
          "text-[10px] font-bold tabular-nums",
          expired ? "text-red-500" : urgent ? "text-red-500" : warning ? "text-amber-600" : "text-emerald-600"
        )}>
          {expired ? t("remind.expired_label") : t("remind.days_label").replace("{{n}}", String(days))}
        </span>
      </div>
      <div className="w-full h-1.5 rounded-full bg-black/5 dark:bg-white/10 overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            expired ? "bg-red-500" : urgent ? "bg-red-400" : warning ? "bg-amber-400" : "bg-emerald-500"
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className={cn(
        "text-[9px]",
        expired ? "text-red-500/70" : urgent ? "text-red-500/70" : warning ? "text-amber-600/70" : "text-emerald-700/60 dark:text-emerald-400/60"
      )}>
        {expired ? t("remind.domain_expired_hint") :
          urgent  ? t("remind.domain_urgent_hint") :
          warning ? t("remind.domain_warning_hint") :
          t("remind.domain_healthy_hint")}
      </p>
    </div>
  );
}

function DirectSubscribeForm({ domain }: { domain: string }) {
  const router = useRouter();
  const { t, locale } = useTranslation();
  const { data: session, status } = useSession();
  const [email, setEmail] = React.useState("");
  const [thresholds, setThresholds] = React.useState<number[]>([60, 30, 1]);
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);
  const [whois, setWhois] = React.useState<WhoisInfo | null>(null);
  const [whoisLoading, setWhoisLoading] = React.useState(true);
  const [whoisError, setWhoisError] = React.useState(false);

  // Redirect unauthenticated users to login, preserving ?domain=
  React.useEffect(() => {
    if (status === "unauthenticated") {
      router.replace(`/login?callbackUrl=${encodeURIComponent(`/remind?domain=${encodeURIComponent(domain)}`)}`);
    }
  }, [status, domain, router]);

  // Prefill email from session
  React.useEffect(() => {
    if (session?.user?.email) setEmail(prev => prev || session.user!.email!);
  }, [session]);

  const fetchWhois = React.useCallback(() => {
    if (!domain) return;
    setWhoisLoading(true);
    setWhoisError(false);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20_000);

    fetch(`/api/remind/whois?query=${encodeURIComponent(domain)}`, { signal: controller.signal })
      .then(r => r.json())   // Always parse JSON regardless of status code
      .then((data: any) => {
        clearTimeout(timer);
        // If lookup truly failed with no result at all, show error
        if (!data || (!data.result && data.status === false)) {
          setWhoisError(true);
          return;
        }
        const r: any = data.result ?? data;

        const clean = (v: any) => (v && v !== "Unknown" && v !== "N/A" ? String(v) : null);
        const creation   = clean(r.creationDate);
        const updated    = clean(r.updatedDate);
        const expiration = clean(r.expirationDate);
        const remaining  = typeof r.remainingDays === "number" ? r.remainingDays : null;
        const domainAge  = typeof r.domainAge === "number" ? r.domainAge : null;
        const registrar  = clean(r.registrar);
        const dnssec     = clean(r.dnssec);
        const nameServers: string[] = Array.isArray(r.nameServers)
          ? r.nameServers.filter((ns: any) => ns && ns !== "Unknown").slice(0, 4)
          : [];
        const statusFlags: string[] = Array.isArray(r.status)
          ? r.status.map((s: any) => s.status || s).filter((s: any) => s && s !== "Unknown").slice(0, 3)
          : [];

        // Derive regStatus from lookup API fields
        let regStatus: WhoisInfo["regStatus"] = "unknown";
        if (data.status === true && r.registrar && r.registrar !== "Unknown") regStatus = "registered";
        else if (expiration || creation) regStatus = "registered";

        setWhois({
          creationDate: creation,
          updatedDate:  updated,
          expirationDate: expiration,
          remainingDays:  remaining,
          domainAge,
          registrar,
          nameServers,
          statusFlags,
          dnssec,
          regStatus,
          hasData: !!(creation || expiration || remaining !== null || registrar || nameServers.length > 0),
        });
      })
      .catch((err: any) => {
        clearTimeout(timer);
        if (err?.name !== "AbortError") setWhoisError(true);
      })
      .finally(() => setWhoisLoading(false));
  }, [domain]);

  React.useEffect(() => { fetchWhois(); }, [fetchWhois]);

  function toggleThreshold(d: number) {
    setThresholds(prev => prev.includes(d) ? prev.filter(x => x !== d) : [...prev, d].sort((a, b) => b - a));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email || !email.includes("@")) { toast.error(t("remind.err_email")); return; }
    if (thresholds.length === 0) { toast.error(t("remind.err_threshold")); return; }
    setSubmitting(true);
    try {
      const res = await fetch("/api/remind/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain: domain.toLowerCase().trim(),
          email,
          expirationDate: (whois?.expirationDate && whois.expirationDate !== "Unknown") ? whois.expirationDate : null,
          phaseAlerts: { grace: true, redemption: true, pendingDelete: true, dropSoon: true, dropped: true },
          thresholds,
          regStatusType: null,
        }),
      });
      if (res.ok) {
        setDone(true);
      } else {
        const data = await res.json().catch(() => ({}));
        if (data.code === "LIMIT_EXCEEDED") {
          toast.error(
            t("remind.limit_reached").replace("{{n}}", String(data.limit)),
            {
              action: { label: t("remind.upgrade_now"), onClick: () => router.push("/payment/checkout") },
              duration: 6000,
            }
          );
        } else {
          toast.error(data.error || t("remind.err_submit"));
        }
      }
    } catch { toast.error(t("remind.network_error")); }
    finally { setSubmitting(false); }
  }

  if (status === "loading" || status === "unauthenticated") {
    return (
      <div className="min-h-[calc(100vh-64px)] bg-background">
        <div className="max-w-lg mx-auto px-4 py-5 space-y-4 animate-pulse">
          <div className="h-5 w-32 rounded-lg bg-muted/50" />
          <div className="h-32 rounded-2xl bg-muted/40" />
          <div className="h-24 rounded-2xl bg-muted/40" />
          <div className="h-28 rounded-2xl bg-muted/40" />
          <div className="h-12 rounded-xl bg-muted/35" />
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title key="title">{`${t("remind.sub_success")} · ${domain}`}</title>
      </Head>
      <div className="min-h-[calc(100vh-64px)] bg-background">
        <div className="max-w-lg mx-auto px-4 py-5 pb-10">
          {/* Back nav */}
          <div className="flex items-center gap-2 mb-5">
            <button
              onClick={() => { if (window.history.length > 1) router.back(); else router.push("/dashboard"); }}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors group"
            >
              <RiArrowLeftLine className="w-4 h-4 transition-transform group-hover:-translate-x-0.5" />
              {t("remind.back")}
            </button>
            <span className="text-muted-foreground/30">·</span>
            <span className="text-sm font-mono text-muted-foreground/80">{domain}</span>
          </div>

          {done ? (
            /* ── Success state ── */
            <div className="space-y-4">
              <div className="glass-panel border border-border rounded-2xl p-8 text-center space-y-4">
                <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-200/60 dark:border-emerald-800/40 flex items-center justify-center mx-auto">
                  <RiCheckboxCircleLine className="w-7 h-7 text-emerald-500" />
                </div>
                <div className="space-y-1.5">
                  <p className="text-base font-bold">{t("remind.sub_success")}</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {t("remind.sub_success_domain").replace("{{domain}}", domain)}<br />
                    {t("remind.confirm_sent").replace("{{email}}", email)}
                  </p>
                </div>
                {whois?.hasData && whois.expirationDate && (
                  <div className="w-full space-y-1.5">
                    <div className="bg-muted/40 rounded-xl px-4 py-2.5 text-[11px] text-muted-foreground flex items-center justify-between gap-2">
                      <span>{t("remind.expiration_date_label")}</span>
                      <span className="font-semibold text-foreground font-mono">{fmtDate(whois.expirationDate, locale)}</span>
                    </div>
                    {whois.remainingDays !== null && <DaysRemainingBar days={whois.remainingDays} />}
                  </div>
                )}
                <div className="flex gap-2 justify-center pt-1">
                  <Button size="sm" variant="outline" className="rounded-xl text-xs h-8 gap-1" onClick={() => router.push("/dashboard")}>
                    {t("remind.goto_dashboard")}
                  </Button>
                  <Button size="sm" className="rounded-xl text-xs h-8 gap-1" onClick={() => router.push(`/${domain}`)}>
                    {t("remind.view_whois")}
                  </Button>
                </div>
              </div>
            </div>
          ) : (
            /* ── Subscription form ── */
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Header */}
              <div className="flex items-center gap-2 mb-1">
                <RiCalendarLine className="w-4 h-4 text-sky-500 shrink-0" />
                <h1 className="text-sm font-bold">{t("remind.page_title_main")}</h1>
              </div>

              {/* Domain + WHOIS info card */}
              <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                {/* Domain header row */}
                <div className="px-4 pt-4 pb-3 flex items-center gap-3 border-b border-border/60">
                  <div className="w-9 h-9 rounded-xl bg-sky-500/10 flex items-center justify-center shrink-0">
                    <RiGlobalLine className="w-4.5 h-4.5 text-sky-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/50 mb-0.5">{t("remind.domain_label")}</p>
                    <p className="text-sm font-bold font-mono truncate">{domain.toUpperCase()}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {!whoisLoading && (
                      <button
                        type="button"
                        onClick={fetchWhois}
                        className="p-1 rounded-lg text-muted-foreground hover:text-foreground transition-colors hover:bg-muted"
                        title={t("remind.refresh_hint")}
                      >
                        <RiRefreshLine className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <Link
                      href={`/${domain}`}
                      className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                    >
                      WHOIS <RiExternalLinkLine className="w-3 h-3" />
                    </Link>
                  </div>
                </div>

                {/* Date info — 4 states */}
                {whoisLoading ? (
                  /* Loading skeleton */
                  <div className="px-4 py-4 space-y-3 animate-pulse">
                    <div className="flex items-center justify-between">
                      <div className="h-3 w-16 rounded bg-muted/50" />
                      <div className="h-3 w-24 rounded bg-muted/40" />
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="h-3 w-16 rounded bg-muted/50" />
                      <div className="h-3 w-24 rounded bg-muted/40" />
                    </div>
                    <div className="h-14 w-full rounded-xl bg-muted/30" />
                  </div>
                ) : whoisError ? (
                  /* Error state */
                  <div className="px-4 py-4 space-y-3">
                    <div className="flex items-start gap-3">
                      <RiAlertLine className="w-4 h-4 text-amber-500 mt-0.5 shrink-0" />
                      <div className="flex-1">
                        <p className="text-[11px] font-semibold text-foreground">{t("remind.whois_unavailable")}</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5">
                          {t("remind.whois_fail_hint")}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={fetchWhois}
                        className="text-[10px] font-semibold text-sky-600 dark:text-sky-400 hover:underline shrink-0"
                      >
                        {t("remind.retry")}
                      </button>
                    </div>
                    <div className="flex items-center gap-2 sm:hidden">
                      <Link
                        href="/"
                        className="flex-1 flex items-center justify-center gap-1.5 h-7 rounded-lg border border-border bg-muted/30 text-[10px] text-muted-foreground hover:text-foreground font-medium"
                      >
                        <RiSearchLine className="w-3 h-3" /> {t("remind.goto_home_query")}
                      </Link>
                      <Link
                        href="/guide"
                        className="flex-1 flex items-center justify-center gap-1.5 h-7 rounded-lg border border-sky-200 dark:border-sky-800 bg-sky-50/60 dark:bg-sky-950/20 text-[10px] text-sky-600 dark:text-sky-400 font-medium"
                      >
                        <RiArrowRightLine className="w-3 h-3" /> {t("remind.view_guide")}
                      </Link>
                    </div>
                  </div>
                ) : !whois?.hasData ? (
                  /* No date data */
                  <div className="px-4 py-4 space-y-1.5">
                    <div className="flex items-start gap-2.5">
                      <RiInformationLine className="w-4 h-4 text-muted-foreground/60 mt-0.5 shrink-0" />
                      <div>
                        <p className="text-[11px] text-muted-foreground">{t("remind.no_expiry_hint")}</p>
                        <p className="text-[10px] text-muted-foreground/60 mt-0.5 leading-relaxed">
                          {t("remind.no_expiry_detail")}
                        </p>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* Has data — simplified WHOIS key info */
                  <div className="px-4 pb-4 space-y-3">

                    {/* Days remaining bar (most prominent) */}
                    {whois.remainingDays !== null && (
                      <DaysRemainingBar days={whois.remainingDays} />
                    )}

                    {/* Grid of key dates */}
                    <div className="grid grid-cols-2 gap-2">
                      {whois.creationDate && (
                        <div className="rounded-xl bg-muted/30 dark:bg-muted/20 px-3 py-2 space-y-0.5">
                          <div className="flex items-center gap-1 text-[9px] text-muted-foreground font-medium uppercase tracking-wide">
                            <RiTimeLine className="w-2.5 h-2.5" /> {t("remind.reg_date")}
                          </div>
                          <div className="text-[11px] font-mono font-semibold text-foreground">{fmtDate(whois.creationDate, locale)}</div>
                          {whois.domainAge !== null && (
                            <div className="text-[9px] text-muted-foreground">{t("remind.days_registered").replace("{{n}}", String(whois.domainAge))}</div>
                          )}
                        </div>
                      )}
                      {whois.expirationDate && (
                        <div className={cn(
                          "rounded-xl px-3 py-2 space-y-0.5",
                          whois.remainingDays !== null && whois.remainingDays <= 30
                            ? "bg-red-50/70 dark:bg-red-950/20 border border-red-200/50 dark:border-red-800/30"
                            : "bg-muted/30 dark:bg-muted/20"
                        )}>
                          <div className={cn(
                            "flex items-center gap-1 text-[9px] font-medium uppercase tracking-wide",
                            whois.remainingDays !== null && whois.remainingDays <= 30
                              ? "text-red-500 dark:text-red-400"
                              : "text-muted-foreground"
                          )}>
                            <RiCalendarLine className="w-2.5 h-2.5" /> {t("remind.exp_date")}
                          </div>
                          <div className="text-[11px] font-mono font-semibold text-foreground">{fmtDate(whois.expirationDate, locale)}</div>
                          {whois.updatedDate && (
                            <div className="text-[9px] text-muted-foreground">{t("remind.updated_date").replace("{{date}}", fmtDate(whois.updatedDate, locale))}</div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Registrar + DNSSEC row */}
                    {(whois.registrar || whois.dnssec) && (
                      <div className="space-y-1.5">
                        {whois.registrar && (
                          <div className="flex items-center justify-between gap-3">
                            <span className="text-[10px] text-muted-foreground flex items-center gap-1.5 shrink-0">
                              <RiInformationLine className="w-3 h-3" /> {t("remind.registrar_label")}
                            </span>
                            <span className="text-[10px] font-medium text-foreground/80 text-right truncate max-w-[60%]">
                              {whois.registrar}
                            </span>
                          </div>
                        )}
                        {whois.dnssec && whois.dnssec !== "unsigned" && (
                          <div className="flex items-center justify-between gap-3">
                            <span className="text-[10px] text-muted-foreground flex items-center gap-1.5 shrink-0">
                              <RiShieldCheckLine className="w-3 h-3" /> DNSSEC
                            </span>
                            <span className="text-[10px] font-medium text-emerald-600 dark:text-emerald-400">
                              {t("remind.dnssec_signed")}
                            </span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Name servers */}
                    {whois.nameServers.length > 0 && (
                      <div className="space-y-1">
                        <div className="text-[9px] text-muted-foreground font-medium uppercase tracking-wide flex items-center gap-1">
                          <RiGlobalLine className="w-2.5 h-2.5" /> {t("remind.nameservers_label")}
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {whois.nameServers.map((ns, i) => (
                            <span key={i} className="text-[9px] font-mono bg-muted/40 dark:bg-muted/25 rounded-md px-1.5 py-0.5 text-muted-foreground lowercase">
                              {ns.toLowerCase()}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Status flags */}
                    {whois.statusFlags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {whois.statusFlags.map((sf, i) => {
                          const short = sf.split(/\s+/)[0];
                          const ok = short.toLowerCase().startsWith("ok") || short.toLowerCase().includes("active");
                          return (
                            <span key={i} className={cn(
                              "text-[8px] font-mono rounded-md px-1.5 py-0.5 font-medium",
                              ok
                                ? "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400"
                                : "bg-amber-50 dark:bg-amber-950/20 text-amber-600 dark:text-amber-400"
                            )}>
                              {short}
                            </span>
                          );
                        })}
                      </div>
                    )}

                    {/* View full WHOIS link */}
                    <a
                      href={`/${domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] text-sky-600 dark:text-sky-400 hover:underline font-medium"
                    >
                      {t("remind.view_full_whois")} <RiExternalLinkLine className="w-2.5 h-2.5" />
                    </a>
                  </div>
                )}
              </div>

              {/* Email */}
              <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />
                  <p className="text-xs font-semibold">{t("remind.email_label")}</p>
                </div>
                <Input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="your@email.com"
                  className="h-9 rounded-xl text-sm"
                  required
                />
                <p className="text-[10px] text-muted-foreground">{t("remind.email_hint")}</p>
              </div>

              {/* Thresholds */}
              <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <RiBellLine className="w-3.5 h-3.5 text-muted-foreground" />
                  <p className="text-xs font-semibold">{t("remind.threshold_label")}</p>
                  <span className="text-[10px] text-muted-foreground ml-auto">{t("remind.threshold_hint")}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {ALL_THRESHOLDS.map(d => {
                    const active = thresholds.includes(d);
                    return (
                      <button
                        key={d}
                        type="button"
                        onClick={() => toggleThreshold(d)}
                        className={cn(
                          "px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all",
                          active
                            ? "bg-sky-500 text-white border-sky-500"
                            : "bg-background text-muted-foreground border-border hover:border-sky-400/60 hover:text-sky-600"
                        )}
                      >
                        {t("remind.days_before").replace("{{n}}", String(d))}
                      </button>
                    );
                  })}
                </div>
                <p className="text-[10px] text-muted-foreground">{t("remind.lifecycle_hint")}</p>
              </div>

              {/* Submit */}
              <Button type="submit" disabled={submitting} className="w-full h-11 rounded-xl gap-1.5">
                {submitting ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiCheckLine className="w-4 h-4" />}
                {submitting ? t("remind.submitting") : t("remind.submit")}
              </Button>

              <p className="text-[10px] text-muted-foreground text-center">
                {t("remind.manage_hint_prefix")}{" "}
                <button type="button" className="underline hover:text-foreground" onClick={() => router.push("/dashboard")}>{t("remind.manage_link")}</button>
                {" "}{t("remind.manage_hint_suffix")}
              </p>
            </form>
          )}
        </div>
      </div>
    </>
  );
}

export default function RemindPage() {
  const router = useRouter();
  const { t, locale } = useTranslation();
  const { data: session, status } = useSession();
  const siteSettings = useSiteSettings();
  const siteName = siteSettings.site_logo_text || "X.RW";
  const [searchQuery, setSearchQuery] = React.useState("");
  const [subscriptions, setSubscriptions] = React.useState<Subscription[]>([]);
  const [loadingSubs, setLoadingSubs] = React.useState(false);
  const [cancelling, setCancelling] = React.useState<string | null>(null);
  const [reactivating, setReactivating] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState<FilterKey>("all");
  const [expandInactive, setExpandInactive] = React.useState(false);

  const domainParam = String(router.query.domain || "").trim();

  // Load subscriptions only in list mode (no domain param)
  React.useEffect(() => {
    if (domainParam) return;
    if (status === "authenticated") {
      setLoadingSubs(true);
      fetch("/api/user/subscriptions")
        .then(r => r.json())
        .then(d => { if (d.subscriptions) setSubscriptions(d.subscriptions); })
        .catch(() => {})
        .finally(() => setLoadingSubs(false));
    }
  }, [status, domainParam]);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = searchQuery.trim();
    if (!q) return;
    router.push(`/${q}?subscribe=1`);
  }

  // Delegate to DirectSubscribeForm when ?domain= is present — after all hooks
  if (domainParam) return <DirectSubscribeForm domain={domainParam} />;

  async function cancelSub(id: string) {
    setCancelling(id);
    try {
      await fetch(`/api/user/subscriptions?id=${id}`, { method: "DELETE" });
      setSubscriptions(prev => prev.map(s => s.id === id ? { ...s, active: false } : s));
      toast.success(t("remind.cancel_sub_success"));
    } catch {
      toast.error(t("remind.cancel_sub_fail"));
    } finally {
      setCancelling(null);
    }
  }

  async function reactivateSub(id: string, domain: string) {
    setReactivating(id);
    try {
      const r = await fetch(`/api/user/subscriptions?id=${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active: true }),
      });
      if (!r.ok) throw new Error();
      setSubscriptions(prev => prev.map(s => s.id === id ? { ...s, active: true } : s));
      toast.success(t("remind.reactivate_success"));
    } catch {
      router.push(`/${domain}?subscribe=1`);
    } finally {
      setReactivating(null);
    }
  }

  const activeSubs = subscriptions.filter(s => s.active);
  const inactiveSubs = subscriptions.filter(s => !s.active);

  const expiringSoon = activeSubs.filter(s => {
    const d = s.days_to_expiry ?? getDaysLeft(s.expiration_date);
    return d !== null && d >= 0 && d <= 30;
  });

  const expiredSubs = activeSubs.filter(s => {
    const d = s.days_to_expiry ?? getDaysLeft(s.expiration_date);
    return d !== null && d < 0;
  });

  const totalSent = subscriptions.reduce((acc, s) => acc + (s.sent_keys?.length ?? 0), 0);

  const filteredSubs = (() => {
    switch (filter) {
      case "expiring": return expiringSoon;
      case "expired":  return expiredSubs;
      case "inactive": return inactiveSubs;
      default:         return activeSubs;
    }
  })();

  const filterTabs: { key: FilterKey; label: string; count?: number }[] = [
    { key: "all",      label: t("remind.filter_all"),      count: activeSubs.length },
    { key: "expiring", label: t("remind.filter_expiring"), count: expiringSoon.length },
    { key: "expired",  label: t("remind.filter_expired"),  count: expiredSubs.length },
    { key: "inactive", label: t("remind.filter_inactive"), count: inactiveSubs.length },
  ];

  return (
    <>
      <Head>
        <title key="title">{`${t("remind.page_title_main")} · ${siteName}`}</title>
        <meta name="description" content={t("remind.page_desc_main")} />
      </Head>

      <div className="max-w-2xl mx-auto px-4 py-8 space-y-8">
        {/* Back */}
        <Link href="/dashboard" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
          <RiArrowLeftLine className="w-3.5 h-3.5" />{t("remind.back_dashboard")}
        </Link>

        {/* Hero */}
        <div className="space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center">
            <RiCalendarLine className="w-6 h-6 text-primary" />
          </div>
          <h1 className="text-2xl font-bold">{t("remind.page_title_main")}</h1>
          <p className="text-sm text-muted-foreground leading-relaxed">
            {t("remind.page_desc_main")}
          </p>
        </div>

        {/* Search bar */}
        <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-2">
            <RiSearchLine className="w-4 h-4 text-primary" />
            <p className="text-sm font-bold">{t("remind.search_title")}</p>
          </div>
          <form onSubmit={handleSearch} className="flex gap-2">
            <Input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder={t("remind.search_placeholder")}
              className="h-10 rounded-xl text-sm font-mono flex-1"
              autoComplete="off"
            />
            <Button type="submit" className="h-10 rounded-xl gap-1.5 px-5 shrink-0">
              {t("remind.search_btn")}
              <RiArrowRightLine className="w-3.5 h-3.5" />
            </Button>
          </form>
        </div>

        {/* Visual mockup */}
        <div className="space-y-2">
          <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">{t("remind.find_entry")}</p>
          <div className="relative rounded-2xl border border-border bg-muted/10 p-4">
            <span className="absolute top-3 right-3 text-[9px] font-bold uppercase tracking-widest text-muted-foreground/50 bg-muted/60 px-2 py-0.5 rounded-full">{t("remind.preview_label")}</span>
            <div className="rounded-xl border border-border bg-background shadow-sm overflow-hidden">
              <div className="px-4 pt-3.5 pb-2 space-y-1.5">
                <p className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/50">DOMAIN</p>
                <p className="text-sm font-bold font-mono tracking-tight">X.RW</p>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />Active
                  </span>
                  <span className="text-[10px] text-muted-foreground">⏱ 2y</span>
                </div>
              </div>
              <div className="px-4 pb-3.5 hidden sm:flex items-center gap-2">
                <div className="flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-medium border bg-muted/40 border-border/50 text-muted-foreground/50">
                  <RiShieldCheckLine className="w-3 h-3" />{t("remind.brand_stamp")}
                </div>
                <div className="relative flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-semibold border bg-sky-100 dark:bg-sky-950/50 border-sky-400/70 text-sky-600 dark:text-sky-400 shadow-sm ring-2 ring-sky-400/20">
                  <RiTimeLine className="w-3 h-3" />{t("remind.domain_subscription")}
                  <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-60" />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-sky-500" />
                  </span>
                </div>
              </div>
              <div className="px-4 pb-3.5 flex items-center gap-2 sm:hidden">
                <div className="flex items-center justify-center w-6 h-6 rounded-full border bg-muted/40 border-border/50 text-muted-foreground/60">
                  <RiShieldCheckLine className="w-3 h-3" />
                </div>
                <div className="relative flex items-center justify-center w-6 h-6 rounded-full border bg-sky-50 dark:bg-sky-950/40 border-sky-400/60 text-sky-500">
                  <RiTimerLine className="w-3 h-3" />
                  <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-60" />
                    <span className="relative inline-flex h-2 w-2 rounded-full bg-sky-500" />
                  </span>
                </div>
                <span className="text-[9px] text-muted-foreground ml-1">{t("remind.click_subscribe_btn")}</span>
              </div>
            </div>
            <p className="text-[10px] text-muted-foreground text-center mt-2.5">
              <span className="sm:hidden">{t("remind.mobile_hint")}</span>
              <span className="hidden sm:inline">{t("remind.desktop_hint")}</span>
            </p>
          </div>

          {/* Mobile guide CTA — only shown on small screens */}
          <div className="sm:hidden mt-4 rounded-2xl border border-sky-200 dark:border-sky-800 bg-sky-50/60 dark:bg-sky-950/20 p-4">
            <div className="flex items-start gap-3">
              <div className="w-9 h-9 rounded-xl bg-sky-100 dark:bg-sky-900/40 border border-sky-200 dark:border-sky-800 flex items-center justify-center shrink-0">
                <RiBellLine className="w-4.5 h-4.5 text-sky-600 dark:text-sky-400" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-foreground">{t("remind.first_time")}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">
                  {t("remind.first_time_desc")}
                </p>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-2">
              <Link href="/guide">
                <Button variant="outline" size="sm" className="w-full h-9 rounded-xl text-xs gap-1.5 border-sky-200 dark:border-sky-700 text-sky-700 dark:text-sky-400">
                  <RiArrowRightLine className="w-3 h-3" /> {t("remind.view_guide")}
                </Button>
              </Link>
              <Link href="/">
                <Button size="sm" className="w-full h-9 rounded-xl text-xs gap-1.5">
                  <RiSearchLine className="w-3 h-3" /> {t("remind.goto_query")}
                </Button>
              </Link>
            </div>
          </div>
        </div>

        {/* How it works */}
        <div className="space-y-3">
          <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{t("remind.how_to_use")}</p>
          <div className="grid gap-3">
            {getSteps(t as (k: string) => string).map((step, i) => (
              <div key={i} className="glass-panel border border-border rounded-2xl p-4 flex items-start gap-4">
                <div className={cn("w-9 h-9 rounded-xl flex items-center justify-center shrink-0", step.color)}>
                  <step.icon className="w-4.5 h-4.5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-bold text-muted-foreground/60 uppercase tracking-widest">{t("remind.step_n").replace("{{n}}", String(i + 1))}</span>
                  </div>
                  <p className="text-sm font-semibold">{step.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Features */}
        <div className="grid grid-cols-2 gap-3">
          {[
            { icon: RiMailLine,        title: t("remind.feature_email"),     desc: t("remind.feature_email_desc") },
            { icon: RiShieldCheckLine, title: t("remind.feature_lifecycle"), desc: t("remind.feature_lifecycle_desc") },
            { icon: RiTimeLine,        title: t("remind.feature_calendar"),  desc: t("remind.feature_calendar_desc") },
            { icon: RiGlobalLine,      title: t("remind.feature_multi"),     desc: t("remind.feature_multi_desc") },
          ].map(f => (
            <div key={f.title} className="glass-panel border border-border rounded-xl p-3.5 flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                <f.icon className="w-3.5 h-3.5 text-primary" />
              </div>
              <div>
                <p className="text-xs font-semibold">{f.title}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">{f.desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Existing subscriptions (if logged in) */}
        {status === "authenticated" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{t("remind.my_subs")}</p>
              <Link href="/dashboard" className="text-xs text-primary hover:underline">
                {t("remind.goto_dashboard_arrow")}
              </Link>
            </div>

            {!(session?.user as any)?.subscriptionAccess && (
              <div className="flex flex-col items-center text-center py-8 space-y-3">
                <div className="w-12 h-12 rounded-2xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200/60 dark:border-amber-700/40 flex items-center justify-center">
                  <RiLockLine className="w-5 h-5 text-amber-500" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-bold">{t("remind.need_invite")}</p>
                  <p className="text-xs text-muted-foreground leading-relaxed max-w-[200px] mx-auto">
                    {t("remind.need_invite_desc")}
                  </p>
                </div>
              </div>
            )}

            {(session?.user as any)?.subscriptionAccess && (
              <>
                {/* Stats row */}
                {!loadingSubs && subscriptions.length > 0 && (
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { label: t("remind.stat_active"),          value: activeSubs.length,   color: "text-primary" },
                      { label: t("remind.stat_expiring"),        value: expiringSoon.length, color: expiringSoon.length > 0 ? "text-orange-500" : "text-muted-foreground" },
                      { label: t("remind.stat_reminders_sent"),  value: totalSent,           color: "text-muted-foreground" },
                    ].map(stat => (
                      <div key={stat.label} className="glass-panel border border-border rounded-xl p-3 text-center">
                        <p className={cn("text-xl font-bold", stat.color)}>{stat.value}</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{stat.label}</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Filter tabs */}
                {!loadingSubs && subscriptions.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap">
                    {filterTabs.map(tab => (
                      <button
                        key={tab.key}
                        onClick={() => setFilter(tab.key)}
                        className={cn(
                          "inline-flex items-center gap-1 px-3 py-1.5 rounded-full text-xs font-semibold transition-colors",
                          filter === tab.key
                            ? "bg-primary text-primary-foreground"
                            : "bg-muted/60 text-muted-foreground hover:bg-muted hover:text-foreground"
                        )}
                      >
                        {tab.label}
                        {tab.count !== undefined && (
                          <span className={cn(
                            "text-[10px] px-1 rounded-full",
                            filter === tab.key ? "bg-white/20 text-white" : "bg-muted text-muted-foreground"
                          )}>
                            {tab.count}
                          </span>
                        )}
                      </button>
                    ))}
                  </div>
                )}

                {loadingSubs ? (
                  <div className="flex justify-center py-6">
                    <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
                  </div>
                ) : filteredSubs.length === 0 ? (
                  <div className="glass-panel border border-dashed border-border rounded-2xl p-8 text-center space-y-2">
                    <RiCalendarLine className="w-8 h-8 text-muted-foreground/30 mx-auto" />
                    <p className="text-sm text-muted-foreground">
                      {filter === "all"      && t("remind.empty_all")}
                      {filter === "expiring" && t("remind.empty_expiring")}
                      {filter === "expired"  && t("remind.empty_expired")}
                      {filter === "inactive" && t("remind.empty_inactive")}
                    </p>
                    {filter === "all" && subscriptions.length === 0 && (
                      <p className="text-xs text-muted-foreground/60">{t("remind.empty_hint")}</p>
                    )}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {filteredSubs.map(sub => {
                      const daysLeft = sub.days_to_expiry ?? getDaysLeft(sub.expiration_date);
                      const isExpired = daysLeft !== null && daysLeft < 0;
                      const isUrgent  = daysLeft !== null && daysLeft >= 0 && daysLeft <= 7;
                      const isWarn    = daysLeft !== null && daysLeft >= 0 && daysLeft <= 30;
                      const isInactive = !sub.active;

                      return (
                        <div
                          key={sub.id}
                          className={cn(
                            "glass-panel border rounded-2xl p-4 space-y-2.5",
                            isUrgent  ? "border-red-200 dark:border-red-800/50 bg-red-50/30 dark:bg-red-950/10" :
                            isExpired ? "border-orange-200 dark:border-orange-800/50 bg-orange-50/20 dark:bg-orange-950/10" :
                            isInactive ? "border-border/50 opacity-60" :
                                         "border-border"
                          )}
                        >
                          {/* Row 1: icon + domain + phase + actions */}
                          <div className="flex items-center gap-3">
                            <div className={cn(
                              "w-8 h-8 rounded-lg flex items-center justify-center shrink-0",
                              isUrgent   ? "bg-red-100 dark:bg-red-950/40" :
                              isExpired  ? "bg-orange-100 dark:bg-orange-950/40" :
                              isInactive ? "bg-muted/40" :
                                           "bg-primary/10"
                            )}>
                              {isUrgent
                                ? <RiAlertLine className="w-4 h-4 text-red-600 dark:text-red-400" />
                                : isExpired
                                  ? <RiAlertLine className="w-4 h-4 text-orange-500" />
                                  : <RiGlobalLine className={cn("w-4 h-4", isInactive ? "text-muted-foreground/50" : "text-primary")} />
                              }
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <p className={cn("text-sm font-semibold font-mono truncate", isInactive && "text-muted-foreground")}>
                                  {sub.domain}
                                </p>
                                <PhaseChip phase={sub.phase} />
                                {isInactive && (
                                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground">{t("remind.cancelled_badge")}</span>
                                )}
                              </div>
                              <p className={cn(
                                "text-[11px] mt-0.5",
                                isUrgent  ? "text-red-600 dark:text-red-400 font-semibold" :
                                isExpired ? "text-orange-600 dark:text-orange-400 font-semibold" :
                                isWarn    ? "text-amber-600 dark:text-amber-400" :
                                            "text-muted-foreground"
                              )}>
                                {sub.expiration_date
                                  ? daysLeft !== null
                                    ? daysLeft >= 0
                                      ? t("remind.days_to_expire").replace("{{n}}", String(daysLeft)).replace("{{date}}", fmt(new Date(sub.expiration_date), locale))
                                      : t("remind.expired_at").replace("{{date}}", fmt(new Date(sub.expiration_date), locale))
                                    : fmt(new Date(sub.expiration_date), locale)
                                  : t("remind.no_expiry")}
                              </p>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              <Link href={`/${sub.domain}`} className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground" title={t("remind.view_whois")}>
                                <RiExternalLinkLine className="w-3.5 h-3.5" />
                              </Link>
                              {isInactive ? (
                                <button
                                  onClick={() => reactivateSub(sub.id, sub.domain)}
                                  disabled={reactivating === sub.id}
                                  title={t("remind.resubscribe_hint")}
                                  className="p-1.5 rounded-lg hover:bg-primary/10 text-muted-foreground hover:text-primary transition-colors"
                                >
                                  {reactivating === sub.id
                                    ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                                    : <RiRefreshLine className="w-3.5 h-3.5" />
                                  }
                                </button>
                              ) : (
                                <button
                                  onClick={() => cancelSub(sub.id)}
                                  disabled={cancelling === sub.id}
                                  title={t("remind.unsubscribe_hint")}
                                  className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors"
                                >
                                  {cancelling === sub.id
                                    ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                                    : <RiDeleteBinLine className="w-3.5 h-3.5" />
                                  }
                                </button>
                              )}
                            </div>
                          </div>

                          {/* Urgency progress bar */}
                          {sub.active && <UrgencyBar daysLeft={daysLeft} phase={sub.phase} />}

                          {/* Row 2: meta chips */}
                          {sub.active && (
                            <div className="flex items-center gap-2 flex-wrap">
                              {sub.next_reminder_at && sub.next_reminder_days !== null && (
                                <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground bg-muted/60 rounded-full px-2 py-0.5">
                                  <RiBellLine className="w-2.5 h-2.5" />
                                  {t("remind.next_reminder").replace("{{n}}", String(sub.next_reminder_days)).replace("{{date}}", fmtShort(new Date(sub.next_reminder_at), locale))}
                                </span>
                              )}
                              {sub.last_reminded_at && (
                                <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground bg-muted/60 rounded-full px-2 py-0.5">
                                  <RiCheckLine className="w-2.5 h-2.5" />
                                  {t("remind.last_reminder").replace("{{date}}", fmtShort(new Date(sub.last_reminded_at), locale))}
                                </span>
                              )}
                              {sub.sent_keys.length > 0 && (
                                <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground bg-muted/60 rounded-full px-2 py-0.5">
                                  <RiMailLine className="w-2.5 h-2.5" />
                                  {t("remind.sent_count").replace("{{n}}", String(sub.sent_keys.length))}
                                </span>
                              )}
                              {sub.phase && sub.phase !== "active" && sub.drop_date && (
                                <span className="inline-flex items-center gap-1 text-[10px] text-orange-600 dark:text-orange-400 bg-orange-100/60 dark:bg-orange-950/30 rounded-full px-2 py-0.5">
                                  <RiInformationLine className="w-2.5 h-2.5" />
                                  {t("remind.drop_date").replace("{{date}}", fmt(new Date(sub.drop_date), locale))}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Login prompt */}
        {status === "unauthenticated" && (
          <div className="glass-panel border border-primary/20 rounded-2xl p-6 text-center space-y-3">
            <RiShieldCheckLine className="w-8 h-8 text-primary/50 mx-auto" />
            <div>
              <p className="text-sm font-semibold">{t("remind.login_manage_title")}</p>
              <p className="text-xs text-muted-foreground mt-1">{t("remind.login_manage_desc")}</p>
            </div>
            <div className="flex gap-2 justify-center">
              <Link href="/login?callbackUrl=%2Fremind">
                <Button size="sm" className="rounded-xl h-9 gap-1.5 text-xs">
                  {t("remind.login_btn")}
                </Button>
              </Link>
              <Link href="/register?callbackUrl=%2Fremind">
                <Button size="sm" variant="outline" className="rounded-xl h-9 gap-1.5 text-xs">
                  {t("remind.register_btn")}
                </Button>
              </Link>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
