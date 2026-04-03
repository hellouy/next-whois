import React from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiCalendarLine, RiAlertLine, RiExternalLinkLine,
  RiDeleteBinLine, RiEdit2Line, RiFireLine, RiTimeLine, RiTimerLine,
  RiCheckLine, RiSearchLine, RiCloseLine, RiGlobalLine, RiShieldCheckLine,
  RiDownloadLine, RiBellLine, RiMailLine, RiInformationLine, RiVipCrownLine,
  RiKeyLine, RiBankCardLine,
} from "@remixicon/react";
import type { Subscription, DashboardUser, TFunction } from "./types";
import { PHASE_LABEL, fmt, daysUntilExpiry } from "./types";
import type { TranslationKey } from "@/lib/i18n";

export type SubscriptionsTabProps = {
  subscriptionAccessDB: boolean | null;
  subscriptions: Subscription[];
  filteredSubscriptions: Subscription[];
  loadingData: boolean;
  dashError: boolean;
  subSearch: string;
  subFilter: "all" | "expiring" | "urgent" | "expired";
  subscriptionExpiresAt: string | null;
  activeSubs: Subscription[];
  expiringSoon: Subscription[];
  urgentSubs: Subscription[];
  postExpirySubs: Subscription[];
  cancelling: string | null;
  inviteCodeInput: string;
  applyingCode: boolean;
  paymentEnabled: boolean;
  user: DashboardUser;
  locale: string;
  t: TFunction;
  setSubSearch: (v: string) => void;
  setSubFilter: (v: "all" | "expiring" | "urgent" | "expired") => void;
  onShowSubscribeGuide: () => void;
  onExportCSV: () => void;
  onCancelSubscription: (id: string) => void;
  onEditSubscription: (sub: Subscription) => void;
  onApplyInviteCode: (e: React.FormEvent) => void;
  setInviteCodeInput: (v: string) => void;
  onRetryLoad: () => void;
};

export function SubscriptionsTab({
  subscriptionAccessDB, subscriptions, filteredSubscriptions, loadingData, dashError,
  subSearch, subFilter, subscriptionExpiresAt,
  activeSubs, expiringSoon, urgentSubs, postExpirySubs,
  cancelling, inviteCodeInput, applyingCode, paymentEnabled, user, locale, t,
  setSubSearch, setSubFilter, onShowSubscribeGuide, onExportCSV,
  onCancelSubscription, onEditSubscription, onApplyInviteCode, setInviteCodeInput,
  onRetryLoad,
}: SubscriptionsTabProps) {
  return (
    <motion.div key="subscriptions" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }} className="space-y-3">
      {!(subscriptionAccessDB ?? user.subscriptionAccess) && (
        <div className="space-y-5 py-4">
          <div className="flex flex-col items-center text-center space-y-3">
            <div className="w-14 h-14 rounded-2xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200/60 dark:border-amber-700/40 flex items-center justify-center">
              <RiBankCardLine className="w-6 h-6 text-amber-500" />
            </div>
            <div className="space-y-1">
              <p className="text-sm font-bold">{t("dashboard.needs_invite")}</p>
              <p className="text-xs text-muted-foreground leading-relaxed max-w-[220px] mx-auto">
                {t("dashboard.needs_invite_desc")}
              </p>
            </div>
          </div>
          {paymentEnabled && (
            <Link href="/payment/checkout">
              <Button className="w-full h-9 rounded-xl gap-1.5 text-xs bg-violet-600 hover:bg-violet-700 text-white">
                <RiBankCardLine className="w-3.5 h-3.5" />{t("dashboard.buy_plan_unlock")}
              </Button>
            </Link>
          )}
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground/50 justify-center select-none">
            <span>{t("dashboard.or_invite_code")}</span>
          </div>
          <form onSubmit={onApplyInviteCode} className="space-y-2">
            <div className="relative">
              <RiKeyLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/50" />
              <input
                type="text"
                placeholder={t("dashboard.invite_code_placeholder")}
                value={inviteCodeInput}
                onChange={e => setInviteCodeInput(e.target.value.toUpperCase())}
                disabled={applyingCode}
                maxLength={24}
                autoComplete="off"
                className="w-full h-10 pl-9 pr-3 rounded-xl border border-border bg-muted/30 text-xs font-mono font-semibold tracking-wider focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition disabled:opacity-50"
              />
            </div>
            <Button
              type="submit"
              disabled={applyingCode || !inviteCodeInput.trim()}
              size="sm"
              className="w-full h-9 rounded-xl gap-1.5 text-xs"
            >
              {applyingCode
                ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.verifying")}</>
                : <><RiKeyLine className="w-3.5 h-3.5" />{t("dashboard.verify_unlock")}</>
              }
            </Button>
          </form>
        </div>
      )}
      {(subscriptionAccessDB ?? user.subscriptionAccess) && <>
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{t("dashboard.sub_section_title")}</p>
        <div className="flex items-center gap-2">
          {activeSubs.length > 0 && (
            <button
              onClick={onExportCSV}
              className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1 px-2 py-1 rounded-lg hover:bg-muted transition-colors"
            >
              <RiDownloadLine className="w-3 h-3" />{t("dashboard.export_csv")}
            </button>
          )}
          <button
            onClick={onShowSubscribeGuide}
            className="text-[11px] text-primary hover:underline flex items-center gap-1"
          >
            <RiCalendarLine className="w-3 h-3" />{t("dashboard.new_sub")}
          </button>
        </div>
      </div>

      {/* Subscription search */}
      {subscriptions.length > 4 && (
        <div className="relative">
          <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
          <input
            type="text"
            value={subSearch}
            onChange={e => setSubSearch(e.target.value)}
            placeholder={t("dashboard.sub_search_placeholder")}
            className="w-full h-9 pl-9 pr-3 rounded-xl border border-border bg-muted/30 text-xs focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition"
          />
          {subSearch && (
            <button onClick={() => setSubSearch("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground">
              <RiCloseLine className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}

      {/* Membership expiry */}
      {subscriptionExpiresAt && (
        <div className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-violet-50 dark:bg-violet-950/20 border border-violet-200/50 dark:border-violet-700/30 text-[11px] text-violet-700 dark:text-violet-400">
          <RiVipCrownLine className="w-3 h-3 shrink-0" />
          <span>{t("dashboard.member_until")} <span className="font-semibold font-mono">{new Date(subscriptionExpiresAt).toLocaleDateString()}</span></span>
        </div>
      )}

      {/* Filter chips */}
      {activeSubs.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          <button type="button" onClick={() => setSubFilter("all")}
            className={cn(
              "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-colors",
              subFilter === "all"
                ? "bg-emerald-100 dark:bg-emerald-900/50 text-emerald-800 dark:text-emerald-300 border-emerald-400/60"
                : "bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 border-emerald-200/50 dark:border-emerald-700/30 hover:bg-emerald-100 dark:hover:bg-emerald-900/40"
            )}>
            <RiCheckLine className="w-2.5 h-2.5" />{activeSubs.length} {t("dashboard.chip_active")}
          </button>
          {expiringSoon.length > 0 && (
            <button type="button" onClick={() => setSubFilter(subFilter === "expiring" ? "all" : "expiring")}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-colors",
                subFilter === "expiring"
                  ? "bg-amber-100 dark:bg-amber-900/50 text-amber-800 dark:text-amber-300 border-amber-400/60"
                  : "bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 border-amber-200/50 dark:border-amber-700/30 hover:bg-amber-100 dark:hover:bg-amber-900/40"
              )}>
              <RiTimerLine className="w-2.5 h-2.5" />{expiringSoon.length} {t("dashboard.chip_expiring")}
            </button>
          )}
          {urgentSubs.length > 0 && (
            <button type="button" onClick={() => setSubFilter(subFilter === "urgent" ? "all" : "urgent")}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-colors",
                subFilter === "urgent"
                  ? "bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300 border-red-400/60"
                  : "bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-400 border-red-200/50 dark:border-red-700/30 hover:bg-red-100 dark:hover:bg-red-900/40"
              )}>
              <RiFireLine className="w-2.5 h-2.5" />{urgentSubs.length} {t("dashboard.chip_urgent")}
            </button>
          )}
          {postExpirySubs.length > 0 && (
            <button type="button" onClick={() => setSubFilter(subFilter === "expired" ? "all" : "expired")}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-colors",
                subFilter === "expired"
                  ? "bg-orange-100 dark:bg-orange-900/50 text-orange-800 dark:text-orange-300 border-orange-400/60"
                  : "bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400 border-orange-200/50 dark:border-orange-700/30 hover:bg-orange-100 dark:hover:bg-orange-900/40"
              )}>
              <RiAlertLine className="w-2.5 h-2.5" />{postExpirySubs.length} {t("dashboard.chip_expired")}
            </button>
          )}
        </div>
      )}

      {/* Urgent alert banner */}
      {urgentSubs.length > 0 && (
        <div className="flex items-start gap-2.5 px-3.5 py-2.5 rounded-xl bg-red-50 dark:bg-red-950/30 border border-red-200/60 dark:border-red-800/40">
          <RiFireLine className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs text-red-700 dark:text-red-300 font-semibold">
              {t("dashboard.urgent_domains", { count: urgentSubs.length })}
            </p>
            <p className="text-[11px] text-red-600/80 dark:text-red-400/80 mt-0.5">
              {urgentSubs.map(s => s.domain).join(", ")}
            </p>
          </div>
        </div>
      )}

      {/* Post-expiry alert */}
      {postExpirySubs.length > 0 && urgentSubs.length === 0 && (
        <div className="flex items-start gap-2.5 px-3.5 py-2.5 rounded-xl bg-orange-50 dark:bg-orange-950/30 border border-orange-200/60 dark:border-orange-800/40">
          <RiAlertLine className="w-4 h-4 text-orange-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs text-orange-700 dark:text-orange-300 font-semibold">
              {t("dashboard.post_expiry_domains", { count: postExpirySubs.length })}
            </p>
            <p className="text-[11px] text-orange-600/80 dark:text-orange-400/80 mt-0.5">
              {postExpirySubs.map(s => s.domain).join(", ")}
            </p>
          </div>
        </div>
      )}

      {loadingData ? (
        <div className="flex justify-center py-8"><RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" /></div>
      ) : dashError ? (
        <div className="flex flex-col items-center py-10 gap-3 text-center">
          <RiAlertLine className="w-7 h-7 text-destructive/60" />
          <p className="text-sm text-muted-foreground">{t("dashboard.load_failed")}</p>
          <Button size="sm" variant="outline" className="rounded-xl text-xs gap-1.5" onClick={onRetryLoad}>{t("dashboard.reload")}</Button>
        </div>
      ) : subscriptions.length === 0 ? (
        <div className="text-center py-12 space-y-4">
          <div className="w-14 h-14 rounded-2xl bg-primary/8 border border-dashed border-border flex items-center justify-center mx-auto">
            <RiCalendarLine className="w-7 h-7 text-muted-foreground/40" />
          </div>
          <div className="space-y-1.5">
            <p className="text-sm font-semibold">{t("dashboard.no_subs")}</p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              {t("dashboard.no_subs_desc")}
            </p>
          </div>
          <div className="flex flex-col gap-2 items-center">
            <Button variant="default" size="sm" className="rounded-xl text-xs gap-1.5" onClick={onShowSubscribeGuide}>
              <RiBellLine className="w-3.5 h-3.5" />{t("dashboard.how_to_sub")}
            </Button>
            <Link href="/remind" className="text-[11px] text-muted-foreground hover:text-primary underline underline-offset-2">
              {t("dashboard.go_sub_mgmt")}
            </Link>
          </div>
        </div>
      ) : filteredSubscriptions.length === 0 ? (
        <div className="flex flex-col items-center py-8 gap-2 text-center">
          <RiSearchLine className="w-6 h-6 text-muted-foreground/40" />
          <p className="text-xs text-muted-foreground">{t("dashboard.no_filter_results")}</p>
          <button type="button" onClick={() => setSubFilter("all")} className="text-[11px] text-primary hover:underline">{t("dashboard.clear_filter")}</button>
        </div>
      ) : filteredSubscriptions.map(sub => {
        const phase = sub.phase;
        const phaseInfo = phase ? PHASE_LABEL[phase] : null;
        const days = daysUntilExpiry(sub);
        const daysDropping = sub.days_to_drop;
        const isDropSoon = sub.active && daysDropping !== null && daysDropping >= 0 && daysDropping <= 7 && phase !== "active";
        const isUrgent = sub.active && ((days !== null && days >= 0 && days <= 7) || isDropSoon);
        const isWarn = sub.active && days !== null && days >= 0 && days <= 30 && !isUrgent;
        const isPostExpiry = sub.active && phase && phase !== "active";

        const barPct = (days !== null && days > 0 && phase === "active")
          ? Math.min(100, Math.round((days / 365) * 100))
          : 0;
        const barColor = isUrgent ? "bg-red-500" : isWarn ? "bg-amber-500" : days !== null && days <= 90 ? "bg-yellow-500" : "bg-emerald-500";

        const nextReminderDate = sub.next_reminder_at ? new Date(sub.next_reminder_at) : null;
        const lastReminderDate = sub.last_reminded_at ? new Date(sub.last_reminded_at) : null;
        const daysSinceLastReminder = lastReminderDate
          ? Math.floor((Date.now() - lastReminderDate.getTime()) / 86400000)
          : null;
        const nextReminderIsUpcoming = nextReminderDate && nextReminderDate > new Date();

        const phaseGuidance: Record<string, string> = {
          grace: t("dashboard.phase_guidance_grace"),
          redemption: t("dashboard.phase_guidance_redemption"),
          pendingDelete: t("dashboard.phase_guidance_pendingDelete"),
          dropped: t("dashboard.phase_guidance_dropped"),
        };

        return (
          <div key={sub.id} className={cn(
            "glass-panel border rounded-2xl p-4 space-y-3 transition-all",
            !sub.active ? "border-border/40 opacity-60" :
            isUrgent ? "border-red-300/60 dark:border-red-700/50" :
            isPostExpiry ? "border-orange-300/60 dark:border-orange-700/50" :
            isWarn ? "border-amber-300/60 dark:border-amber-700/50" : "border-border"
          )}>
            <div className="flex items-start gap-3">
              <div className={cn(
                "w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5",
                isUrgent ? "bg-red-100 dark:bg-red-950/40" :
                isPostExpiry ? "bg-orange-100 dark:bg-orange-950/40" :
                isWarn ? "bg-amber-100 dark:bg-amber-950/40" : "bg-primary/10"
              )}>
                {isUrgent ? <RiFireLine className="w-4 h-4 text-red-500" /> :
                 isPostExpiry ? <RiAlertLine className="w-4 h-4 text-orange-500" /> :
                 isWarn ? <RiTimerLine className="w-4 h-4 text-amber-500" /> :
                 <RiGlobalLine className="w-4 h-4 text-primary" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-sm font-semibold truncate">{sub.domain}</p>
                  {!sub.active && <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{t("dashboard.cancelled")}</span>}
                  {isUrgent && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400 font-semibold border border-red-300/50">
                      {days === 0 ? t("dashboard.expires_today") : t("dashboard.expires_in_days", { n: days ?? 0 })}
                    </span>
                  )}
                  {isWarn && !isUrgent && !isPostExpiry && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 font-semibold border border-amber-300/50">
                      {t("dashboard.expires_in_days", { n: days ?? 0 })}
                    </span>
                  )}
                  {isDropSoon && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-purple-100 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400 font-semibold border border-purple-300/50">
                      {daysDropping === 0 ? t("dashboard.drop_today") : t("dashboard.drop_in_days", { n: daysDropping })}
                    </span>
                  )}
                  {phaseInfo && phase !== "active" && (
                    <span className={cn("text-[10px] font-semibold px-1.5 py-0.5 rounded-md border", phaseInfo.color,
                      phase === "grace" ? "bg-amber-50 dark:bg-amber-950/30 border-amber-300/50" :
                      phase === "redemption" ? "bg-orange-50 dark:bg-orange-950/30 border-orange-300/50" :
                      phase === "pendingDelete" ? "bg-purple-50 dark:bg-purple-950/30 border-purple-300/50" :
                      "bg-muted border-border/50"
                    )}>{t(("dashboard.phase_" + phase) as TranslationKey)}</span>
                  )}
                </div>
                <p className="text-[11px] text-muted-foreground mt-0.5 flex items-center gap-1">
                  <RiTimeLine className="w-3 h-3 shrink-0" />
                  {sub.expiration_date
                    ? t("dashboard.expires_on", { date: fmt(new Date(sub.expiration_date), locale) })
                    : t("dashboard.expiry_not_set")}
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  onClick={() => onEditSubscription(sub)}
                  title={t("dashboard.edit_expiry_title")}
                  className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                  <RiEdit2Line className="w-3.5 h-3.5" />
                </button>
                <Link href={`/${sub.domain}`} className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                  <RiExternalLinkLine className="w-3.5 h-3.5" />
                </Link>
                {sub.active && (
                  <button onClick={() => onCancelSubscription(sub.id)} disabled={cancelling === sub.id}
                    className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors">
                    {cancelling === sub.id
                      ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                      : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                  </button>
                )}
              </div>
            </div>

            {/* Lifecycle progress bar */}
            {sub.active && sub.expiration_date && phase === "active" && (
              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] text-muted-foreground">{t("dashboard.remaining_validity")}</span>
                  <span className="text-[10px] font-semibold text-muted-foreground tabular-nums">
                    {days !== null && days > 0 ? t("dashboard.n_days", { n: days }) : days === 0 ? t("dashboard.expires_today") : t("dashboard.expired")}
                  </span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
                  <div className={cn("h-full rounded-full transition-all", barColor)} style={{ width: `${barPct}%` }} />
                </div>
              </div>
            )}

            {/* Phase guidance */}
            {isPostExpiry && phase && phaseGuidance[phase] && (
              <div className="px-3 py-2 rounded-lg bg-orange-50 dark:bg-orange-950/20 border border-orange-200/50 dark:border-orange-700/30">
                <p className="text-[11px] text-orange-700 dark:text-orange-300 leading-relaxed">{phaseGuidance[phase]}</p>
              </div>
            )}

            {/* WHOIS info */}
            {(sub.registrar || sub.creation_date || sub.nameservers?.length > 0) && (
              <div className="pt-2 border-t border-border/40 space-y-1.5">
                {(sub.registrar || sub.creation_date) && (
                  <div className="flex items-center gap-3 flex-wrap">
                    {sub.registrar && (
                      <div className="flex items-center gap-1 min-w-0">
                        <RiInformationLine className="w-3 h-3 text-muted-foreground shrink-0" />
                        <span className="text-[10px] text-muted-foreground truncate max-w-[160px]" title={sub.registrar}>{sub.registrar}</span>
                      </div>
                    )}
                    {sub.creation_date && (
                      <div className="flex items-center gap-1 shrink-0">
                        <RiTimeLine className="w-3 h-3 text-muted-foreground" />
                        <span className="text-[10px] text-muted-foreground">{t("dashboard.registered_on")} {fmt(new Date(sub.creation_date), locale)}</span>
                      </div>
                    )}
                  </div>
                )}
                {sub.nameservers?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {sub.nameservers.slice(0, 4).map((ns, i) => (
                      <span key={i} className="text-[9px] font-mono bg-muted/50 rounded-md px-1.5 py-0.5 text-muted-foreground lowercase">{ns}</span>
                    ))}
                  </div>
                )}
                {sub.whois_synced_at && (
                  <div className="flex items-center gap-1">
                    <RiShieldCheckLine className="w-2.5 h-2.5 text-emerald-500" />
                    <span className="text-[9px] text-emerald-600 dark:text-emerald-400">{t("dashboard.whois_synced")} {fmt(new Date(sub.whois_synced_at), locale)}</span>
                  </div>
                )}
              </div>
            )}

            {/* Reminder info */}
            {sub.active && (
              <div className="pt-2 border-t border-border/40 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <RiCalendarLine className="w-3 h-3 text-muted-foreground shrink-0" />
                    <span className="text-[11px] text-muted-foreground truncate">
                      {nextReminderIsUpcoming
                        ? <>{t("dashboard.next_reminder")} <span className="font-medium text-foreground">{fmt(nextReminderDate!, locale)}</span></>
                        : phase === "dropped"
                          ? t("dashboard.no_pending_reminder")
                          : t("dashboard.no_reminder")
                      }
                    </span>
                  </div>
                  {sub.next_reminder_days !== null && sub.next_reminder_days !== undefined && nextReminderIsUpcoming && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/8 text-primary font-semibold shrink-0 tabular-nums">
                      {t("dashboard.advance_days", { n: sub.next_reminder_days })}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  <RiMailLine className="w-3 h-3 text-muted-foreground shrink-0" />
                  <span className="text-[11px] text-muted-foreground">
                    {daysSinceLastReminder !== null
                      ? daysSinceLastReminder === 0
                        ? <>{t("dashboard.last_reminded_today")}</>
                        : <>{t("dashboard.last_reminded_days_ago", { n: daysSinceLastReminder })}</>
                      : t("dashboard.never_reminded")}
                  </span>
                </div>
                <div className="flex items-start gap-2 flex-wrap">
                  <span className="text-[10px] text-muted-foreground mt-0.5 shrink-0">{t("dashboard.reminder_threshold")}</span>
                  <div className="flex flex-wrap gap-1">
                    {(sub.thresholds?.length ? sub.thresholds : [60, 30, 1]).map(d => (
                      <span key={d} className="text-[9px] px-1.5 py-0.5 rounded-full border bg-sky-50 dark:bg-sky-950/20 text-sky-700 dark:text-sky-400 border-sky-200 dark:border-sky-800 font-semibold tabular-nums">
                        {t("dashboard.n_days_abbr", { days: d })}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Lifecycle dates */}
            {sub.drop_date && sub.expiration_date && (
              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border/40">
                <div className="text-center">
                  <p className="text-[10px] text-muted-foreground mb-0.5">{t("dashboard.grace_end")}</p>
                  <p className={cn("text-[11px] font-semibold tabular-nums", phase === "grace" ? "text-amber-600 dark:text-amber-400" : "text-foreground")}>
                    {sub.grace_end ? fmt(new Date(sub.grace_end), locale) : "—"}
                  </p>
                </div>
                <div className="text-center">
                  <p className="text-[10px] text-muted-foreground mb-0.5">{t("dashboard.redemption_end")}</p>
                  <p className={cn("text-[11px] font-semibold tabular-nums", phase === "redemption" ? "text-orange-600 dark:text-orange-400" : "text-foreground")}>
                    {sub.redemption_end ? fmt(new Date(sub.redemption_end), locale) : "—"}
                  </p>
                </div>
                <div className="text-center">
                  <p className="text-[10px] text-muted-foreground mb-0.5">{t("dashboard.estimated_drop")}</p>
                  <p className={cn("text-[11px] font-semibold tabular-nums", phase === "pendingDelete" || isDropSoon ? "text-purple-600 dark:text-purple-400" : "text-foreground")}>
                    {fmt(new Date(sub.drop_date), locale)}
                  </p>
                </div>
              </div>
            )}
          </div>
        );
      })}
      </>}
    </motion.div>
  );
}
