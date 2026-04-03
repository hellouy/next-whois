import React from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  RiTimerLine,
  RiCalendarEventLine,
  RiShieldCheckLine,
  RiLoader4Line,
  RiCheckLine,
  RiCheckboxCircleLine,
  RiCheckboxBlankCircleLine,
  RiAlertLine,
  RiFlagLine,
  RiInformationLine,
  RiTimeLine,
  RiExchangeDollarFill,
  RiDeleteBin2Line,
  RiShoppingCartLine,
} from "@remixicon/react";
import { AnimatePresence, motion } from "framer-motion";
import { computeLifecycle } from "@/lib/lifecycle";
import { DomainLifecycleSection } from "@/components/query/DomainLifecycleSection";
import { toast } from "sonner";
import { RegistrationStatusType } from "@/lib/domain-status-types";

export type { RegistrationStatusType };

const ALL_REMINDER_THRESHOLDS = [60, 30, 10, 5, 1];
const DEFAULT_REMINDER_THRESHOLDS = [60, 30, 1];

type PhaseAlerts = {
  grace: boolean;
  redemption: boolean;
  pendingDelete: boolean;
  dropSoon: boolean;
  dropped: boolean;
};

type PhaseChip = {
  key: keyof PhaseAlerts;
  label: string;
  icon: React.ReactNode;
  activeCls: string;
  inactiveCls: string;
  always?: boolean;
};

interface DomainReminderDialogProps {
  domain: string;
  expirationDate: string | null | undefined;
  remainingDays: number | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  isZh: boolean;
  userEmail?: string;
  registerPriceFmt?: string;
  renewPriceFmt?: string;
  isPremium?: boolean;
  eppStatuses?: string[];
  regStatusType?: RegistrationStatusType;
}

export function DomainReminderDialog({
  domain,
  expirationDate,
  remainingDays,
  open,
  onOpenChange,
  isZh,
  userEmail,
  registerPriceFmt,
  renewPriceFmt,
  isPremium,
  eppStatuses,
  regStatusType,
}: DomainReminderDialogProps) {
  const hasExpiry = !!(expirationDate && expirationDate !== "Unknown");
  const [email, setEmail] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);
  const [selectedThresholds, setSelectedThresholds] = React.useState<number[]>(DEFAULT_REMINDER_THRESHOLDS);

  const [lcFeedbackOpen, setLcFeedbackOpen] = React.useState(false);
  const [lcForm, setLcForm] = React.useState({ grace: "0", redemption: "0", pendingDelete: "0", sourceUrl: "", notes: "", email: "" });
  const [lcSubmitting, setLcSubmitting] = React.useState(false);
  const [lcDone, setLcDone] = React.useState(false);

  function toggleThreshold(d: number) {
    setSelectedThresholds(prev =>
      prev.includes(d) ? prev.filter(x => x !== d) : [...prev, d]
    );
  }

  React.useEffect(() => {
    if (open) { setEmail(userEmail || ""); setDone(false); setSelectedThresholds(DEFAULT_REMINDER_THRESHOLDS); }
  }, [open, userEmail]);

  const isRestricted = regStatusType === "prohibited" || regStatusType === "reserved";

  async function handleSubmit() {
    if (!email || !email.includes("@")) {
      toast.error(isZh ? "请输入有效邮箱" : "Please enter a valid email");
      return;
    }
    if (!isRestricted && selectedThresholds.length === 0) {
      toast.error(isZh ? "请至少选择一个到期前提醒时间" : "Please select at least one pre-expiry reminder");
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/remind/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domain, email, expirationDate, phaseAlerts,
          thresholds: isRestricted ? [] : selectedThresholds,
          regStatusType,
        }),
      });
      if (res.ok) {
        setDone(true);
      } else {
        toast.error(isZh ? "提交失败，请重试" : "Submission failed");
      }
    } catch {
      toast.error(isZh ? "网络错误" : "Network error");
    } finally {
      setSubmitting(false);
    }
  }

  const lc = React.useMemo(
    () => computeLifecycle(domain, expirationDate ?? null, eppStatuses),
    [domain, expirationDate, eppStatuses]
  );
  const tldUpper = domain.split(".").pop()?.toUpperCase() ?? "";
  const hasPricing = !!(registerPriceFmt || renewPriceFmt);

  React.useEffect(() => {
    if (lcFeedbackOpen && lc) {
      setLcForm({
        grace: String(lc.cfg.grace),
        redemption: String(lc.cfg.redemption),
        pendingDelete: String(lc.cfg.pendingDelete),
        sourceUrl: "",
        notes: "",
        email: userEmail || "",
      });
      setLcDone(false);
    }
  }, [lcFeedbackOpen, lc, userEmail]);

  async function handleLcFeedbackSubmit() {
    const sg = parseInt(lcForm.grace, 10);
    const sr = parseInt(lcForm.redemption, 10);
    const sp = parseInt(lcForm.pendingDelete, 10);
    if (isNaN(sg) || isNaN(sr) || isNaN(sp) || sg < 0 || sr < 0 || sp < 0) {
      toast.error(isZh ? "天数必须为非负整数" : "Days must be a non-negative integer");
      return;
    }
    if (lcForm.email && !lcForm.email.includes("@")) {
      toast.error(isZh ? "请输入有效邮箱" : "Please enter a valid email");
      return;
    }
    setLcSubmitting(true);
    try {
      const tld = domain.split(".").pop()?.toLowerCase() ?? "";
      const res = await fetch("/api/user/tld-lifecycle-feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tld,
          current_grace: lc?.cfg.grace ?? null,
          current_redemption: lc?.cfg.redemption ?? null,
          current_pending_delete: lc?.cfg.pendingDelete ?? null,
          suggested_grace: sg,
          suggested_redemption: sr,
          suggested_pending_delete: sp,
          source_url: lcForm.sourceUrl || null,
          notes: lcForm.notes || null,
          submitter_email: lcForm.email || null,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "提交失败");
      }
      setLcDone(true);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : (isZh ? "提交失败" : "Submission failed"));
    } finally {
      setLcSubmitting(false);
    }
  }

  const PHASE_UI = {
    active:        { label: isZh ? "正常有效" : "Active",        colorClass: "text-emerald-600 dark:text-emerald-400", bgClass: "bg-emerald-50/70 dark:bg-emerald-950/25", borderClass: "border-emerald-200/60 dark:border-emerald-800/40", dotClass: "bg-emerald-500" },
    grace:         { label: isZh ? "宽限期"   : "Grace Period",  colorClass: "text-amber-600 dark:text-amber-400",    bgClass: "bg-amber-50/70 dark:bg-amber-950/25",    borderClass: "border-amber-200/60 dark:border-amber-800/40",    dotClass: "bg-amber-500" },
    redemption:    { label: isZh ? "赎回期"   : "Redemption",    colorClass: "text-orange-600 dark:text-orange-400",  bgClass: "bg-orange-50/70 dark:bg-orange-950/25",  borderClass: "border-orange-200/60 dark:border-orange-800/40",  dotClass: "bg-orange-500" },
    pendingDelete: { label: isZh ? "待删除"   : "Pending Delete", colorClass: "text-red-600 dark:text-red-400",        bgClass: "bg-red-50/70 dark:bg-red-950/25",        borderClass: "border-red-200/60 dark:border-red-800/40",        dotClass: "bg-red-500" },
    dropped:       { label: isZh ? "已释放"   : "Available",     colorClass: "text-emerald-600 dark:text-emerald-400",        bgClass: "bg-emerald-50/70 dark:bg-emerald-950/25",        borderClass: "border-emerald-200/60 dark:border-emerald-800/40",        dotClass: "bg-emerald-400" },
  };

  const PHASE_ADVICE: Record<string, { zh: string; en: string }> = {
    active:        { zh: "域名状态正常，我们将在到期前自动发送提醒邮件。", en: "Domain is active. We'll alert you before expiry." },
    grace:         { zh: "域名已过期，仍处于宽限期内，可按正常价格续费，请尽快操作！", en: "Expired but renewable at normal price during grace — act now!" },
    redemption:    { zh: "已进入赎回期，续费费用大幅增加，请立即联系注册商赎回。", en: "In redemption. Recovery fees are much higher — contact your registrar." },
    pendingDelete: { zh: "即将被注册局删除，通常无法再续期，请提前做好准备。", en: "Pending deletion. Usually cannot be renewed anymore." },
    dropped:       { zh: "域名已被删除，即将或已可重新注册。", en: "Domain has been deleted and may be available for re-registration." },
  };

  void PHASE_ADVICE;

  const urgencyNum =
    remainingDays === null ? "text-muted-foreground" :
    remainingDays <= 0  ? "text-red-500 dark:text-red-400" :
    remainingDays <= 30 ? "text-orange-500 dark:text-orange-400" :
    remainingDays <= 90 ? "text-amber-500 dark:text-amber-400" :
    "text-emerald-500 dark:text-emerald-400";

  const phaseUI = lc ? PHASE_UI[lc.phase] : null;

  const [phaseAlerts, setPhaseAlerts] = React.useState<PhaseAlerts>({
    grace: true, redemption: true, pendingDelete: true, dropSoon: true, dropped: true,
  });
  function togglePhase(key: keyof PhaseAlerts) {
    setPhaseAlerts((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  const phaseChips: PhaseChip[] = lc ? [
    lc.cfg.grace > 0         && { key: "grace"       as const, label: isZh ? "进入宽限期"   : "Grace Period",    icon: <RiTimeLine className="w-2.5 h-2.5" />,            activeCls: "bg-amber-500/18 border-amber-400/60 text-amber-700 dark:text-amber-300",   inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    lc.cfg.redemption > 0    && { key: "redemption"  as const, label: isZh ? "进入赎回期"   : "Redemption",      icon: <RiExchangeDollarFill className="w-2.5 h-2.5" />,  activeCls: "bg-orange-500/18 border-orange-400/60 text-orange-700 dark:text-orange-300", inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    lc.cfg.pendingDelete > 0 && { key: "pendingDelete" as const, label: isZh ? "进入待删除期" : "Pending Delete",  icon: <RiDeleteBin2Line className="w-2.5 h-2.5" />,     activeCls: "bg-red-500/18 border-red-400/60 text-red-700 dark:text-red-300",          inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    (lc.cfg.pendingDelete > 0 || lc.cfg.redemption > 0 || lc.cfg.grace > 0) && { key: "dropSoon" as const, always: true, label: isZh ? "即将可注册" : "Drop Soon",       icon: <RiAlertLine className="w-2.5 h-2.5" />,           activeCls: "bg-foreground/10 border-foreground/25 text-foreground",                   inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
    (lc.cfg.pendingDelete > 0 || lc.cfg.redemption > 0 || lc.cfg.grace > 0) && { key: "dropped"  as const, always: true, label: isZh ? "域名可注册"  : "Available",      icon: <RiShoppingCartLine className="w-2.5 h-2.5" />,    activeCls: "bg-emerald-500/18 border-emerald-400/60 text-emerald-700 dark:text-emerald-300", inactiveCls: "bg-muted/30 border-border/50 text-muted-foreground/50" },
  ].filter(Boolean) as PhaseChip[] : [];

  return (<>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[420px] p-0 overflow-hidden gap-0">

        {/* ── Header ── */}
        <div className="px-5 pt-5 pb-4 border-b border-border/50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-muted border border-border/60 flex items-center justify-center shrink-0">
              <RiTimerLine className="w-[18px] h-[18px] text-foreground/70" />
            </div>
            <h2 className="text-sm font-bold text-foreground leading-none">
              {isZh ? "域名监控订阅" : "Domain Monitoring"}
            </h2>
          </div>
        </div>

        {/* ── Body ── */}
        <div className="px-5 pb-5 overflow-y-auto max-h-[72dvh]">

          {/* ── Domain name card — centered, above pricing ── */}
          <div className="flex flex-col items-center justify-center pt-4 pb-1 gap-1">
            <div className="px-4 py-2.5 rounded-xl border border-border/60 bg-muted/30 text-center min-w-0 max-w-full">
              <p className="text-[15px] font-mono font-bold text-foreground truncate tracking-tight">{domain}</p>
              {lc?.cfg.registry && (
                <p className="text-[10px] text-muted-foreground/55 mt-0.5 truncate">{lc.cfg.registry}</p>
              )}
            </div>
          </div>

          <AnimatePresence mode="wait" initial={false}>

            {/* ── Success ── */}
            {done ? (
              <motion.div
                key="done"
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.96 }}
                transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
                className="py-7 text-center space-y-4"
              >
                <div className="relative w-16 h-16 mx-auto">
                  <div className="absolute inset-0 rounded-full bg-emerald-500/15 animate-ping" style={{ animationDuration: "1.6s" }} />
                  <div className="relative w-16 h-16 bg-emerald-500/10 border-2 border-emerald-400/30 rounded-full flex items-center justify-center">
                    <RiCheckLine className="w-7 h-7 text-emerald-500" />
                  </div>
                </div>
                <div>
                  <p className="font-bold text-[15px] text-foreground">{isZh ? "订阅成功！" : "Subscribed!"}</p>
                  <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                    {isZh ? "将向" : "We'll notify"}{" "}
                    <strong className="text-foreground font-mono text-[11px]">{email}</strong>{" "}
                    {isZh ? "发送以下提醒" : "with the alerts below"}
                  </p>
                </div>
                <div className="text-left rounded-xl border border-border/60 bg-muted/15 p-3 space-y-2.5">
                  <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                    {isZh ? "已订阅的提醒类型" : "Subscribed alerts"}
                  </p>
                  {isRestricted ? (
                    <div className="flex items-center gap-1.5">
                      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-foreground/8 border border-foreground/20 text-foreground/80 text-[10px] font-semibold">
                        <RiCheckboxCircleLine className="w-2.5 h-2.5" />
                        {isZh ? "域名状态变化通知" : "Status change alert"}
                      </span>
                    </div>
                  ) : (
                    <>
                      <div>
                        <p className="text-[10px] text-foreground/60 font-semibold mb-1.5">{isZh ? "到期前提醒" : "Pre-expiry"}</p>
                        <div className="flex flex-wrap gap-1">
                          {[...selectedThresholds].sort((a, b) => b - a).map((d) => (
                            <span key={d} className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md bg-foreground/8 border border-foreground/20 text-foreground/80 text-[10px] font-semibold">
                              <RiTimerLine className="w-2.5 h-2.5" />{isZh ? `提前${d}天` : `${d}d`}
                            </span>
                          ))}
                        </div>
                      </div>
                      {phaseChips.filter((c) => phaseAlerts[c.key]).length > 0 && (
                        <div>
                          <p className="text-[10px] text-foreground/60 font-semibold mb-1.5">{isZh ? "阶段提醒" : "Phase alerts"}</p>
                          <div className="flex flex-wrap gap-1">
                            {phaseChips.filter((c) => phaseAlerts[c.key]).map((chip) => (
                              <span key={chip.key} className={cn("inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md border text-[10px] font-semibold", chip.activeCls)}>
                                <RiCheckboxCircleLine className="w-2.5 h-2.5" />{chip.label}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
                <p className="text-[10px] text-muted-foreground/55">{isZh ? "确认邮件已发送，请查收" : "Check your inbox for confirmation"}</p>
                <button
                  type="button"
                  onClick={() => setDone(false)}
                  className="text-xs text-muted-foreground/70 hover:text-foreground transition-colors underline-offset-2 hover:underline"
                >
                  {isZh ? "← 返回修改信息" : "← Edit subscription"}
                </button>
              </motion.div>

            ) : (
              /* ── Form ── */
              <motion.div
                key="form"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="space-y-3 pt-2"
              >
                {/* ── Prohibited / Reserved warning banner ─────────────── */}
                {(regStatusType === "prohibited" || regStatusType === "reserved") && (
                  <div className={cn(
                    "flex items-start gap-2.5 rounded-xl border px-3.5 py-3",
                    regStatusType === "prohibited"
                      ? "bg-red-50/60 dark:bg-red-950/20 border-red-300/50 dark:border-red-700/40"
                      : "bg-amber-50/60 dark:bg-amber-950/20 border-amber-300/50 dark:border-amber-700/40"
                  )}>
                    <RiInformationLine className={cn(
                      "w-4 h-4 mt-0.5 shrink-0",
                      regStatusType === "prohibited" ? "text-red-500" : "text-amber-500"
                    )} />
                    <div className="min-w-0">
                      <p className={cn(
                        "text-xs font-bold leading-snug",
                        regStatusType === "prohibited" ? "text-red-600 dark:text-red-400" : "text-amber-600 dark:text-amber-400"
                      )}>
                        {regStatusType === "prohibited"
                          ? (isZh ? "该域名被禁止注册" : "Registration Prohibited")
                          : (isZh ? "该域名为保留域名" : "Reserved Domain")}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {regStatusType === "prohibited"
                          ? (isZh
                              ? "该域名被注册局标记为禁止注册字符串，通常无法通过常规渠道注册。仍可订阅，当域名状态变化时会发送通知。"
                              : "This domain is marked as prohibited by the registry and cannot be registered through normal channels. You can still subscribe to receive status change notifications.")
                          : (isZh
                              ? "该域名目前为保留状态，不对公众开放注册。仍可订阅，如状态发生变化或域名开放注册时会收到通知。"
                              : "This domain is currently reserved and not available for public registration. You can still subscribe to receive notifications if the status changes.")}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Hold warning banner ───────────────────────────────── */}
                {regStatusType === "hold" && (
                  <div className="flex items-start gap-2.5 rounded-xl border px-3.5 py-3 bg-orange-50/60 dark:bg-orange-950/20 border-orange-300/50 dark:border-orange-700/40">
                    <RiInformationLine className="w-4 h-4 mt-0.5 shrink-0 text-orange-500" />
                    <div className="min-w-0">
                      <p className="text-xs font-bold leading-snug text-orange-600 dark:text-orange-400">
                        {isZh ? "该域名当前处于暂停状态" : "Domain On Hold"}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {isZh
                          ? "该域名已被注册局或注册商暂停（如违规、欠款或政府扣押），目前无法正常解析。仍可订阅到期提醒，以便跟踪续费或状态变化。"
                          : "This domain has been suspended by the registry or registrar (e.g. policy violation, non-payment, or seizure) and cannot currently resolve. You can still subscribe for expiry and status alerts."}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Dispute warning banner ────────────────────────────── */}
                {regStatusType === "dispute" && (
                  <div className="flex items-start gap-2.5 rounded-xl border px-3.5 py-3 bg-rose-50/60 dark:bg-rose-950/20 border-rose-300/50 dark:border-rose-700/40">
                    <RiInformationLine className="w-4 h-4 mt-0.5 shrink-0 text-rose-500" />
                    <div className="min-w-0">
                      <p className="text-xs font-bold leading-snug text-rose-600 dark:text-rose-400">
                        {isZh ? "该域名正处于争议程序中" : "Domain In Dispute"}
                      </p>
                      <p className="text-[11px] text-muted-foreground leading-snug mt-0.5">
                        {isZh
                          ? "该域名正处于 UDRP 或其他争议解决程序中，当前被锁定，等待仲裁结果。仍可订阅到期提醒，以便及时获知域名状态变化。"
                          : "This domain is currently locked in a UDRP or other dispute resolution proceeding. You can still subscribe for expiry and status alerts to stay informed of any outcome."}
                      </p>
                    </div>
                  </div>
                )}

                {/* ── Pricing + premium row ────────────────────────────── */}
                {hasPricing && (
                  <div className="grid grid-cols-3 gap-1.5 rounded-xl border border-border/50 bg-muted/15 overflow-hidden">
                    {/* Register price */}
                    <div className="flex flex-col items-center justify-center px-2 py-2.5 gap-0.5">
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "注册" : "Register"}
                      </p>
                      <p className={cn("text-[13px] font-black tabular-nums leading-none", isPremium ? "text-amber-500" : "text-foreground")}>
                        {registerPriceFmt ?? "—"}
                      </p>
                    </div>
                    {/* Renew price */}
                    <div className="flex flex-col items-center justify-center px-2 py-2.5 gap-0.5 border-x border-border/40">
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "续费" : "Renew"}
                      </p>
                      <p className={cn("text-[13px] font-black tabular-nums leading-none", isPremium ? "text-amber-500" : "text-foreground")}>
                        {renewPriceFmt ?? "—"}
                      </p>
                    </div>
                    {/* Premium badge */}
                    <div className={cn(
                      "flex flex-col items-center justify-center px-2 py-2.5 gap-0.5",
                      isPremium ? "bg-amber-500/8 dark:bg-amber-500/12" : ""
                    )}>
                      <p className="text-[9px] font-bold text-muted-foreground/70 uppercase tracking-widest">
                        {isZh ? "溢价" : "Premium"}
                      </p>
                      <p className={cn(
                        "text-[12px] font-black leading-none",
                        isPremium
                          ? "text-amber-500"
                          : "text-emerald-600 dark:text-emerald-400"
                      )}>
                        {isPremium
                          ? (isZh ? "是" : "Yes")
                          : (isZh ? "否" : "No")}
                      </p>
                    </div>
                  </div>
                )}

                {/* Lifecycle card — phase dot + expiry countdown + drop date multi-tz */}
                {hasExpiry && lc && phaseUI ? (
                  <DomainLifecycleSection
                    lc={lc}
                    phaseUI={phaseUI}
                    remainingDays={remainingDays}
                    urgencyNum={urgencyNum}
                    isZh={isZh}
                    onFeedbackClick={() => setLcFeedbackOpen(true)}
                  />
                ) : !hasExpiry ? (
                  <div className="px-3.5 py-3 rounded-xl border border-border/50 bg-muted/15 flex items-center gap-2.5">
                    <span className="relative flex h-2 w-2 shrink-0">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-40 bg-foreground/40" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-foreground/50" />
                    </span>
                    <p className="text-[11px] text-muted-foreground">
                      {isZh ? "暂无到期日期，仍可订阅提醒" : "No expiry info yet, but you can still subscribe"}
                    </p>
                  </div>
                ) : null}

                {/* Reminder plan */}
                {isRestricted ? (
                  /* Restricted (prohibited / reserved) — status-change only */
                  <div className="rounded-xl border border-border/60 bg-muted/15 p-3.5 space-y-2.5">
                    <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                      {isZh ? "提醒计划" : "Reminder plan"}
                    </p>
                    <div className="flex items-center gap-2.5 rounded-lg border border-border/50 bg-muted/30 px-3 py-2.5">
                      <RiCheckboxCircleLine className="w-4 h-4 text-foreground/60 shrink-0" />
                      <div>
                        <p className="text-[11px] font-bold text-foreground/80">
                          {isZh ? "域名状态变化通知" : "Status change alert"}
                        </p>
                        <p className="text-[10px] text-muted-foreground leading-snug mt-0.5">
                          {isZh
                            ? "当该域名注册状态发生变化（如解禁、开放注册）时，系统将自动发送邮件通知。"
                            : "You'll be notified by email if this domain's status changes (e.g. restriction lifted, becomes available)."}
                        </p>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground/65 border-t border-border/40 pt-2 leading-relaxed">
                      {isZh ? "可随时取消订阅" : "Unsubscribe anytime"}
                    </p>
                  </div>
                ) : (
                  /* Normal domain — pre-expiry + phase chips */
                  <div className="rounded-xl border border-border/60 bg-muted/15 p-3.5 space-y-3">
                    <p className="text-[10px] font-bold text-foreground/60 uppercase tracking-widest">
                      {isZh ? "提醒计划" : "Reminder plan"}
                    </p>
                    {/* Pre-expiry day alerts — interactive */}
                    <div>
                      <p className="text-[10px] text-foreground/70 mb-2 flex items-center gap-1.5 font-semibold">
                        <RiTimerLine className="w-3 h-3 text-foreground/50" />
                        {isZh ? "到期前提醒" : "Pre-expiry alerts"}
                        <span className="ml-auto text-[9px] text-muted-foreground/60 font-normal normal-case">
                          {isZh ? "点击选择" : "tap to toggle"}
                        </span>
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {ALL_REMINDER_THRESHOLDS.map((d) => {
                          const on = selectedThresholds.includes(d);
                          return (
                            <button
                              key={d}
                              type="button"
                              onClick={() => toggleThreshold(d)}
                              className={cn(
                                "inline-flex items-center gap-0.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold transition-all cursor-pointer select-none",
                                on
                                  ? "bg-foreground/10 border-foreground/30 text-foreground"
                                  : "bg-muted/30 border-border/50 text-muted-foreground/55"
                              )}
                            >
                              {on
                                ? <RiCheckboxCircleLine className="w-2.5 h-2.5 shrink-0" />
                                : <RiCheckboxBlankCircleLine className="w-2.5 h-2.5 shrink-0" />}
                              {isZh ? `提前 ${d} 天` : `${d}d`}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                    {/* Phase event alerts */}
                    {phaseChips.length > 0 ? (
                      <div>
                        <p className="text-[10px] text-foreground/70 mb-2 flex items-center gap-1.5 font-semibold">
                          <RiCalendarEventLine className="w-3 h-3 text-violet-500" />
                          {isZh ? `阶段提醒（.${tldUpper}）` : `Phase alerts (.${tldUpper})`}
                          <span className="ml-auto text-[9px] text-muted-foreground/60 font-normal normal-case">
                            {isZh ? "点击选择" : "tap to toggle"}
                          </span>
                        </p>
                        <div className="flex flex-wrap gap-1.5">
                          {phaseChips.map((chip) => {
                            const on = phaseAlerts[chip.key];
                            return (
                              <button
                                key={chip.key}
                                type="button"
                                onClick={() => togglePhase(chip.key)}
                                className={cn(
                                  "inline-flex items-center gap-0.5 px-2 py-0.5 rounded-md border text-[11px] font-semibold transition-all cursor-pointer select-none",
                                  on ? chip.activeCls : chip.inactiveCls
                                )}
                              >
                                {on
                                  ? <RiCheckboxCircleLine className="w-2.5 h-2.5 shrink-0" />
                                  : <RiCheckboxBlankCircleLine className="w-2.5 h-2.5 shrink-0" />}
                                {chip.label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ) : lc ? (
                      <p className="text-[10px] text-muted-foreground/55 italic">
                        {isZh
                          ? `.${tldUpper} 注册局不设宽限期，仅发送到期前提醒`
                          : `.${tldUpper} has no grace/redemption — pre-expiry alerts only`}
                      </p>
                    ) : null}
                    <p className="text-[10px] text-muted-foreground/65 border-t border-border/40 pt-2.5 leading-relaxed">
                      {isZh
                        ? "域名释放后自动停止 · 续费时提醒保留直至到期 · 可随时取消"
                        : "Auto-stops on drop · Reminders continue after renewal until new expiry · Unsubscribe anytime"}
                    </p>
                  </div>
                )}

                {/* Email input */}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1.5">
                    {isZh ? "接收邮箱" : "Email address"} <span className="text-red-500">*</span>
                  </p>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                    placeholder="your@email.com"
                    className="w-full text-sm rounded-xl border border-border bg-background px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-ring/30 transition-shadow font-mono"
                  />
                  {userEmail && email === userEmail && (
                    <p className="text-[10px] text-muted-foreground/60 mt-1 flex items-center gap-1">
                      <RiShieldCheckLine className="w-3 h-3 text-emerald-500" />
                      {isZh ? "已自动填入您的账户邮箱" : "Pre-filled from your account"}
                    </p>
                  )}
                </div>

                {/* Submit */}
                <Button
                  onClick={handleSubmit}
                  disabled={submitting}
                  className="w-full gap-2 h-10 bg-primary hover:bg-primary/90 active:bg-primary/80 text-primary-foreground border-0 rounded-xl font-semibold text-sm transition-all"
                >
                  {submitting
                    ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{isZh ? "订阅中…" : "Subscribing…"}</>
                    : <><RiCalendarEventLine className="w-4 h-4" />{isZh ? "订阅域名监控" : "Subscribe"}</>
                  }
                </Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </DialogContent>
    </Dialog>

    {/* TLD Lifecycle Correction feedback dialog */}
    <Dialog open={lcFeedbackOpen} onOpenChange={setLcFeedbackOpen}>
      <DialogContent className="max-w-sm rounded-2xl gap-0 p-0 overflow-hidden">
        <DialogHeader className="px-5 pt-5 pb-3 border-b border-border/40">
          <DialogTitle className="text-base flex items-center gap-2">
            <RiFlagLine className="w-4 h-4 text-amber-500" />
            {isZh ? `纠正 .${tldUpper} 生命周期数据` : `Correct .${tldUpper} Lifecycle Data`}
          </DialogTitle>
          <p className="text-xs text-muted-foreground mt-1">
            {isZh
              ? "若实际注册局政策与显示数据不符，请填写正确天数并提交，管理员审核后将更新数据。"
              : "If the registry policy differs from what's shown, enter the correct days and submit. Admin will review and update."}
          </p>
        </DialogHeader>

        {lcDone ? (
          <div className="px-5 py-8 text-center space-y-2">
            <p className="text-2xl">✅</p>
            <p className="text-sm font-semibold">
              {isZh ? "感谢您的反馈！" : "Thanks for your feedback!"}
            </p>
            <p className="text-xs text-muted-foreground">
              {isZh ? "管理员审核后将更新数据，届时页面会自动反映最新信息。" : "Admin will review and update the data accordingly."}
            </p>
            <Button variant="outline" size="sm" className="mt-3" onClick={() => setLcFeedbackOpen(false)}>
              {isZh ? "关闭" : "Close"}
            </Button>
          </div>
        ) : (
          <div className="px-5 py-4 space-y-4">
            <p className="text-[10px] text-muted-foreground/60 uppercase tracking-widest font-bold">
              {isZh ? "建议天数（填 0 表示无该阶段）" : "Suggested Days (0 = phase does not exist)"}
            </p>

            <div className="grid grid-cols-3 gap-3">
              {([
                { key: "grace",        label: isZh ? "宽限期" : "Grace",      placeholder: "30" },
                { key: "redemption",   label: isZh ? "赎回期" : "Redemption", placeholder: "30" },
                { key: "pendingDelete",label: isZh ? "待删除" : "Pending Del", placeholder: "5"  },
              ] as const).map(f => (
                <div key={f.key} className="space-y-1">
                  <label className="text-[10px] font-semibold text-muted-foreground/80">{f.label}</label>
                  <Input
                    type="number"
                    min="0"
                    max="365"
                    value={lcForm[f.key]}
                    onChange={e => setLcForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                    placeholder={f.placeholder}
                    className="h-9 text-sm font-mono text-center"
                  />
                  {lc && (
                    <p className="text-[9px] text-muted-foreground/50 text-center font-mono">
                      {isZh ? "当前" : "now"}: {f.key === "grace" ? lc.cfg.grace : f.key === "redemption" ? lc.cfg.redemption : lc.cfg.pendingDelete}d
                    </p>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "来源链接（可选）" : "Source URL (optional)"}
              </label>
              <Input
                type="url"
                value={lcForm.sourceUrl}
                onChange={e => setLcForm(prev => ({ ...prev, sourceUrl: e.target.value }))}
                placeholder="https://registry.example/policy"
                className="h-9 text-xs font-mono"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "备注（可选）" : "Notes (optional)"}
              </label>
              <Input
                type="text"
                value={lcForm.notes}
                onChange={e => setLcForm(prev => ({ ...prev, notes: e.target.value }))}
                placeholder={isZh ? "如：官网政策更新日期 2025-01-01" : "e.g. Registry policy updated 2025-01-01"}
                className="h-9 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-muted-foreground/80">
                {isZh ? "联系邮箱（可选，用于告知审核结果）" : "Contact email (optional)"}
              </label>
              <Input
                type="email"
                value={lcForm.email}
                onChange={e => setLcForm(prev => ({ ...prev, email: e.target.value }))}
                placeholder="your@email.com"
                className="h-9 text-xs font-mono"
              />
            </div>
          </div>
        )}

        {!lcDone && (
          <div className="flex flex-row gap-2 px-5 pb-5 pt-0">
            <Button variant="outline" size="sm" onClick={() => setLcFeedbackOpen(false)} className="flex-1">
              {isZh ? "取消" : "Cancel"}
            </Button>
            <Button
              size="sm"
              onClick={handleLcFeedbackSubmit}
              disabled={lcSubmitting}
              className="flex-1 bg-amber-500 hover:bg-amber-600 text-white"
            >
              {lcSubmitting
                ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" />{isZh ? "提交中…" : "Submitting…"}</>
                : <><RiFlagLine className="w-3.5 h-3.5 mr-1" />{isZh ? "提交纠错" : "Submit Correction"}</>}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  </>);
}
