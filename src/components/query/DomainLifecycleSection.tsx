import React from "react";
import { cn } from "@/lib/utils";
import { RiShieldCheckLine, RiShoppingCartLine, RiFlagLine } from "@remixicon/react";
import { fmtDate, fmtCountdown } from "@/lib/lifecycle";

type LifecyclePhase = "active" | "grace" | "redemption" | "pendingDelete" | "dropped";

type PhaseUI = {
  label: string;
  colorClass: string;
  bgClass: string;
  borderClass: string;
  dotClass: string;
};

type LifecycleData = {
  expiry: Date;
  dropDate: Date;
  phase: LifecyclePhase;
  phaseSource?: string;
  cfg: {
    grace: number;
    redemption: number;
    pendingDelete: number;
    registry?: string;
  };
};

const PHASE_ADVICE: Record<string, { zh: string; en: string }> = {
  active:        { zh: "域名状态正常，我们将在到期前自动发送提醒邮件。", en: "Domain is active. We'll alert you before expiry." },
  grace:         { zh: "域名已过期，仍处于宽限期内，可按正常价格续费，请尽快操作！", en: "Expired but renewable at normal price during grace — act now!" },
  redemption:    { zh: "已进入赎回期，续费费用大幅增加，请立即联系注册商赎回。", en: "In redemption. Recovery fees are much higher — contact your registrar." },
  pendingDelete: { zh: "即将被注册局删除，通常无法再续期，请提前做好准备。", en: "Pending deletion. Usually cannot be renewed anymore." },
  dropped:       { zh: "域名已被删除，即将或已可重新注册。", en: "Domain has been deleted and may be available for re-registration." },
};

export function DomainLifecycleSection({
  lc,
  phaseUI,
  remainingDays,
  urgencyNum,
  isZh,
  onFeedbackClick,
}: {
  lc: LifecycleData;
  phaseUI: PhaseUI;
  remainingDays: number | null;
  urgencyNum: string;
  isZh: boolean;
  onFeedbackClick: () => void;
}) {
  return (
    <div className={cn("rounded-xl border overflow-hidden", phaseUI.borderClass)}>
      {/* Expiry + countdown row */}
      <div className={cn("flex items-center justify-between px-3.5 py-3", phaseUI.bgClass)}>
        <div className="min-w-0">
          <p className="text-[9px] text-muted-foreground/70 uppercase tracking-wider font-bold mb-1">
            {isZh ? "到期日期" : "Expiry date"}
          </p>
          <p className="text-[13px] font-mono font-bold text-foreground leading-none">{fmtDate(lc.expiry)}</p>
          <p className="text-[10px] font-mono text-muted-foreground/60 mt-0.5 tabular-nums">
            {`${String(lc.expiry.getUTCHours()).padStart(2,"0")}:${String(lc.expiry.getUTCMinutes()).padStart(2,"0")}:${String(lc.expiry.getUTCSeconds()).padStart(2,"0")} UTC`}
          </p>
        </div>
        <div className="text-right shrink-0 pl-2">
          {remainingDays !== null && remainingDays >= 0 && remainingDays <= 7 ? (
            <>
              <p className={cn("text-[20px] font-black tabular-nums leading-none", urgencyNum)}>
                {fmtCountdown(lc.expiry, isZh)}
              </p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{isZh ? "后到期" : "remaining"}</p>
            </>
          ) : (
            <>
              <p className={cn("text-[30px] font-black tabular-nums leading-none", urgencyNum)}>
                {remainingDays !== null ? Math.max(0, remainingDays) : "—"}
              </p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{isZh ? "天后到期" : "days left"}</p>
            </>
          )}
        </div>
      </div>

      {/* Current phase — animated dot + label + advice */}
      <div className="px-3.5 py-3 bg-background/60 border-t border-border/25">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2 shrink-0">
            {lc.phase !== "active" && (
              <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-60", phaseUI.dotClass)} />
            )}
            <span className={cn("relative inline-flex rounded-full h-2 w-2", phaseUI.dotClass)} />
          </span>
          <span className={cn("text-[11px] font-bold tracking-wide", phaseUI.colorClass)}>
            {phaseUI.label}
          </span>
          {lc.phaseSource === "epp" && (
            <span className="ml-auto inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-400/20 text-[9px] font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wide">
              <RiShieldCheckLine className="w-2 h-2" />EPP
            </span>
          )}
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed mt-1.5">
          {isZh ? PHASE_ADVICE[lc.phase]?.zh : PHASE_ADVICE[lc.phase]?.en}
        </p>
      </div>

      {/* Drop/available date with multi-timezone breakdown */}
      {(lc.cfg.pendingDelete > 0 || lc.cfg.grace > 0 || lc.cfg.redemption > 0) && (() => {
        const dropIsPast = new Date() > lc.dropDate;
        const daysToDropDate = Math.ceil((lc.dropDate.getTime() - Date.now()) / 86_400_000);

        type TzRow = { label: string; tz: string };
        const tzRows: TzRow[] = [{ label: "UTC", tz: "UTC" }];
        if (isZh) {
          tzRows.push({ label: "北京时间", tz: "Asia/Shanghai" });
        } else {
          tzRows.push({ label: "New York", tz: "America/New_York" });
          tzRows.push({ label: "London",   tz: "Europe/London"   });
        }
        try {
          const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
          if (!tzRows.some(r => r.tz === localTz)) {
            tzRows.push({ label: isZh ? "本地时间" : "Local", tz: localTz });
          }
        } catch { /* ignore */ }

        const fmtInTz = (d: Date, tz: string) => {
          try {
            return new Intl.DateTimeFormat(isZh ? "zh-CN" : "en-US", {
              timeZone: tz,
              year: "numeric", month: "2-digit", day: "2-digit",
              hour: "2-digit", minute: "2-digit", second: "2-digit",
              hour12: false,
            }).format(d).replace(/\//g, "/");
          } catch { return "—"; }
        };

        return (
          <div className={cn(
            "border-t px-3.5 py-3",
            dropIsPast ? "border-emerald-300/40 bg-emerald-50/40 dark:bg-emerald-950/15" : "border-border/25 bg-muted/20"
          )}>
            <div className="flex items-center gap-2 mb-2.5">
              <RiShoppingCartLine className={cn("w-3.5 h-3.5 shrink-0", dropIsPast ? "text-emerald-500" : "text-foreground/50")} />
              <span className={cn("text-[11px] font-bold", dropIsPast ? "text-emerald-600 dark:text-emerald-400" : "text-foreground/70")}>
                {isZh ? "预计可注册" : "Est. available"}
              </span>
              {dropIsPast ? (
                <span className="ml-auto inline-flex items-center px-1.5 py-0.5 rounded text-[8px] font-bold bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-400/30 uppercase tracking-wide">
                  {isZh ? "现在可注册" : "NOW"}
                </span>
              ) : (
                <span className={cn("ml-auto text-[11px] font-black tabular-nums", urgencyNum === "text-muted-foreground" ? "text-foreground/80" : urgencyNum)}>
                  {Math.max(0, daysToDropDate)}{isZh ? "天后" : "d"}
                </span>
              )}
            </div>
            <div className="space-y-1.5">
              {tzRows.map(({ label, tz }) => (
                <div key={tz} className="flex items-center justify-between gap-2">
                  <span className="text-[10px] text-muted-foreground/70 font-medium shrink-0 w-[64px]">{label}</span>
                  <span className="text-[10px] font-mono font-semibold tabular-nums text-foreground/80 text-right">
                    {fmtInTz(lc.dropDate, tz)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Feedback row */}
      <div className="px-3.5 py-2 border-t border-border/20 bg-background/40 flex items-center justify-between">
        <p className="text-[10px] text-muted-foreground/50">
          {isZh ? "时间不准确？" : "Timing incorrect?"}
        </p>
        <button
          type="button"
          onClick={onFeedbackClick}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border border-border/40 bg-muted/20 text-muted-foreground hover:bg-amber-50 dark:hover:bg-amber-950/30 hover:border-amber-400/40 hover:text-amber-600 dark:hover:text-amber-400 transition-colors cursor-pointer"
        >
          <RiFlagLine className="w-2.5 h-2.5" />
          {isZh ? "反馈纠错" : "Report"}
        </button>
      </div>
    </div>
  );
}
