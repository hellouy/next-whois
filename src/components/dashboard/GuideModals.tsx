import React from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import {
  RiCloseLine, RiSearchLine, RiShieldCheckLine, RiWifiLine,
  RiCheckLine, RiBellLine, RiMailLine, RiCalendarLine,
  RiArrowRightLine, RiTimeLine, RiTimerLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";

function GuideModalShell({ onClose, icon, iconBg, title, subtitle, children }: {
  onClose: () => void;
  icon: React.ReactNode;
  iconBg: string;
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-end sm:items-center justify-center"
      style={{ paddingTop: "calc(var(--ann-h, 0px) + 4.5rem)" }}
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/75 backdrop-blur-sm pointer-events-none" />
      <div
        className="relative z-10 w-full max-w-sm bg-background border border-border rounded-t-2xl sm:rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        style={{ maxHeight: "calc(100dvh - var(--ann-h, 0px) - 4.5rem)" }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
          <div className="flex items-center gap-2">
            <div className={cn("w-7 h-7 rounded-lg flex items-center justify-center shrink-0", iconBg)}>
              {icon}
            </div>
            <div>
              <p className="text-sm font-bold leading-none">{title}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{subtitle}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-muted transition-colors shrink-0 touch-manipulation"
          >
            <RiCloseLine className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>
        <div
          className="flex-1 min-h-0 overflow-y-auto overscroll-contain"
          style={{ WebkitOverflowScrolling: "touch" } as React.CSSProperties}
        >
          <div className="p-4 space-y-3 pb-safe">{children}</div>
        </div>
      </div>
    </div>,
    document.body
  );
}

function MiniMockup({ highlightClaim }: { highlightClaim: boolean }) {
  const { t } = useTranslation();
  const claimColor = highlightClaim
    ? "bg-violet-50 dark:bg-violet-950/40 border-violet-400/60 text-violet-500"
    : "bg-muted/40 border-border/50 text-muted-foreground/60";
  const subColor = !highlightClaim
    ? "bg-sky-50 dark:bg-sky-950/40 border-sky-400/60 text-sky-500"
    : "bg-muted/40 border-border/50 text-muted-foreground/60";

  return (
    <div className="rounded-xl bg-muted/20 border border-border p-3">
      <p className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground/50 mb-2">
        {t("dashboard.preview_title")}
        <span className="sm:hidden normal-case tracking-normal font-normal">{t("dashboard.preview_mobile")}</span>
        <span className="hidden sm:inline normal-case tracking-normal font-normal">{t("dashboard.preview_desktop")}</span>
      </p>
      <div className="rounded-lg border border-border bg-background shadow-sm">
        <div className="px-3 pt-2.5 pb-1.5">
          <p className="text-[8px] font-bold uppercase tracking-wider text-muted-foreground/40 mb-1">DOMAIN</p>
          <p className="text-sm font-bold font-mono leading-none">example.com</p>
          <div className="flex items-center gap-1.5 mt-1.5">
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[8px] font-semibold bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400">
              <span className="w-1 h-1 rounded-full bg-emerald-500 shrink-0" />Active
            </span>
            <span className="text-[8px] text-muted-foreground">⏱ 2y</span>
          </div>
        </div>
        <div className="px-3 pb-2.5 flex items-center gap-1.5 sm:hidden">
          <div className={cn("relative flex items-center justify-center w-5 h-5 rounded-full border", claimColor)}>
            <RiShieldCheckLine className="w-2.5 h-2.5" />
            {highlightClaim && (
              <span className="absolute -top-0.5 -right-0.5 flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-70" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-violet-500" />
              </span>
            )}
          </div>
          <div className={cn("relative flex items-center justify-center w-5 h-5 rounded-full border", subColor)}>
            <RiTimerLine className="w-2.5 h-2.5" />
            {!highlightClaim && (
              <span className="absolute -top-0.5 -right-0.5 flex h-1.5 w-1.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-70" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-sky-500" />
              </span>
            )}
          </div>
          <span className="text-[8px] text-muted-foreground ml-0.5">{highlightClaim ? t("dashboard.click_claim_btn") : t("dashboard.click_sub_btn")}</span>
        </div>
        <div className="px-3 pb-2.5 hidden sm:flex items-center gap-1.5">
          <div className={cn("relative flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border", highlightClaim ? "bg-violet-100 dark:bg-violet-950/50 border-violet-400/70 text-violet-600 dark:text-violet-400 ring-1 ring-violet-400/20" : "bg-muted/40 border-border/50 text-muted-foreground/50 font-medium")}>
            <RiShieldCheckLine className="w-2.5 h-2.5" />{t("dashboard.brand_claim_btn")}
            {highlightClaim && (
              <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-violet-500" />
              </span>
            )}
          </div>
          <div className={cn("relative flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold border", !highlightClaim ? "bg-sky-100 dark:bg-sky-950/50 border-sky-400/70 text-sky-600 dark:text-sky-400 ring-1 ring-sky-400/20" : "bg-muted/40 border-border/50 text-muted-foreground/50 font-medium")}>
            <RiTimeLine className="w-2.5 h-2.5" />{t("dashboard.domain_sub_btn")}
            {!highlightClaim && (
              <span className="absolute -top-0.5 -right-0.5 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-sky-500" />
              </span>
            )}
          </div>
          <span className="text-[8px] text-muted-foreground ml-0.5">{t("dashboard.click_btn_hint", { label: highlightClaim ? t("dashboard.brand_claim_btn") : t("dashboard.domain_sub_btn") })}</span>
        </div>
      </div>
    </div>
  );
}

export function ClaimGuideModal({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const { t } = useTranslation();
  const [domain, setDomain] = React.useState("");
  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = domain.trim();
    if (!q) return;
    router.push(`/stamp?domain=${encodeURIComponent(q)}`);
    onClose();
  }
  return (
    <GuideModalShell
      onClose={onClose}
      icon={<RiShieldCheckLine className="w-3.5 h-3.5 text-violet-600 dark:text-violet-400" />}
      iconBg="bg-violet-100 dark:bg-violet-950/40"
      title={t("dashboard.claim_title")}
      subtitle={t("dashboard.claim_subtitle")}
    >
      <MiniMockup highlightClaim={true} />
      <div className="space-y-1.5">
        {[
          { icon: RiSearchLine,      color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",    n: "1", title: t("dashboard.claim_step1_title"), desc: t("dashboard.claim_step1_desc") },
          { icon: RiShieldCheckLine, color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400", n: "2", title: t("dashboard.claim_step2_title"), desc: t("dashboard.claim_step2_desc") },
          { icon: RiWifiLine,        color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400", n: "3", title: t("dashboard.claim_step3_title"), desc: t("dashboard.claim_step3_desc") },
          { icon: RiCheckLine,       color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",    n: "4", title: t("dashboard.claim_step4_title"), desc: t("dashboard.claim_step4_desc") },
        ].map((s) => (
          <div key={s.n} className="flex items-start gap-2.5 px-2.5 py-2 rounded-xl bg-muted/25">
            <div className={cn("w-6 h-6 rounded-lg flex items-center justify-center shrink-0 mt-0.5", s.color)}>
              <s.icon className="w-3 h-3" />
            </div>
            <div className="min-w-0">
              <p className="text-[9px] font-bold text-muted-foreground/40 uppercase tracking-widest">{t("dashboard.step_n", { n: s.n })}</p>
              <p className="text-xs font-semibold leading-snug">{s.title}</p>
              <p className="text-[10px] text-muted-foreground leading-snug">{s.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <form onSubmit={handleSearch} className="flex gap-2">
        <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" className="h-9 rounded-xl text-sm font-mono flex-1" />
        <Button type="submit" size="sm" className="h-9 rounded-xl px-3 gap-1 shrink-0 touch-manipulation">
          {t("dashboard.go_btn")} <RiArrowRightLine className="w-3.5 h-3.5" />
        </Button>
      </form>
      <p className="text-[10px] text-muted-foreground text-center px-2 pb-1">{t("dashboard.claim_note")}</p>
    </GuideModalShell>
  );
}

export function SubscribeGuideModal({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const { t } = useTranslation();
  const [domain, setDomain] = React.useState("");
  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = domain.trim();
    if (!q) return;
    onClose();
    router.push(`/remind?domain=${encodeURIComponent(q)}`);
  }
  return (
    <GuideModalShell
      onClose={onClose}
      icon={<RiCalendarLine className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />}
      iconBg="bg-sky-100 dark:bg-sky-950/40"
      title={t("dashboard.sub_guide_title")}
      subtitle={t("dashboard.sub_guide_subtitle")}
    >
      <MiniMockup highlightClaim={false} />
      <div className="space-y-1.5">
        {[
          { icon: RiSearchLine, color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",    n: "1", title: t("dashboard.sub_step1_title"), desc: t("dashboard.sub_step1_desc") },
          { icon: RiBellLine,   color: "bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400",        n: "2", title: t("dashboard.sub_step2_title"), desc: t("dashboard.sub_step2_desc") },
          { icon: RiMailLine,   color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400", n: "3", title: t("dashboard.sub_step3_title"), desc: t("dashboard.sub_step3_desc") },
        ].map((s) => (
          <div key={s.n} className="flex items-start gap-2.5 px-2.5 py-2 rounded-xl bg-muted/25">
            <div className={cn("w-6 h-6 rounded-lg flex items-center justify-center shrink-0 mt-0.5", s.color)}>
              <s.icon className="w-3 h-3" />
            </div>
            <div className="min-w-0">
              <p className="text-[9px] font-bold text-muted-foreground/40 uppercase tracking-widest">{t("dashboard.step_n", { n: s.n })}</p>
              <p className="text-xs font-semibold leading-snug">{s.title}</p>
              <p className="text-[10px] text-muted-foreground leading-snug">{s.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <form onSubmit={handleSearch} className="flex gap-2">
        <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" className="h-9 rounded-xl text-sm font-mono flex-1" />
        <Button type="submit" size="sm" className="h-9 rounded-xl px-3 gap-1 shrink-0 touch-manipulation">
          {t("dashboard.go_btn")} <RiArrowRightLine className="w-3.5 h-3.5" />
        </Button>
      </form>
      <button
        type="button"
        onClick={() => {
          const q = domain.trim();
          onClose();
          router.push(q ? `/stamp?domain=${encodeURIComponent(q)}` : "/stamp");
        }}
        className="w-full h-9 rounded-xl text-xs touch-manipulation flex items-center justify-center border border-border bg-background hover:bg-muted transition-colors font-medium"
      >
        <RiShieldCheckLine className="w-3.5 h-3.5 mr-1" />{t("dashboard.go_claim_btn")}
      </button>
    </GuideModalShell>
  );
}
