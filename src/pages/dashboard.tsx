import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession, signOut } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiLoader4Line, RiCalendarLine, RiShieldCheckLine, RiGlobalLine,
  RiDeleteBinLine, RiPencilLine, RiCheckLine, RiCloseLine,
  RiUserLine, RiLogoutBoxLine, RiAlertLine, RiExternalLinkLine,
  RiFlashlightLine, RiTimeLine, RiSearchLine,
  RiEdit2Line, RiShieldUserLine, RiLockLine, RiMailLine,
  RiEyeLine, RiEyeOffLine, RiPaletteLine, RiArrowRightLine,
  RiBellLine, RiFileTextLine, RiWifiLine,
  RiDownloadLine, RiFireLine,
  RiTimerLine, RiBarChartLine, RiKeyLine,
  RiIdCardLine, RiBuildingLine, RiAwardLine, RiShakeHandsLine,
  RiCodeSLine, RiVipCrownLine, RiCoinLine, RiGiftLine,
  RiCoupon2Line, RiWalletLine, RiArrowLeftLine, RiCheckboxCircleLine,
  RiRefreshLine,
} from "@remixicon/react";
import { RiBankCardLine, RiStarLine } from "@remixicon/react";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import type { HistoryItem } from "@/lib/history";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";

type Subscription = {
  id: string; domain: string; expiration_date: string | null;
  active: boolean; created_at: string; cancel_token: string;
  drop_date: string | null; grace_end: string | null; redemption_end: string | null;
  phase: string | null; days_to_expiry: number | null; days_to_drop: number | null;
  tld_confidence: string | null;
  days_before: number | null;
  sent_keys: number[];
  last_reminded_at: string | null;
  next_reminder_at: string | null;
  next_reminder_days: number | null;
};

type RegStatus = "registered" | "unregistered" | "reserved" | "error" | "unknown";

type Order = {
  id: string;
  plan_name: string;
  amount: number;
  currency: string;
  provider: string;
  status: string;
  paid_at: string | null;
  created_at: string;
};

type Plan = {
  id: string;
  name: string;
  price: number;
  currency: string;
  duration_days: number | null;
  description: string | null;
  is_recurring: boolean;
  grants_subscription: boolean;
};

type Stamp = {
  id: string; domain: string; tag_name: string; tag_style: string;
  link: string | null; description: string | null; nickname: string;
  verified: boolean; verified_at: string | null; created_at: string;
};

const TAG_COLORS: Record<string, string> = {
  personal: "bg-teal-500 text-white",
  official: "bg-blue-500 text-white",
  brand:    "bg-violet-500 text-white",
  verified: "bg-emerald-500 text-white",
  partner:  "bg-orange-500 text-white",
  dev:      "bg-sky-500 text-white",
  warning:  "bg-amber-400 text-white",
  premium:  "bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white",
};

function TagBadge({ style, name }: { style: string; name: string }) {
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold", TAG_COLORS[style] || TAG_COLORS.personal)}>
      {name}
    </span>
  );
}

const PHASE_LABEL: Record<string, { color: string }> = {
  active: { color: "text-emerald-600 dark:text-emerald-400" },
  grace: { color: "text-amber-600 dark:text-amber-400" },
  redemption: { color: "text-orange-600 dark:text-orange-400" },
  pendingDelete: { color: "text-red-600 dark:text-red-400" },
  dropped: { color: "text-muted-foreground" },
};

function fmt(d: Date) {
  return d.toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}

/* ── Tag style definitions — mirrored from admin stamps.tsx ──────────────── */
const EDIT_TAG_STYLES: {
  value: string; zhLabel: string; enLabel: string; color: string;
  icon: React.ElementType; previewBorder: string; previewBg: string; previewIcon: string;
}[] = [
  { value: "personal", zhLabel: "个人持有", enLabel: "Personal",  color: "bg-teal-500 text-white",
    icon: RiIdCardLine,      previewBorder: "border-l-teal-500",    previewBg: "bg-teal-50 dark:bg-teal-900/20",    previewIcon: "text-teal-500" },
  { value: "official", zhLabel: "官方",     enLabel: "Official",  color: "bg-blue-500 text-white",
    icon: RiBuildingLine,    previewBorder: "border-l-blue-500",    previewBg: "bg-blue-50 dark:bg-blue-900/20",    previewIcon: "text-blue-500" },
  { value: "brand",    zhLabel: "品牌",     enLabel: "Brand",     color: "bg-violet-500 text-white",
    icon: RiAwardLine,       previewBorder: "border-l-violet-500",  previewBg: "bg-violet-50 dark:bg-violet-900/20",previewIcon: "text-violet-500" },
  { value: "verified", zhLabel: "认证",     enLabel: "Verified",  color: "bg-emerald-500 text-white",
    icon: RiShieldCheckLine, previewBorder: "border-l-emerald-500", previewBg: "bg-emerald-50 dark:bg-emerald-900/20",previewIcon: "text-emerald-500" },
  { value: "partner",  zhLabel: "合作",     enLabel: "Partner",   color: "bg-orange-500 text-white",
    icon: RiShakeHandsLine,  previewBorder: "border-l-orange-500",  previewBg: "bg-orange-50 dark:bg-orange-900/20",previewIcon: "text-orange-500" },
  { value: "dev",      zhLabel: "开发者",   enLabel: "Developer", color: "bg-sky-500 text-white",
    icon: RiCodeSLine,       previewBorder: "border-l-sky-500",     previewBg: "bg-sky-50 dark:bg-sky-900/20",     previewIcon: "text-sky-500" },
  { value: "warning",  zhLabel: "提醒",     enLabel: "Warning",   color: "bg-amber-400 text-white",
    icon: RiAlertLine,       previewBorder: "border-l-amber-400",   previewBg: "bg-amber-50 dark:bg-amber-900/20", previewIcon: "text-amber-500" },
  { value: "premium",  zhLabel: "高级",     enLabel: "Premium",   color: "bg-gradient-to-r from-violet-500 to-fuchsia-500 text-white",
    icon: RiVipCrownLine,    previewBorder: "border-l-fuchsia-500", previewBg: "bg-fuchsia-50 dark:bg-fuchsia-900/20",previewIcon: "text-fuchsia-500" },
];

// ── Edit Stamp Modal ──────────────────────────────────────────────────────────
function EditStampModal({ stamp, onClose, onSaved, isMember }: { stamp: Stamp; onClose: () => void; onSaved: () => void; isMember: boolean }) {
  const [tagName, setTagName] = React.useState(stamp.tag_name);
  const [tagStyle, setTagStyle] = React.useState(stamp.tag_style);
  const [link, setLink] = React.useState(stamp.link || "");
  const [description, setDescription] = React.useState(stamp.description || "");
  const [nickname, setNickname] = React.useState(stamp.nickname);
  const [saving, setSaving] = React.useState(false);
  const { t, locale } = useTranslation();
  const isZh = locale.startsWith("zh");

  async function handleSave() {
    setSaving(true);
    try {
      const res = await fetch(`/api/user/stamps?id=${stamp.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tagName, tagStyle, link, description, nickname }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      toast.success(t("dashboard.save_success"));
      onSaved();
      onClose();
    } catch (e: any) {
      toast.error(e.message || t("dashboard.save_failed"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-end sm:items-center justify-center p-4 pb-6 sm:p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-background border border-border rounded-t-2xl sm:rounded-2xl shadow-2xl p-6 space-y-4 max-h-[88vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold flex items-center gap-2">
            <RiPencilLine className="w-4 h-4 text-primary" />{t("dashboard.edit_stamp_title")}
          </h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>
        <p className="text-xs text-muted-foreground">{t("dashboard.domain_label")}<span className="font-mono text-foreground">{stamp.domain}</span></p>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <div className="flex items-baseline justify-between">
              <Label className="text-xs font-semibold">{t("dashboard.tag_label")}</Label>
              {!isMember && <span className="text-[10px] text-amber-500">{t("dashboard.tag_limit_free")}</span>}
            </div>
            <Input value={tagName} onChange={e => setTagName(e.target.value)} maxLength={isMember ? 32 : 5} className="h-9 rounded-xl text-sm" />
          </div>
          <div className="space-y-1.5">
            <div className="flex items-baseline justify-between">
              <Label className="text-xs font-semibold">{t("dashboard.tag_style")}</Label>
              {!isMember && <span className="text-[10px] text-violet-600 flex items-center gap-0.5"><RiVipCrownLine className="w-3 h-3"/>{t("dashboard.member_only")}</span>}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {EDIT_TAG_STYLES.map(ts => {
                const Icon = ts.icon;
                const isFree = ts.value === "personal";
                const locked = !isMember && !isFree;
                return (
                  <button key={ts.value} type="button"
                    onClick={() => { if (!locked) setTagStyle(ts.value); else toast.info(t("dashboard.upgrade_style_toast")); }}
                    title={locked ? t("dashboard.member_style_tooltip") : undefined}
                    className={cn(
                      "relative flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-semibold border-2 transition-all active:scale-[0.96]",
                      locked ? "opacity-40 cursor-not-allowed border-transparent" : tagStyle === ts.value
                        ? "border-white/60 ring-2 ring-offset-1 ring-primary scale-105 shadow-md"
                        : "border-transparent opacity-75 hover:opacity-100",
                      ts.color
                    )}>
                    {locked ? <RiLockLine className="w-3 h-3 shrink-0" /> : <Icon className="w-3 h-3 shrink-0" />}
                    {isZh ? ts.zhLabel : ts.enLabel}
                    {isFree && !isMember && (
                      <span className="ml-0.5 text-[7px] font-bold bg-white/30 px-1 py-0.5 rounded-full leading-tight">{t("dashboard.tag_free")}</span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Live style preview */}
            {(() => {
              const sel = EDIT_TAG_STYLES.find(ts => ts.value === tagStyle) || EDIT_TAG_STYLES[0];
              const Icon = sel.icon;
              return (
                <AnimatePresence mode="wait">
                  <motion.div
                    key={tagStyle}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    transition={{ duration: 0.15 }}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2.5 rounded-xl border-l-4 mt-2",
                      sel.previewBg, sel.previewBorder
                    )}
                  >
                    <Icon className={cn("w-5 h-5 shrink-0", sel.previewIcon)} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs font-mono text-muted-foreground truncate">{stamp.domain}</span>
                        <span className={cn("inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-md text-[10px] font-semibold", sel.color)}>
                          <Icon className="w-2.5 h-2.5" />
                          {tagName || (isZh ? sel.zhLabel : sel.enLabel)}
                        </span>
                      </div>
                      <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{nickname || t("dashboard.nickname")}</p>
                    </div>
                  </motion.div>
                </AnimatePresence>
              );
            })()}
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs font-semibold">{t("dashboard.nickname")}</Label>
            <Input value={nickname} onChange={e => setNickname(e.target.value)} maxLength={50} className="h-9 rounded-xl text-sm" />
          </div>
          {isMember ? (
            <>
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold">{t("dashboard.link")} <span className="text-muted-foreground font-normal">{t("dashboard.optional")}</span></Label>
                <Input value={link} onChange={e => setLink(e.target.value)} maxLength={200} placeholder="https://" className="h-9 rounded-xl text-sm" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold">{t("dashboard.description")} <span className="text-muted-foreground font-normal">{t("dashboard.optional")}</span></Label>
                <Input value={description} onChange={e => setDescription(e.target.value)} maxLength={200} className="h-9 rounded-xl text-sm" />
              </div>
            </>
          ) : (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-violet-50/50 dark:bg-violet-950/10 border border-dashed border-violet-200/60 dark:border-violet-800/40">
              <RiVipCrownLine className="w-4 h-4 text-violet-500 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-[11px] font-semibold text-violet-700 dark:text-violet-300">{t("dashboard.link_member_title")}</p>
                <p className="text-[10px] text-muted-foreground/70 leading-relaxed">{t("dashboard.link_member_desc")}</p>
              </div>
            </div>
          )}
        </div>
        <div className="flex gap-2 pt-1">
          <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
          <Button onClick={handleSave} disabled={saving} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
            {saving ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.save")}</>}
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Edit Subscription Expiry Modal ────────────────────────────────────────────
function EditExpiryModal({ sub, onClose, onSaved }: { sub: Subscription; onClose: () => void; onSaved: (newDate: string) => void }) {
  const [dateValue, setDateValue] = React.useState(
    sub.expiration_date ? sub.expiration_date.slice(0, 10) : ""
  );
  const [saving, setSaving] = React.useState(false);
  const { t } = useTranslation();

  async function handleSave() {
    if (!dateValue) { toast.error(t("dashboard.date_required")); return; }
    setSaving(true);
    try {
      const res = await fetch(`/api/user/subscriptions?id=${sub.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expiration_date: dateValue }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      toast.success(t("dashboard.expiry_updated"));
      onSaved(new Date(dateValue).toISOString());
      onClose();
    } catch (e: any) {
      toast.error(e.message || t("dashboard.update_failed"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-end sm:items-center justify-center p-4 pb-6 sm:p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-sm bg-background border border-border rounded-t-2xl sm:rounded-2xl shadow-2xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold flex items-center gap-2">
            <RiCalendarLine className="w-4 h-4 text-primary" />{t("dashboard.edit_expiry_title")}
          </h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>
        <p className="text-xs text-muted-foreground">{t("dashboard.domain_label")}<span className="font-mono text-foreground">{sub.domain}</span></p>
        <div className="space-y-1.5">
          <Label className="text-xs font-semibold">{t("dashboard.expiry_date")}</Label>
          <Input type="date" value={dateValue} onChange={e => setDateValue(e.target.value)} className="h-9 rounded-xl text-sm" />
        </div>
        <div className="flex gap-2 pt-1">
          <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
          <Button onClick={handleSave} disabled={saving} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
            {saving ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.save")}</>}
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Claim Guide Modal ─────────────────────────────────────────────────────────
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

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center px-4 pb-4"
      style={{ paddingTop: "clamp(60px, 10vh, 80px)" }}
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/75 backdrop-blur-sm pointer-events-none" />
      <div
        className="relative z-10 w-full max-w-sm bg-background border border-border rounded-2xl shadow-2xl flex flex-col"
        style={{ maxHeight: "calc(100vh - clamp(60px,10vh,80px) - 16px)" }}
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
          <div className="p-4 space-y-3">{children}</div>
        </div>
      </div>
    </div>
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
          <p className="text-sm font-bold font-mono leading-none">X.RW</p>
          <div className="flex items-center gap-1.5 mt-1.5">
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[8px] font-semibold bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400">
              <span className="w-1 h-1 rounded-full bg-emerald-500 shrink-0" />Active
            </span>
            <span className="text-[8px] text-muted-foreground">⏱ 2y</span>
          </div>
        </div>
        {/* Mobile: small circle icon buttons */}
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
        {/* Desktop: text pill buttons */}
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

function ClaimGuideModal({ onClose }: { onClose: () => void }) {
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
        <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="x.rw" className="h-9 rounded-xl text-sm font-mono flex-1" />
        <Button type="submit" size="sm" className="h-9 rounded-xl px-3 gap-1 shrink-0 touch-manipulation">
          {t("dashboard.go_btn")} <RiArrowRightLine className="w-3.5 h-3.5" />
        </Button>
      </form>
      <p className="text-[10px] text-muted-foreground text-center px-2 pb-1">{t("dashboard.claim_note")}</p>
    </GuideModalShell>
  );
}

// ── Subscribe Guide Modal ──────────────────────────────────────────────────────
function SubscribeGuideModal({ onClose }: { onClose: () => void }) {
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
        <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="x.rw" className="h-9 rounded-xl text-sm font-mono flex-1" />
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

// ── Module-level dashboard data cache (survives tab switches / soft-navs) ────
interface DashData {
  subscriptions: Subscription[];
  stamps: Stamp[];
  /** DB-authoritative — heals stale JWTs automatically */
  subscriptionAccess: boolean;
}
let _dashCache: DashData | null = null;
let _dashCacheTs = 0;
const DASH_CACHE_TTL = 60_000; // 60 s

async function fetchDashData(): Promise<DashData> {
  const res = await fetch("/api/user/dashboard");
  if (!res.ok) throw new Error(`${res.status}`);
  const data = await res.json();
  const result: DashData = {
    subscriptions: data.subscriptions ?? [],
    stamps: data.stamps ?? [],
    subscriptionAccess: data.subscriptionAccess ?? false,
  };
  _dashCache = result;
  _dashCacheTs = Date.now();
  return result;
}

function invalidateDashCache() {
  _dashCache = null;
  _dashCacheTs = 0;
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const { data: session, status, update: updateSession } = useSession();
  const siteSettings = useSiteSettings();
  const paymentEnabled = !!(siteSettings.payment_stripe_enabled || siteSettings.payment_xunhupay_enabled || siteSettings.payment_alipay_enabled || siteSettings.payment_paypal_enabled);
  const [tab, setTab] = React.useState<"subscriptions" | "stamps" | "account" | "membership">("stamps");
  const [subscriptions, setSubscriptions] = React.useState<Subscription[]>([]);
  const [stamps, setStamps] = React.useState<Stamp[]>([]);
  // DB-authoritative access flag; initialized from session (fast), then confirmed by API
  const [subscriptionAccessDB, setSubscriptionAccessDB] = React.useState<boolean | null>(null);
  const [subscriptionExpiresAt, setSubscriptionExpiresAt] = React.useState<string | null>(null);
  const [loadingData, setLoadingData] = React.useState(false);
  const [dashError, setDashError] = React.useState(false);
  const [editingStamp, setEditingStamp] = React.useState<Stamp | null>(null);
  const [editingSubscription, setEditingSubscription] = React.useState<Subscription | null>(null);
  const [savingDaysBefore, setSavingDaysBefore] = React.useState<string | null>(null);
  const [cancelling, setCancelling] = React.useState<string | null>(null);
  const [deletingStamp, setDeletingStamp] = React.useState<string | null>(null);
  const [showClaimGuide, setShowClaimGuide] = React.useState(false);
  const [showSubscribeGuide, setShowSubscribeGuide] = React.useState(false);
  const [balanceCents, setBalanceCents] = React.useState(0);
  const [membershipPlan, setMembershipPlan] = React.useState<string | null>(null);
  const [orders, setOrders] = React.useState<Order[]>([]);
  const [loadingOrders, setLoadingOrders] = React.useState(false);
  const [plans, setPlans] = React.useState<Plan[]>([]);
  const [loadingPlans, setLoadingPlans] = React.useState(false);
  const [redeemCode, setRedeemCode] = React.useState("");
  const [redeeming, setRedeeming] = React.useState(false);
  const [contactMsg, setContactMsg] = React.useState("");
  const [contactCategory, setContactCategory] = React.useState(() => t("contact.cat_payment"));
  const [contactSending, setContactSending] = React.useState(false);
  const [contactSent, setContactSent] = React.useState(false);
  const [inviteCodeInput, setInviteCodeInput] = React.useState("");
  const [applyingCode, setApplyingCode] = React.useState(false);
  const [editingName, setEditingName] = React.useState(false);
  const [nameValue, setNameValue] = React.useState("");
  const [savingName, setSavingName] = React.useState(false);
  const [editingEmail, setEditingEmail] = React.useState(false);
  const [emailValue, setEmailValue] = React.useState("");
  const [savingEmail, setSavingEmail] = React.useState(false);
  const [showPwdSection, setShowPwdSection] = React.useState(false);
  const [currentPwd, setCurrentPwd] = React.useState("");
  const [newPwd, setNewPwd] = React.useState("");
  const [confirmPwd, setConfirmPwd] = React.useState("");
  const [showCurrent, setShowCurrent] = React.useState(false);
  const [showNew, setShowNew] = React.useState(false);
  const [savingPwd, setSavingPwd] = React.useState(false);
  const [avatarColor, setAvatarColor] = React.useState("violet");
  const [editingAvatar, setEditingAvatar] = React.useState(false);
  const [savingAvatar, setSavingAvatar] = React.useState(false);

  React.useEffect(() => {
    if (status === "unauthenticated") router.replace("/login");
  }, [status, router]);

  React.useEffect(() => {
    if (status !== "authenticated") return;
    if ((session?.user as any)?.subscriptionAccess) {
      setTab("subscriptions");
    }
  }, [status, session]);

  // Apply fetched dashboard data and auto-heal session if subscriptionAccess is stale
  const applyDashData = React.useCallback((d: DashData) => {
    setSubscriptions(d.subscriptions);
    setStamps(d.stamps);
    setSubscriptionAccessDB(d.subscriptionAccess);
    setSubscriptionExpiresAt((d as any).subscriptionExpiresAt ?? null);
    setBalanceCents((d as any).balanceCents ?? 0);
    setMembershipPlan((d as any).membershipPlan ?? null);
    // Heal the JWT if DB says TRUE but session says FALSE — no re-login needed
    if (d.subscriptionAccess && !(session?.user as any)?.subscriptionAccess) {
      updateSession({ refreshSubscription: true });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, updateSession]);

  React.useEffect(() => {
    if (status !== "authenticated") return;

    // Serve cached data immediately so the UI is populated on re-visits
    if (_dashCache && Date.now() - _dashCacheTs < DASH_CACHE_TTL) {
      applyDashData(_dashCache);
      // Still refresh in background without a visible spinner
      fetchDashData().then(applyDashData).catch(() => {});
      return;
    }

    setDashError(false);
    setLoadingData(true);
    fetchDashData()
      .then(applyDashData)
      .catch(() => setDashError(true))
      .finally(() => setLoadingData(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  // Load orders and plans when membership tab opens
  React.useEffect(() => {
    if (tab === "membership" && status === "authenticated") {
      if (orders.length === 0) {
        setLoadingOrders(true);
        fetch("/api/user/orders")
          .then(r => r.json())
          .then(d => { if (d.orders) setOrders(d.orders); })
          .catch(() => {})
          .finally(() => setLoadingOrders(false));
      }
      if (plans.length === 0) {
        setLoadingPlans(true);
        fetch("/api/payment/plans")
          .then(r => r.json())
          .then(d => { if (Array.isArray(d.plans)) setPlans(d.plans); })
          .catch(() => {})
          .finally(() => setLoadingPlans(false));
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, status]);

  async function handleRedeemCode(e: React.FormEvent) {
    e.preventDefault();
    const code = redeemCode.trim().toUpperCase();
    if (!code) { toast.error(t("dashboard.enter_code")); return; }
    setRedeeming(true);
    try {
      const res = await fetch("/api/user/redeem-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (res.ok) {
        toast.success(data.message || t("dashboard.redeem_success"));
        setRedeemCode("");
        setSubscriptionAccessDB(data.subscriptionAccess ?? subscriptionAccessDB);
        setSubscriptionExpiresAt(data.subscriptionExpiresAt ?? subscriptionExpiresAt);
        setMembershipPlan(data.membershipPlan ?? membershipPlan);
        setBalanceCents(data.balanceCents ?? balanceCents);
        if (data.subscriptionAccess) updateSession({ refreshSubscription: true });
      } else {
        toast.error(data.error || t("dashboard.redeem_failed"));
      }
    } catch {
      toast.error(t("remind.network_error"));
    } finally {
      setRedeeming(false);
    }
  }

  function refreshData() {
    invalidateDashCache();
    fetchDashData().then(applyDashData).catch(() => {});
  }

  async function cancelSubscription(id: string) {
    setCancelling(id);
    try {
      await fetch(`/api/user/subscriptions?id=${id}`, { method: "DELETE" });
      setSubscriptions(prev => prev.map(s => s.id === id ? { ...s, active: false } : s));
      invalidateDashCache();
      toast.success(t("dashboard.sub_cancelled"));
    } catch {
      toast.error(t("dashboard.op_failed"));
    } finally {
      setCancelling(null);
    }
  }

  async function saveDaysBefore(id: string, days: number) {
    setSavingDaysBefore(id);
    try {
      const res = await fetch(`/api/user/subscriptions?id=${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days_before: days }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      setSubscriptions(prev => prev.map(s => s.id === id ? { ...s, days_before: days } : s));
      invalidateDashCache();
      toast.success(t("dashboard.days_before_updated", { days }));
    } catch (e: any) {
      toast.error(e.message || t("dashboard.update_failed"));
    } finally {
      setSavingDaysBefore(null);
    }
  }

  async function deleteStamp(id: string) {
    setDeletingStamp(id);
    try {
      const res = await fetch(`/api/user/stamps?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error((await res.json()).error);
      setStamps(prev => prev.filter(s => s.id !== id));
      invalidateDashCache();
      toast.success(t("dashboard.stamp_deleted"));
    } catch (e: any) {
      toast.error(e.message || t("dashboard.delete_failed"));
    } finally {
      setDeletingStamp(null);
    }
  }

  function exportSubscriptionsCSV() {
    const activeSubs = subscriptions.filter(s => s.active);
    if (activeSubs.length === 0) { toast.info(t("dashboard.csv_empty")); return; }
    const rows = [
      [t("dashboard.csv_domain"), t("dashboard.csv_expiry"), t("dashboard.csv_phase"), t("dashboard.csv_days"), t("dashboard.csv_drop"), t("dashboard.csv_advance"), t("dashboard.csv_last_reminded"), t("dashboard.csv_created")],
      ...activeSubs.map(s => [
        s.domain,
        s.expiration_date ? new Date(s.expiration_date).toLocaleDateString() : t("dashboard.unknown"),
        s.phase ?? t("dashboard.unknown"),
        s.days_to_expiry !== null ? String(s.days_to_expiry) : "—",
        s.drop_date ? new Date(s.drop_date).toLocaleDateString() : "—",
        String(s.days_before ?? 30),
        s.last_reminded_at ? new Date(s.last_reminded_at).toLocaleDateString() : t("dashboard.never"),
        new Date(s.created_at).toLocaleDateString(),
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "domain-subscriptions.csv"; a.click();
    URL.revokeObjectURL(url);
    toast.success(t("dashboard.csv_exported", { count: activeSubs.length }));
  }

  function daysUntilExpiry(sub: Subscription): number | null {
    return sub.days_to_expiry ?? null;
  }

  const AVATAR_COLORS: { key: string; bg: string; text: string; label: string }[] = [
    { key: "violet", bg: "bg-violet-500", text: "text-white", label: "Aa" },
    { key: "blue",   bg: "bg-blue-500",   text: "text-white", label: "Aa" },
    { key: "emerald",bg: "bg-emerald-500",text: "text-white", label: "Aa" },
    { key: "orange", bg: "bg-orange-500", text: "text-white", label: "Aa" },
    { key: "pink",   bg: "bg-pink-500",   text: "text-white", label: "Aa" },
    { key: "red",    bg: "bg-red-500",    text: "text-white", label: "Aa" },
    { key: "yellow", bg: "bg-yellow-400", text: "text-black", label: "Aa" },
    { key: "slate",  bg: "bg-slate-600",  text: "text-white", label: "Aa" },
  ];

  React.useEffect(() => {
    if (status === "authenticated") {
      fetch("/api/user/profile")
        .then(r => r.json())
        .then(data => {
          if (data.user?.avatar_color) setAvatarColor(data.user.avatar_color);
        })
        .catch(() => {});
    }
  }, [status]);

  async function saveName() {
    setSavingName(true);
    try {
      const res = await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: nameValue }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      await updateSession({ name: nameValue.trim() || null });
      toast.success(t("dashboard.name_updated"));
      setEditingName(false);
    } catch (e: any) {
      toast.error(e.message || t("dashboard.update_failed"));
    } finally {
      setSavingName(false);
    }
  }

  async function saveEmail() {
    if (!emailValue.trim()) { toast.error(t("dashboard.enter_email")); return; }
    setSavingEmail(true);
    try {
      const res = await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailValue.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      await updateSession({ email: emailValue.trim().toLowerCase() });
      toast.success(t("dashboard.email_updated"));
      setEditingEmail(false);
    } catch (e: any) {
      toast.error(e.message || t("dashboard.update_failed"));
    } finally {
      setSavingEmail(false);
    }
  }

  async function changePassword() {
    if (!currentPwd) { toast.error(t("dashboard.enter_current_pwd")); return; }
    if (newPwd.length < 8) { toast.error(t("dashboard.pwd_min_length")); return; }
    if (newPwd !== confirmPwd) { toast.error(t("dashboard.pwd_mismatch")); return; }
    setSavingPwd(true);
    try {
      const res = await fetch("/api/user/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: currentPwd, newPassword: newPwd }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(t("dashboard.pwd_updated"));
      setShowPwdSection(false);
      setCurrentPwd(""); setNewPwd(""); setConfirmPwd("");
    } catch (e: any) {
      toast.error(e.message || t("dashboard.change_failed"));
    } finally {
      setSavingPwd(false);
    }
  }

  async function saveAvatarColor(color: string) {
    setSavingAvatar(true);
    try {
      await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ avatar_color: color }),
      });
      setAvatarColor(color);
      setEditingAvatar(false);
    } catch {
      toast.error(t("dashboard.avatar_save_failed"));
    } finally {
      setSavingAvatar(false);
    }
  }

  async function handleApplyInviteCode(e: React.FormEvent) {
    e.preventDefault();
    if (!inviteCodeInput.trim()) { toast.error(t("dashboard.enter_invite_code")); return; }
    setApplyingCode(true);
    try {
      const res = await fetch("/api/user/apply-invite-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inviteCode: inviteCodeInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        const errMsg = data.error || t("dashboard.invite_code_invalid");
        if (errMsg === "你已拥有订阅权限") {
          setSubscriptionAccessDB(true);
          await updateSession({ refreshSubscription: true });
          setInviteCodeInput("");
          setTab("subscriptions");
          toast.success(t("dashboard.already_has_access"));
          return;
        }
        toast.error(errMsg);
        return;
      }
      toast.success(t("dashboard.invite_code_success"));
      setSubscriptionAccessDB(true);
      await updateSession({ refreshSubscription: true });
      setInviteCodeInput("");
      setTab("subscriptions");
    } catch {
      toast.error(t("dashboard.op_failed_retry"));
    } finally {
      setApplyingCode(false);
    }
  }

  if (status === "loading" || status === "unauthenticated") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const user = session!.user!;
  const isAdminUser = (user as any)?.email?.toLowerCase?.()?.trim?.() === ADMIN_EMAIL;

  // Computed stats
  const activeSubs = subscriptions.filter(s => s.active);
  const expiringSoon = activeSubs.filter(s => {
    const d = daysUntilExpiry(s);
    return d !== null && d >= 0 && d <= 30;
  });
  const urgentSubs = activeSubs.filter(s => {
    const d = daysUntilExpiry(s);
    const dd = s.days_to_drop;
    return (d !== null && d >= 0 && d <= 7) || (dd !== null && dd >= 0 && dd <= 7);
  });
  const postExpirySubs = activeSubs.filter(s => s.phase && s.phase !== "active");
  const verifiedStamps = stamps.filter(s => s.verified);

  const TABS = [
    { key: "subscriptions" as const, label: t("dashboard.tab_subscriptions"), icon: <RiCalendarLine className="w-3.5 h-3.5" />, count: activeSubs.length || undefined },
    { key: "stamps" as const, label: t("dashboard.tab_stamps"), icon: <RiShieldCheckLine className="w-3.5 h-3.5" />, count: stamps.length || undefined },
    { key: "membership" as const, label: t("dashboard.tab_membership"), icon: <RiVipCrownLine className="w-3.5 h-3.5" /> },
    { key: "account" as const, label: t("dashboard.tab_account"), icon: <RiUserLine className="w-3.5 h-3.5" /> },
  ];


  return (
    <>
      <Head><title key="title">{`${t("nav_dashboard")} · ${siteSettings.site_logo_text || "X.RW"}`}</title></Head>
      {showClaimGuide && <ClaimGuideModal onClose={() => setShowClaimGuide(false)} />}
      {showSubscribeGuide && <SubscribeGuideModal onClose={() => setShowSubscribeGuide(false)} />}
      {editingStamp && (
        <EditStampModal stamp={editingStamp} onClose={() => setEditingStamp(null)} onSaved={refreshData} isMember={!!subscriptionAccessDB} />
      )}
      {editingSubscription && (
        <EditExpiryModal
          sub={editingSubscription}
          onClose={() => setEditingSubscription(null)}
          onSaved={(newDate) => {
            setSubscriptions(prev => prev.map(s =>
              s.id === editingSubscription.id ? { ...s, expiration_date: newDate } : s
            ));
            invalidateDashCache();
          }}
        />
      )}

      <div className="max-w-2xl mx-auto px-4 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              {t("nav_dashboard")}
              {isAdminUser && (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-gradient-to-r from-violet-500/20 to-indigo-500/20 text-violet-700 dark:text-violet-300 font-bold border border-violet-200/50 dark:border-violet-700/30 uppercase tracking-wider">
                  {t("founder")}
                </span>
              )}
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">{user.email}</p>
          </div>
          <div className="flex items-center gap-2">
            {isAdminUser && (
              <Link href="/admin"
                className="flex items-center gap-1.5 text-xs text-violet-600 dark:text-violet-400 hover:bg-violet-50 dark:hover:bg-violet-950/30 transition-colors px-3 py-1.5 rounded-lg font-semibold">
                <RiShieldUserLine className="w-3.5 h-3.5" />
                {t("nav_admin")}
              </Link>
            )}
            <button onClick={() => signOut({ callbackUrl: "/" })}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors px-3 py-1.5 rounded-lg hover:bg-muted">
              <RiLogoutBoxLine className="w-3.5 h-3.5" />
              {t("sign_out")}
            </button>
          </div>
        </div>

        {/* Stats overview bar */}
        {!loadingData && (activeSubs.length > 0 || stamps.length > 0) && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div className="glass-panel border border-border rounded-xl px-3 py-2.5 flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                <RiCalendarLine className="w-3.5 h-3.5 text-primary" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{activeSubs.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_active_subs")}</p>
              </div>
            </div>
            <div className={cn(
              "glass-panel border rounded-xl px-3 py-2.5 flex items-center gap-2.5",
              urgentSubs.length > 0 ? "border-red-300/60 bg-red-50/40 dark:bg-red-950/20" :
              expiringSoon.length > 0 ? "border-amber-300/60 bg-amber-50/40 dark:bg-amber-950/20" : "border-border"
            )}>
              <div className={cn("w-7 h-7 rounded-lg flex items-center justify-center shrink-0",
                urgentSubs.length > 0 ? "bg-red-100 dark:bg-red-950/40" :
                expiringSoon.length > 0 ? "bg-amber-100 dark:bg-amber-950/40" : "bg-muted"
              )}>
                <RiFireLine className={cn("w-3.5 h-3.5",
                  urgentSubs.length > 0 ? "text-red-500" :
                  expiringSoon.length > 0 ? "text-amber-500" : "text-muted-foreground"
                )} />
              </div>
              <div>
                <p className={cn("text-base font-bold leading-none",
                  urgentSubs.length > 0 ? "text-red-600 dark:text-red-400" :
                  expiringSoon.length > 0 ? "text-amber-600 dark:text-amber-400" : ""
                )}>{expiringSoon.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_expiring_30")}</p>
              </div>
            </div>
            <div className="glass-panel border border-border rounded-xl px-3 py-2.5 flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center shrink-0">
                <RiShieldCheckLine className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{verifiedStamps.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_verified_brands")}</p>
              </div>
            </div>
          </div>
        )}

        {/* Tab switcher */}
        <div className="flex rounded-xl bg-muted/40 border border-border/50 p-1 gap-1">
          {TABS.map(t => (
            <button key={t.key} type="button" onClick={() => setTab(t.key)}
              className={cn(
                "flex-1 flex items-center justify-center gap-1.5 py-2 px-1 rounded-lg text-xs font-semibold transition-all",
                tab === t.key
                  ? "bg-background shadow-sm text-foreground border border-border/60"
                  : "text-muted-foreground hover:text-foreground"
              )}>
              {t.icon}
              <span className="hidden sm:inline">{t.label}</span>
              {t.count !== undefined && (
                <span className={cn(
                  "text-[10px] font-bold px-1 py-0 rounded-full min-w-[16px] text-center leading-4",
                  tab === t.key ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
                )}>{t.count}</span>
              )}
            </button>
          ))}
        </div>

        <AnimatePresence mode="wait">
          {/* ── Subscriptions ── */}
          {tab === "subscriptions" && (
            <motion.div key="subscriptions" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18 }} className="space-y-3">
              {!(subscriptionAccessDB ?? (user as any).subscriptionAccess) && (
                <div className="space-y-5 py-4">
                  <div className="flex flex-col items-center text-center space-y-3">
                    <div className="w-14 h-14 rounded-2xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200/60 dark:border-amber-700/40 flex items-center justify-center">
                      <RiLockLine className="w-6 h-6 text-amber-500" />
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
                  <form onSubmit={handleApplyInviteCode} className="space-y-2">
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
              {(subscriptionAccessDB ?? (user as any).subscriptionAccess) && <>
              {/* Header */}
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{t("dashboard.sub_section_title")}</p>
                <div className="flex items-center gap-2">
                  {activeSubs.length > 0 && (
                    <button
                      onClick={exportSubscriptionsCSV}
                      className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1 px-2 py-1 rounded-lg hover:bg-muted transition-colors"
                    >
                      <RiDownloadLine className="w-3 h-3" />{t("dashboard.export_csv")}
                    </button>
                  )}
                  <button
                    onClick={() => setShowSubscribeGuide(true)}
                    className="text-[11px] text-primary hover:underline flex items-center gap-1"
                  >
                    <RiCalendarLine className="w-3 h-3" />{t("dashboard.new_sub")}
                  </button>
                </div>
              </div>

              {/* Subscription membership expiry */}
              {subscriptionExpiresAt && (
                <div className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-violet-50 dark:bg-violet-950/20 border border-violet-200/50 dark:border-violet-700/30 text-[11px] text-violet-700 dark:text-violet-400">
                  <RiVipCrownLine className="w-3 h-3 shrink-0" />
                  <span>{t("dashboard.member_until")} <span className="font-semibold font-mono">{new Date(subscriptionExpiresAt).toLocaleDateString()}</span></span>
                </div>
              )}

              {/* In-tab stats chips */}
              {activeSubs.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400 text-[10px] font-semibold border border-emerald-200/50 dark:border-emerald-700/30">
                    <RiCheckLine className="w-2.5 h-2.5" />{activeSubs.length} {t("dashboard.chip_active")}
                  </span>
                  {expiringSoon.length > 0 && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400 text-[10px] font-semibold border border-amber-200/50 dark:border-amber-700/30">
                      <RiTimerLine className="w-2.5 h-2.5" />{expiringSoon.length} {t("dashboard.chip_expiring")}
                    </span>
                  )}
                  {urgentSubs.length > 0 && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-400 text-[10px] font-semibold border border-red-200/50 dark:border-red-700/30">
                      <RiFireLine className="w-2.5 h-2.5" />{urgentSubs.length} {t("dashboard.chip_urgent")}
                    </span>
                  )}
                  {postExpirySubs.length > 0 && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400 text-[10px] font-semibold border border-orange-200/50 dark:border-orange-700/30">
                      <RiAlertLine className="w-2.5 h-2.5" />{postExpirySubs.length} {t("dashboard.chip_expired")}
                    </span>
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

              {/* Post-expiry phase alert */}
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
                  <Button size="sm" variant="outline" className="rounded-xl text-xs gap-1.5" onClick={() => {
                    setDashError(false); setLoadingData(true);
                    fetchDashData().then(applyDashData).catch(() => setDashError(true)).finally(() => setLoadingData(false));
                  }}>{t("dashboard.reload")}</Button>
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
                    <Button
                      variant="default"
                      size="sm"
                      className="rounded-xl text-xs gap-1.5"
                      onClick={() => setShowSubscribeGuide(true)}
                    >
                      <RiBellLine className="w-3.5 h-3.5" />{t("dashboard.how_to_sub")}
                    </Button>
                    <Link href="/remind" className="text-[11px] text-muted-foreground hover:text-primary underline underline-offset-2">
                      {t("dashboard.go_sub_mgmt")}
                    </Link>
                  </div>
                </div>
              ) : [...subscriptions]
                .sort((a, b) => {
                  if (!a.active && b.active) return 1;
                  if (a.active && !b.active) return -1;
                  const da = daysUntilExpiry(a) ?? 9999;
                  const db = daysUntilExpiry(b) ?? 9999;
                  return da - db;
                })
                .map(sub => {
                const phase = sub.phase;
                const phaseInfo = phase ? PHASE_LABEL[phase] : null;
                const days = daysUntilExpiry(sub);
                const daysDropping = sub.days_to_drop;
                const isDropSoon = sub.active && daysDropping !== null && daysDropping >= 0 && daysDropping <= 7 && phase !== "active";
                const isUrgent = sub.active && ((days !== null && days >= 0 && days <= 7) || isDropSoon);
                const isWarn = sub.active && days !== null && days >= 0 && days <= 30 && !isUrgent;
                const isPostExpiry = sub.active && phase && phase !== "active";

                // Lifecycle progress bar (days remaining / 365)
                const barPct = (days !== null && days > 0 && phase === "active")
                  ? Math.min(100, Math.round((days / 365) * 100))
                  : 0;
                const barColor = isUrgent ? "bg-red-500" : isWarn ? "bg-amber-500" : days !== null && days <= 90 ? "bg-yellow-500" : "bg-emerald-500";

                // Reminder info
                const nextReminderDate = sub.next_reminder_at ? new Date(sub.next_reminder_at) : null;
                const lastReminderDate = sub.last_reminded_at ? new Date(sub.last_reminded_at) : null;
                const daysSinceLastReminder = lastReminderDate
                  ? Math.floor((Date.now() - lastReminderDate.getTime()) / 86400000)
                  : null;
                const nextReminderIsUpcoming = nextReminderDate && nextReminderDate > new Date();

                // Phase guidance text
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
                    {/* Card header: icon + domain name + badges + actions */}
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
                              {days === 0 ? t("dashboard.expires_today") : t("dashboard.expires_in_days", { days: days ?? 0 })}
                            </span>
                          )}
                          {isWarn && !isUrgent && !isPostExpiry && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 font-semibold border border-amber-300/50">
                              {t("dashboard.expires_in_days", { days: days ?? 0 })}
                            </span>
                          )}
                          {isDropSoon && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-purple-100 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400 font-semibold border border-purple-300/50">
                              {daysDropping === 0 ? t("dashboard.drop_today") : t("dashboard.drop_in_days", { days: daysDropping })}
                            </span>
                          )}
                          {phaseInfo && phase !== "active" && (
                            <span className={cn("text-[10px] font-semibold px-1.5 py-0.5 rounded-md border", phaseInfo.color,
                              phase === "grace" ? "bg-amber-50 dark:bg-amber-950/30 border-amber-300/50" :
                              phase === "redemption" ? "bg-orange-50 dark:bg-orange-950/30 border-orange-300/50" :
                              phase === "pendingDelete" ? "bg-purple-50 dark:bg-purple-950/30 border-purple-300/50" :
                              "bg-muted border-border/50"
                            )}>{t(("dashboard.phase_" + phase) as any)}</span>
                          )}
                        </div>
                        <p className="text-[11px] text-muted-foreground mt-0.5 flex items-center gap-1">
                          <RiTimeLine className="w-3 h-3 shrink-0" />
                          {sub.expiration_date
                            ? t("dashboard.expires_on", { date: fmt(new Date(sub.expiration_date)) })
                            : t("dashboard.expiry_not_set")}
                        </p>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          onClick={() => setEditingSubscription(sub)}
                          title={t("dashboard.edit_expiry_title")}
                          className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                          <RiEdit2Line className="w-3.5 h-3.5" />
                        </button>
                        <Link href={`/${sub.domain}`} className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                          <RiExternalLinkLine className="w-3.5 h-3.5" />
                        </Link>
                        {sub.active && (
                          <button onClick={() => cancelSubscription(sub.id)} disabled={cancelling === sub.id}
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
                            {days !== null && days > 0 ? t("dashboard.n_days", { days }) : days === 0 ? t("dashboard.expires_today") : t("dashboard.expired")}
                          </span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all", barColor)}
                            style={{ width: `${barPct}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Phase-specific guidance for post-expiry domains */}
                    {isPostExpiry && phase && phaseGuidance[phase] && (
                      <div className="px-3 py-2 rounded-lg bg-orange-50 dark:bg-orange-950/20 border border-orange-200/50 dark:border-orange-700/30">
                        <p className="text-[11px] text-orange-700 dark:text-orange-300 leading-relaxed">
                          {phaseGuidance[phase]}
                        </p>
                      </div>
                    )}

                    {/* Reminder info section */}
                    {sub.active && (
                      <div className="pt-2 border-t border-border/40 space-y-2">
                        {/* Next reminder */}
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <RiCalendarLine className="w-3 h-3 text-muted-foreground shrink-0" />
                            <span className="text-[11px] text-muted-foreground truncate">
                              {nextReminderIsUpcoming
                                ? <>{t("dashboard.next_reminder")} <span className="font-medium text-foreground">{fmt(nextReminderDate!)}</span></>
                                : phase === "dropped"
                                  ? t("dashboard.no_pending_reminder")
                                  : t("dashboard.no_reminder")
                              }
                            </span>
                          </div>
                          {sub.next_reminder_days !== null && sub.next_reminder_days !== undefined && nextReminderIsUpcoming && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-primary/8 text-primary font-semibold shrink-0 tabular-nums">
                              {t("dashboard.advance_days", { days: sub.next_reminder_days })}
                            </span>
                          )}
                        </div>

                        {/* Last reminded */}
                        <div className="flex items-center gap-1.5">
                          <RiMailLine className="w-3 h-3 text-muted-foreground shrink-0" />
                          <span className="text-[11px] text-muted-foreground">
                            {daysSinceLastReminder !== null
                              ? daysSinceLastReminder === 0
                                ? <>{t("dashboard.last_reminded_today")}</>
                                : <>{t("dashboard.last_reminded_days_ago", { days: daysSinceLastReminder })}</>
                              : t("dashboard.never_reminded")}
                          </span>
                        </div>

                        {/* days_before inline editor */}
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[10px] text-muted-foreground">{t("dashboard.reminder_threshold")}</span>
                          {[7, 14, 30, 60, 90].map(d => (
                            <button
                              key={d}
                              disabled={savingDaysBefore === sub.id}
                              onClick={() => saveDaysBefore(sub.id, d)}
                              className={cn(
                                "text-[10px] px-2 py-0.5 rounded-full border transition-colors font-semibold",
                                sub.days_before === d
                                  ? "bg-primary text-primary-foreground border-primary"
                                  : "bg-muted/50 text-muted-foreground border-border hover:border-primary/50 hover:text-foreground"
                              )}
                            >
                              {savingDaysBefore === sub.id && sub.days_before === d
                                ? "…"
                                : t("dashboard.n_days_abbr", { days: d })}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Lifecycle dates (server-computed) */}
                    {sub.drop_date && sub.expiration_date && (
                      <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border/40">
                        <div className="text-center">
                          <p className="text-[10px] text-muted-foreground mb-0.5">{t("dashboard.grace_end")}</p>
                          <p className={cn("text-[11px] font-semibold tabular-nums", phase === "grace" ? "text-amber-600 dark:text-amber-400" : "text-foreground")}>
                            {sub.grace_end ? fmt(new Date(sub.grace_end)) : "—"}
                          </p>
                        </div>
                        <div className="text-center">
                          <p className="text-[10px] text-muted-foreground mb-0.5">{t("dashboard.redemption_end")}</p>
                          <p className={cn("text-[11px] font-semibold tabular-nums", phase === "redemption" ? "text-orange-600 dark:text-orange-400" : "text-foreground")}>
                            {sub.redemption_end ? fmt(new Date(sub.redemption_end)) : "—"}
                          </p>
                        </div>
                        <div className="text-center">
                          <p className="text-[10px] text-muted-foreground mb-0.5">{t("dashboard.estimated_drop")}</p>
                          <p className={cn("text-[11px] font-semibold tabular-nums", phase === "pendingDelete" || isDropSoon ? "text-purple-600 dark:text-purple-400" : "text-foreground")}>
                            {fmt(new Date(sub.drop_date))}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
              </>}
            </motion.div>
          )}

          {/* ── Stamps ── */}
          {tab === "stamps" && (
            <motion.div key="stamps" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18 }} className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{t("dashboard.stamps_section_title")}</p>
                <button
                  onClick={() => setShowClaimGuide(true)}
                  className="text-xs text-primary hover:underline flex items-center gap-1"
                >
                  <RiShieldCheckLine className="w-3 h-3" />{t("dashboard.claim_new_domain")}
                </button>
              </div>
              {loadingData ? (
                <div className="flex justify-center py-8"><RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" /></div>
              ) : dashError ? (
                <div className="flex flex-col items-center py-10 gap-3 text-center">
                  <RiAlertLine className="w-7 h-7 text-destructive/60" />
                  <p className="text-sm text-muted-foreground">{t("dashboard.load_failed")}</p>
                  <Button size="sm" variant="outline" className="rounded-xl text-xs gap-1.5" onClick={() => {
                    setDashError(false); setLoadingData(true);
                    fetchDashData().then(applyDashData).catch(() => setDashError(true)).finally(() => setLoadingData(false));
                  }}>{t("dashboard.reload")}</Button>
                </div>
              ) : stamps.length === 0 ? (
                <div className="text-center py-12 space-y-4">
                  <div className="w-14 h-14 rounded-2xl bg-violet-500/8 border border-dashed border-border flex items-center justify-center mx-auto">
                    <RiShieldCheckLine className="w-7 h-7 text-muted-foreground/40" />
                  </div>
                  <div className="space-y-1.5">
                    <p className="text-sm font-semibold">{t("dashboard.no_stamps")}</p>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {t("dashboard.no_stamps_desc")}
                    </p>
                  </div>
                  <Button
                    variant="default"
                    size="sm"
                    className="rounded-xl text-xs gap-1.5"
                    onClick={() => setShowClaimGuide(true)}
                  >
                    <RiShieldCheckLine className="w-3.5 h-3.5" />{t("dashboard.how_to_claim")}
                  </Button>
                </div>
              ) : stamps.map(stamp => (
                <div key={stamp.id} className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold">{stamp.domain}</p>
                        <TagBadge style={stamp.tag_style} name={stamp.tag_name} />
                        {stamp.verified
                          ? <span className="flex items-center gap-0.5 text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">
                              <RiCheckLine className="w-3 h-3" />{t("dashboard.verified")}
                            </span>
                          : <span className="flex items-center gap-0.5 text-[10px] text-amber-600 dark:text-amber-400 font-semibold">
                              <RiTimeLine className="w-3 h-3" />{t("dashboard.pending_verify")}
                            </span>
                        }
                      </div>
                      <p className="text-[11px] text-muted-foreground mt-1">
                        {t("dashboard.nickname_prefix")}{stamp.nickname}
                        {stamp.link && <> · <a href={stamp.link} target="_blank" rel="noopener noreferrer" className="hover:underline">{stamp.link}</a></>}
                      </p>
                      {stamp.description && (
                        <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{stamp.description}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {!stamp.verified && (
                        <Link href={`/stamp?domain=${stamp.domain}`}>
                          <button className="p-1.5 rounded-lg hover:bg-violet-50 dark:hover:bg-violet-950/30 text-muted-foreground hover:text-violet-500 transition-colors" title={t("dashboard.go_verify")}>
                            <RiFlashlightLine className="w-3.5 h-3.5" />
                          </button>
                        </Link>
                      )}
                      <button onClick={() => setEditingStamp(stamp)}
                        className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                        <RiPencilLine className="w-3.5 h-3.5" />
                      </button>
                      <Link href={`/${stamp.domain}`} className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                        <RiExternalLinkLine className="w-3.5 h-3.5" />
                      </Link>
                      <button
                        onClick={() => deleteStamp(stamp.id)}
                        disabled={deletingStamp === stamp.id}
                        title={t("dashboard.delete_stamp_title")}
                        className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors">
                        {deletingStamp === stamp.id
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                  {!stamp.verified && (
                    <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-amber-50/50 dark:bg-amber-950/20 border border-amber-200/40">
                      <RiAlertLine className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <p className="text-[11px] text-muted-foreground">{t("dashboard.stamp_unverified_hint")}</p>
                    </div>
                  )}
                </div>
              ))}
            </motion.div>
          )}

          {/* ── Membership ── */}
          {tab === "membership" && (() => {
            // While dashboard data is still loading, show a skeleton to prevent flash
            if (subscriptionAccessDB === null && loadingData) {
              return (
                <motion.div key="membership-loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4 animate-pulse">
                  <div className="h-28 rounded-2xl bg-muted/50" />
                  <div className="h-36 rounded-2xl bg-muted/50" />
                  <div className="h-24 rounded-2xl bg-muted/50" />
                </motion.div>
              );
            }
            const isLifetime = subscriptionAccessDB && !subscriptionExpiresAt;
            const expiresDate = subscriptionExpiresAt ? new Date(subscriptionExpiresAt) : null;
            const remainingDays = expiresDate ? Math.ceil((expiresDate.getTime() - Date.now()) / 86_400_000) : null;
            const currencyCode = (siteSettings.payment_currency || "CNY").toUpperCase();
            const CURRENCY_SYM: Record<string, string> = { CNY: "¥", USD: "$", EUR: "€", HKD: "HK$" };
            const balanceSym = CURRENCY_SYM[currencyCode] ?? currencyCode + " ";
            const STATUS_CLS: Record<string, string> = {
              paid: "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200/60 dark:border-emerald-700/40",
              pending: "text-amber-600 bg-amber-50 dark:bg-amber-950/30 border-amber-200/60 dark:border-amber-700/40",
              failed: "text-red-600 bg-red-50 dark:bg-red-950/30 border-red-200/60 dark:border-red-700/40",
              expired: "text-muted-foreground bg-muted border-border",
            };
            const PROVIDER_LABEL: Record<string, string> = {
              stripe: t("dashboard.provider_stripe"), xunhupay: t("dashboard.provider_xunhupay"), alipay: t("dashboard.provider_alipay"), paypal: "PayPal",
            };
            return (
              <motion.div key="membership" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18 }} className="space-y-4">

                {/* ── 会员状态卡 ── */}
                <div className={cn(
                  "glass-panel border rounded-2xl overflow-hidden",
                  subscriptionAccessDB ? "border-violet-200/60 dark:border-violet-700/30" : "border-border"
                )}>
                  {/* Header */}
                  <div className={cn(
                    "px-4 pt-4 pb-3 flex items-center gap-3",
                    subscriptionAccessDB ? "bg-violet-50/60 dark:bg-violet-950/10" : ""
                  )}>
                    <div className={cn(
                      "w-10 h-10 rounded-xl flex items-center justify-center shrink-0",
                      subscriptionAccessDB ? "bg-violet-100 dark:bg-violet-900/30" : "bg-muted"
                    )}>
                      <RiVipCrownLine className={cn("w-5 h-5", subscriptionAccessDB ? "text-violet-600 dark:text-violet-400" : "text-muted-foreground")} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-bold">
                        {subscriptionAccessDB
                          ? (membershipPlan || t("dashboard.member_active_label"))
                          : t("dashboard.non_member")}
                      </p>
                      {subscriptionAccessDB ? (
                        <p className="text-[10px] text-muted-foreground">
                          {isLifetime ? t("dashboard.lifetime_member") : expiresDate
                            ? t("dashboard.valid_until_details", { date: expiresDate.toLocaleDateString(), days: remainingDays ?? 0 })
                            : t("dashboard.in_membership")}
                        </p>
                      ) : (
                        <p className="text-[10px] text-muted-foreground">{t("dashboard.upgrade_sub_desc")}</p>
                      )}
                    </div>
                    {subscriptionAccessDB && (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-300 shrink-0">
                        {isLifetime ? t("dashboard.lifetime_badge") : t("dashboard.active_badge")}
                      </span>
                    )}
                  </div>

                  {/* Balance row */}
                  <div className="px-4 py-3 border-t border-border/60 flex items-center justify-between">
                    <span className="text-[11px] text-muted-foreground flex items-center gap-1.5">
                      <RiWalletLine className="w-3.5 h-3.5" /> {t("dashboard.balance")}
                    </span>
                    <span className="text-sm font-bold font-mono">
                      {balanceSym}{(balanceCents / 100).toFixed(2)}
                    </span>
                  </div>
                </div>

                {/* ── 会员权益说明 ── */}
                {!subscriptionAccessDB && (
                  <div className="glass-panel border border-violet-200/50 dark:border-violet-800/30 rounded-2xl overflow-hidden">
                    <div className="px-4 pt-3 pb-2 bg-violet-50/50 dark:bg-violet-950/10 flex items-center gap-2 border-b border-violet-100/60 dark:border-violet-800/20">
                      <RiVipCrownLine className="w-3.5 h-3.5 text-violet-500" />
                      <p className="text-xs font-bold">{t("dashboard.upgrade_title")}</p>
                    </div>
                    <div className="px-4 py-3 grid grid-cols-1 gap-1.5">
                      {[
                        { icon: RiBellLine,         text: t("dashboard.benefit_subs") },
                        { icon: RiShieldCheckLine,  text: t("dashboard.benefit_styles") },
                        { icon: RiExternalLinkLine, text: t("dashboard.benefit_links") },
                        { icon: RiEdit2Line,        text: t("dashboard.benefit_tag_len") },
                        { icon: RiBarChartLine,     text: t("dashboard.benefit_history") },
                        { icon: RiFlashlightLine,   text: t("dashboard.benefit_priority") },
                      ].map((item, i) => (
                        <div key={i} className="flex items-start gap-2.5">
                          <item.icon className="w-3.5 h-3.5 text-violet-500 mt-0.5 shrink-0" />
                          <p className="text-[11px] text-muted-foreground leading-snug">{item.text}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── 购买会员 ── */}
                <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <RiStarLine className="w-3.5 h-3.5 text-violet-500" />
                    <p className="text-xs font-semibold">{t("dashboard.buy_membership")}</p>
                    {plans.length > 0 && !paymentEnabled && (
                      <span className="text-[10px] text-muted-foreground/60 ml-auto">激活码可兑换</span>
                    )}
                  </div>

                  {loadingPlans ? (
                    <div className="grid grid-cols-3 gap-2 animate-pulse">
                      {[1, 2, 3].map(i => <div key={i} className="h-[72px] rounded-xl bg-muted/50" />)}
                    </div>
                  ) : plans.length > 0 ? (() => {
                    const totalPlans = plans.length;
                    const getBadge = (idx: number) => {
                      if (totalPlans >= 3 && idx === totalPlans - 1) return t("dashboard.plan_badge_best_value");
                      if (totalPlans >= 3 && idx === totalPlans - 2) return t("dashboard.plan_badge_recommended");
                      if (totalPlans === 2 && idx === 1) return t("dashboard.plan_badge_best_value");
                      return null;
                    };
                    const fmtDur = (p: Plan) => {
                      if (!p.duration_days) return t("dashboard.plan_lifetime_period");
                      return `${p.duration_days}天`;
                    };
                    const fmtPrice = (p: Plan) => {
                      const sym = p.currency?.toUpperCase() === "CNY" ? "¥" : p.currency?.toUpperCase() === "USD" ? "$" : (p.currency ?? "¥");
                      return `${sym}${p.price.toFixed(2).replace(/\.00$/, "")}`;
                    };
                    const cols = totalPlans <= 2 ? "grid-cols-2" : totalPlans === 4 ? "grid-cols-2" : "grid-cols-3";
                    return (
                      <div className={cn("grid gap-2", cols)}>
                        {plans.map((p, idx) => {
                          const badge = getBadge(idx);
                          const isHighlight = !!badge;
                          return (
                            <Link
                              key={p.id}
                              href={`/payment/checkout?plan=${p.id}`}
                              className={cn(
                                "relative flex flex-col items-center gap-1 px-2 py-3 rounded-xl border text-center transition-all group hover:border-violet-400/60 hover:bg-violet-50/50 dark:hover:bg-violet-950/10",
                                isHighlight ? "border-violet-300/70 dark:border-violet-700/40 bg-violet-50/30 dark:bg-violet-950/10" : "border-border"
                              )}
                            >
                              {badge && (
                                <span className="absolute -top-2 left-1/2 -translate-x-1/2 text-[8px] font-bold px-1.5 py-0.5 rounded-full bg-violet-500 text-white whitespace-nowrap">
                                  {badge}
                                </span>
                              )}
                              <RiVipCrownLine className={cn("w-4 h-4", isHighlight ? "text-violet-500" : "text-muted-foreground group-hover:text-violet-500")} />
                              <p className="text-[10px] font-semibold leading-tight line-clamp-1">{p.name}</p>
                              <p className="text-[9px] text-muted-foreground">{fmtDur(p)}</p>
                              <p className="text-[10px] font-bold text-violet-600 dark:text-violet-400 mt-0.5">{fmtPrice(p)}</p>
                            </Link>
                          );
                        })}
                      </div>
                    );
                  })() : (
                    <div className="grid grid-cols-3 gap-2 opacity-40 pointer-events-none">
                      {[
                        { label: t("dashboard.plan_monthly"), sub: t("dashboard.plan_monthly_period"), badge: null },
                        { label: t("dashboard.plan_yearly"), sub: t("dashboard.plan_yearly_period"), badge: t("dashboard.plan_badge_recommended") },
                        { label: t("dashboard.plan_lifetime"), sub: t("dashboard.plan_lifetime_period"), badge: t("dashboard.plan_badge_best_value") },
                      ].map(p => (
                        <div key={p.label} className={cn(
                          "relative flex flex-col items-center gap-1 px-2 py-3 rounded-xl border text-center",
                          p.badge === t("dashboard.plan_badge_recommended") ? "border-violet-300/70 dark:border-violet-700/40 bg-violet-50/30 dark:bg-violet-950/10" : "border-border"
                        )}>
                          {p.badge && (
                            <span className="absolute -top-2 left-1/2 -translate-x-1/2 text-[8px] font-bold px-1.5 py-0.5 rounded-full bg-violet-500 text-white whitespace-nowrap">
                              {p.badge}
                            </span>
                          )}
                          <RiVipCrownLine className="w-4 h-4 text-muted-foreground" />
                          <p className="text-[10px] font-semibold leading-tight">{p.label}</p>
                          <p className="text-[9px] text-muted-foreground">{p.sub}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  <Link href="/payment/checkout" className="flex items-center justify-center gap-1.5 text-[11px] text-muted-foreground hover:text-foreground transition-colors py-1">
                    {t("dashboard.view_all_plans")} <RiArrowRightLine className="w-3 h-3" />
                  </Link>
                  {!paymentEnabled && (
                    <p className="text-[10px] text-muted-foreground/60 text-center -mt-1">{t("dashboard.payment_note")}</p>
                  )}
                </div>

                {/* ── 激活码兑换 ── */}
                <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <RiCoupon2Line className="w-3.5 h-3.5 text-amber-500" />
                    <p className="text-xs font-semibold">{t("dashboard.activation_code")}</p>
                  </div>
                  <form onSubmit={handleRedeemCode} className="flex gap-2">
                    <Input
                      value={redeemCode}
                      onChange={e => setRedeemCode(e.target.value.toUpperCase())}
                      placeholder={t("dashboard.activation_placeholder")}
                      className="h-9 rounded-xl text-sm font-mono flex-1"
                    />
                    <Button type="submit" disabled={redeeming || !redeemCode.trim()} size="sm" className="h-9 rounded-xl px-3 shrink-0">
                      {redeeming ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiGiftLine className="w-4 h-4" />}
                    </Button>
                  </form>
                  <p className="text-[10px] text-muted-foreground">{t("dashboard.activation_note")}</p>
                </div>

                {/* ── 购买记录 ── */}
                <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-border/60 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <RiFileTextLine className="w-3.5 h-3.5 text-muted-foreground" />
                      <p className="text-xs font-semibold">{t("dashboard.order_history")}</p>
                    </div>
                    <button
                      onClick={() => {
                        setLoadingOrders(true);
                        fetch("/api/user/orders").then(r => r.json()).then(d => {
                          if (d.orders) setOrders(d.orders);
                        }).catch(() => {}).finally(() => setLoadingOrders(false));
                      }}
                      className="text-[10px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
                    >
                      <RiRefreshLine className={cn("w-3 h-3", loadingOrders && "animate-spin")} />
                      {t("dashboard.refresh")}
                    </button>
                  </div>

                  {loadingOrders ? (
                    <div className="p-4 space-y-3 animate-pulse">
                      {[1,2].map(i => <div key={i} className="h-14 rounded-xl bg-muted/50" />)}
                    </div>
                  ) : orders.length === 0 ? (
                    <div className="px-4 py-8 text-center text-[11px] text-muted-foreground">
                      <RiCoinLine className="w-7 h-7 mx-auto mb-2 text-muted-foreground/30" />
                      {t("dashboard.no_orders")}
                    </div>
                  ) : (
                    <div className="divide-y divide-border/50">
                      {orders.map(o => (
                        <div key={o.id} className="px-4 py-3 flex items-center gap-3">
                          <div className={cn(
                            "w-7 h-7 rounded-lg flex items-center justify-center shrink-0",
                            o.status === "paid" ? "bg-emerald-50 dark:bg-emerald-950/30" : "bg-muted"
                          )}>
                            {o.status === "paid"
                              ? <RiCheckboxCircleLine className="w-4 h-4 text-emerald-500" />
                              : <RiCoinLine className="w-4 h-4 text-muted-foreground" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-semibold truncate">{o.plan_name}</p>
                            <p className="text-[10px] text-muted-foreground">
                              {PROVIDER_LABEL[o.provider] ?? o.provider} · {new Date(o.created_at).toLocaleDateString()}
                            </p>
                          </div>
                          <div className="text-right shrink-0">
                            <p className="text-xs font-bold font-mono">{CURRENCY_SYM[o.currency] ?? ""}{o.amount.toFixed(2)}</p>
                            <span className={cn(
                              "inline-block text-[9px] font-semibold px-1.5 py-0.5 rounded-full border",
                              STATUS_CLS[o.status] ?? STATUS_CLS.expired
                            )}>
                              {o.status === "paid" ? t("dashboard.order_paid") : o.status === "pending" ? t("dashboard.order_pending") : o.status === "failed" ? t("dashboard.order_failed") : t("dashboard.order_expired")}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* ── 联系客服 ── */}
                <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                  <div className="px-4 pt-3 pb-2 border-b border-border/60 flex items-center gap-2">
                    <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />
                    <p className="text-xs font-semibold">{t("contact.title")}</p>
                  </div>
                  {contactSent ? (
                    <div className="px-4 py-5 flex flex-col items-center gap-2 text-center">
                      <RiCheckboxCircleLine className="w-8 h-8 text-emerald-500" />
                      <p className="text-xs font-semibold">{t("contact.sent_title")}</p>
                      <button onClick={() => { setContactSent(false); setContactMsg(""); setContactCategory(t("contact.cat_payment")); }} className="text-[10px] text-muted-foreground hover:text-foreground mt-1">{t("contact.resend")}</button>
                    </div>
                  ) : (
                    <div className="px-4 py-3 space-y-2.5">
                      {/* Category selector */}
                      <div className="space-y-1.5">
                        <p className="text-[10px] font-medium text-muted-foreground">{t("contact.category_label")}</p>
                        <div className="grid grid-cols-2 gap-1.5">
                          {([
                            [t("contact.cat_payment"), "cat_payment"],
                            [t("contact.cat_membership"), "cat_membership"],
                            [t("contact.cat_feature"), "cat_feature"],
                            [t("contact.cat_other"), "cat_other"],
                          ] as [string, string][]).map(([label]) => (
                            <button
                              key={label}
                              type="button"
                              onClick={() => setContactCategory(label)}
                              className={cn(
                                "h-8 rounded-xl text-[11px] font-medium border transition-all",
                                contactCategory === label
                                  ? "bg-foreground text-background border-foreground"
                                  : "bg-muted/30 text-muted-foreground border-border hover:border-muted-foreground/40"
                              )}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                      <textarea
                        value={contactMsg}
                        onChange={e => setContactMsg(e.target.value)}
                        placeholder={t("contact.placeholder")}
                        rows={3}
                        maxLength={500}
                        className="w-full text-sm rounded-xl border border-border bg-background px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-primary/30 transition-shadow placeholder:text-muted-foreground/40"
                      />
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-[10px] text-muted-foreground/60">{t("contact.char_count", { count: contactMsg.length })}</p>
                        <Button
                          size="sm"
                          className="h-8 rounded-xl text-xs gap-1.5 shrink-0"
                          disabled={!contactMsg.trim() || contactSending}
                          onClick={async () => {
                            if (!contactMsg.trim()) return;
                            setContactSending(true);
                            try {
                              const r = await fetch("/api/user/contact", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ category: contactCategory, message: contactMsg }),
                              });
                              if (!r.ok) { toast.error(t("contact.send_failed")); return; }
                              setContactSent(true);
                            } catch {
                              toast.error(t("contact.send_failed"));
                            } finally {
                              setContactSending(false);
                            }
                          }}
                        >
                          {contactSending ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiMailLine className="w-3.5 h-3.5" />}
                          {t("contact.send")}
                        </Button>
                      </div>
                    </div>
                  )}
                </div>

                {/* ── 支付说明 ── */}
                <div className="px-1 text-[10px] text-muted-foreground/60 text-center leading-relaxed">
                  {t("dashboard.payment_methods")}
                </div>
              </motion.div>
            );
          })()}


          {/* ── Account ── */}
          {tab === "account" && (() => {
            const ac = AVATAR_COLORS.find(c => c.key === avatarColor) || AVATAR_COLORS[0];
            const initial = ((user as any).name || user.email || "U").charAt(0).toUpperCase();
            return (
            <motion.div key="account" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18 }} className="space-y-4">

              {/* ── Avatar card ── */}
              <div className="glass-panel border border-border rounded-2xl p-5 flex items-center gap-4">
                <div className="relative shrink-0">
                  <div className={cn("w-16 h-16 rounded-2xl flex items-center justify-center text-2xl font-bold shadow-sm", ac.bg, ac.text)}>
                    {initial}
                  </div>
                  <button
                    onClick={() => setEditingAvatar(v => !v)}
                    className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-background border border-border shadow flex items-center justify-center hover:bg-muted transition-colors"
                  >
                    <RiPaletteLine className="w-3 h-3 text-muted-foreground" />
                  </button>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-bold text-base truncate">{(user as any).name || t("dashboard.nickname_not_set")}</p>
                  <p className="text-xs text-muted-foreground truncate">{user.email}</p>
                  {isAdminUser && (
                    <span className="inline-block mt-1 text-[10px] px-2 py-0.5 rounded-full bg-gradient-to-r from-violet-500/20 to-indigo-500/20 text-violet-700 dark:text-violet-300 font-bold border border-violet-200/50 dark:border-violet-700/30 uppercase tracking-wider">
                      {t("founder")}
                    </span>
                  )}
                </div>
              </div>

              {/* Color picker */}
              {editingAvatar && (
                <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("dashboard.select_avatar_color")}</p>
                  <div className="flex gap-2 flex-wrap">
                    {AVATAR_COLORS.map(c => (
                      <button
                        key={c.key}
                        onClick={() => saveAvatarColor(c.key)}
                        disabled={savingAvatar}
                        className={cn(
                          "w-9 h-9 rounded-xl font-bold text-xs transition-all",
                          c.bg, c.text,
                          avatarColor === c.key ? "ring-2 ring-offset-2 ring-primary scale-110" : "opacity-70 hover:opacity-100 hover:scale-105"
                        )}
                      >
                        {savingAvatar && avatarColor === c.key ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mx-auto" /> : c.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Profile fields ── */}
              <div className="glass-panel border border-border rounded-2xl divide-y divide-border/50">

                {/* Name */}
                <div className="px-4 py-3 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 shrink-0">
                    <RiUserLine className="w-3.5 h-3.5 text-muted-foreground" />
                    <p className="text-xs text-muted-foreground">{t("dashboard.nickname_field")}</p>
                  </div>
                  {editingName ? (
                    <div className="flex items-center gap-2 flex-1 justify-end">
                      <Input
                        value={nameValue}
                        onChange={e => setNameValue(e.target.value)}
                        maxLength={50}
                        className="h-7 rounded-lg text-xs w-36"
                        autoFocus
                        onKeyDown={e => { if (e.key === "Enter") saveName(); if (e.key === "Escape") setEditingName(false); }}
                      />
                      <button onClick={saveName} disabled={savingName} className="p-1.5 rounded-lg hover:bg-muted text-emerald-600 transition-colors">
                        {savingName ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiCheckLine className="w-3.5 h-3.5" />}
                      </button>
                      <button onClick={() => setEditingName(false)} className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground transition-colors">
                        <RiCloseLine className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <p className="text-xs font-semibold">{(user as any).name || t("dashboard.not_set")}</p>
                      <button onClick={() => { setNameValue((user as any).name || ""); setEditingName(true); }}
                        className="p-1 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                        <RiPencilLine className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>

                {/* Email */}
                <div className="px-4 py-3 space-y-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 shrink-0">
                      <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />
                      <p className="text-xs text-muted-foreground">{t("dashboard.email_field")}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <p className="text-xs font-semibold truncate max-w-[160px]">{user.email}</p>
                      {!editingEmail && (
                        <button onClick={() => { setEmailValue(user.email || ""); setEditingEmail(true); }}
                          className="p-1 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                          <RiPencilLine className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                  {editingEmail && (
                    <div className="space-y-2 pt-1">
                      <Input
                        type="email"
                        value={emailValue}
                        onChange={e => setEmailValue(e.target.value)}
                        placeholder={t("dashboard.new_email_placeholder")}
                        className="h-8 rounded-xl text-xs"
                        autoFocus
                      />
                      <p className="text-[10px] text-amber-600 dark:text-amber-400">{t("dashboard.email_change_warn")}</p>
                      <div className="flex gap-2">
                        <Button size="sm" onClick={saveEmail} disabled={savingEmail} className="h-7 text-xs rounded-lg gap-1 flex-1">
                          {savingEmail ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiCheckLine className="w-3 h-3" />}
                          {t("dashboard.confirm_change")}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setEditingEmail(false)} className="h-7 text-xs rounded-lg">{t("dashboard.cancel")}</Button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Stats */}
                {[
                  { label: t("dashboard.domain_sub_count"), value: t("dashboard.active_count", { n: subscriptions.filter(s => s.active).length }) },
                  { label: t("dashboard.brand_claim_count"), value: t("dashboard.brand_count", { n: stamps.length, v: stamps.filter(s => s.verified).length }) },
                ].map(row => (
                  <div key={row.label} className="flex items-center justify-between px-4 py-3">
                    <p className="text-xs text-muted-foreground">{row.label}</p>
                    <p className="text-xs font-semibold">{row.value}</p>
                  </div>
                ))}
              </div>

              {/* ── Change password ── */}
              <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                <button
                  onClick={() => { setShowPwdSection(v => !v); setCurrentPwd(""); setNewPwd(""); setConfirmPwd(""); }}
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/40 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <RiLockLine className="w-3.5 h-3.5 text-muted-foreground" />
                    <p className="text-xs font-semibold">{t("dashboard.change_password")}</p>
                  </div>
                  <RiPencilLine className="w-3.5 h-3.5 text-muted-foreground" />
                </button>
                {showPwdSection && (
                  <div className="border-t border-border px-4 py-4 space-y-3">
                    {[
                      { label: t("dashboard.current_password"), value: currentPwd, onChange: setCurrentPwd, show: showCurrent, toggle: () => setShowCurrent(v => !v) },
                      { label: t("dashboard.new_password_min"), value: newPwd, onChange: setNewPwd, show: showNew, toggle: () => setShowNew(v => !v) },
                      { label: t("dashboard.confirm_new_password"), value: confirmPwd, onChange: setConfirmPwd, show: showNew, toggle: () => {} },
                    ].map((f, i) => (
                      <div key={i} className="space-y-1">
                        <Label className="text-[11px] text-muted-foreground">{f.label}</Label>
                        <div className="relative">
                          <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
                          <Input
                            type={f.show ? "text" : "password"}
                            value={f.value}
                            onChange={e => f.onChange(e.target.value)}
                            className="pl-8 pr-8 h-9 rounded-xl text-xs"
                          />
                          {i < 2 && (
                            <button type="button" onClick={f.toggle}
                              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground transition-colors">
                              {f.show ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                    <div className="flex gap-2 pt-1">
                      <Button onClick={changePassword} disabled={savingPwd} className="flex-1 h-9 rounded-xl text-xs gap-1.5">
                        {savingPwd ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.changing")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.confirm_modify")}</>}
                      </Button>
                      <Button variant="outline" onClick={() => setShowPwdSection(false)} className="h-9 rounded-xl text-xs">{t("dashboard.cancel")}</Button>
                    </div>
                  </div>
                )}
              </div>

              {/* ── Danger zone ── */}
              <button onClick={() => signOut({ callbackUrl: "/" })}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl border border-red-200/50 bg-red-50/40 dark:bg-red-950/20 text-red-600 dark:text-red-400 text-sm font-semibold hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors">
                <RiLogoutBoxLine className="w-4 h-4" />
                {t("sign_out")}
              </button>
            </motion.div>
            );
          })()}
        </AnimatePresence>
      </div>
    </>
  );
}
