import React from "react";
import { createPortal } from "react-dom";
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
  RiRefreshLine, RiInformationLine, RiAddLine, RiSubtractLine, RiArrowDownSLine,
} from "@remixicon/react";
import { RiBankCardLine, RiStarLine } from "@remixicon/react";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import type { HistoryItem } from "@/lib/history";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import { StampPreviewCard, STAMP_CARD_THEMES } from "@/components/stamp-preview-card";
import { SubscriptionsTab } from "@/components/dashboard/SubscriptionsTab";
import { StampsTab } from "@/components/dashboard/StampsTab";
import { MembershipTab } from "@/components/dashboard/MembershipTab";
import { AccountTab } from "@/components/dashboard/AccountTab";

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
  thresholds: number[];
  phase_flags: Record<string, boolean>;
  nameservers: string[];
  registrar: string | null;
  creation_date: string | null;
  whois_synced_at: string | null;
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

type BalanceTx = {
  id: number;
  amount_cents: number;
  type: string;
  description: string | null;
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
  balance_grant_cents: number;
};

type Stamp = {
  id: string; domain: string; tag_name: string; tag_style: string; card_theme: string;
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

function fmt(d: Date, locale?: string) {
  return d.toLocaleDateString(locale, { year: "numeric", month: "2-digit", day: "2-digit" });
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
  const [cardTheme, setCardTheme] = React.useState(stamp.card_theme || "app");
  const [link, setLink] = React.useState(stamp.link || "");
  const [description, setDescription] = React.useState(stamp.description || "");
  const [nickname, setNickname] = React.useState(stamp.nickname);
  const [saving, setSaving] = React.useState(false);
  const [themePickerOpen, setThemePickerOpen] = React.useState(false);
  const { t, locale } = useTranslation();
  const isZh = locale.startsWith("zh");

  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  async function handleSave() {
    setSaving(true);
    try {
      const res = await fetch(`/api/user/stamps?id=${stamp.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tagName, tagStyle, cardTheme, link, description, nickname }),
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

  const curTheme = STAMP_CARD_THEMES[cardTheme];
  const selStyle = EDIT_TAG_STYLES.find(ts => ts.value === tagStyle) || EDIT_TAG_STYLES[0];

  return createPortal(
    <>
      {/* ── Theme picker overlay ── */}
      {themePickerOpen && (
        <div className="fixed inset-0 z-[80] flex flex-col items-stretch" style={{ background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}>
          <div className="flex-1" onClick={() => setThemePickerOpen(false)} />
          <div className="bg-background rounded-t-2xl shadow-2xl max-h-[82vh] flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
              <div>
                <p className="font-bold text-base">{isZh ? "选择弹窗样式" : "Card Theme"}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{isZh ? "点击样式即可选中并关闭" : "Tap to select"}</p>
              </div>
              <button type="button" onClick={() => setThemePickerOpen(false)}
                className="w-8 h-8 flex items-center justify-center rounded-xl hover:bg-muted transition-colors text-muted-foreground">
                <RiCloseLine className="w-4 h-4" />
              </button>
            </div>
            <div className="overflow-y-auto px-5 py-4 space-y-5">
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-3">{isZh ? "标准配色" : "Standard"}</p>
                <div className="grid grid-cols-4 gap-2">
                  {Object.entries(STAMP_CARD_THEMES).filter(([, th]) => !th.special).map(([key, th]) => (
                    <button key={key} type="button"
                      onClick={() => { setCardTheme(key); setThemePickerOpen(false); }}
                      className={cn(
                        "flex flex-col items-center gap-1.5 p-2.5 rounded-xl border-2 transition-all active:scale-[0.97]",
                        cardTheme === key ? "border-primary bg-primary/5" : "border-transparent hover:border-border hover:bg-muted/40"
                      )}>
                      <span className={cn("w-full h-6 rounded-lg", th.hero)} />
                      <span className="text-[10px] font-semibold leading-none">{th.label}</span>
                      {cardTheme === key && <span className="text-[8px] text-primary font-bold uppercase tracking-widest">{isZh ? "已选" : "✓"}</span>}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-3">
                  {isZh ? "特殊排版" : "Special layouts"} <span className="normal-case font-normal opacity-60">· {isZh ? "实际效果预览" : "preview"}</span>
                </p>
                <div className="grid grid-cols-2 gap-3">
                  {Object.entries(STAMP_CARD_THEMES).filter(([, th]) => !!th.special).map(([key, th]) => (
                    <button key={key} type="button"
                      onClick={() => { setCardTheme(key); setThemePickerOpen(false); }}
                      className={cn(
                        "flex flex-col gap-2 rounded-xl border-2 overflow-hidden transition-all active:scale-[0.97]",
                        cardTheme === key ? "border-primary" : "border-transparent hover:border-border"
                      )}>
                      <div className="pointer-events-none scale-[0.72] origin-top-left w-[138.8%]">
                        <StampPreviewCard themeKey={key} />
                      </div>
                      <div className="flex items-center justify-between px-2 pb-2 -mt-[28%]">
                        <span className="text-[11px] font-semibold">{th.special} {th.label}</span>
                        {cardTheme === key && <span className="text-[9px] text-primary font-bold uppercase tracking-widest">{isZh ? "已选" : "✓"}</span>}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
              <div className="pb-safe" />
            </div>
          </div>
        </div>
      )}

      <div
        className="fixed inset-0 z-[70] flex items-end sm:items-center justify-center"
        style={{ paddingTop: "calc(var(--ann-h, 0px) + 4.5rem)" }}
      >
        <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
        <div
          className="relative w-full max-w-md bg-background border border-border rounded-t-2xl sm:rounded-2xl shadow-2xl flex flex-col overflow-hidden"
          style={{ maxHeight: "calc(100dvh - var(--ann-h, 0px) - 4.5rem)" }}
        >
          {/* Header — always visible, never scrolled away */}
          <div className="flex items-center justify-between px-6 pt-5 pb-4 shrink-0">
            <h2 className="text-base font-bold flex items-center gap-2">
              <RiPencilLine className="w-4 h-4 text-primary" />{t("dashboard.edit_stamp_title")}
            </h2>
            <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
              <RiCloseLine className="w-5 h-5 text-muted-foreground" />
            </button>
          </div>

          {/* Scrollable content — fills remaining space between header and footer */}
          <div className="flex-1 overflow-y-auto overscroll-contain px-6 pb-2 space-y-3" style={{ minHeight: 0 }}>
            <p className="text-xs text-muted-foreground">{t("dashboard.domain_label")}<span className="font-mono text-foreground">{stamp.domain}</span></p>

            {/* Tag name */}
            <div className="space-y-1.5">
              <div className="flex items-baseline justify-between">
                <Label className="text-xs font-semibold">{t("dashboard.tag_label")}</Label>
                {!isMember && <span className="text-[10px] text-amber-500">{t("dashboard.tag_limit_free")}</span>}
              </div>
              <Input value={tagName} onChange={e => setTagName(e.target.value)} maxLength={isMember ? 32 : 5} className="h-9 rounded-xl text-sm" />
            </div>

            {/* Tag style */}
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
            </div>

            {/* Card theme picker */}
            <div className="space-y-1.5">
              <Label className="text-xs font-semibold">{isZh ? "弹窗样式" : "Card Theme"}</Label>
              <button type="button" onClick={() => setThemePickerOpen(true)}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl border border-border bg-muted/30 hover:bg-muted/60 transition-colors text-left">
                <span className={cn("w-5 h-5 rounded-md shrink-0 overflow-hidden flex items-center justify-center text-xs", curTheme?.hero ?? "bg-zinc-700")}>
                  {curTheme?.special && <span className="leading-none">{curTheme.special}</span>}
                </span>
                <span className="text-sm font-medium flex-1">
                  {curTheme?.label ?? cardTheme}
                  {curTheme?.special && <span className="ml-1.5 text-muted-foreground text-xs font-normal">· {isZh ? "特殊排版" : "special"}</span>}
                </span>
                <span className="text-[11px] text-muted-foreground font-medium shrink-0">{isZh ? "点击更换 ›" : "Change ›"}</span>
              </button>
            </div>

            {/* Nickname */}
            <div className="space-y-1.5">
              <Label className="text-xs font-semibold">{t("dashboard.nickname")}</Label>
              <Input value={nickname} onChange={e => setNickname(e.target.value)} maxLength={50} className="h-9 rounded-xl text-sm" />
            </div>

            {/* Link + description (members only) */}
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

            {/* ── Live popup preview ── */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <RiEyeLine className="w-3.5 h-3.5 text-muted-foreground" />
                <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">{isZh ? "弹窗实际效果" : "Preview"}</span>
                <div className="flex-1 h-px bg-border/50" />
              </div>
              <div className="rounded-2xl overflow-hidden shadow-sm border border-border/30">
                <StampPreviewCard
                  themeKey={cardTheme || "app"}
                  data={{
                    tagName: tagName || stamp.tag_name,
                    domain: stamp.domain,
                    description: description || undefined,
                    link: link || undefined,
                    tagLabel: isZh ? (selStyle.zhLabel) : selStyle.enLabel,
                    icon: selStyle.icon,
                  }}
                />
              </div>
            </div>
            <div className="h-1" />
          </div>

          {/* Footer buttons — always visible */}
          <div className="flex gap-2 px-6 py-4 border-t border-border/50 shrink-0">
            <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
            <Button onClick={handleSave} disabled={saving} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
              {saving ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.save")}</>}
            </Button>
          </div>
        </div>
      </div>
    </>,
    document.body
  );
}

// ── Edit Subscription Expiry Modal ────────────────────────────────────────────
function EditExpiryModal({ sub, onClose, onSaved }: { sub: Subscription; onClose: () => void; onSaved: (newDate: string) => void }) {
  const [dateValue, setDateValue] = React.useState(
    sub.expiration_date ? sub.expiration_date.slice(0, 10) : ""
  );
  const [saving, setSaving] = React.useState(false);
  const { t } = useTranslation();

  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

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

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center"
      style={{ padding: "calc(var(--ann-h, 0px) + 4.5rem) 1rem 1rem" }}
    >
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div
        className="relative w-full max-w-sm bg-background border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        style={{ maxHeight: "calc(100dvh - var(--ann-h, 0px) - 5.5rem)" }}
      >
        <div className="flex items-center justify-between px-6 pt-5 pb-4 shrink-0">
          <h2 className="text-base font-bold flex items-center gap-2">
            <RiCalendarLine className="w-4 h-4 text-primary" />{t("dashboard.edit_expiry_title")}
          </h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto overscroll-contain px-6 pb-2 space-y-4" style={{ minHeight: 0 }}>
          <p className="text-xs text-muted-foreground">{t("dashboard.domain_label")}<span className="font-mono text-foreground">{sub.domain}</span></p>
          <div className="space-y-1.5">
            <Label className="text-xs font-semibold">{t("dashboard.expiry_date")}</Label>
            <Input type="date" value={dateValue} onChange={e => setDateValue(e.target.value)} className="h-9 rounded-xl text-sm" />
          </div>
        </div>
        <div className="flex gap-2 px-6 py-4 border-t border-border/50 shrink-0">
          <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
          <Button onClick={handleSave} disabled={saving} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
            {saving ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.save")}</>}
          </Button>
        </div>
      </div>
    </div>,
    document.body
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
interface SearchStats {
  total: number;
  today: number;
  thisWeek: number;
  available: number;
  highValue: number;
  topType: string | null;
}

interface DashData {
  subscriptions: Subscription[];
  stamps: Stamp[];
  /** DB-authoritative — heals stale JWTs automatically */
  subscriptionAccess: boolean;
  searchStats: SearchStats | null;
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
    searchStats: data.searchStats ?? null,
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
  const { t, locale } = useTranslation();
  const { data: session, status, update: updateSession } = useSession();
  const siteSettings = useSiteSettings();
  const paymentEnabled = !!(siteSettings.payment_stripe_enabled || siteSettings.payment_xunhupay_enabled || siteSettings.payment_alipay_enabled || siteSettings.payment_paypal_enabled);
  const [tab, setTab] = React.useState<"subscriptions" | "stamps" | "account" | "membership">("stamps");
  const [subFilter, setSubFilter] = React.useState<"all" | "expiring" | "urgent" | "expired">("all");
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
  const [balanceTxs, setBalanceTxs] = React.useState<BalanceTx[]>([]);
  const [showBalanceTxs, setShowBalanceTxs] = React.useState(false);
  const [loadingBalanceTxs, setLoadingBalanceTxs] = React.useState(false);
  const [plans, setPlans] = React.useState<Plan[]>([]);
  const [loadingPlans, setLoadingPlans] = React.useState(false);
  const [redeemCode, setRedeemCode] = React.useState("");
  const [redeeming, setRedeeming] = React.useState(false);
  const [contactMsg, setContactMsg] = React.useState("");
  const [contactCategory, setContactCategory] = React.useState(() => t("contact.cat_payment"));
  const [contactSending, setContactSending] = React.useState(false);
  const [contactSent, setContactSent] = React.useState(false);
  const [subSearch, setSubSearch] = React.useState("");
  const [emailChangeCode, setEmailChangeCode] = React.useState("");
  const [sendingChangeCode, setSendingChangeCode] = React.useState(false);
  const [changeCodeCooldown, setChangeCodeCooldown] = React.useState(0);
  const [showDeleteConfirm, setShowDeleteConfirm] = React.useState(false);
  const [deleteConfirmEmail, setDeleteConfirmEmail] = React.useState("");
  const [deletingAccount, setDeletingAccount] = React.useState(false);
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
  const [searchStats, setSearchStats] = React.useState<SearchStats | null>(null);

  React.useEffect(() => {
    if (status === "unauthenticated") router.replace("/login?callbackUrl=/dashboard");
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
    setSearchStats(d.searchStats ?? null);
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

  async function sendEmailChangeCode() {
    if (!emailValue.trim()) return;
    setSendingChangeCode(true);
    try {
      const res = await fetch("/api/user/send-email-change-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ newEmail: emailValue.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(t("dashboard.code_sent"));
      let countdown = 60;
      setChangeCodeCooldown(countdown);
      const timer = setInterval(() => {
        countdown--;
        setChangeCodeCooldown(countdown);
        if (countdown <= 0) clearInterval(timer);
      }, 1000);
    } catch (e: any) {
      toast.error(e.message || t("dashboard.send_failed"));
    } finally {
      setSendingChangeCode(false);
    }
  }

  async function saveEmail() {
    if (!emailValue.trim()) { toast.error(t("dashboard.enter_email")); return; }
    if (!emailChangeCode.trim()) { toast.error(t("dashboard.code_required")); return; }
    setSavingEmail(true);
    try {
      const res = await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailValue.trim(), emailChangeCode: emailChangeCode.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      await updateSession({ email: emailValue.trim().toLowerCase() });
      toast.success(t("dashboard.email_updated"));
      setEditingEmail(false);
      setEmailChangeCode("");
      setChangeCodeCooldown(0);
    } catch (e: any) {
      toast.error(e.message || t("dashboard.update_failed"));
    } finally {
      setSavingEmail(false);
    }
  }

  async function deleteAccount() {
    if (deleteConfirmEmail.toLowerCase().trim() !== user?.email?.toLowerCase()) {
      toast.error(t("dashboard.email_confirm_mismatch"));
      return;
    }
    setDeletingAccount(true);
    try {
      const res = await fetch("/api/user/delete-account", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmEmail: deleteConfirmEmail.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(t("dashboard.account_deleted"));
      await signOut({ callbackUrl: "/" });
    } catch (e: any) {
      toast.error(e.message || t("dashboard.delete_account_failed"));
    } finally {
      setDeletingAccount(false);
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

  function retryLoad() {
    setDashError(false);
    setLoadingData(true);
    fetchDashData().then(applyDashData).catch(() => setDashError(true)).finally(() => setLoadingData(false));
  }

  if (status === "unauthenticated") return null;

  if (status === "loading") {
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

  const filteredSubscriptions = [...subscriptions]
    .filter(s => {
      if (subSearch.trim() && !s.domain.toLowerCase().includes(subSearch.trim().toLowerCase())) return false;
      if (subFilter === "all") return true;
      const d = daysUntilExpiry(s);
      const dd = s.days_to_drop;
      if (subFilter === "urgent") return s.active && ((d !== null && d >= 0 && d <= 7) || (dd !== null && dd >= 0 && dd <= 7));
      if (subFilter === "expiring") return s.active && d !== null && d >= 0 && d <= 30;
      if (subFilter === "expired") return !!(s.active && s.phase && s.phase !== "active");
      return true;
    })
    .sort((a, b) => {
      if (!a.active && b.active) return 1;
      if (a.active && !b.active) return -1;
      const da = daysUntilExpiry(a) ?? 9999;
      const db = daysUntilExpiry(b) ?? 9999;
      return da - db;
    });


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
            <button
              type="button"
              onClick={() => { setTab("subscriptions"); setSubFilter("all"); }}
              className="glass-panel border border-border rounded-xl px-3 py-2.5 flex items-center gap-2.5 text-left hover:border-primary/40 hover:bg-primary/5 transition-colors"
            >
              <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                <RiCalendarLine className="w-3.5 h-3.5 text-primary" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{activeSubs.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_active_subs")}</p>
              </div>
            </button>
            <button
              type="button"
              onClick={() => { setTab("subscriptions"); setSubFilter(urgentSubs.length > 0 ? "urgent" : "expiring"); }}
              className={cn(
                "glass-panel border rounded-xl px-3 py-2.5 flex items-center gap-2.5 text-left transition-colors",
                urgentSubs.length > 0 ? "border-red-300/60 bg-red-50/40 dark:bg-red-950/20 hover:bg-red-100/40 dark:hover:bg-red-950/30" :
                expiringSoon.length > 0 ? "border-amber-300/60 bg-amber-50/40 dark:bg-amber-950/20 hover:bg-amber-100/40 dark:hover:bg-amber-950/30" : "border-border hover:border-primary/40 hover:bg-primary/5"
              )}
            >
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
            </button>
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
          {TABS.map(tabItem => (
            <button key={tabItem.key} type="button" onClick={() => setTab(tabItem.key)}
              className={cn(
                "relative flex-1 flex items-center justify-center gap-1.5 py-2 px-1 rounded-lg text-xs font-semibold transition-colors duration-150",
                tab === tabItem.key ? "text-foreground" : "text-muted-foreground hover:text-foreground"
              )}>
              {tab === tabItem.key && (
                <motion.div
                  layoutId="dashTabActive"
                  className="absolute inset-0 bg-background shadow-sm border border-border/60 rounded-lg"
                  transition={{ type: "spring", stiffness: 450, damping: 38 }}
                />
              )}
              <span className="relative z-10 flex items-center gap-1.5">
                {tabItem.icon}
                <span className="hidden sm:inline">{tabItem.label}</span>
                {tabItem.count !== undefined && (
                  <span className={cn(
                    "text-[10px] font-bold px-1 py-0 rounded-full min-w-[16px] text-center leading-4",
                    tab === tabItem.key ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
                  )}>{tabItem.count}</span>
                )}
              </span>
            </button>
          ))}
        </div>

        <AnimatePresence mode="wait">
          {/* ── Subscriptions ── */}
          {tab === "subscriptions" && (
            <SubscriptionsTab
              subscriptionAccessDB={subscriptionAccessDB}
              subscriptions={subscriptions}
              filteredSubscriptions={filteredSubscriptions}
              loadingData={loadingData}
              dashError={dashError}
              subSearch={subSearch}
              subFilter={subFilter}
              subscriptionExpiresAt={subscriptionExpiresAt}
              activeSubs={activeSubs}
              expiringSoon={expiringSoon}
              urgentSubs={urgentSubs}
              postExpirySubs={postExpirySubs}
              cancelling={cancelling}
              inviteCodeInput={inviteCodeInput}
              applyingCode={applyingCode}
              paymentEnabled={paymentEnabled}
              user={user}
              locale={locale}
              t={t}
              setSubSearch={setSubSearch}
              setSubFilter={setSubFilter}
              onShowSubscribeGuide={() => setShowSubscribeGuide(true)}
              onExportCSV={exportSubscriptionsCSV}
              onCancelSubscription={cancelSubscription}
              onEditSubscription={setEditingSubscription}
              onApplyInviteCode={handleApplyInviteCode}
              setInviteCodeInput={setInviteCodeInput}
              onRetryLoad={retryLoad}
            />
          )}

          {/* ── Stamps ── */}
          {tab === "stamps" && (
            <StampsTab
              stamps={stamps}
              loadingData={loadingData}
              dashError={dashError}
              deletingStamp={deletingStamp}
              t={t}
              onShowClaimGuide={() => setShowClaimGuide(true)}
              onEditStamp={setEditingStamp}
              onDeleteStamp={deleteStamp}
              onRetryLoad={retryLoad}
            />
          )}

          {/* ── Membership ── */}
          {tab === "membership" && (
            <MembershipTab
              subscriptionAccessDB={subscriptionAccessDB}
              subscriptionExpiresAt={subscriptionExpiresAt}
              loadingData={loadingData}
              balanceCents={balanceCents}
              membershipPlan={membershipPlan}
              orders={orders}
              loadingOrders={loadingOrders}
              balanceTxs={balanceTxs}
              showBalanceTxs={showBalanceTxs}
              loadingBalanceTxs={loadingBalanceTxs}
              plans={plans}
              loadingPlans={loadingPlans}
              redeemCode={redeemCode}
              redeeming={redeeming}
              paymentEnabled={paymentEnabled}
              siteSettings={siteSettings}
              t={t}
              setShowBalanceTxs={setShowBalanceTxs}
              setLoadingBalanceTxs={setLoadingBalanceTxs}
              setBalanceTxs={setBalanceTxs}
              setBalanceCents={setBalanceCents}
              setOrders={setOrders}
              setLoadingOrders={setLoadingOrders}
              onRedeemCode={handleRedeemCode}
              setRedeemCode={setRedeemCode}
            />
          )}

          {/* ── Account ── */}
          {tab === "account" && (
            <AccountTab
              user={user}
              isAdminUser={isAdminUser}
              avatarColor={avatarColor}
              editingAvatar={editingAvatar}
              savingAvatar={savingAvatar}
              editingName={editingName}
              nameValue={nameValue}
              savingName={savingName}
              editingEmail={editingEmail}
              emailValue={emailValue}
              savingEmail={savingEmail}
              showPwdSection={showPwdSection}
              currentPwd={currentPwd}
              newPwd={newPwd}
              confirmPwd={confirmPwd}
              showCurrent={showCurrent}
              showNew={showNew}
              savingPwd={savingPwd}
              emailChangeCode={emailChangeCode}
              sendingChangeCode={sendingChangeCode}
              changeCodeCooldown={changeCodeCooldown}
              showDeleteConfirm={showDeleteConfirm}
              deleteConfirmEmail={deleteConfirmEmail}
              deletingAccount={deletingAccount}
              contactMsg={contactMsg}
              contactCategory={contactCategory}
              contactSending={contactSending}
              contactSent={contactSent}
              subscriptions={subscriptions}
              stamps={stamps}
              t={t}
              setEditingAvatar={setEditingAvatar}
              onSaveAvatarColor={saveAvatarColor}
              setEditingName={setEditingName}
              setNameValue={setNameValue}
              onSaveName={saveName}
              setEditingEmail={setEditingEmail}
              setEmailValue={setEmailValue}
              setEmailChangeCode={setEmailChangeCode}
              onSaveEmail={saveEmail}
              onSendEmailChangeCode={sendEmailChangeCode}
              setChangeCodeCooldown={setChangeCodeCooldown}
              setShowPwdSection={setShowPwdSection}
              setCurrentPwd={setCurrentPwd}
              setNewPwd={setNewPwd}
              setConfirmPwd={setConfirmPwd}
              setShowCurrent={setShowCurrent}
              setShowNew={setShowNew}
              onChangePassword={changePassword}
              setContactMsg={setContactMsg}
              setContactCategory={setContactCategory}
              setContactSending={setContactSending}
              setContactSent={setContactSent}
              setShowDeleteConfirm={setShowDeleteConfirm}
              setDeleteConfirmEmail={setDeleteConfirmEmail}
              onDeleteAccount={deleteAccount}
            />
          )}
        </AnimatePresence>
      </div>
    </>
  );
}
