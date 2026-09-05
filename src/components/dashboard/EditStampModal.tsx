import React from "react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import {
  RiLoader4Line, RiCloseLine, RiCheckLine, RiPencilLine,
  RiVipCrownLine, RiLockLine, RiEyeLine,
  RiIdCardLine, RiBuildingLine, RiAwardLine, RiShieldCheckLine,
  RiShakeHandsLine, RiCodeSLine, RiAlertLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import { StampPreviewCard, STAMP_CARD_THEMES } from "@/components/stamp-preview-card";
import type { Stamp } from "@/components/dashboard/types";

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

export { EDIT_TAG_STYLES };

export function EditStampModal({ stamp, onClose, onSaved, isMember }: {
  stamp: Stamp;
  onClose: () => void;
  onSaved: () => void;
  isMember: boolean;
}) {
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
      {themePickerOpen && (
        <div className="fixed inset-0 z-[80] flex flex-col items-stretch" style={{ background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}>
          <div className="flex-1" onClick={() => setThemePickerOpen(false)} />
          <div className="bg-background rounded-t-2xl shadow-2xl max-h-[82vh] flex flex-col">
            <div className="flex items-center justify-between gap-3 px-4 py-4 sm:px-5 border-b border-border shrink-0">
              <div className="min-w-0">
                <p className="font-bold text-base truncate">{isZh ? "选择品牌卡片样式" : "Card Theme"}</p>
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
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(STAMP_CARD_THEMES).filter(([, th]) => !th.special).map(([key, th]) => {
                    const selected = cardTheme === key;
                    return (
                      <button key={key} type="button"
                        onClick={() => { setCardTheme(key); setThemePickerOpen(false); }}
                        aria-pressed={selected}
                        className={cn(
                          "group flex min-w-0 items-center gap-2.5 rounded-xl border p-2.5 text-left transition-colors active:scale-[0.98]",
                          selected ? "border-primary bg-primary/5 ring-1 ring-primary/20" : "border-border/60 hover:border-primary/40 hover:bg-muted/40"
                        )}>
                        <span className={cn("h-9 w-9 shrink-0 rounded-lg shadow-inner", th.hero)} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-xs font-semibold">{th.label}</span>
                          <span className="mt-0.5 block text-[9px] text-muted-foreground">{key}</span>
                        </span>
                        <span className={cn("flex size-4 shrink-0 items-center justify-center rounded-full border", selected ? "border-primary bg-primary text-primary-foreground" : "border-border")}>{selected && <RiCheckLine className="size-3" />}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
              <div>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-3">
                  {isZh ? "特殊排版" : "Special layouts"} <span className="normal-case font-normal opacity-60">· {isZh ? "实际效果预览" : "preview"}</span>
                </p>
                <div className="flex flex-col gap-2">
                  {Object.entries(STAMP_CARD_THEMES).filter(([, th]) => !!th.special).map(([key, th]) => {
                    const selected = cardTheme === key;
                    return (
                      <button key={key} type="button"
                        onClick={() => { setCardTheme(key); setThemePickerOpen(false); }}
                        aria-pressed={selected}
                        className={cn(
                          "flex min-w-0 items-center gap-3 rounded-xl border p-2.5 text-left transition-colors active:scale-[0.99]",
                          selected ? "border-primary bg-primary/5 ring-1 ring-primary/20" : "border-border/60 hover:border-primary/40 hover:bg-muted/40"
                        )}>
                        <div className="pointer-events-none h-16 w-28 shrink-0 overflow-hidden rounded-lg border border-border/40 bg-muted/20">
                          <div className="w-[178px] origin-top-left scale-[0.63]">
                            <StampPreviewCard themeKey={key} />
                          </div>
                        </div>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-xs font-semibold">{th.special} {th.label}</span>
                          <span className="mt-1 block text-[10px] leading-relaxed text-muted-foreground">{isZh ? "独特的品牌展示排版" : "Distinctive card composition"}</span>
                        </span>
                        <span className={cn("flex size-5 shrink-0 items-center justify-center rounded-full border", selected ? "border-primary bg-primary text-primary-foreground" : "border-border")}>{selected && <RiCheckLine className="size-3.5" />}</span>
                      </button>
                    );
                  })}
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
          <div className="flex items-center justify-between px-6 pt-5 pb-4 shrink-0">
            <h2 className="text-base font-bold flex items-center gap-2">
              <RiPencilLine className="w-4 h-4 text-primary" />{t("dashboard.edit_stamp_title")}
            </h2>
            <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
              <RiCloseLine className="w-5 h-5 text-muted-foreground" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto overscroll-contain px-6 pb-2 space-y-3" style={{ minHeight: 0 }}>
            <p className="text-xs text-muted-foreground">{t("dashboard.domain_label")}<span className="font-mono text-foreground">{stamp.domain}</span></p>

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
            </div>

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
