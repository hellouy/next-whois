import React from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiCheckLine,
  RiCloseLine,
  RiVipCrownLine,
  RiIdCardLine,
  RiBuildingLine,
  RiAwardLine,
  RiShieldCheckLine,
  RiShakeHandsLine,
  RiCodeSLine,
  RiAlertLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { StampPreviewCard } from "@/components/stamp-preview-card";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

export const TAG_STYLES: { id: string; label: string; zhName: string; className: string; glow?: string; icon: React.ElementType; theme: string; accent: string }[] = [
  { id: "personal",  label: "Personal",  zhName: "个人",   icon: RiIdCardLine,      className: "bg-zinc-900 text-zinc-100 ring-1 ring-white/[0.07]",                                        glow: "shadow-zinc-800/50",   theme: "app",      accent: "from-zinc-500 via-zinc-700 to-zinc-900"                },
  { id: "official",  label: "Official",  zhName: "官方",   icon: RiBuildingLine,    className: "bg-gradient-to-r from-blue-600 to-blue-800 text-white",                                     glow: "shadow-blue-700/50",   theme: "official", accent: "from-blue-500 via-blue-700 to-indigo-900"              },
  { id: "brand",     label: "Brand",     zhName: "品牌",   icon: RiAwardLine,       className: "bg-gradient-to-r from-violet-600 to-violet-900 text-white",                                 glow: "shadow-violet-600/50", theme: "aurora",   accent: "from-violet-500 via-fuchsia-600 to-pink-600"           },
  { id: "verified",  label: "Verified",  zhName: "认证",   icon: RiShieldCheckLine, className: "bg-gradient-to-r from-emerald-500 to-teal-600 text-white",                                  glow: "shadow-emerald-500/50",theme: "emerald",  accent: "from-emerald-400 via-teal-500 to-teal-700"             },
  { id: "partner",   label: "Partner",   zhName: "合作",   icon: RiShakeHandsLine,  className: "bg-gradient-to-r from-orange-500 to-amber-400 text-white",                                  glow: "shadow-orange-500/50", theme: "solar",    accent: "from-amber-400 via-orange-500 to-orange-600"           },
  { id: "dev",       label: "Dev",       zhName: "开发",   icon: RiCodeSLine,       className: "bg-[#0d1117] text-[#58a6ff] ring-1 ring-[#30363d] font-mono",                               glow: "shadow-slate-900/60",  theme: "dev",      accent: "from-slate-600 via-slate-800 to-black"                 },
  { id: "warning",   label: "Warning",   zhName: "警示",   icon: RiAlertLine,       className: "bg-amber-400 text-amber-950 font-bold ring-1 ring-amber-300/50",                             glow: "shadow-amber-400/50",  theme: "warning",  accent: "from-yellow-300 via-amber-400 to-orange-400"           },
  { id: "premium",   label: "Premium",   zhName: "尊享",   icon: RiVipCrownLine,    className: "bg-gradient-to-r from-purple-600 via-fuchsia-500 to-rose-500 text-white",                   glow: "shadow-fuchsia-500/60",theme: "premium",  accent: "from-purple-500 via-fuchsia-500 to-rose-500"           },
];

interface TagStylePickerProps {
  selectedStyle: string;
  isMember: boolean;
  isZh: boolean;
  tagName: string;
  domain: string;
  description: string;
  link: string;
  onSelect: (styleId: string) => void;
  previewStyleId: string | null;
  onPreviewOpen: (styleId: string) => void;
  onPreviewClose: () => void;
}

export function TagStylePicker({
  selectedStyle,
  isMember,
  isZh,
  tagName,
  domain,
  description,
  link,
  onSelect,
  previewStyleId,
  onPreviewOpen,
  onPreviewClose,
}: TagStylePickerProps) {
  const { t } = useTranslation();
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  return (
    <>
      <div>
        <div className="flex items-center justify-between mb-2.5">
          <label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">{s("tag_style_label")}</label>
          {!isMember
            ? <span className="text-[10px] text-violet-600 dark:text-violet-400 flex items-center gap-1"><RiVipCrownLine className="w-3 h-3" />{s("member_only")}</span>
            : <span className="text-[10px] text-muted-foreground/50">{s("click_preview")}</span>
          }
        </div>
        <div className="grid grid-cols-1 gap-2 min-[390px]:grid-cols-2">
          {TAG_STYLES.map((ts) => {
            const isSelected = selectedStyle === ts.id;
            const Icon = ts.icon;
            const isFree = ts.id === "personal";
            const locked = !isMember && !isFree;
            return (
              <button
                key={ts.id}
                type="button"
                onClick={() => {
                  if (locked) { toast.info(s("upgrade_to_unlock")); return; }
                  onSelect(ts.id);
                  onPreviewOpen(ts.id);
                }}
                className={cn(
                  "relative flex min-w-0 items-center gap-3 overflow-hidden rounded-2xl border p-2.5 text-left transition-all duration-150",
                  locked ? "opacity-50 cursor-not-allowed border-border/30 bg-muted/20"
                    : isSelected ? "border-primary bg-primary/5 shadow-md shadow-primary/10 ring-1 ring-primary/20"
                    : "border-border/60 bg-background hover:border-primary/40 hover:shadow-sm"
                )}
              >
                <div className={cn("relative flex h-14 w-14 shrink-0 items-center justify-center overflow-hidden rounded-xl bg-gradient-to-br", ts.accent)}>
                  <div className="absolute inset-0 opacity-[0.08]" style={{ backgroundImage: "radial-gradient(circle, white 1px, transparent 1px)", backgroundSize: "8px 8px" }} />
                  {locked ? <RiVipCrownLine className="relative h-5 w-5 text-white/80 drop-shadow" /> : <Icon className="relative h-5 w-5 text-white drop-shadow" />}
                </div>
                <div className="min-w-0 flex-1">
                  <p className={cn("truncate text-xs font-bold", isSelected && !locked ? "text-primary" : "text-foreground")}>
                    {isZh ? ts.zhName : ts.label}
                  </p>
                  <p className="mt-1 truncate text-[10px] text-muted-foreground">
                    {locked ? (isZh ? "会员专属配色" : "Members only") : isSelected ? (isZh ? "当前已选" : "Selected") : (isFree && !isMember ? "FREE" : (isZh ? "点击查看预览" : "Tap to preview"))}
                  </p>
                </div>
                <span className={cn("flex size-5 shrink-0 items-center justify-center rounded-full border", isSelected && !locked ? "border-primary bg-primary text-primary-foreground" : "border-border")}>{isSelected && !locked && <RiCheckLine className="size-3" />}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Style preview bottom sheet */}
      <AnimatePresence>
        {previewStyleId && (() => {
          const ts = TAG_STYLES.find(t => t.id === previewStyleId) || TAG_STYLES[0];
          const Icon = ts.icon;
          const badgeLabel = s((`badge_${previewStyleId}`) as StampKey) || s("badge_default");
          const previewName = tagName.trim() || t("stamp.brand_name_placeholder" as TranslationKey);
          const isSelected = selectedStyle === previewStyleId;
          return (
            <>
              <motion.div
                className="fixed inset-0 z-[70] bg-black/40 backdrop-blur-[2px]"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                onClick={onPreviewClose}
              />
              <motion.div
                className="fixed inset-0 z-[75] flex items-center justify-center px-4"
                initial={{ scale: 0.93, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.93, opacity: 0 }}
                transition={{ type: "spring", damping: 24, stiffness: 300 }}
                onClick={(e) => { if (e.target === e.currentTarget) onPreviewClose(); }}
              >
                <div className="bg-background border border-border rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
                  <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-border/50">
                    <div className="flex items-center gap-2">
                      <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold", ts.className)}>
                        <Icon className="w-3 h-3" />
                        {isZh ? ts.zhName : ts.label}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={onPreviewClose}
                      className="w-7 h-7 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
                    >
                      <RiCloseLine className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="px-4 py-4">
                    <div className="rounded-[18px] overflow-hidden shadow-md">
                      <StampPreviewCard
                        themeKey={ts.theme || "app"}
                        data={{
                          tagName: previewName,
                          domain: domain || undefined,
                          description: description || undefined,
                          link: link || undefined,
                          tagLabel: badgeLabel,
                          icon: ts.icon,
                        }}
                      />
                    </div>
                  </div>
                  <div className="px-4 pb-4 flex gap-2">
                    {isSelected ? (
                      <button
                        type="button"
                        onClick={onPreviewClose}
                        className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-1.5"
                      >
                        <RiCheckLine className="w-4 h-4" />
                        {s("selected")}
                      </button>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={onPreviewClose}
                          className="px-4 py-2.5 rounded-xl border border-border text-sm font-medium text-muted-foreground hover:bg-muted/50 transition-colors"
                        >
                          {t("common.cancel")}
                        </button>
                        <button
                          type="button"
                          onClick={() => { onSelect(previewStyleId); onPreviewClose(); }}
                          className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity"
                        >
                          {s("use_this_style")}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </motion.div>
            </>
          );
        })()}
      </AnimatePresence>
    </>
  );
}
