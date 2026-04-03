import React from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiCheckLine,
  RiCloseLine,
  RiVipCrownLine,
  RiCheckboxCircleLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { StampPreviewCard, STAMP_CARD_THEMES } from "@/components/stamp-preview-card";
import { TAG_STYLES } from "./TagStylePicker";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

const SPECIAL_THEME_IDS = ["celebrate", "neon", "gradient", "split", "flash"] as const;

const CARD_THEME_OPTIONS: {
  id: string; label: string; enLabel: string; hero: string; dot: string;
  shimmer: string; cardBg: string; cardBorder: string; cardText: string; btn: string;
}[] = [
  { id: "app",      label: "极简", enLabel: "Minimal",  hero: "bg-gradient-to-br from-zinc-600 to-zinc-900",                      dot: "bg-zinc-600",    shimmer: "text-shimmer",              cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-zinc-900 text-white"                              },
  { id: "official", label: "官方", enLabel: "Official", hero: "bg-gradient-to-br from-blue-600 to-indigo-800",                    dot: "bg-blue-700",    shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-blue-700 text-white"                               },
  { id: "aurora",   label: "极光", enLabel: "Aurora",   hero: "bg-gradient-to-br from-violet-500 via-fuchsia-500 to-purple-700",  dot: "bg-violet-600",  shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-violet-600 text-white"                             },
  { id: "emerald",  label: "翡翠", enLabel: "Emerald",  hero: "bg-gradient-to-br from-emerald-400 to-teal-700",                   dot: "bg-emerald-600", shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-emerald-600 text-white"                            },
  { id: "solar",    label: "暖阳", enLabel: "Solar",    hero: "bg-gradient-to-br from-amber-400 to-orange-600",                   dot: "bg-orange-500",  shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-orange-500 text-white"                             },
  { id: "dev",      label: "开发", enLabel: "Dev",      hero: "bg-gradient-to-br from-slate-600 to-[#0d1117]",                    dot: "bg-[#238636]",   shimmer: "text-[#58a6ff] font-black font-mono", cardBg: "bg-zinc-950",   cardBorder: "border-zinc-800",  cardText: "text-zinc-200",   btn: "bg-[#238636] text-white"                          },
  { id: "warning",  label: "警示", enLabel: "Warning",  hero: "bg-gradient-to-br from-yellow-400 to-amber-600",                   dot: "bg-amber-500",   shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-amber-500 text-white"                             },
  { id: "premium",  label: "尊享", enLabel: "Premium",  hero: "bg-gradient-to-br from-purple-600 via-fuchsia-500 to-rose-500",    dot: "bg-fuchsia-600", shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-gradient-to-r from-purple-600 to-fuchsia-500 text-white" },
];

interface CardThemePickerProps {
  selectedTheme: string;
  selectedTagStyle: string;
  isMember: boolean;
  isZh: boolean;
  tagName: string;
  domain: string;
  description: string;
  link: string;
  previewThemeKey: string | null;
  onThemeSelect: (themeId: string) => void;
  onSpecialDeselect: () => void;
  onPreviewOpen: (themeKey: string) => void;
  onPreviewClose: () => void;
}

export function CardThemePicker({
  selectedTheme,
  selectedTagStyle,
  isMember,
  isZh,
  tagName,
  domain,
  description,
  link,
  previewThemeKey,
  onThemeSelect,
  onSpecialDeselect,
  onPreviewOpen,
  onPreviewClose,
}: CardThemePickerProps) {
  const { t } = useTranslation();
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  return (
    <>
      <div>
        <div className="flex items-center justify-between mb-2.5">
          <div className="flex items-center gap-1.5">
            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">{isZh ? "卡片排版" : "Card Layout"}</label>
            {!isMember && (
              <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-violet-600 dark:text-violet-400">
                <RiVipCrownLine className="w-2.5 h-2.5" />{isZh ? "会员专属" : "Members Only"}
              </span>
            )}
          </div>
          {!(SPECIAL_THEME_IDS as readonly string[]).includes(selectedTheme) && (
            <span className="text-[9px] text-muted-foreground/60 font-mono">
              {isZh ? STAMP_CARD_THEMES[selectedTheme]?.label : selectedTheme}
            </span>
          )}
        </div>
        <div className="grid grid-cols-5 gap-1.5">
          {(SPECIAL_THEME_IDS as readonly string[]).map((themeId) => {
            const th = STAMP_CARD_THEMES[themeId];
            if (!th) return null;
            const isSpecialSelected = selectedTheme === themeId;
            const locked = !isMember;
            return (
              <button
                key={themeId}
                type="button"
                onClick={() => {
                  if (locked) { toast.info(isZh ? "升级会员解锁特殊排版" : "Upgrade to unlock special layouts"); return; }
                  if (isSpecialSelected) {
                    onSpecialDeselect();
                  } else {
                    onThemeSelect(themeId);
                    onPreviewOpen(themeId);
                  }
                }}
                className={cn(
                  "relative flex flex-col overflow-hidden rounded-xl border-2 transition-all duration-150",
                  locked ? "opacity-50 cursor-not-allowed border-border/20"
                    : isSpecialSelected ? "border-violet-400 dark:border-violet-500 shadow-md shadow-violet-500/15"
                    : "border-border/40 hover:border-border/70"
                )}
              >
                <div className={cn("h-10 w-full flex items-center justify-center", th.hero)}>
                  {locked
                    ? <RiVipCrownLine className="w-3.5 h-3.5 text-white/70 drop-shadow" />
                    : isSpecialSelected
                      ? <RiCheckLine className="w-3.5 h-3.5 text-white drop-shadow" />
                      : <span className="text-[11px]">{th.special || "✨"}</span>
                  }
                </div>
                <div className={cn("px-0.5 py-1 text-center", isSpecialSelected ? "bg-violet-50 dark:bg-violet-950/40" : "bg-background")}>
                  <p className={cn("text-[8.5px] font-semibold leading-none tracking-tight",
                    isSpecialSelected ? "text-violet-600 dark:text-violet-400" : "text-foreground/70")}>
                    {th.label}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
        {(SPECIAL_THEME_IDS as readonly string[]).includes(selectedTheme) && (
          <p className="text-[9.5px] text-muted-foreground/60 mt-1.5 flex items-center gap-1">
            <RiCheckboxCircleLine className="w-3 h-3 text-violet-400" />
            {isZh ? `已选特殊排版：${STAMP_CARD_THEMES[selectedTheme]?.label}` : `Special layout selected: ${selectedTheme}`}
            <button type="button" className="text-muted-foreground/40 hover:text-muted-foreground underline ml-1"
              onClick={onSpecialDeselect}>
              {isZh ? "重置" : "Reset"}
            </button>
          </p>
        )}
      </div>

      {/* Card Layout preview popup */}
      <AnimatePresence>
        {previewThemeKey && isMember && (() => {
          const th = STAMP_CARD_THEMES[previewThemeKey];
          if (!th) return null;
          const styleObj = TAG_STYLES.find(ts => ts.id === selectedTagStyle) || TAG_STYLES[0];
          const badgeLabel = s((`badge_${selectedTagStyle}`) as StampKey) || s("badge_default");
          const previewName = tagName.trim() || t("stamp.brand_name_placeholder" as TranslationKey);
          const isSelected = selectedTheme === previewThemeKey;
          return (
            <>
              <motion.div className="fixed inset-0 z-[70] bg-black/40 backdrop-blur-[2px]"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                onClick={onPreviewClose} />
              <motion.div className="fixed inset-0 z-[75] flex items-center justify-center px-4"
                initial={{ scale: 0.93, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.93, opacity: 0 }}
                transition={{ type: "spring", damping: 24, stiffness: 300 }}
                onClick={(e) => { if (e.target === e.currentTarget) onPreviewClose(); }}
              >
                <div className="bg-background border border-border rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
                  <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-border/50">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold">{isZh ? "特殊排版预览" : "Special Layout Preview"}</span>
                      <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[9px] font-bold"
                        style={{background:"rgba(124,58,237,0.08)",color:"#7C3AED",border:"1px solid rgba(124,58,237,0.2)"}}>
                        {th.label}
                      </span>
                    </div>
                    <button type="button" onClick={onPreviewClose}
                      className="w-7 h-7 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors">
                      <RiCloseLine className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="px-4 py-4">
                    <div className="rounded-[18px] overflow-hidden shadow-md">
                      <StampPreviewCard
                        themeKey={previewThemeKey}
                        data={{
                          tagName: previewName,
                          domain: domain || undefined,
                          description: description || undefined,
                          link: link || undefined,
                          tagLabel: badgeLabel,
                          icon: styleObj.icon,
                        }}
                      />
                    </div>
                  </div>
                  <div className="px-4 pb-4 flex gap-2">
                    <button type="button" onClick={onPreviewClose}
                      className="px-4 py-2.5 rounded-xl border border-border text-sm font-medium text-muted-foreground hover:bg-muted/50 transition-colors">
                      {t("common.cancel")}
                    </button>
                    {isSelected ? (
                      <button type="button" onClick={onPreviewClose}
                        className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-1.5">
                        <RiCheckLine className="w-4 h-4" />
                        {s("selected")}
                      </button>
                    ) : (
                      <button type="button"
                        onClick={() => { onThemeSelect(previewThemeKey); onPreviewClose(); }}
                        className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity">
                        {isZh ? "使用此排版" : "Use This Layout"}
                      </button>
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
