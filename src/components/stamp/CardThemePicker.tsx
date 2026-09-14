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

export const SPECIAL_THEME_IDS = ["neon", "gradient", "split", "flash"] as const;

const CARD_THEME_KEYS = Object.keys(STAMP_CARD_THEMES);

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

  const renderThemeCard = (themeId: string) => {
    const th = STAMP_CARD_THEMES[themeId];
    if (!th) return null;
    const isSpecial = (SPECIAL_THEME_IDS as readonly string[]).includes(themeId);
    const isSelected = selectedTheme === themeId;
    const locked = !isMember && isSpecial;
    return (
      <button
        key={themeId}
        type="button"
        onClick={() => {
          if (locked) { toast.info(isZh ? "升级会员解锁特殊排版" : "Upgrade to unlock special layouts"); return; }
          if (isSelected && isSpecial) {
            onSpecialDeselect();
          } else {
            onThemeSelect(themeId);
            onPreviewOpen(themeId);
          }
        }}
        className={cn(
          "group relative flex min-w-0 items-center gap-3 overflow-hidden rounded-2xl border p-2.5 text-left transition-all duration-150",
          locked ? "opacity-55 cursor-not-allowed border-border/30 bg-muted/20"
            : isSelected ? "border-primary bg-primary/5 shadow-md shadow-primary/10 ring-1 ring-primary/20"
            : "border-border/60 bg-background hover:border-primary/40 hover:shadow-sm"
        )}
      >
        <div className={cn("flex h-14 w-24 shrink-0 items-center justify-center rounded-xl shadow-inner", th.hero)}>
          {locked
            ? <RiVipCrownLine className="h-5 w-5 text-white/80 drop-shadow" />
            : isSelected
              ? <RiCheckLine className="h-5 w-5 text-white drop-shadow" />
              : <span className="text-xl">{th.special || "*"}</span>
          }
        </div>
        <div className="min-w-0 flex-1">
          <p className={cn("truncate text-xs font-bold", isSelected ? "text-primary" : "text-foreground")}>
            {th.label}
          </p>
          <p className="mt-1 truncate text-[10px] text-muted-foreground">
            {locked ? (isZh ? "会员专属排版" : "Members only") : isSelected ? (isZh ? "当前已选" : "Selected") : (isZh ? "点击查看预览" : "Tap to preview")}
          </p>
        </div>
        <span className={cn("flex size-5 shrink-0 items-center justify-center rounded-full border", isSelected ? "border-primary bg-primary text-primary-foreground" : "border-border")}>{isSelected && <RiCheckLine className="size-3" />}</span>
      </button>
    );
  };

  return (
    <>
      <div>
        <div className="flex items-center justify-between mb-2.5">
          <div className="flex items-center gap-1.5">
            <label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">{isZh ? "卡片排版" : "Card Layout"}</label>
            {!isMember && (
              <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-violet-600 dark:text-violet-400">
                <RiVipCrownLine className="w-2.5 h-2.5" />{isZh ? "部分会员专属" : "Members Only"}
              </span>
            )}
          </div>
        </div>
        <div className="grid grid-cols-1 gap-2 min-[390px]:grid-cols-2">
          {CARD_THEME_KEYS.map(renderThemeCard)}
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
        {previewThemeKey && (() => {
          const th = STAMP_CARD_THEMES[previewThemeKey];
          if (!th) return null;
          const styleObj = TAG_STYLES.find(ts => ts.id === selectedTagStyle) || TAG_STYLES[0];
          const badgeLabel = s((`badge_${selectedTagStyle}`) as StampKey) || s("badge_default");
          const previewName = tagName.trim() || t("stamp.brand_name_placeholder" as TranslationKey);
          const isSelected = selectedTheme === previewThemeKey;
          const isSpecial = (SPECIAL_THEME_IDS as readonly string[]).includes(previewThemeKey);
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
                      <span className="text-sm font-semibold">{isZh ? "排版预览" : "Layout Preview"}</span>
                      <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[9px] font-bold"
                        style={{background:"rgba(124,58,237,0.08)",color:"#7C3AED",border:"1px solid rgba(124,58,237,0.2)"}}>
                        {th.label}
                      </span>
                      {isSpecial && (
                        <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[9px] font-bold"
                          style={{background:"rgba(245,158,11,0.1)",color:"#D97706",border:"1px solid rgba(245,158,11,0.25)"}}>
                          {isZh ? "特殊" : "Special"}
                        </span>
                      )}
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
