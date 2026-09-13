import React from "react";
import Link from "next/link";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiGlobalLine,
  RiAlertLine,
  RiLoader4Line,
  RiFlashlightLine,
  RiVipCrownLine,
  RiCheckLine,
  RiArrowRightLine,
  RiArrowLeftLine,
} from "@remixicon/react";
import { StampPreviewCard } from "@/components/stamp-preview-card";
import { TagStylePicker } from "./TagStylePicker";
import { CardThemePicker } from "./CardThemePicker";
import { TAG_STYLES } from "./TagStylePicker";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

interface FormState {
  tagName: string;
  tagStyle: string;
  cardTheme: string;
  link: string;
  description: string;
  nickname: string;
  email: string;
}

interface StampFormCardProps {
  form: FormState;
  domain: string;
  isMember: boolean;
  isZh: boolean;
  loading: boolean;
  formError: string | null;
  previewStyleId: string | null;
  previewThemeKey: string | null;
  onUpdate: (field: string, value: string) => void;
  onSubmit: () => void;
  onPreviewStyleOpen: (id: string) => void;
  onPreviewStyleClose: () => void;
  onPreviewThemeOpen: (key: string) => void;
  onPreviewThemeClose: () => void;
  onSpecialDeselect: () => void;
}

type FormStep = "info" | "style" | "theme" | "preview";

const STEP_ORDER: FormStep[] = ["info", "style", "theme", "preview"];

const stepLabels = (isZh: boolean): Record<FormStep, string> => ({
  info: isZh ? "资料" : "Info",
  style: isZh ? "标签样式" : "Style",
  theme: isZh ? "卡片主题" : "Theme",
  preview: isZh ? "预览提交" : "Preview",
});

const stepVariants = {
  enter: (dir: number) => ({ opacity: 0, x: dir > 0 ? 24 : -24 }),
  center: { opacity: 1, x: 0 },
  exit: (dir: number) => ({ opacity: 0, x: dir > 0 ? -24 : 24 }),
};

export function StampFormCard({
  form, domain, isMember, isZh, loading, formError,
  previewStyleId, previewThemeKey,
  onUpdate, onSubmit,
  onPreviewStyleOpen, onPreviewStyleClose,
  onPreviewThemeOpen, onPreviewThemeClose,
  onSpecialDeselect,
}: StampFormCardProps) {
  const { t } = useTranslation();
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  const [formStep, setFormStep] = React.useState<FormStep>("info");
  const [direction, setDirection] = React.useState(1);

  const styleObj = TAG_STYLES.find(ts => ts.id === form.tagStyle) || TAG_STYLES[0];
  const badgeLabel = s((`badge_${form.tagStyle}`) as StampKey) || s("badge_default");
  const currentIdx = STEP_ORDER.indexOf(formStep);

  function goToStep(next: FormStep) {
    setDirection(STEP_ORDER.indexOf(next) > currentIdx ? 1 : -1);
    setFormStep(next);
  }

  function validateStep(step: FormStep): boolean {
    if (step === "info") {
      if (!form.tagName.trim()) return false;
      if (!form.nickname.trim()) return false;
      if (!form.email.trim()) return false;
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) return false;
    }
    return true;
  }

  function handleNext() {
    if (!validateStep(formStep)) {
      onSubmit();
      return;
    }
    const nextIdx = currentIdx + 1;
    if (nextIdx < STEP_ORDER.length) goToStep(STEP_ORDER[nextIdx]);
  }

  function handlePrev() {
    if (currentIdx > 0) goToStep(STEP_ORDER[currentIdx - 1]);
  }

  return (
    <div className="space-y-4">
      {/* Step indicator */}
      <div className="flex items-center px-1">
        {STEP_ORDER.map((st, i) => {
          const isActive = st === formStep;
          const isDone = i < currentIdx;
          return (
            <React.Fragment key={st}>
              <div className="flex items-center gap-1.5">
                <div className={cn(
                  "w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold transition-all shrink-0",
                  isActive ? "bg-violet-500 text-white shadow-sm shadow-violet-500/30"
                    : isDone ? "bg-emerald-500 text-white"
                    : "bg-muted text-muted-foreground"
                )}>
                  {isDone ? <RiCheckLine className="w-3 h-3" /> : i + 1}
                </div>
                <span className={cn(
                  "text-[10px] font-medium transition-colors hidden min-[360px]:block",
                  isActive ? "text-foreground" : isDone ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"
                )}>
                  {stepLabels(isZh)[st]}
                </span>
              </div>
              {i < STEP_ORDER.length - 1 && (
                <div className={cn("flex-1 h-px mx-1.5 transition-colors", isDone ? "bg-emerald-400/60" : "bg-border")} />
              )}
            </React.Fragment>
          );
        })}
      </div>

      <div className="glass-panel border border-border rounded-2xl p-5 space-y-5">
        <AnimatePresence mode="wait" custom={direction} initial={false}>
          <motion.div
            key={formStep}
            custom={direction}
            variants={stepVariants}
            initial="enter"
            animate="center"
            exit="exit"
            transition={{ duration: 0.18, ease: [0.32, 0.72, 0, 1] }}
          >
            {/* ── STEP 1: INFO ── */}
            {formStep === "info" && (
              <div className="space-y-5">
                <div>
                  <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-2 block">{s("domain_label")}</Label>
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-muted/30 border border-border/60">
                    <RiGlobalLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                    <span className="text-sm font-mono text-foreground">{domain}</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-1.5">{s("domain_hint")}</p>
                </div>

                <div>
                  <div className="flex items-baseline justify-between mb-2">
                    <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                      {s("tag_name_label")} <span className="text-red-500 normal-case tracking-normal font-normal">*</span>
                    </Label>
                    {!isMember && (
                      <span className="text-[10px] text-amber-600 dark:text-amber-400">
                        {s("char_limit_hint")} · <Link href="/payment/checkout" className="underline underline-offset-2">{s("upgrade_now")}</Link>
                      </span>
                    )}
                  </div>
                  <Input value={form.tagName} onChange={(e) => onUpdate("tagName", e.target.value)}
                    placeholder={s("tag_name_placeholder")} maxLength={isMember ? 20 : 5} />
                  {!isMember && form.tagName.length >= 5 && (
                    <p className="text-[10px] text-amber-500 mt-1 flex items-center gap-1">
                      <RiVipCrownLine className="w-3 h-3" /> {s("member_title_hint")}
                    </p>
                  )}
                </div>

                <div className="space-y-3">
                  <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest block">{s("contact_label")}</Label>
                  <div>
                    <Label className="text-xs font-medium mb-1.5 block">{s("name_label")} <span className="text-red-500">*</span></Label>
                    <Input value={form.nickname} onChange={(e) => onUpdate("nickname", e.target.value)} placeholder={s("name_placeholder")} maxLength={30} />
                  </div>
                  <div>
                    <Label className="text-xs font-medium mb-1.5 block">{s("email_label")} <span className="text-red-500">*</span></Label>
                    <Input value={form.email} onChange={(e) => onUpdate("email", e.target.value)} placeholder="your@email.com" type="text" />
                    <p className="text-[11px] text-muted-foreground mt-1">{s("email_hint")}</p>
                  </div>
                </div>
              </div>
            )}

            {/* ── STEP 2: STYLE ── */}
            {formStep === "style" && (
              <TagStylePicker
                selectedStyle={form.tagStyle} isMember={isMember} isZh={isZh}
                tagName={form.tagName} domain={domain} description={form.description} link={form.link}
                onSelect={(id) => onUpdate("tagStyle", id)}
                previewStyleId={previewStyleId}
                onPreviewOpen={onPreviewStyleOpen}
                onPreviewClose={onPreviewStyleClose}
              />
            )}

            {/* ── STEP 3: THEME ── */}
            {formStep === "theme" && (
              <CardThemePicker
                selectedTheme={form.cardTheme} selectedTagStyle={form.tagStyle}
                isMember={isMember} isZh={isZh}
                tagName={form.tagName} domain={domain} description={form.description} link={form.link}
                previewThemeKey={previewThemeKey}
                onThemeSelect={(id) => onUpdate("cardTheme", id)}
                onSpecialDeselect={onSpecialDeselect}
                onPreviewOpen={onPreviewThemeOpen}
                onPreviewClose={onPreviewThemeClose}
              />
            )}

            {/* ── STEP 4: PREVIEW + SUBMIT ── */}
            {formStep === "preview" && (
              <div className="space-y-5">
                {isMember ? (
                  <div>
                    <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-2 block">
                      {s("link_label")} <span className="normal-case tracking-normal font-normal text-muted-foreground/60">{s("optional")}</span>
                    </Label>
                    <Input value={form.link} onChange={(e) => onUpdate("link", e.target.value)} placeholder="https://example.com" type="text" inputMode="url" />
                  </div>
                ) : (
                  <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-muted/50 border border-dashed border-border">
                    <RiVipCrownLine className="w-4 h-4 text-violet-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-[11px] font-semibold text-muted-foreground">{s("link_member_only")}</p>
                      <p className="text-[10px] text-muted-foreground/60">{s("link_upgrade_hint")}</p>
                    </div>
                    <Link href="/payment/checkout" className="text-[10px] font-semibold text-violet-600 dark:text-violet-400 shrink-0 hover:underline">{s("upgrade_now")}</Link>
                  </div>
                )}

                {isMember ? (
                  <div>
                    <div className="flex items-baseline justify-between mb-2">
                      <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                        {s("desc_label")} <span className="normal-case tracking-normal font-normal text-muted-foreground/60">{s("optional")}</span>
                      </Label>
                      <span className={cn("text-[10px] tabular-nums", form.description.length >= 270 ? "text-red-500 font-semibold" : "text-muted-foreground/50")}>{form.description.length}/300</span>
                    </div>
                    <textarea value={form.description} onChange={(e) => onUpdate("description", e.target.value)}
                      placeholder={s("desc_placeholder")} maxLength={300} rows={2}
                      className="w-full text-base sm:text-sm rounded-lg border border-border bg-background px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-violet-400/40 transition-shadow placeholder:text-muted-foreground/50" />
                  </div>
                ) : (
                  <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-muted/50 border border-dashed border-border">
                    <RiVipCrownLine className="w-4 h-4 text-violet-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-[11px] font-semibold text-muted-foreground">{s("desc_member_only")}</p>
                      <p className="text-[10px] text-muted-foreground/60">{s("desc_upgrade_hint")}</p>
                    </div>
                    <Link href="/payment/checkout" className="text-[10px] font-semibold text-violet-600 dark:text-violet-400 shrink-0 hover:underline">{s("upgrade_now")}</Link>
                  </div>
                )}

                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-violet-400/70">{s("live_preview")}</span>
                    <div className="flex-1 h-px bg-violet-200/40 dark:bg-violet-800/30" />
                  </div>
                  <div className="rounded-[18px] overflow-hidden shadow-md">
                    <StampPreviewCard themeKey={form.cardTheme || "app"}
                      data={{ tagName: form.tagName, domain: domain || undefined, description: form.description || undefined, link: form.link || undefined, tagLabel: badgeLabel, icon: styleObj.icon }} />
                  </div>
                </div>

              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      <AnimatePresence>
        {formError && (
          <motion.div key="form-error" initial={{ opacity: 0, y: -6, height: 0 }} animate={{ opacity: 1, y: 0, height: "auto" }} exit={{ opacity: 0, y: -4, height: 0 }} transition={{ duration: 0.18 }} className="overflow-hidden">
            <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-red-50/80 dark:bg-red-950/30 border border-red-200/60 dark:border-red-800/40 text-red-600 dark:text-red-400">
              <RiAlertLine className="w-4 h-4 shrink-0" />
              <span className="text-sm">{formError}</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Navigation */}
      <div className="flex gap-2">
        {currentIdx > 0 && (
          <Button
            type="button"
            onClick={handlePrev}
            variant="outline"
            className="h-12 w-12 rounded-xl shrink-0 border-border text-muted-foreground"
            aria-label="上一步"
          >
            <RiArrowLeftLine className="w-4 h-4" />
          </Button>
        )}
        {currentIdx < STEP_ORDER.length - 1 ? (
          <Button
            type="button"
            onClick={handleNext}
            className="flex-1 gap-2 h-12 bg-violet-500 hover:bg-violet-600 active:bg-violet-700 text-white border-0 rounded-xl text-sm font-semibold shadow-md shadow-violet-500/25 transition-all hover:shadow-lg hover:shadow-violet-500/30 hover:-translate-y-px"
          >
            下一步
            <RiArrowRightLine className="w-4 h-4" />
          </Button>
        ) : (
          <Button
            type="button"
            onClick={onSubmit}
            disabled={loading}
            className="flex-1 gap-2 h-12 bg-violet-500 hover:bg-violet-600 active:bg-violet-700 text-white border-0 rounded-xl text-sm font-semibold shadow-md shadow-violet-500/25 transition-all hover:shadow-lg hover:shadow-violet-500/30 hover:-translate-y-px"
          >
            {loading
              ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{s("btn_submitting")}</>
              : <><RiFlashlightLine className="w-4 h-4" />{s("btn_submit")}</>
            }
          </Button>
        )}
      </div>
    </div>
  );
}
