import React from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiShieldCheckLine,
  RiCloseLine,
  RiArrowRightLine,
  RiPencilLine,
  RiServerLine,
  RiFlashlightLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import { useTranslation, TranslationKey } from "@/lib/i18n";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

const HOW_TO_STEPS = [
  { icon: RiPencilLine, color: "text-violet-500", bg: "bg-violet-500/10" },
  { icon: RiServerLine, color: "text-sky-500", bg: "bg-sky-500/10" },
  { icon: RiFlashlightLine, color: "text-emerald-500", bg: "bg-emerald-500/10" },
];

const HOW_STEP_TITLE_KEYS: StampKey[] = ["how_step1_title", "how_step2_title", "how_step3_title"];
const HOW_STEP_DESC_KEYS: StampKey[] = ["how_step1_desc", "how_step2_desc", "how_step3_desc"];

interface HowItWorksGuideProps {
  show: boolean;
  onDismiss: () => void;
}

export function HowItWorksGuide({ show, onDismiss }: HowItWorksGuideProps) {
  const { t } = useTranslation();
  const s = (key: StampKey) => t(`stamp.${key}` as TranslationKey);

  return (
    <AnimatePresence>
      {show && (
        <>
          <motion.div
            className="fixed inset-0 z-[70] bg-black/40 backdrop-blur-[2px]"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onDismiss}
          />
          <motion.div
            className="fixed inset-0 z-[75] flex items-center justify-center px-4"
            initial={{ scale: 0.93, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.93, opacity: 0 }}
            transition={{ type: "spring", damping: 24, stiffness: 300 }}
            onClick={(e) => { if (e.target === e.currentTarget) onDismiss(); }}
          >
            <div className="bg-background border border-border rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
              <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border/60">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-violet-500/10 flex items-center justify-center">
                    <RiShieldCheckLine className="w-4 h-4 text-violet-500" />
                  </div>
                  <p className="text-sm font-bold">{s("how_it_works")}</p>
                </div>
                <button
                  type="button"
                  onClick={onDismiss}
                  className="w-7 h-7 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
                >
                  <RiCloseLine className="w-4 h-4" />
                </button>
              </div>
              <div className="px-5 py-4 space-y-3.5">
                {HOW_TO_STEPS.map((hwStep, i) => {
                  const Icon = hwStep.icon;
                  return (
                    <div key={i} className="flex gap-3 items-start">
                      <div className={cn("shrink-0 w-7 h-7 rounded-lg flex items-center justify-center", hwStep.bg)}>
                        <Icon className={cn("w-3.5 h-3.5", hwStep.color)} />
                      </div>
                      <div className="min-w-0 flex-1 pt-0.5">
                        <p className="text-xs font-semibold text-foreground leading-none mb-1">{s(HOW_STEP_TITLE_KEYS[i])}</p>
                        <p className="text-[11px] text-muted-foreground leading-relaxed">{s(HOW_STEP_DESC_KEYS[i])}</p>
                      </div>
                      {i < HOW_TO_STEPS.length - 1 && (
                        <div className="shrink-0 flex items-center mt-1.5 text-muted-foreground/30">
                          <RiArrowRightLine className="w-3.5 h-3.5" />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              <div className="px-5 pb-5">
                <button
                  type="button"
                  onClick={onDismiss}
                  className="w-full py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity"
                >
                  {s("got_it")}
                </button>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
