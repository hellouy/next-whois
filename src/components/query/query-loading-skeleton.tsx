import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import { useTranslation, type TranslationKey } from "@/lib/i18n";

interface QueryLoadingSkeletonProps {
  domain?: string;
  /** Render as a centered overlay (blurred backdrop) on top of previous content. */
  overlay?: boolean;
}

const STAGE_KEYS: TranslationKey[] = [
  "query.stage_rdap",
  "query.stage_whois",
  "query.stage_dns",
  "query.stage_verify",
];

const TYPE_SPEED_MS = 32;
const STAGE_HOLD_MS = 1300;

/**
 * Centered query loading indicator with a radar-sweep motif, the domain
 * name rendered with the site-wide shimmer gradient, and a typewriter
 * carousel cycling through playful lookup stages (RDAP → WHOIS → DNS →
 * verify). Fills its absolutely-positioned parent, so the composition
 * always sits mid-viewport.
 */
export function QueryLoadingSkeleton({ domain, overlay }: QueryLoadingSkeletonProps) {
  const { t } = useTranslation();

  const [stageIdx, setStageIdx] = useState(0);
  const [chars, setChars] = useState(0);
  const stageText = t(STAGE_KEYS[stageIdx]);

  useEffect(() => {
    if (chars < stageText.length) {
      const id = setTimeout(() => setChars((c) => c + 1), TYPE_SPEED_MS);
      return () => clearTimeout(id);
    }
    const id = setTimeout(() => {
      setStageIdx((i) => (i + 1) % STAGE_KEYS.length);
      setChars(0);
    }, STAGE_HOLD_MS);
    return () => clearTimeout(id);
  }, [chars, stageText]);

  return (
    <motion.div
      key="skeleton"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.15, ease: "easeInOut" } }}
      transition={{ duration: 0.18 }}
      className={`absolute inset-0 z-10 flex flex-col items-center justify-center gap-5 pointer-events-none ${
        overlay ? "bg-background/70 backdrop-blur-[2px]" : ""
      }`}
    >
      {/* Radar motif: expanding ping, two static rings, rotating sweep, core dot */}
      <div className="relative w-14 h-14" aria-hidden>
        <span className="radar-ping absolute inset-0" />
        <span className="absolute inset-0 rounded-full border border-primary/25" />
        <span className="absolute inset-2 rounded-full border border-primary/15" />
        <span className="radar-sweep absolute inset-0" />
        <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-primary/70" />
      </div>

      {domain && (
        <p className="text-shimmer text-base font-semibold select-none">
          {domain}
        </p>
      )}

      <p className="font-mono text-xs text-muted-foreground/80 select-none" aria-live="polite">
        {"> "}
        {stageText.slice(0, chars)}
        <span className="type-cursor">▍</span>
      </p>
    </motion.div>
  );
}
