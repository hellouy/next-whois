import { motion } from "framer-motion";
import { useTranslation } from "@/lib/i18n";
import { RiLoader4Line } from "@remixicon/react";

interface QueryLoadingSkeletonProps {
  domain?: string;
}

/**
 * Minimal centered loading indicator. Renders as an absolutely-positioned
 * overlay filling its parent (the parent must be `relative` and provide the
 * height), so the text always sits in the middle of the viewport area —
 * never behind the navbar, never hugging the top edge.
 */
export function QueryLoadingSkeleton({ domain }: QueryLoadingSkeletonProps) {
  const { t } = useTranslation();
  return (
    <motion.div
      key="skeleton"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.15, ease: "easeInOut" } }}
      transition={{ duration: 0.18 }}
      className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 pointer-events-none"
    >
      <div className="flex items-center gap-2.5">
        <RiLoader4Line className="w-4 h-4 animate-spin text-primary" />
        <p className="text-sm font-medium text-foreground/80 select-none">
          {domain
            ? t("query.loading_with_domain", { domain })
            : t("query.loading")}
        </p>
      </div>
      <p className="text-[11px] text-muted-foreground/50 select-none tracking-wide">
        RDAP · WHOIS · DNS
      </p>
    </motion.div>
  );
}
