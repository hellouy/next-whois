import React from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { TAG_STYLES } from "./TagStylePicker";

export function TagBadge({ tagName, tagStyle, live = false }: { tagName: string; tagStyle: string; live?: boolean }) {
  const style = TAG_STYLES.find((s) => s.id === tagStyle) || TAG_STYLES[0];
  const Icon = style.icon;
  return (
    <span className={cn(
      "relative inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold overflow-hidden select-none",
      style.className,
      live && style.glow && `shadow-md ${style.glow}`,
    )}>
      <span className="shrink-0 text-white/90">
        <Icon className="w-3 h-3" />
      </span>
      <span>{tagName || style.label}</span>
      {live && style.glow && (
        <motion.span
          className="absolute inset-0 pointer-events-none"
          style={{ background: "linear-gradient(105deg, transparent 20%, rgba(255,255,255,0.28) 50%, transparent 80%)" }}
          initial={{ x: "-120%" }}
          animate={{ x: "220%" }}
          transition={{ duration: 1.8, repeat: Infinity, ease: "easeInOut", repeatDelay: 2.2 }}
        />
      )}
    </span>
  );
}
