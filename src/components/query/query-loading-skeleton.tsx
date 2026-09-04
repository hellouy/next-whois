import { cn } from "@/lib/utils";
import { RiGlobalLine } from "@remixicon/react";
import { motion } from "framer-motion";
import { useTranslation } from "@/lib/i18n";

interface QueryLoadingSkeletonProps {
  domain?: string;
}

export function QueryLoadingSkeleton({ domain }: QueryLoadingSkeletonProps) {
  const { t } = useTranslation();
  return (
    <motion.div
      key="skeleton"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.08, ease: "easeIn" } }}
      transition={{ duration: 0.1 }}
      className="grid grid-cols-1 gap-5"
    >
      <style>{`
        @keyframes sk-spin   { to { transform: rotate(360deg) } }
        @keyframes sk-ping   { 0%,100%{transform:scale(1);opacity:.7} 50%{transform:scale(1.14);opacity:1} }
        @keyframes sk-scan   { 0%{top:-6%;opacity:.55} 100%{top:108%;opacity:0} }
        @keyframes sk-step   { from{opacity:0;transform:translateX(-6px)} to{opacity:1;transform:translateX(0)} }
        @keyframes sk-bar    { 0%{background-position:200% 0} 100%{background-position:-200% 0} }
        .sk-shimbar { background: linear-gradient(90deg, hsl(var(--muted)/.45) 25%, hsl(var(--muted)/.7) 50%, hsl(var(--muted)/.45) 75%); background-size: 200% 100%; animation: sk-bar 1.6s ease-in-out infinite; }
      `}</style>

      {/* Lookup animation card */}
      <div className="glass-panel rounded-2xl border border-border/60 overflow-hidden">
        <div className="flex flex-col items-center pt-10 pb-8 px-6 gap-6">

          {/* Animated orb */}
          <div className="relative flex items-center justify-center" style={{ width: 96, height: 96 }}>
            <div className="absolute inset-0 rounded-full border-2 border-primary/10"
              style={{ animation: "sk-ping 2.8s ease-in-out infinite" }} />
            <div className="absolute rounded-full border-2 border-transparent"
              style={{ inset: 8, borderTopColor: "hsl(var(--primary)/.55)", borderRightColor: "hsl(var(--primary)/.2)", animation: "sk-spin 1.1s linear infinite" }} />
            <div className="absolute rounded-full border border-primary/20"
              style={{ inset: 16, animation: "sk-ping 1.9s ease-in-out infinite 0.4s" }} />
            <div className="relative z-10 w-10 h-10 rounded-full flex items-center justify-center"
              style={{ background: "hsl(var(--primary)/.1)", border: "1.5px solid hsl(var(--primary)/.3)" }}>
              <RiGlobalLine className="w-5 h-5 text-primary/60" />
            </div>
            <div className="absolute overflow-hidden pointer-events-none" style={{ inset: 8, borderRadius: "50%" }}>
              <div className="absolute left-0 right-0 h-px"
                style={{ background: "linear-gradient(90deg,transparent,hsl(var(--primary)/.5),transparent)", animation: "sk-scan 2s linear infinite" }} />
            </div>
          </div>

          {/* Labels */}
          <div className="text-center space-y-2">
            <p className="text-sm font-semibold tracking-[0.06em] text-foreground/70 select-none">
              {domain
                ? t("query.loading_with_domain", { domain })
                : t("query.loading")}
            </p>
            <p className="text-[11px] text-muted-foreground/45 select-none tracking-wide">
              RDAP · WHOIS · DNS
            </p>
          </div>

          {/* Step list */}
          <div className="w-full max-w-[280px] space-y-2">
            {[
              t("query.step_connect"),
              t("query.step_whois"),
              t("query.step_parse"),
            ].map((step, i) => (
              <div key={i} className="flex items-center gap-2.5"
                style={{ animation: "sk-step 0.35s ease both", animationDelay: `${0.2 + i * 0.38}s` }}>
                <span className="w-1.5 h-1.5 rounded-full shrink-0 bg-primary/45 animate-pulse"
                  style={{ animationDelay: `${i * 0.3}s` }} />
                <span className="text-[11px] text-muted-foreground/55 leading-none font-mono">{step}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Shimmer bars */}
        <div className="border-t border-border/30 px-6 py-5 space-y-3">
          <div className="grid grid-cols-3 gap-4">
            {[["w-14","w-20"],["w-16","w-24"],["w-12","w-16"]].map(([a,b],i) => (
              <div key={i} className="space-y-1.5">
                <div className={cn("h-2.5 rounded-full sk-shimbar", a)} />
                <div className={cn("h-3.5 rounded sk-shimbar", b)} />
              </div>
            ))}
          </div>
          <div className="space-y-1.5">
            <div className="h-2.5 w-12 rounded-full sk-shimbar" />
            <div className="h-3.5 w-40 rounded sk-shimbar" />
          </div>
          <div className="flex gap-2.5 pt-0.5">
            <div className="h-7 w-20 rounded-lg sk-shimbar" />
            <div className="h-7 w-20 rounded-lg sk-shimbar" style={{ opacity: 0.75 }} />
            <div className="h-7 w-16 rounded-lg sk-shimbar" style={{ opacity: 0.55 }} />
          </div>
        </div>
      </div>

      {/* Secondary placeholder cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
        {[["w-24","w-full","w-4/5","w-3/5"],["w-20","w-full","w-3/4","w-2/3"]].map((ws, idx) => (
          <div key={idx} className="glass-panel rounded-xl border border-border/50 p-5 space-y-3">
            <div className={cn("h-3.5 rounded sk-shimbar", ws[0])} />
            <div className="space-y-2">
              {ws.slice(1).map((w,i) => <div key={i} className={cn("h-3 rounded sk-shimbar", w)} style={{ opacity: 1 - i * 0.15 }} />)}
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
