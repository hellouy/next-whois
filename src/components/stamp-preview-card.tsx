/**
 * StampPreviewCard — shared popup preview component.
 * Used by: admin/stamp-styles.tsx, admin/stamps.tsx, stamp.tsx, dashboard.tsx,
 *          StampFormCard.tsx, CardThemePicker.tsx, TagStylePicker.tsx
 *
 * The 8 tag-style themes (app/official/aurora/emerald/solar/dev/warning/premium)
 * each render a structurally distinct layout. The special member themes
 * (neon/gradient/split/flash) keep their flashy design language.
 *
 * Design rules:
 *  - Animations are pure CSS keyframes injected via <style> (no JS rAF loops)
 *  - No generic icon prop rendering (kept for API compat only)
 *  - Badge text prefers data.tagLabel, falls back to the theme default label
 *  - CTA copies are locale-aware ("访问官网 →" / "Visit Website →")
 */
import React from "react";
import { cn } from "@/lib/utils";
import { RiArrowRightSLine, RiShakeHandsLine } from "@remixicon/react";

export type CardThemeDef = {
  hero: string; shimmer: string;
  badge: string; btn: string;
  cardBg: string; cardBorder: string; cardText: string;
  layout?: "default" | "neon" | "gradient" | "split" | "flash";
  accent?: string; accentText?: string;
};

export const STAMP_CARD_THEMES: Record<string, CardThemeDef & { label: string; special?: string }> = {
  app:      { label: "极简",     hero: "bg-gradient-to-br from-zinc-600 to-zinc-900",                    shimmer: "text-shimmer",                   badge: "bg-zinc-100 text-zinc-600 border border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",                                btn: "bg-zinc-900 text-white",                                                      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  official: { label: "官方",     hero: "bg-gradient-to-br from-blue-600 to-indigo-800",                  shimmer: "text-foreground font-black",       badge: "bg-blue-50 text-blue-700 border border-blue-200/80 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800/60",                    btn: "bg-blue-700 text-white",                                                      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  aurora:   { label: "极光",     hero: "bg-gradient-to-br from-violet-500 via-fuchsia-500 to-purple-700", shimmer: "text-foreground font-black",       badge: "bg-violet-50 text-violet-700 border border-violet-200/80 dark:bg-violet-950/60 dark:text-violet-300 dark:border-violet-800/60",      btn: "bg-violet-600 text-white",                                                    cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  emerald:  { label: "翡翠",     hero: "bg-gradient-to-br from-emerald-400 to-teal-700",                 shimmer: "text-foreground font-black",       badge: "bg-emerald-50 text-emerald-700 border border-emerald-200/80 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/60", btn: "bg-emerald-600 text-white",                                                   cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  solar:    { label: "暖阳",     hero: "bg-gradient-to-br from-amber-400 to-orange-600",                 shimmer: "text-foreground font-black",       badge: "bg-amber-50 text-amber-700 border border-amber-200/80 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/60",              btn: "bg-orange-500 text-white",                                                    cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  dev:      { label: "开发",     hero: "bg-gradient-to-br from-slate-600 to-[#0d1117]",                  shimmer: "text-[#58a6ff] font-black font-mono", badge: "bg-[#161b22] text-[#58a6ff] border border-[#30363d]",                                                                                btn: "bg-[#238636] text-white",                                                     cardBg: "bg-zinc-950",   cardBorder: "border-zinc-800",  cardText: "text-zinc-200" },
  warning:  { label: "警示",     hero: "bg-gradient-to-br from-red-500 to-red-900",                     shimmer: "text-foreground font-black",       badge: "bg-red-50 text-red-700 border border-red-200/80 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800/60",                        btn: "bg-red-600 text-white",                                                     cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  premium:  { label: "尊享",     hero: "bg-gradient-to-br from-purple-600 via-fuchsia-500 to-rose-500",  shimmer: "text-foreground font-black",       badge: "bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200/80 dark:bg-fuchsia-950/60 dark:text-fuchsia-300 dark:border-fuchsia-800/60", btn: "bg-gradient-to-r from-purple-600 to-fuchsia-500 text-white",                  cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  neon:      { label: "霓虹",     layout: "neon",      hero: "bg-[#050d18]",                                                   shimmer: "text-white font-black",    badge: "bg-cyan-400 text-slate-900 border-0", btn: "bg-gradient-to-r from-cyan-400 to-violet-600 text-white", cardBg: "bg-[#050d18]", cardBorder: "border-slate-800", cardText: "text-white", special: "⚡" },
  gradient:  { label: "渐变流光", layout: "gradient",  hero: "bg-gradient-to-br from-rose-300 via-sky-300 to-emerald-300",    shimmer: "text-gray-900 font-black", badge: "bg-black/10 text-gray-800 border border-black/20", btn: "bg-gray-900 text-white", cardBg: "bg-transparent", cardBorder: "border-0", cardText: "text-gray-900", special: "✨" },
  split:     { label: "分栏",     layout: "split",     hero: "bg-black",                                                       shimmer: "text-white font-black",    badge: "bg-blue-500 text-white border-0", btn: "bg-gray-900 text-white", cardBg: "bg-white", cardBorder: "border-gray-100", cardText: "text-gray-900", special: "◼" },
  flash:     { label: "特卖",     layout: "flash",     hero: "bg-[#FF3800]",                                                   shimmer: "text-white font-black",    badge: "bg-[#FF3800] text-white border-0", btn: "bg-orange-500 text-white", cardBg: "bg-white", cardBorder: "border-0", cardText: "text-gray-900", special: "💥" },
};

export interface StampPreviewData {
  tagName?: string;
  domain?: string;
  description?: string;
  link?: string;
  tagLabel?: string;
  icon?: React.ElementType; // kept for API compat, no longer rendered
}

const DEMO: Required<StampPreviewData> = {
  tagName:     "不讲•李",
  domain:      "hello.sn",
  description: "域名爱好者，专注稀缺后缀收藏与品牌孵化。",
  link:        "https://hello.sn",
  tagLabel:    "开发者",
  icon:        () => null,
};

/* ─────────────────────────────────────────────────────────────
   Shared keyframes injected by each theme
───────────────────────────────────────────────────────────── */
const BASE_ANIM = `
  @keyframes card-sheen  { 0%{background-position:200% center} 100%{background-position:-200% center} }
  @keyframes badge-pulse { 0%,100%{opacity:.88;transform:scale(1)} 50%{opacity:1;transform:scale(1.055)} }
`;

/* Shimmer text styles */
const sheenW: React.CSSProperties = {
  background: "linear-gradient(90deg, rgba(255,255,255,.65) 20%, #fff 50%, rgba(255,255,255,.65) 80%)",
  backgroundSize: "200% auto", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
  backgroundClip: "text", animation: "card-sheen 3s linear infinite",
};
const sheenG: React.CSSProperties = {
  background: "linear-gradient(90deg, #D4AF37 20%, #FFF5CC 50%, #D4AF37 80%)",
  backgroundSize: "200% auto", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
  backgroundClip: "text", animation: "card-sheen 3s linear infinite",
};

/* Animated badge base */
const badgeAnim: React.CSSProperties = { animation: "badge-pulse 2.2s ease-in-out infinite" };

/* Shared size tokens */
const SZ = {
  badgePad:   "4px 12px",
  badgeFs:    12,
  titleFs:    26,
  domainFs:   14,
  descFs:     13,
  btnPad:     "12px 20px",
  btnFs:      13,
  btnRadius:  10,
  btnIconSz:  15,
  hdrPad:     "18px 16px 14px",
  bodyPad:    "12px 16px 16px",
  noLinkFs:   12,
};

/* ─────────────────────────────────────────────────────────────
   Helper: Centered header block used by the special member themes
───────────────────────────────────────────────────────────── */
function CenteredHeader({
  children, padding = SZ.hdrPad,
}: { children: React.ReactNode; padding?: string }) {
  return (
    <div style={{ position: "relative", padding, textAlign: "center", overflow: "hidden" }}>
      {children}
    </div>
  );
}

/* Theme default badge labels (used when data.tagLabel is absent) */
const DEFAULT_BADGE: Record<string, { zh: string; en: string }> = {
  app:      { zh: "个人", en: "Personal" },
  official: { zh: "官方网站", en: "Official Website" },
  aurora:   { zh: "品牌", en: "Brand" },
  emerald:  { zh: "已认证", en: "DNS Verified" },
  solar:    { zh: "合作", en: "PARTNER" },
  dev:      { zh: "开发", en: "DEV" },
  warning:  { zh: "警示", en: "WARNING" },
  premium:  { zh: "尊享", en: "PREMIUM" },
};

/* ─────────────────────────────────────────────────────────────
   Component
───────────────────────────────────────────────────────────── */
export function StampPreviewCard({ themeKey, data, locale = "zh" }: { themeKey: string; data?: StampPreviewData; locale?: "zh" | "en" }) {
  const t = STAMP_CARD_THEMES[themeKey] ?? STAMP_CARD_THEMES.app;
  if (!t) return null;

  const tagName  = data?.tagName    || DEMO.tagName;
  const domain   = data?.domain     || DEMO.domain;
  const desc     = data?.description || DEMO.description;
  const link     = data !== undefined ? (data?.link || null) : DEMO.link;
  const badge    = data !== undefined
    ? (data?.tagLabel || DEFAULT_BADGE[themeKey]?.[locale] || DEMO.tagLabel)
    : DEMO.tagLabel;
  const ctaText  = locale === "en" ? "Visit Website" : "访问官网";
  const ctaHome  = locale === "en" ? "Visit Profile" : "访问主页";
  const noLinkText = locale === "en" ? "No profile link" : "未设置主页链接";

  /* ═══ app — 个人·极简名片 ═══════════════════════════════════════════ */
  if (themeKey === "app") return (
    <>
      <div className={cn(
        "rounded-[16px] overflow-hidden border bg-white dark:bg-zinc-900",
        "border-zinc-200/80 dark:border-zinc-800",
        "shadow-[0_2px_16px_rgba(0,0,0,0.07)] dark:shadow-none"
      )}>
        {/* Top hairline accent */}
        <div className="h-[2px] w-full"
             style={{ background: "linear-gradient(90deg,#e4e4e7,#71717a,#e4e4e7)" }} />
        <div className="flex flex-col px-[18px] py-5 text-left gap-1">
          <span className={cn(
            "inline-flex w-fit items-center rounded-[6px] px-1.5 py-0.5 text-[10px] font-medium",
            "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"
          )}>{badge}</span>
          <p className="text-[20px] font-bold leading-snug text-zinc-900 dark:text-zinc-50">{tagName}</p>
          <p className="text-[11px] font-mono text-zinc-400 dark:text-zinc-500">{domain}</p>
          {desc && (
            <p className="text-[12px] leading-relaxed text-zinc-500 dark:text-zinc-400 mt-0.5 overflow-hidden"
               style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
          )}
          {link ? (
            <a href={link} className="inline-flex w-fit items-center gap-0.5 mt-1 text-[12px] font-semibold underline underline-offset-4 text-zinc-800 dark:text-zinc-200">
              {ctaHome} <RiArrowRightSLine className="w-3.5 h-3.5" />
            </a>
          ) : (
            <p className="mt-1 text-[12px] text-zinc-400 dark:text-zinc-500">{noLinkText}</p>
          )}
        </div>
      </div>
    </>
  );

  /* ═══ official — 官方·地址栏官方网站 ═════════════════════════════════ */
  if (themeKey === "official") return (
    <>
      <style>{`@keyframes off-verified{0%,100%{opacity:.85}50%{opacity:1}}`}</style>
      <div className="rounded-[16px] overflow-hidden bg-[#0f2b52] border border-[#1e3a8a]/60 shadow-[0_6px_28px_rgba(30,58,138,0.3)]">
        {/* Browser address bar */}
        <div className="flex items-center gap-2 px-4 py-3" style={{ background: "#0b2140" }}>
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/10">
            <svg viewBox="0 0 24 24" fill="none" stroke="#7dd3fc" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-3.5 w-3.5">
              <rect x="5" y="11" width="14" height="9" rx="2" />
              <path d="M8 11V8a4 4 0 0 1 8 0v3" />
            </svg>
          </span>
          <span className="flex-1 truncate rounded-lg bg-black/25 px-2.5 py-1 text-[11px] font-mono text-sky-200/80">
            https://{domain}
          </span>
          <span className="shrink-0 rounded-full px-2 py-0.5 text-[9px] font-bold text-white"
                style={{ background: "linear-gradient(135deg,#2563eb,#1d4ed8)" }}>
            {locale === "en" ? "Official" : "官方"}
          </span>
        </div>
        {/* Body */}
        <div className="px-5 pb-5 pt-4 text-left">
          <p className="text-[10px] font-semibold uppercase tracking-[0.25em] text-sky-400">
            {locale === "en" ? "Official Website" : "官方网站"}
          </p>
          <p className="mt-1.5 text-[20px] font-bold leading-tight text-white">{tagName}</p>
          <p className="mt-0.5 text-[11px] font-mono text-sky-300/50">{domain}</p>
          {desc && (
            <p className="mt-2 text-[12px] leading-relaxed text-slate-300/75 overflow-hidden"
               style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
          )}
          {link ? (
            <a href={link}
               className="mt-3 flex h-[38px] w-full items-center justify-center gap-1 rounded-[9px] bg-[#2563eb] text-[13px] font-semibold text-white">
              {ctaText} <RiArrowRightSLine className="w-4 h-4" />
            </a>
          ) : (
            <p className="mt-2 text-[12px] text-slate-400/60">{noLinkText}</p>
          )}
        </div>
      </div>
    </>
  );

  /* ═══ aurora — 品牌·极光沉浸 + 底浮层 ═════════════════════════════════ */
  if (themeKey === "aurora") return (
    <>
      <style>{`
        @keyframes au-shift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
        @keyframes au-breathe{0%,100%{opacity:.5}50%{opacity:.9}}
        @keyframes au-shimmer{0%{background-position:200% center}100%{background-position:-200% center}}
      `}</style>
      <div className="relative overflow-hidden rounded-[18px] border border-violet-400/30 shadow-[0_10px_34px_rgba(124,58,237,0.35)]">
        {/* Animated gradient backdrop */}
        <div className="absolute inset-0"
             style={{
               background: "linear-gradient(135deg,#7c3aed,#d946ef,#6366f1,#a855f7)",
               backgroundSize: "300% 300%",
               animation: "au-shift 10s ease infinite",
             }} />
        {/* Soft radial highlight */}
        <div className="absolute -top-10 left-1/2 h-32 w-4/5 -translate-x-1/2 rounded-full bg-white/25 blur-2xl"
             style={{ animation: "au-breathe 5s ease-in-out infinite" }} />
        <div className="relative flex min-h-[220px] flex-col justify-between px-5 pt-7 pb-5 text-center">
          <div>
            <span className="inline-flex items-center rounded-full border border-white/60 bg-white/15 px-3 py-1 text-[10px] font-semibold text-white backdrop-blur-sm">
              {badge}
            </span>
            <p className="mt-3 text-[26px] font-black leading-tight"
               style={{
                 background: "linear-gradient(90deg,#ffffff 20%,#fda4af 40%,#ffffff 50%,#d8b4fe 70%,#ffffff 80%)",
                 backgroundSize: "200% auto",
                 WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text",
                 animation: "au-shimmer 4.5s linear infinite",
               }}>{tagName}</p>
            <p className="mt-1 text-[11px] font-mono text-white/55">{domain}</p>
          </div>
          {/* Bottom floating panel */}
          <div className="mt-3 w-full rounded-[12px] border border-white/25 bg-black/30 px-4 py-3 text-left backdrop-blur-md">
            {desc && (
              <p className="text-[12px] leading-relaxed text-white/75 overflow-hidden"
                 style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
            )}
            {link ? (
              <a href={link}
                 className="mt-2.5 flex h-[40px] w-full items-center justify-center gap-1 rounded-[10px] bg-white text-[13px] font-bold text-[#7c3aed]">
                {ctaText} <RiArrowRightSLine className="w-4 h-4" />
              </a>
            ) : (
              <p className="mt-2 text-[12px] text-white/55">{noLinkText}</p>
            )}
          </div>
        </div>
      </div>
    </>
  );

  /* ═══ emerald — 认证·验证横幅卡 ══════════════════════════════════════ */
  if (themeKey === "emerald") return (
    <>
      <style>{`@keyframes em-ring{0%{transform:scale(1);opacity:.55}100%{transform:scale(1.75);opacity:0}}`}</style>
      <div className={cn(
        "rounded-[16px] overflow-hidden border bg-white dark:bg-zinc-900",
        "border-emerald-200 dark:border-emerald-800/60",
        "shadow-[0_3px_18px_rgba(16,185,129,0.14)] dark:shadow-none"
      )}>
        {/* Verification banner */}
        <div className="flex items-center gap-3.5 px-5 py-4"
             style={{ background: "linear-gradient(90deg,#ecfdf5,#d1fae5)" }}>
          <div className="relative h-12 w-12 shrink-0">
            <div className="absolute inset-0 rounded-full border-2 border-emerald-400/60"
                 style={{ animation: "em-ring 2.8s ease-out infinite" }} />
            <div className="relative flex h-12 w-12 items-center justify-center rounded-full"
                 style={{ background: "linear-gradient(135deg,#10b981,#059669)" }}>
              <svg viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2"
                   strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                <path d="M12 2l8 3.5v5c0 5-3.5 8.5-8 11.5-4.5-3-8-6.5-8-11.5v-5l8-3.5z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
          </div>
          <div className="min-w-0">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-emerald-700 dark:text-emerald-600">
              {locale === "en" ? "DNS Verified" : "已认证"}
            </p>
            <p className="mt-0.5 truncate text-[10px] font-mono text-emerald-700/50 dark:text-emerald-600/50">{domain}</p>
          </div>
        </div>
        <div className="px-5 pb-5 pt-3.5 text-left">
          <p className="text-[21px] font-extrabold leading-tight text-zinc-900 dark:text-zinc-50">{tagName}</p>
          {desc && (
            <p className="mt-1 text-[12px] leading-relaxed text-zinc-500 dark:text-zinc-400 overflow-hidden"
               style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
          )}
          {link ? (
            <a href={link}
               className="mt-3 flex h-[42px] w-full items-center justify-center gap-1 rounded-[10px] bg-[#059669] text-[13px] font-semibold text-white">
              {ctaText} <RiArrowRightSLine className="w-4 h-4" />
            </a>
          ) : (
            <p className="mt-2 text-[12px] text-zinc-400 dark:text-zinc-500">{noLinkText}</p>
          )}
        </div>
      </div>
    </>
  );

  /* ═══ solar — 合作·金色横幅 + 香槟主体 ════════════════════════════════ */
  if (themeKey === "solar") return (
    <>
      <style>{`@keyframes sol-breathe{0%,100%{transform:scaleX(.4);opacity:.6}50%{transform:scaleX(1);opacity:1}}`}</style>
      <div className="rounded-[16px] overflow-hidden border border-amber-200/30 bg-[#1c1610] shadow-[0_6px_26px_rgba(0,0,0,0.4)]">
        {/* Gold banner */}
        <div className="flex items-center justify-center gap-2.5 px-5 py-3.5"
             style={{ background: "linear-gradient(90deg,#b8860b,#d4a84b,#b8860b)" }}>
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 border-[#1c1610]/30">
            <RiShakeHandsLine className="h-4 w-4 text-[#1c1610]" />
          </div>
          <p className="text-[11px] font-bold uppercase tracking-[0.28em] text-[#1c1610]">
            {locale === "en" ? "Partner" : "合作伙伴"}
          </p>
        </div>
        <div className="px-5 pb-[18px] pt-4 text-center">
          <p className="text-[22px] font-bold leading-tight text-[#f5efe2]">{tagName}</p>
          <p className="mt-1 text-[11px] font-mono text-[#d4a84b]/70">{domain}</p>
          {desc && (
            <p className="mt-2.5 text-[12px] leading-relaxed text-[#e8dcc8]/70 overflow-hidden"
               style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
          )}
          {link ? (
            <a href={link}
               className="mt-3.5 flex h-[40px] w-full items-center justify-center gap-1 rounded-[10px] text-[13px] font-bold text-[#1c1610]"
               style={{ background: "linear-gradient(135deg,#d4a84b,#b8860b)" }}>
              {ctaText} <RiArrowRightSLine className="w-4 h-4" />
            </a>
          ) : (
            <p className="mt-2 text-[12px] text-[#d4a84b]/50">{noLinkText}</p>
          )}
        </div>
      </div>
    </>
  );

  /* ═══ dev — 开发·终端窗口 ═══════════════════════════════════════════ */
  if (themeKey === "dev") return (
    <>
      <style>{`
        @keyframes dev-cursor{0%,100%{opacity:1}50%{opacity:0}}
        @keyframes dev-scan{0%{top:-4%;opacity:.6}100%{top:110%;opacity:0}}
      `}</style>
      <div className="rounded-[12px] overflow-hidden border border-[#30363d] bg-[#0d1117] shadow-[0_6px_28px_rgba(0,0,0,0.6)]"
           style={{ fontFamily: "'SF Mono','Fira Code',ui-monospace,Menlo,monospace" }}>
        {/* macOS-style title bar */}
        <div className="flex items-center gap-1.5 px-3.5 py-2.5 bg-[#161b22] border-b border-[#21262d]">
          <span className="h-[10px] w-[10px] rounded-full bg-[#ff5f56] shrink-0" />
          <span className="h-[10px] w-[10px] rounded-full bg-[#ffbd2e] shrink-0" />
          <span className="h-[10px] w-[10px] rounded-full bg-[#27c93f] shrink-0" />
          <span className="flex-1" />
          <span className="truncate max-w-[55%] text-[11px] text-[#8b949e] tracking-wide">{tagName} — zsh</span>
          <span className="shrink-0 rounded-full border border-[#2ea043] bg-[#238636]/20 px-1.5 py-px text-[9px] font-semibold text-[#7ee787]">
            {locale === "en" ? "VERIFIED" : "已验证"}
          </span>
        </div>
        {/* Terminal body */}
        <div className="relative min-h-[150px] overflow-hidden px-3.5 py-4">
          <div className="absolute left-0 right-0 h-px"
               style={{ background: "linear-gradient(90deg,transparent,rgba(56,139,253,0.35),transparent)", animation: "dev-scan 4s linear infinite" }} />
          <p className="m-0 text-[12px] leading-[1.9]">
            <span className="text-[#7ee787]">$</span>{" "}
            <span className="text-[#79c0ff]">whois</span>{" "}
            <span className="text-[#ffa657]">--claim</span>{" "}
            <span className="text-[#a5d6ff]">{tagName}</span>
          </p>
          <p className="m-0 text-[12px] leading-[1.9]">
            <span className="text-[#79c0ff]">domain:</span>{" "}
            <span className="text-[#a5d6ff]">{domain}</span>
          </p>
          <p className="m-0 text-[12px] leading-[1.9]">
            <span className="text-[#79c0ff]">status:</span>{" "}
            <span className="text-[#7ee787]">verified</span>
          </p>
          <p className="m-0 text-[12px] leading-[1.9]">
            <span className="text-[#79c0ff]">type:</span>{" "}
            <span className="text-[#ffa657]">{badge}<span style={{ animation: "dev-cursor 1s step-end infinite" }}>▌</span></span>
          </p>
          {desc && (
            <p className="mt-1 m-0 text-[11px] leading-[1.7] text-[#8b949e] overflow-hidden"
               style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
              <span className="text-[#7ee787]">#</span> {desc}
            </p>
          )}
        </div>
        <div className="m-3.5">
          {link ? (
            <a href={link}
               className="flex h-9 w-full items-center justify-center gap-1 rounded-md bg-[#238636] border border-[#2ea043] text-[12px] font-semibold text-white">
              <span className="text-[#7ee787]">→</span> {ctaText}
            </a>
          ) : (
            <p className="py-1.5 text-center text-[12px] text-[#8b949e]">{noLinkText}</p>
          )}
        </div>
      </div>
    </>
  );

  /* ═══ warning — 警示·安全横幅 ════════════════════════════════════════ */
  if (themeKey === "warning") return (
    <>
      <div className={cn(
        "rounded-[14px] overflow-hidden border-2 bg-white dark:bg-[#1c1010]",
        "border-red-200 dark:border-red-900/70",
        "shadow-[0_3px_18px_rgba(220,38,38,0.14)] dark:shadow-none"
      )}>
        {/* Red banner */}
        <div className="relative flex items-center gap-3 px-4 py-3.5"
             style={{ background: "linear-gradient(120deg,#dc2626,#b91c1c)" }}>
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white/20 ring-1 ring-white/30">
            <svg viewBox="0 0 24 24" fill="currentColor" className="h-4 w-4 text-white">
              <path d="M12 2L1 21h22L12 2zm1 15h-2v2h2v-2zm0-8h-2v6h2V9z" />
            </svg>
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[13px] font-extrabold leading-tight text-white">{locale === "en" ? "Risk Notice" : "风险提示"}</p>
            <p className="text-[10px] text-white/75 tracking-wide">
              WARNING · {locale === "en" ? "Please proceed with caution" : "请谨慎访问"}
            </p>
          </div>
          <span className="shrink-0 rounded-md bg-white/15 px-2 py-1 text-[9px] font-bold uppercase tracking-widest text-white ring-1 ring-white/25">
            {locale === "en" ? "Caution" : "注意"}
          </span>
        </div>
        {/* Body */}
        <div className="px-4 pb-[18px] pt-4 text-left">
          <p className="text-[17px] font-bold leading-tight text-[#991b1b] dark:text-[#fca5a5]">{tagName}</p>
          <p className="mt-0.5 text-[11px] font-mono text-red-800/60 dark:text-red-200/50">{domain}</p>
          {desc && (
            <div className="mt-2.5 rounded-lg border border-red-100 bg-[#fef2f2] dark:border-red-900/50 dark:bg-[#2a1212] px-3 py-2.5">
              <p className="text-[12px] leading-relaxed text-red-900 dark:text-red-100/80 overflow-hidden"
                 style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
            </div>
          )}
          {link ? (
            <a href={link}
               className="mt-3.5 flex h-10 w-full items-center justify-center gap-1 rounded-[10px] bg-[#dc2626] text-[13px] font-semibold text-white">
              {ctaText} <RiArrowRightSLine className="w-4 h-4" />
            </a>
          ) : (
            <p className="mt-2 text-[12px] text-red-400/70 dark:text-red-300/50">{noLinkText}</p>
          )}
        </div>
      </div>
    </>
  );

  /* ═══ premium — 尊享·彩虹描边双框 ════════════════════════════════════ */
  if (themeKey === "premium") return (
    <>
      <style>{`
        @keyframes prem-flow{0%{background-position:0% 50%}100%{background-position:300% 50%}}
        @keyframes prem-shimmer{0%{background-position:200% center}100%{background-position:-200% center}}
        @keyframes prem-btn-sweep{0%{transform:translateX(-140%) skewX(-20deg)}100%{transform:translateX(340%) skewX(-20deg)}}
      `}</style>
      {/* Rainbow gradient frame */}
      <div className="rounded-[18px] p-[2px]"
           style={{
             background: "linear-gradient(135deg,#a855f7,#e879f9,#f43f5e,#fbbf24,#a855f7)",
             backgroundSize: "300% 300%",
             animation: "prem-flow 5s linear infinite",
           }}>
        <div className="rounded-[16px] overflow-hidden bg-[#12081a] text-center">
          <div className="relative overflow-hidden px-5 pt-[26px] pb-4">
            {/* Diagonal sweep on hero */}
            <div className="absolute inset-y-0 w-[40%]"
                 style={{
                   background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.05),transparent)",
                   transform: "skewX(-20deg)",
                 }} />
            <span className="mx-auto flex h-11 w-11 items-center justify-center rounded-full text-[22px] leading-none text-[#f5c542]"
                  style={{ background: "rgba(245,197,66,0.12)", border: "1px solid rgba(245,197,66,0.35)", boxShadow: "0 0 18px rgba(245,197,66,0.35)" }}>♛</span>
            <span className="mt-2 inline-flex items-center rounded-full border border-[#d4a84b]/60 bg-[#d4a84b]/15 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.22em] text-[#e6c25a]">
              {locale === "en" ? "Premium" : "尊享"}
            </span>
            <p className="mt-3 text-[24px] font-black leading-tight"
               style={{
                 background: "linear-gradient(90deg,#ffffff 20%,#f9a8d4 40%,#f5c542 55%,#ffffff 80%)",
                 backgroundSize: "200% auto",
                 WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text",
                 animation: "prem-shimmer 5s linear infinite",
               }}>{tagName}</p>
            <p className="mt-1 text-[11px] font-mono text-white/40">{domain}</p>
          </div>
          <div className="px-5 pb-5 pt-3 text-center" style={{ borderTop: "1px solid rgba(255,255,255,0.15)" }}>
            {desc && (
              <p className="text-[12px] leading-relaxed text-[#f3d7ff]/70 overflow-hidden"
                 style={{ display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>{desc}</p>
            )}
            {link ? (
              <a href={link}
                 className="relative mt-3 flex h-[42px] w-full items-center justify-center gap-1 overflow-hidden rounded-[10px] text-[13px] font-bold text-white shadow-[0_4px_18px_rgba(168,85,247,0.5)]"
                 style={{ background: "linear-gradient(135deg,#a855f7,#d946ef)" }}>
                <span className="absolute inset-y-0 w-[35%]"
                      style={{
                        background: "linear-gradient(90deg,transparent,rgba(255,255,255,0.28),transparent)",
                        animation: "prem-btn-sweep 2.6s ease-in-out infinite",
                      }} />
                <span className="relative flex items-center gap-1">{ctaText} <RiArrowRightSLine className="w-4 h-4" /></span>
              </a>
            ) : (
              <p className="mt-2 text-[12px] text-white/40">{noLinkText}</p>
            )}
          </div>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: neon — 霓虹·赛博网格
  ════════════════════════════════════════ */
  if (t.layout === "neon") return (
    <>
      <style>{`
        ${BASE_ANIM}
        @keyframes neon-flicker{0%,100%{opacity:1}6%{opacity:.55}8%{opacity:1}11%{opacity:.7}14%{opacity:1}}
        @keyframes neon-grid-move{0%{background-position:0 0}100%{background-position:0 42px}}
        @keyframes neon-title-glow{0%,100%{text-shadow:0 0 8px rgba(0,229,255,.7),0 0 22px rgba(0,229,255,.4),0 0 44px rgba(0,229,255,.25)}50%{text-shadow:0 0 14px rgba(0,229,255,.95),0 0 34px rgba(0,229,255,.6),0 0 66px rgba(0,229,255,.35)}}
        @keyframes neon-sun{0%,100%{opacity:.5}50%{opacity:.85}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg" style={{ background: "#07030d" }}>
        {/* Grid horizon backdrop */}
        <div className="relative flex flex-col items-center px-4 pt-7 pb-4 text-center overflow-hidden">
          {/* Synthwave grid floor */}
          <div className="absolute inset-x-0 bottom-0 h-[46%]"
               style={{
                 backgroundImage: "linear-gradient(to right,rgba(0,229,255,0.16) 1px,transparent 1px),linear-gradient(to bottom,rgba(0,229,255,0.16) 1px,transparent 1px)",
                 backgroundSize: "26px 26px",
                 transform: "perspective(220px) rotateX(62deg)",
                 transformOrigin: "bottom",
                 animation: "neon-grid-move 1.2s linear infinite",
               }} />
          {/* Neon sun */}
          <div className="absolute left-1/2 -translate-x-1/2 bottom-0 h-14 w-24 rounded-t-full"
               style={{ background: "linear-gradient(to top,#ff2ec4,rgba(255,46,196,0.15))", filter: "blur(1px)", animation: "neon-sun 3.5s ease-in-out infinite" }} />
          <div className="absolute inset-x-0 bottom-[2px] h-px" style={{ background: "linear-gradient(90deg,transparent,#00e5ff,transparent)" }} />
          {/* Header */}
          <span className="relative z-10 inline-block font-bold font-mono rounded-full" style={{ ...badgeAnim, padding: SZ.badgePad, fontSize: SZ.badgeFs, background: "rgba(255,46,196,0.12)", border: "1px solid rgba(255,46,196,0.6)", color: "#ff6ad5", marginBottom: 12 }}>{badge}</span>
          <p className="relative z-10 font-black leading-tight tracking-tight" style={{ fontSize: SZ.titleFs, margin: 0, color: "#00E5FF", animation: "neon-title-glow 2.2s ease-in-out infinite, neon-flicker 6s linear infinite" }}>{tagName}</p>
          <p className="relative z-10 font-mono tracking-[0.15em] mt-2" style={{ fontSize: SZ.domainFs, color: "rgba(0,229,255,0.55)" }}>{domain}</p>
        </div>
        <div className="px-4 pt-2 pb-4 text-center" style={{ borderTop: "1px solid rgba(255,46,196,0.25)" }}>
          {desc && <p style={{ fontSize: SZ.descFs, color: "rgba(150,190,220,0.85)", lineHeight: 1.6, marginBottom: 12, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" } as React.CSSProperties}>{desc}</p>}
          {link ? <a href={link} className="inline-flex items-center gap-1.5 rounded-full font-bold text-white" style={{ padding: SZ.btnPad, fontSize: SZ.btnFs, background: "linear-gradient(135deg,#00E5FF,#FF2EC4)", boxShadow: "0 0 22px rgba(0,229,255,0.45),0 0 30px rgba(255,46,196,0.3)" }}>
            {ctaText} <RiArrowRightSLine style={{ width: SZ.btnIconSz, height: SZ.btnIconSz, opacity: .9 }} />
          </a> : <p style={{ fontSize: SZ.noLinkFs, textAlign: "center", margin: 0, padding: "8px 0", opacity: 0.35, color: "#00E5FF" }}>{noLinkText}</p>}
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: gradient — 渐变·流光
  ════════════════════════════════════════ */
  if (t.layout === "gradient") return (
    <>
      <style>{`${BASE_ANIM} @keyframes grad-shift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}`}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg" style={{ background: "linear-gradient(135deg,#FF6B6B,#FFD93D,#6BCB77,#4D96FF,#C77DFF,#FF6B6B)", backgroundSize: "300% 300%", animation: "grad-shift 5s ease infinite" }}>
        <div className="flex flex-col items-center pt-6 pb-3 text-center px-4">
          <span className="inline-block font-bold rounded-full" style={{ ...badgeAnim, padding: SZ.badgePad, fontSize: SZ.badgeFs, background: "rgba(255,255,255,0.5)", backdropFilter: "blur(8px)", border: "1px solid rgba(255,255,255,0.7)", color: "rgba(20,20,20,0.8)", marginBottom: 12 }}>{badge}</span>
          <p className="font-black leading-tight tracking-tight" style={{ background: "linear-gradient(90deg,rgba(20,20,20,0.7) 20%,rgba(20,20,20,1) 50%,rgba(20,20,20,0.7) 80%)", backgroundSize: "200% auto", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text", animation: "card-sheen 3s linear infinite", fontSize: SZ.titleFs, margin: 0, textShadow: "none" }}>{tagName}</p>
          <p className="font-mono tracking-wider mt-2" style={{ fontSize: SZ.domainFs, color: "rgba(20,20,20,0.42)" }}>{domain}</p>
          {desc && <p style={{ fontSize: SZ.descFs, color: "rgba(20,20,20,0.6)", lineHeight: 1.6, marginTop: 8, overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" } as React.CSSProperties}>{desc}</p>}
        </div>
        <div className="flex justify-center pb-4 pt-2">
          {link ? <a href={link} className="inline-flex items-center gap-1.5 rounded-full font-bold text-white" style={{ padding: SZ.btnPad, fontSize: SZ.btnFs, background: "rgba(10,10,20,0.82)", backdropFilter: "blur(8px)" }}>
            {ctaText} <RiArrowRightSLine style={{ width: SZ.btnIconSz, height: SZ.btnIconSz, opacity: .85 }} />
          </a> : <p style={{ fontSize: SZ.noLinkFs, textAlign: "center", margin: 0, padding: "8px 0", opacity: 0.5, color: "#111" }}>{noLinkText}</p>}
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: split — 分栏·黑白
  ════════════════════════════════════════ */
  if (t.layout === "split") return (
    <>
      <style>{`
        ${BASE_ANIM}
        @keyframes split-bar{0%{background:linear-gradient(to bottom,#60a5fa,#818cf8,#c084fc);opacity:.7}50%{background:linear-gradient(to bottom,#38bdf8,#6366f1,#e879f9);opacity:1}100%{background:linear-gradient(to bottom,#60a5fa,#818cf8,#c084fc);opacity:.7}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg flex">
        {/* Left black panel */}
        <div className="relative flex flex-col items-center justify-center w-[38%] shrink-0 overflow-hidden gap-2 py-5" style={{ background: "#000" }}>
          <div className="absolute top-0 right-0 w-[2.5px] h-full" style={{ animation: "split-bar 2.5s ease-in-out infinite" }} />
          <span className="relative z-10 font-bold text-center px-2 py-1 rounded-lg" style={{ ...badgeAnim, fontSize: SZ.badgeFs, background: "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.14)", color: "rgba(255,255,255,0.75)" }}>{badge}</span>
          <p className="relative z-10 font-mono text-center px-2 truncate" style={{ fontSize: SZ.domainFs - 2, color: "rgba(255,255,255,0.3)", letterSpacing: "0.06em" }}>{domain}</p>
        </div>
        {/* Right white panel */}
        <div className="flex-1 flex flex-col justify-between px-4 py-4" style={{ background: "#FAFAFA" }}>
          <div>
            <p className="font-black text-gray-900 leading-none tracking-tight mb-2" style={{ ...{ background: "linear-gradient(90deg,#111 25%,#555 50%,#111 75%)", backgroundSize: "200% auto", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text", animation: "card-sheen 3s linear infinite" }, fontSize: SZ.titleFs - 2 }}>{tagName}</p>
            {desc && <p className="leading-relaxed line-clamp-2" style={{ fontSize: SZ.descFs, color: "#9ca3af" }}>{desc}</p>}
          </div>
          {link ? <a href={link} className="flex items-center justify-between mt-3 rounded-[10px] text-white font-bold shrink-0" style={{ fontSize: SZ.btnFs, padding: SZ.btnPad, background: "#111" }}>
            <span>{ctaText}</span>
            <RiArrowRightSLine style={{ width: SZ.btnIconSz, height: SZ.btnIconSz, opacity: .8 }} />
          </a> : <p style={{ fontSize: SZ.noLinkFs, textAlign: "center", margin: "12px 0 0", opacity: 0.4, color: "#6b7280" }}>{noLinkText}</p>}
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: flash — 特卖·电光
  ════════════════════════════════════════ */
  if (t.layout === "flash") return (
    <>
      <style>{`
        ${BASE_ANIM}
        @keyframes flash-panel{0%,100%{background:#FFE500}18%{background:#FFF100}19%{background:#FFE500}}
        @keyframes flash-cta{0%,100%{box-shadow:0 2px 8px rgba(255,56,0,0.28)}50%{box-shadow:0 4px 18px rgba(255,56,0,0.55)}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg">
        {/* Top bar */}
        <div className="px-4 py-2.5 flex items-center" style={{ background: "#FF3800" }}>
          <p className="font-mono flex-1 truncate" style={{ fontSize: SZ.domainFs - 2, color: "rgba(255,255,255,0.85)" }}>{domain}</p>
        </div>
        <div className="flex">
          {/* Left yellow panel */}
          <div className="w-[40%] shrink-0 relative overflow-hidden flex flex-col items-center justify-center px-3 py-5 gap-2" style={{ animation: "flash-panel 2.2s ease-in-out infinite" }}>
            <svg className="absolute top-2 right-2 pointer-events-none opacity-30" width={14} height={22} viewBox="0 0 10 18" fill="rgba(255,80,0,0.7)">
              <path d="M7 0L1 10h5L3 18l8-11H6L7 0Z" />
            </svg>
            <span className="relative z-10 font-bold text-center px-2 py-1 rounded-lg" style={{ ...badgeAnim, fontSize: SZ.badgeFs, background: "rgba(255,56,0,0.12)", border: "1.5px solid rgba(255,56,0,0.3)", color: "#c2410c" }}>{badge}</span>
          </div>
          {/* Right white */}
          <div className="flex-1 flex flex-col justify-between px-4 py-4 bg-white">
            <div>
              <p className="font-black text-gray-900 leading-none tracking-tight mb-2" style={{ ...{ background: "linear-gradient(90deg,#111 25%,#c2410c 50%,#111 75%)", backgroundSize: "200% auto", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text", animation: "card-sheen 3s linear infinite" }, fontSize: SZ.titleFs - 2 }}>{tagName}</p>
              {desc && <p className="leading-relaxed line-clamp-2" style={{ fontSize: SZ.descFs, color: "#9ca3af" }}>{desc}</p>}
            </div>
            {link ? <a href={link} className="inline-flex items-center gap-1.5 mt-3 rounded-full font-bold text-white shrink-0" style={{ fontSize: SZ.btnFs, padding: SZ.btnPad, background: "linear-gradient(135deg,#FF3800,#FF6800)", animation: "flash-cta 2s ease-in-out infinite" }}>
              {ctaText} <RiArrowRightSLine style={{ width: SZ.btnIconSz, height: SZ.btnIconSz, opacity: .85 }} />
            </a> : <p style={{ fontSize: SZ.noLinkFs, textAlign: "center", margin: "12px 0 0", opacity: 0.4, color: "#6b7280" }}>{noLinkText}</p>}
          </div>
        </div>
      </div>
    </>
  );

  /* Fallback */
  return null;
}
