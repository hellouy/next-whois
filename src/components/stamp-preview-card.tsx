/**
 * StampPreviewCard — shared popup preview component.
 * Used by: admin/stamp-styles.tsx, admin/stamps.tsx, stamp.tsx, dashboard.tsx
 *
 * Each theme has its own layout personality — not just color swaps.
 */
import React from "react";
import { cn } from "@/lib/utils";
import { RiShieldCheckLine, RiArrowRightSLine, RiGlobalLine } from "@remixicon/react";

export type CardThemeDef = {
  hero: string; shimmer: string;
  badge: string; btn: string;
  cardBg: string; cardBorder: string; cardText: string;
  layout?: "default" | "celebrate" | "neon" | "gradient" | "split" | "flash";
  accent?: string; accentText?: string;
};

export const STAMP_CARD_THEMES: Record<string, CardThemeDef & { label: string; special?: string }> = {
  app:      { label: "极简",     hero: "bg-gradient-to-br from-zinc-600 to-zinc-900",                    shimmer: "text-shimmer",                   badge: "bg-zinc-100 text-zinc-600 border border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",                                btn: "bg-zinc-900 text-white",                                                      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  official: { label: "官方",     hero: "bg-gradient-to-br from-blue-600 to-indigo-800",                  shimmer: "text-foreground font-black",       badge: "bg-blue-50 text-blue-700 border border-blue-200/80 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800/60",                    btn: "bg-blue-700 text-white",                                                      cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  aurora:   { label: "极光",     hero: "bg-gradient-to-br from-violet-500 via-fuchsia-500 to-purple-700", shimmer: "text-foreground font-black",       badge: "bg-violet-50 text-violet-700 border border-violet-200/80 dark:bg-violet-950/60 dark:text-violet-300 dark:border-violet-800/60",      btn: "bg-violet-600 text-white",                                                    cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  emerald:  { label: "翡翠",     hero: "bg-gradient-to-br from-emerald-400 to-teal-700",                 shimmer: "text-foreground font-black",       badge: "bg-emerald-50 text-emerald-700 border border-emerald-200/80 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/60", btn: "bg-emerald-600 text-white",                                                   cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  solar:    { label: "暖阳",     hero: "bg-gradient-to-br from-amber-400 to-orange-600",                 shimmer: "text-foreground font-black",       badge: "bg-amber-50 text-amber-700 border border-amber-200/80 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/60",              btn: "bg-orange-500 text-white",                                                    cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  dev:      { label: "开发",     hero: "bg-gradient-to-br from-slate-600 to-[#0d1117]",                  shimmer: "text-[#58a6ff] font-black font-mono", badge: "bg-[#161b22] text-[#58a6ff] border border-[#30363d]",                                                                                btn: "bg-[#238636] text-white",                                                     cardBg: "bg-zinc-950",   cardBorder: "border-zinc-800",  cardText: "text-zinc-200" },
  warning:  { label: "警示",     hero: "bg-gradient-to-br from-yellow-400 to-amber-600",                 shimmer: "text-foreground font-black",       badge: "bg-yellow-50 text-yellow-800 border border-yellow-300/80 dark:bg-yellow-950/60 dark:text-yellow-300 dark:border-yellow-800/60",       btn: "bg-amber-500 text-white",                                                     cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  premium:  { label: "尊享",     hero: "bg-gradient-to-br from-purple-600 via-fuchsia-500 to-rose-500",  shimmer: "text-foreground font-black",       badge: "bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200/80 dark:bg-fuchsia-950/60 dark:text-fuchsia-300 dark:border-fuchsia-800/60", btn: "bg-gradient-to-r from-purple-600 to-fuchsia-500 text-white",                  cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  celebrate: { label: "庆典",     layout: "celebrate", hero: "bg-gradient-to-br from-red-700 to-red-900",                     shimmer: "text-white font-black",    badge: "bg-amber-400 text-amber-900 border-0", btn: "bg-amber-500 text-white",  cardBg: "bg-white",       cardBorder: "border-amber-100",  cardText: "text-gray-900", special: "🎊" },
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
  icon?: React.ElementType;
}

const DEMO: Required<StampPreviewData> & { icon: React.ElementType } = {
  tagName:     "不讲•李",
  domain:      "hello.sn",
  description: "域名爱好者，专注稀缺后缀收藏与品牌孵化。",
  link:        "https://hello.sn",
  tagLabel:    "开发者",
  icon:        RiGlobalLine,
};

function mono2(name: string) { return name.replace(/[•·\s]/g, "").slice(0, 2).toUpperCase(); }
function mono1(name: string) { return name.replace(/[•·\s]/g, "").slice(0, 1).toUpperCase(); }

export function StampPreviewCard({ themeKey, data }: { themeKey: string; data?: StampPreviewData }) {
  const t = STAMP_CARD_THEMES[themeKey] ?? STAMP_CARD_THEMES.app;
  if (!t) return null;

  const tagName  = data?.tagName    || DEMO.tagName;
  const domain   = data?.domain     || DEMO.domain;
  const desc     = data?.description || DEMO.description;
  const link     = data?.link       || DEMO.link;
  const tagLabel = data?.tagLabel   || DEMO.tagLabel;

  /* ═══ app — 苹果式极简 ════════════════════════════════════════════════ */
  if (themeKey === "app") return (
    <div style={{ background: "#fff", borderRadius: 16, overflow: "hidden", boxShadow: "0 2px 16px rgba(0,0,0,0.08)" }}>
      {/* Full-width charcoal banner */}
      <div style={{ background: "linear-gradient(135deg,#1c1c1e,#3a3a3c)", padding: "18px 16px 14px", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 40, height: 40, borderRadius: 12, background: "rgba(255,255,255,0.1)", border: "1px solid rgba(255,255,255,0.15)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 14, color: "rgba(255,255,255,0.88)", letterSpacing: -0.5, flexShrink: 0 }}>
          {mono2(tagName)}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ margin: 0, fontWeight: 800, fontSize: 14, color: "#fff", letterSpacing: -0.3, lineHeight: 1.2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{tagName}</p>
          <p style={{ margin: "2px 0 0", fontFamily: "monospace", fontSize: 9, color: "rgba(255,255,255,0.35)", letterSpacing: "0.12em" }}>{domain}</p>
        </div>
        <span style={{ background: "rgba(255,255,255,0.12)", border: "1px solid rgba(255,255,255,0.18)", borderRadius: 6, padding: "3px 7px", fontSize: 9, fontWeight: 700, color: "rgba(255,255,255,0.7)", flexShrink: 0 }}>{tagLabel}</span>
      </div>
      {/* Body */}
      <div style={{ padding: "12px 16px 14px" }}>
        {desc && <p style={{ margin: "0 0 10px", fontSize: 10, color: "#888", lineHeight: 1.6, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
        <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "#1c1c1e", color: "#fff", borderRadius: 10, padding: "9px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none" }}>
          访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.7 }} />
        </a>
      </div>
    </div>
  );

  /* ═══ official — 商务名片横版 ═════════════════════════════════════════ */
  if (themeKey === "official") return (
    <div style={{ background: "#fff", borderRadius: 16, overflow: "hidden", boxShadow: "0 2px 16px rgba(0,0,0,0.1)" }}>
      {/* Blue side-stripe + header */}
      <div style={{ display: "flex", background: "linear-gradient(135deg,#1D4ED8,#3730A3)", padding: "14px 14px 14px 0", gap: 0 }}>
        {/* Blue accent stripe */}
        <div style={{ width: 5, background: "rgba(255,255,255,0.3)", borderRadius: "0 3px 3px 0", flexShrink: 0, marginRight: 12 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: "rgba(255,255,255,0.15)", border: "1px solid rgba(255,255,255,0.25)", borderRadius: 20, padding: "2px 8px", fontSize: 8, fontWeight: 700, color: "rgba(255,255,255,0.9)", marginBottom: 6 }}>
            <RiShieldCheckLine style={{ width: 8, height: 8 }} />{tagLabel}
          </span>
          <p style={{ margin: 0, fontWeight: 900, fontSize: 15, color: "#fff", letterSpacing: -0.4, lineHeight: 1.15 }}>{tagName}</p>
          <p style={{ margin: "3px 0 0", fontFamily: "monospace", fontSize: 9, color: "rgba(255,255,255,0.4)", letterSpacing: "0.15em" }}>{domain}</p>
        </div>
        {/* Seal */}
        <div style={{ width: 44, height: 44, borderRadius: "50%", background: "rgba(255,255,255,0.15)", border: "2px solid rgba(255,255,255,0.3)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
          <RiShieldCheckLine style={{ width: 22, height: 22, color: "rgba(255,255,255,0.9)" }} />
        </div>
      </div>
      {/* White body */}
      <div style={{ padding: "10px 14px 13px" }}>
        {desc && <p style={{ margin: "0 0 8px", fontSize: 10, color: "#6b7280", lineHeight: 1.6, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
        <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "#1D4ED8", color: "#fff", borderRadius: 10, padding: "9px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none" }}>
          访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.7 }} />
        </a>
      </div>
    </div>
  );

  /* ═══ aurora — 暗色极光玻璃 ══════════════════════════════════════════ */
  if (themeKey === "aurora") return (
    <>
      <style>{`
        @keyframes au-shift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
        @keyframes au-float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-4px)} }
      `}</style>
      <div style={{ borderRadius: 16, overflow: "hidden", background: "#0f0728", boxShadow: "0 4px 24px rgba(124,58,237,0.3)" }}>
        {/* Aurora header */}
        <div style={{ position: "relative", padding: "20px 16px 16px", overflow: "hidden", textAlign: "center" }}>
          <div style={{ position: "absolute", inset: 0, background: "linear-gradient(135deg,#7c3aed,#c026d3,#7c3aed,#4f46e5)", backgroundSize: "300% 300%", animation: "au-shift 6s ease infinite", opacity: 0.85 }} />
          {/* Glow orbs */}
          <div style={{ position: "absolute", top: -20, left: "20%", width: 80, height: 80, borderRadius: "50%", background: "rgba(255,100,200,0.3)", filter: "blur(30px)", pointerEvents: "none" }} />
          <div style={{ position: "absolute", bottom: -10, right: "15%", width: 70, height: 70, borderRadius: "50%", background: "rgba(100,50,255,0.35)", filter: "blur(25px)", pointerEvents: "none" }} />
          {/* Badge */}
          <span style={{ position: "relative", zIndex: 1, display: "inline-flex", alignItems: "center", gap: 4, background: "rgba(255,255,255,0.15)", border: "1px solid rgba(255,255,255,0.3)", borderRadius: 20, padding: "3px 10px", fontSize: 8, fontWeight: 700, color: "rgba(255,255,255,0.95)", marginBottom: 8 }}>
            <RiShieldCheckLine style={{ width: 8, height: 8 }} />{tagLabel}
          </span>
          {/* Avatar */}
          <div style={{ position: "relative", zIndex: 1, display: "inline-flex", animation: "au-float 3s ease-in-out infinite", background: "rgba(255,255,255,0.15)", backdropFilter: "blur(12px)", border: "1.5px solid rgba(255,255,255,0.3)", borderRadius: 14, width: 48, height: 48, alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 16, color: "#fff" }}>
            {mono2(tagName)}
          </div>
          <p style={{ position: "relative", zIndex: 1, margin: "8px 0 0", fontWeight: 900, fontSize: 14, color: "#fff", letterSpacing: -0.3 }}>{tagName}</p>
          <p style={{ position: "relative", zIndex: 1, margin: "2px 0 0", fontFamily: "monospace", fontSize: 8, color: "rgba(255,255,255,0.35)", letterSpacing: "0.15em" }}>{domain}</p>
        </div>
        {/* Dark body */}
        <div style={{ padding: "10px 14px 13px", background: "rgba(0,0,0,0.3)" }}>
          {desc && <p style={{ margin: "0 0 8px", fontSize: 10, color: "rgba(200,180,255,0.7)", lineHeight: 1.6, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
          <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "linear-gradient(135deg,#7c3aed,#c026d3)", color: "#fff", borderRadius: 10, padding: "9px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none", boxShadow: "0 0 16px rgba(124,58,237,0.45)" }}>
            访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.8 }} />
          </a>
        </div>
      </div>
    </>
  );

  /* ═══ emerald — 自然·绿野 ════════════════════════════════════════════ */
  if (themeKey === "emerald") return (
    <div style={{ background: "linear-gradient(145deg,#065f46,#047857,#059669)", borderRadius: 16, overflow: "hidden", boxShadow: "0 4px 20px rgba(5,150,105,0.35)" }}>
      {/* Hexagon pattern overlay */}
      <div style={{ position: "relative", padding: "18px 16px 14px", overflow: "hidden" }}>
        <div style={{ position: "absolute", inset: 0, opacity: 0.06, backgroundImage: `url("data:image/svg+xml,%3Csvg width='40' height='46' viewBox='0 0 40 46' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M20 1l19 11v22L20 45 1 34V12z' fill='none' stroke='white' stroke-width='1'/%3E%3C/svg%3E")`, backgroundSize: "40px 46px", pointerEvents: "none" }} />
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {/* Avatar */}
          <div style={{ width: 44, height: 44, borderRadius: "50%", background: "rgba(255,255,255,0.2)", border: "2px solid rgba(255,255,255,0.35)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 15, color: "#fff", flexShrink: 0 }}>
            {mono2(tagName)}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{ margin: 0, fontWeight: 900, fontSize: 14, color: "#fff", letterSpacing: -0.3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{tagName}</p>
            <p style={{ margin: "2px 0 0", fontFamily: "monospace", fontSize: 8, color: "rgba(255,255,255,0.4)", letterSpacing: "0.12em" }}>{domain}</p>
          </div>
          <span style={{ background: "rgba(255,255,255,0.18)", border: "1px solid rgba(255,255,255,0.3)", borderRadius: 6, padding: "3px 7px", fontSize: 8, fontWeight: 700, color: "rgba(255,255,255,0.9)", flexShrink: 0 }}>{tagLabel}</span>
        </div>
      </div>
      {/* Frosted body */}
      <div style={{ margin: "0 10px 10px", background: "rgba(255,255,255,0.12)", backdropFilter: "blur(8px)", borderRadius: 12, padding: "10px 12px 12px", border: "1px solid rgba(255,255,255,0.2)" }}>
        {desc && <p style={{ margin: "0 0 8px", fontSize: 10, color: "rgba(255,255,255,0.75)", lineHeight: 1.6, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
        <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "rgba(0,0,0,0.4)", color: "#fff", borderRadius: 9, padding: "8px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none" }}>
          访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.7 }} />
        </a>
      </div>
    </div>
  );

  /* ═══ solar — 暖阳·晨光 ══════════════════════════════════════════════ */
  if (themeKey === "solar") return (
    <>
      <style>{`@keyframes sol-ray { 0%,100%{opacity:.4;transform:rotate(0deg)} 50%{opacity:.7;transform:rotate(3deg)} }`}</style>
      <div style={{ background: "#fff8f0", borderRadius: 16, overflow: "hidden", boxShadow: "0 4px 20px rgba(251,146,60,0.3)" }}>
        {/* Radial sunrise header */}
        <div style={{ position: "relative", background: "radial-gradient(ellipse 100% 120% at 50% 0%,#fb923c 0%,#f59e0b 40%,#fbbf24 70%,#fef3c7 100%)", padding: "24px 16px 28px", textAlign: "center", overflow: "hidden" }}>
          {/* Sun rays */}
          {[0,30,60,90,120,150,180,210,240,270,300,330].map((deg,i) => (
            <div key={i} style={{ position: "absolute", top: "0%", left: "50%", width: 2, height: "55%", background: "linear-gradient(to bottom, rgba(255,255,255,0.35), transparent)", transformOrigin: "50% 0%", transform: `translateX(-50%) rotate(${deg}deg)`, animation: "sol-ray 3s ease-in-out infinite", animationDelay: `${i*0.15}s`, pointerEvents: "none" }} />
          ))}
          {/* Avatar */}
          <div style={{ position: "relative", zIndex: 1, display: "inline-flex", width: 48, height: 48, borderRadius: "50%", background: "rgba(255,255,255,0.92)", border: "2.5px solid rgba(255,255,255,0.9)", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 16, color: "#d97706", boxShadow: "0 4px 16px rgba(255,140,0,0.35)", marginBottom: 6 }}>
            {mono2(tagName)}
          </div>
          <p style={{ position: "relative", zIndex: 1, margin: 0, fontWeight: 900, fontSize: 14, color: "#7c2d12", letterSpacing: -0.3 }}>{tagName}</p>
        </div>
        {/* Warm body */}
        <div style={{ padding: "10px 14px 13px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 7 }}>
            <span style={{ fontSize: 8, fontFamily: "monospace", color: "#d97706", letterSpacing: "0.12em" }}>{domain}</span>
            <span style={{ flex: 1, height: 1, background: "#fed7aa" }} />
            <span style={{ background: "#fff3cd", border: "1px solid #fcd34d", borderRadius: 5, padding: "2px 6px", fontSize: 8, fontWeight: 700, color: "#92400e" }}>{tagLabel}</span>
          </div>
          {desc && <p style={{ margin: "0 0 8px", fontSize: 10, color: "#78350f", lineHeight: 1.6, opacity: 0.7, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
          <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "linear-gradient(135deg,#f97316,#ea580c)", color: "#fff", borderRadius: 10, padding: "9px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none", boxShadow: "0 3px 12px rgba(249,115,22,0.4)" }}>
            访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.8 }} />
          </a>
        </div>
      </div>
    </>
  );

  /* ═══ dev — 终端·代码 ════════════════════════════════════════════════ */
  if (themeKey === "dev") return (
    <>
      <style>{`@keyframes dev-cursor{0%,100%{opacity:1}50%{opacity:0}} @keyframes dev-scan{0%{top:-4%;opacity:.6}100%{top:110%;opacity:0}}`}</style>
      <div style={{ background: "#0d1117", borderRadius: 16, overflow: "hidden", boxShadow: "0 4px 20px rgba(0,0,0,0.6)", border: "1px solid #30363d" }}>
        {/* Terminal title bar */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 12px", background: "#161b22", borderBottom: "1px solid #30363d" }}>
          <span style={{ width: 9, height: 9, borderRadius: "50%", background: "#ff5f57", flexShrink: 0 }} />
          <span style={{ width: 9, height: 9, borderRadius: "50%", background: "#febc2e", flexShrink: 0 }} />
          <span style={{ width: 9, height: 9, borderRadius: "50%", background: "#28c840", flexShrink: 0 }} />
          <span style={{ flex: 1 }} />
          <span style={{ fontSize: 8, fontFamily: "monospace", color: "#8b949e", letterSpacing: "0.08em" }}>{domain} — bash</span>
        </div>
        {/* Code body */}
        <div style={{ padding: "12px 14px", position: "relative", overflow: "hidden" }}>
          {/* Scan line */}
          <div style={{ position: "absolute", left: 0, right: 0, height: 1, background: "linear-gradient(90deg,transparent,rgba(88,166,255,0.3),transparent)", animation: "dev-scan 4s linear infinite" }} />
          <p style={{ margin: 0, fontFamily: "monospace", fontSize: 9, color: "#8b949e", lineHeight: 2 }}>
            <span style={{ color: "#58a6ff" }}>$</span> <span style={{ color: "#79c0ff" }}>whois</span> <span style={{ color: "#a5d6ff" }}>{domain}</span>
          </p>
          <p style={{ margin: 0, fontFamily: "monospace", fontSize: 9, color: "#8b949e", lineHeight: 2 }}>
            <span style={{ color: "#3fb950" }}>owner:</span> <span style={{ color: "#e6edf3", fontWeight: 700 }}>{tagName}<span style={{ animation: "dev-cursor 1s step-end infinite" }}>▌</span></span>
          </p>
          <p style={{ margin: 0, fontFamily: "monospace", fontSize: 9, color: "#8b949e", lineHeight: 2 }}>
            <span style={{ color: "#3fb950" }}>type:</span>  <span style={{ color: "#ffa657" }}>{tagLabel}</span>
          </p>
          {desc && <p style={{ margin: "6px 0 0", fontFamily: "monospace", fontSize: 8, color: "#8b949e", lineHeight: 1.7, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
            <span style={{ color: "#3fb950" }}>#</span> {desc}
          </p>}
        </div>
        {/* Green CTA */}
        <div style={{ padding: "0 14px 13px" }}>
          <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "#238636", color: "#fff", borderRadius: 8, padding: "9px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none", fontFamily: "monospace", border: "1px solid #2ea043" }}>
            <span style={{ color: "#56d364" }}>→</span> 访问主页
          </a>
        </div>
      </div>
    </>
  );

  /* ═══ warning — 警示·危险 ════════════════════════════════════════════ */
  if (themeKey === "warning") return (
    <>
      <style>{`@keyframes warn-stripe{0%{background-position:0 0}100%{background-position:28px 0}} @keyframes warn-pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.06)}}`}</style>
      <div style={{ background: "#fff", borderRadius: 16, overflow: "hidden", boxShadow: "0 4px 20px rgba(251,191,36,0.35)", border: "2px solid #fbbf24" }}>
        {/* Hazard stripe header */}
        <div style={{ position: "relative", overflow: "hidden", padding: "14px 14px 12px", background: "#fbbf24" }}>
          <div style={{ position: "absolute", inset: 0, backgroundImage: "repeating-linear-gradient(45deg,transparent,transparent 10px,rgba(0,0,0,0.08) 10px,rgba(0,0,0,0.08) 20px)", animation: "warn-stripe 1.5s linear infinite", pointerEvents: "none" }} />
          <div style={{ position: "relative", zIndex: 1, display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 38, height: 38, background: "#92400e", borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 18, color: "#fbbf24", flexShrink: 0, animation: "warn-pulse 2s ease-in-out infinite" }}>!</div>
            <div>
              <p style={{ margin: 0, fontWeight: 900, fontSize: 14, color: "#451a03", letterSpacing: -0.3 }}>{tagName}</p>
              <p style={{ margin: "2px 0 0", fontFamily: "monospace", fontSize: 8, color: "rgba(69,26,3,0.5)", letterSpacing: "0.12em" }}>{domain}</p>
            </div>
            <span style={{ marginLeft: "auto", background: "rgba(255,255,255,0.5)", border: "1px solid rgba(255,255,255,0.6)", borderRadius: 5, padding: "2px 7px", fontSize: 8, fontWeight: 700, color: "#78350f", flexShrink: 0 }}>{tagLabel}</span>
          </div>
        </div>
        {/* White body */}
        <div style={{ padding: "10px 14px 13px" }}>
          {desc && <p style={{ margin: "0 0 8px", fontSize: 10, color: "#6b7280", lineHeight: 1.6, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
          <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "#d97706", color: "#fff", borderRadius: 10, padding: "9px 14px", fontSize: 11, fontWeight: 700, textDecoration: "none" }}>
            访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.8 }} />
          </a>
        </div>
      </div>
    </>
  );

  /* ═══ premium — 黑金奢华 ═════════════════════════════════════════════ */
  if (themeKey === "premium") return (
    <>
      <style>{`@keyframes prem-shimmer{0%{transform:translateX(-100%) skewX(-20deg)}100%{transform:translateX(300%) skewX(-20deg)}} @keyframes prem-glow{0%,100%{opacity:.5}50%{opacity:1}}`}</style>
      <div style={{ background: "#09090b", borderRadius: 16, overflow: "hidden", boxShadow: "0 4px 28px rgba(0,0,0,0.7), 0 0 0 1px rgba(212,175,55,0.25)" }}>
        {/* Gold shimmer hero */}
        <div style={{ position: "relative", padding: "20px 16px 16px", overflow: "hidden" }}>
          <div style={{ position: "absolute", inset: 0, background: "linear-gradient(135deg,#1a0a2e,#0d0d0d)", opacity: 1 }} />
          {/* Gold line at top */}
          <div style={{ position: "absolute", top: 0, left: "10%", right: "10%", height: 1, background: "linear-gradient(90deg,transparent,rgba(212,175,55,0.8),transparent)", animation: "prem-glow 2.5s ease-in-out infinite" }} />
          {/* Shimmer sweep */}
          <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
            <div style={{ position: "absolute", top: 0, bottom: 0, width: "30%", background: "linear-gradient(90deg,transparent,rgba(212,175,55,0.06),transparent)", animation: "prem-shimmer 4s ease-in-out infinite" }} />
          </div>
          {/* Gold monogram */}
          <div style={{ position: "relative", zIndex: 1, display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 48, height: 48, borderRadius: 14, background: "linear-gradient(135deg,#D4AF37,#F7C948,#B8860B)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 16, color: "#1a0a2e", flexShrink: 0, boxShadow: "0 0 20px rgba(212,175,55,0.4)" }}>
              {mono2(tagName)}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <p style={{ margin: 0, fontWeight: 900, fontSize: 14, color: "#F7C948", letterSpacing: -0.3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{tagName}</p>
              <p style={{ margin: "3px 0 0", fontFamily: "monospace", fontSize: 8, color: "rgba(212,175,55,0.3)", letterSpacing: "0.15em" }}>{domain}</p>
            </div>
            <span style={{ background: "linear-gradient(135deg,rgba(212,175,55,0.15),rgba(247,201,72,0.08))", border: "1px solid rgba(212,175,55,0.35)", borderRadius: 6, padding: "3px 8px", fontSize: 8, fontWeight: 700, color: "#D4AF37", flexShrink: 0 }}>{tagLabel}</span>
          </div>
        </div>
        {/* Dark body */}
        <div style={{ padding: "8px 14px 13px", borderTop: "1px solid rgba(212,175,55,0.15)" }}>
          {desc && <p style={{ margin: "0 0 8px", fontSize: 10, color: "rgba(212,175,55,0.5)", lineHeight: 1.6, display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>{desc}</p>}
          <a href={link} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, background: "linear-gradient(135deg,#D4AF37,#B8860B)", color: "#1a0a2e", borderRadius: 10, padding: "9px 14px", fontSize: 11, fontWeight: 900, textDecoration: "none", boxShadow: "0 0 18px rgba(212,175,55,0.35)" }}>
            访问主页 <RiArrowRightSLine style={{ width: 13, height: 13, opacity: 0.8 }} />
          </a>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: celebrate — 中国红·节庆
  ════════════════════════════════════════ */
  if (t.layout === "celebrate") return (
    <>
      <style>{`
        @keyframes cel-confetti{0%{transform:translateY(0) rotate(0deg) scale(1);opacity:.8}30%{transform:translateY(-7px) rotate(130deg) scale(1.1);opacity:1}60%{transform:translateY(-3px) rotate(260deg) scale(.9);opacity:.7}100%{transform:translateY(0) rotate(360deg) scale(1);opacity:.8}}
        @keyframes cel-gold-glow{0%,100%{box-shadow:0 0 10px 2px rgba(212,175,55,0.45),0 4px 16px rgba(180,140,30,0.4)}50%{box-shadow:0 0 28px 8px rgba(247,201,72,0.85),0 6px 24px rgba(212,175,55,0.65)}}
        @keyframes cel-badge-pop{0%,100%{transform:scale(1);opacity:.9}50%{transform:scale(1.06);opacity:1}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg bg-white">
        <div className="relative pt-5 pb-9 overflow-hidden text-center" style={{background:"linear-gradient(160deg,#C8102E 0%,#7B0D1E 100%)"}}>
          {[{x:"7%",y:"10%",s:8,d:"0s"},{x:"22%",y:"5%",s:5,d:"0.5s"},{x:"38%",y:"18%",s:9,d:"1s"},{x:"57%",y:"4%",s:6,d:"0.3s"},{x:"72%",y:"14%",s:8,d:"1.4s"},{x:"87%",y:"7%",s:5,d:"0.7s"}].map((p,i) => (
            <span key={i} className="absolute pointer-events-none rounded-[2px]" style={{left:p.x,top:p.y,width:p.s,height:p.s,background:"rgba(212,175,55,0.8)",transform:"rotate(45deg)",animation:`cel-confetti 2.8s ease-in-out ${p.d} infinite`}} />
          ))}
          <div className="absolute bottom-0 left-0 right-0 pointer-events-none">
            <svg viewBox="0 0 400 28" preserveAspectRatio="none" className="w-full h-7 block"><path d="M0 28 C80 6,160 22,240 10,320 -2,380 20,400 8 L400 28 Z" fill="white"/></svg>
          </div>
          <div className="flex justify-center mb-3 relative z-10">
            <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[7.5px] font-bold" style={{background:"rgba(212,175,55,0.22)",border:"1px solid rgba(212,175,55,0.5)",color:"rgba(255,220,100,0.95)",animation:"cel-badge-pop 2s ease-in-out infinite"}}>
              <RiShieldCheckLine style={{width:8,height:8}} />{tagLabel}
            </span>
          </div>
        </div>
        <div className="flex justify-center -mt-7 relative z-10">
          <div className="w-[54px] h-[54px] rounded-full border-[3px] border-white flex items-center justify-center" style={{background:"linear-gradient(135deg,#F7C948 0%,#D4AF37 50%,#B8860B 100%)",animation:"cel-gold-glow 2s ease-in-out infinite"}}>
            <span className="font-black text-[15px] text-white/90 leading-none">{mono2(tagName)}</span>
          </div>
        </div>
        <div className="px-4 pt-2 pb-4 text-center">
          <p className="text-[14.5px] font-black text-gray-900 leading-tight tracking-tight mt-1">{tagName}</p>
          <p className="text-[6.5px] font-mono tracking-wider mt-0.5 mb-1" style={{color:"rgba(0,0,0,0.28)"}}>{domain}</p>
          {desc && <p className="text-[7.5px] text-gray-400 mt-1.5 mb-3 leading-relaxed line-clamp-2">{desc}</p>}
          <a href={link} className="inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-white text-[8.5px] font-bold" style={{background:"linear-gradient(135deg,#D4AF37,#B8860B)",boxShadow:"0 3px 12px rgba(180,140,30,0.35)"}}>
            访问主页 <RiArrowRightSLine style={{width:10,height:10,opacity:.9}} />
          </a>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: neon — 赛博·霓虹
  ════════════════════════════════════════ */
  if (t.layout === "neon") return (
    <>
      <style>{`
        @keyframes neon-ring{0%,100%{box-shadow:0 0 10px rgba(0,210,255,0.35),0 0 30px rgba(0,210,255,0.1);border-color:rgba(0,210,255,0.45)}50%{box-shadow:0 0 24px rgba(0,210,255,0.8),0 0 56px rgba(0,210,255,0.25);border-color:rgba(0,210,255,0.9)}}
        @keyframes neon-scan{0%{top:-8%;opacity:.5}100%{top:110%;opacity:0}}
        @keyframes neon-badge-glow{0%,100%{box-shadow:0 0 8px rgba(0,210,255,0.2);color:#00D2FF}50%{box-shadow:0 0 18px rgba(0,210,255,0.6);color:#7DF9FF}}
        @keyframes neon-mono-glow{0%,100%{text-shadow:0 0 8px rgba(0,210,255,0.5)}50%{text-shadow:0 0 20px rgba(0,210,255,0.9),0 0 40px rgba(0,210,255,0.4)}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg" style={{background:"#050d18"}}>
        <div className="relative flex flex-col items-center pt-5 pb-4 overflow-hidden" style={{background:"#050d18"}}>
          <div className="absolute inset-0 pointer-events-none" style={{background:"radial-gradient(ellipse 85% 65% at 50% 0%,rgba(0,210,255,0.14) 0%,rgba(123,47,190,0.08) 55%,transparent 80%)"}}/>
          <div className="absolute left-0 right-0 pointer-events-none overflow-hidden" style={{top:0,bottom:0}}>
            <div style={{position:"absolute",left:0,right:0,height:2,background:"linear-gradient(90deg,transparent,rgba(0,210,255,0.5),transparent)",animation:"neon-scan 3.5s linear infinite"}}/>
          </div>
          <div className="relative z-10 mb-3">
            <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[7.5px] font-bold font-mono" style={{background:"rgba(0,210,255,0.08)",border:"1px solid rgba(0,210,255,0.45)",animation:"neon-badge-glow 2.2s ease-in-out infinite"}}>
              <RiShieldCheckLine style={{width:8,height:8}} />{tagLabel}
            </span>
          </div>
          <div className="relative z-10 w-[60px] h-[60px] rounded-full flex items-center justify-center" style={{background:"rgba(0,210,255,0.05)",border:"2px solid rgba(0,210,255,0.45)",animation:"neon-ring 2.4s ease-in-out infinite"}}>
            <span className="font-black text-[14px] leading-none select-none" style={{color:"rgba(0,210,255,0.85)",animation:"neon-mono-glow 2.4s ease-in-out infinite"}}>
              {mono2(tagName)}
            </span>
          </div>
        </div>
        <div className="px-4 pt-1.5 pb-4 text-center">
          <p className="text-white text-[14px] font-black leading-tight tracking-tight">{tagName}</p>
          <p className="text-[6px] font-mono tracking-[0.2em] mt-0.5" style={{color:"rgba(0,210,255,0.3)"}}>{domain}</p>
          {desc && <p className="text-[7.5px] leading-relaxed mt-1.5 mb-3.5 line-clamp-2" style={{color:"rgba(100,130,160,0.85)"}}>{desc}</p>}
          <a href={link} className="inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-[8.5px] font-bold text-white" style={{background:"linear-gradient(135deg,#00D2FF,#7B2FBE)",boxShadow:"0 0 18px rgba(0,210,255,0.4)"}}>
            访问主页 <RiArrowRightSLine style={{width:10,height:10,opacity:.9}} />
          </a>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: gradient — 全息·流光
  ════════════════════════════════════════ */
  if (t.layout === "gradient") return (
    <>
      <style>{`@keyframes grad-shift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}} @keyframes grad-float{0%,100%{transform:translateY(0px)}50%{transform:translateY(-3px)}}`}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg" style={{background:"linear-gradient(135deg,#FF6B6B,#FFD93D,#6BCB77,#4D96FF,#C77DFF,#FF6B6B)",backgroundSize:"300% 300%",animation:"grad-shift 5s ease infinite"}}>
        <div className="flex justify-center pt-4 pb-1">
          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[7.5px] font-bold" style={{background:"rgba(255,255,255,0.45)",backdropFilter:"blur(8px)",border:"1px solid rgba(255,255,255,0.6)",color:"rgba(20,20,20,0.75)"}}>
            <RiShieldCheckLine style={{width:8,height:8}} />{tagLabel}
          </span>
        </div>
        <div className="flex justify-center my-2" style={{animation:"grad-float 3s ease-in-out infinite"}}>
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center font-black text-[18px]" style={{background:"rgba(255,255,255,0.42)",backdropFilter:"blur(12px)",border:"1.5px solid rgba(255,255,255,0.65)",boxShadow:"0 4px 24px rgba(0,0,0,0.1)",color:"rgba(20,20,20,0.8)"}}>
            {mono2(tagName)}
          </div>
        </div>
        <div className="px-4 text-center pb-2">
          <p className="font-black text-gray-900 leading-tight tracking-tight" style={{fontSize:16,textShadow:"0 1px 6px rgba(255,255,255,0.7)"}}>{tagName}</p>
          <p className="text-[6.5px] font-mono tracking-wider mt-0.5" style={{color:"rgba(20,20,20,0.35)",textShadow:"0 1px 2px rgba(255,255,255,0.5)"}}>{domain}</p>
          {desc && <p className="text-[7px] leading-relaxed mt-1.5 line-clamp-2" style={{color:"rgba(20,20,20,0.55)",textShadow:"0 1px 3px rgba(255,255,255,0.5)"}}>{desc}</p>}
        </div>
        <div className="flex justify-center pb-4 pt-1">
          <a href={link} className="inline-flex items-center gap-1 px-5 py-2 rounded-full text-[8.5px] font-bold text-white" style={{background:"rgba(10,10,20,0.82)",backdropFilter:"blur(8px)"}}>
            访问主页 <RiArrowRightSLine style={{width:10,height:10,opacity:.8}} />
          </a>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: split — 高反差·黑白
  ════════════════════════════════════════ */
  if (t.layout === "split") return (
    <>
      <style>{`
        @keyframes split-bar{0%{background:linear-gradient(to bottom,#60a5fa,#818cf8,#c084fc);opacity:.7}50%{background:linear-gradient(to bottom,#38bdf8,#6366f1,#e879f9);opacity:1}100%{background:linear-gradient(to bottom,#60a5fa,#818cf8,#c084fc);opacity:.7}}
        @keyframes split-badge{0%,100%{opacity:.8;transform:scale(1)}50%{opacity:1;transform:scale(1.04)}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg flex" style={{minHeight:130}}>
        {/* Left black panel */}
        <div className="relative flex flex-col items-center justify-center w-[36%] shrink-0 overflow-hidden" style={{background:"#000"}}>
          <div className="absolute inset-0 flex items-center justify-center overflow-hidden select-none pointer-events-none">
            <span className="font-black select-none" style={{fontSize:80,color:"rgba(255,255,255,0.04)",lineHeight:1}}>{mono1(tagName)}</span>
          </div>
          <div className="absolute top-0 right-0 w-[2.5px] h-full" style={{animation:"split-bar 2.5s ease-in-out infinite"}}/>
          <div className="relative z-10 w-11 h-11 rounded-xl flex items-center justify-center font-black text-[14px] text-white/80" style={{background:"rgba(255,255,255,0.07)",border:"1px solid rgba(255,255,255,0.12)"}}>
            {mono2(tagName)}
          </div>
          <p className="relative z-10 font-mono text-[6px] mt-1.5 tracking-wider text-center px-2 truncate" style={{color:"rgba(255,255,255,0.18)"}}>{domain}</p>
        </div>
        {/* Right white panel */}
        <div className="flex-1 flex flex-col justify-between px-3 py-3" style={{background:"#FAFAFA"}}>
          <div>
            <span className="inline-flex items-center gap-0.5 text-[6.5px] font-bold px-2 py-0.5 rounded-md mb-1" style={{background:"rgba(99,102,241,0.08)",color:"#6366F1",border:"1px solid rgba(99,102,241,0.15)",animation:"split-badge 2.4s ease-in-out infinite"}}>
              <RiShieldCheckLine style={{width:7,height:7}} />{tagLabel}
            </span>
            <p className="font-black text-gray-900 leading-none tracking-tight" style={{fontSize:14}}>{tagName}</p>
            {desc && <p className="text-[7px] leading-relaxed mt-1 line-clamp-2" style={{color:"#9ca3af"}}>{desc}</p>}
          </div>
          <a href={link} className="flex items-center justify-between mt-2 px-2.5 py-1.5 rounded-[10px] text-white text-[8px] font-bold shrink-0" style={{background:"#111"}}>
            <span>访问主页</span>
            <RiArrowRightSLine style={{width:11,height:11,opacity:.8}} />
          </a>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: flash — 闪购·电光
  ════════════════════════════════════════ */
  if (t.layout === "flash") return (
    <>
      <style>{`
        @keyframes flash-bolt-a{0%,100%{opacity:.35;transform:scale(1) rotate(0deg)}15%{opacity:.9;transform:scale(1.2) rotate(-3deg)}30%{opacity:.35;transform:scale(1) rotate(0deg)}}
        @keyframes flash-panel{0%,100%{background:#FFE500}18%{background:#FFF100}19%{background:#FFE500}}
        @keyframes flash-mono-pulse{0%,100%{transform:scale(1);opacity:.85}18%{transform:scale(1.08);opacity:1}19%{transform:scale(1);opacity:.85}}
        @keyframes flash-cta{0%,100%{box-shadow:0 2px 8px rgba(255,56,0,0.28)}50%{box-shadow:0 4px 18px rgba(255,56,0,0.55)}}
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg">
        {/* top bar — domain only, no tagLabel clutter */}
        <div className="px-3 py-2 flex items-center gap-2" style={{background:"#FF3800"}}>
          <div className="w-5 h-5 rounded-md flex items-center justify-center font-black text-[9px] text-white/90 shrink-0" style={{background:"rgba(255,255,255,0.15)"}}>
            {mono1(tagName)}
          </div>
          <p className="text-[7.5px] font-mono flex-1 truncate" style={{color:"rgba(255,255,255,0.85)"}}>{domain}</p>
        </div>
        {/* body */}
        <div className="flex" style={{minHeight:108}}>
          {/* Left yellow — monogram only */}
          <div className="w-[40%] shrink-0 relative overflow-hidden flex flex-col items-center justify-center px-3 py-4" style={{animation:"flash-panel 2.2s ease-in-out infinite"}}>
            <svg className="absolute top-2 right-2 pointer-events-none" style={{animation:"flash-bolt-a 2.2s ease-in-out infinite"}} width={14} height={22} viewBox="0 0 10 18" fill="rgba(255,80,0,0.5)">
              <path d="M7 0L1 10h5L3 18l8-11H6L7 0Z"/>
            </svg>
            <div className="relative z-10 font-black leading-none text-center" style={{fontSize:26,color:"#111",animation:"flash-mono-pulse 2.2s ease-in-out infinite"}}>
              {mono2(tagName)}
            </div>
          </div>
          {/* Right white */}
          <div className="flex-1 flex flex-col justify-between px-3 py-3 bg-white">
            <div>
              <span className="inline-flex items-center gap-0.5 text-[6.5px] font-bold px-2 py-0.5 rounded mb-1" style={{background:"rgba(255,56,0,0.1)",color:"#FF3800",border:"1px solid rgba(255,56,0,0.2)"}}>
                <RiShieldCheckLine style={{width:7,height:7}} />{tagLabel}
              </span>
              <p className="font-black text-gray-900 leading-none tracking-tight" style={{fontSize:14}}>{tagName}</p>
              {desc && <p className="text-[7.5px] text-gray-400 leading-relaxed mt-1 line-clamp-2">{desc}</p>}
            </div>
            <a href={link} className="inline-flex items-center gap-0.5 mt-2 px-3.5 py-1.5 rounded-full text-[8.5px] font-bold text-white shrink-0" style={{background:"linear-gradient(135deg,#FF3800,#FF6800)",animation:"flash-cta 2s ease-in-out infinite"}}>
              访问主页 <RiArrowRightSLine style={{width:10,height:10,opacity:.85}} />
            </a>
          </div>
        </div>
      </div>
    </>
  );

  /* Fallback — should never reach here */
  return null;
}
