/**
 * StampPreviewCard — shared real popup preview component.
 * Used by: admin/stamp-styles.tsx, admin/stamps.tsx, stamp.tsx
 *
 * Renders the EXACT same layout as the stamp popup in [...query].tsx,
 * including all special layouts (celebrate / neon / gradient / split / flash).
 */
import React from "react";
import { cn } from "@/lib/utils";
import {
  RiShieldCheckLine, RiArrowRightSLine,
  RiGlobalLine,
} from "@remixicon/react";

/* ── Theme definitions (mirror of [...query].tsx CARD_THEMES) ── */
export type CardThemeDef = {
  hero: string; shimmer: string;
  badge: string; btn: string;
  cardBg: string; cardBorder: string; cardText: string;
  layout?: "default" | "celebrate" | "neon" | "gradient" | "split" | "flash";
  accent?: string; accentText?: string;
};

export const STAMP_CARD_THEMES: Record<string, CardThemeDef & { label: string; special?: string }> = {
  /* ── 8 standard themes ── */
  app:      { label: "极简", hero: "bg-gradient-to-br from-zinc-600 to-zinc-900",                 shimmer: "text-shimmer",              badge: "bg-zinc-100 text-zinc-600 border border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700",                              btn: "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900",    cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  official: { label: "官方", hero: "bg-gradient-to-br from-blue-600 to-indigo-800",               shimmer: "text-foreground font-black", badge: "bg-blue-50 text-blue-700 border border-blue-200/80 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800/60",                  btn: "bg-blue-700 text-white",                                         cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  aurora:   { label: "极光", hero: "bg-gradient-to-br from-violet-500 via-fuchsia-500 to-purple-700", shimmer: "text-foreground font-black", badge: "bg-violet-50 text-violet-700 border border-violet-200/80 dark:bg-violet-950/60 dark:text-violet-300 dark:border-violet-800/60", btn: "bg-violet-600 text-white",                                       cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  emerald:  { label: "翡翠", hero: "bg-gradient-to-br from-emerald-400 to-teal-700",               shimmer: "text-foreground font-black", badge: "bg-emerald-50 text-emerald-700 border border-emerald-200/80 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/60", btn: "bg-emerald-600 text-white",                                    cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  solar:    { label: "暖阳", hero: "bg-gradient-to-br from-amber-400 to-orange-600",               shimmer: "text-foreground font-black", badge: "bg-amber-50 text-amber-700 border border-amber-200/80 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/60",              btn: "bg-orange-500 text-white",                                       cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  dev:      { label: "开发", hero: "bg-gradient-to-br from-slate-600 to-[#0d1117]",                shimmer: "text-[#58a6ff] font-black font-mono", badge: "bg-[#161b22] text-[#58a6ff] border border-[#30363d]",                                                                        btn: "bg-[#238636] text-white",                                        cardBg: "bg-zinc-950",   cardBorder: "border-zinc-800",  cardText: "text-zinc-200" },
  warning:  { label: "警示", hero: "bg-gradient-to-br from-yellow-400 to-amber-600",               shimmer: "text-foreground font-black", badge: "bg-yellow-50 text-yellow-800 border border-yellow-300/80 dark:bg-yellow-950/60 dark:text-yellow-300 dark:border-yellow-800/60",       btn: "bg-amber-500 text-white",                                        cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  premium:  { label: "尊享", hero: "bg-gradient-to-br from-purple-600 via-fuchsia-500 to-rose-500", shimmer: "text-foreground font-black", badge: "bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200/80 dark:bg-fuchsia-950/60 dark:text-fuchsia-300 dark:border-fuchsia-800/60", btn: "bg-gradient-to-r from-purple-600 to-fuchsia-500 text-white",   cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground" },
  /* ── 5 special themes ── */
  celebrate: { label: "庆典",     layout: "celebrate", hero: "bg-gradient-to-br from-red-700 to-red-900",                    shimmer: "text-white font-black",    badge: "bg-amber-400 text-amber-900 border-0",    btn: "bg-amber-500 text-white",                                      cardBg: "bg-white",       cardBorder: "border-amber-100",  cardText: "text-gray-900", special: "🎊" },
  neon:      { label: "霓虹",     layout: "neon",      hero: "bg-[#050d18]",                                                  shimmer: "text-white font-black",    badge: "bg-cyan-400 text-slate-900 border-0",     btn: "bg-gradient-to-r from-cyan-400 to-violet-600 text-white",     cardBg: "bg-[#050d18]",   cardBorder: "border-slate-800",  cardText: "text-white",    special: "⚡" },
  gradient:  { label: "渐变流光", layout: "gradient",  hero: "bg-gradient-to-br from-rose-300 via-sky-300 to-emerald-300",   shimmer: "text-gray-900 font-black", badge: "bg-black/10 text-gray-800 border border-black/20", btn: "bg-gray-900 text-white",                              cardBg: "bg-transparent", cardBorder: "border-0",          cardText: "text-gray-900", special: "✨" },
  split:     { label: "分栏",     layout: "split",     hero: "bg-black",                                                      shimmer: "text-white font-black",    badge: "bg-blue-500 text-white border-0",         btn: "bg-gray-900 text-white",                                       cardBg: "bg-white",       cardBorder: "border-gray-100",   cardText: "text-gray-900", special: "◼" },
  flash:     { label: "特卖",     layout: "flash",     hero: "bg-[#FF3800]",                                                  shimmer: "text-white font-black",    badge: "bg-[#FF3800] text-white border-0",        btn: "bg-orange-500 text-white",                                     cardBg: "bg-white",       cardBorder: "border-0",          cardText: "text-gray-900", special: "💥" },
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
  domain:      "x.rw",
  description: "全球 WHOIS & RDAP 域名信息查询平台，多协议数据源，实时解析全球域名注册信息。",
  link:        "https://x.rw",
  tagLabel:    "官方认证",
  icon:        RiGlobalLine,
};

/* ── Monogram avatar — replaces generic icon for a unique brand identity ── */
function Monogram({ name, className, textClass }: { name: string; className?: string; textClass?: string }) {
  const chars = name.replace(/[•·\s]/g, "").slice(0, 2).toUpperCase();
  return (
    <div className={cn("flex items-center justify-center font-black select-none", className)}>
      <span className={textClass}>{chars}</span>
    </div>
  );
}

export function StampPreviewCard({
  themeKey,
  data,
}: {
  themeKey: string;
  data?: StampPreviewData;
}) {
  const t = STAMP_CARD_THEMES[themeKey] ?? STAMP_CARD_THEMES.app;
  if (!t) return null;

  const tagName  = data?.tagName    || DEMO.tagName;
  const domain   = data?.domain     || DEMO.domain;
  const desc     = data?.description || DEMO.description;
  const link     = data?.link       || DEMO.link;
  const tagLabel = data?.tagLabel   || DEMO.tagLabel;

  /* ════════════════════════════════════════
     Layout: celebrate — 中国红·节庆
  ════════════════════════════════════════ */
  if (t.layout === "celebrate") return (
    <>
      <style>{`
        @keyframes cel-confetti {
          0%   { transform: translateY(0) rotate(0deg)   scale(1);   opacity: .8; }
          30%  { transform: translateY(-7px) rotate(130deg) scale(1.1); opacity: 1; }
          60%  { transform: translateY(-3px) rotate(260deg) scale(.9); opacity: .7; }
          100% { transform: translateY(0) rotate(360deg) scale(1);   opacity: .8; }
        }
        @keyframes cel-gold-glow {
          0%,100% { box-shadow: 0 0 10px 2px rgba(212,175,55,0.45), 0 4px 16px rgba(180,140,30,0.4); }
          50%     { box-shadow: 0 0 28px 8px rgba(247,201,72,0.85), 0 6px 24px rgba(212,175,55,0.65); }
        }
        @keyframes cel-hero-shimmer {
          0%   { transform: translateX(-100%) skewX(-20deg); }
          100% { transform: translateX(260%)  skewX(-20deg); }
        }
        @keyframes cel-badge-pop {
          0%,100% { transform: scale(1);    opacity: .9; }
          50%     { transform: scale(1.06); opacity: 1;  }
        }
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg bg-white">
        {/* Hero */}
        <div className="relative pt-5 pb-9 overflow-hidden text-center"
          style={{background:"linear-gradient(160deg,#C8102E 0%,#7B0D1E 100%)"}}>
          {/* shimmer sweep */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div style={{
              position:"absolute",inset:0,
              background:"linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.12) 50%,transparent 100%)",
              width:"40%",
              animation:"cel-hero-shimmer 2.8s ease-in-out infinite",
            }}/>
          </div>
          {/* animated confetti */}
          {[
            {x:"7%",y:"10%",s:8,d:"0s"},{x:"22%",y:"5%",s:5,d:"0.5s"},
            {x:"38%",y:"18%",s:9,d:"1s"},{x:"57%",y:"4%",s:6,d:"0.3s"},
            {x:"72%",y:"14%",s:8,d:"1.4s"},{x:"87%",y:"7%",s:5,d:"0.7s"},
            {x:"13%",y:"38%",s:7,d:"1.8s"},{x:"59%",y:"35%",s:5,d:"1.1s"},
            {x:"83%",y:"37%",s:7,d:"0.4s"},
          ].map((p,i) => (
            <span key={i} className="absolute pointer-events-none rounded-[2px]"
              style={{left:p.x,top:p.y,width:p.s,height:p.s,
                background:"rgba(212,175,55,0.8)",transform:"rotate(45deg)",
                animation:`cel-confetti 2.8s ease-in-out ${p.d} infinite`}} />
          ))}
          {/* wave */}
          <div className="absolute bottom-0 left-0 right-0 pointer-events-none">
            <svg viewBox="0 0 400 28" preserveAspectRatio="none" className="w-full h-7 block">
              <path d="M0 28 C80 6,160 22,240 10,320 -2,380 20,400 8 L400 28 Z" fill="white"/>
            </svg>
          </div>
          {/* badge */}
          <div className="flex justify-center mb-3 relative z-10">
            <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[7.5px] font-bold"
              style={{background:"rgba(212,175,55,0.22)",border:"1px solid rgba(212,175,55,0.5)",
                color:"rgba(255,220,100,0.95)",
                animation:"cel-badge-pop 2s ease-in-out infinite"}}>
              <RiShieldCheckLine style={{width:8,height:8}} />{tagLabel}
            </span>
          </div>
        </div>

        {/* Gold monogram avatar */}
        <div className="flex justify-center -mt-7 relative z-10">
          <div className="w-[54px] h-[54px] rounded-full border-[3px] border-white flex items-center justify-center"
            style={{background:"linear-gradient(135deg,#F7C948 0%,#D4AF37 50%,#B8860B 100%)",
              animation:"cel-gold-glow 2s ease-in-out infinite"}}>
            <Monogram name={tagName} textClass="text-[15px] text-white/90 leading-none" />
          </div>
        </div>

        {/* Info */}
        <div className="px-4 pt-2 pb-4 text-center">
          <p className="text-[14.5px] font-black text-gray-900 leading-tight tracking-tight mt-1">{tagName}</p>
          <p className="text-[6.5px] font-mono tracking-wider mt-0.5 mb-1" style={{color:"rgba(0,0,0,0.28)"}}>{domain}</p>
          {desc && <p className="text-[7.5px] text-gray-400 mt-1.5 mb-3 leading-relaxed line-clamp-2">{desc}</p>}
          <a href={link} className="inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-white text-[8.5px] font-bold"
            style={{background:"linear-gradient(135deg,#D4AF37,#B8860B)",
              boxShadow:"0 3px 12px rgba(180,140,30,0.35)"}}>
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
        @keyframes neon-ring {
          0%,100% {
            box-shadow: 0 0 10px rgba(0,210,255,0.35), 0 0 30px rgba(0,210,255,0.1);
            border-color: rgba(0,210,255,0.45);
          }
          50% {
            box-shadow: 0 0 24px rgba(0,210,255,0.8), 0 0 56px rgba(0,210,255,0.25), 0 0 80px rgba(123,47,190,0.2);
            border-color: rgba(0,210,255,0.9);
          }
        }
        @keyframes neon-title-flicker {
          0%,92%,96%,100% { opacity: 1; }
          94% { opacity: 0.55; }
          95% { opacity: 1; }
        }
        @keyframes neon-scan {
          0%   { top: -8%; opacity: .5; }
          100% { top: 110%; opacity: 0; }
        }
        @keyframes neon-badge-glow {
          0%,100% { box-shadow: 0 0 8px rgba(0,210,255,0.2);  color: #00D2FF; }
          50%     { box-shadow: 0 0 18px rgba(0,210,255,0.6); color: #7DF9FF; }
        }
        @keyframes neon-bg-pulse {
          0%,100% { opacity: .4; }
          50%     { opacity: .65; }
        }
        @keyframes neon-mono-glow {
          0%,100% { text-shadow: 0 0 8px rgba(0,210,255,0.5); }
          50%     { text-shadow: 0 0 20px rgba(0,210,255,0.9), 0 0 40px rgba(0,210,255,0.4); }
        }
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg" style={{background:"#050d18"}}>
        <div className="relative flex flex-col items-center pt-5 pb-4 overflow-hidden" style={{background:"#050d18"}}>
          {/* bg glow */}
          <div className="absolute inset-0 pointer-events-none"
            style={{background:"radial-gradient(ellipse 85% 65% at 50% 0%,rgba(0,210,255,0.14) 0%,rgba(123,47,190,0.08) 55%,transparent 80%)",
              animation:"neon-bg-pulse 3s ease-in-out infinite"}}/>
          {/* scan line */}
          <div className="absolute left-0 right-0 pointer-events-none overflow-hidden" style={{top:0,bottom:0}}>
            <div style={{
              position:"absolute",left:0,right:0,height:2,
              background:"linear-gradient(90deg,transparent,rgba(0,210,255,0.5),transparent)",
              animation:"neon-scan 3.5s linear infinite",
            }}/>
          </div>
          {/* badge */}
          <div className="relative z-10 mb-3">
            <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[7.5px] font-bold font-mono"
              style={{background:"rgba(0,210,255,0.08)",border:"1px solid rgba(0,210,255,0.45)",
                animation:"neon-badge-glow 2.2s ease-in-out infinite"}}>
              <RiShieldCheckLine style={{width:8,height:8}} />{tagLabel}
            </span>
          </div>
          {/* monogram ring */}
          <div className="relative z-10 w-[60px] h-[60px] rounded-full flex items-center justify-center"
            style={{background:"rgba(0,210,255,0.05)",border:"2px solid rgba(0,210,255,0.45)",
              animation:"neon-ring 2.4s ease-in-out infinite"}}>
            <span className="font-black text-[14px] leading-none select-none"
              style={{color:"rgba(0,210,255,0.85)",animation:"neon-mono-glow 2.4s ease-in-out infinite"}}>
              {(tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase()}
            </span>
          </div>
        </div>
        {/* info */}
        <div className="px-4 pt-1.5 pb-4 text-center">
          <p className="text-white text-[14px] font-black leading-tight tracking-tight"
            style={{textShadow:"0 0 18px rgba(0,210,255,0.4)",
              animation:"neon-title-flicker 5s ease-in-out infinite"}}>{tagName}</p>
          <p className="text-[6px] font-mono tracking-[0.2em] mt-0.5" style={{color:"rgba(0,210,255,0.3)"}}>{domain}</p>
          {desc && <p className="text-[7.5px] leading-relaxed mt-1.5 mb-3.5 line-clamp-2"
            style={{color:"rgba(100,130,160,0.85)"}}>{desc}</p>}
          <a href={link} className="inline-flex items-center gap-1 px-4 py-1.5 rounded-full text-[8.5px] font-bold text-white"
            style={{background:"linear-gradient(135deg,#00D2FF,#7B2FBE)",
              boxShadow:"0 0 18px rgba(0,210,255,0.4)"}}>
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
      <style>{`
        @keyframes grad-shift {
          0%   { background-position: 0% 50%; }
          50%  { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
        @keyframes grad-float {
          0%,100% { transform: translateY(0px); }
          50%     { transform: translateY(-3px); }
        }
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg"
        style={{background:"linear-gradient(135deg,#FF6B6B,#FFD93D,#6BCB77,#4D96FF,#C77DFF,#FF6B6B)",
          backgroundSize:"300% 300%",animation:"grad-shift 5s ease infinite"}}>
        {/* badge */}
        <div className="flex justify-center pt-4 pb-1">
          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-[7.5px] font-bold"
            style={{background:"rgba(255,255,255,0.45)",backdropFilter:"blur(8px)",
              border:"1px solid rgba(255,255,255,0.6)",color:"rgba(20,20,20,0.75)"}}>
            <RiShieldCheckLine style={{width:8,height:8}} />{tagLabel}
          </span>
        </div>
        {/* floating monogram */}
        <div className="flex justify-center my-2" style={{animation:"grad-float 3s ease-in-out infinite"}}>
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center font-black text-[18px]"
            style={{background:"rgba(255,255,255,0.42)",backdropFilter:"blur(12px)",
              border:"1.5px solid rgba(255,255,255,0.65)",boxShadow:"0 4px 24px rgba(0,0,0,0.1)",
              color:"rgba(20,20,20,0.8)"}}>
            {(tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase()}
          </div>
        </div>
        {/* title + desc */}
        <div className="px-4 text-center pb-2">
          <p className="font-black text-gray-900 leading-tight tracking-tight"
            style={{fontSize:16,textShadow:"0 1px 6px rgba(255,255,255,0.7)"}}>{tagName}</p>
          <p className="text-[6.5px] font-mono tracking-wider mt-0.5"
            style={{color:"rgba(20,20,20,0.35)",textShadow:"0 1px 2px rgba(255,255,255,0.5)"}}>{domain}</p>
          {desc && <p className="text-[7px] leading-relaxed mt-1.5 line-clamp-2"
            style={{color:"rgba(20,20,20,0.55)",textShadow:"0 1px 3px rgba(255,255,255,0.5)"}}>{desc}</p>}
        </div>
        {/* CTA — simple centered pill button */}
        <div className="flex justify-center pb-4 pt-1">
          <a href={link} className="inline-flex items-center gap-1 px-5 py-2 rounded-full text-[8.5px] font-bold text-white"
            style={{background:"rgba(10,10,20,0.82)",backdropFilter:"blur(8px)"}}>
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
        @keyframes split-bar {
          0%   { background: linear-gradient(to bottom,#60a5fa,#818cf8,#c084fc); opacity:.7; }
          50%  { background: linear-gradient(to bottom,#38bdf8,#6366f1,#e879f9); opacity:1;  }
          100% { background: linear-gradient(to bottom,#60a5fa,#818cf8,#c084fc); opacity:.7; }
        }
        @keyframes split-shine {
          0%   { transform: translateX(-110%) skewX(-18deg); opacity:0;    }
          15%  { opacity: .6; }
          100% { transform: translateX(220%)  skewX(-18deg); opacity:0;    }
        }
        @keyframes split-badge {
          0%,100% { opacity: .8; transform: scale(1);    }
          50%     { opacity: 1;  transform: scale(1.04); }
        }
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg flex" style={{minHeight:140}}>
        {/* Left black panel — monogram */}
        <div className="relative flex flex-col items-center justify-center w-[36%] shrink-0 overflow-hidden"
          style={{background:"#000"}}>
          {/* ghost initial watermark */}
          <div className="absolute inset-0 flex items-center justify-center overflow-hidden select-none pointer-events-none">
            <span className="font-black select-none"
              style={{fontSize:80,color:"rgba(255,255,255,0.04)",lineHeight:1}}>
              {(tagName || "X").replace(/[•·\s]/g, "").slice(0, 1).toUpperCase()}
            </span>
          </div>
          {/* shine sweep */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div style={{
              position:"absolute",top:0,bottom:0,width:"40%",
              background:"linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent)",
              animation:"split-shine 4s ease-in-out 1s infinite",
            }}/>
          </div>
          {/* animated divider bar */}
          <div className="absolute top-0 right-0 w-[2.5px] h-full"
            style={{animation:"split-bar 2.5s ease-in-out infinite"}}/>
          {/* monogram */}
          <div className="relative z-10 w-11 h-11 rounded-xl flex items-center justify-center font-black text-[14px] text-white/80"
            style={{background:"rgba(255,255,255,0.07)",border:"1px solid rgba(255,255,255,0.12)"}}>
            {(tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase()}
          </div>
        </div>

        {/* Right white panel */}
        <div className="flex-1 flex flex-col justify-between px-3 py-3" style={{background:"#FAFAFA"}}>
          <div>
            <span className="inline-flex items-center gap-0.5 text-[6.5px] font-bold px-2 py-0.5 rounded-md mb-1.5"
              style={{background:"rgba(99,102,241,0.08)",color:"#6366F1",border:"1px solid rgba(99,102,241,0.15)",
                animation:"split-badge 2.4s ease-in-out infinite"}}>
              <RiShieldCheckLine style={{width:7,height:7}} />{tagLabel}
            </span>
            <p className="font-black text-gray-900 leading-none tracking-tight" style={{fontSize:17}}>{tagName}</p>
            <p className="text-[6px] font-mono tracking-wider mt-0.5" style={{color:"#d1d5db"}}>{domain}</p>
            {desc && <p className="text-[7px] leading-relaxed mt-1.5 line-clamp-2" style={{color:"#9ca3af"}}>{desc}</p>}
          </div>
          <a href={link} className="flex items-center justify-between mt-2 px-2.5 py-1.5 rounded-[10px] text-white text-[8px] font-bold"
            style={{background:"#111"}}>
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
        @keyframes flash-bolt-a {
          0%,100% { opacity:.35; transform:scale(1)   rotate(0deg);  }
          15%     { opacity:.9;  transform:scale(1.2) rotate(-3deg); }
          30%     { opacity:.35; transform:scale(1)   rotate(0deg);  }
        }
        @keyframes flash-bolt-b {
          0%,100% { opacity:.2;  }
          40%     { opacity:.65; }
          41%     { opacity:.2;  }
        }
        @keyframes flash-panel {
          0%,100% { background: #FFE500; }
          18%     { background: #FFF100; }
          19%     { background: #FFE500; }
        }
        @keyframes flash-mono-pulse {
          0%,100% { transform: scale(1);    opacity: .85; }
          18%     { transform: scale(1.08); opacity: 1;   }
          19%     { transform: scale(1);    opacity: .85; }
        }
        @keyframes flash-cta {
          0%,100% { box-shadow: 0 2px 8px rgba(255,56,0,0.28);  }
          50%     { box-shadow: 0 4px 18px rgba(255,56,0,0.55); }
        }
      `}</style>
      <div className="rounded-2xl overflow-hidden shadow-lg">
        {/* top bar */}
        <div className="px-3 py-2 flex items-center gap-2" style={{background:"#FF3800"}}>
          <div className="w-5 h-5 rounded-md flex items-center justify-center font-black text-[9px] text-white/90 shrink-0"
            style={{background:"rgba(255,255,255,0.15)"}}>
            {(tagName || "X").replace(/[•·\s]/g, "").slice(0, 1).toUpperCase()}
          </div>
          <p className="text-[7.5px] font-mono flex-1 truncate" style={{color:"rgba(255,255,255,0.8)"}}>{domain}</p>
          <span className="text-[7px] font-bold px-1.5 py-0.5 rounded"
            style={{background:"rgba(255,255,255,0.15)",color:"rgba(255,255,255,0.75)"}}>
            {tagLabel}
          </span>
        </div>
        {/* body */}
        <div className="flex" style={{minHeight:108}}>
          {/* Left yellow — animated monogram only */}
          <div className="w-[40%] shrink-0 relative overflow-hidden flex flex-col items-center justify-center px-3 py-4"
            style={{animation:"flash-panel 2.2s ease-in-out infinite"}}>
            <svg className="absolute top-2 right-2 pointer-events-none"
              style={{animation:"flash-bolt-a 2.2s ease-in-out infinite"}}
              width={14} height={22} viewBox="0 0 10 18" fill="rgba(255,80,0,0.5)">
              <path d="M7 0L1 10h5L3 18l8-11H6L7 0Z"/>
            </svg>
            <svg className="absolute bottom-3 left-2 pointer-events-none"
              style={{animation:"flash-bolt-b 2.2s ease-in-out 0.6s infinite"}}
              width={8} height={13} viewBox="0 0 10 18" fill="rgba(255,80,0,0.35)">
              <path d="M7 0L1 10h5L3 18l8-11H6L7 0Z"/>
            </svg>
            {/* monogram — no duplicate tagName text */}
            <div className="relative z-10 font-black leading-none text-center"
              style={{fontSize:26,color:"#111",
                animation:"flash-mono-pulse 2.2s ease-in-out infinite"}}>
              {(tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase()}
            </div>
          </div>
          {/* Right white */}
          <div className="flex-1 flex flex-col justify-between px-3 py-3 bg-white">
            <div>
              <p className="font-black text-gray-900 leading-none tracking-tight" style={{fontSize:15}}>{tagName}</p>
              {desc && <p className="text-[7.5px] text-gray-400 leading-relaxed mt-1.5 line-clamp-2">{desc}</p>}
            </div>
            <a href={link} className="inline-flex items-center gap-0.5 mt-2 px-3.5 py-1.5 rounded-full text-[8.5px] font-bold text-white"
              style={{background:"linear-gradient(135deg,#FF3800,#FF6800)",
                animation:"flash-cta 2s ease-in-out infinite"}}>
              访问主页 <RiArrowRightSLine style={{width:10,height:10,opacity:.85}} />
            </a>
          </div>
        </div>
      </div>
    </>
  );

  /* ════════════════════════════════════════
     Layout: default — 8 standard themes
  ════════════════════════════════════════ */
  const isDarkCard = t.cardBg === "bg-zinc-950" || t.cardBg === "bg-slate-900";
  const mono = (tagName || "X").replace(/[•·\s]/g, "").slice(0, 2).toUpperCase();

  return (
    <div className={cn("rounded-2xl overflow-hidden shadow-lg", t.cardBg)}>
      {/* ── Hero — compact, monogram-centered ── */}
      <div className={cn("relative px-4 pt-5 pb-10 text-center overflow-hidden", t.hero)}>
        <div className="absolute inset-0 opacity-[0.04]"
          style={{ backgroundImage: "radial-gradient(circle, white 1px, transparent 1px)", backgroundSize: "14px 14px" }} />
        <div className="absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-black/35 to-transparent pointer-events-none" />
        {/* monogram avatar */}
        <div className="relative flex flex-col items-center gap-0">
          <div className="relative">
            <div className="absolute inset-0 rounded-2xl bg-white/15 blur-md scale-125 pointer-events-none" />
            <div className="relative w-12 h-12 rounded-2xl bg-white/20 border border-white/30 flex items-center justify-center shadow-xl backdrop-blur-sm ring-4 ring-white/[0.07] font-black text-white/90 text-[15px] leading-none select-none">
              {mono}
            </div>
          </div>
        </div>
      </div>

      {/* ── Floating info card ── */}
      <div className={cn("relative -mt-5 mx-2 mb-2 rounded-[18px] border shadow-xl overflow-hidden", t.cardBg, t.cardBorder)}>
        {/* theme accent stripe */}
        <div className={cn("h-[3px] w-full", t.hero)} />
        <div className="px-3 pt-2.5 pb-3">
          {/* name + badge */}
          <div className="flex items-start justify-between gap-2 mb-0.5">
            <div className="flex-1 min-w-0">
              <p className={cn("text-[13px] font-black leading-snug tracking-tight truncate", t.shimmer)}>{tagName}</p>
              <p className={cn("text-[6px] font-mono tracking-wider mt-0.5 truncate", isDarkCard ? "text-zinc-700" : "text-foreground/25")}>{domain}</p>
            </div>
            <span className={cn("inline-flex items-center gap-0.5 text-[6px] font-bold px-1.5 py-[3px] rounded-full shrink-0 whitespace-nowrap mt-1 leading-none", t.badge)}>
              <RiShieldCheckLine className="w-[7px] h-[7px]" />{tagLabel}
            </span>
          </div>
          {/* description */}
          {desc && (
            <p className={cn("text-[7.5px] leading-[1.6] mt-2 mb-2.5 line-clamp-2", isDarkCard ? "text-zinc-500" : "text-foreground/50")}>{desc}</p>
          )}
          {/* CTA — button only, no redundant domain text */}
          <div className="pt-2 border-t flex justify-end" style={{borderColor: isDarkCard ? "rgba(63,63,70,1)" : "rgba(0,0,0,0.07)"}}>
            <a href={link} className={cn(
              "inline-flex items-center gap-1 px-3.5 py-1.5 rounded-full text-[8.5px] font-bold tracking-wide shrink-0",
              t.btn
            )}>
              <span>访问主页</span>
              <RiArrowRightSLine className="w-2.5 h-2.5 opacity-80" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
