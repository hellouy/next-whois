/** Text ad banner — multi-item with 4s fade cycling, only shown after results load. */
import React from "react";
import Link from "next/link";
import { RiExternalLinkLine, RiMegaphoneLine } from "@remixicon/react";
import { cn } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";

export type AdRichItem = { text: string; color?: string; size?: "xs" | "sm" | "base"; bold?: boolean };

/** Parse the raw ad text config into display items (JSON array or |-separated). */
export function parseAdItems(raw: string): AdRichItem[] {
  const trimmed = (raw || "").trim();
  if (trimmed.startsWith("[")) {
    try {
      const p = JSON.parse(trimmed);
      if (Array.isArray(p)) {
        const r = p.filter((i: unknown) => i && typeof (i as AdRichItem).text === "string" && (i as AdRichItem).text.trim());
        if (r.length > 0) return r as AdRichItem[];
      }
    } catch {}
  }
  return trimmed.split("|").map(s => s.trim()).filter(Boolean).map(t => ({ text: t }));
}

export function ResultTextAd({ loading = false, inline = false }: { loading?: boolean; inline?: boolean }) {
  const settings = useSiteSettings();
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  const mode    = settings.result_ad_mode || "text";
  const rawText = settings.result_ad_text || "";
  const items   = React.useMemo(() => parseAdItems(rawText), [rawText]);

  React.useEffect(() => {
    if (mode !== "text" || items.length <= 1) return;
    setActiveIdx(0);
    const timer = setInterval(() => {
      setFading(true);
      setTimeout(() => {
        setActiveIdx(i => (i + 1) % items.length);
        setFading(false);
      }, 350);
    }, 5000);
    return () => clearInterval(timer);
  }, [mode, items.length, rawText]);

  if (settings.result_ad_enabled !== "1") return null;
  if (loading) return null;

  const url = settings.result_ad_url;

  // ── IMAGE mode ─────────────────────────────────────────────────────────────
  if (mode === "image") {
    const imgUrl = settings.result_ad_image_url;
    const imgAlt = settings.result_ad_image_alt || "广告";
    if (!imgUrl) return null;

    const imgEl = (
      <img
        src={imgUrl}
        alt={imgAlt}
        className={cn(
          "max-w-full max-h-24 object-contain rounded-xl mx-auto block",
          url && "hover:opacity-80 transition-opacity cursor-pointer",
        )}
        onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
      />
    );
    const wrapped = url
      ? <Link href={url} target="_blank" rel="noopener noreferrer sponsored">{imgEl}</Link>
      : imgEl;

    if (inline) return <div className="sm:hidden mt-4 px-1 text-center">{wrapped}</div>;
    return <div className="hidden sm:block mt-5 text-center">{wrapped}</div>;
  }

  // ── HTML mode ──────────────────────────────────────────────────────────────
  if (mode === "html") {
    const html = settings.result_ad_html;
    if (!html) return null;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const sanitized = typeof window !== "undefined"
      ? (require("dompurify") as typeof import("dompurify")).default.sanitize(html, { USE_PROFILES: { html: true } })
      : "";
    if (!sanitized) return null;
    const div = (
      <div
        className="result-ad-html max-w-full overflow-hidden"
        dangerouslySetInnerHTML={{ __html: sanitized }}
      />
    );
    if (inline) return <div className="sm:hidden mt-4 px-1">{div}</div>;
    return <div className="hidden sm:block mt-5">{div}</div>;
  }

  // ── TEXT mode (default) ────────────────────────────────────────────────────
  if (items.length === 0) return null;
  const label   = settings.result_ad_label || "广告";
  const current = items[activeIdx] ?? items[0];

  const content = (
    <div className={`flex items-center justify-center gap-2 ${url ? "hover:opacity-60 transition-opacity cursor-pointer" : ""}`}>
      <RiMegaphoneLine
        className="w-3 h-3 shrink-0 text-foreground/25"
        style={{ animation: "ad-float 3s ease-in-out infinite" }}
      />
      <span className="text-foreground/30 text-[10px] tracking-widest uppercase shrink-0">{label}</span>
      <span className="text-foreground/15 shrink-0">·</span>
      <span
        className="truncate text-foreground/40 leading-none"
        style={{
          opacity: fading ? 0 : 1,
          transition: "opacity 0.35s ease",
          color: current.color || undefined,
          fontWeight: current.bold ? "600" : undefined,
          fontSize: current.size === "xs" ? "10px" : current.size === "base" ? "12px" : "11px",
        }}
      >
        {current.text}
      </span>
      {items.length > 1 && (
        <div className="flex items-center gap-0.5 shrink-0">
          {items.map((_, i) => (
            <div
              key={i}
              className={`rounded-full transition-all duration-300 ${i === activeIdx ? "w-2.5 h-1 bg-foreground/25" : "w-1 h-1 bg-foreground/12"}`}
            />
          ))}
        </div>
      )}
      {url && <RiExternalLinkLine className="w-2.5 h-2.5 text-foreground/20 shrink-0" />}
    </div>
  );

  const wrapper = url
    ? <Link href={url} target="_blank" rel="noopener noreferrer sponsored" className="block">{content}</Link>
    : content;

  if (inline) return <div className="sm:hidden mt-4 px-1">{wrapper}</div>;
  return <div className="hidden sm:block mt-5 text-center">{wrapper}</div>;
}