/** Result page ad slots — multi-ad management.
 *
 * Each slot holds a list of ads (`result_ads` JSON). Every enabled ad in the
 * slot is rendered; an ad is a single unit that may combine text, an image, a
 * click-through URL and/or custom HTML (HTML wins when present). Plain-text
 * ads with multiple items keep the 4s fade cycling.
 */
import React from "react";
import Link from "next/link";
import { RiExternalLinkLine, RiMegaphoneLine } from "@remixicon/react";
import { cn } from "@/lib/utils";
import { useSiteSettings, parseResultAds, type ResultAdItem, type ResultAdSlot } from "@/lib/site-settings";

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

/** Individual ad unit — text + image + url + html combined, HTML wins. */
function AdUnit({
  ad, variant, inline,
}: { ad: ResultAdItem; variant: "bar" | "card"; inline: boolean }) {
  const items = React.useMemo(() => parseAdItems(ad.text || ""), [ad.text]);
  const [activeIdx, setActiveIdx] = React.useState(0);
  const [fading, setFading] = React.useState(false);
  const cycling = items.length > 1;

  React.useEffect(() => {
    if (!cycling) return;
    setActiveIdx(0);
    const timer = setInterval(() => {
      setFading(true);
      setTimeout(() => {
        setActiveIdx(i => (i + 1) % items.length);
        setFading(false);
      }, 350);
    }, 5000);
    return () => clearInterval(timer);
  }, [cycling, items.length, ad.text]);

  const url = (ad.url || "").trim();
  const html = (ad.html || "").trim();

  // ── HTML content takes precedence ─────────────────────────────────────────
  if (html) {
    let sanitized = "";
    if (typeof window !== "undefined") {
      const win = window as unknown as { DOMPurify?: { sanitize: (h: string, o: object) => string } };
      if (win.DOMPurify) {
        sanitized = win.DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
      } else {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const mod = require("dompurify") as unknown as {
          default?: { sanitize: (h: string, o: object) => string };
          sanitize?: (h: string, o: object) => string;
        };
        const purify = (mod.default ?? mod) as { sanitize: (h: string, o: object) => string };
        sanitized = purify.sanitize(html, { USE_PROFILES: { html: true } });
      }
    }
    if (!sanitized) return null;
    const div = (
      <div
        className="result-ad-html max-w-full overflow-hidden"
        dangerouslySetInnerHTML={{ __html: sanitized }}
      />
    );
    return (
      <div className={cn(
        "rounded-lg border border-border/60 bg-card",
        variant === "card" ? "px-3 py-2" : "px-3 py-2 inline-block",
        url && "hover:opacity-90 transition-opacity cursor-pointer",
      )}>
        {url ? <Link href={url} target="_blank" rel="noopener noreferrer sponsored">{div}</Link> : div}
      </div>
    );
  }

  const imgUrl = (ad.image_url || "").trim();
  const label = (ad.label || "广告").trim();

  const imgEl = imgUrl ? (
    <img
      src={imgUrl}
      alt={(ad.image_alt || label).trim()}
      className={cn(
        "max-w-full object-contain mx-auto block",
        variant === "card" ? "max-h-40" : "max-h-24",
        url && "hover:opacity-80 transition-opacity cursor-pointer",
      )}
      onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
    />
  ) : null;

  const current = items[activeIdx] ?? items[0];
  const textEl = items.length > 0 ? (
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
          color: current?.color || undefined,
          fontWeight: current?.bold ? "600" : undefined,
          fontSize: current?.size === "xs" ? "10px" : current?.size === "base" ? "12px" : "11px",
        }}
      >
        {current?.text}
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
  ) : null;

  if (!imgEl && !textEl) return null;

  const body = imgEl && textEl ? (
    <div className="space-y-2">
      {imgEl}
      {textEl}
    </div>
  ) : imgEl || textEl;

  const wrapped = url ? <Link href={url} target="_blank" rel="noopener noreferrer sponsored">{body}</Link> : body;
  return <div className="flex justify-center">{wrapped}</div>;
}

export function ResultTextAd({
  loading = false,
  inline = false,
  variant = "bar",
  slot = "slot2",
}: { loading?: boolean; inline?: boolean; variant?: "bar" | "card"; slot?: ResultAdSlot }) {
  const settings = useSiteSettings();
  const ads = React.useMemo(() => parseResultAds(settings.result_ads)[slot], [settings.result_ads, slot]);
  const enabledAds = ads.filter(a => a.enabled === "1");

  if (enabledAds.length === 0) return null;
  if (loading) return null;

  if (variant === "card") {
    return (
      <div className="mt-3 px-3 py-2 rounded-lg border border-border/60 bg-card space-y-3">
        {enabledAds.map(ad => <AdUnit key={ad.id} ad={ad} variant="card" inline={false} />)}
      </div>
    );
  }
  if (inline) {
    return (
      <div className="sm:hidden mt-4 px-1 space-y-3">
        {enabledAds.map(ad => <AdUnit key={ad.id} ad={ad} variant="bar" inline />)}
      </div>
    );
  }
  return (
    <div className="hidden sm:block mt-5 text-center space-y-3">
      {enabledAds.map(ad => <AdUnit key={ad.id} ad={ad} variant="bar" inline={false} />)}
    </div>
  );
}
