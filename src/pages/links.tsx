import React from "react";
import Head from "next/head";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import {
  RiArrowLeftSLine,
  RiLinksLine,
  RiLoader4Line,
  RiArrowRightUpLine,
  RiAddLine,
} from "@remixicon/react";

interface FriendlyLink {
  id: number;
  name: string;
  url: string;
  description: string | null;
  category: string | null;
  sort_order: number;
  logo_url: string | null;
}

type Row = [string, FriendlyLink[]];

/** Deterministic palette — cyan-leaning accent used for tiny dots / halos. */
function hashStr(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const ACCENTS = [
  { from: "from-cyan-400",   to: "to-sky-500" },
  { from: "from-teal-400",   to: "to-cyan-500" },
  { from: "from-sky-400",    to: "to-blue-500" },
  { from: "from-emerald-400", to: "to-teal-500" },
];

function accentFor(s: string) {
  return ACCENTS[hashStr(s) % ACCENTS.length];
}

function initialOf(name: string): string {
  for (const ch of name.trim()) {
    if (ch !== "." && ch !== "-" && ch !== "_" && ch !== " ") return ch.toUpperCase();
  }
  return "?";
}

function displayHost(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/** Network-node background: faint constellation drawn behind the hero. */
function NetworkField() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      <svg className="absolute -top-10 left-1/2 -translate-x-1/2 w-[720px] h-[320px]" viewBox="0 0 720 320" fill="none">
        <g stroke="currentColor" strokeOpacity="0.08" strokeWidth="1">
          <line x1="90" y1="60" x2="230" y2="120" />
          <line x1="230" y1="120" x2="360" y2="52" />
          <line x1="360" y1="52" x2="520" y2="140" />
          <line x1="520" y1="140" x2="640" y2="70" />
          <line x1="230" y1="120" x2="300" y2="240" />
          <line x1="360" y1="52" x2="420" y2="200" />
          <line x1="520" y1="140" x2="470" y2="260" />
          <line x1="640" y1="70" x2="600" y2="230" />
          <line x1="90" y1="60" x2="120" y2="200" />
          <line x1="120" y1="200" x2="300" y2="240" />
        </g>
        <g fill="currentColor" fillOpacity="0.35">
          <circle cx="90" cy="60" r="2.5" />
          <circle cx="230" cy="120" r="3" />
          <circle cx="360" cy="52" r="2" />
          <circle cx="520" cy="140" r="3" />
          <circle cx="640" cy="70" r="2" />
          <circle cx="300" cy="240" r="2.5" />
          <circle cx="420" cy="200" r="2" />
          <circle cx="470" cy="260" r="2.5" />
          <circle cx="600" cy="230" r="2" />
          <circle cx="120" cy="200" r="2" />
        </g>
        {/* cyan pulse nodes */}
        <g className="animate-pulse">
          <circle cx="230" cy="120" r="5" fill="#22d3ee" fillOpacity="0.18" />
          <circle cx="520" cy="140" r="5" fill="#22d3ee" fillOpacity="0.18" />
        </g>
      </svg>
    </div>
  );
}

const fadeUp = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.3, ease: [0.32, 0.72, 0, 1] } },
};

export default function LinksPage() {
  const { t, locale } = useTranslation();
  const settings = useSiteSettings();
  const siteName = settings.site_logo_text || "WHOIS";
  const pageTitle = settings.links_title || t("links.page_title");
  const zh = locale === "zh" || locale === "zh-tw";

  const [links, setLinks] = React.useState<FriendlyLink[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);
  const [activeCat, setActiveCat] = React.useState("all");

  React.useEffect(() => {
    fetch("/api/links")
      .then(r => r.json())
      .then(d => { setLinks(d.links || []); setLoading(false); })
      .catch(() => { setError(true); setLoading(false); });
  }, []);

  const grouped = React.useMemo<Row[]>(() => {
    const map = new Map<string, FriendlyLink[]>();
    links.forEach(link => {
      const key = link.category || t("links.default_category");
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(link);
    });
    return Array.from(map.entries());
  }, [links, t]);

  const cats = ["all", ...grouped.map(g => g[0])];
  const activeRows = activeCat === "all" ? grouped : grouped.filter(g => g[0] === activeCat);
  const featured = links[0] ?? null;
  const gridItems = featured ? links.slice(1) : links;

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="relative w-full max-w-4xl mx-auto px-4 sm:px-6 py-6 pb-14">
          {/* ── Hero ────────────────────────────────────────────── */}
          <motion.section
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            className="relative glass-panel border border-border rounded-3xl overflow-hidden mb-8"
          >
            <NetworkField />
            <div aria-hidden className="pointer-events-none absolute inset-0 bg-dot-pattern text-muted-foreground/[0.05]" />

            <div className="relative z-10 px-6 sm:px-8 py-8 sm:py-10">
              <div className="flex items-center gap-3 mb-6">
                <Link
                  href="/about"
                  aria-label={zh ? "返回" : "Back"}
                  className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
                >
                  <RiArrowLeftSLine className="w-5 h-5" />
                </Link>
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="relative w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/15 to-sky-500/15 ring-1 ring-inset ring-cyan-500/30 flex items-center justify-center text-cyan-600 dark:text-cyan-400 shrink-0">
                    <RiLinksLine className="w-4 h-4" />
                  </div>
                  <span className="text-sm font-bold tracking-tight truncate">{siteName}</span>
                </div>
                <Link
                  href="/links/apply"
                  className="ml-auto shrink-0 inline-flex items-center gap-1.5 text-xs font-semibold text-background bg-foreground hover:opacity-85 rounded-lg px-3 py-2 transition-opacity"
                >
                  <RiAddLine className="w-3.5 h-3.5" />
                  {zh ? "申请友链" : "Apply"}
                </Link>
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">
                <span className="text-shimmer">{pageTitle}</span>
              </h1>
              <p className="text-sm text-muted-foreground leading-relaxed mt-3 max-w-xl">
                {zh
                  ? "互联网是连接彼此的桥梁，每个链接都是一次信任的握手。以下是值得你关注的朋友们。"
                  : "The web connects us — every link is a handshake of trust. Here are friends worth your attention."}
              </p>
              {!loading && !error && (
                <p className="inline-flex items-center gap-2 text-[11px] font-medium text-muted-foreground mt-4">
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-500/80" />
                  {links.length} {zh ? "个站点" : "sites"} · {grouped.length} {zh ? "个分类" : "categories"}
                </p>
              )}
            </div>
          </motion.section>

          {/* ── Category chips ───────────────────────────────────── */}
          {!loading && !error && cats.length > 1 && (
            <motion.div
              initial="hidden"
              animate="visible"
              variants={fadeUp}
              className="relative flex items-center gap-2 mb-6 overflow-x-auto pb-1 -mx-1 px-1 custom-scrollbar"
            >
              {cats.map(cat => {
                const active = activeCat === cat;
                return (
                  <button
                    key={cat}
                    onClick={() => setActiveCat(cat)}
                    className={cn(
                      "shrink-0 inline-flex items-center gap-1.5 text-xs font-semibold rounded-full px-3 py-1.5 border transition-colors",
                      active
                        ? "border-cyan-500/50 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300"
                        : "border-border bg-background text-muted-foreground hover:text-foreground hover:border-foreground/30",
                    )}
                  >
                    {cat === "all" ? (zh ? "全部" : "All") : cat}
                  </button>
                );
              })}
            </motion.div>
          )}

          {/* ── Cards ───────────────────────────────────────────── */}
          <AnimatePresence mode="wait">
            {loading ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="relative flex flex-col items-center justify-center py-20 gap-3 text-muted-foreground"
              >
                <RiLoader4Line className="w-6 h-6 animate-spin" />
                <p className="text-sm">{t("links.loading")}</p>
              </motion.div>
            ) : error ? (
              <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="relative py-20 text-center">
                <p className="text-sm text-muted-foreground">{t("links.load_failed")}</p>
              </motion.div>
            ) : links.length === 0 ? (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="relative py-20 text-center">
                <RiLinksLine className="w-11 h-11 text-muted-foreground/20 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground font-medium">{t("links.empty")}</p>
                <p className="text-xs text-muted-foreground/60 mt-1">{t("links.empty_hint")}</p>
              </motion.div>
            ) : activeRows.length === 0 ? (
              <motion.div key="none" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="relative py-20 text-center">
                <p className="text-sm text-muted-foreground">{zh ? "该分类下暂无站点" : "No sites in this category"}</p>
              </motion.div>
            ) : (
              <motion.div key={activeCat} initial="hidden" animate="visible" className="relative space-y-9">
                {activeRows.map(([category, items], gi) => {
                  const accent = accentFor(category);
                  const isFeaturedRow = gi === 0 && activeCat === "all" && featured && items[0]?.id === featured.id;
                  return (
                    <section key={category}>
                      <div className="flex items-center gap-2.5 mb-3.5">
                        <span className={cn("w-2 h-2 rounded-[5px] bg-gradient-to-br rotate-45 shrink-0", accent.from, accent.to)} />
                        <h2 className="text-sm font-bold tracking-tight">{category}</h2>
                        <div className="h-px flex-1 bg-border" />
                        <span className="text-[10px] font-mono text-muted-foreground tabular-nums">
                          {String(items.length).padStart(2, "0")}
                        </span>
                      </div>

                      <div className={cn("grid gap-3", isFeaturedRow ? "grid-cols-1" : "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3")}>
                        {items.map((item, ii) => {
                          const isFeatured = isFeaturedRow && ii === 0;
                          const itemAccent = accentFor(item.name + item.url);
                          return (
                            <motion.a
                              key={item.id}
                              href={item.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              initial={{ opacity: 0, y: 12 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: Math.min((gi * 10 + ii) * 0.035, 0.45), duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
                              whileHover={{ y: -3 }}
                              whileTap={{ scale: 0.985 }}
                              className={cn(
                                "group relative block glass-panel border border-border rounded-2xl p-4 sm:p-5 overflow-hidden transition-colors hover:border-cyan-500/40",
                                isFeatured && "sm:p-6",
                              )}
                            >
                              {/* hover accent halo (subtle) */}
                              <div
                                aria-hidden
                                className={cn(
                                  "absolute -top-14 -right-14 w-32 h-32 rounded-full bg-gradient-to-br opacity-0 blur-xl group-hover:opacity-25 transition-opacity duration-300",
                                  itemAccent.from,
                                  itemAccent.to,
                                )}
                              />
                              {/* shine sweep */}
                              <div
                                aria-hidden
                                className="pointer-events-none absolute inset-y-0 -left-full w-1/2 bg-gradient-to-r from-transparent via-white/10 to-transparent skew-x-12 group-hover:left-[130%] transition-all duration-700 ease-out"
                              />

                              <div className="relative z-10 flex items-start gap-3.5">
                                <div className="group-hover:-rotate-3 transition-transform duration-300 shrink-0">
                                  <Monogram name={item.name} url={item.url} logo={item.logo_url} />
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center justify-between gap-2">
                                    <h3 className="text-sm font-bold truncate">{item.name}</h3>
                                    <span className="inline-flex items-center gap-0.5 text-[10px] font-semibold text-muted-foreground/50 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors shrink-0">
                                      {zh ? "访问" : "Visit"}
                                      <RiArrowRightUpLine className="w-3 h-3" />
                                    </span>
                                  </div>
                                  <p className="font-mono text-[10px] text-muted-foreground/60 truncate mt-0.5">
                                    {displayHost(item.url)}
                                  </p>
                                </div>
                              </div>

                              {item.description && (
                                <p className={cn(
                                  "text-[11px] text-muted-foreground leading-snug line-clamp-2 mt-3",
                                  isFeatured && "text-xs mt-4 line-clamp-3",
                                )}>
                                  {item.description}
                                </p>
                              )}

                              <div className={cn("mt-3.5 flex items-center justify-between border-t border-border/70 pt-2.5", isFeatured && "mt-4")}>
                                <span className="inline-flex items-center gap-1.5 text-[10px] text-muted-foreground">
                                  <span className={cn("w-1.5 h-1.5 rounded-full bg-gradient-to-br", itemAccent.from, itemAccent.to)} />
                                  {category}
                                </span>
                              </div>
                            </motion.a>
                          );
                        })}
                      </div>
                    </section>
                  );
                })}
              </motion.div>
            )}
          </AnimatePresence>

          {/* ── Footer quote ─────────────────────────────────────── */}
          {!loading && !error && links.length > 0 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} className="relative flex flex-col items-center gap-3 mt-12 text-center">
              <div className="flex items-center gap-1.5 text-muted-foreground/40">
                {[0, 1, 2, 3, 4, 5].map(i => (
                  <span key={i} className={cn("h-1 rounded-full", i === 3 ? "w-3.5 bg-cyan-500/70" : "w-1 bg-muted-foreground/30")} />
                ))}
              </div>
              <p className="text-xs text-muted-foreground/70 leading-relaxed max-w-md">
                {zh
                  ? "友情链接的本质是信任与推荐——每一条链接背后，都是一次真诚的相遇。"
                  : "A friendly link is trust and recommendation — behind each one is a sincere encounter."}
              </p>
            </motion.div>
          )}
        </main>
      </ScrollArea>
    </>
  );
}

/** Neutral glass monogram tile — cyan accent halo appears on hover. */
function Monogram({ name, url, logo }: { name: string; url: string; logo?: string | null }) {
  const accent = accentFor(name || url);
  const [tilt, setTilt] = React.useState(false);
  const [logoBroken, setLogoBroken] = React.useState(false);
  const showLogo = !!logo && !logoBroken;
  return (
    <div
      onMouseEnter={() => setTilt(true)}
      onMouseLeave={() => setTilt(false)}
      className="relative shrink-0 w-11 h-11 rounded-[14px] select-none"
    >
      <div
        aria-hidden
        className={cn(
          "absolute -inset-1 rounded-xl bg-gradient-to-br opacity-0 blur-md transition-opacity duration-300",
          accent.from,
          accent.to,
          tilt && "opacity-40",
        )}
      />
      <div
        className={cn(
          "relative h-full w-full rounded-[14px] bg-gradient-to-br from-zinc-500 to-zinc-700",
          "shadow-inner ring-1 ring-inset ring-white/15 overflow-hidden transition-transform duration-300",
          tilt && "scale-105 -rotate-3",
        )}
      >
        <div aria-hidden className="absolute inset-x-0 top-0 h-1/2 bg-gradient-to-b from-white/25 to-transparent" />
        <div aria-hidden className="absolute inset-x-0 bottom-0 h-1/3 bg-gradient-to-t from-black/30 to-transparent" />
        {showLogo ? (
          <img src={logo} alt="" loading="lazy" className="relative w-full h-full object-cover" onError={() => setLogoBroken(true)} />
        ) : (
          <span className="relative flex items-center justify-center w-full h-full text-white font-bold text-base leading-none">
            {initialOf(name)}
          </span>
        )}
      </div>
    </div>
  );
}