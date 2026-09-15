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
  RiExternalLinkLine,
  RiAddLine,
  RiHeartLine,
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

/** Google favicon, same approach as the about page acknowledgements. */
function FaviconImage({ url, name, logo }: { url: string; name: string; logo?: string | null }) {
  const [failed, setFailed] = React.useState(false);
  const hostname = React.useMemo(() => {
    try { return new URL(url).hostname; } catch { return name; }
  }, [url, name]);

  const src = logo && !failed ? logo : `https://www.google.com/s2/favicons?domain=${hostname}&sz=64`;
  return (
    <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 bg-muted/60 overflow-hidden border border-border/40">
      {failed ? (
        <RiHeartLine className="w-4 h-4 text-rose-400" />
      ) : (
        <img
          src={src}
          alt={name}
          width={18}
          height={18}
          className="rounded-sm object-cover"
          onError={() => setFailed(true)}
        />
      )}
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

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="relative w-full max-w-3xl mx-auto px-4 sm:px-6 py-6 pb-14">
          {/* ── Header ─────────────────────────────────────────────── */}
          <motion.div initial="hidden" animate="visible" variants={fadeUp} className="flex items-center gap-3 mb-6">
            <Link
              href="/about"
              aria-label={zh ? "返回" : "Back"}
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-9 h-9 rounded-xl bg-muted/60 border border-border/60 flex items-center justify-center text-muted-foreground shrink-0">
                <RiLinksLine className="w-4 h-4" />
              </div>
              <div className="min-w-0">
                <h1 className="text-base font-bold leading-none truncate">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-1">
                  {!loading && !error && (
                    <>{links.length} {zh ? "个站点" : "sites"} · {grouped.length} {zh ? "个分类" : "categories"}</>
                  )}
                </p>
              </div>
            </div>
            <Link
              href="/links/apply"
              className="ml-auto shrink-0 inline-flex items-center gap-1.5 text-xs font-semibold text-background bg-foreground hover:opacity-85 rounded-lg px-3 py-2 transition-opacity"
            >
              <RiAddLine className="w-3.5 h-3.5" />
              {zh ? "申请友链" : "Apply"}
            </Link>
          </motion.div>

          {/* ── Intro ──────────────────────────────────────────────── */}
          <motion.p
            initial="hidden"
            animate="visible"
            variants={fadeUp}
            className="text-xs text-muted-foreground leading-relaxed mb-5"
          >
            {zh
              ? "互联网是连接彼此的桥梁，每个链接都是一次信任的握手。以下是值得你关注的朋友们。"
              : "The web connects us — every link is a handshake of trust. Here are friends worth your attention."}
          </motion.p>

          {/* ── Category chips ─────────────────────────────────────── */}
          {!loading && !error && cats.length > 1 && (
            <motion.div
              initial="hidden"
              animate="visible"
              variants={fadeUp}
              className="flex items-center gap-2 mb-6 overflow-x-auto pb-1 -mx-1 px-1 custom-scrollbar"
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
                        ? "border-foreground/40 bg-foreground text-background"
                        : "border-border bg-background text-muted-foreground hover:text-foreground hover:border-foreground/30",
                    )}
                  >
                    {cat === "all" ? (zh ? "全部" : "All") : cat}
                  </button>
                );
              })}
            </motion.div>
          )}

          {/* ── Cards ──────────────────────────────────────────────── */}
          <AnimatePresence mode="wait">
            {loading ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center py-20 gap-3 text-muted-foreground"
              >
                <RiLoader4Line className="w-6 h-6 animate-spin" />
                <p className="text-sm">{t("links.loading")}</p>
              </motion.div>
            ) : error ? (
              <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="py-20 text-center">
                <p className="text-sm text-muted-foreground">{t("links.load_failed")}</p>
              </motion.div>
            ) : links.length === 0 ? (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="py-20 text-center">
                <RiLinksLine className="w-11 h-11 text-muted-foreground/20 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground font-medium">{t("links.empty")}</p>
                <p className="text-xs text-muted-foreground/60 mt-1">{t("links.empty_hint")}</p>
              </motion.div>
            ) : activeRows.length === 0 ? (
              <motion.div key="none" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="py-20 text-center">
                <p className="text-sm text-muted-foreground">{zh ? "该分类下暂无站点" : "No sites in this category"}</p>
              </motion.div>
            ) : (
              <motion.div key={activeCat} initial="hidden" animate="visible" className="space-y-7">
                {activeRows.map(([category, items], gi) => (
                  <section key={category}>
                    <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                      <RiHeartLine className="w-4 h-4 text-rose-500" />
                      {category}
                      <span className="text-[10px] font-mono text-muted-foreground/60 font-normal tabular-nums">
                        {String(items.length).padStart(2, "0")}
                      </span>
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      {items.map((item, ii) => (
                        <motion.a
                          key={item.id}
                          href={item.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: Math.min((gi * 10 + ii) * 0.03, 0.4), duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
                          className="flex items-center gap-3 p-3 rounded-xl bg-muted/40 hover:bg-muted/70 border border-border/60 hover:border-border transition-all group"
                        >
                          <FaviconImage url={item.url} name={item.name} logo={item.logo_url} />
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-semibold leading-none truncate">{item.name}</p>
                            <p className="text-[10px] text-muted-foreground mt-1 leading-snug truncate">
                              {item.description || displayHost(item.url)}
                            </p>
                          </div>
                          <RiExternalLinkLine className="w-3.5 h-3.5 text-muted-foreground/30 group-hover:text-muted-foreground/60 transition-colors shrink-0" />
                        </motion.a>
                      ))}
                    </div>
                  </section>
                ))}
              </motion.div>
            )}
          </AnimatePresence>

          {/* ── Footer quote ───────────────────────────────────────── */}
          {!loading && !error && links.length > 0 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} className="flex flex-col items-center gap-3 mt-12 text-center">
              <div className="flex items-center gap-1.5 text-muted-foreground/40">
                {[0, 1, 2, 3, 4, 5].map(i => (
                  <span key={i} className={cn("h-1 rounded-full", i === 3 ? "w-3.5 bg-rose-500/70" : "w-1 bg-muted-foreground/30")} />
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

function displayHost(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}