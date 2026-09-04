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
  RiExternalLinkLine,
  RiGlobalLine,
  RiLoader4Line,
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

const card = {
  hidden: { opacity: 0, y: 10 },
  visible: (i: number) => ({
    opacity: 1, y: 0,
    transition: { duration: 0.28, delay: i * 0.07, ease: [0.32, 0.72, 0, 1] },
  }),
};

export default function LinksPage() {
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteName = settings.site_logo_text || "WHOIS";
  const pageTitle = settings.links_title || t("links.page_title");

  const [links, setLinks] = React.useState<FriendlyLink[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);

  React.useEffect(() => {
    fetch("/api/links")
      .then(r => r.json())
      .then(d => { setLinks(d.links || []); setLoading(false); })
      .catch(() => { setError(true); setLoading(false); });
  }, []);

  const grouped = React.useMemo(() => {
    const map = new Map<string, FriendlyLink[]>();
    links.forEach(link => {
      const key = link.category || t("links.default_category");
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(link);
    });
    return Array.from(map.entries());
  }, [links, t]);

  return (
    <>
      <Head>
        <title key="title">{`${pageTitle} — ${siteName}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6 pb-16">
          <div className="flex items-center gap-3 mb-6">
            <Link
              href="/about"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-500">
                <RiLinksLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{pageTitle}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  {settings.links_content || t("links.default_content")}
                </p>
              </div>
            </div>
            {!loading && !error && (
              <span className="ml-auto text-[10px] text-muted-foreground hidden sm:block">
                {t("links.count", { count: links.length })}
              </span>
            )}
          </div>

          <AnimatePresence mode="wait">
            {loading ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center py-24 gap-3 text-muted-foreground"
              >
                <RiLoader4Line className="w-7 h-7 animate-spin" />
                <p className="text-sm">{t("links.loading")}</p>
              </motion.div>
            ) : error ? (
              <motion.div
                key="error"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="py-24 text-center"
              >
                <p className="text-sm text-muted-foreground">{t("links.load_failed")}</p>
              </motion.div>
            ) : links.length === 0 ? (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="py-24 text-center"
              >
                <RiLinksLine className="w-12 h-12 text-muted-foreground/20 mx-auto mb-4" />
                <p className="text-sm text-muted-foreground font-medium">
                  {t("links.empty")}
                </p>
                <p className="text-xs text-muted-foreground/60 mt-1">
                  {t("links.empty_hint")}
                </p>
              </motion.div>
            ) : (
              <motion.div key="content" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
                {grouped.map(([category, items], gi) => (
                  <section key={category}>
                    <div className="flex items-center gap-3 mb-3">
                      <RiLinksLine className="w-4 h-4 text-emerald-500" />
                      <h2 className="text-sm font-bold tracking-tight">{category}</h2>
                      <div className="h-px flex-1 bg-border" />
                      <span className="text-[10px] text-muted-foreground tabular-nums">{items.length}</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {items.map((item, ii) => (
                        <motion.a
                          key={item.id}
                          href={item.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          custom={gi * 10 + ii}
                          initial="hidden"
                          animate="visible"
                          variants={card}
                          whileTap={{ scale: 0.96 }}
                          className="group glass-panel border border-border rounded-xl p-3 flex items-start gap-3 hover:border-primary/30 hover:bg-muted/40 transition-all cursor-pointer"
                        >
                          <div className="w-8 h-8 rounded-lg bg-muted/60 flex items-center justify-center shrink-0 overflow-hidden text-muted-foreground group-hover:bg-primary/10 group-hover:text-primary transition-colors">
                            {item.logo_url ? (
                              <img
                                src={item.logo_url}
                                alt={item.name}
                                className="w-full h-full object-cover rounded-lg"
                                onError={e => {
                                  const t = e.currentTarget;
                                  t.style.display = "none";
                                  t.nextElementSibling?.classList.remove("hidden");
                                }}
                              />
                            ) : null}
                            <RiGlobalLine className={cn("w-4 h-4", item.logo_url ? "hidden" : "")} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 mb-0.5">
                              <span className="text-sm font-semibold truncate">{item.name}</span>
                              <RiExternalLinkLine className="w-2.5 h-2.5 text-muted-foreground/40 group-hover:text-primary/50 transition-colors shrink-0" />
                            </div>
                            {item.description && (
                              <p className="text-[11px] text-muted-foreground leading-snug line-clamp-2">
                                {item.description}
                              </p>
                            )}
                            {!item.description && (
                              <p className="text-[11px] text-muted-foreground/50 truncate">
                                {item.url.replace(/^https?:\/\//, "").split("/")[0]}
                              </p>
                            )}
                          </div>
                        </motion.a>
                      ))}
                    </div>
                  </section>
                ))}
              </motion.div>
            )}
          </AnimatePresence>

          <div className="mt-10 pt-6 border-t border-border/40 text-center space-y-2">
            <p className="text-[11px] text-muted-foreground/50">
              {t("links.apply_hint")}
            </p>
            <Link
              href="/feedback"
              className="text-[11px] text-primary hover:underline flex items-center gap-1 justify-center"
            >
              {t("links.go_feedback")}
            </Link>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
