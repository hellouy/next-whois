import React from "react";
import Head from "next/head";
import Link from "next/link";
import {
  RiArrowLeftSLine,
  RiExternalLinkLine,
  RiCompassLine,
  RiFireLine,
} from "@remixicon/react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { TOOL_CATEGORIES, Tool } from "@/lib/tools-data";
import { motion } from "framer-motion";
import { useTranslation } from "@/lib/i18n";
import { useSession } from "next-auth/react";
import { useSiteSettings } from "@/lib/site-settings";

const CLICKS_KEY = "tool_clicks";

function loadLocalClicks(): Record<string, number> {
  if (typeof window === "undefined") return {};
  try {
    return JSON.parse(localStorage.getItem(CLICKS_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveLocalClick(url: string, prev: Record<string, number>): Record<string, number> {
  const next = { ...prev, [url]: (prev[url] || 0) + 1 };
  try {
    localStorage.setItem(CLICKS_KEY, JSON.stringify(next));
  } catch {}
  return next;
}

function mergeClicks(
  local: Record<string, number>,
  remote: Record<string, number>
): Record<string, number> {
  const merged: Record<string, number> = { ...remote };
  for (const [url, count] of Object.entries(local)) {
    merged[url] = Math.max(merged[url] ?? 0, count);
  }
  return merged;
}

export default function NavPage() {
  const { t, locale } = useTranslation();
  const { data: session } = useSession();
  const settings = useSiteSettings();
  const siteLabel = settings.site_logo_text || "X.RW";

  const [clicks, setClicks] = React.useState<Record<string, number>>(loadLocalClicks);

  const fetchedRef = React.useRef(false);
  React.useEffect(() => {
    if (fetchedRef.current) return;
    fetchedRef.current = true;
    fetch("/api/tools/clicks")
      .then((r) => r.json())
      .then((json) => {
        if (json.clicks) {
          setClicks((prev) => mergeClicks(prev, json.clicks));
        }
      })
      .catch(() => {});
  }, []);

  const isChinese = locale === "zh" || locale === "zh-tw";
  const getDesc = (tool: Tool) => (isChinese ? tool.desc : tool.descEn);

  const handleClick = (url: string) => {
    setClicks((prev) => {
      const updated = saveLocalClick(url, prev);
      fetch("/api/tools/click", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      }).catch(() => {});
      return updated;
    });
  };

  const sortedCategories = TOOL_CATEGORIES.map((cat) => {
    const sorted = [...cat.tools].sort(
      (a, b) => (clicks[b.url] || 0) - (clicks[a.url] || 0)
    );
    return { ...cat, tools: sorted };
  });

  const totalTools = TOOL_CATEGORIES.reduce((s, c) => s + c.tools.length, 0);

  return (
    <>
      <Head>
        <title key="title">{`${t("nav_directory")} — ${siteLabel}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6">

          <div className="flex items-center gap-3 mb-6">
            <Link
              href="/"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
                <RiCompassLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("nav_directory")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("nav_directory_desc")}</p>
              </div>
            </div>
            <div className="ml-auto">
              <span className="text-[11px] text-muted-foreground/60 tabular-nums">
                {totalTools} {isChinese ? "个工具" : "tools"}
              </span>
            </div>
          </div>

          <div className="space-y-7">
            {sortedCategories.map((cat) => (
              <section key={cat.id}>
                <div className="flex items-center gap-2.5 mb-3">
                  <h2 className="text-sm font-bold tracking-tight text-foreground/80">
                    {t(cat.titleKey as Parameters<typeof t>[0])}
                  </h2>
                  {clicks && Object.keys(clicks).length > 0 && (
                    <span className="inline-flex items-center gap-0.5 text-[9px] text-orange-500/60 font-medium">
                      <RiFireLine className="w-2.5 h-2.5" />
                      {isChinese ? "按热度排序" : "by clicks"}
                    </span>
                  )}
                  <div className="h-px flex-1 bg-border/50" />
                  <span className="text-[9px] text-muted-foreground/50 tabular-nums">
                    {cat.tools.length}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {cat.tools.map((tool, ti) => {
                    const clickCount = clicks[tool.url] || 0;
                    return (
                      <motion.a
                        key={`${tool.url}-${ti}`}
                        href={tool.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        whileTap={{ scale: 0.95 }}
                        onClick={() => handleClick(tool.url)}
                        className="group relative flex flex-col gap-1 p-3 rounded-xl border border-border/60 bg-background hover:bg-muted/30 hover:border-primary/30 transition-all duration-150 cursor-pointer overflow-hidden"
                      >
                        <div className="flex items-start justify-between gap-1">
                          <span className="text-[13px] font-semibold leading-tight truncate text-foreground/90 group-hover:text-foreground transition-colors">
                            {tool.name}
                          </span>
                          <div className="flex items-center gap-1 shrink-0 pt-0.5">
                            {clickCount > 0 && (
                              <span className="text-[8px] text-orange-500/50 tabular-nums">
                                {clickCount}
                              </span>
                            )}
                            <RiExternalLinkLine className="w-2.5 h-2.5 text-muted-foreground/30 group-hover:text-primary/50 transition-colors" />
                          </div>
                        </div>
                        <span className="text-[10px] text-muted-foreground/70 leading-snug line-clamp-2">
                          {getDesc(tool)}
                        </span>
                      </motion.a>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>

          <div className="mt-10 pt-5 border-t border-border/30 text-center">
            <p className="text-[10px] text-muted-foreground/40">
              {t("tools.footer")}
            </p>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
