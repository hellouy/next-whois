"use client";

import * as React from "react";
import {
  RiSunFill,
  RiMoonFill,
  RiSmartphoneFill,
  RiApps2Line,
  RiCodeSSlashLine,
  RiCloseLine,
  RiGlobalLine,
  RiServerLine,
  RiHistoryLine,
  RiDeleteBinLine,
  RiToolsLine,
  RiUserLine,
  RiLogoutBoxLine,
  RiDashboardLine,
  RiShieldUserLine,
  RiLockLine,
  RiMapPinLine,
  RiInformationLine,
  RiHeart3Line,
  RiFileList2Line,
  RiCompassLine,
  RiWifiLine,
  RiArrowLeftSLine,
} from "@remixicon/react";
import { useTheme } from "next-themes";
import { motion, AnimatePresence } from "framer-motion";
import { cn, toSearchURI } from "@/lib/utils";
import { VERSION } from "@/lib/env";
import Link from "next/link";
import { useRouter } from "next/router";
import { useScrollDirection } from "@/hooks/useScrollDirection";
import { LanguageSwitcher } from "./language-switcher";
import {
  Drawer,
  DrawerContent,
  DrawerTrigger,
  DrawerClose,
  DrawerTitle,
} from "@/components/ui/drawer";
import { listHistory, removeHistory } from "@/lib/history";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { useSession, signOut } from "next-auth/react";
import { useSiteSettings } from "@/lib/site-settings";
import { ADMIN_EMAIL } from "@/lib/admin-shared";
import { useTranslation, TranslationKey } from "@/lib/i18n";

const TAP = { whileTap: { scale: 0.88 }, transition: { type: "spring" as const, stiffness: 500, damping: 22 } };

function HistoryTypeIcon({ type }: { type: string }) {
  const config: Record<string, { label: string; color: string }> = {
    domain: { label: "🌐", color: "text-blue-500" },
    ipv4: { label: "4", color: "text-emerald-600" },
    ipv6: { label: "6", color: "text-purple-500" },
    asn: { label: "AS", color: "text-orange-500" },
    cidr: { label: "/", color: "text-pink-500" },
  };
  const c = config[type] || { label: "?", color: "text-gray-500" };
  if (type === "domain") {
    return <RiGlobalLine className={cn("w-3.5 h-3.5", c.color)} />;
  }
  return <span className={cn("text-[9px] font-bold", c.color)}>{c.label}</span>;
}

function HistoryDrawer() {
  const [open, setOpen] = React.useState(false);
  const [mounted, setMounted] = React.useState(false);
  const [refreshTick, setRefreshTick] = React.useState(0);
  const { t, locale } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const { data: sessionData } = useSession();
  const histSettings = useSiteSettings();
  const queryOnlyMode = histSettings.query_only_mode === "1";
  const isHistAdmin = (sessionData?.user as any)?.email?.toLowerCase?.()?.trim?.() === ADMIN_EMAIL;

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const allHistory = React.useMemo(() => {
    if (!mounted) return [];
    return listHistory().sort((a, b) => b.timestamp - a.timestamp);
  }, [mounted, refreshTick, open]);

  const grouped = React.useMemo(() => {
    const groups: { label: string; items: typeof allHistory }[] = [];
    if (!allHistory.length) return groups;
    let curLabel = "";
    let curItems: typeof allHistory = [];
    for (const item of allHistory) {
      const date = new Date(item.timestamp);
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const yesterday = new Date(today.getTime() - 86400000);
      const d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
      let label: string;
      if (d.getTime() === today.getTime()) {
        label = t("today");
      } else if (d.getTime() === yesterday.getTime()) {
        label = t("yesterday");
      } else if (isChinese) {
        label = date.getFullYear() === now.getFullYear()
          ? format(date, "M月d日")
          : format(date, "yyyy年M月d日");
      } else {
        label = date.getFullYear() === now.getFullYear()
          ? format(date, "MMM d")
          : format(date, "MMM d, yyyy");
      }
      if (label !== curLabel) {
        if (curItems.length) groups.push({ label: curLabel, items: curItems });
        curLabel = label;
        curItems = [item];
      } else {
        curItems.push(item);
      }
    }
    if (curItems.length) groups.push({ label: curLabel, items: curItems });
    return groups;
  }, [allHistory, isChinese, t]);

  const handleDelete = React.useCallback(
    (e: React.MouseEvent, query: string) => {
      e.preventDefault();
      e.stopPropagation();
      removeHistory(query);
      setRefreshTick((t) => t + 1);
    },
    [],
  );

  if (queryOnlyMode && !isHistAdmin) return null;

  return (
    <Drawer open={open} onOpenChange={setOpen}>
      <DrawerTrigger asChild>
        <motion.button
          type="button"
          className="p-2 pr-0 inline-flex items-center justify-center touch-manipulation min-h-[44px] min-w-[44px]"
          {...TAP}
          aria-label={t("nav_search_history")}
        >
          <RiHistoryLine className="h-[1rem] w-[1rem]" />
        </motion.button>
      </DrawerTrigger>

      <DrawerContent className="max-h-[82vh]">
        <div className="flex items-center justify-between px-4 pt-4 pb-2">
          <DrawerTitle className="text-sm font-semibold">{t("nav_search_history")}</DrawerTitle>
          <DrawerClose asChild>
            <button className="p-1.5 rounded-lg hover:bg-muted/50 transition-colors touch-manipulation">
              <RiCloseLine className="w-4 h-4 text-muted-foreground" />
            </button>
          </DrawerClose>
        </div>
        <div className="overflow-y-auto px-2 pb-8">
          {allHistory.length > 0 ? (
            <div className="space-y-1">
              {grouped.map((group) => (
                <div key={group.label}>
                  <div className="flex items-center gap-3 py-2 px-1">
                    <div className="h-px flex-1 bg-border" />
                    <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider shrink-0">
                      {group.label}
                    </span>
                    <div className="h-px flex-1 bg-border" />
                  </div>
                  {group.items.map((item) => {
                    const rs = item.regStatus ?? "unknown";
                    const statusCfg: Record<string, { label: string; cls: string }> = {
                      registered:   { label: t("history_registered"),   cls: "text-emerald-600 border-emerald-300/70 bg-emerald-50 dark:bg-emerald-950/30 dark:border-emerald-700/40" },
                      unregistered: { label: t("history_unregistered"), cls: "text-sky-600 border-sky-300/70 bg-sky-50 dark:bg-sky-950/30 dark:border-sky-700/40" },
                      reserved:     { label: t("history_reserved"),     cls: "text-amber-600 border-amber-300/70 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-700/40" },
                      error:        { label: t("history_error"),        cls: "text-rose-600 border-rose-300/70 bg-rose-50 dark:bg-rose-950/30 dark:border-rose-700/40" },
                      unknown:      { label: t("history_unknown"),      cls: "text-muted-foreground border-border bg-muted/50" },
                    };
                    const cfg = statusCfg[rs] ?? statusCfg.unknown;
                    return (
                    <DrawerClose
                      asChild
                      key={`${item.query}-${item.timestamp}`}
                    >
                      <Link
                        href={item.query ? toSearchURI(item.query) : "/"}
                        className="group flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-muted/50 active:bg-muted transition-colors touch-manipulation"
                      >
                        <div className="w-7 h-7 rounded-md grid place-items-center border border-border bg-muted/20 shrink-0">
                          <HistoryTypeIcon type={item.queryType} />
                        </div>
                        <span className="text-sm font-medium truncate flex-1 min-w-0 uppercase">
                          {item.query}
                        </span>
                        {item.queryType === "domain" ? (
                          <span className={`shrink-0 text-[10px] font-semibold px-1.5 py-0.5 rounded-md border ${cfg.cls}`}>
                            {cfg.label}
                          </span>
                        ) : (
                          <Badge
                            variant="outline"
                            className="text-[8px] px-1.5 py-0 uppercase tracking-wider shrink-0"
                          >
                            {item.queryType}
                          </Badge>
                        )}
                        <span className="text-[11px] text-muted-foreground tabular-nums shrink-0">
                          {format(item.timestamp, "h:mm a")}
                        </span>
                        <button
                          className="opacity-0 group-hover:opacity-100 [@media(hover:none)]:opacity-50 transition-opacity p-1.5 -mr-0.5 rounded-lg hover:bg-destructive/10 active:bg-destructive/20 shrink-0 touch-manipulation"
                          onClick={(e) => handleDelete(e, item.query)}
                        >
                          <RiDeleteBinLine className="w-3.5 h-3.5 text-muted-foreground group-hover:text-destructive [@media(hover:none)]:text-muted-foreground/70" />
                        </button>
                      </Link>
                    </DrawerClose>
                    );
                  })}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <RiHistoryLine className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">{t("no_history_title")}</p>
              <p className="text-xs text-muted-foreground/60 mt-1">
                {t("no_history_description")}
              </p>
            </div>
          )}
        </div>
      </DrawerContent>
    </Drawer>
  );
}

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const toggleTheme = () => {
    if (theme === "light") setTheme("dark");
    else if (theme === "dark") setTheme("system");
    else setTheme("light");
  };

  if (!mounted) {
    return (
      <button>
        <span className="sr-only">Toggle theme</span>
      </button>
    );
  }

  return (
    <motion.button
      type="button"
      className="p-2 pr-0 touch-manipulation min-h-[44px] min-w-[44px] inline-flex items-center justify-center"
      onClick={toggleTheme}
      {...TAP}
    >
      <AnimatePresence mode="wait">
        <motion.div
          key={theme}
          initial={{ opacity: 0, rotate: -180 }}
          animate={{ opacity: 1, rotate: 0 }}
          exit={{ opacity: 0, rotate: 180 }}
          transition={{ duration: 0.2 }}
        >
          {theme === "light" && <RiSunFill className="h-[1rem] w-[1rem]" />}
          {theme === "dark" && <RiMoonFill className="h-[1rem] w-[1rem]" />}
          {theme === "system" && (
            <RiSmartphoneFill className="h-[1rem] w-[1rem]" />
          )}
        </motion.div>
      </AnimatePresence>
      <span className="sr-only">Toggle theme</span>
    </motion.button>
  );
}

interface NavItem {
  labelKey: TranslationKey;
  descKey: TranslationKey;
  href?: string;
  subPanel?: string;
  icon: React.ReactNode;
  external?: boolean;
  settingKey?: string;
}

interface NavGroup {
  groupKey: TranslationKey;
  items: NavItem[];
}

interface SubPanelItem {
  href: string;
  labelKey: TranslationKey;
  descKey: TranslationKey;
  icon: React.ReactNode;
  colorClass: string;
  bgClass: string;
  settingKey?: string;
}

const TOOLS_SUB_ITEMS: SubPanelItem[] = [
  { href: "/dns",  labelKey: "nav_dns",         descKey: "nav_dns_desc",       icon: <RiServerLine className="h-5 w-5" />,    colorClass: "text-violet-600 dark:text-violet-400", bgClass: "bg-violet-500/10", settingKey: "enable_dns" },
  { href: "/ip",   labelKey: "nav_ip",          descKey: "nav_ip_desc",        icon: <RiMapPinLine className="h-5 w-5" />,    colorClass: "text-blue-600 dark:text-blue-400",    bgClass: "bg-blue-500/10",   settingKey: "enable_ip" },
  { href: "/ssl",  labelKey: "nav_ssl",         descKey: "nav_ssl_desc",       icon: <RiLockLine className="h-5 w-5" />,      colorClass: "text-emerald-600 dark:text-emerald-400", bgClass: "bg-emerald-500/10", settingKey: "enable_ssl" },
  { href: "/icp",  labelKey: "nav_icp",         descKey: "nav_icp_desc",       icon: <RiFileList2Line className="h-5 w-5" />, colorClass: "text-amber-600 dark:text-amber-400",  bgClass: "bg-amber-500/10", settingKey: "enable_icp" },
  { href: "/http", labelKey: "http.page_title", descKey: "http.page_subtitle", icon: <RiWifiLine className="h-5 w-5" />,      colorClass: "text-sky-600 dark:text-sky-400",      bgClass: "bg-sky-500/10",   settingKey: "enable_http" },
];

const NAV_GROUPS: NavGroup[] = [
  {
    groupKey: "nav_section_tools",
    items: [
      { labelKey: "nav_domain_lookup",  descKey: "nav_domain_lookup_desc",  href: "/",           icon: <RiGlobalLine className="h-6 w-6" /> },
      { labelKey: "nav_tools",          descKey: "nav_tools_desc",           subPanel: "tools",   icon: <RiToolsLine className="h-6 w-6" /> },
      { labelKey: "nav_directory",      descKey: "nav_directory_desc",       href: "/directory",  icon: <RiCompassLine className="h-6 w-6" /> },
      { labelKey: "nav_search_history", descKey: "nav_search_history",       subPanel: "history", icon: <RiHistoryLine className="h-6 w-6" /> },
    ],
  },
  {
    groupKey: "nav_section_info",
    items: [
      { labelKey: "nav_api_docs",   descKey: "nav_api_docs_desc",   href: "/docs",    icon: <RiCodeSSlashLine className="h-6 w-6" />, settingKey: "enable_docs" },
      { labelKey: "nav_tlds",       descKey: "nav_tlds_desc",       href: "/tlds",    icon: <RiServerLine className="h-6 w-6" /> },
      { labelKey: "nav_about",      descKey: "nav_about_desc",      href: "/about",   icon: <RiInformationLine className="h-6 w-6" />, settingKey: "enable_about" },
      { labelKey: "nav_sponsor",    descKey: "nav_sponsor_desc",    href: "/sponsor", icon: <RiHeart3Line className="h-6 w-6" />, settingKey: "enable_sponsor" },
    ],
  },
];

export function NavDrawer() {
  const [open, setOpen] = React.useState(false);
  const [subPanel, setSubPanel] = React.useState<string | null>(null);
  const settings = useSiteSettings();
  const { t, locale } = useTranslation();
  const isChinese = locale === "zh" || locale === "zh-tw";
  const logoText = settings.site_logo_text || "X.RW";

  // ── History sub-panel state ────────────────────────────────────────────
  const [histMounted, setHistMounted] = React.useState(false);
  const [histRefreshTick, setHistRefreshTick] = React.useState(0);

  React.useEffect(() => {
    if (!open) { setSubPanel(null); return; }
    setHistMounted(true);
  }, [open]);

  const allHistory = React.useMemo(() => {
    if (!histMounted) return [];
    return listHistory().sort((a, b) => b.timestamp - a.timestamp);
  }, [histMounted, histRefreshTick, subPanel]);

  const histGrouped = React.useMemo(() => {
    const groups: { label: string; items: typeof allHistory }[] = [];
    if (!allHistory.length) return groups;
    let curLabel = "";
    let curItems: typeof allHistory = [];
    for (const item of allHistory) {
      const date = new Date(item.timestamp);
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const yesterday = new Date(today.getTime() - 86400000);
      const d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
      let label: string;
      if (d.getTime() === today.getTime()) label = t("today");
      else if (d.getTime() === yesterday.getTime()) label = t("yesterday");
      else if (isChinese) label = date.getFullYear() === now.getFullYear() ? format(date, "M月d日") : format(date, "yyyy年M月d日");
      else label = date.getFullYear() === now.getFullYear() ? format(date, "MMM d") : format(date, "MMM d, yyyy");
      if (label !== curLabel) {
        if (curItems.length) groups.push({ label: curLabel, items: curItems });
        curLabel = label;
        curItems = [item];
      } else {
        curItems.push(item);
      }
    }
    if (curItems.length) groups.push({ label: curLabel, items: curItems });
    return groups;
  }, [allHistory, isChinese, t]);

  const handleHistDelete = React.useCallback((e: React.MouseEvent, query: string) => {
    e.preventDefault();
    e.stopPropagation();
    removeHistory(query);
    setHistRefreshTick(v => v + 1);
  }, []);
  // ─────────────────────────────────────────────────────────────────────

  const visibleGroups = NAV_GROUPS.map(group => ({
    ...group,
    items: group.items.filter(item =>
      !item.settingKey || !!(settings as unknown as Record<string, string>)[item.settingKey]
    ),
  })).filter(group => group.items.length > 0);

  const visibleSubItems = TOOLS_SUB_ITEMS.filter(item =>
    !item.settingKey || !!(settings as unknown as Record<string, string>)[item.settingKey]
  );

  return (
    <Drawer open={open} onOpenChange={setOpen}>
      <DrawerTrigger asChild>
        <motion.button
          type="button"
          className="p-2 pr-0 inline-flex items-center justify-center touch-manipulation min-h-[44px] min-w-[44px]"
          {...TAP}
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={open ? "close" : "open"}
              initial={{ opacity: 0, rotate: -90 }}
              animate={{ opacity: 1, rotate: 0 }}
              exit={{ opacity: 0, rotate: 90 }}
              transition={{ duration: 0.15 }}
            >
              {open ? (
                <RiCloseLine className="h-[1rem] w-[1rem]" />
              ) : (
                <RiApps2Line className="h-[1rem] w-[1rem]" />
              )}
            </motion.div>
          </AnimatePresence>
          <span className="sr-only">Navigation menu</span>
        </motion.button>
      </DrawerTrigger>

      <DrawerContent className="pb-safe overflow-hidden">
        <AnimatePresence mode="wait" initial={false}>
          {!subPanel ? (
            <motion.div
              key="main"
              initial={{ x: "-100%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: "-100%", opacity: 0 }}
              transition={{ type: "spring", stiffness: 400, damping: 35 }}
              className="px-4 pt-2 pb-8"
            >
              <div className="flex items-center justify-between mb-5">
                <div>
                  <p className="text-base font-semibold tracking-tight">{logoText}</p>
                  <p className="text-xs text-muted-foreground mt-0.5" suppressHydrationWarning>
                    {t("nav_version_menu", { version: VERSION })}
                  </p>
                </div>
                <DrawerClose asChild>
                  <button className="rounded-full p-1.5 hover:bg-muted transition-colors touch-manipulation">
                    <RiCloseLine className="h-4 w-4 text-muted-foreground" />
                  </button>
                </DrawerClose>
              </div>

              <div className="space-y-5">
                {visibleGroups.map((group) => (
                  <div key={group.groupKey}>
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 mb-2.5 px-0.5">
                      {t(group.groupKey)}
                    </p>
                    <div className={cn(
                      "grid gap-2.5",
                      group.items.length === 3 ? "grid-cols-3" :
                      group.items.length % 2 === 0 ? "grid-cols-2" : "grid-cols-3"
                    )}>
                      {group.items.map((item) => {
                        const cardContent = (
                          <motion.div
                            className={cn(
                              "flex flex-col items-center gap-2 p-3.5 rounded-2xl",
                              "border border-border/50 bg-background",
                              "hover:bg-muted/50 hover:border-primary/25 hover:shadow-sm",
                              "transition-all duration-150 cursor-pointer text-center",
                            )}
                            whileTap={{ scale: 0.94 }}
                          >
                            <div className="p-2.5 rounded-xl bg-muted/60 text-foreground/70">
                              {item.icon}
                            </div>
                            <p className="text-xs font-semibold leading-tight text-foreground/80">
                              {t(item.labelKey)}
                            </p>
                          </motion.div>
                        );

                        if (item.subPanel) {
                          return (
                            <button
                              key={item.subPanel}
                              type="button"
                              className="touch-manipulation w-full text-left"
                              onClick={() => setSubPanel(item.subPanel!)}
                            >
                              {cardContent}
                            </button>
                          );
                        }

                        return (
                          <DrawerClose key={item.href} asChild>
                            <Link href={item.href!} className="touch-manipulation">
                              {cardContent}
                            </Link>
                          </DrawerClose>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-5 pt-4 border-t border-border/40">
                <p className="text-[11px] text-muted-foreground text-center">
                  {t("nav_tagline")}
                </p>
              </div>
            </motion.div>
          ) : subPanel === "tools" ? (
            <motion.div
              key="tools-sub"
              initial={{ x: "100%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: "100%", opacity: 0 }}
              transition={{ type: "spring", stiffness: 400, damping: 35 }}
              className="px-4 pt-2 pb-8"
            >
              <div className="flex items-center gap-2 mb-5">
                <button
                  type="button"
                  onClick={() => setSubPanel(null)}
                  className="p-1.5 rounded-lg hover:bg-muted transition-colors touch-manipulation text-muted-foreground hover:text-foreground"
                >
                  <RiArrowLeftSLine className="h-5 w-5" />
                </button>
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
                    <RiToolsLine className="h-4 w-4" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold leading-tight">{t("nav_tools")}</p>
                    <p className="text-[10px] text-muted-foreground">{t("tools_builtin_subtitle")}</p>
                  </div>
                </div>
                <div className="ml-auto">
                  <DrawerClose asChild>
                    <button className="rounded-full p-1.5 hover:bg-muted transition-colors touch-manipulation">
                      <RiCloseLine className="h-4 w-4 text-muted-foreground" />
                    </button>
                  </DrawerClose>
                </div>
              </div>

              <div className="space-y-2">
                {visibleSubItems.map((item) => (
                  <DrawerClose key={item.href} asChild>
                    <Link href={item.href} className="touch-manipulation block">
                      <motion.div
                        whileTap={{ scale: 0.97 }}
                        className="flex items-center gap-3 p-3 rounded-xl border border-border/50 bg-muted/10 hover:bg-muted/40 hover:border-primary/20 transition-all duration-150 cursor-pointer"
                      >
                        <div className={cn("p-2 rounded-lg shrink-0", item.bgClass, item.colorClass)}>
                          {item.icon}
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-semibold leading-tight">{t(item.labelKey)}</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5 leading-snug line-clamp-1">
                            {t(item.descKey)}
                          </p>
                        </div>
                      </motion.div>
                    </Link>
                  </DrawerClose>
                ))}
              </div>

              <div className="mt-4 pt-3 border-t border-border/30">
                <DrawerClose asChild>
                  <Link href="/tools" className="touch-manipulation block">
                    <div className="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl bg-muted/20 hover:bg-muted/40 transition-colors">
                      <span className="text-xs font-medium text-muted-foreground">{t("tools_builtin_title")}</span>
                      <span className="text-xs text-muted-foreground/40">→</span>
                    </div>
                  </Link>
                </DrawerClose>
              </div>
            </motion.div>
          ) : (
            /* ── History sub-panel ── */
            <motion.div
              key="history-sub"
              initial={{ x: "100%", opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: "100%", opacity: 0 }}
              transition={{ type: "spring", stiffness: 400, damping: 35 }}
              className="px-4 pt-2 pb-8 flex flex-col"
              style={{ maxHeight: "70vh" }}
            >
              <div className="flex items-center gap-2 mb-4 shrink-0">
                <button
                  type="button"
                  onClick={() => setSubPanel(null)}
                  className="p-1.5 rounded-lg hover:bg-muted transition-colors touch-manipulation text-muted-foreground hover:text-foreground"
                >
                  <RiArrowLeftSLine className="h-5 w-5" />
                </button>
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
                    <RiHistoryLine className="h-4 w-4" />
                  </div>
                  <p className="text-sm font-semibold leading-tight">{t("nav_search_history")}</p>
                </div>
                <div className="ml-auto">
                  <DrawerClose asChild>
                    <button className="rounded-full p-1.5 hover:bg-muted transition-colors touch-manipulation">
                      <RiCloseLine className="h-4 w-4 text-muted-foreground" />
                    </button>
                  </DrawerClose>
                </div>
              </div>

              <div className="overflow-y-auto flex-1">
                {allHistory.length > 0 ? (
                  <div className="space-y-1">
                    {histGrouped.map((group) => (
                      <div key={group.label}>
                        <div className="flex items-center gap-3 py-2 px-1">
                          <div className="h-px flex-1 bg-border" />
                          <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider shrink-0">{group.label}</span>
                          <div className="h-px flex-1 bg-border" />
                        </div>
                        {group.items.map((item) => {
                          const rs = item.regStatus ?? "unknown";
                          const statusCfg: Record<string, { label: string; cls: string }> = {
                            registered:   { label: t("history_registered"),   cls: "text-emerald-600 border-emerald-300/70 bg-emerald-50 dark:bg-emerald-950/30 dark:border-emerald-700/40" },
                            unregistered: { label: t("history_unregistered"), cls: "text-sky-600 border-sky-300/70 bg-sky-50 dark:bg-sky-950/30 dark:border-sky-700/40" },
                            reserved:     { label: t("history_reserved"),     cls: "text-amber-600 border-amber-300/70 bg-amber-50 dark:bg-amber-950/30 dark:border-amber-700/40" },
                            error:        { label: t("history_error"),        cls: "text-rose-600 border-rose-300/70 bg-rose-50 dark:bg-rose-950/30 dark:border-rose-700/40" },
                            unknown:      { label: t("history_unknown"),      cls: "text-muted-foreground border-border bg-muted/50" },
                          };
                          const cfg = statusCfg[rs] ?? statusCfg.unknown;
                          return (
                            <DrawerClose asChild key={`${item.query}-${item.timestamp}`}>
                              <Link
                                href={item.query ? toSearchURI(item.query) : "/"}
                                className="group flex items-center gap-2.5 px-3 py-2.5 rounded-lg hover:bg-muted/50 active:bg-muted transition-colors touch-manipulation"
                              >
                                <div className="w-7 h-7 rounded-md grid place-items-center border border-border bg-muted/20 shrink-0">
                                  <HistoryTypeIcon type={item.queryType} />
                                </div>
                                <span className="text-sm font-medium truncate flex-1 min-w-0 uppercase">{item.query}</span>
                                {item.queryType === "domain" ? (
                                  <span className={`shrink-0 text-[10px] font-semibold px-1.5 py-0.5 rounded-md border ${cfg.cls}`}>
                                    {cfg.label}
                                  </span>
                                ) : (
                                  <Badge variant="outline" className="text-[8px] px-1.5 py-0 uppercase tracking-wider shrink-0">
                                    {item.queryType}
                                  </Badge>
                                )}
                                <span className="text-[11px] text-muted-foreground tabular-nums shrink-0">
                                  {format(item.timestamp, "h:mm a")}
                                </span>
                                <button
                                  className="opacity-0 group-hover:opacity-100 [@media(hover:none)]:opacity-50 transition-opacity p-1.5 -mr-0.5 rounded-lg hover:bg-destructive/10 active:bg-destructive/20 shrink-0 touch-manipulation"
                                  onClick={(e) => handleHistDelete(e, item.query)}
                                >
                                  <RiDeleteBinLine className="w-3.5 h-3.5 text-muted-foreground group-hover:text-destructive [@media(hover:none)]:text-muted-foreground/70" />
                                </button>
                              </Link>
                            </DrawerClose>
                          );
                        })}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <RiHistoryLine className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">{t("no_history_title")}</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">{t("no_history_description")}</p>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </DrawerContent>
    </Drawer>
  );
}

function UserButton() {
  const { data: session, status } = useSession();
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const [open, setOpen] = React.useState(false);
  const [dropdownStyle, setDropdownStyle] = React.useState<React.CSSProperties>({});
  const buttonRef = React.useRef<HTMLButtonElement>(null);
  const email = (session?.user as any)?.email as string | undefined;
  const isAdminUser = !!email && email.toLowerCase().trim() === ADMIN_EMAIL;

  const loginDisabled  = settings.disable_login   === "1";
  const queryOnlyMode  = settings.query_only_mode  === "1";

  // Close on outside tap/click (works on both desktop and mobile)
  React.useEffect(() => {
    if (!open) return;
    function handleOutside(e: MouseEvent | TouchEvent) {
      if (buttonRef.current && buttonRef.current.contains(e.target as Node)) return;
      setOpen(false);
    }
    document.addEventListener("mousedown", handleOutside);
    document.addEventListener("touchstart", handleOutside, { passive: true });
    return () => {
      document.removeEventListener("mousedown", handleOutside);
      document.removeEventListener("touchstart", handleOutside);
    };
  }, [open]);

  const handleToggle = React.useCallback(() => {
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect();
      // Position dropdown using fixed coords so it escapes the overflow:hidden navbar wrapper
      setDropdownStyle({
        position: "fixed",
        top: rect.bottom + 8,
        right: Math.max(8, window.innerWidth - rect.right),
        zIndex: 9999,
        width: 192,
      });
    }
    setOpen(v => !v);
  }, []);


  if (status === "loading") return null;

  // Hide login button when login is disabled or in query-only mode (unless admin)
  if (status === "unauthenticated") {
    if (loginDisabled || queryOnlyMode) return null;
    return (
      <motion.div {...TAP} style={{ display: "inline-flex" }}>
        <Link
          href="/login"
          className="p-2 inline-flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors touch-manipulation"
          aria-label={t("nav_login")}
        >
          <RiUserLine className="h-[1rem] w-[1rem]" />
        </Link>
      </motion.div>
    );
  }

  // In query-only mode, hide the avatar/dashboard for non-admin logged-in users too
  if (queryOnlyMode && !isAdminUser) return null;

  const name = session?.user?.name || email || "U";
  const initials = name.slice(0, 1).toUpperCase();

  return (
    <div className="relative inline-flex">
      <motion.button
        {...TAP}
        ref={buttonRef}
        onClick={handleToggle}
        className={cn(
          "w-6 h-6 rounded-full text-[10px] font-bold flex items-center justify-center touch-manipulation",
          isAdminUser
            ? "bg-gradient-to-br from-violet-500 to-indigo-600 text-white"
            : "bg-primary text-primary-foreground"
        )}
        aria-label={t("nav_dashboard")}
      >
        {initials}
      </motion.button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, scale: 0.92, y: -4 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.92, y: -4 }}
            transition={{ duration: 0.14 }}
            style={dropdownStyle}
            className="bg-background border border-border rounded-xl shadow-lg overflow-hidden"
          >
            <div className="px-3 py-2 border-b border-border/50">
              <p className="text-[10px] text-muted-foreground truncate">{email}</p>
              {isAdminUser && (
                <p className="text-[9px] font-bold text-violet-600 dark:text-violet-400 mt-0.5 uppercase tracking-wider">{t("founder")} · {t("nav_admin")}</p>
              )}
            </div>
            <Link
              href="/dashboard"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2 text-xs hover:bg-muted active:bg-muted/70 transition-colors touch-manipulation"
            >
              <RiDashboardLine className="w-3.5 h-3.5 text-muted-foreground" />{t("nav_dashboard")}
            </Link>
            {isAdminUser && (
              <Link
                href="/admin"
                onClick={() => setOpen(false)}
                className="flex items-center gap-2 px-3 py-2 text-xs hover:bg-violet-50 dark:hover:bg-violet-950/30 transition-colors text-violet-600 dark:text-violet-400 touch-manipulation"
              >
                <RiShieldUserLine className="w-3.5 h-3.5" />{t("nav_admin")}
              </Link>
            )}
            <button
              onClick={() => { setOpen(false); signOut({ callbackUrl: "/" }); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-muted active:bg-muted/70 transition-colors text-red-500 touch-manipulation"
            >
              <RiLogoutBoxLine className="w-3.5 h-3.5" />{t("sign_out")}
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function Navbar() {
  const router = useRouter();
  // Pass pathname so the hook resets to visible on every page navigation.
  const isVisible = useScrollDirection(router.pathname);
  const settings = useSiteSettings();
  const logoText = settings.site_logo_text || "X.RW";
  const { t } = useTranslation();

  // Publish current nav height as a CSS variable so the layout (paddingTop on
  // <main>) can smoothly shrink/grow without requiring prop drilling or context.
  const NAV_H = "calc(1rem + 2.5rem)"; // mt-4 + h-10
  React.useEffect(() => {
    document.documentElement.style.setProperty("--nav-h", isVisible ? NAV_H : "0px");
  }, [isVisible]);

  return (
    <div
      className="fixed left-0 right-0 z-50 flex justify-center overflow-hidden"
      style={{
        // overflow:hidden clips the nav as it slides up so no ghost background
        // remains visible in the wrapper's area when the nav is off-screen.
        top: "var(--ann-h, 0px)",
        // margin-top (mt-4=1rem) + nav height (h-10=2.5rem) + 8px bottom
        // clearance so shadow-sm and the border are not clipped.
        height: "calc(1rem + 2.5rem + 8px)",
        transition: "top 0.22s cubic-bezier(0.25,0.46,0.45,0.94)",
        pointerEvents: isVisible ? "auto" : "none",
      }}
    >
      <motion.nav
        animate={{
          y: isVisible ? 0 : -56,
          opacity: isVisible ? 1 : 0,
          scale: isVisible ? 1 : 0.97,
        }}
        transition={{
          y:       { duration: 0.28, ease: [0.22, 1, 0.36, 1] },
          opacity: { duration: 0.22, ease: [0.22, 1, 0.36, 1] },
          scale:   { duration: 0.28, ease: [0.22, 1, 0.36, 1] },
        }}
        style={{ pointerEvents: isVisible ? "auto" : "none" }}
        className={cn(
          "mt-4 px-2 h-10 rounded-full",
          "bg-background shadow-sm",
          "flex items-center gap-6",
          "border border-primary/25 border-dashed",
        )}
      >
        <motion.div {...TAP}>
          <Link
            href="/"
            className="text-xs ml-2 font-medium tracking-wide hover:text-primary/80 transition-colors flex items-center touch-manipulation select-none"
          >
            <span suppressHydrationWarning>{logoText}</span>
            <p className="text-xs text-muted-foreground ml-1.5" suppressHydrationWarning>{VERSION}</p>
          </Link>
        </motion.div>

        <div className="h-4 w-[1px] bg-primary/10" />

        <div className="flex items-center gap-3">
          <ThemeToggle />
          <LanguageSwitcher />
          <motion.div {...TAP} className="hidden sm:inline-flex">
            <Link
              href="/directory"
              className="p-2 pr-0 inline-flex items-center justify-center touch-manipulation"
              aria-label={t("nav_directory")}
            >
              <RiCompassLine className="h-[1rem] w-[1rem]" />
            </Link>
          </motion.div>
          <UserButton />
          <div className="hidden sm:block">
            <HistoryDrawer />
          </div>
          <NavDrawer />
        </div>
      </motion.nav>
    </div>
  );
}
