import React from "react";
import Head from "next/head";
import Link from "next/link";
import {
  RiArrowLeftSLine,
  RiToolsLine,
  RiServerLine,
  RiMapPinLine,
  RiLockLine,
  RiFileList2Line,
  RiWifiLine,
  RiArrowRightLine,
  RiCompassLine,
  RiShieldCheckLine,
  RiCalendarLine,
} from "@remixicon/react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { motion } from "framer-motion";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import { cn } from "@/lib/utils";

interface BuiltinTool {
  href: string;
  icon: React.ReactNode;
  labelKey: TranslationKey;
  descKey: TranslationKey;
  colorClass: string;
  bgClass: string;
  settingKey?: string;
}

const BUILTIN_TOOLS: BuiltinTool[] = [
  {
    href: "/dns",
    icon: <RiServerLine className="w-6 h-6" />,
    labelKey: "nav_dns",
    descKey: "nav_dns_desc",
    colorClass: "text-violet-600 dark:text-violet-400",
    bgClass: "bg-violet-500/10 dark:bg-violet-500/15",
    settingKey: "enable_dns",
  },
  {
    href: "/ip",
    icon: <RiMapPinLine className="w-6 h-6" />,
    labelKey: "nav_ip",
    descKey: "nav_ip_desc",
    colorClass: "text-blue-600 dark:text-blue-400",
    bgClass: "bg-blue-500/10 dark:bg-blue-500/15",
    settingKey: "enable_ip",
  },
  {
    href: "/ssl",
    icon: <RiLockLine className="w-6 h-6" />,
    labelKey: "nav_ssl",
    descKey: "nav_ssl_desc",
    colorClass: "text-emerald-600 dark:text-emerald-400",
    bgClass: "bg-emerald-500/10 dark:bg-emerald-500/15",
    settingKey: "enable_ssl",
  },
  {
    href: "/icp",
    icon: <RiFileList2Line className="w-6 h-6" />,
    labelKey: "nav_icp",
    descKey: "nav_icp_desc",
    colorClass: "text-amber-600 dark:text-amber-400",
    bgClass: "bg-amber-500/10 dark:bg-amber-500/15",
  },
  {
    href: "/http",
    icon: <RiWifiLine className="w-6 h-6" />,
    labelKey: "http.page_title",
    descKey: "http.page_subtitle",
    colorClass: "text-sky-600 dark:text-sky-400",
    bgClass: "bg-sky-500/10 dark:bg-sky-500/15",
  },
  {
    href: "/stamp",
    icon: <RiShieldCheckLine className="w-6 h-6" />,
    labelKey: "stamp.title",
    descKey: "stamp.subtitle",
    colorClass: "text-violet-600 dark:text-violet-400",
    bgClass: "bg-violet-500/10 dark:bg-violet-500/15",
    settingKey: "enable_stamps",
  },
  {
    href: "/remind",
    icon: <RiCalendarLine className="w-6 h-6" />,
    labelKey: "remind.page_title_main",
    descKey: "remind.page_desc_main",
    colorClass: "text-rose-600 dark:text-rose-400",
    bgClass: "bg-rose-500/10 dark:bg-rose-500/15",
    settingKey: "enable_remind",
  },
];

export default function ToolsPage() {
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteLabel = settings.site_logo_text || "WHOIS";

  const visibleTools = BUILTIN_TOOLS.filter(
    (tool) =>
      !tool.settingKey ||
      !!(settings as unknown as Record<string, string>)[tool.settingKey]
  );

  return (
    <>
      <Head>
        <title key="title">{`${t("nav_tools")} — ${siteLabel}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-6">

          <div className="flex items-center gap-3 mb-7">
            <Link
              href="/"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-primary/10 text-primary">
                <RiToolsLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("nav_tools")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("tools_builtin_subtitle")}</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3">
            {visibleTools.map((tool) => (
              <Link key={tool.href} href={tool.href}>
                <motion.div
                  whileTap={{ scale: 0.97 }}
                  className={cn(
                    "group flex items-center gap-4 p-4 rounded-2xl border transition-all duration-150 cursor-pointer",
                    "border-border bg-card hover:bg-muted/30 hover:border-primary/30 hover:shadow-sm"
                  )}
                >
                  <div className={cn("p-3 rounded-xl shrink-0", tool.bgClass, tool.colorClass)}>
                    {tool.icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">
                      {t(tool.labelKey)}
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5 leading-snug">
                      {t(tool.descKey)}
                    </p>
                  </div>
                  <RiArrowRightLine className="w-4 h-4 text-muted-foreground/30 group-hover:text-primary/50 shrink-0 transition-colors" />
                </motion.div>
              </Link>
            ))}
          </div>

          <div className="mt-6">
            <Link href="/directory">
              <motion.div
                whileTap={{ scale: 0.97 }}
                className="group flex items-center gap-4 p-4 rounded-2xl border border-dashed border-border/50 bg-muted/5 hover:bg-muted/20 hover:border-primary/20 transition-all duration-150 cursor-pointer"
              >
                <div className="p-3 rounded-xl shrink-0 bg-muted/30 text-muted-foreground group-hover:text-primary transition-colors">
                  <RiCompassLine className="w-6 h-6" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-muted-foreground group-hover:text-foreground transition-colors">
                    {t("nav_directory")}
                  </p>
                  <p className="text-xs text-muted-foreground/60 mt-0.5 leading-snug">
                    {t("nav_directory_desc")}
                  </p>
                </div>
                <RiArrowRightLine className="w-4 h-4 text-muted-foreground/20 group-hover:text-primary/40 shrink-0 transition-colors" />
              </motion.div>
            </Link>
          </div>

        </main>
      </ScrollArea>
    </>
  );
}
