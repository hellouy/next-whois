import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { cn } from "@/lib/utils";
import { useTranslation } from "@/lib/i18n";
import {
  RiDashboardLine, RiDashboardFill,
  RiSettings4Line, RiSettings4Fill,
  RiUserLine, RiUserFill,
  RiShieldCheckLine, RiShieldCheckFill,
  RiBellLine, RiBellFill,
  RiArrowLeftLine, RiLoader4Line,
  RiShieldUserLine, RiFeedbackLine, RiFeedbackFill,
  RiServerLine, RiServerFill,
  RiPlugLine, RiPlugFill,
  RiSearchLine, RiSearchFill,
  RiHeart3Line, RiHeart3Fill,
  RiLinksLine, RiTimeLine, RiHistoryLine, RiImageLine,
  RiMenuLine, RiCloseLine,
  RiBankCardLine, RiBankCardFill,
  RiMailSendLine,
  RiFireLine,
  RiPaletteLine, RiGithubLine,
  RiGlobalLine,
  RiDownloadLine,
  RiCodeBoxLine,
  RiBillLine,
  RiWifiLine,
  RiNotification3Line,
  RiNetworkLine,
  RiAlertLine,
} from "@remixicon/react";

type NavItem = {
  href: string;
  labelKey: string;
  icon: React.ElementType;
  activeIcon: React.ElementType;
  exact?: boolean;
};

const NAV_GROUPS: { titleKey: string; items: NavItem[] }[] = [
  {
    titleKey: "admin.nav_core",
    items: [
      { href: "/admin",                  labelKey: "admin.nav_overview",  icon: RiDashboardLine,  activeIcon: RiDashboardFill,  exact: true },
      { href: "/admin/users",            labelKey: "admin.nav_users",     icon: RiUserLine,       activeIcon: RiUserFill },
      { href: "/admin/stamps",           labelKey: "admin.nav_stamps",    icon: RiShieldCheckLine,activeIcon: RiShieldCheckFill },
      { href: "/admin/payment/plans",    labelKey: "admin.nav_plans",     icon: RiBankCardLine,   activeIcon: RiBankCardFill },
      { href: "/admin/payment/orders",   labelKey: "admin.nav_orders",    icon: RiBillLine,       activeIcon: RiBillLine },
    ],
  },
  {
    titleKey: "admin.nav_content",
    items: [
      { href: "/admin/search-records", labelKey: "admin.nav_search_records", icon: RiSearchLine,   activeIcon: RiSearchFill },
      { href: "/admin/feedback",       labelKey: "admin.nav_feedback",       icon: RiFeedbackLine, activeIcon: RiFeedbackFill },
      { href: "/admin/reminders",      labelKey: "admin.nav_reminders",      icon: RiBellLine,     activeIcon: RiBellFill },
      { href: "/admin/notify",          labelKey: "admin.nav_notify",          icon: RiMailSendLine,      activeIcon: RiMailSendLine },
      { href: "/admin/notify-service", labelKey: "admin.nav_notify_service", icon: RiNotification3Line, activeIcon: RiNotification3Line },
    ],
  },
  {
    titleKey: "admin.nav_config",
    items: [
      { href: "/admin/domain-access",  labelKey: "admin.nav_domain_access",  icon: RiNetworkLine,    activeIcon: RiNetworkLine },
      { href: "/admin/domains",        labelKey: "admin.nav_domains",        icon: RiGlobalLine,     activeIcon: RiGlobalLine },
      { href: "/admin/tld-failures",   labelKey: "admin.nav_tld_failures",   icon: RiAlertLine,      activeIcon: RiAlertLine },
      { href: "/admin/tld-rules",      labelKey: "admin.nav_tld_rules",      icon: RiCodeBoxLine,    activeIcon: RiCodeBoxLine },
      { href: "/admin/api",            labelKey: "admin.nav_api",            icon: RiPlugLine,       activeIcon: RiPlugFill },
      { href: "/admin/access-control", labelKey: "admin.nav_access_control", icon: RiShieldUserLine, activeIcon: RiShieldUserLine },
    ],
  },
  {
    titleKey: "admin.nav_brand",
    items: [
      { href: "/admin/stamp-styles",   labelKey: "admin.nav_stamp_styles",   icon: RiPaletteLine,  activeIcon: RiPaletteLine },
      { href: "/admin/og-styles",      labelKey: "admin.nav_og_styles",      icon: RiImageLine,    activeIcon: RiImageLine },
      { href: "/admin/hot-prefixes",   labelKey: "admin.nav_hot_prefixes",   icon: RiFireLine,     activeIcon: RiFireLine },
      { href: "/admin/links",          labelKey: "admin.nav_links",          icon: RiLinksLine,    activeIcon: RiLinksLine },
      { href: "/admin/sponsors",       labelKey: "admin.nav_sponsors",       icon: RiHeart3Line,   activeIcon: RiHeart3Fill },
      { href: "/admin/changelog",      labelKey: "admin.nav_changelog",      icon: RiHistoryLine,  activeIcon: RiHistoryLine },
    ],
  },
  {
    titleKey: "admin.nav_system",
    items: [
      { href: "/admin/system",      labelKey: "admin.nav_system_label",  icon: RiServerLine,    activeIcon: RiServerFill },
      { href: "/admin/tld-speed",   labelKey: "admin.nav_tld_speed",     icon: RiTimeLine,      activeIcon: RiTimeLine },
      { href: "/admin/server-test", labelKey: "admin.nav_server_test",   icon: RiWifiLine,      activeIcon: RiWifiLine },
      { href: "/admin/db-export",   labelKey: "admin.nav_db_export",     icon: RiDownloadLine,  activeIcon: RiDownloadLine },
      { href: "/admin/settings",    labelKey: "admin.nav_settings",      icon: RiSettings4Line, activeIcon: RiSettings4Fill },
    ],
  },
];

const NAV_FLAT: NavItem[] = NAV_GROUPS.flatMap(g => g.items);

const BOTTOM_PINNED: NavItem[] = [
  { href: "/admin",                labelKey: "admin.nav_overview",        icon: RiDashboardLine,  activeIcon: RiDashboardFill, exact: true },
  { href: "/admin/search-records", labelKey: "admin.nav_search_records",  icon: RiSearchLine,     activeIcon: RiSearchFill },
  { href: "/admin/feedback",       labelKey: "admin.nav_feedback",        icon: RiFeedbackLine,   activeIcon: RiFeedbackFill },
  { href: "/admin/settings",       labelKey: "admin.nav_settings",        icon: RiSettings4Line,  activeIcon: RiSettings4Fill },
];

export function AdminLayout({ children, title }: { children: React.ReactNode; title?: string }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const { t } = useTranslation();
  const email = (session?.user as any)?.email as string | undefined;
  const isAdmin = (session?.user as any)?.isAdmin === true;
  const [drawerOpen, setDrawerOpen] = React.useState(false);

  React.useEffect(() => {
    if (drawerOpen) setDrawerOpen(false);
  }, [router.pathname]);

  React.useEffect(() => {
    if (drawerOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => { document.body.style.overflow = ""; };
  }, [drawerOpen]);

  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (status === "unauthenticated" || !isAdmin) {
    return (
      <>
        <Head><title>{t("admin.page_title_no_access")}</title></Head>
        <div className="min-h-screen flex items-center justify-center px-4">
          <div className="text-center space-y-4 max-w-sm">
            <div className="w-14 h-14 rounded-2xl bg-red-100 dark:bg-red-950/40 flex items-center justify-center mx-auto">
              <RiShieldUserLine className="w-7 h-7 text-red-500" />
            </div>
            <h1 className="text-xl font-bold">{t("admin.no_access_title")}</h1>
            <p className="text-sm text-muted-foreground">{t("admin.no_access_desc")}</p>
            <button
              onClick={() => router.push("/")}
              className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline font-semibold"
            >
              <RiArrowLeftLine className="w-4 h-4" />{t("admin.back_to_home")}
            </button>
          </div>
        </div>
      </>
    );
  }

  function isActive(href: string, exact?: boolean): boolean {
    const p = router.pathname;
    if (exact) return p === href;
    return p === href || p.startsWith(href + "/");
  }

  function navigate(href: string) {
    router.push(href, undefined, { locale: false });
  }

  const currentLabel = title || t((NAV_FLAT.find(n => isActive(n.href, n.exact))?.labelKey || "admin.panel_title") as any);

  return (
    <>
      <Head>
        <title key="site-title">{title ? `${title} · ${t("admin.panel_title")}` : t("admin.page_title")}</title>
      </Head>

      {/* ── Desktop layout ──────────────────────────────── */}
      <div className="hidden md:flex min-h-screen">
        <aside className="w-52 shrink-0 border-r border-border bg-background/80 backdrop-blur-sm flex flex-col py-6 px-3 gap-1 sticky top-0 h-screen overflow-y-auto">
          <div className="flex items-center gap-2.5 px-3 pb-5 mb-1 border-b border-border/60">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center shrink-0">
              <RiShieldUserLine className="w-4 h-4 text-white" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-bold leading-none">{t("admin.panel_title")}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{email}</p>
            </div>
          </div>

          {NAV_GROUPS.map(group => (
            <div key={group.titleKey} className="mb-2">
              <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-widest px-3 py-1.5">
                {t(group.titleKey as any)}
              </p>
              {group.items.map(({ href, labelKey, icon: Icon, activeIcon: ActiveIcon, exact }) => {
                const active = isActive(href, exact);
                return (
                  <button
                    key={href}
                    onClick={() => navigate(href)}
                    className={cn(
                      "w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-sm font-medium transition-all text-left",
                      active
                        ? "bg-primary/10 text-primary border border-primary/20"
                        : "text-muted-foreground hover:text-foreground hover:bg-muted"
                    )}
                  >
                    {active ? <ActiveIcon className="w-4 h-4 shrink-0" /> : <Icon className="w-4 h-4 shrink-0" />}
                    {t(labelKey as any)}
                  </button>
                );
              })}
            </div>
          ))}

          <div className="mt-auto pt-4 border-t border-border/60">
            <button
              onClick={() => navigate("/")}
              className="w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs text-muted-foreground hover:text-foreground hover:bg-muted transition-all"
            >
              <RiArrowLeftLine className="w-3.5 h-3.5" />{t("admin.back_to_site")}
            </button>
          </div>
        </aside>

        <main className="flex-1 min-w-0 overflow-y-auto">
          <div className="max-w-4xl mx-auto px-6 py-8">
            {children}
          </div>
        </main>
      </div>

      {/* ── Mobile layout ───────────────────────────────── */}
      <div className="md:hidden min-h-screen flex flex-col">
        {/* Top header */}
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-md border-b border-border px-4 h-14 flex items-center gap-3">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center shrink-0">
            <RiShieldUserLine className="w-3.5 h-3.5 text-white" />
          </div>
          <p className="flex-1 text-sm font-bold truncate">{currentLabel}</p>
          <button
            onClick={() => navigate("/")}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors px-2.5 py-1.5 rounded-lg hover:bg-muted"
          >
            <RiArrowLeftLine className="w-3.5 h-3.5" />
            <span>{t("admin.frontend")}</span>
          </button>
          <button
            onClick={() => setDrawerOpen(true)}
            className="flex items-center justify-center w-8 h-8 rounded-lg hover:bg-muted transition-colors"
            aria-label={t("admin.open_menu")}
          >
            <RiMenuLine className="w-5 h-5" />
          </button>
        </header>

        {/* Scrollable content */}
        <main className="flex-1 overflow-y-auto pb-20">
          <div className="px-4 py-5">
            {children}
          </div>
        </main>

        {/* Bottom bar — pinned items + more button */}
        <nav className="fixed bottom-0 inset-x-0 z-40 bg-background/95 backdrop-blur-md border-t border-border">
          <div className="flex items-stretch h-16">
            {BOTTOM_PINNED.map(({ href, labelKey, icon: Icon, activeIcon: ActiveIcon, exact }) => {
              const active = isActive(href, exact);
              return (
                <button
                  key={href}
                  onClick={() => navigate(href)}
                  className={cn(
                    "flex-1 flex flex-col items-center justify-center gap-1 transition-colors",
                    active ? "text-primary" : "text-muted-foreground"
                  )}
                >
                  {active ? <ActiveIcon className="w-5 h-5" /> : <Icon className="w-5 h-5" />}
                  <span className={cn("text-[10px] font-semibold leading-none", active ? "text-primary" : "text-muted-foreground/70")}>
                    {t(labelKey as any)}
                  </span>
                </button>
              );
            })}
            {/* More button */}
            <button
              onClick={() => setDrawerOpen(true)}
              className={cn(
                "flex-1 flex flex-col items-center justify-center gap-1 transition-colors",
                drawerOpen ? "text-primary" : "text-muted-foreground"
              )}
            >
              <RiMenuLine className="w-5 h-5" />
              <span className="text-[10px] font-semibold leading-none text-muted-foreground/70">{t("admin.more")}</span>
            </button>
          </div>
          {/* safe area inset */}
          <div className="h-safe-bottom" />
        </nav>

        {/* Drawer overlay */}
        {drawerOpen && (
          <div
            className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm"
            onClick={() => setDrawerOpen(false)}
          />
        )}

        {/* Drawer panel */}
        <div className={cn(
          "fixed top-0 right-0 bottom-0 z-50 w-72 bg-background border-l border-border flex flex-col shadow-2xl transition-transform duration-300 ease-out",
          drawerOpen ? "translate-x-0" : "translate-x-full"
        )}>
          {/* Drawer header */}
          <div className="flex items-center gap-3 px-5 h-14 border-b border-border shrink-0">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center shrink-0">
              <RiShieldUserLine className="w-3.5 h-3.5 text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-bold leading-none">{t("admin.panel_title")}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{email}</p>
            </div>
            <button
              onClick={() => setDrawerOpen(false)}
              className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-muted transition-colors"
            >
              <RiCloseLine className="w-4 h-4" />
            </button>
          </div>

          {/* Drawer nav — scrollable */}
          <div className="flex-1 overflow-y-auto py-4 px-3 space-y-4">
            {NAV_GROUPS.map(group => (
              <div key={group.titleKey}>
                <p className="text-[10px] font-semibold text-muted-foreground/50 uppercase tracking-widest px-3 mb-1.5">
                  {t(group.titleKey as any)}
                </p>
                <div className="space-y-0.5">
                  {group.items.map(({ href, labelKey, icon: Icon, activeIcon: ActiveIcon, exact }) => {
                    const active = isActive(href, exact);
                    return (
                      <button
                        key={href}
                        onClick={() => navigate(href)}
                        className={cn(
                          "w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all text-left",
                          active
                            ? "bg-primary/10 text-primary border border-primary/20"
                            : "text-muted-foreground hover:text-foreground hover:bg-muted"
                        )}
                      >
                        {active ? <ActiveIcon className="w-4 h-4 shrink-0" /> : <Icon className="w-4 h-4 shrink-0" />}
                        {t(labelKey as any)}
                        {active && (
                          <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary" />
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* Drawer footer */}
          <div className="shrink-0 px-3 py-4 border-t border-border/60">
            <button
              onClick={() => { setDrawerOpen(false); navigate("/"); }}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-all"
            >
              <RiArrowLeftLine className="w-4 h-4 shrink-0" />
              {t("admin.back_to_site")}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
