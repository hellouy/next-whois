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
  RiLinksLine, RiAddBoxLine, RiTimeLine, RiHistoryLine, RiImageLine,
  RiMenuLine, RiCloseLine,
  RiBankCardLine, RiBankCardFill,
  RiMailSendLine,
  RiFireLine,
  RiPaletteLine,
  RiGlobalLine,
  RiDownloadLine,
  RiCodeBoxLine,
  RiBillLine,
  RiWifiLine,
  RiNotification3Line,
  RiNetworkLine,
  RiAlertLine,
  RiBarChartLine,
  RiPriceTag3Line,
  RiMailLine,
  RiArrowRightLine,
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
    titleKey: "admin.nav_group_ops",
    items: [
      { href: "/admin",                     labelKey: "admin.nav_overview",       icon: RiDashboardLine,   activeIcon: RiDashboardFill,   exact: true },
      { href: "/admin/users",               labelKey: "admin.nav_users",          icon: RiUserLine,        activeIcon: RiUserFill },
      { href: "/admin/stamps",              labelKey: "admin.nav_stamps",         icon: RiShieldCheckLine, activeIcon: RiShieldCheckFill },
      { href: "/admin/access-control",      labelKey: "admin.nav_access_control", icon: RiShieldUserLine, activeIcon: RiShieldUserLine },
      { href: "/admin/search-records",      labelKey: "admin.nav_search_records", icon: RiSearchLine,     activeIcon: RiSearchFill },
      { href: "/admin/query-logs",          labelKey: "admin.nav_query_logs",     icon: RiHistoryLine,     activeIcon: RiHistoryLine },
      { href: "/admin/feedback",            labelKey: "admin.nav_feedback",       icon: RiFeedbackLine,   activeIcon: RiFeedbackFill },
      { href: "/admin/reminders",           labelKey: "admin.nav_reminders",      icon: RiBellLine,        activeIcon: RiBellFill },
      { href: "/admin/expired-domains",     labelKey: "admin.nav_expired_domains", icon: RiGlobalLine,   activeIcon: RiGlobalLine },
    ],
  },
  {
    titleKey: "admin.nav_payment",
    items: [
      { href: "/admin/payment/settings",    labelKey: "admin.nav_payment_settings", icon: RiBankCardLine, activeIcon: RiBankCardFill },
      { href: "/admin/payment/plans",       labelKey: "admin.nav_plans",            icon: RiPriceTag3Line, activeIcon: RiPriceTag3Line },
      { href: "/admin/payment/orders",      labelKey: "admin.nav_orders",           icon: RiBillLine,      activeIcon: RiBillLine },
      { href: "/admin/sponsors",            labelKey: "admin.nav_sponsors",         icon: RiHeart3Line,    activeIcon: RiHeart3Fill },
    ],
  },
  {
    titleKey: "admin.nav_config",
    items: [
      { href: "/admin/tlds-hub",      labelKey: "admin.nav_tld_hub",       icon: RiCodeBoxLine,  activeIcon: RiCodeBoxLine },
      { href: "/admin/domain-access", labelKey: "admin.nav_domain_access", icon: RiNetworkLine,  activeIcon: RiNetworkLine },
      { href: "/admin/access-control?tab=providers", labelKey: "admin.nav_api", icon: RiPlugLine, activeIcon: RiPlugFill },
    ],
  },
  {
    titleKey: "admin.nav_brand",
    items: [
      { href: "/admin/settings",      labelKey: "admin.nav_settings",      icon: RiSettings4Line, activeIcon: RiSettings4Fill },
      { href: "/admin/stamp-styles",  labelKey: "admin.nav_stamp_styles",  icon: RiPaletteLine,  activeIcon: RiPaletteLine },
      { href: "/admin/og-styles",     labelKey: "admin.nav_og_styles",     icon: RiImageLine,    activeIcon: RiImageLine },
      { href: "/admin/hot-prefixes",  labelKey: "admin.nav_hot_prefixes",  icon: RiFireLine,     activeIcon: RiFireLine },
      { href: "/admin/links",         labelKey: "admin.nav_links",         icon: RiLinksLine,    activeIcon: RiLinksLine },
      { href: "/admin/links/applications", labelKey: "admin.nav_link_applications", icon: RiAddBoxLine, activeIcon: RiAddBoxLine },
      { href: "/admin/changelog",     labelKey: "admin.nav_changelog",     icon: RiHistoryLine,  activeIcon: RiHistoryLine },
    ],
  },
  {
    titleKey: "admin.nav_group_notify",
    items: [
      { href: "/admin/notify-service", labelKey: "admin.nav_notify_service", icon: RiNotification3Line, activeIcon: RiNotification3Line },
      { href: "/admin/notify",         labelKey: "admin.nav_notify",         icon: RiMailSendLine,      activeIcon: RiMailSendLine },
      { href: "/admin/email-settings", labelKey: "admin.nav_email_settings", icon: RiMailLine,         activeIcon: RiMailLine },
    ],
  },
  {
    titleKey: "admin.nav_system",
    items: [
      { href: "/admin/system",      labelKey: "admin.nav_system_label",  icon: RiServerLine,    activeIcon: RiServerFill },
      { href: "/admin/tld-speed",   labelKey: "admin.nav_tld_speed",     icon: RiTimeLine,      activeIcon: RiTimeLine },
      { href: "/admin/server-test", labelKey: "admin.nav_server_test",   icon: RiWifiLine,      activeIcon: RiWifiLine },
      { href: "/admin/db-export",   labelKey: "admin.nav_db_export",     icon: RiDownloadLine,  activeIcon: RiDownloadLine },
    ],
  },
];

const NAV_FLAT: NavItem[] = NAV_GROUPS.flatMap(g => g.items);

type SearchEntry = { label: string; keywords: string; href: string };

const SEARCH_EXTRAS: SearchEntry[] = [
  { label: "站点设置 — 外观与首页", keywords: "settings branding name logo seo meta title", href: "/admin/settings?tab=branding" },
  { label: "站点设置 — 广告管理",    keywords: "settings ads slots banner megaphone ad", href: "/admin/settings?tab=ads" },
  { label: "站点设置 — 安全防护",    keywords: "settings access security shield captcha ip", href: "/admin/settings?tab=access" },
  { label: "站点设置 — 功能开关",    keywords: "settings features toggles switch", href: "/admin/settings?tab=features" },
  { label: "站点设置 — 统计分析",    keywords: "settings analytics stats chart", href: "/admin/settings?tab=analytics" },
  { label: "支付配置 — Stripe / PayPal / 虎皮椒 / 微信 / 支付宝", keywords: "payment stripe paypal xunhupay wechat alipay currency", href: "/admin/payment/settings" },
  { label: "邮件配置 — SMTP / Resend / 测试邮件", keywords: "email smtp resend mail test", href: "/admin/email-settings" },
  { label: "TLD 失败列表",   keywords: "tld failures errors", href: "/admin/tlds-hub?tab=failures" },
  { label: "WHOIS 服务器覆盖", keywords: "whois server override", href: "/admin/tlds-hub?tab=whois" },
];

function AdminSearchModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const { t } = useTranslation();
  const [q, setQ] = React.useState("");
  const [sel, setSel] = React.useState(0);
  const [entries, setEntries] = React.useState<SearchEntry[]>([]);
  const inputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  React.useEffect(() => {
    if (!open) return;
    const nav = NAV_GROUPS.flatMap(g => g.items).map(n => ({
      label: t(n.labelKey as any),
      keywords: "",
      href: n.href,
    }));
    setEntries([...nav, ...SEARCH_EXTRAS]);
  }, [open, t]);

  if (!open) return null;
  const ql = q.trim().toLowerCase();
  const items = ql
    ? entries.filter(e => `${e.label} ${e.keywords}`.toLowerCase().includes(ql))
    : entries;
  const flat = items.slice(0, 12);

  function go(href: string) {
    onClose();
    router.push(href, undefined, { locale: false });
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center px-4 pt-[12vh]"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="fixed inset-0 bg-black/40 backdrop-blur-sm" aria-hidden />
      <div className="relative w-full max-w-lg bg-background border border-border rounded-2xl shadow-2xl overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border/60">
          <RiSearchLine className="w-4 h-4 text-muted-foreground" />
          <input
            ref={inputRef}
            value={q}
            onChange={e => { setQ(e.target.value); setSel(0); }}
            onKeyDown={e => {
              if (e.key === "ArrowDown") { e.preventDefault(); setSel(s => Math.min(s + 1, flat.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setSel(s => Math.max(s - 1, 0)); }
              else if (e.key === "Enter" && flat[sel]) go(flat[sel].href);
              else if (e.key === "Escape") onClose();
            }}
            placeholder="搜索后台页面 / 设置项…"
            className="flex-1 bg-transparent outline-none text-sm placeholder:text-muted-foreground/60"
          />
          <kbd className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground shrink-0">ESC</kbd>
        </div>
        <div className="max-h-72 overflow-y-auto p-1.5">
          {flat.length === 0 ? (
            <p className="text-xs text-muted-foreground text-center py-6">无匹配结果</p>
          ) : flat.map((it, i) => (
            <button
              key={it.href + it.label}
              onClick={() => go(it.href)}
              onMouseEnter={() => setSel(i)}
              className={cn("w-full flex items-center gap-2.5 rounded-xl px-3 py-2 text-left text-sm transition-colors",
                i === sel ? "bg-primary/10 text-primary" : "text-foreground hover:bg-muted")}
            >
              <RiArrowRightLine className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
              <span className="min-w-0 truncate font-medium">{it.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

const BOTTOM_PINNED: NavItem[] = [
  { href: "/admin",               labelKey: "admin.nav_overview",       icon: RiDashboardLine,  activeIcon: RiDashboardFill,  exact: true },
  { href: "/admin/users",         labelKey: "admin.nav_users",          icon: RiUserLine,       activeIcon: RiUserFill },
  { href: "/admin/query-logs",    labelKey: "admin.nav_query_logs",     icon: RiHistoryLine,    activeIcon: RiHistoryLine },
  { href: "/admin/tlds-hub",     labelKey: "admin.nav_tld_rules",      icon: RiCodeBoxLine,    activeIcon: RiCodeBoxLine },
];

export function AdminLayout({ children, title }: { children: React.ReactNode; title?: string }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const { t } = useTranslation();
  const email = (session?.user as any)?.email as string | undefined;
  const isAdmin = (session?.user as any)?.isAdmin === true;
  const [drawerOpen, setDrawerOpen] = React.useState(false);
  const [searchOpen, setSearchOpen] = React.useState(false);

  React.useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearchOpen(o => !o);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

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
    const [path, query] = href.split("?");
    const pathMatch = exact ? p === path : (p === path || p.startsWith(path + "/"));
    if (!pathMatch) return false;
    if (!query) return true;
    const params = new URLSearchParams(query);
    for (const [k, v] of params) {
      if (String(router.query[k] ?? "") !== v) return false;
    }
    return true;
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

          <button
            onClick={() => setSearchOpen(true)}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-muted-foreground hover:text-foreground hover:bg-muted border border-border/60 mb-2 transition-all"
          >
            <RiSearchLine className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">搜索后台页面…</span>
            <kbd className="ml-auto text-[9px] px-1.5 py-0.5 rounded border border-border shrink-0">Ctrl K</kbd>
          </button>

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
        <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-md border-b border-border px-3 h-14 flex items-center gap-2 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center shrink-0">
            <RiShieldUserLine className="w-3.5 h-3.5 text-white" />
          </div>
          <p className="flex-1 min-w-0 text-sm font-bold truncate">{currentLabel}</p>
          <button
            onClick={() => navigate("/")}
            aria-label={t("admin.frontend")}
            className="flex size-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <RiArrowLeftLine className="w-4 h-4" />
          </button>
          <button
            onClick={() => setSearchOpen(true)}
            aria-label="搜索"
            className="flex size-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <RiSearchLine className="w-4 h-4" />
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
                    "min-w-0 flex-1 flex flex-col items-center justify-center gap-1 px-0.5 transition-colors",
                    active ? "text-primary" : "text-muted-foreground"
                  )}
                >
                  {active ? <ActiveIcon className="w-5 h-5" /> : <Icon className="w-5 h-5" />}
                  <span className={cn("max-w-full truncate text-[10px] font-semibold leading-none", active ? "text-primary" : "text-muted-foreground/70")}>
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

        {/* Drawer panel — bottom sheet style, full width */}
        <div className={cn(
          "fixed left-0 right-0 bottom-0 z-50 bg-background border-t border-border flex flex-col shadow-2xl transition-transform duration-300 ease-out rounded-t-2xl",
          "max-h-[85vh]",
          drawerOpen ? "translate-y-0" : "translate-y-full"
        )}>
          {/* Handle bar */}
          <div className="flex justify-center pt-3 pb-1 shrink-0">
            <div className="w-10 h-1 rounded-full bg-border" />
          </div>

          {/* Drawer header */}
          <div className="flex items-center gap-3 px-5 py-3 border-b border-border/60 shrink-0">
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

          {/* Drawer nav — compact grid cards, scrollable */}
          <div className="flex-1 overflow-y-auto py-3 px-4 space-y-4">
            {NAV_GROUPS.map(group => (
              <div key={group.titleKey}>
                <p className="text-[10px] font-bold text-muted-foreground/50 uppercase tracking-widest mb-2 px-0.5">
                  {t(group.titleKey as any)}
                </p>
                <div className="grid grid-cols-4 gap-1.5">
                  {group.items.map(({ href, labelKey, icon: Icon, activeIcon: ActiveIcon, exact }) => {
                    const active = isActive(href, exact);
                    return (
                      <button
                        key={href}
                        onClick={() => navigate(href)}
                        className={cn(
                          "flex flex-col items-center justify-center gap-1.5 rounded-xl p-2.5 transition-all active:scale-95",
                          active
                            ? "bg-primary/10 text-primary border border-primary/25"
                            : "bg-muted/40 text-muted-foreground hover:bg-muted hover:text-foreground border border-transparent"
                        )}
                      >
                        {active
                          ? <ActiveIcon className="w-5 h-5 shrink-0" />
                          : <Icon className="w-5 h-5 shrink-0" />}
                        <span className="text-[10px] font-semibold leading-tight text-center line-clamp-2">
                          {t(labelKey as any)}
                        </span>
                        {active && <span className="w-1 h-1 rounded-full bg-primary shrink-0" />}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}

            {/* Back to site */}
            <button
              onClick={() => { setDrawerOpen(false); navigate("/"); }}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm text-muted-foreground hover:text-foreground hover:bg-muted transition-all border border-border/50 mt-1"
            >
              <RiArrowLeftLine className="w-4 h-4 shrink-0" />
              {t("admin.back_to_site")}
            </button>
          </div>

          {/* Safe area bottom */}
          <div className="h-safe-bottom shrink-0" />
        </div>
      </div>

      <AdminSearchModal open={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  );
}
