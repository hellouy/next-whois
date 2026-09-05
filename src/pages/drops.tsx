import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiCalendarLine,
  RiLoader4Line,
  RiArrowLeftLine,
  RiAddLine,
  RiCheckLine,
  RiLockLine,
  RiRefreshLine,
  RiGlobalLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import { format } from "date-fns";

interface DropDomain {
  domain: string;
  tld?: string;
  reminder_id?: string;
}

interface DropGroup {
  date: string;
  domains: DropDomain[];
}

interface DropsData {
  today: string;
  days: number;
  public_locked: boolean;
  drops: DropGroup[];
  user_drops: DropGroup[];
}

export default function DropsPage() {
  const { data: session, status } = useSession();
  const { t, locale } = useTranslation();
  const router = useRouter();
  const [data, setData] = React.useState<DropsData | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);
  const [subscribing, setSubscribing] = React.useState<Record<string, boolean>>({});
  const [monitoredSet, setMonitoredSet] = React.useState<Set<string>>(new Set());

  const load = React.useCallback(async () => {
    try {
      const res = await fetch("/api/drops?days=30");
      if (!res.ok) throw new Error("bad status");
      const d = await res.json();
      setData(d);
      setError(false);
      if (Array.isArray(d.user_drops)) {
        const set = new Set<string>();
        for (const g of d.user_drops) for (const dm of g.domains) set.add(dm.domain);
        setMonitoredSet(set);
      }
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (status !== "loading") load();
  }, [status, load]);

  const fmtDay = (iso: string): { label: string; weekday: string; isToday: boolean } => {
    const d = new Date(`${iso}T00:00:00Z`);
    if (isNaN(d.getTime())) return { label: iso, weekday: "", isToday: false };
    const isChinese = locale === "zh" || locale === "zh-tw";
    const label = isChinese
      ? format(d, "M月d日")
      : format(d, "MMM d");
    const weekday = isChinese ? format(d, "EEE") : format(d, "EEEE");
    const isToday = iso === data?.today;
    return { label, weekday, isToday };
  };

  const handleMonitor = async (domain: string) => {
    const email = (session?.user as any)?.email as string | undefined;
    if (!email) {
      router.push("/login");
      return;
    }
    if (subscribing[domain]) return;
    setSubscribing(prev => ({ ...prev, [domain]: true }));
    try {
      const res = await fetch("/api/remind/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, email }),
      });
      if (res.status === 409) {
        toast.info(t("drops.already_subscribed"));
        setMonitoredSet(prev => new Set(prev).add(domain));
      } else if (res.status === 403) {
        toast.error(t("drops.limit_exceeded"));
      } else if (res.ok) {
        toast.success(t("drops.subscribed_ok"));
        setMonitoredSet(prev => new Set(prev).add(domain));
      } else {
        toast.error(t("drops.failed"));
      }
    } catch {
      toast.error(t("drops.failed"));
    } finally {
      setSubscribing(prev => { const n = { ...prev }; delete n[domain]; return n; });
    }
  };

  const mergedGroups: DropGroup[] = React.useMemo(() => {
    if (!data) return [];
    const byDate = new Map<string, DropDomain[]>();
    for (const g of data.drops) {
      if (!byDate.has(g.date)) byDate.set(g.date, []);
      byDate.get(g.date)!.push(...g.domains.map(d => ({ domain: d.domain, tld: d.tld })));
    }
    for (const g of data.user_drops) {
      if (!byDate.has(g.date)) byDate.set(g.date, []);
      byDate.get(g.date)!.push(...g.domains.map(d => ({ domain: d.domain, reminder_id: d.reminder_id })));
    }
    return [...byDate.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, domains]) => {
        const seen = new Set<string>();
        const unique = domains.filter(d => {
          if (seen.has(d.domain)) return false;
          seen.add(d.domain);
          return true;
        });
        return { date, domains: unique };
      });
  }, [data]);

  const totalCount = mergedGroups.reduce((acc, g) => acc + g.domains.length, 0);

  return (
    <>
      <Head>
        <title>{t("drops.title")}</title>
      </Head>
      <div className="min-h-screen flex justify-center pt-8 pb-16 px-4">
        <div className="w-full max-w-2xl">
          <div className="flex items-center justify-between mb-4">
            <button
              type="button"
              onClick={() => router.push("/")}
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors touch-manipulation py-2"
            >
              <RiArrowLeftLine className="w-4 h-4" />
              {t("drops.back_home")}
            </button>
            <button
              type="button"
              onClick={() => { setLoading(true); setError(false); load(); }}
              className="inline-flex items-center gap-1.5 text-[11px] font-medium rounded-lg px-2.5 py-1.5 border border-border text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors touch-manipulation"
            >
              <RiRefreshLine className="w-3.5 h-3.5" />
              {t("drops.retry")}
            </button>
          </div>

          <div className="glass-panel border border-border rounded-xl overflow-hidden mb-4">
            <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2">
              <RiCalendarLine className="w-4 h-4 text-primary" />
              <div className="flex-1 min-w-0">
                <h1 className="text-sm font-bold leading-tight">{t("drops.title")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("drops.subtitle")}</p>
              </div>
              {totalCount > 0 && (
                <span className="text-[10px] text-muted-foreground bg-muted/60 rounded-full px-2 py-1 shrink-0">
                  {t("drops.domains_count", { count: totalCount })}
                </span>
              )}
            </div>
          </div>

          {loading ? (
            <div className="glass-panel border border-border rounded-xl px-4 py-16 text-center">
              <RiLoader4Line className="w-5 h-5 animate-spin mx-auto text-muted-foreground" />
            </div>
          ) : error ? (
            <div className="glass-panel border border-border rounded-xl px-4 py-16 text-center space-y-3">
              <RiCalendarLine className="w-7 h-7 mx-auto text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">{t("drops.load_failed")}</p>
              <button
                type="button"
                onClick={() => { setLoading(true); setError(false); load(); }}
                className="text-[11px] font-medium text-primary hover:underline touch-manipulation"
              >
                {t("drops.retry")}
              </button>
            </div>
          ) : data?.public_locked ? (
            <div className="glass-panel border border-border rounded-xl px-4 py-16 text-center space-y-3">
              <RiLockLine className="w-7 h-7 mx-auto text-muted-foreground/50" />
              <h2 className="text-sm font-bold">{t("drops.public_locked_title")}</h2>
              <p className="text-xs text-muted-foreground max-w-xs mx-auto">{t("drops.public_locked_desc")}</p>
              <Link
                href="/login"
                className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-white bg-primary rounded-lg px-3 py-1.5 hover:bg-primary/90 transition-colors"
              >
                {t("nav_login")}
              </Link>
            </div>
          ) : mergedGroups.length === 0 ? (
            <div className="glass-panel border border-border rounded-xl px-4 py-16 text-center space-y-2">
              <RiCalendarLine className="w-7 h-7 mx-auto text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">{t("drops.empty")}</p>
            </div>
          ) : (
            <div className="space-y-3">
              {!data?.user_drops?.length && (
                <p className="text-[10px] text-muted-foreground px-1">{t("drops.public_note")}</p>
              )}
              <AnimatePresence>
                {mergedGroups.map(group => {
                  const { label, weekday, isToday } = fmtDay(group.date);
                  return (
                    <motion.div
                      key={group.date}
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="glass-panel border border-border rounded-xl overflow-hidden"
                    >
                      <div className={cn(
                        "px-4 py-2.5 border-b border-border/50 flex items-center gap-2",
                        isToday ? "bg-primary/10" : "bg-muted/30",
                      )}>
                        <span className="text-sm font-bold">{label}</span>
                        <span className="text-[10px] text-muted-foreground">{weekday}</span>
                        {isToday && <span className="text-[9px] font-semibold text-primary bg-primary/15 rounded-full px-1.5 py-0.5">{t("today")}</span>}
                        <span className="ml-auto text-[10px] text-muted-foreground">{group.domains.length}</span>
                      </div>
                      <div className="divide-y divide-border/40">
                        {group.domains.map(dm => {
                          const monitored = monitoredSet.has(dm.domain);
                          const busy = !!subscribing[dm.domain];
                          const isUser = !!dm.reminder_id;
                          return (
                            <div key={dm.domain} className="flex items-center gap-2 px-4 py-2.5">
                              <RiGlobalLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                              <span className="flex-1 min-w-0">
                                <span className="block text-xs font-medium truncate">{dm.domain}</span>
                                {dm.tld && <span className="block text-[9px] text-muted-foreground/70">{dm.tld}</span>}
                              </span>
                              {monitored ? (
                                <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950/40 rounded-full px-2 py-1 shrink-0">
                                  <RiCheckLine className="w-3 h-3" />
                                  {t("drops.monitored")}
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  disabled={busy}
                                  onClick={() => handleMonitor(dm.domain)}
                                  className={cn(
                                    "inline-flex items-center gap-1 text-[10px] font-medium rounded-full px-2.5 py-1 border transition-colors shrink-0 touch-manipulation",
                                    status === "authenticated"
                                      ? "border-primary/30 text-primary hover:bg-primary/10 disabled:opacity-50 disabled:cursor-not-allowed"
                                      : "border-border text-muted-foreground hover:text-foreground hover:border-primary/40",
                                  )}
                                >
                                  {busy ? (
                                    <RiLoader4Line className="w-3 h-3 animate-spin" />
                                  ) : (
                                    <RiAddLine className="w-3 h-3" />
                                  )}
                                  {busy ? t("drops.monitoring") : t("drops.monitor")}
                                </button>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
              {status === "unauthenticated" && (
                <p className="text-[10px] text-muted-foreground text-center pt-1">
                  {t("drops.login_hint")}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
