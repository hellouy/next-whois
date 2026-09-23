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
  RiArrowLeftSLine,
  RiArrowRightSLine,
  RiAddLine,
  RiCheckLine,
  RiLockLine,
  RiRefreshLine,
  RiGlobalLine,
  RiFilter3Line,
  RiRadarLine,
  RiForbidLine,
} from "@remixicon/react";
import { useTranslation, type TranslationKey } from "@/lib/i18n";
import { format } from "date-fns";

type SortKey = "value" | "date" | "bl";

interface DropLead {
  domain: string;
  tld: string;
  dropDate: string;
  dropTime: string | null;
  dateType: "source" | "derived";
  source: string;
  valueScore: number;
  valueTier: string;
  reasons: string[];
  regStatus?: "reserved" | "prohibited";
  reminder_id?: string;
}

interface DropGroup {
  date: string;
  total: number;
  topTier: string;
  domains: DropLead[];
}

interface SourceStatus {
  source: string;
  stage: string;
  lastSuccessAt: string | null;
  stale: boolean;
}

interface DropsData {
  today: string;
  days: number;
  public_locked: boolean;
  sources: SourceStatus[];
  drops: DropGroup[];
  stats: { total: number; today: number; tlds: { tld: string; count: number }[]; top: DropLead[] };
  user_drops: { date: string; domains: { domain: string; reminder_id: string }[] }[];
}

const TIER_COLOR: Record<string, string> = {
  top: "#dc2626",
  high: "#d97706",
  medium: "#7c3aed",
  normal: "#64748b",
  low: "#94a3b8",
};

/** Restricted-registration leads get their own card treatment, distinct from normal registerable ones. */
const REG_STATUS_META: Record<
  NonNullable<DropLead["regStatus"]>,
  { labelKey: TranslationKey; noteKey: TranslationKey; bar: string; accent: string; chip: string; lockChip: string; Icon: typeof RiLockLine }
> = {
  reserved: {
    labelKey: "drops.reg_reserved",
    noteKey: "drops.reg_reserved_note",
    bar: "border-l-2 bg-amber-500/[0.04]",
    accent: "rgba(245,158,11,0.75)",
    chip: "text-amber-600 dark:text-amber-400 bg-amber-500/10",
    lockChip: "border-amber-400/40 text-amber-600 dark:text-amber-400",
    Icon: RiLockLine,
  },
  prohibited: {
    labelKey: "drops.reg_prohibited",
    noteKey: "drops.reg_prohibited_note",
    bar: "border-l-2 bg-rose-500/[0.04]",
    accent: "rgba(244,63,94,0.75)",
    chip: "text-rose-600 dark:text-rose-400 bg-rose-500/10",
    lockChip: "border-rose-400/40 text-rose-600 dark:text-rose-400",
    Icon: RiForbidLine,
  },
};

const WINDOWS = [7, 30, 90];

export default function DropsPage() {
  const { data: session, status } = useSession();
  const { t, locale } = useTranslation();
  const router = useRouter();

  const [data, setData] = React.useState<DropsData | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);

  const [days, setDays] = React.useState(30);
  const [sort, setSort] = React.useState<SortKey>("value");
  const [tldFilter, setTldFilter] = React.useState("");
  const [lenFilter, setLenFilter] = React.useState("");
  const [scoreFilter, setScoreFilter] = React.useState("");
  const [sourceFilter, setSourceFilter] = React.useState("");
  const [dateTypeFilter, setDateTypeFilter] = React.useState("");

  const [monthCursor, setMonthCursor] = React.useState(() => {
    const now = new Date();
    return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  });
  const [selectedDate, setSelectedDate] = React.useState<string | null>(null);
  const [monitoredSet, setMonitoredSet] = React.useState<Set<string>>(new Set());
  const [subscribing, setSubscribing] = React.useState<Record<string, boolean>>({});
  const [sniping, setSniping] = React.useState<Record<string, boolean>>({});

  const isAdmin = !!(session?.user as any)?.isAdmin;

  const load = React.useCallback(async () => {
    const params = new URLSearchParams({ days: String(days), sort });
    if (tldFilter.trim()) params.set("tld", tldFilter.trim());
    if (lenFilter) { params.set("minLen", lenFilter); params.set("maxLen", lenFilter); }
    if (scoreFilter) params.set("minScore", scoreFilter);
    if (sourceFilter) params.set("source", sourceFilter);
    if (dateTypeFilter) params.set("dateType", dateTypeFilter);

    try {
      const res = await fetch(`/api/drops?${params.toString()}`);
      if (!res.ok) throw new Error("bad status");
      const d: DropsData = await res.json();
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
  }, [days, sort, tldFilter, lenFilter, scoreFilter, sourceFilter, dateTypeFilter]);

  React.useEffect(() => {
    if (status !== "loading") load();
  }, [status, load]);

  const groupByDate = React.useMemo(() => {
    const m = new Map<string, DropGroup>();
    for (const g of data?.drops ?? []) m.set(g.date, g);
    return m;
  }, [data]);

  const userDomains = React.useMemo(() => {
    const m = new Map<string, string>();
    for (const g of data?.user_drops ?? []) {
      for (const dm of g.domains) m.set(dm.domain, dm.reminder_id);
    }
    return m;
  }, [data]);

  const monthGrid = React.useMemo(() => {
    const year = monthCursor.getUTCFullYear();
    const month = monthCursor.getUTCMonth();
    const first = new Date(Date.UTC(year, month, 1));
    const cells: (string | null)[] = [];
    for (let i = 0; i < first.getUTCDay(); i++) cells.push(null);
    const daysInMonth = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
    for (let d = 1; d <= daysInMonth; d++) {
      cells.push(new Date(Date.UTC(year, month, d)).toISOString().slice(0, 10));
    }
    while (cells.length % 7 !== 0) cells.push(null);
    return cells;
  }, [monthCursor]);

  const monthLabel = React.useMemo(() => {
    const d = monthCursor;
    const isChinese = locale === "zh" || locale === "zh-tw";
    return format(d, isChinese ? "yyyy年M月" : "MMMM yyyy");
  }, [monthCursor, locale]);

  const weekdayLabels = React.useMemo(() => {
    const isChinese = locale === "zh" || locale === "zh-tw";
    const base = new Date(Date.UTC(2024, 0, 7)); // a Sunday
    return Array.from({ length: 7 }, (_, i) =>
      format(new Date(base.getTime() + i * 86_400_000), isChinese ? "EEEEE" : "EEE"),
    );
  }, [locale]);

  const hasFilters = !!(tldFilter || lenFilter || scoreFilter || sourceFilter || dateTypeFilter);

  const clearFilters = () => {
    setTldFilter("");
    setLenFilter("");
    setScoreFilter("");
    setSourceFilter("");
    setDateTypeFilter("");
  };

  const handleMonitor = async (domain: string) => {
    const email = (session?.user as any)?.email as string | undefined;
    if (!email) { router.push("/login"); return; }
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

  const handleSnipe = async (domain: string) => {
    if (sniping[domain]) return;
    setSniping(prev => ({ ...prev, [domain]: true }));
    try {
      const res = await fetch("/api/admin/snipe-targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      if (res.ok) toast.success(t("drops.snipe_ok"));
      else toast.error(t("drops.snipe_failed"));
    } catch {
      toast.error(t("drops.snipe_failed"));
    } finally {
      setSniping(prev => { const n = { ...prev }; delete n[domain]; return n; });
    }
  };

  const selectedGroup = selectedDate ? groupByDate.get(selectedDate) ?? null : null;
  const selectedLeads: DropLead[] = selectedGroup
    ? selectedGroup.domains.map(d => ({ ...d, reminder_id: userDomains.get(d.domain) }))
    : [];

  const fmtSourceFreshness = (s: SourceStatus): string => {
    if (!s.lastSuccessAt) return t("drops.source_never");
    const d = new Date(s.lastSuccessAt);
    if (isNaN(d.getTime())) return t("drops.source_never");
    return format(d, "MMM d HH:mm");
  };

  return (
    <>
      <Head>
        <title>{t("drops.title")}</title>
      </Head>
      <div className="min-h-screen flex justify-center pt-8 pb-16 px-3 sm:px-4">
        <div className="w-full max-w-4xl">
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
            </div>

            {/* Window switcher — R7.3 */}
            <div className="px-4 py-2 flex items-center gap-1.5 border-b border-border/40 overflow-x-auto">
              <span className="text-[10px] text-muted-foreground shrink-0">{t("drops.window")}</span>
              {WINDOWS.map(w => (
                <button
                  key={w}
                  type="button"
                  onClick={() => setDays(w)}
                  className={cn(
                    "text-[10px] font-medium rounded-full px-2.5 py-1 border transition-colors shrink-0 touch-manipulation",
                    days === w ? "border-primary/40 text-primary bg-primary/10" : "border-border text-muted-foreground hover:text-foreground",
                  )}
                >
                  {t("drops.window_days", { days: w })}
                </button>
              ))}
            </div>

            {/* Source freshness — R9.1 / R9.2 */}
            {data && data.sources.length > 0 && (
              <div className="px-4 py-2 flex items-center gap-2 flex-wrap border-b border-border/40">
                <RiRadarLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                <span className="text-[10px] text-muted-foreground">{t("drops.sources_title")}</span>
                {data.sources.map(s => (
                  <span
                    key={s.source}
                    className={cn(
                      "inline-flex items-center gap-1 text-[10px] rounded-full px-2 py-0.5 border",
                      s.stale ? "border-amber-400/40 text-amber-600 dark:text-amber-400" : "border-border text-muted-foreground",
                    )}
                  >
                    {s.source} · {fmtSourceFreshness(s)}
                    <span className="opacity-70">{s.stale ? t("drops.source_stale") : t("drops.source_fresh")}</span>
                  </span>
                ))}
              </div>
            )}
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
          ) : (
            <div className="space-y-3">
              {/* Stats overview — R11 */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { label: t("drops.stats_total"), value: data?.stats.total ?? 0 },
                  { label: t("drops.stats_today"), value: data?.stats.today ?? 0 },
                  { label: t("drops.stats_tlds"), value: (data?.stats.tlds ?? []).slice(0, 3).map(x => `.${x.tld}`).join(" ") || "—" },
                  { label: t("drops.stats_top"), value: data?.stats.top[0]?.domain ?? "—" },
                ].map((c, i) => (
                  <div key={i} className="glass-panel border border-border rounded-xl px-3 py-2.5">
                    <div className="text-[10px] text-muted-foreground">{c.label}</div>
                    <div className="text-sm font-bold mt-0.5 truncate">{c.value}</div>
                  </div>
                ))}
              </div>

              {/* Filters — R7.1 / R7.2 */}
              <div className="glass-panel border border-border rounded-xl px-3 py-2.5">
                <div className="flex items-center gap-2 mb-2">
                  <RiFilter3Line className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="text-[10px] font-medium text-muted-foreground">{t("drops.filters")}</span>
                  {hasFilters && (
                    <button type="button" onClick={clearFilters} className="ml-auto text-[10px] text-primary hover:underline touch-manipulation">
                      {t("drops.clear_filters")}
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  <input
                    value={tldFilter}
                    onChange={e => setTldFilter(e.target.value)}
                    placeholder={t("drops.filter_tld")}
                    className="text-[11px] rounded-lg border border-border bg-transparent px-2 py-1.5 outline-none focus:border-primary/50"
                  />
                  <input
                    value={lenFilter}
                    onChange={e => setLenFilter(e.target.value.replace(/\D/g, ""))}
                    placeholder={t("drops.filter_len")}
                    inputMode="numeric"
                    className="text-[11px] rounded-lg border border-border bg-transparent px-2 py-1.5 outline-none focus:border-primary/50"
                  />
                  <input
                    value={scoreFilter}
                    onChange={e => setScoreFilter(e.target.value.replace(/\D/g, ""))}
                    placeholder={t("drops.filter_score")}
                    inputMode="numeric"
                    className="text-[11px] rounded-lg border border-border bg-transparent px-2 py-1.5 outline-none focus:border-primary/50"
                  />
                  <select
                    value={sourceFilter}
                    onChange={e => setSourceFilter(e.target.value)}
                    className="text-[11px] rounded-lg border border-border bg-transparent px-2 py-1.5 outline-none focus:border-primary/50"
                  >
                    <option value="">{t("drops.filter_all")} · {t("drops.filter_source")}</option>
                    <option value="expireddomains.net">expireddomains.net</option>
                    <option value="whoisds.com">whoisds.com</option>
                  </select>
                  <select
                    value={dateTypeFilter}
                    onChange={e => setDateTypeFilter(e.target.value)}
                    className="text-[11px] rounded-lg border border-border bg-transparent px-2 py-1.5 outline-none focus:border-primary/50"
                  >
                    <option value="">{t("drops.filter_all")} · {t("drops.filter_datetype")}</option>
                    <option value="source">{t("drops.date_source")}</option>
                    <option value="derived">{t("drops.date_derived")}</option>
                  </select>
                  <select
                    value={sort}
                    onChange={e => setSort(e.target.value as SortKey)}
                    className="text-[11px] rounded-lg border border-border bg-transparent px-2 py-1.5 outline-none focus:border-primary/50"
                  >
                    <option value="value">{t("drops.sort_value")}</option>
                    <option value="date">{t("drops.sort_date")}</option>
                    <option value="bl">{t("drops.sort_bl")}</option>
                  </select>
                </div>
              </div>

              {/* Calendar — R6.1 / R6.3 / R6.4 */}
              <div className="glass-panel border border-border rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-border/50 flex items-center gap-2">
                  <button
                    type="button"
                    aria-label={t("drops.month_prev")}
                    onClick={() => setMonthCursor(m => new Date(Date.UTC(m.getUTCFullYear(), m.getUTCMonth() - 1, 1)))}
                    className="p-1 rounded-md hover:bg-muted/50 touch-manipulation"
                  >
                    <RiArrowLeftSLine className="w-4 h-4" />
                  </button>
                  <span className="text-xs font-bold flex-1 text-center">{monthLabel}</span>
                  <button
                    type="button"
                    aria-label={t("drops.month_next")}
                    onClick={() => setMonthCursor(m => new Date(Date.UTC(m.getUTCFullYear(), m.getUTCMonth() + 1, 1)))}
                    className="p-1 rounded-md hover:bg-muted/50 touch-manipulation"
                  >
                    <RiArrowRightSLine className="w-4 h-4" />
                  </button>
                </div>
                <div className="grid grid-cols-7 gap-px bg-border/30 p-px">
                  {weekdayLabels.map((w, i) => (
                    <div key={i} className="bg-background/60 text-center text-[9px] text-muted-foreground py-1">{w}</div>
                  ))}
                  {monthGrid.map((iso, i) => {
                    if (!iso) return <div key={i} className="bg-background/30 min-h-[44px]" />;
                    const g = groupByDate.get(iso);
                    const isToday = iso === data?.today;
                    const selected = iso === selectedDate;
                    return (
                      <button
                        key={i}
                        type="button"
                        disabled={!g}
                        onClick={() => setSelectedDate(prev => (prev === iso ? null : iso))}
                        className={cn(
                          "min-h-[44px] p-1 text-left align-top flex flex-col gap-0.5 transition-colors touch-manipulation",
                          g ? "hover:bg-primary/5 cursor-pointer" : "cursor-default",
                          selected && "bg-primary/10 ring-1 ring-inset ring-primary/40",
                          isToday && "bg-primary/5",
                        )}
                      >
                        <span className={cn("text-[10px]", isToday ? "font-bold text-primary" : "text-muted-foreground")}>
                          {Number(iso.slice(8, 10))}
                        </span>
                        {g && (
                          <>
                            <span className="text-[10px] font-semibold">{g.total}</span>
                            <span className="flex gap-0.5 flex-wrap">
                              {g.domains.slice(0, 4).map(d => (
                                <span
                                  key={d.domain}
                                  className="w-1.5 h-1.5 rounded-full"
                                  style={{ backgroundColor: TIER_COLOR[d.valueTier] ?? TIER_COLOR.low }}
                                />
                              ))}
                            </span>
                          </>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Selected day list — R6.2 / R7.4 */}
              {selectedDate && (
                <AnimatePresence>
                  <motion.div
                    key={selectedDate}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="glass-panel border border-border rounded-xl overflow-hidden"
                  >
                    <div className="px-4 py-2.5 border-b border-border/50 flex items-center gap-2">
                      <span className="text-sm font-bold">{selectedDate}</span>
                      <span className="text-[10px] text-muted-foreground">{selectedGroup?.total ?? 0}</span>
                    </div>
                    {selectedLeads.length === 0 ? (
                      <div className="px-4 py-8 text-center text-xs text-muted-foreground">{t("drops.no_results")}</div>
                    ) : (
                      <div className="divide-y divide-border/40">
                        {selectedLeads.map(dm => {
                          const monitored = monitoredSet.has(dm.domain);
                          const busy = !!subscribing[dm.domain];
                          const isUser = !!dm.reminder_id;
                          const regMeta = dm.regStatus ? REG_STATUS_META[dm.regStatus] : undefined;
                          const RegIcon = regMeta?.Icon;
                          return (
                            <div
                              key={dm.domain}
                              className={cn("px-4 py-2.5", regMeta && regMeta.bar)}
                              style={regMeta ? { borderLeftColor: regMeta.accent } : undefined}
                            >
                              <div className="flex items-center gap-2">
                                <RiGlobalLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                                <span className="flex-1 min-w-0">
                                  <span className="flex items-center gap-1.5 flex-wrap">
                                    <span className="truncate text-xs font-medium">{dm.domain}</span>
                                    {regMeta && RegIcon && (
                                      <span className={cn("shrink-0 inline-flex items-center gap-1 text-[9px] font-bold rounded-full px-1.5 py-0.5", regMeta.chip)}>
                                        <RegIcon className="w-2.5 h-2.5" />
                                        {t(regMeta.labelKey)}
                                      </span>
                                    )}
                                    <span
                                      className="shrink-0 text-[9px] font-bold rounded-full px-1.5 py-0.5"
                                      style={{ color: TIER_COLOR[dm.valueTier] ?? TIER_COLOR.low, backgroundColor: `${TIER_COLOR[dm.valueTier] ?? TIER_COLOR.low}1a` }}
                                    >
                                      {dm.valueScore}
                                    </span>
                                    <span className="shrink-0 text-[9px] text-muted-foreground border border-border rounded-full px-1.5 py-0.5">
                                      {dm.dateType === "derived" ? t("drops.date_derived") : t("drops.date_source")}
                                    </span>
                                    {isUser && (
                                      <span className="shrink-0 text-[9px] font-semibold text-primary bg-primary/15 rounded-full px-1.5 py-0.5">
                                        {t("drops.my_subscription")}
                                      </span>
                                    )}
                                  </span>
                                  <span className="block text-[9px] text-muted-foreground/70 mt-0.5">
                                    {dm.source}
                                    {dm.dropTime ? ` · ${t("drops.drop_time")} ${dm.dropTime}` : ""}
                                  </span>
                                  {regMeta && RegIcon && (
                                    <span className="flex items-start gap-1 mt-1 text-[9px] text-muted-foreground">
                                      <RegIcon className="w-2.5 h-2.5 shrink-0 mt-px" />
                                      {t(regMeta.noteKey)}
                                    </span>
                                  )}
                                  {dm.reasons.length > 0 && (
                                    <span className="flex flex-wrap gap-1 mt-1">
                                      {dm.reasons.slice(0, 4).map((r, ri) => (
                                        <span key={ri} className="text-[9px] text-muted-foreground bg-muted/50 rounded px-1.5 py-0.5">{r}</span>
                                      ))}
                                    </span>
                                  )}
                                </span>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  {isAdmin && (
                                    <button
                                      type="button"
                                      disabled={!!sniping[dm.domain]}
                                      onClick={() => handleSnipe(dm.domain)}
                                      className="inline-flex items-center gap-1 text-[10px] font-medium rounded-full px-2 py-1 border border-amber-400/40 text-amber-600 dark:text-amber-400 hover:bg-amber-500/10 disabled:opacity-50 touch-manipulation"
                                    >
                                      {sniping[dm.domain] ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiRadarLine className="w-3 h-3" />}
                                      {sniping[dm.domain] ? t("drops.sniping") : t("drops.snipe")}
                                    </button>
                                  )}
                                  {regMeta && RegIcon ? (
                                    <span className={cn("inline-flex items-center gap-1 text-[10px] font-medium border rounded-full px-2 py-1 opacity-90", regMeta.lockChip)}>
                                      <RegIcon className="w-3 h-3" />
                                      {t(regMeta.labelKey)}
                                    </span>
                                  ) : monitored ? (
                                    <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950/40 rounded-full px-2 py-1">
                                      <RiCheckLine className="w-3 h-3" />
                                      {t("drops.monitored")}
                                    </span>
                                  ) : (
                                    <button
                                      type="button"
                                      disabled={busy}
                                      onClick={() => handleMonitor(dm.domain)}
                                      className={cn(
                                        "inline-flex items-center gap-1 text-[10px] font-medium rounded-full px-2.5 py-1 border transition-colors touch-manipulation",
                                        status === "authenticated"
                                          ? "border-primary/30 text-primary hover:bg-primary/10 disabled:opacity-50 disabled:cursor-not-allowed"
                                          : "border-border text-muted-foreground hover:text-foreground hover:border-primary/40",
                                      )}
                                    >
                                      {busy ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiAddLine className="w-3 h-3" />}
                                      {busy ? t("drops.monitoring") : t("drops.monitor")}
                                    </button>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </motion.div>
                </AnimatePresence>
              )}

              {!selectedDate && (data?.drops.length ?? 0) > 0 && (
                <p className="text-[10px] text-muted-foreground text-center px-1">{t("drops.select_day")}</p>
              )}

              {(data?.drops.length ?? 0) === 0 && (
                <div className="glass-panel border border-border rounded-xl px-4 py-16 text-center space-y-2">
                  <RiCalendarLine className="w-7 h-7 mx-auto text-muted-foreground/50" />
                  <p className="text-sm text-muted-foreground">{hasFilters ? t("drops.no_results") : t("drops.empty")}</p>
                </div>
              )}

              {!data?.user_drops?.length && (
                <p className="text-[10px] text-muted-foreground px-1">{t("drops.public_note")}</p>
              )}
              {status === "unauthenticated" && (
                <p className="text-[10px] text-muted-foreground text-center pt-1">{t("drops.login_hint")}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
