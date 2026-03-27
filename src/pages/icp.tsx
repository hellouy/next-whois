import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiArrowLeftSLine, RiSearchLine, RiLoader4Line,
  RiCheckLine, RiFileCopyLine, RiFileList2Line,
  RiArrowLeftSFill, RiArrowRightSFill, RiAlertLine,
  RiGlobalLine, RiSmartphoneLine, RiAppsLine, RiThunderstormsLine,
  RiRefreshLine, RiWifiLine, RiWifiOffLine,
} from "@remixicon/react";
import type { IcpRecord, IcpResponse } from "@/pages/api/icp/query";
import type { IcpHealthResponse } from "@/pages/api/icp/health";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";

// ── Constants ─────────────────────────────────────────────────────────────────

const ICP_TYPES = [
  { id: "web",   tabKey: "icp.tab_web",   icon: RiGlobalLine,        color: "text-blue-600 dark:text-blue-400",     bg: "bg-blue-500/10 border-blue-400/40",      blacklist: false },
  { id: "app",   tabKey: "icp.tab_app",   icon: RiSmartphoneLine,    color: "text-violet-600 dark:text-violet-400", bg: "bg-violet-500/10 border-violet-400/40",   blacklist: false },
  { id: "mapp",  tabKey: "icp.tab_mapp",  icon: RiAppsLine,          color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-500/10 border-emerald-400/40", blacklist: false },
  { id: "kapp",  tabKey: "icp.tab_kapp",  icon: RiThunderstormsLine, color: "text-amber-600 dark:text-amber-400",   bg: "bg-amber-500/10 border-amber-400/40",     blacklist: false },
  { id: "bweb",  tabKey: "icp.tab_bweb",  icon: RiGlobalLine,        color: "text-red-600 dark:text-red-400",       bg: "bg-red-500/10 border-red-400/40",         blacklist: true  },
  { id: "bapp",  tabKey: "icp.tab_bapp",  icon: RiSmartphoneLine,    color: "text-red-600 dark:text-red-400",       bg: "bg-red-500/10 border-red-400/40",         blacklist: true  },
  { id: "bmapp", tabKey: "icp.tab_bmapp", icon: RiAppsLine,          color: "text-red-600 dark:text-red-400",       bg: "bg-red-500/10 border-red-400/40",         blacklist: true  },
  { id: "bkapp", tabKey: "icp.tab_bkapp", icon: RiThunderstormsLine, color: "text-red-600 dark:text-red-400",       bg: "bg-red-500/10 border-red-400/40",         blacklist: true  },
] as const;

type IcpTypeId = typeof ICP_TYPES[number]["id"];

const EXAMPLE_HINTS = ["baidu.com", "京ICP证030173号", "深圳市腾讯计算机系统有限公司"];

// ── Small components ─────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = React.useState(false);
  const { t } = useTranslation();
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(text).catch(() => {});
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      }}
      className="p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground shrink-0"
      title={t("icp.copy")}
    >
      {copied
        ? <RiCheckLine className="w-3 h-3 text-emerald-500" />
        : <RiFileCopyLine className="w-3 h-3" />}
    </button>
  );
}

function InfoRow({ label, value, mono }: {
  label: string; value?: string | number | boolean | null; mono?: boolean;
}) {
  if (value === null || value === undefined || value === "") return null;
  const str = String(value);
  return (
    <div className="flex items-start gap-2 py-2 border-b border-border/30 last:border-0">
      <span className="text-xs text-muted-foreground shrink-0 w-[6.5rem] pt-0.5">{label}</span>
      <div className="flex items-center gap-1 flex-1 min-w-0">
        <span className={cn("text-xs break-all flex-1", mono && "font-mono")}>{str}</span>
        {str && <CopyButton text={str} />}
      </div>
    </div>
  );
}

function BlackListBadge({ level }: { level?: string | number | null }) {
  const { t } = useTranslation();
  if (level === null || level === undefined) return null;
  const n = Number(level);
  if (n === 2) return (
    <Badge className="text-[9px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-0 px-1.5 shrink-0">
      {t("icp.threat_none")}
    </Badge>
  );
  return (
    <Badge className="text-[9px] bg-red-500/10 text-red-500 border-0 px-1.5 shrink-0">
      {t("icp.threat_level", { level: String(level) })}
    </Badge>
  );
}

function RecordCard({ record, isBlacklist, index }: {
  record: IcpRecord; isBlacklist: boolean; index: number;
}) {
  const { t } = useTranslation();
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18, delay: index * 0.04 }}
      className="rounded-xl border border-border/60 bg-card p-4"
    >
      {/* Card title row */}
      <div className="flex items-start justify-between gap-2 mb-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          {record.domain && (
            <span className="font-mono font-semibold text-sm">{record.domain}</span>
          )}
          {record.serviceName && record.serviceName !== record.domain && (
            <span className="text-sm font-medium">{record.serviceName}</span>
          )}
          {record.version && (
            <Badge variant="outline" className="text-[9px] font-mono shrink-0">{record.version}</Badge>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {isBlacklist && <BlackListBadge level={record.blackListLevel} />}
          {(record.limitAccess === true || record.limitAccess === "是" || record.limitAccess === "1") && (
            <Badge className="text-[9px] bg-orange-500/10 text-orange-500 border-0 shrink-0">{t("icp.field_limit")}</Badge>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6">
        <InfoRow label={t("icp.field_company")} value={record.unitName} />
        <InfoRow label={t("icp.field_nature")} value={record.natureName} />
        <InfoRow label={t("icp.field_icp")} value={record.mainLicence} mono />
        <InfoRow label={t("icp.field_service_license")} value={record.serviceLicence} mono />
        {record.serviceName && record.serviceName !== record.domain && (
          <InfoRow label={t("icp.field_name")} value={record.serviceName} />
        )}
        <InfoRow label={t("icp.field_type")} value={record.contentTypeName} />
        <InfoRow label={t("icp.field_verify_time")} value={record.updateRecordTime} />
        <InfoRow label={t("icp.field_domain")} value={record.mainUnitAddress} />
      </div>
    </motion.div>
  );
}

// ── Pagination ────────────────────────────────────────────────────────────────

function Pagination({ pageNum, pages, total, pageSize, hasNextPage, hasPreviousPage, onPage }: {
  pageNum: number; pages: number; total: number; pageSize: number;
  hasNextPage: boolean; hasPreviousPage: boolean; onPage: (p: number) => void;
}) {
  const { t } = useTranslation();
  if (pages <= 1) return null;
  const start = (pageNum - 1) * pageSize + 1;
  const end = Math.min(pageNum * pageSize, total);
  return (
    <div className="flex items-center justify-between gap-2 pt-3 flex-wrap">
      <span className="text-xs text-muted-foreground">
        {start}–{end} / {t("icp.results_count", { count: String(total) })}
      </span>
      <div className="flex items-center gap-1.5">
        <button
          onClick={() => onPage(pageNum - 1)}
          disabled={!hasPreviousPage}
          className="p-1.5 rounded-lg border border-border/60 hover:bg-muted/60 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <RiArrowLeftSFill className="w-4 h-4" />
        </button>
        <span className="text-xs font-mono px-2.5 py-1 rounded-lg border border-border/60 bg-muted/30 min-w-[4.5rem] text-center">
          {t("icp.page_of", { current: String(pageNum), total: String(pages) })}
        </span>
        <button
          onClick={() => onPage(pageNum + 1)}
          disabled={!hasNextPage}
          className="p-1.5 rounded-lg border border-border/60 hover:bg-muted/60 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <RiArrowRightSFill className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}

// ── Health check ──────────────────────────────────────────────────────────────

type HealthStatus = "checking" | "online" | "offline";

function useApiHealth() {
  const [status, setStatus] = React.useState<HealthStatus>("checking");
  const [latency, setLatency] = React.useState<number | null>(null);
  const [error, setError] = React.useState<string | undefined>();
  const [checking, setChecking] = React.useState(false);

  const check = React.useCallback(async () => {
    setChecking(true);
    try {
      const res = await fetch("/api/icp/health");
      const data: IcpHealthResponse = await res.json();
      setStatus(data.online ? "online" : "offline");
      setLatency(data.latencyMs);
      setError(data.error);
    } catch {
      setStatus("offline");
      setLatency(null);
      setError("检测失败");
    } finally {
      setChecking(false);
    }
  }, []);

  React.useEffect(() => { check(); }, [check]);
  return { status, latency, error, checking, check };
}

function ApiStatusBadge({ status, latency, error, checking, onRefresh }: {
  status: HealthStatus; latency: number | null; error?: string;
  checking: boolean; onRefresh: () => void;
}) {
  const { t } = useTranslation();
  return (
    <button
      onClick={onRefresh}
      disabled={checking}
      title={
        checking ? t("icp.check_status")
          : status === "online" ? `${t("icp.check_status")} · ${latency}ms`
          : `${t("icp.offline")}${error ? `: ${error}` : ""}`
      }
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-medium border transition-all select-none",
        checking || status === "checking"
          ? "border-border/50 text-muted-foreground bg-muted/30"
          : status === "online"
          ? "border-emerald-500/30 text-emerald-600 dark:text-emerald-400 bg-emerald-500/10"
          : "border-red-500/30 text-red-500 bg-red-500/10",
      )}
    >
      {checking
        ? <RiLoader4Line className="w-3 h-3 animate-spin" />
        : status === "online"
        ? <RiWifiLine className="w-3 h-3" />
        : <RiWifiOffLine className="w-3 h-3" />}
      {checking
        ? t("icp.check_status")
        : status === "online"
        ? `${t("icp.check_status")}${latency != null ? ` · ${latency}ms` : ""}`
        : `${t("icp.offline")}${error ? ` · ${error}` : ""}`}
      {!checking && status === "offline" && <RiRefreshLine className="w-3 h-3 opacity-70" />}
    </button>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function IcpPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteLabel = settings.site_logo_text || "X.RW";
  const [query, setQuery] = React.useState("");
  const [selectedType, setSelectedType] = React.useState<IcpTypeId>("web");
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<IcpResponse | null>(null);
  const [currentPage, setCurrentPage] = React.useState(1);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const { status: apiStatus, latency: apiLatency, error: apiError, checking: apiChecking, check: recheckApi } = useApiHealth();

  // Sync URL query params → state (once on mount / when query changes)
  const didInit = React.useRef(false);
  React.useEffect(() => {
    if (didInit.current || !router.isReady) return;
    didInit.current = true;
    const q = (router.query.q as string) || "";
    const t = (router.query.type as IcpTypeId) || "web";
    if (q) setQuery(q);
    if (ICP_TYPES.find(x => x.id === t)) setSelectedType(t);
  }, [router.isReady, router.query]);

  const handleSearch = React.useCallback(async (
    searchQuery?: string, type?: IcpTypeId, page = 1
  ) => {
    const q = (searchQuery ?? query).trim();
    const tp = type ?? selectedType;
    if (!q) { toast.error(t("icp.search_placeholder")); inputRef.current?.focus(); return; }

    setLoading(true);
    setCurrentPage(page);
    router.replace({ pathname: "/icp", query: { q, type: tp } }, undefined, { shallow: true });

    try {
      const url = `/api/icp/query?type=${encodeURIComponent(tp)}&search=${encodeURIComponent(q)}&pageNum=${page}&pageSize=10`;
      const res = await fetch(url);
      const data: IcpResponse = await res.json();
      setResult(data);
      if (!data.ok) toast.error(data.error || t("icp.no_data"));
    } catch {
      toast.error(t("icp.offline_desc"));
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [query, selectedType, router, t]);

  const handlePage = (p: number) => {
    handleSearch(query, selectedType, p);
  };

  const handleTypeChange = (tp: IcpTypeId) => {
    setSelectedType(tp);
    setResult(null);
    setCurrentPage(1);
  };

  const typeInfo = ICP_TYPES.find(x => x.id === selectedType)!;
  const isBlacklist = typeInfo.blacklist;
  const hasResult = !!result?.ok && result.list.length > 0;

  return (
    <>
      <Head>
        <title key="title">{`${t("icp.page_title")} — ${siteLabel}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6">

          {/* Header — no layout shift: status badge is always in the DOM */}
          <div className="flex items-center gap-3 mb-5">
            <Link href="/">
              <Button variant="ghost" size="icon-sm" className="shrink-0">
                <RiArrowLeftSLine className="w-4 h-4" />
              </Button>
            </Link>
            <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-500 shrink-0">
              <RiFileList2Line className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <h1 className="text-lg font-bold leading-none">{t("icp.page_title")}</h1>
              <p className="text-[11px] text-muted-foreground mt-0.5">{t("icp.page_subtitle")}</p>
            </div>
            <ApiStatusBadge
              status={apiStatus}
              latency={apiLatency}
              error={apiError}
              checking={apiChecking}
              onRefresh={recheckApi}
            />
          </div>

          {/* Offline banner — animate height instead of mount/unmount */}
          <AnimatePresence initial={false}>
            {apiStatus === "offline" && !apiChecking && (
              <motion.div
                key="offline-banner"
                initial={{ opacity: 0, height: 0, marginBottom: 0 }}
                animate={{ opacity: 1, height: "auto", marginBottom: 16 }}
                exit={{ opacity: 0, height: 0, marginBottom: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="flex items-start gap-2.5 rounded-xl border border-orange-500/20 bg-orange-500/5 px-4 py-3 text-sm">
                  <RiAlertLine className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
                  <span className="flex-1 text-muted-foreground">
                    <span className="font-medium text-orange-600 dark:text-orange-400">{t("icp.offline")}</span>
                    {" · "}{apiError || t("icp.offline_desc")}
                  </span>
                  <button
                    onClick={recheckApi}
                    className="text-xs text-orange-500 hover:text-orange-600 shrink-0 font-medium flex items-center gap-1"
                  >
                    <RiRefreshLine className="w-3.5 h-3.5" />{t("icp.check_status")}
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Type selector */}
          <div className="mb-4">
            <div className="flex flex-wrap gap-1.5">
              {ICP_TYPES.map(typeItem => {
                const Icon = typeItem.icon;
                const active = selectedType === typeItem.id;
                return (
                  <button
                    key={typeItem.id}
                    onClick={() => handleTypeChange(typeItem.id as IcpTypeId)}
                    className={cn(
                      "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all duration-150",
                      active
                        ? cn(typeItem.bg, typeItem.color)
                        : "border-border/50 text-muted-foreground hover:border-border hover:text-foreground bg-transparent",
                      typeItem.blacklist && !active && "border-dashed",
                    )}
                  >
                    <Icon className="w-3 h-3" />
                    {t(typeItem.tabKey as Parameters<typeof t>[0])}
                  </button>
                );
              })}
            </div>
            {isBlacklist && (
              <p className="flex items-center gap-1.5 mt-2 text-[11px] text-red-500/80">
                <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
                {t("icp.hint_china_only")}
              </p>
            )}
          </div>

          {/* Search box */}
          <form
            onSubmit={e => { e.preventDefault(); handleSearch(); }}
            className="flex gap-2 mb-5"
          >
            <div className="relative flex-1">
              <RiSearchLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
              <Input
                ref={inputRef}
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder={t("icp.search_placeholder")}
                className="pl-9 text-sm"
              />
            </div>
            <Button type="submit" disabled={loading} className="shrink-0 gap-1.5">
              {loading
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : <RiSearchLine className="w-4 h-4" />}
              <span className="hidden sm:inline">{t("search")}</span>
            </Button>
          </form>

          {/* Example hints — always rendered, opacity transition only */}
          <div
            className={cn(
              "flex flex-wrap gap-2 mb-5 transition-opacity duration-200",
              hasResult || loading ? "opacity-0 pointer-events-none h-0 mb-0 overflow-hidden" : "opacity-100",
            )}
          >
            {EXAMPLE_HINTS.map(hint => (
              <button
                key={hint}
                onClick={() => { setQuery(hint); handleSearch(hint, selectedType, 1); }}
                className="text-xs px-2.5 py-1 rounded-full border border-border/50 text-muted-foreground hover:text-foreground hover:border-border transition-all font-mono"
              >
                {hint}
              </button>
            ))}
          </div>

          {/* Results area — fixed min-height prevents layout jumps */}
          <div className="relative min-h-[120px]">

            {/* Loading overlay over previous results */}
            <AnimatePresence>
              {loading && (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 text-muted-foreground bg-background/60 backdrop-blur-sm rounded-xl"
                >
                  <RiLoader4Line className="w-7 h-7 animate-spin" />
                  <span className="text-sm">{t("icp.loading")}</span>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Error state */}
            {!loading && result && !result.ok && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-8 text-center">
                <RiAlertLine className="w-8 h-8 text-red-400 mx-auto mb-2" />
                <p className="text-sm font-medium text-red-600 dark:text-red-400">{result.error || t("icp.no_data")}</p>
                <p className="text-xs text-muted-foreground mt-1">{t("icp.no_data_hint")}</p>
              </div>
            )}

            {/* Empty state */}
            {!loading && result?.ok && result.list.length === 0 && (
              <div className="rounded-xl border border-border/50 p-10 text-center">
                <RiFileList2Line className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm font-medium">{t("icp.no_data")}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  <span className="font-mono">{result.search}</span>
                </p>
              </div>
            )}

            {/* Results list */}
            {result?.ok && result.list.length > 0 && (
              <div className="space-y-3">
                {/* Summary bar */}
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm">
                      {t("icp.results_count", { count: String(result.total) })}
                    </span>
                    <Badge variant="outline" className="text-[9px]">{t(typeInfo.tabKey as Parameters<typeof t>[0])}</Badge>
                  </div>
                  <span className="text-xs text-muted-foreground font-mono truncate max-w-[18rem]">
                    {result.search}
                  </span>
                </div>

                {/* Cards */}
                {result.list.map((record, i) => (
                  <RecordCard key={i} record={record} isBlacklist={isBlacklist} index={i} />
                ))}

                {/* Pagination */}
                <Pagination
                  pageNum={currentPage}
                  pages={result.pages}
                  total={result.total}
                  pageSize={result.pageSize}
                  hasNextPage={result.hasNextPage}
                  hasPreviousPage={result.hasPreviousPage}
                  onPage={handlePage}
                />

                <p className="text-[10px] text-muted-foreground/40 text-center pt-1">
                  {t("icp.hint_china_only")}
                </p>
              </div>
            )}
          </div>

        </main>
      </ScrollArea>
    </>
  );
}
