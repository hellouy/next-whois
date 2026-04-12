import React, { useCallback, useRef, useState } from "react";
import Head from "next/head";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { TextArea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import {
  RiArrowLeftSLine,
  RiSearchLine,
  RiStopCircleLine,
  RiDeleteBinLine,
  RiDownloadLine,
  RiFileCopyLine,
  RiCheckboxCircleLine,
  RiCloseCircleLine,
  RiErrorWarningLine,
  RiTimeLine,
  RiLoginBoxLine,
} from "@remixicon/react";
import type { BatchItem } from "./api/lookup-batch";

// ── Popular TLDs preset ───────────────────────────────────────────────────────
const POPULAR_TLDS = [
  "com", "net", "org", "io", "co", "ai", "app", "dev",
  "xyz", "online", "site", "tech", "info", "biz", "me",
  "cc", "tv", "us", "uk", "cn",
];

type TldPreset = "popular" | "gtld" | "cctld" | "all" | "custom";

type ResultFilter = "all" | "available" | "registered";

type RowStatus = "available" | "registered" | "reserved" | "premium" | "error" | "checking";

function getDomainStatus(item: BatchItem): RowStatus {
  if (!item.status) return "error";
  const r = item.result;
  if (!r || r.status.length === 0) return "available";
  const codes = r.status.map(s => s.status.toLowerCase());
  if (codes.some(c => c.includes("registry-reserved") || c.includes("registry-hold"))) return "reserved";
  if (codes.some(c => c.includes("registry-premium"))) return "premium";
  return "registered";
}

function StatusBadge({ status }: { status: RowStatus; }) {
  const { t } = useTranslation();
  const cfg: Record<RowStatus, { label: string; cls: string }> = {
    available:  { label: t("batch_check.tag_available"),   cls: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20" },
    registered: { label: t("batch_check.tag_registered"),  cls: "bg-slate-500/10 text-slate-500 dark:text-slate-400 border-slate-500/20" },
    reserved:   { label: t("batch_check.tag_reserved"),    cls: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20" },
    premium:    { label: t("batch_check.tag_premium"),     cls: "bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/20" },
    error:      { label: t("batch_check.tag_error"),       cls: "bg-red-500/10 text-red-500 dark:text-red-400 border-red-500/20" },
    checking:   { label: "...",                             cls: "bg-muted/60 text-muted-foreground border-border animate-pulse" },
  };
  const { label, cls } = cfg[status];
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border", cls)}>
      {label}
    </span>
  );
}

export default function BatchCheckPage() {
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteLabel = settings.site_logo_text || "WHOIS";
  const { data: session } = useSession();
  const isLoggedIn = !!session?.user?.email;

  const [prefix, setPrefix] = useState("");
  const [preset, setPreset] = useState<TldPreset>("popular");
  const [customTlds, setCustomTlds] = useState("");
  const [results, setResults] = useState<Map<string, BatchItem>>(new Map());
  const [checking, setChecking] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [filter, setFilter] = useState<ResultFilter>("all");
  const stopRef = useRef(false);

  const MAX_ANON = 10;
  const CHUNK_SIZE = 20; // domains per API call

  // ── TLD list derivation ───────────────────────────────────────────────────
  const [ianaTlds, setIanaTlds] = useState<{ tld: string; type: "cctld" | "gtld" }[]>([]);

  const fetchIanaTlds = useCallback(async () => {
    if (ianaTlds.length > 0) return ianaTlds;
    const r = await fetch("/api/iana-tlds");
    if (!r.ok) return [];
    const data = await r.json();
    const list = (data.tlds ?? []) as { tld: string; type: "cctld" | "gtld" }[];
    setIanaTlds(list);
    return list;
  }, [ianaTlds]);

  const getTldList = async (): Promise<string[]> => {
    if (preset === "popular") return POPULAR_TLDS;
    if (preset === "custom") {
      return customTlds
        .split(/[\s,，]+/)
        .map(s => s.replace(/^\./, "").toLowerCase().trim())
        .filter(Boolean);
    }
    const list = await fetchIanaTlds();
    if (preset === "gtld")  return list.filter(t => t.type === "gtld").map(t => t.tld);
    if (preset === "cctld") return list.filter(t => t.type === "cctld").map(t => t.tld);
    return list.map(t => t.tld);
  };

  // ── Run check ────────────────────────────────────────────────────────────
  const handleCheck = async () => {
    const cleanPrefix = prefix.trim().toLowerCase().replace(/^[\s.]+|[\s.]+$/g, "");
    if (!cleanPrefix) { toast.error(t("batch_check.err_no_prefix")); return; }

    const tldList = await getTldList();
    if (tldList.length === 0) { toast.error(t("batch_check.err_no_tlds")); return; }

    const effectiveTlds = isLoggedIn ? tldList : tldList.slice(0, MAX_ANON);

    if (!isLoggedIn && tldList.length > MAX_ANON) {
      toast.warning(t("batch_check.warn_anon_limit", { max: MAX_ANON }));
    } else if (effectiveTlds.length > 50) {
      toast.info(t("batch_check.warn_large_batch", { count: effectiveTlds.length }));
    }

    const domains = effectiveTlds.map(tld => `${cleanPrefix}.${tld}`);

    setResults(new Map());
    setProgress({ done: 0, total: domains.length });
    setChecking(true);
    stopRef.current = false;

    // Insert "checking" placeholders immediately for visual feedback
    const placeholders = new Map<string, BatchItem>();
    for (const d of domains) {
      placeholders.set(d, { domain: d, status: false, time: 0, error: "checking" });
    }
    setResults(new Map(placeholders));

    // Process in chunks sequentially
    for (let i = 0; i < domains.length; i += CHUNK_SIZE) {
      if (stopRef.current) break;
      const chunk = domains.slice(i, i + CHUNK_SIZE);

      try {
        const res = await fetch("/api/lookup-batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domains: chunk }),
        });

        if (res.status === 401) { toast.error(t("batch_check.err_login_required")); break; }
        if (res.status === 429) { toast.error("Rate limit exceeded, please wait"); break; }
        if (!res.ok) { toast.error(`Error ${res.status}`); break; }

        const data = await res.json();
        const items: BatchItem[] = data.items ?? [];

        setResults(prev => {
          const next = new Map(prev);
          for (const item of items) next.set(item.domain, item);
          return next;
        });
        setProgress(prev => ({ ...prev, done: prev.done + items.length }));
      } catch {
        // network error — mark chunk as error
        setResults(prev => {
          const next = new Map(prev);
          for (const d of chunk) {
            next.set(d, { domain: d, status: false, time: 0, error: "Network error" });
          }
          return next;
        });
        setProgress(prev => ({ ...prev, done: prev.done + chunk.length }));
      }
    }

    setChecking(false);
  };

  const handleStop = () => { stopRef.current = true; };

  const handleClear = () => {
    setResults(new Map());
    setProgress({ done: 0, total: 0 });
    setChecking(false);
  };

  // ── Export / Copy ─────────────────────────────────────────────────────────
  const exportCsv = () => {
    const rows = [["Domain", "Status", "Registrar", "Expires", "Cached"]];
    for (const item of results.values()) {
      const st = item.error === "checking" ? "checking" : getDomainStatus(item);
      rows.push([
        item.domain,
        st,
        item.result?.registrar ?? "",
        item.result?.expirationDate ?? "",
        item.cached ? "yes" : "no",
      ]);
    }
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `batch-check-${prefix || "result"}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const copyAvailable = () => {
    const avail = [...results.values()]
      .filter(i => i.error !== "checking" && getDomainStatus(i) === "available")
      .map(i => i.domain)
      .join("\n");
    if (!avail) { toast.info("No available domains found"); return; }
    navigator.clipboard.writeText(avail).then(() => toast.success(t("batch_check.btn_copy_available") + " ✓"));
  };

  // ── Filtered results ──────────────────────────────────────────────────────
  const allItems = [...results.values()].filter(i => i.error !== "checking" || checking);
  const filteredItems = allItems.filter(item => {
    if (item.error === "checking") return true;
    const st = getDomainStatus(item);
    if (filter === "available") return st === "available" || st === "premium";
    if (filter === "registered") return st === "registered" || st === "reserved";
    return true;
  });

  const countAvail = allItems.filter(i => i.error !== "checking" && (getDomainStatus(i) === "available" || getDomainStatus(i) === "premium")).length;
  const countReg   = allItems.filter(i => i.error !== "checking" && (getDomainStatus(i) === "registered" || getDomainStatus(i) === "reserved")).length;
  const hasResults = results.size > 0;

  const FADE = { duration: 0.15 };

  const presets: { id: TldPreset; label: string }[] = [
    { id: "popular", label: t("batch_check.tld_preset_popular") },
    { id: "gtld",    label: t("batch_check.tld_preset_gtld") },
    { id: "cctld",   label: t("batch_check.tld_preset_cctld") },
    { id: "all",     label: t("batch_check.tld_preset_all") },
    { id: "custom",  label: t("batch_check.tld_preset_custom") },
  ];

  return (
    <>
      <Head>
        <title key="title">{`${t("batch_check.page_title")} — ${siteLabel}`}</title>
      </Head>

      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-3xl mx-auto px-4 sm:px-6 py-6">

          {/* Header */}
          <div className="flex items-center gap-3 mb-6">
            <Link
              href="/tools"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-teal-500/10 text-teal-600 dark:text-teal-400">
                <RiSearchLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("batch_check.page_title")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("batch_check.page_subtitle")}</p>
              </div>
            </div>
          </div>

          {/* Input card */}
          <div className="rounded-2xl border border-border bg-card p-5 mb-4 space-y-4">

            {/* Prefix input */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                {t("batch_check.input_label")}
              </label>
              <Input
                value={prefix}
                onChange={e => setPrefix(e.target.value)}
                placeholder={t("batch_check.input_placeholder")}
                className="font-mono"
                onKeyDown={e => { if (e.key === "Enter" && !checking) handleCheck(); }}
                disabled={checking}
              />
            </div>

            {/* TLD group picker */}
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                {t("batch_check.tld_group_label")}
              </label>
              <div className="flex flex-wrap gap-2">
                {presets.map(p => (
                  <button
                    key={p.id}
                    onClick={() => setPreset(p.id)}
                    className={cn(
                      "px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
                      preset === p.id
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-muted/30 text-muted-foreground border-border hover:border-primary/40 hover:text-foreground"
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              {/* Popular TLD chips preview */}
              {preset === "popular" && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {POPULAR_TLDS.map(tld => (
                    <span key={tld} className="px-2 py-0.5 rounded-md bg-muted/50 text-muted-foreground text-[10px] font-mono border border-border/50">
                      .{tld}
                    </span>
                  ))}
                </div>
              )}

              {/* Custom TLD textarea */}
              {preset === "custom" && (
                <TextArea
                  value={customTlds}
                  onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setCustomTlds(e.target.value)}
                  placeholder={t("batch_check.custom_tld_placeholder")}
                  rows={3}
                  className="font-mono text-xs resize-none"
                />
              )}
            </div>

            {/* Login notice */}
            {!isLoggedIn && (
              <div className="flex items-center gap-2 rounded-lg bg-amber-500/8 border border-amber-500/20 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
                <RiLoginBoxLine className="w-4 h-4 shrink-0" />
                <span>
                  {t("batch_check.info_login_for_more")} —{" "}
                  <Link href="/login" className="underline underline-offset-2 font-semibold">
                    {t("nav_login")}
                  </Link>
                </span>
              </div>
            )}

            {/* Action buttons */}
            <div className="flex gap-2">
              {!checking ? (
                <Button
                  onClick={handleCheck}
                  className="flex-1 gap-2"
                  disabled={!prefix.trim()}
                >
                  <RiSearchLine className="w-4 h-4" />
                  {t("batch_check.btn_check")}
                </Button>
              ) : (
                <Button
                  onClick={handleStop}
                  variant="destructive"
                  className="flex-1 gap-2"
                >
                  <RiStopCircleLine className="w-4 h-4" />
                  {t("batch_check.btn_stop")}
                </Button>
              )}
              {hasResults && !checking && (
                <Button variant="outline" size="icon" onClick={handleClear} title={t("batch_check.btn_clear")}>
                  <RiDeleteBinLine className="w-4 h-4" />
                </Button>
              )}
            </div>
          </div>

          {/* Progress bar */}
          {(checking || (hasResults && progress.total > 0)) && (
            <div className="mb-4 space-y-1">
              <div className="flex justify-between text-[11px] text-muted-foreground">
                <span>
                  {checking ? t("batch_check.status_checking") : t("batch_check.status_done")}
                  {" "}{progress.done}/{progress.total}
                </span>
                <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                  {countAvail > 0 && t("batch_check.summary_available", { count: countAvail })}
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full bg-teal-500 rounded-full transition-all duration-300"
                  style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }}
                />
              </div>
            </div>
          )}

          {/* Results area */}
          <AnimatePresence>
            {hasResults && (
              <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={FADE}>

                {/* Toolbar */}
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div className="flex gap-1.5">
                    {(["all", "available", "registered"] as ResultFilter[]).map(f => (
                      <button
                        key={f}
                        onClick={() => setFilter(f)}
                        className={cn(
                          "px-3 py-1 rounded-lg text-xs font-semibold border transition-all",
                          filter === f
                            ? "bg-primary text-primary-foreground border-primary"
                            : "bg-muted/30 text-muted-foreground border-border hover:border-primary/30"
                        )}
                      >
                        {t(`batch_check.filter_${f}` as any)}
                        {f === "all" && <span className="ml-1 opacity-60">{allItems.filter(i => i.error !== "checking").length}</span>}
                        {f === "available" && <span className="ml-1 opacity-60">{countAvail}</span>}
                        {f === "registered" && <span className="ml-1 opacity-60">{countReg}</span>}
                      </button>
                    ))}
                  </div>
                  <div className="flex gap-1.5">
                    <Button variant="outline" size="sm" className="gap-1.5 text-xs h-7 px-2.5" onClick={copyAvailable}>
                      <RiFileCopyLine className="w-3.5 h-3.5" />
                      {t("batch_check.btn_copy_available")}
                    </Button>
                    <Button variant="outline" size="sm" className="gap-1.5 text-xs h-7 px-2.5" onClick={exportCsv}>
                      <RiDownloadLine className="w-3.5 h-3.5" />
                      {t("batch_check.btn_export_csv")}
                    </Button>
                  </div>
                </div>

                {/* Result list */}
                <div className="rounded-2xl border border-border bg-card overflow-hidden divide-y divide-border">
                  {filteredItems.map(item => {
                    const isChecking = item.error === "checking";
                    const st = isChecking ? "checking" : getDomainStatus(item);
                    const isAvail = st === "available" || st === "premium";

                    return (
                      <div
                        key={item.domain}
                        className={cn(
                          "flex items-center gap-3 px-4 py-3 transition-colors",
                          isAvail && !isChecking && "bg-emerald-500/3 hover:bg-emerald-500/6",
                          !isAvail && !isChecking && "hover:bg-muted/30",
                          isChecking && "opacity-50"
                        )}
                      >
                        {/* Status icon */}
                        <div className="shrink-0 w-4">
                          {isChecking   ? <RiTimeLine className="w-4 h-4 text-muted-foreground animate-spin" /> :
                           isAvail      ? <RiCheckboxCircleLine className="w-4 h-4 text-emerald-500" /> :
                           st === "error" ? <RiErrorWarningLine className="w-4 h-4 text-red-400" /> :
                                           <RiCloseCircleLine className="w-4 h-4 text-muted-foreground/50" />}
                        </div>

                        {/* Domain name */}
                        <div className="flex-1 min-w-0">
                          {isAvail && !isChecking ? (
                            <a
                              href={`/${item.domain}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-sm font-semibold text-emerald-600 dark:text-emerald-400 hover:underline truncate block"
                            >
                              {item.domain}
                            </a>
                          ) : (
                            <a
                              href={`/${item.domain}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-sm text-foreground hover:text-primary hover:underline truncate block transition-colors"
                            >
                              {item.domain}
                            </a>
                          )}
                          {item.result?.registrar && !isChecking && (
                            <p className="text-[10px] text-muted-foreground truncate mt-0.5">
                              {item.result.registrar}
                              {item.result.expirationDate ? ` · ${item.result.expirationDate.slice(0, 10)}` : ""}
                            </p>
                          )}
                        </div>

                        {/* Status badge */}
                        <div className="shrink-0 flex items-center gap-2">
                          {item.cached && !isChecking && (
                            <span className="text-[9px] text-muted-foreground/50 font-mono uppercase tracking-wide">cached</span>
                          )}
                          <StatusBadge status={st} />
                        </div>
                      </div>
                    );
                  })}

                  {filteredItems.length === 0 && (
                    <div className="py-12 text-center text-sm text-muted-foreground">
                      {t(`batch_check.filter_${filter}` as any)} — 0
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

        </main>
      </ScrollArea>
    </>
  );
}
