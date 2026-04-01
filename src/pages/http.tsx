import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiArrowLeftSLine, RiLoader4Line, RiCheckLine, RiAlertLine,
  RiArrowRightLine, RiFileCopyLine, RiWifiLine, RiWifiOffLine,
  RiTimeLine, RiLink, RiServerLine, RiRefreshLine, RiShieldCheckLine,
  RiShieldLine, RiSearchLine, RiLockLine, RiExternalLinkLine,
  RiInformationLine, RiCloseLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import { toast } from "sonner";
import type { HttpCheckResult, SecurityHeader } from "@/pages/api/http/check";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1400); }}
      className="p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground shrink-0 touch-manipulation"
    >
      {copied ? <RiCheckLine className="w-3 h-3 text-emerald-500" /> : <RiFileCopyLine className="w-3 h-3" />}
    </button>
  );
}

function StatusBadge({ code }: { code: number }) {
  const color =
    code >= 200 && code < 300 ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-400/30" :
    code >= 300 && code < 400 ? "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-400/30" :
    code >= 400 ? "bg-red-500/15 text-red-600 dark:text-red-400 border-red-400/30" :
    "bg-muted/50 text-muted-foreground border-border/40";
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold border", color)}>
      {code}
    </span>
  );
}

function InfoRow({ label, value, mono, copyable }: {
  label: string; value?: string | number | null; mono?: boolean; copyable?: boolean;
}) {
  if (value === null || value === undefined || value === "") return null;
  const str = String(value);
  return (
    <div className="flex items-start gap-2 py-2 border-b border-border/30 last:border-0">
      <span className="text-xs text-muted-foreground shrink-0 w-28 pt-0.5">{label}</span>
      <div className="flex items-center gap-1 flex-1 min-w-0">
        <span className={cn("text-xs break-all flex-1", mono && "font-mono")}>{str}</span>
        {copyable && str && <CopyButton text={str} />}
      </div>
    </div>
  );
}

function ScoreRing({ score }: { score: number }) {
  const r = 20;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const color = score >= 80 ? "#22c55e" : score >= 50 ? "#f59e0b" : score >= 25 ? "#f97316" : "#ef4444";
  const textColor = score >= 80 ? "text-emerald-600 dark:text-emerald-400" : score >= 50 ? "text-amber-600 dark:text-amber-400" : score >= 25 ? "text-orange-600 dark:text-orange-400" : "text-red-600 dark:text-red-400";
  return (
    <div className="relative w-12 h-12 shrink-0">
      <svg viewBox="0 0 48 48" className="w-12 h-12 -rotate-90">
        <circle cx="24" cy="24" r={r} fill="none" stroke="currentColor" strokeWidth="4" className="text-muted/30" />
        <circle
          cx="24" cy="24" r={r} fill="none" stroke={color} strokeWidth="4"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className={cn("text-[10px] font-bold tabular-nums leading-none", textColor)}>{score}</span>
      </div>
    </div>
  );
}

function SecurityHeaderRow({ h }: { h: SecurityHeader }) {
  const [expanded, setExpanded] = React.useState(false);
  const severityColor = h.severity === "critical" ? "text-red-500" : h.severity === "high" ? "text-orange-500" : h.severity === "medium" ? "text-amber-500" : "text-muted-foreground";
  return (
    <div className="border-b border-border/30 last:border-0">
      <div
        className="flex items-center gap-2 py-2 cursor-pointer hover:bg-muted/10 transition-colors px-1 -mx-1 rounded"
        onClick={() => h.value && setExpanded(v => !v)}
      >
        <div className={cn("w-4 h-4 rounded-full flex items-center justify-center shrink-0",
          h.present ? "bg-emerald-100 dark:bg-emerald-950/40" : "bg-red-100 dark:bg-red-950/30")}>
          {h.present
            ? <RiCheckLine className="w-2.5 h-2.5 text-emerald-600 dark:text-emerald-400" />
            : <RiCloseLine className="w-2.5 h-2.5 text-red-500" />}
        </div>
        <span className="text-xs font-mono font-medium flex-1 truncate min-w-0">{h.name}</span>
        <span className={cn("text-[9px] font-bold uppercase shrink-0", severityColor)}>{h.severity}</span>
        {h.value && <RiInformationLine className="w-3 h-3 text-muted-foreground/50 shrink-0" />}
      </div>
      {expanded && h.value && (
        <div className="px-1 pb-2">
          <code className="text-[10px] text-muted-foreground break-all font-mono block bg-muted/30 rounded p-2">{h.value}</code>
        </div>
      )}
    </div>
  );
}

const FADE = { duration: 0.18, ease: "easeOut" as const };

const EXAMPLES = ["https://google.com", "https://github.com", "https://cloudflare.com"];

export default function HttpCheckPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteLabel = settings.site_logo_text || "X.RW";

  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<HttpCheckResult | null>(null);

  React.useEffect(() => {
    if (!router.isReady) return;
    const q = router.query.q as string;
    if (q) {
      const normalized = q.startsWith("http") ? q : `https://${q}`;
      setInput(normalized);
      setTimeout(() => runCheck(normalized), 80);
    }
  }, [router.isReady]);

  async function runCheck(urlToCheck?: string) {
    const raw = (urlToCheck ?? input).trim();
    if (!raw) { toast.error(t("http.err_invalid_url")); return; }
    const normalized = raw.startsWith("http") ? raw : `https://${raw}`;

    setLoading(true);
    setResult(null);
    router.replace({ pathname: "/http", query: { q: normalized } }, undefined, { locale: false, shallow: true });

    try {
      const r = await fetch(`/api/http/check?url=${encodeURIComponent(normalized)}`);
      const data: HttpCheckResult = await r.json();
      setResult(data);
    } catch {
      toast.error(t("http.err_fetch_failed"));
    } finally {
      setLoading(false);
    }
  }

  const isOnline  = result?.ok === true;
  const isOffline = result?.ok === false;
  const hasSecurityData = (result?.securityHeaders?.length ?? 0) > 0;
  const presentCount  = result?.securityHeaders?.filter(h => h.present).length ?? 0;
  const totalCount    = result?.securityHeaders?.length ?? 0;

  return (
    <>
      <Head>
        <title key="title">{`${t("http.page_title")} — ${siteLabel}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-6 space-y-5">
          <div className="flex items-center gap-3">
            <Link href="/" className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground touch-manipulation">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400">
                <RiWifiLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("http.page_title")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("http.page_subtitle")}</p>
              </div>
            </div>
          </div>

          <form onSubmit={e => { e.preventDefault(); runCheck(); }} className="flex gap-2">
            <div className="relative flex-1">
              <RiLink className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
              <Input
                value={input}
                onChange={e => setInput(e.target.value)}
                placeholder={t("http.placeholder")}
                className="pl-9 h-10 rounded-xl font-mono text-base sm:text-sm"
                disabled={loading}
                autoFocus
              />
            </div>
            <Button type="submit" disabled={loading || !input.trim()} className="h-10 px-4 rounded-xl gap-2 shrink-0">
              {loading ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSearchLine className="w-4 h-4" />}
              {t("http.btn_check")}
            </Button>
            {result && (
              <Button type="button" variant="outline" onClick={() => runCheck(result.url)} disabled={loading}
                className="h-10 w-10 px-0 rounded-xl shrink-0">
                <RiRefreshLine className="w-4 h-4" />
              </Button>
            )}
          </form>

          <AnimatePresence mode="wait" initial={false}>
            {loading ? (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="flex flex-col items-center justify-center py-16 gap-4">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-full border-2 border-blue-500/20" />
                    <RiLoader4Line className="w-6 h-6 animate-spin text-blue-500 absolute inset-0 m-auto" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium">{t("http.loading")}</p>
                    <p className="text-xs text-muted-foreground mt-1">{t("http.loading_sub")}</p>
                  </div>
                </div>
              </motion.div>
            ) : result ? (
              <motion.div key="result" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE} className="space-y-4">

                {/* Status banner */}
                <div className={cn(
                  "glass-panel border rounded-2xl p-4 flex items-center gap-3",
                  isOnline
                    ? "border-emerald-300 dark:border-emerald-800"
                    : "border-red-300 dark:border-red-800"
                )}>
                  <div className={cn(
                    "w-10 h-10 rounded-xl flex items-center justify-center shrink-0",
                    isOnline ? "bg-emerald-100 dark:bg-emerald-950/40" : "bg-red-100 dark:bg-red-950/30"
                  )}>
                    {isOnline
                      ? <RiWifiLine className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                      : <RiWifiOffLine className="w-5 h-5 text-red-500 dark:text-red-400" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={cn("font-semibold", isOnline ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400")}>
                      {isOnline ? t("http.label_online") : t("http.label_offline")}
                    </p>
                    {result.error && <p className="text-xs text-red-600 dark:text-red-400 mt-0.5">{result.error}</p>}
                    {result.finalUrl && result.finalUrl !== result.url && (
                      <p className="text-[11px] text-muted-foreground mt-0.5 font-mono truncate">{result.finalUrl}</p>
                    )}
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0">
                    {result.statusCode !== null && <StatusBadge code={result.statusCode} />}
                    {result.latencyMs !== null && (
                      <span className="text-[11px] text-muted-foreground tabular-nums flex items-center gap-1">
                        <RiTimeLine className="w-3 h-3" />{result.latencyMs}ms
                      </span>
                    )}
                  </div>
                </div>

                {/* Response Details */}
                <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                    <RiServerLine className="w-3.5 h-3.5 text-muted-foreground" />
                    <h3 className="text-sm font-bold">{t("http.section_details")}</h3>
                    {result.finalUrl && (
                      <a href={result.finalUrl} target="_blank" rel="noopener noreferrer"
                        className="ml-auto flex items-center gap-1 text-[10px] text-primary hover:underline">
                        {t("http.open_link")} <RiExternalLinkLine className="w-2.5 h-2.5" />
                      </a>
                    )}
                  </div>
                  <div className="px-4">
                    <InfoRow label={t("http.result_url")}          value={result.finalUrl}         mono copyable />
                    <InfoRow label={t("http.result_status")}       value={result.statusCode !== null ? `${result.statusCode}${result.statusText ? ` ${result.statusText}` : ""}` : undefined} />
                    <InfoRow label={t("http.result_latency")}      value={result.latencyMs !== null ? `${result.latencyMs} ms` : undefined} />
                    <InfoRow label={t("http.result_server")}       value={result.server}           mono />
                    <InfoRow label={t("http.result_content_type")} value={result.contentType}      mono />
                    <InfoRow label={t("http.result_content_len")}  value={result.contentLength !== null ? `${(result.contentLength / 1024).toFixed(1)} KB` : null} />
                    <InfoRow label={t("http.result_powered_by")}   value={result.xPoweredBy}       mono />
                    <InfoRow label={t("http.result_cache")}        value={result.cacheControl}     mono />
                    <InfoRow label={t("http.result_via")}          value={result.via}              mono />
                  </div>
                </div>

                {/* Redirect chain */}
                {result.redirectChain.length > 0 && (
                  <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                      <RiArrowRightLine className="w-3.5 h-3.5 text-muted-foreground" />
                      <h3 className="text-sm font-bold">{t("http.redirect_chain")}</h3>
                      <span className="ml-auto text-xs text-muted-foreground">{result.redirectChain.length} {t("http.redirect_hops")}</span>
                    </div>
                    <div className="px-4 py-3 space-y-2">
                      {result.redirectChain.map((hop, i) => (
                        <div key={i} className="flex items-center gap-2">
                          <StatusBadge code={hop.status} />
                          <code className="text-[11px] font-mono text-muted-foreground flex-1 truncate min-w-0">{hop.url}</code>
                          <CopyButton text={hop.url} />
                        </div>
                      ))}
                      <div className="flex items-center gap-2 pt-1 border-t border-border/30">
                        <RiCheckLine className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                        <code className="text-[11px] font-mono flex-1 truncate min-w-0">{result.finalUrl}</code>
                        <CopyButton text={result.finalUrl} />
                      </div>
                    </div>
                  </div>
                )}

                {/* Security Headers */}
                {hasSecurityData && (
                  <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                    <div className="px-4 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                      <RiShieldCheckLine className="w-3.5 h-3.5 text-muted-foreground" />
                      <h3 className="text-sm font-bold">{t("http.section_security")}</h3>
                      <span className="ml-2 text-xs text-muted-foreground">{presentCount}/{totalCount} {t("http.security_present")}</span>
                      <div className="ml-auto">
                        <ScoreRing score={result.securityScore} />
                      </div>
                    </div>

                    {/* HSTS badge for HTTPS */}
                    {result.finalUrl?.startsWith("https://") && (
                      <div className={cn(
                        "mx-4 mt-3 mb-0 px-3 py-2 rounded-xl border flex items-center gap-2",
                        result.hsts
                          ? "bg-emerald-50/60 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800"
                          : "bg-amber-50/60 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800"
                      )}>
                        <RiLockLine className={cn("w-3.5 h-3.5 shrink-0", result.hsts ? "text-emerald-600" : "text-amber-600")} />
                        <div className="flex-1 min-w-0">
                          <p className={cn("text-[11px] font-semibold", result.hsts ? "text-emerald-700 dark:text-emerald-400" : "text-amber-700 dark:text-amber-400")}>
                            {result.hsts ? t("http.hsts_enabled") : t("http.hsts_missing")}
                          </p>
                          {result.hsts && <p className="text-[10px] text-muted-foreground font-mono truncate">{result.hsts}</p>}
                        </div>
                      </div>
                    )}

                    <div className="px-4 py-2">
                      {result.securityHeaders.map(h => (
                        <SecurityHeaderRow key={h.key} h={h} />
                      ))}
                    </div>

                    {/* Score explanation */}
                    <div className="px-4 pb-3">
                      <p className="text-[10px] text-muted-foreground/60">
                        {t("http.security_score_note")}
                      </p>
                    </div>
                  </div>
                )}

                {/* Protocol info */}
                {result.finalUrl && (
                  <div className="flex items-center gap-2 flex-wrap text-[10px] text-muted-foreground/50 pb-1">
                    <span className="flex items-center gap-1">
                      {result.finalUrl.startsWith("https://")
                        ? <RiLockLine className="w-3 h-3 text-emerald-500" />
                        : <RiShieldLine className="w-3 h-3 text-amber-500" />}
                      {result.finalUrl.startsWith("https://") ? "HTTPS" : "HTTP (not encrypted)"}
                    </span>
                    <span>|</span>
                    <span className="flex items-center gap-1"><RiTimeLine className="w-3 h-3" />{t("http.footer_realtime")}</span>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="text-center py-14 space-y-2">
                  <div className="w-14 h-14 rounded-2xl bg-blue-500/8 border border-blue-500/20 flex items-center justify-center mx-auto mb-4">
                    <RiWifiLine className="w-7 h-7 text-blue-500/60" />
                  </div>
                  <p className="text-sm font-medium text-muted-foreground">{t("http.empty_title")}</p>
                  <p className="text-xs text-muted-foreground/60">{t("http.empty_subtitle")}</p>
                  <div className="flex justify-center gap-2 mt-4 flex-wrap">
                    {EXAMPLES.map(ex => (
                      <button key={ex} onClick={() => { setInput(ex); runCheck(ex); }}
                        className="text-[11px] font-mono px-2.5 py-1 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:border-blue-300 transition-colors touch-manipulation">
                        {ex.replace("https://", "")}
                      </button>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </ScrollArea>
    </>
  );
}
