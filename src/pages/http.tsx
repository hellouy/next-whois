import React from "react";
import Head from "next/head";
import Link from "next/link";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiArrowLeftSLine,
  RiLoader4Line,
  RiCheckLine,
  RiAlertLine,
  RiArrowRightLine,
  RiFileCopyLine,
  RiWifiLine,
  RiWifiOffLine,
  RiTimeLine,
  RiLink,
  RiServerLine,
  RiRefreshLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import { toast } from "sonner";
import type { HttpCheckResult } from "@/pages/api/http/check";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(text).catch(() => {});
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      }}
      className="p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground shrink-0"
    >
      {copied
        ? <RiCheckLine className="w-3 h-3 text-emerald-500" />
        : <RiFileCopyLine className="w-3 h-3" />}
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
      <span className="text-xs text-muted-foreground shrink-0 w-24 pt-0.5">{label}</span>
      <div className="flex items-center gap-1 flex-1 min-w-0">
        <span className={cn("text-xs break-all flex-1", mono && "font-mono")}>{str}</span>
        {copyable && str && <CopyButton text={str} />}
      </div>
    </div>
  );
}

export default function HttpCheckPage() {
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteLabel = settings.site_logo_text || "X.RW";

  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<HttpCheckResult | null>(null);

  async function runCheck(urlToCheck?: string) {
    const url = (urlToCheck ?? input).trim();
    if (!url) return;
    const normalized = url.startsWith("http") ? url : `https://${url}`;

    setLoading(true);
    setResult(null);
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

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") runCheck();
  }

  const isOnline = result && result.ok;
  const isOffline = result && !result.ok;

  return (
    <>
      <Head>
        <title key="title">{`${t("http.page_title")} — ${siteLabel}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-6">
          <div className="flex items-center gap-3 mb-6">
            <Link
              href="/"
              className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
            >
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

          <div className="flex gap-2 mb-6">
            <Input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={t("http.placeholder")}
              className="font-mono text-sm h-10 flex-1"
              disabled={loading}
            />
            <Button
              onClick={() => runCheck()}
              disabled={loading || !input.trim()}
              className="h-10 px-4 font-semibold shrink-0"
            >
              {loading
                ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                : t("http.btn_check")}
            </Button>
          </div>

          <AnimatePresence mode="wait">
            {loading && (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center gap-3 py-16 text-muted-foreground"
              >
                <RiLoader4Line className="w-8 h-8 animate-spin" />
                <p className="text-sm">{t("http.btn_check")}...</p>
              </motion.div>
            )}

            {result && !loading && (
              <motion.div
                key="result"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-4"
              >
                <div className={cn(
                  "rounded-2xl border p-4 flex items-center gap-3",
                  isOnline
                    ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200/70 dark:border-emerald-800/40"
                    : "bg-red-50 dark:bg-red-950/30 border-red-200/70 dark:border-red-800/40"
                )}>
                  {isOnline
                    ? <RiWifiLine className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    : <RiWifiOffLine className="w-5 h-5 text-red-500 dark:text-red-400 shrink-0" />}
                  <div className="flex-1 min-w-0">
                    <p className={cn(
                      "font-semibold text-sm",
                      isOnline ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"
                    )}>
                      {isOnline ? t("http.label_online") : t("http.label_offline")}
                    </p>
                    {result.error && (
                      <p className="text-xs text-red-600 dark:text-red-400 mt-0.5">{result.error}</p>
                    )}
                  </div>
                  {result.statusCode !== null && <StatusBadge code={result.statusCode} />}
                  {result.latencyMs !== null && (
                    <span className="text-[11px] text-muted-foreground tabular-nums shrink-0 flex items-center gap-1">
                      <RiTimeLine className="w-3 h-3" />
                      {result.latencyMs}ms
                    </span>
                  )}
                </div>

                <div className="rounded-2xl border border-border bg-card p-4">
                  <InfoRow label={t("http.result_url")}       value={result.finalUrl}      mono copyable />
                  <InfoRow label={t("http.result_status")}    value={result.statusCode !== null ? `${result.statusCode}${result.statusText ? ` ${result.statusText}` : ""}` : undefined} />
                  <InfoRow label={t("http.result_latency")}   value={result.latencyMs !== null ? `${result.latencyMs} ms` : undefined} />
                  <InfoRow label={t("http.result_server")}    value={result.server}        mono />
                  <InfoRow label={t("http.result_content_type")} value={result.contentType} mono />
                </div>

                {result.redirectChain.length > 0 && (
                  <div className="rounded-2xl border border-border bg-card p-4">
                    <p className="text-xs font-semibold text-muted-foreground mb-3 flex items-center gap-1.5">
                      <RiArrowRightLine className="w-3.5 h-3.5" />
                      {t("http.redirect_chain")} ({result.redirectChain.length})
                    </p>
                    <div className="space-y-2">
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

                <div className="flex justify-center">
                  <button
                    onClick={() => runCheck(result.url)}
                    className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors py-1 px-3 rounded-lg hover:bg-muted/60"
                  >
                    <RiRefreshLine className="w-3.5 h-3.5" />
                    {t("http.btn_check")}
                  </button>
                </div>
              </motion.div>
            )}

            {!result && !loading && (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-center py-16 text-muted-foreground/50 space-y-2"
              >
                <RiLink className="w-8 h-8 mx-auto opacity-30" />
                <p className="text-sm">{t("http.placeholder")}</p>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </ScrollArea>
    </>
  );
}
