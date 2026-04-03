import React from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiServerLine,
  RiFlashlightLine,
  RiFileCopyLine,
  RiAlertLine,
  RiLoader4Line,
  RiRefreshLine,
  RiTimeLine,
  RiCloudLine,
  RiCheckLine,
  RiFileTextLine,
  RiLinksLine,
  RiCheckboxCircleLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { Button } from "@/components/ui/button";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

const POLL_SCHEDULE = [30, 60, 120, 300, 600, 900, 1200] as const;
const AUTO_POLL_SEC = POLL_SCHEDULE[0];

interface SubmitResult {
  id: string;
  txtRecord: string;
  txtValue: string;
}

interface ResolverResult {
  name: string;
  proto?: string;
  latencyMs: number;
  found: boolean;
  nearMatch?: boolean;
  records: string[];
  error: string | null;
}

interface HttpCheck {
  found: boolean;
  latencyMs: number;
  error: string | null;
  url: string;
  nearMatch?: boolean;
}

interface QuickTxtResult {
  found: boolean;
  flat: string[];
  records: string[][];
  latencyMs: number;
  tokenFound?: boolean;
  resolvers: { name: string; proto?: string; records: string[][]; flat?: string[]; latencyMs: number; error?: string | null }[];
}

interface VercelState {
  txtValue: string | null;
  txtFullDomain: string | null;
  apiError: string | null;
  initLoading: boolean;
  checkLoading: boolean;
  checkAttempt: number;
  countdown: number;
}

interface DnsVerificationPanelProps {
  submitResult: SubmitResult;
  domain: string;
  verifyState: "idle" | "loading" | "fail" | "dnsError" | "nearMatch" | "giveUp";
  verifyTab: "dns" | "http" | "vercel";
  resolvers: ResolverResult[];
  anyNearMatch: boolean;
  anyRecordFound: boolean;
  expectedVal: string | null;
  httpCheck: HttpCheck | null;
  pollAttempt: number;
  countdown: number;
  quickTxtLoading: boolean;
  quickTxtResult: QuickTxtResult | null;
  vercel: VercelState;
  onVerify: (silent?: boolean) => void;
  onQuickTxt: () => void;
  onTabChange: (tab: "dns" | "http" | "vercel") => void;
  onBackEdit: () => void;
  onVercelInit: () => void;
  onVercelCheck: (silent?: boolean) => void;
  onVercelCheckAttemptReset: () => void;
}

export function DnsVerificationPanel({
  submitResult,
  domain,
  verifyState,
  verifyTab,
  resolvers,
  anyNearMatch,
  anyRecordFound: _anyRecordFound,
  expectedVal,
  httpCheck,
  pollAttempt,
  countdown,
  quickTxtLoading,
  quickTxtResult,
  vercel,
  onVerify,
  onQuickTxt,
  onTabChange,
  onBackEdit,
  onVercelInit,
  onVercelCheck,
  onVercelCheckAttemptReset,
}: DnsVerificationPanelProps) {
  const { t } = useTranslation();
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  function copyText(text: string) {
    navigator.clipboard.writeText(text).then(() => toast.success(s("copied")));
  }

  const hostPrefix = submitResult.txtRecord.replace(new RegExp(`\\.${domain.replace(/\./g, "\\.")}$`), "");

  return (
    <div className="space-y-4">
      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">

        {/* Method tab switcher */}
        <div className="flex rounded-xl bg-muted/40 border border-border/50 p-1 gap-1">
          <button
            type="button"
            onClick={() => onTabChange("dns")}
            className={cn(
              "flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-semibold transition-all",
              verifyTab === "dns"
                ? "bg-background shadow-sm text-foreground border border-border/60"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <RiServerLine className="w-3.5 h-3.5 shrink-0" />
            <span className="hidden sm:inline">DNS TXT</span>
            <span className="sm:hidden">DNS</span>
          </button>
          <button
            type="button"
            onClick={() => onTabChange("http")}
            className={cn(
              "flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-semibold transition-all",
              verifyTab === "http"
                ? "bg-background shadow-sm text-foreground border border-border/60"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <RiFlashlightLine className="w-3.5 h-3.5 text-sky-500 shrink-0" />
            <span className="hidden sm:inline">{s("file_verify")}</span>
            <span className="sm:hidden">{s("file_verify_short")}</span>
          </button>
          <button
            type="button"
            onClick={() => onTabChange("vercel")}
            className={cn(
              "flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-semibold transition-all",
              verifyTab === "vercel"
                ? "bg-background shadow-sm text-foreground border border-border/60"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <span className={cn(
              "shrink-0 text-[11px] font-black leading-none",
              verifyTab === "vercel" ? "text-foreground" : "text-muted-foreground"
            )}>▲</span>
            Vercel
          </button>
        </div>

        {/* ── DNS tab ── */}
        {verifyTab === "dns" && (
          <>
            <div>
              <h2 className="text-sm font-bold flex items-center gap-2 mb-1">
                <RiServerLine className="w-4 h-4 text-sky-500" />
                {s("verify_dns_title")}
              </h2>
              <p className="text-xs text-muted-foreground">
                {s("verify_dns_desc", { sec: AUTO_POLL_SEC })}
              </p>
            </div>

            {/* DNS record table */}
            <div className="rounded-xl border border-border/60 overflow-hidden divide-y divide-border/60">
              <div className="px-3 py-2 bg-amber-50/60 dark:bg-amber-950/20 border-b border-amber-200/40">
                <p className="text-[10px] text-amber-700 dark:text-amber-400 leading-relaxed">
                  {s("host_prefix_note")}
                </p>
              </div>
              {[
                { label: s("dns_field_type"), value: "TXT", mono: false, copyable: false, note: null, color: undefined },
                { label: s("dns_field_host"), value: hostPrefix, mono: true, color: "text-violet-600 dark:text-violet-400", copyable: true, note: `${s("full_label")}: ${submitResult.txtRecord}` },
                { label: s("dns_field_value"), value: submitResult.txtValue, mono: true, color: "text-emerald-600 dark:text-emerald-400", copyable: true, note: null },
                { label: "TTL", value: s("dns_field_ttl_val"), mono: false, copyable: false, note: null, color: undefined },
              ].map((row) => (
                <div key={row.label} className="flex items-center justify-between gap-3 px-3 py-2.5 bg-muted/20">
                  <div className="shrink-0 w-20">
                    <p className="text-[10px] font-bold text-muted-foreground/70 uppercase tracking-wider">{row.label}</p>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={cn("text-xs break-all leading-relaxed", row.mono ? "font-mono" : "", row.color || "text-foreground")}>
                      {row.value}
                    </p>
                    {row.note && (
                      <p className="text-[10px] text-muted-foreground/50 mt-0.5 font-mono">{row.note}</p>
                    )}
                  </div>
                  {row.copyable && (
                    <button
                      onClick={() => copyText(row.value)}
                      className="shrink-0 p-1.5 rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                    >
                      <RiFileCopyLine className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Quick TXT check */}
            <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
              <div className="px-3 py-2 border-b border-border/40 flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <RiFlashlightLine className="w-3.5 h-3.5 text-sky-500 shrink-0" />
                  <p className="text-[11px] font-semibold text-foreground">
                    {s("quick_txt_lookup")}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onQuickTxt}
                  disabled={quickTxtLoading}
                  className={cn(
                    "flex items-center gap-1 text-[10px] font-semibold px-2.5 py-1 rounded-lg transition-all border",
                    quickTxtLoading
                      ? "bg-muted/40 text-muted-foreground border-border/40 cursor-not-allowed"
                      : "bg-sky-50 dark:bg-sky-950/30 text-sky-700 dark:text-sky-300 border-sky-200/60 dark:border-sky-800/40 hover:bg-sky-100 dark:hover:bg-sky-900/30"
                  )}
                >
                  {quickTxtLoading
                    ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                    : <RiFlashlightLine className="w-3 h-3" />}
                  {s("check_now")}
                </button>
              </div>
              <div className="px-3 py-2.5">
                {!quickTxtResult && !quickTxtLoading && (
                  <p className="text-[11px] text-muted-foreground/60 text-center py-1">
                    {s("quick_txt_lookup")}
                  </p>
                )}
                {quickTxtLoading && (
                  <div className="flex items-center gap-2 py-1">
                    <RiLoader4Line className="w-3.5 h-3.5 animate-spin text-muted-foreground/60 shrink-0" />
                    <p className="text-[11px] text-muted-foreground">{s("querying")}…</p>
                  </div>
                )}
                {quickTxtResult && !quickTxtLoading && (
                  <div className="space-y-2">
                    {quickTxtResult.tokenFound && (
                      <div className="flex items-center gap-2 rounded-lg border border-emerald-400/60 bg-emerald-50/60 dark:bg-emerald-950/30 px-3 py-2">
                        <RiCheckboxCircleLine className="w-4 h-4 text-emerald-500 shrink-0" />
                        <p className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                          {s("token_detected")}
                        </p>
                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin text-emerald-500 shrink-0 ml-auto" />
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-1.5">
                      {quickTxtResult.resolvers.map((r) => {
                        const recCount = (r.flat || r.records || []).length;
                        const hasRecords = recCount > 0;
                        return (
                          <div key={r.name} className={cn(
                            "rounded-lg border px-2.5 py-2 flex items-center gap-2",
                            hasRecords ? "border-emerald-300/60 bg-emerald-50/50 dark:bg-emerald-950/25"
                              : r.error === "timeout" ? "border-amber-200/50 bg-amber-50/30 dark:bg-amber-950/15"
                              : "border-border/50 bg-muted/10"
                          )}>
                            <div className={cn("shrink-0 w-5 h-5 rounded-md flex items-center justify-center",
                              hasRecords ? "bg-emerald-500/10" : r.error === "timeout" ? "bg-amber-500/10" : "bg-muted/30"
                            )}>
                              {hasRecords ? <RiCheckLine className="w-3 h-3 text-emerald-500" />
                                : r.error === "timeout" ? <RiTimeLine className="w-3 h-3 text-amber-500" />
                                : <RiCloudLine className="w-3 h-3 text-muted-foreground/30" />}
                            </div>
                            <div className="min-w-0 flex-1">
                              <p className={cn("text-[10px] font-semibold truncate",
                                hasRecords ? "text-emerald-700 dark:text-emerald-300"
                                  : r.error === "timeout" ? "text-amber-600 dark:text-amber-400"
                                  : "text-muted-foreground"
                              )}>{r.name}</p>
                              <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                                {hasRecords ? `${r.latencyMs}ms · ${s("records_count", { count: recCount })}`
                                  : r.error === "timeout" ? s("timeout_label")
                                  : r.error === "no_record" ? s("no_record_label")
                                  : r.error ? r.error
                                  : s("not_found_label")}
                              </p>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {(quickTxtResult.flat || []).length > 0 && (
                      <div className={cn(
                        "rounded-lg border px-2.5 py-2 space-y-1",
                        quickTxtResult.tokenFound
                          ? "border-emerald-400/60 bg-emerald-50/40 dark:bg-emerald-950/25"
                          : "border-emerald-300/50 bg-emerald-50/30 dark:bg-emerald-950/20"
                      )}>
                        <p className="text-[10px] font-bold text-emerald-700 dark:text-emerald-400 flex items-center gap-1">
                          <RiCheckLine className="w-3 h-3" />
                          {s("txt_records_found", { n: quickTxtResult.flat.length })}
                        </p>
                        {quickTxtResult.flat.slice(0, 5).map((record, i) => {
                          const isToken = record === submitResult.txtValue || record.includes(submitResult.txtValue || "");
                          return (
                            <div key={i} className="flex items-start gap-1.5">
                              <code className={cn(
                                "text-[10px] font-mono break-all leading-relaxed flex-1 rounded px-1.5 py-0.5",
                                isToken
                                  ? "text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 ring-1 ring-emerald-400/40"
                                  : "text-emerald-600 dark:text-emerald-400 bg-emerald-500/5"
                              )}>
                                {isToken && <RiCheckLine className="w-2.5 h-2.5 inline mr-1 mb-0.5" />}
                                {record}
                              </code>
                              <button onClick={() => navigator.clipboard.writeText(record).then(() => toast.success(s("copied")))}
                                className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground/50 hover:text-foreground mt-0.5">
                                <RiFileCopyLine className="w-2.5 h-2.5" />
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    )}
                    {(quickTxtResult.flat || []).length === 0 && (
                      <p className="text-[11px] text-muted-foreground/70 text-center py-0.5">
                        {s("add_txt_first")}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* DNS status grid — DoH only */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                  <RiCloudLine className="w-3 h-3" />
                  {s("parallel_check")}
                </p>
                <span className="flex items-center gap-0.5 text-[10px] text-muted-foreground/50">
                  <RiCloudLine className="w-2.5 h-2.5" />DoH
                </span>
              </div>
              {(() => {
                const PLACEHOLDER_RESOLVERS = [
                  { name: "Google DoH",     proto: "doh" },
                  { name: "Cloudflare DoH", proto: "doh" },
                  { name: "Quad9 DoH",      proto: "doh" },
                  { name: "AdGuard DoH",    proto: "doh" },
                ];
                const isLoading = verifyState === "loading";
                const displayList = isLoading && resolvers.length === 0
                  ? PLACEHOLDER_RESOLVERS
                  : resolvers;
                return (
                  <div className="grid grid-cols-2 gap-1.5">
                    {displayList.map((item, i) => {
                      const r = resolvers[i];
                      return (
                        <div
                          key={item.name}
                          className={cn(
                            "rounded-lg border px-2.5 py-2 flex items-center gap-2 transition-all",
                            r?.found
                              ? "border-emerald-300/60 bg-emerald-50/50 dark:bg-emerald-950/25"
                              : r?.nearMatch
                              ? "border-orange-300/60 bg-orange-50/40 dark:bg-orange-950/20"
                              : r?.error === "timeout"
                              ? "border-amber-200/50 bg-amber-50/30 dark:bg-amber-950/15"
                              : "border-border/50 bg-muted/15"
                          )}
                        >
                          <div className={cn(
                            "shrink-0 w-6 h-6 rounded-md flex items-center justify-center",
                            r?.found ? "bg-emerald-500/10"
                              : r?.nearMatch ? "bg-orange-500/10"
                              : r?.error === "timeout" ? "bg-amber-500/10"
                              : "bg-muted/40"
                          )}>
                            {isLoading
                              ? <RiLoader4Line className="w-3 h-3 animate-spin text-muted-foreground/60" />
                              : r?.found
                              ? <RiCheckLine className="w-3 h-3 text-emerald-500" />
                              : r?.nearMatch
                              ? <RiAlertLine className="w-3 h-3 text-orange-500" />
                              : r?.error === "timeout"
                              ? <RiTimeLine className="w-3 h-3 text-amber-500" />
                              : <RiCloudLine className="w-3 h-3 text-muted-foreground/30" />
                            }
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className={cn(
                              "text-[11px] font-semibold leading-none truncate",
                              r?.found ? "text-emerald-700 dark:text-emerald-300"
                                : r?.nearMatch ? "text-orange-600 dark:text-orange-400"
                                : r?.error === "timeout" ? "text-amber-600 dark:text-amber-400"
                                : "text-muted-foreground"
                            )}>{item.name}</p>
                            <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                              {isLoading ? s("checking")
                                : r?.found ? `${r.latencyMs}ms ✓`
                                : r?.nearMatch ? s("token_mismatch")
                                : r?.error === "timeout" ? s("timeout")
                                : r?.error === "servfail" ? "SERVFAIL"
                                : r?.error ? s("not_found_dns")
                                : s("waiting")}
                            </p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                );
              })()}
            </div>
          </>
        )}

        {/* ── HTTP File tab ── */}
        {verifyTab === "http" && (
          <>
            <div>
              <h2 className="text-sm font-bold flex items-center gap-2 mb-1">
                <RiFileTextLine className="w-4 h-4 text-sky-500" />
                {s("file_verify")}
              </h2>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {s("file_verify_desc")}
              </p>
            </div>

            <div className="space-y-2.5">
              <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                  <span className="w-4 h-4 rounded-full bg-sky-500 text-white text-[9px] font-bold flex items-center justify-center shrink-0">1</span>
                  <p className="text-[11px] font-semibold text-foreground">
                    {s("file_verify_step1")}
                  </p>
                </div>
                <div className="px-3 py-2.5 space-y-2">
                  <div>
                    <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                      <RiLinksLine className="w-2.5 h-2.5" />
                      {s("file_path_label")}
                    </p>
                    <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                      <code className="text-[11px] font-mono text-violet-600 dark:text-violet-400 flex-1 break-all">
                        {`/.well-known/next-whois-verify.txt`}
                      </code>
                      <button
                        onClick={() => copyText(`/.well-known/next-whois-verify.txt`)}
                        className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                      >
                        <RiFileCopyLine className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  <div>
                    <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                      <RiFileTextLine className="w-2.5 h-2.5" />
                      {s("file_content_label")}
                    </p>
                    <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                      <code className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex-1 break-all">
                        {submitResult.txtValue}
                      </code>
                      <button
                        onClick={() => copyText(submitResult.txtValue)}
                        className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                      >
                        <RiFileCopyLine className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                  <span className="w-4 h-4 rounded-full bg-sky-500 text-white text-[9px] font-bold flex items-center justify-center shrink-0">2</span>
                  <p className="text-[11px] font-semibold text-foreground">
                    {s("file_verify_step2")}
                  </p>
                </div>
                <div className="px-3 py-2.5">
                  <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                    <RiLinksLine className="w-3 h-3 text-muted-foreground/50 shrink-0" />
                    <code className="text-[11px] font-mono text-sky-600 dark:text-sky-400 flex-1 break-all">
                      {`https://${domain}/.well-known/next-whois-verify.txt`}
                    </code>
                    <button
                      onClick={() => copyText(`https://${domain}/.well-known/next-whois-verify.txt`)}
                      className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                    >
                      <RiFileCopyLine className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {httpCheck && (
              <div className={cn(
                "flex items-center gap-3 px-3 py-3 rounded-xl border transition-all",
                httpCheck.found
                  ? "border-emerald-300/60 bg-emerald-50/50 dark:bg-emerald-950/25"
                  : httpCheck.error === "timeout"
                  ? "border-amber-200/50 bg-amber-50/30 dark:bg-amber-950/15"
                  : "border-border/50 bg-muted/20"
              )}>
                <div className={cn(
                  "shrink-0 w-8 h-8 rounded-lg flex items-center justify-center",
                  httpCheck.found ? "bg-emerald-500/10"
                    : httpCheck.error === "timeout" ? "bg-amber-500/10"
                    : "bg-muted/40"
                )}>
                  {verifyState === "loading"
                    ? <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground/60" />
                    : httpCheck.found
                    ? <RiCheckLine className="w-4 h-4 text-emerald-500" />
                    : httpCheck.error === "timeout"
                    ? <RiTimeLine className="w-4 h-4 text-amber-500" />
                    : <RiFileTextLine className="w-4 h-4 text-muted-foreground/40" />
                  }
                </div>
                <div className="min-w-0 flex-1">
                  <p className={cn(
                    "text-xs font-semibold",
                    httpCheck.found ? "text-emerald-700 dark:text-emerald-300"
                      : httpCheck.error === "timeout" ? "text-amber-600 dark:text-amber-400"
                      : "text-muted-foreground"
                  )}>
                    {httpCheck.found
                      ? s("file_found")
                      : httpCheck.error === "timeout"
                      ? s("request_timeout")
                      : httpCheck.error
                      ? s("file_not_found_err").replace("{{error}}", httpCheck.error)
                      : s("file_not_found")}
                  </p>
                  <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                    {s("http_check")} · {httpCheck.latencyMs}ms
                  </p>
                </div>
              </div>
            )}
            {!httpCheck && verifyState === "loading" && (
              <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl border border-border/50 bg-muted/20">
                <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground/60 shrink-0" />
                <p className="text-xs text-muted-foreground">{s("checking_file")}</p>
              </div>
            )}
          </>
        )}

        {/* ── Vercel tab ── */}
        {verifyTab === "vercel" && (
          <>
            <div>
              <h2 className="text-sm font-bold flex items-center gap-2 mb-1">
                <span className="text-sm font-black">▲</span>
                {s("vercel_verify_title")}
              </h2>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {s("vercel_verify_desc")}
              </p>
            </div>

            {vercel.initLoading && (
              <div className="flex items-center gap-2 px-3 py-3 rounded-xl border border-border/50 bg-muted/20">
                <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground/60 shrink-0" />
                <p className="text-xs text-muted-foreground">{s("fetching_record")}</p>
              </div>
            )}

            {vercel.apiError && !vercel.initLoading && (
              <div className="rounded-xl border border-red-300/50 bg-red-50/40 dark:bg-red-950/20 p-3 space-y-2">
                <p className="text-xs font-semibold text-red-700 dark:text-red-400 flex items-center gap-1.5">
                  <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
                  {s("network_error_retry")}
                </p>
                <p className="text-[10px] text-red-600/70 dark:text-red-400/60 font-mono break-all">{vercel.apiError}</p>
                <button
                  type="button"
                  onClick={onVercelInit}
                  className="text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline flex items-center gap-1"
                >
                  <RiRefreshLine className="w-3 h-3" />
                  {t("common.retry")}
                </button>
              </div>
            )}

            {vercel.txtValue && !vercel.initLoading && (
              <div className="space-y-2.5">
                <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                  <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                    <span className="w-4 h-4 rounded-full bg-foreground text-background text-[9px] font-bold flex items-center justify-center shrink-0">1</span>
                    <p className="text-[11px] font-semibold text-foreground">
                      {s("add_txt_record")}
                    </p>
                  </div>
                  <div className="px-3 py-2.5 space-y-2">
                    <div>
                      <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                        <RiServerLine className="w-2.5 h-2.5" />
                        {s("record_name")}
                      </p>
                      <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                        <code className="text-[11px] font-mono text-violet-600 dark:text-violet-400 flex-1 break-all">
                          {vercel.txtFullDomain ?? `_vercel.${domain}`}
                        </code>
                        <button
                          onClick={() => copyText(vercel.txtFullDomain ?? `_vercel.${domain}`)}
                          className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                        >
                          <RiFileCopyLine className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                        <RiFileTextLine className="w-2.5 h-2.5" />
                        {s("record_value")}
                      </p>
                      <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                        <code className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex-1 break-all">
                          {vercel.txtValue}
                        </code>
                        <button
                          onClick={() => copyText(vercel.txtValue!)}
                          className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                        >
                          <RiFileCopyLine className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground/50 pt-0.5">
                      {s("record_note_txt")}
                    </p>
                  </div>
                </div>

                <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                  <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                    <span className="w-4 h-4 rounded-full bg-foreground text-background text-[9px] font-bold flex items-center justify-center shrink-0">2</span>
                    <p className="text-[11px] font-semibold text-foreground">
                      {s("click_verify_after")}
                    </p>
                  </div>
                  <div className="px-3 py-2.5">
                    <button
                      type="button"
                      disabled={vercel.checkLoading}
                      onClick={() => { onVercelCheckAttemptReset(); onVercelCheck(false); }}
                      className={cn(
                        "w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg text-xs font-semibold transition-all border",
                        vercel.checkLoading
                          ? "bg-muted/40 text-muted-foreground border-border/40 cursor-not-allowed"
                          : "bg-foreground text-background border-transparent hover:opacity-90 active:scale-[0.98]"
                      )}
                    >
                      {vercel.checkLoading
                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin shrink-0" />
                        : <RiCheckboxCircleLine className="w-3.5 h-3.5 shrink-0" />}
                      {vercel.countdown > 0 && !vercel.checkLoading
                        ? s("auto_checking", { n: vercel.countdown })
                        : vercel.checkLoading
                        ? `${s("checking_label")}…`
                        : s("verify_now")}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {/* Near match raw records panel */}
        {anyNearMatch && resolvers.some(r => r.nearMatch && r.records.length > 0) && verifyTab === "dns" && (
          <div className="rounded-xl border border-orange-300/50 bg-orange-50/50 dark:bg-orange-950/20 p-3 space-y-2">
            <p className="text-[11px] font-semibold text-orange-700 dark:text-orange-400 flex items-center gap-1.5">
              <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
              {s("token_mismatch")}
            </p>
            {resolvers.filter(r => r.nearMatch && r.records.length > 0).slice(0, 2).flatMap(r => r.records).slice(0, 3).map((record, i) => (
              <div key={i} className="flex items-start gap-1.5">
                <span className="text-[10px] font-bold text-orange-500/70 shrink-0 mt-0.5">{s("found_label")}</span>
                <code className="text-[10px] font-mono text-orange-600 dark:text-orange-400 break-all leading-relaxed flex-1 bg-orange-500/5 rounded px-1.5 py-0.5">{record}</code>
              </div>
            ))}
            {expectedVal && (
              <div className="flex items-start gap-1.5">
                <span className="text-[10px] font-bold text-emerald-600/70 shrink-0 mt-0.5">{s("expected_label")}</span>
                <code className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 break-all leading-relaxed flex-1 bg-emerald-500/5 rounded px-1.5 py-0.5">{expectedVal}</code>
              </div>
            )}
            <p className="text-[10px] text-muted-foreground leading-relaxed">
              {s("token_mismatch_note")}
            </p>
          </div>
        )}

        {/* Status messages */}
        <AnimatePresence mode="wait">
          {verifyState === "nearMatch" && verifyTab === "dns" && (
            <motion.div
              key="nearMatch"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18 }}
              className="flex gap-2.5 p-3 rounded-xl bg-orange-50/60 dark:bg-orange-950/20 border border-orange-300/50"
            >
              <RiAlertLine className="w-4 h-4 text-orange-500 shrink-0 mt-0.5" />
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                {s("check_content_note")}
              </p>
            </motion.div>
          )}
          {verifyState === "fail" && resolvers.length > 0 && verifyTab === "dns" && (
            <motion.div
              key="fail"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18 }}
              className="flex gap-2.5 p-3 rounded-xl bg-amber-50/60 dark:bg-amber-950/20 border border-amber-200/50"
            >
              <RiAlertLine className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
              <div className="space-y-1 flex-1">
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  {s("fail_msg")}
                </p>
              </div>
            </motion.div>
          )}
          {verifyState === "dnsError" && verifyTab === "dns" && (
            <motion.div
              key="dnsError"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.18 }}
              className="flex gap-2.5 p-3 rounded-xl bg-red-50/60 dark:bg-red-950/20 border border-red-200/50"
            >
              <RiAlertLine className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                {s("dns_error_msg")}
              </p>
            </motion.div>
          )}
          {verifyState === "giveUp" && (
            <motion.div
              key="giveUp"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.2 }}
              className="rounded-xl border border-orange-200/60 bg-orange-50/50 dark:bg-orange-950/20 overflow-hidden"
            >
              <div className="flex gap-2.5 p-3">
                <div className="shrink-0 w-7 h-7 rounded-lg bg-orange-500/10 flex items-center justify-center mt-0.5">
                  <RiAlertLine className="w-3.5 h-3.5 text-orange-500" />
                </div>
                <div className="space-y-1 flex-1 min-w-0">
                  <p className="text-xs font-semibold text-orange-700 dark:text-orange-400">
                    {s("auto_checked_n", { n: POLL_SCHEDULE.length })}
                  </p>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    {s("tld_no_dns_note")}
                  </p>
                  <button
                    type="button"
                    onClick={() => onTabChange("http")}
                    className="mt-1 flex items-center gap-1 text-[11px] font-semibold text-orange-600 dark:text-orange-400 hover:underline"
                  >
                    <RiFlashlightLine className="w-3.5 h-3.5" />
                    {s("switch_file_verify")} →
                  </button>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Verify button + progress + countdown */}
        <div className="space-y-2">
          <Button
            onClick={() => onVerify(false)}
            disabled={verifyState === "loading"}
            className="w-full gap-2 h-11 bg-violet-500 hover:bg-violet-600 active:bg-violet-700 text-white border-0 rounded-xl text-sm font-semibold shadow-sm shadow-violet-500/20 transition-all"
          >
            {verifyState === "loading"
              ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{s("checking")}</>
              : <><RiRefreshLine className="w-4 h-4" />{s("btn_check")}</>
            }
          </Button>
          {pollAttempt > 0 && verifyState !== "giveUp" && (
            <div className="space-y-1">
              <div className="flex justify-between items-center text-[10px] text-muted-foreground/60">
                <span className="flex items-center gap-1">
                  <RiTimeLine className="w-3 h-3" />
                  {s("attempt_n", { current: pollAttempt, total: POLL_SCHEDULE.length })}
                </span>
                {countdown > 0 && verifyState !== "loading" && (
                  <span>
                    {countdown >= 60
                      ? s("next_check_min", { n: Math.ceil(countdown / 60) })
                      : s("next_check_sec", { n: countdown })}
                  </span>
                )}
              </div>
              <div className="w-full h-1 rounded-full bg-muted/40 overflow-hidden">
                <div
                  className="h-full rounded-full bg-violet-400/60 transition-all duration-500"
                  style={{ width: `${(pollAttempt / POLL_SCHEDULE.length) * 100}%` }}
                />
              </div>
            </div>
          )}
          {pollAttempt === 0 && countdown > 0 && verifyState !== "loading" && (
            <div className="rounded-lg bg-sky-50/60 dark:bg-sky-950/20 border border-sky-200/50 px-3 py-2 flex items-center gap-2">
              <RiTimeLine className="w-3.5 h-3.5 text-sky-500 shrink-0" />
              <p className="text-[11px] text-sky-700 dark:text-sky-300 flex-1">
                {s("add_txt_first")}
              </p>
              <span className="shrink-0 text-[10px] font-mono text-sky-500 tabular-nums">
                {countdown >= 60
                  ? `${Math.ceil(countdown / 60)}m`
                  : `${countdown}s`}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Tips card — only DNS tab */}
      {verifyTab === "dns" && (
        <div className="rounded-2xl border border-border/50 bg-muted/20 p-4 flex gap-3">
          <div className="shrink-0 w-7 h-7 rounded-lg bg-amber-500/10 flex items-center justify-center mt-0.5">
            <RiAlertLine className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="space-y-1">
            <p className="text-xs font-semibold text-foreground">{s("dns_prop_title")}</p>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              {s("dns_prop_prefix")}<strong className="text-foreground">{s("dns_prop_highlight")}</strong>{s("dns_prop_suffix")}
            </p>
          </div>
        </div>
      )}

      <button
        onClick={onBackEdit}
        className="text-xs text-muted-foreground hover:text-foreground transition-colors w-full text-center py-1"
      >
        {s("back_edit")}
      </button>
    </div>
  );
}
