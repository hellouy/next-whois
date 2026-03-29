import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";
import {
  RiArrowLeftSLine, RiSearchLine, RiLoader4Line,
  RiLockLine, RiLockUnlockLine, RiShieldCheckLine, RiShieldLine,
  RiCalendarLine, RiFileCopyLine, RiCheckLine, RiAlertLine,
  RiTimeLine, RiLinkM, RiServerLine, RiRefreshLine, RiExternalLinkLine,
} from "@remixicon/react";

type SanEntry = { type: string; value: string };
type CertChain = { subject: Record<string, string>; issuer: Record<string, string>; valid_from: string; valid_to: string; fingerprint256: string; serialNumber: string };

type SslResult = {
  ok: boolean;
  hostname: string;
  port: number;
  authorized: boolean;
  authError: string | null;
  protocol: string | null;
  cipher: string | null;
  cipherBits: number | null;
  subject: Record<string, string>;
  issuer: Record<string, string>;
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  is_expired: boolean;
  is_expiring_soon: boolean;
  fingerprint: string;
  fingerprint256: string;
  serialNumber: string;
  keyAlgorithm: string | null;
  keyBits: number | null;
  sans: SanEntry[];
  chain: CertChain[];
  latencyMs: number;
  error?: string;
};

function CopyButton({ text, copyLabel }: { text: string; copyLabel: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground touch-manipulation"
      title={copyLabel}
    >
      {copied ? <RiCheckLine className="w-3 h-3 text-emerald-500" /> : <RiFileCopyLine className="w-3 h-3" />}
    </button>
  );
}

function InfoRow({ label, value, mono, copyLabel }: { label: string; value: string; mono?: boolean; copyLabel: string }) {
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-border/40 last:border-0">
      <span className="text-xs text-muted-foreground w-28 shrink-0 pt-0.5">{label}</span>
      <div className="flex items-start gap-1.5 flex-1 min-w-0">
        <span className={cn("text-sm break-all flex-1", mono && "font-mono")}>{value || "—"}</span>
        {value && <CopyButton text={value} copyLabel={copyLabel} />}
      </div>
    </div>
  );
}

function ValidityBar({ daysRemaining, validFrom, validTo }: { daysRemaining: number; validFrom: string; validTo: string }) {
  const from = new Date(validFrom).getTime();
  const to = new Date(validTo).getTime();
  const now = Date.now();
  const total = to - from;
  const elapsed = now - from;
  const pct = Math.max(0, Math.min(100, (elapsed / total) * 100));
  const remaining = 100 - pct;

  const color = daysRemaining <= 0 ? "bg-red-500" : daysRemaining <= 30 ? "bg-amber-500" : "bg-emerald-500";
  const trackColor = daysRemaining <= 0 ? "bg-red-200 dark:bg-red-950/40" : daysRemaining <= 30 ? "bg-amber-200 dark:bg-amber-950/40" : "bg-emerald-200 dark:bg-emerald-950/40";

  return (
    <div className="space-y-1.5">
      <div className={cn("h-1.5 rounded-full overflow-hidden", trackColor)}>
        <div
          className={cn("h-full rounded-full transition-all", color)}
          style={{ width: `${remaining}%` }}
        />
      </div>
      <div className="flex justify-between text-[10px] text-muted-foreground">
        <span>{validFrom.split("T")[0]}</span>
        <span>{validTo.split("T")[0]}</span>
      </div>
    </div>
  );
}

function subjectStr(s: Record<string, string>): string {
  return [s.CN && `CN=${s.CN}`, s.O && `O=${s.O}`, s.C && `C=${s.C}`].filter(Boolean).join(", ");
}

const FADE = { duration: 0.18, ease: "easeOut" as const };

export default function SslPage() {
  const router = useRouter();
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const siteLabel = settings.site_logo_text || "X.RW";
  const [hostname, setHostname] = React.useState("");
  const [result, setResult] = React.useState<SslResult | null>(null);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (!router.isReady) return;
    const q = router.query.q as string;
    if (q) {
      setHostname(q);
      setTimeout(() => doQuery(q), 50);
    }
  }, [router.isReady]);

  async function doQuery(h?: string) {
    const host = (h ?? hostname).trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    if (!host) { toast.error(t("ssl.err_empty")); return; }

    setLoading(true);
    setResult(null);
    router.replace({ pathname: "/ssl", query: { q: host } }, undefined, { locale: false, shallow: true });

    try {
      const res = await fetch(`/api/ssl/cert?hostname=${encodeURIComponent(host)}`);
      const data: SslResult = await res.json();
      setResult(data);
    } catch (e: unknown) {
      toast.error((e as Error).message || t("ssl.err_failed"));
    } finally {
      setLoading(false);
    }
  }

  const validityColor = !result ? "border-border" :
    !result.ok || result.error ? "border-red-300 dark:border-red-800" :
    result.is_expired ? "border-red-300 dark:border-red-800" :
    result.is_expiring_soon ? "border-amber-300 dark:border-amber-800" :
    "border-emerald-300 dark:border-emerald-800";

  const hasResult = !loading && !!result;
  const copyLabel = t("ssl.copy");

  const validityText = !result ? "" :
    result.is_expired
      ? t("ssl.expired")
      : result.is_expiring_soon
      ? t("ssl.expiring_soon").replace("{{n}}", String(result.days_remaining))
      : t("ssl.valid").replace("{{n}}", String(result.days_remaining));

  return (
    <>
      <Head><title key="title">{`${t("ssl.title")} — ${siteLabel}`}</title></Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-6 space-y-5">
          <div className="flex items-center gap-3">
            <Link href="/" className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground touch-manipulation">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <RiLockLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("ssl.title")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("ssl.subtitle")}</p>
              </div>
            </div>
          </div>

          <form onSubmit={e => { e.preventDefault(); doQuery(); }} className="flex gap-2">
            <div className="relative flex-1">
              <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
              <Input
                value={hostname}
                onChange={e => setHostname(e.target.value)}
                placeholder={t("ssl.placeholder")}
                className="pl-9 h-10 rounded-xl font-mono text-base sm:text-sm"
                autoFocus
              />
            </div>
            <Button type="submit" disabled={loading} className="h-10 px-4 rounded-xl gap-2 shrink-0">
              {loading ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSearchLine className="w-4 h-4" />}
              {t("ssl.search")}
            </Button>
            {result && (
              <Button type="button" variant="outline" onClick={() => doQuery()} disabled={loading}
                className="h-10 w-10 px-0 rounded-xl shrink-0" title={t("ssl.refresh_title")}>
                <RiRefreshLine className="w-4 h-4" />
              </Button>
            )}
          </form>

          <AnimatePresence mode="wait" initial={false}>
            {loading ? (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="flex flex-col items-center justify-center py-16 gap-4">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-full border-2 border-emerald-500/20" />
                    <RiLoader4Line className="w-6 h-6 animate-spin text-emerald-500 absolute inset-0 m-auto" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium">{t("ssl.loading")}</p>
                    <p className="text-xs text-muted-foreground mt-1">{t("ssl.loading_sub")}</p>
                  </div>
                </div>
              </motion.div>
            ) : hasResult ? (
              <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE} className="space-y-4">

                {(!result!.ok || result!.error) ? (
                  <div className={cn("glass-panel border rounded-2xl p-5 space-y-3", validityColor)}>
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-red-100 dark:bg-red-950/40 flex items-center justify-center">
                        <RiLockUnlockLine className="w-5 h-5 text-red-500" />
                      </div>
                      <div>
                        <p className="font-semibold text-red-600 dark:text-red-400">{t("ssl.failed_title")}</p>
                        <p className="text-sm text-muted-foreground">{result!.error}</p>
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground">{t("ssl.failed_note")}</p>
                  </div>
                ) : (
                  <>
                    <div className={cn("glass-panel border rounded-2xl p-4 space-y-3", validityColor)}>
                      <div className="flex items-center gap-4">
                        <div className={cn(
                          "w-12 h-12 rounded-xl flex items-center justify-center shrink-0",
                          result!.is_expired ? "bg-red-100 dark:bg-red-950/40" :
                          result!.is_expiring_soon ? "bg-amber-100 dark:bg-amber-950/40" :
                          "bg-emerald-100 dark:bg-emerald-950/40"
                        )}>
                          {result!.is_expired || !result!.authorized
                            ? <RiShieldLine className={cn("w-6 h-6", result!.is_expired ? "text-red-500" : "text-amber-500")} />
                            : <RiShieldCheckLine className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
                          }
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className={cn(
                              "font-bold",
                              result!.is_expired ? "text-red-600 dark:text-red-400" :
                              result!.is_expiring_soon ? "text-amber-600 dark:text-amber-400" :
                              "text-emerald-700 dark:text-emerald-400"
                            )}>
                              {validityText}
                            </p>
                            {result!.authorized
                              ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 font-semibold border border-emerald-200 dark:border-emerald-800">{t("ssl.trusted")}</span>
                              : <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-semibold border border-amber-200 dark:border-amber-800">{t("ssl.untrusted")}</span>
                            }
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {result!.protocol} · {result!.cipher}
                          </p>
                          {!result!.authorized && result!.authError && (
                            <p className="text-xs text-amber-600 dark:text-amber-400 mt-1 flex items-center gap-1">
                              <RiAlertLine className="w-3 h-3" />{result!.authError}
                            </p>
                          )}
                        </div>
                        <div className="text-right shrink-0">
                          <p className="text-[10px] text-muted-foreground">{result!.latencyMs}ms</p>
                          <p className="text-[10px] text-muted-foreground">:{result!.port}</p>
                        </div>
                      </div>
                      <ValidityBar
                        daysRemaining={result!.days_remaining}
                        validFrom={result!.valid_from}
                        validTo={result!.valid_to}
                      />
                    </div>

                    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                        <RiLinkM className="w-3.5 h-3.5 text-muted-foreground" />
                        <h3 className="text-sm font-bold">{t("ssl.cert_section")}</h3>
                        <a
                          href={`https://crt.sh/?q=${encodeURIComponent(result!.hostname)}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="ml-auto flex items-center gap-1 text-[10px] text-primary hover:underline"
                        >
                          {t("ssl.ct_logs")} <RiExternalLinkLine className="w-2.5 h-2.5" />
                        </a>
                      </div>
                      <div className="px-5">
                        <InfoRow label={t("ssl.issued_to_cn")} value={result!.subject?.CN || ""} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.org_o")} value={result!.subject?.O || ""} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.region_cst")} value={[result!.subject?.C, result!.subject?.ST, result!.subject?.L].filter(Boolean).join(" / ")} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.issuer_cn")} value={result!.issuer?.CN || ""} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.issuer_o")} value={result!.issuer?.O || ""} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.valid_from")} value={result!.valid_from} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.valid_to")} value={result!.valid_to} copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.serial")} value={result!.serialNumber} mono copyLabel={copyLabel} />
                        <InfoRow label={t("ssl.fingerprint")} value={result!.fingerprint256} mono copyLabel={copyLabel} />
                        {(result!.keyAlgorithm || result!.keyBits) && (
                          <InfoRow
                            label={t("ssl.key_info")}
                            value={[result!.keyAlgorithm, result!.keyBits ? `${result!.keyBits} bits` : null].filter(Boolean).join(" · ")}
                            mono
                            copyLabel={copyLabel}
                          />
                        )}
                        {result!.cipher && (
                          <InfoRow
                            label={t("ssl.cipher")}
                            value={result!.cipherBits ? `${result!.cipher} (${result!.cipherBits} bits)` : result!.cipher}
                            mono
                            copyLabel={copyLabel}
                          />
                        )}
                      </div>
                    </div>

                    {result!.sans.length > 0 && (
                      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                          <RiServerLine className="w-3.5 h-3.5 text-muted-foreground" />
                          <h3 className="text-sm font-bold">{t("ssl.san_section")}</h3>
                          <span className="ml-auto text-xs text-muted-foreground">{t("ssl.san_count").replace("{{n}}", String(result!.sans.length))}</span>
                        </div>
                        <div className="p-4">
                          <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto">
                            {result!.sans.map((san, i) => (
                              <span key={i} className="text-xs font-mono px-2 py-0.5 rounded-lg bg-muted border border-border hover:bg-muted/80 transition-colors">
                                {san.type !== "DNS" && <span className="text-muted-foreground">{san.type}:</span>}
                                {san.value}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}

                    {result!.chain.length > 1 && (
                      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                          <RiShieldCheckLine className="w-3.5 h-3.5 text-muted-foreground" />
                          <h3 className="text-sm font-bold">{t("ssl.chain_section")}</h3>
                          <span className="ml-auto text-xs text-muted-foreground">{t("ssl.chain_count").replace("{{n}}", String(result!.chain.length))}</span>
                        </div>
                        <div className="p-4 space-y-2">
                          {result!.chain.map((c, i) => (
                            <div key={i} className="flex items-start gap-3">
                              <div className="flex flex-col items-center mt-1">
                                <div className={cn("w-2 h-2 rounded-full shrink-0",
                                  i === 0 ? "bg-primary" : i === result!.chain.length - 1 ? "bg-emerald-500" : "bg-muted-foreground/40"
                                )} />
                                {i < result!.chain.length - 1 && <div className="w-px h-6 bg-border" />}
                              </div>
                              <div className="flex-1 min-w-0 pb-2">
                                <p className="text-xs font-semibold truncate">{c.subject?.CN || subjectStr(c.subject)}</p>
                                <p className="text-[11px] text-muted-foreground truncate">
                                  {i === 0 ? t("ssl.end_cert") : i === result!.chain.length - 1 ? t("ssl.root_cert") : t("ssl.intermediate_cert")} · {c.issuer?.O || c.issuer?.CN}
                                </p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </motion.div>
            ) : (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="text-center py-14 space-y-2">
                  <div className="w-14 h-14 rounded-2xl bg-emerald-500/8 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
                    <RiLockLine className="w-7 h-7 text-emerald-500/60" />
                  </div>
                  <p className="text-sm font-medium text-muted-foreground">{t("ssl.empty_title")}</p>
                  <p className="text-xs text-muted-foreground/60">{t("ssl.empty_subtitle")}</p>
                  <div className="flex justify-center gap-2 mt-4 flex-wrap">
                    {["google.com", "github.com", "cloudflare.com"].map(h => (
                      <button key={h} onClick={() => { setHostname(h); doQuery(h); }}
                        className="text-[11px] font-mono px-2.5 py-1 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:border-emerald-300 transition-colors touch-manipulation">
                        {h}
                      </button>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex items-center gap-3 flex-wrap text-[10px] text-muted-foreground/50 pb-2">
            <span className="flex items-center gap-1"><RiTimeLine className="w-3 h-3" />{t("ssl.footer_realtime")}</span>
            <span>|</span>
            <span>{t("ssl.footer_tech")}</span>
            <Link href={`/feedback?type=ssl${result?.hostname ? `&q=${encodeURIComponent(result.hostname)}` : ""}`} className="ml-auto hover:text-foreground transition-colors">
              {t("ssl.feedback")}
            </Link>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
