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
type CtLogEntry = { name_value: string; not_before: string; not_after: string; id: number };
type CtResult = { available: boolean; total?: number; entries?: CtLogEntry[] };
type OcspResult = { status: "good" | "revoked" | "unknown"; responder: string | null; latencyMs: number; reason?: string };

type SslResult = {
  ok: boolean;
  hostname: string;
  port: number;
  authorized: boolean;
  authError: string | null;
  protocol: string | null;
  cipher: string | null;
  cipherBits: number | null;
  cipherVersion: string | null;
  ct?: CtResult;
  ocsp?: OcspResult;
  tlsVersions?: Record<string, boolean>;
  tlsRating?: "secure" | "needs_attention" | "insecure";
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
  errorCode?: string;
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

type TFunc = ReturnType<typeof useTranslation>["t"];

function TlsDetailCard({ result, t }: { result: SslResult; t: TFunc }) {
  const versions = result.tlsVersions;
  const order = ["1.0", "1.1", "1.2", "1.3"];
  const rating = result.tlsRating;
  const ratingColor = rating === "secure" ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800"
    : rating === "insecure" ? "bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800"
    : "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800";

  return (
    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2 flex-wrap">
        <RiShieldCheckLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        <h3 className="text-sm font-bold">{t("ssl.tls_section")}</h3>
        {rating && (
          <span className={cn("ml-auto text-[10px] px-2 py-0.5 rounded-full font-semibold border", ratingColor)}>
            {t(`ssl.tls_rating_${rating}`)}
          </span>
        )}
      </div>
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {order.map(v => {
            const enabled = versions ? versions[v] : false;
            const color = enabled
              ? v === "1.0" || v === "1.1"
                ? "bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800"
                : "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800"
              : "bg-muted/50 text-muted-foreground/50 border-border";
            return (
              <div key={v} className={cn("rounded-xl border px-2 py-2 text-center min-w-0", color)}>
                <p className="text-xs font-bold font-mono">TLS {v}</p>
                <p className="text-[10px] mt-0.5 opacity-80">{enabled ? t("ssl.tls_on") : t("ssl.tls_off")}</p>
              </div>
            );
          })}
        </div>
        <div className="space-y-1.5">
          <InfoRow label={t("ssl.protocol_row")} value={[result.protocol, result.cipherVersion].filter(Boolean).join(" · ")} mono copyLabel={t("ssl.copy")} />
          {result.cipher && <InfoRow label={t("ssl.cipher")} value={result.cipherBits ? `${result.cipher} (${result.cipherBits} bits)` : result.cipher} mono copyLabel={t("ssl.copy")} />}
        </div>
      </div>
    </div>
  );
}

function OcspCard({ result, t }: { result: SslResult; t: TFunc }) {
  const ocsp = result.ocsp;
  if (!ocsp) return null;
  const statusColor = ocsp.status === "good"
    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800"
    : ocsp.status === "revoked"
    ? "bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800"
    : "bg-muted/50 text-muted-foreground/50 border-border";
  const Icon = ocsp.status === "good" ? RiShieldCheckLine : ocsp.status === "revoked" ? RiShieldLine : RiTimeLine;
  return (
    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2 flex-wrap">
        <RiTimeLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        <h3 className="text-sm font-bold">{t("ssl.ocsp_section")}</h3>
        <span className={cn("ml-auto text-[10px] px-2 py-0.5 rounded-full font-semibold border flex items-center gap-1", statusColor)}>
          <Icon className="w-3 h-3" />
          {t(`ssl.ocsp_${ocsp.status}`)}
        </span>
      </div>
      <div className="px-5 py-1">
        <InfoRow label={t("ssl.ocsp_responder")} value={ocsp.responder || "—"} mono copyLabel={t("ssl.copy")} />
        <InfoRow label={t("ssl.ocsp_latency")} value={`${ocsp.latencyMs}ms`} copyLabel={t("ssl.copy")} />
        {ocsp.reason && <InfoRow label={t("ssl.ocsp_reason")} value={ocsp.reason} mono copyLabel={t("ssl.copy")} />}
      </div>
    </div>
  );
}

function CtCard({ result, t }: { result: SslResult; t: TFunc }) {
  const ct = result.ct;
  if (!ct) return null;
  if (!ct.available) {
    return (
      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
        <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2 flex-wrap">
          <RiTimeLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
          <h3 className="text-sm font-bold">{t("ssl.ct_section")}</h3>
          <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-muted/50 text-muted-foreground/60 border border-border font-semibold">{t("ssl.ct_unavailable")}</span>
        </div>
        <p className="px-5 py-4 text-xs text-muted-foreground">{t("ssl.ct_unavailable_note")}</p>
      </div>
    );
  }
  const entries = ct.entries ?? [];
  const shown = entries.slice(0, 10);
  return (
    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2 flex-wrap">
        <RiLinkM className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        <h3 className="text-sm font-bold">{t("ssl.ct_section")}</h3>
        <a
          href={`https://crt.sh/?q=${encodeURIComponent(result.hostname)}`}
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto flex items-center gap-1 text-[10px] text-primary hover:underline shrink-0"
        >
          {t("ssl.ct_view_crtsh")} <RiExternalLinkLine className="w-2.5 h-2.5" />
        </a>
      </div>
      <div className="px-5 py-1">
        <InfoRow label={t("ssl.ct_total")} value={String(ct.total ?? entries.length)} copyLabel={t("ssl.copy")} />
      </div>
      <div className="px-5 pb-4 space-y-1.5 max-h-56 overflow-y-auto">
        {shown.map(e => (
          <div key={e.id} className="flex items-start gap-2 text-xs border border-border/50 rounded-lg px-3 py-2 min-w-0">
            <span className="font-mono text-[11px] truncate flex-1 min-w-0">{e.name_value}</span>
            <span className="text-[10px] text-muted-foreground shrink-0">{e.not_before?.slice(0, 10)}</span>
          </div>
        ))}
        {entries.length > 10 && (
          <p className="text-[10px] text-muted-foreground pt-1">{t("ssl.ct_more").replace("{{n}}", String(entries.length - 10))}</p>
        )}
      </div>
    </div>
  );
}

const FADE = { duration: 0.18, ease: "easeOut" as const };

export default function SslPage() {
  const router = useRouter();
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const siteLabel = settings.site_logo_text || "WHOIS";
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
            <div className="relative flex-1 min-w-0">
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
                        <p className="text-sm text-muted-foreground">
                          {result!.errorCode
                            ? (t as (k: string) => string)(`ssl.${result!.errorCode}`).replace("{{port}}", String(result!.port))
                            : result!.error}
                        </p>
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
                      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2 flex-wrap">
                        <RiLinkM className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
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
                              <span key={i} className="text-xs font-mono px-2 py-0.5 rounded-lg bg-muted border border-border hover:bg-muted/80 transition-colors break-all max-w-full">
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

                    <TlsDetailCard result={result!} t={t} />
                    <OcspCard result={result!} t={t} />
                    <CtCard result={result!} t={t} />
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
