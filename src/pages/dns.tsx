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
  RiArrowLeftSLine, RiSearchLine, RiLoader4Line, RiCheckLine,
  RiErrorWarningLine, RiTimeLine, RiRefreshLine, RiFileCopyLine,
  RiShieldCheckLine, RiMailLine, RiServerLine, RiGlobalLine,
  RiKeyLine, RiSpeedUpLine,
} from "@remixicon/react";

type RecordType = "A" | "AAAA" | "MX" | "NS" | "CNAME" | "TXT" | "SOA" | "CAA";

const RECORD_TYPES: { type: RecordType; color: string; bg: string }[] = [
  { type: "A",     color: "text-blue-600 dark:text-blue-400",     bg: "bg-blue-500/8 border-blue-500/30" },
  { type: "AAAA",  color: "text-indigo-600 dark:text-indigo-400", bg: "bg-indigo-500/8 border-indigo-500/30" },
  { type: "MX",    color: "text-violet-600 dark:text-violet-400", bg: "bg-violet-500/8 border-violet-500/30" },
  { type: "NS",    color: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-500/8 border-emerald-500/30" },
  { type: "CNAME", color: "text-amber-600 dark:text-amber-400",   bg: "bg-amber-500/8 border-amber-500/30" },
  { type: "TXT",   color: "text-orange-600 dark:text-orange-400", bg: "bg-orange-500/8 border-orange-500/30" },
  { type: "SOA",   color: "text-rose-600 dark:text-rose-400",     bg: "bg-rose-500/8 border-rose-500/30" },
  { type: "CAA",   color: "text-teal-600 dark:text-teal-400",     bg: "bg-teal-500/8 border-teal-500/30" },
];

type ResolverResult = {
  name: string; kind: "udp" | "doh";
  records: any[]; flat: string[]; latencyMs: number; error?: string;
};

type DnsResult = {
  name: string; type: RecordType; found: boolean;
  records: any[]; flat: string[]; resolvers: ResolverResult[]; latencyMs: number; error?: string;
  _label?: string;
};

function classifyTxt(val: string): { label: string; color: string } {
  if (/^v=spf1/i.test(val))    return { label: "SPF",   color: "bg-blue-100 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800" };
  if (/^v=DMARC1/i.test(val))  return { label: "DMARC", color: "bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-300 border-violet-200 dark:border-violet-800" };
  if (/^v=DKIM1/i.test(val) || (/k=rsa/i.test(val) && /p=/.test(val))) return { label: "DKIM", color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800" };
  if (/^v=BIMI1/i.test(val))   return { label: "BIMI",  color: "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800" };
  if (/^MS=ms/i.test(val))     return { label: "MS",    color: "bg-sky-100 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 border-sky-200 dark:border-sky-800" };
  return { label: "TXT", color: "bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800" };
}

function CopyButton({ text, copyLabel }: { text: string; copyLabel: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).catch(() => {}); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground shrink-0 touch-manipulation"
      title={copyLabel}
    >
      {copied ? <RiCheckLine className="w-3 h-3 text-emerald-500" /> : <RiFileCopyLine className="w-3 h-3" />}
    </button>
  );
}

function ResolverDots({ resolvers }: { resolvers: ResolverResult[] }) {
  return (
    <div className="flex items-center gap-0.5" title={resolvers.map(r => `${r.name}: ${r.error ?? r.latencyMs + "ms"}`).join(" | ")}>
      {resolvers.map(r => (
        <div
          key={r.name}
          className={cn(
            "rounded-full",
            r.kind === "doh" ? "w-2 h-2 ring-1 ring-inset ring-primary/20" : "w-2 h-2",
            r.error
              ? r.error === "no_record" ? "bg-muted-foreground/25" : "bg-red-400/70"
              : "bg-emerald-400"
          )}
        />
      ))}
    </div>
  );
}

function RecordTypeBadge({ type }: { type: RecordType }) {
  const meta = RECORD_TYPES.find(r => r.type === type);
  return (
    <span className={cn("text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border bg-muted/50", meta?.color)}>
      {type}
    </span>
  );
}

function MxRow({ flat }: { flat: string }) {
  const match = flat.match(/^(\d+)\s+(.+)$/);
  if (!match) return <span className="text-sm font-mono break-all flex-1 leading-relaxed">{flat}</span>;
  const [, priority, host] = match;
  return (
    <div className="flex items-center gap-2 flex-1 min-w-0">
      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-violet-100 dark:bg-violet-950/40 text-violet-700 dark:text-violet-400 border-violet-200 dark:border-violet-800 shrink-0">
        MX {priority}
      </span>
      <span className="text-sm font-mono break-all flex-1 leading-relaxed">{host}</span>
    </div>
  );
}

function SoaRow({ records, labels }: {
  records: any[];
  labels: { primaryNs: string; adminEmail: string; serial: string; refresh: string; retry: string; expire: string };
}) {
  const soa = records?.[0];
  if (!soa) return null;
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs py-1">
      {[
        [labels.primaryNs, soa.nsname],
        [labels.adminEmail, soa.hostmaster],
        [labels.serial, soa.serial],
        [labels.refresh, soa.refresh ? `${soa.refresh}s` : "—"],
        [labels.retry, soa.retry ? `${soa.retry}s` : "—"],
        [labels.expire, soa.expire ? `${Math.floor(soa.expire / 86400)}d` : "—"],
      ].filter(([, v]) => v).map(([label, value]) => (
        <div key={String(label)} className="flex items-start gap-2">
          <span className="text-muted-foreground shrink-0">{label}</span>
          <span className="font-mono break-all">{value}</span>
        </div>
      ))}
    </div>
  );
}

function ResultCard({
  result, index, noRecordLabel, hasRecordTemplate, copyLabel, soaLabels,
}: {
  result: DnsResult; index?: number;
  noRecordLabel: string;
  hasRecordTemplate: string;
  copyLabel: string;
  soaLabels: { primaryNs: string; adminEmail: string; serial: string; refresh: string; retry: string; expire: string };
}) {
  if (!result.found) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.18 }}
        className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl border border-border/60 bg-muted/5"
      >
        <RecordTypeBadge type={result.type} />
        {result._label && <span className="text-xs font-mono text-muted-foreground/60 truncate">{result._label}</span>}
        <span className="text-xs text-muted-foreground">{noRecordLabel}</span>
        <ResolverDots resolvers={result.resolvers} />
        <span className="ml-auto text-[10px] text-muted-foreground shrink-0">{result.latencyMs}ms</span>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.18 }}
      className="glass-panel border border-border rounded-2xl overflow-hidden"
    >
      <div className="flex items-center gap-2.5 px-4 py-2 border-b border-border/50 bg-muted/20">
        <RecordTypeBadge type={result.type} />
        {result._label && (
          <span className="text-[11px] font-mono text-muted-foreground truncate">{result._label}</span>
        )}
        <ResolverDots resolvers={result.resolvers} />
        <span className="ml-auto text-[10px] text-muted-foreground shrink-0">
          {hasRecordTemplate.replace("{{n}}", String(result.flat.length)).replace("{{ms}}", String(result.latencyMs))}
        </span>
      </div>
      {result.type === "SOA" ? (
        <div className="px-4 py-3">
          <SoaRow records={result.records} labels={soaLabels} />
        </div>
      ) : (
        <div className="divide-y divide-border/30">
          {result.flat.map((flat, i) => {
            const isTxt = result.type === "TXT";
            const isMx  = result.type === "MX";
            const cls = isTxt ? classifyTxt(flat) : null;
            return (
              <div key={i} className="flex items-start gap-2.5 px-4 py-2.5 group hover:bg-muted/10 transition-colors">
                {isTxt && cls && (
                  <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded border shrink-0 mt-0.5 leading-tight", cls.color)}>
                    {cls.label}
                  </span>
                )}
                {isMx ? <MxRow flat={flat} /> : (
                  <span className="text-sm font-mono break-all flex-1 leading-relaxed">{flat}</span>
                )}
                <CopyButton text={flat} copyLabel={copyLabel} />
              </div>
            );
          })}
        </div>
      )}
    </motion.div>
  );
}

async function fetchDns(name: string, type: RecordType, label?: string): Promise<DnsResult> {
  const r = await fetch(`/api/dns/records?name=${encodeURIComponent(name)}&type=${type}`);
  const data: DnsResult = await r.json();
  if (label) data._label = label;
  return data;
}

const COMMON_DKIM_SELECTORS = ["google", "dkim", "k1", "k2", "s1", "s2", "mail", "smtp", "default", "selector1", "selector2", "protonmail", "pm", "key1", "key2", "mx"];

const FADE = { duration: 0.18, ease: "easeOut" as const };

export default function DnsPage() {
  const router = useRouter();
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const siteLabel = settings.site_logo_text || "X.RW";
  const [domain, setDomain] = React.useState("");
  const [activeTypes, setActiveTypes] = React.useState<RecordType[]>(["A"]);
  const [results, setResults] = React.useState<DnsResult[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [queried, setQueried] = React.useState<string | null>(null);
  const [isEmailPreset, setIsEmailPreset] = React.useState(false);
  const [dkimSelector, setDkimSelector] = React.useState("");
  const [dkimResult, setDkimResult] = React.useState<DnsResult | null>(null);
  const [dkimLoading, setDkimLoading] = React.useState(false);
  const [totalMs, setTotalMs] = React.useState<number | null>(null);

  React.useEffect(() => {
    if (!router.isReady) return;
    const q = router.query.q as string;
    const tp = router.query.type as string;
    if (q) {
      setDomain(q);
      const types: RecordType[] = tp ? (tp.split(",").filter(x => RECORD_TYPES.find(r => r.type === x)) as RecordType[]) : ["A"];
      setActiveTypes(types);
      setTimeout(() => doQuery(q, types), 80);
    }
  }, [router.isReady]);

  async function doQuery(d?: string, types?: RecordType[]) {
    const name = (d ?? domain).trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    const qTypes = types ?? activeTypes;
    if (!name) { toast.error(t("dns.err_empty")); return; }

    const isEmail = qTypes.includes("MX") && qTypes.includes("TXT");
    setLoading(true);
    setQueried(name);
    setResults([]);
    setDkimResult(null);
    setTotalMs(null);
    setIsEmailPreset(isEmail);

    router.replace({ pathname: "/dns", query: { q: name, type: qTypes.join(",") } }, undefined, { locale: false, shallow: true });

    const t0 = Date.now();
    try {
      const jobs: Promise<DnsResult>[] = qTypes.map(type => fetchDns(name, type));
      if (isEmail) jobs.push(fetchDns(`_dmarc.${name}`, "TXT", `_dmarc.${name}`));

      const settled = await Promise.allSettled(jobs);
      const all: DnsResult[] = settled.map((s, i) => {
        if (s.status === "fulfilled") return s.value;
        const type = i < qTypes.length ? qTypes[i] : "TXT";
        return { name: i < qTypes.length ? name : `_dmarc.${name}`, type, found: false, records: [], flat: [], resolvers: [], latencyMs: 0, error: t("dns.err_req_failed") };
      });

      setResults(all);
      setTotalMs(Date.now() - t0);
    } catch (e: unknown) {
      toast.error((e as Error).message || t("dns.err_failed"));
    } finally {
      setLoading(false);
    }
  }

  async function queryDkim(selector?: string) {
    const sel = (selector ?? dkimSelector).trim();
    if (!sel || !queried) return;
    setDkimLoading(true);
    try {
      const dkimName = `${sel}._domainkey.${queried}`;
      const result = await fetchDns(dkimName, "TXT", dkimName);
      setDkimResult(result);
    } catch {
      toast.error(t("dns.dkim_failed"));
    } finally {
      setDkimLoading(false);
    }
  }

  async function autoDetectDkim() {
    if (!queried) return;
    setDkimLoading(true);
    try {
      const settled = await Promise.allSettled(
        COMMON_DKIM_SELECTORS.map(sel =>
          fetchDns(`${sel}._domainkey.${queried}`, "TXT", `${sel}._domainkey.${queried}`)
        )
      );
      const found = settled
        .filter((s): s is PromiseFulfilledResult<DnsResult> => s.status === "fulfilled" && s.value.found)
        .map(s => s.value);
      if (found.length === 0) {
        toast(t("dns.dkim_not_found"));
        setDkimResult({ name: queried, type: "TXT", found: false, records: [], flat: [], resolvers: [], latencyMs: 0, _label: "auto-detect" });
      } else {
        setDkimResult(found[0]);
        if (found[0]._label) {
          const sel = found[0]._label.split("._domainkey.")[0];
          setDkimSelector(sel);
        }
        toast.success(t("dns.dkim_found").replace("{{label}}", found[0]._label || ""));
      }
    } catch {
      toast.error(t("dns.dkim_auto_failed"));
    } finally {
      setDkimLoading(false);
    }
  }

  function toggleType(type: RecordType) {
    setActiveTypes(prev =>
      prev.includes(type)
        ? prev.length === 1 ? prev : prev.filter(tp => tp !== type)
        : [...prev, type]
    );
    setIsEmailPreset(false);
  }

  const mainResults = results.filter(r => !r._label || r._label === r.name);
  const subResults  = results.filter(r => r._label && r._label !== r.name);

  const hasMX    = results.some(r => r.type === "MX" && r.found);
  const hasSPF   = results.some(r => r.type === "TXT" && r.flat.some(f => /^v=spf1/i.test(f)));
  const hasDMARC = [...results, ...(dkimResult ? [dkimResult] : [])].some(
    r => r.type === "TXT" && r.flat.some(f => /^v=DMARC1/i.test(f))
  ) || subResults.some(r => r.found && r.flat.some(f => /^v=DMARC1/i.test(f)));
  const hasDKIM  = dkimResult?.found && dkimResult.flat.some(f => /^v=DKIM1/i.test(f) || (/k=rsa/i.test(f) && /p=/.test(f)));

  const hasContent = results.length > 0;

  const copyLabel = t("dns.copy");
  const soaLabels = {
    primaryNs: t("dns.soa_primary_ns"),
    adminEmail: t("dns.soa_admin_email"),
    serial: t("dns.soa_serial"),
    refresh: t("dns.soa_refresh"),
    retry: t("dns.soa_retry"),
    expire: t("dns.soa_expire"),
  };
  const resultCardProps = {
    noRecordLabel: t("dns.no_record"),
    hasRecordTemplate: t("dns.has_record"),
    copyLabel,
    soaLabels,
  };

  const PRESETS = [
    { label: t("dns.preset_basic"), icon: RiGlobalLine, types: ["A", "AAAA", "CNAME"] as RecordType[] },
    { label: t("dns.preset_email"), icon: RiMailLine,   types: ["MX", "TXT"] as RecordType[], email: true },
    { label: t("dns.preset_ns"),    icon: RiServerLine, types: ["NS", "SOA"] as RecordType[] },
    { label: t("dns.preset_caa"),   icon: RiShieldCheckLine, types: ["CAA"] as RecordType[] },
  ];

  return (
    <>
      <Head><title key="title">{`${t("dns.title")} — ${siteLabel}`}</title></Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-6 space-y-5">
          <div className="flex items-center gap-3">
            <Link href="/" className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground touch-manipulation">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400">
                <RiServerLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("dns.title")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("dns.subtitle")}</p>
              </div>
            </div>
          </div>

          <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
            <form onSubmit={e => { e.preventDefault(); doQuery(); }} className="flex gap-2">
              <div className="relative flex-1">
                <RiGlobalLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                <Input
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  placeholder="example.com"
                  className="pl-9 h-10 rounded-xl font-mono text-base sm:text-sm"
                  autoFocus
                />
              </div>
              <Button type="submit" disabled={loading} className="h-10 px-4 rounded-xl gap-2 shrink-0">
                {loading ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSearchLine className="w-4 h-4" />}
                {t("dns.search")}
              </Button>
            </form>

            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[11px] text-muted-foreground">{t("dns.shortcuts")}</span>
              {PRESETS.map(p => (
                <button
                  key={p.label}
                  type="button"
                  onClick={() => { setActiveTypes(p.types); setIsEmailPreset(!!(p as any).email); }}
                  className={cn(
                    "flex items-center gap-1 text-[11px] px-2.5 py-1 rounded-lg border transition-colors touch-manipulation",
                    JSON.stringify(activeTypes.slice().sort()) === JSON.stringify(p.types.slice().sort())
                      ? "bg-primary/10 border-primary/30 text-primary font-semibold"
                      : "border-border text-muted-foreground hover:border-primary/30 hover:text-foreground"
                  )}
                >
                  <p.icon className="w-3 h-3" />{p.label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[11px] text-muted-foreground shrink-0">{t("dns.record_types")}</span>
              {RECORD_TYPES.map(({ type, color }) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => toggleType(type)}
                  className={cn(
                    "text-[11px] font-mono font-bold px-2 py-0.5 rounded border transition-all touch-manipulation",
                    activeTypes.includes(type)
                      ? cn(color, "border-current/30 bg-current/10")
                      : "text-muted-foreground/50 border-border/40 hover:text-muted-foreground hover:border-border"
                  )}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          <AnimatePresence mode="wait" initial={false}>
            {loading ? (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="flex flex-col items-center justify-center py-16 gap-4">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-full border-2 border-primary/20" />
                    <RiLoader4Line className="w-6 h-6 animate-spin text-primary absolute inset-0 m-auto" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium">{t("dns.loading")}</p>
                    <p className="text-xs text-muted-foreground mt-1">Google · Cloudflare · Quad9 · AdGuard</p>
                  </div>
                </div>
              </motion.div>
            ) : hasContent ? (
              <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE} className="space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="text-xs font-semibold text-muted-foreground">
                    {queried} · {results.filter(r => r.found).length}/{results.length} {t("dns.status_ok").toLowerCase()}
                    {totalMs !== null && <span className="ml-1 text-muted-foreground/60">· {totalMs}ms</span>}
                  </p>
                  <button
                    onClick={() => doQuery()}
                    className="p-1 rounded hover:bg-muted transition-colors text-muted-foreground touch-manipulation"
                    title={t("dns.refresh")}
                  >
                    <RiRefreshLine className="w-3.5 h-3.5" />
                  </button>
                  <div className="ml-auto flex items-center gap-2 text-[10px] text-muted-foreground">
                    <div className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-emerald-400" />{t("dns.status_ok")}</div>
                    <div className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-muted-foreground/25" />{t("dns.status_no_record")}</div>
                    <div className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-red-400/70" />{t("dns.status_error")}</div>
                  </div>
                </div>

                {results[0]?.resolvers?.length > 0 && (
                  <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
                    <RiSpeedUpLine className="w-3 h-3 shrink-0 mt-0.5" />
                    {results[0].resolvers.map(r => (
                      <span key={r.name} className="flex items-center gap-1">
                        <span className={cn(
                          "inline-block w-1.5 h-1.5 rounded-full",
                          r.error ? (r.error === "no_record" ? "bg-muted-foreground/30" : "bg-red-400/70") : "bg-emerald-400"
                        )} />
                        {r.name}
                        {!r.error && <span className="text-muted-foreground/50">{r.latencyMs}ms</span>}
                      </span>
                    ))}
                  </div>
                )}

                {mainResults.map((r, i) => (
                  <ResultCard key={r.type + r.name} result={r} index={i} {...resultCardProps} />
                ))}

                {subResults.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-[11px] font-semibold text-muted-foreground flex items-center gap-1.5">
                      <RiShieldCheckLine className="w-3.5 h-3.5" />{t("dns.sub_query")}
                    </p>
                    {subResults.map((r, i) => (
                      <ResultCard key={r._label} result={r} index={i} {...resultCardProps} />
                    ))}
                  </div>
                )}

                {isEmailPreset && (
                  <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                    <p className="text-xs font-semibold flex items-center gap-1.5">
                      <RiShieldCheckLine className="w-3.5 h-3.5 text-primary" />{t("dns.email_overview")}
                    </p>
                    <div className="grid grid-cols-2 gap-2">
                      {([
                        { k: "MX",    found: hasMX,     desc: t("dns.mx_desc") },
                        { k: "SPF",   found: hasSPF,    desc: t("dns.spf_desc") },
                        { k: "DMARC", found: hasDMARC,  desc: t("dns.dmarc_desc") },
                        { k: "DKIM",  found: !!hasDKIM, desc: dkimResult ? dkimSelector || t("dns.dkim_detected") : t("dns.dkim_pending") },
                      ] as const).map(({ k, found, desc }) => (
                        <div key={k} className={cn(
                          "flex items-center gap-2 px-3 py-2.5 rounded-xl border text-xs font-semibold",
                          found
                            ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400"
                            : "bg-muted border-border text-muted-foreground opacity-60"
                        )}>
                          {found
                            ? <RiCheckLine className="w-3.5 h-3.5 shrink-0" />
                            : <RiErrorWarningLine className="w-3.5 h-3.5 shrink-0" />
                          }
                          <span>{k}</span>
                          <span className="text-[10px] font-normal ml-auto opacity-70">{desc}</span>
                        </div>
                      ))}
                    </div>

                    <div className="space-y-2 pt-1 border-t border-border/40">
                      <p className="text-[11px] text-muted-foreground font-medium flex items-center gap-1">
                        <RiKeyLine className="w-3 h-3" />{t("dns.dkim_section")}
                        <span className="text-muted-foreground/50">{t("dns.dkim_hint")}</span>
                      </p>
                      <div className="flex gap-2">
                        <Input
                          value={dkimSelector}
                          onChange={e => setDkimSelector(e.target.value)}
                          placeholder={t("dns.dkim_placeholder")}
                          className="h-8 text-xs rounded-lg font-mono flex-1"
                          onKeyDown={e => e.key === "Enter" && queryDkim()}
                        />
                        <Button size="sm" variant="outline" onClick={() => queryDkim()}
                          disabled={dkimLoading || !dkimSelector.trim()} className="h-8 px-3 text-xs rounded-lg shrink-0">
                          {dkimLoading ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : t("dns.dkim_query")}
                        </Button>
                        <Button size="sm" variant="outline" onClick={autoDetectDkim}
                          disabled={dkimLoading} className="h-8 px-3 text-xs rounded-lg shrink-0"
                          title={t("dns.dkim_auto_title").replace("{{selectors}}", COMMON_DKIM_SELECTORS.join(", "))}>
                          {dkimLoading ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : t("dns.dkim_auto")}
                        </Button>
                      </div>
                      {dkimResult && <ResultCard result={dkimResult} {...resultCardProps} />}
                    </div>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="text-center py-14 space-y-2">
                  <div className="w-14 h-14 rounded-2xl bg-blue-500/8 border border-blue-500/20 flex items-center justify-center mx-auto mb-4">
                    <RiServerLine className="w-7 h-7 text-blue-500/60" />
                  </div>
                  <p className="text-sm font-medium text-muted-foreground">{t("dns.empty_title")}</p>
                  <p className="text-xs text-muted-foreground/60">{t("dns.empty_subtitle")}</p>
                  <p className="text-xs text-muted-foreground/60">{t("dns.empty_subtitle2")}</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex items-center gap-3 flex-wrap text-[10px] text-muted-foreground/50 pb-2">
            <span className="flex items-center gap-1"><RiTimeLine className="w-3 h-3" />{t("dns.footer_realtime")}</span>
            <span>|</span>
            <span>DoH: Google · Cloudflare · Quad9 · AdGuard</span>
            <Link href={`/feedback?type=dns${queried ? `&q=${encodeURIComponent(queried)}` : ""}`} className="ml-auto hover:text-foreground transition-colors">
              {t("dns.feedback")}
            </Link>
          </div>
        </main>
      </ScrollArea>
    </>
  );
}
