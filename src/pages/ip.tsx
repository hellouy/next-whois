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
  RiGlobalLine, RiMapPinLine, RiWifiLine, RiTimeLine,
  RiShieldLine, RiServerLine, RiFileCopyLine, RiCheckLine,
  RiAlertLine, RiExternalLinkLine,
} from "@remixicon/react";

type IpResult = {
  type: "ipv4" | "ipv6" | "asn";
  query: string;
  resolvedFrom: string | null;
  flag: string | null;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  district: string | null;
  zip: string | null;
  timezone: string | null;
  offset: number | null;
  currency: string | null;
  lat: number | null;
  lon: number | null;
  isp: string | null;
  org: string | null;
  as: string | null;
  asname: string | null;
  reverse: string | null;
  mobile: boolean | null;
  proxy: boolean | null;
  hosting: boolean | null;
  rdap: Record<string, string>;
  asn?: number;
  error?: string;
};

function AbuseTag({ email }: { email: string }) {
  return (
    <a
      href={`mailto:${email}`}
      className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 hover:underline break-all"
    >
      {email}
    </a>
  );
}

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

function InfoRow({ label, value, mono, badge, copyLabel }: { label: string; value?: string | number | null; mono?: boolean; badge?: React.ReactNode; copyLabel: string }) {
  if (!value && value !== 0) return null;
  const str = String(value);
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-border/40 last:border-0">
      <span className="text-xs text-muted-foreground w-24 shrink-0 pt-0.5">{label}</span>
      <div className="flex items-center gap-1.5 flex-1 min-w-0">
        <span className={cn("text-sm break-all flex-1", mono && "font-mono")}>{str}</span>
        {badge}
        {str && <CopyButton text={str} copyLabel={copyLabel} />}
      </div>
    </div>
  );
}

function BoolBadge({ value, trueLabel, falseLabel }: { value: boolean | null; trueLabel: string; falseLabel?: string }) {
  if (value === null || value === undefined) return null;
  return (
    <span className={cn(
      "text-[10px] px-1.5 py-0.5 rounded font-semibold shrink-0",
      value
        ? "bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400"
        : "bg-muted text-muted-foreground"
    )}>
      {value ? trueLabel : (falseLabel || trueLabel)}
    </span>
  );
}

const FADE = { duration: 0.18, ease: "easeOut" as const };

export default function IpPage() {
  const router = useRouter();
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const siteLabel = settings.site_logo_text || "X.RW";
  const [query, setQuery] = React.useState("");
  const [result, setResult] = React.useState<IpResult | null>(null);
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    if (!router.isReady) return;
    const q = router.query.q as string;
    if (q) {
      setQuery(q);
      setTimeout(() => doQuery(q), 50);
    }
  }, [router.isReady]);

  async function doQuery(q?: string) {
    const input = (q ?? query).trim();
    if (!input) { toast.error(t("ip.err_empty")); return; }

    setLoading(true);
    setResult(null);
    router.replace({ pathname: "/ip", query: { q: input } }, undefined, { locale: false, shallow: true });

    try {
      const res = await fetch(`/api/ip/lookup?q=${encodeURIComponent(input)}`);
      const data: IpResult = await res.json();
      if (data.error) throw new Error(data.error);
      setResult(data);
    } catch (e: unknown) {
      toast.error((e as Error).message || t("ip.err_failed"));
    } finally {
      setLoading(false);
    }
  }

  const hasResult = !loading && !!result;
  const copyLabel = t("ip.copy");

  return (
    <>
      <Head><title key="title">{`${t("ip.title")} — ${siteLabel}`}</title></Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-2xl mx-auto px-4 sm:px-6 py-6 space-y-5">
          <div className="flex items-center gap-3">
            <Link href="/" className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground touch-manipulation">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-violet-500/10 text-violet-600 dark:text-violet-400">
                <RiGlobalLine className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{t("ip.title")}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{t("ip.subtitle")}</p>
              </div>
            </div>
          </div>

          <form onSubmit={e => { e.preventDefault(); doQuery(); }} className="flex gap-2">
            <div className="relative flex-1">
              <RiGlobalLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
              <Input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="8.8.8.8 · 2001:db8:: · AS15169 · example.com"
                className="pl-9 h-10 rounded-xl font-mono text-base sm:text-sm"
                autoFocus
              />
            </div>
            <Button type="submit" disabled={loading} className="h-10 px-4 rounded-xl gap-2 shrink-0">
              {loading ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : <RiSearchLine className="w-4 h-4" />}
              {t("ip.search")}
            </Button>
          </form>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] text-muted-foreground">{t("ip.examples")}</span>
            {["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "AS15169", "AS13335"].map(ex => (
              <button
                key={ex}
                type="button"
                onClick={() => { setQuery(ex); doQuery(ex); }}
                className="text-[11px] font-mono px-2 py-0.5 rounded border border-border text-muted-foreground hover:text-foreground hover:border-violet-300 dark:hover:border-violet-700 transition-colors touch-manipulation"
              >
                {ex}
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait" initial={false}>
            {loading ? (
              <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="flex flex-col items-center justify-center py-16 gap-4">
                  <div className="relative">
                    <div className="w-12 h-12 rounded-full border-2 border-violet-500/20" />
                    <RiLoader4Line className="w-6 h-6 animate-spin text-violet-500 absolute inset-0 m-auto" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm font-medium">{t("ip.loading")}</p>
                    <p className="text-xs text-muted-foreground mt-1">ip-api.com · ARIN / RIPE / APNIC</p>
                  </div>
                </div>
              </motion.div>
            ) : hasResult ? (
              <motion.div key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE} className="space-y-4">

                {result!.type === "asn" ? (
                  <>
                    <div className="glass-panel border border-violet-200 dark:border-violet-800 rounded-2xl p-5 flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-violet-100 dark:bg-violet-950/40 flex items-center justify-center shrink-0">
                        <RiServerLine className="w-6 h-6 text-violet-600 dark:text-violet-400" />
                      </div>
                      <div>
                        <p className="font-bold text-lg">AS{result!.asn}</p>
                        <p className="text-sm text-muted-foreground">{result!.rdap.name || "—"}</p>
                      </div>
                    </div>
                    {Object.keys(result!.rdap).length > 0 && (
                      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                          <RiServerLine className="w-3.5 h-3.5 text-muted-foreground" />
                          <h3 className="text-sm font-bold">{t("ip.rdap_asn_section")}</h3>
                        </div>
                        <div className="px-5">
                          {result!.rdap.name && <InfoRow label={t("ip.name_label")} value={result!.rdap.name} copyLabel={copyLabel} />}
                          {result!.rdap.handle && <InfoRow label="Handle" value={result!.rdap.handle} mono copyLabel={copyLabel} />}
                          {result!.rdap.startAutnum && <InfoRow label={t("ip.asn_range")} value={result!.rdap.endAutnum ? `${result!.rdap.startAutnum} – ${result!.rdap.endAutnum}` : result!.rdap.startAutnum} mono copyLabel={copyLabel} />}
                          {result!.rdap.contact_name && <InfoRow label={t("ip.contact")} value={result!.rdap.contact_name} copyLabel={copyLabel} />}
                          {result!.rdap.contact_org && <InfoRow label={t("ip.org")} value={result!.rdap.contact_org} copyLabel={copyLabel} />}
                          {result!.rdap.contact_email && <InfoRow label={t("ip.email_label")} value={result!.rdap.contact_email} mono copyLabel={copyLabel} />}
                          {result!.rdap.description && <InfoRow label={t("ip.description")} value={result!.rdap.description} copyLabel={copyLabel} />}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <>
                    <div className="glass-panel border border-border rounded-2xl p-5">
                      <div className="flex items-start gap-4">
                        <div className="shrink-0 text-5xl leading-none mt-0.5 select-none">
                          {result!.flag || "🌐"}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-xl font-bold font-mono">{result!.query}</p>
                            <span className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded border font-semibold",
                              result!.type === "ipv6"
                                ? "bg-indigo-100 dark:bg-indigo-950/40 border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-400"
                                : "bg-blue-100 dark:bg-blue-950/40 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-400"
                            )}>
                              {result!.type.toUpperCase()}
                            </span>
                            {result!.proxy && <BoolBadge value={result!.proxy} trueLabel={t("ip.proxy")} />}
                            {result!.hosting && <BoolBadge value={result!.hosting} trueLabel={t("ip.hosting")} />}
                            {result!.mobile && <BoolBadge value={result!.mobile} trueLabel={t("ip.mobile")} />}
                          </div>
                          {result!.resolvedFrom && (
                            <p className="text-xs text-muted-foreground mt-0.5">
                              {t("ip.resolved_from")} <span className="font-mono">{result!.resolvedFrom}</span>
                            </p>
                          )}
                          <p className="text-base font-semibold mt-2">
                            {[result!.city, result!.region, result!.country].filter(Boolean).join(", ")}
                          </p>
                          <p className="text-sm text-muted-foreground">{result!.isp || result!.org || "—"}</p>
                        </div>
                      </div>
                    </div>

                    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                        <RiMapPinLine className="w-3.5 h-3.5 text-muted-foreground" />
                        <h3 className="text-sm font-bold">{t("ip.geo_section")}</h3>
                        {result!.lat !== null && result!.lon !== null && (
                          <a
                            href={`https://www.openstreetmap.org/?mlat=${result!.lat}&mlon=${result!.lon}&zoom=10`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="ml-auto flex items-center gap-1 text-[10px] text-primary hover:underline"
                          >
                            {t("ip.map_link")} <RiExternalLinkLine className="w-2.5 h-2.5" />
                          </a>
                        )}
                      </div>
                      <div className="px-5">
                        <InfoRow label={t("ip.country")} value={result!.country ? `${result!.flag || ""} ${result!.country} (${result!.countryCode})` : null} copyLabel={copyLabel} />
                        <InfoRow label={t("ip.region")} value={result!.region} copyLabel={copyLabel} />
                        <InfoRow label={t("ip.city")} value={result!.city} copyLabel={copyLabel} />
                        <InfoRow label={t("ip.district")} value={result!.district} copyLabel={copyLabel} />
                        <InfoRow label={t("ip.zip")} value={result!.zip} mono copyLabel={copyLabel} />
                        <InfoRow label={t("ip.coords")} value={result!.lat !== null ? `${result!.lat}, ${result!.lon}` : null} mono copyLabel={copyLabel} />
                        <InfoRow label={t("ip.currency")} value={result!.currency} copyLabel={copyLabel} />
                      </div>
                    </div>

                    {result!.lat !== null && result!.lon !== null && (
                      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-4 py-3 flex items-center gap-3">
                          <div className="w-9 h-9 rounded-xl bg-violet-500/10 flex items-center justify-center shrink-0">
                            <RiMapPinLine className="w-4 h-4 text-violet-500" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-mono text-foreground/80">{result!.lat}, {result!.lon}</p>
                            <p className="text-[11px] text-muted-foreground mt-0.5">{[result!.city, result!.region, result!.country].filter(Boolean).join(", ")}</p>
                          </div>
                          <div className="flex gap-1.5 shrink-0">
                            <a
                              href={`https://www.openstreetmap.org/?mlat=${result!.lat}&mlon=${result!.lon}&zoom=10`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[10px] px-2 py-1 rounded-lg border border-border hover:bg-muted transition-colors flex items-center gap-1 text-muted-foreground hover:text-foreground"
                            >
                              OSM <RiExternalLinkLine className="w-2.5 h-2.5" />
                            </a>
                            <a
                              href={`https://www.google.com/maps?q=${result!.lat},${result!.lon}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-[10px] px-2 py-1 rounded-lg border border-border hover:bg-muted transition-colors flex items-center gap-1 text-muted-foreground hover:text-foreground"
                            >
                              Google <RiExternalLinkLine className="w-2.5 h-2.5" />
                            </a>
                          </div>
                        </div>
                      </div>
                    )}

                    <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                      <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                        <RiWifiLine className="w-3.5 h-3.5 text-muted-foreground" />
                        <h3 className="text-sm font-bold">{t("ip.net_section")}</h3>
                      </div>
                      <div className="px-5">
                        <InfoRow label="ISP" value={result!.isp} copyLabel={copyLabel} />
                        <InfoRow label={t("ip.org")} value={result!.org} copyLabel={copyLabel} />
                        <InfoRow label="ASN" value={result!.as} mono copyLabel={copyLabel} />
                        <InfoRow label={t("ip.asn_name")} value={result!.asname} copyLabel={copyLabel} />
                        <InfoRow label={t("ip.reverse_dns")} value={result!.reverse} mono copyLabel={copyLabel} />
                        {result!.rdap?.cidr && (
                          <InfoRow label={t("ip.cidr")} value={result!.rdap.cidr} mono copyLabel={copyLabel} />
                        )}
                      </div>
                    </div>

                    {result!.rdap?.abuse_email && (
                      <div className="glass-panel border border-red-200 dark:border-red-900/60 rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-red-200/60 dark:border-red-900/40 bg-red-50/50 dark:bg-red-950/20 flex items-center gap-2">
                          <RiShieldLine className="w-3.5 h-3.5 text-red-500" />
                          <h3 className="text-sm font-bold text-red-700 dark:text-red-400">{t("ip.abuse_section")}</h3>
                        </div>
                        <div className="px-5 py-3 flex items-start gap-3">
                          <span className="text-xs text-muted-foreground w-24 shrink-0 pt-0.5">{t("ip.abuse_email")}</span>
                          <AbuseTag email={result!.rdap.abuse_email} />
                        </div>
                      </div>
                    )}

                    {result!.timezone && (
                      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                          <RiTimeLine className="w-3.5 h-3.5 text-muted-foreground" />
                          <h3 className="text-sm font-bold">{t("ip.tz_section")}</h3>
                        </div>
                        <div className="px-5">
                          <InfoRow label={t("ip.timezone")} value={result!.timezone} mono copyLabel={copyLabel} />
                          <InfoRow label={t("ip.utc_offset")} value={result!.offset !== null ? `UTC${result!.offset >= 0 ? "+" : ""}${result!.offset / 3600}` : null} mono copyLabel={copyLabel} />
                        </div>
                      </div>
                    )}

                    <div className="glass-panel border border-border rounded-2xl p-4 flex flex-wrap gap-3">
                      {[
                        { label: t("ip.proxy"),   value: result!.proxy,   icon: RiShieldLine },
                        { label: t("ip.hosting"), value: result!.hosting, icon: RiServerLine },
                        { label: t("ip.mobile"),  value: result!.mobile,  icon: RiWifiLine },
                      ].map(({ label, value, icon: Icon }) => (
                        <div key={label} className={cn(
                          "flex items-center gap-2 px-3 py-2 rounded-xl border text-xs font-medium",
                          value === true
                            ? "bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400"
                            : "bg-muted border-border text-muted-foreground opacity-60"
                        )}>
                          <Icon className="w-3.5 h-3.5" />
                          {label}
                          <span className={cn("text-[10px] font-bold", value === true ? "text-amber-600" : "text-muted-foreground")}>
                            {value === true ? t("ip.yes") : value === false ? t("ip.no") : "—"}
                          </span>
                        </div>
                      ))}
                    </div>

                    {result!.rdap && Object.keys(result!.rdap).length > 0 && (
                      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-border bg-muted/20 flex items-center gap-2">
                          <RiServerLine className="w-3.5 h-3.5 text-muted-foreground" />
                          <h3 className="text-sm font-bold">{t("ip.rdap_net_section")}</h3>
                        </div>
                        <div className="px-5">
                          {result!.rdap.name && <InfoRow label={t("ip.net_name")} value={result!.rdap.name} copyLabel={copyLabel} />}
                          {result!.rdap.handle && <InfoRow label="Handle" value={result!.rdap.handle} mono copyLabel={copyLabel} />}
                          {result!.rdap.startAddress && <InfoRow label={t("ip.seg_start")} value={result!.rdap.startAddress} mono copyLabel={copyLabel} />}
                          {result!.rdap.endAddress && <InfoRow label={t("ip.seg_end")} value={result!.rdap.endAddress} mono copyLabel={copyLabel} />}
                          {result!.rdap.ipVersion && <InfoRow label={t("ip.ip_version")} value={result!.rdap.ipVersion} copyLabel={copyLabel} />}
                          {result!.rdap.contact_org && <InfoRow label={t("ip.reg_org")} value={result!.rdap.contact_org} copyLabel={copyLabel} />}
                          {result!.rdap.description && <InfoRow label={t("ip.description")} value={result!.rdap.description} copyLabel={copyLabel} />}
                        </div>
                      </div>
                    )}

                    <div className="flex items-start gap-2 text-[10px] text-muted-foreground/60">
                      <RiAlertLine className="w-3 h-3 shrink-0 mt-0.5" />
                      <span>{t("ip.footer")}</span>
                      <Link href={`/feedback?type=ip&q=${encodeURIComponent(result!.query)}`} className="ml-auto shrink-0 hover:text-foreground transition-colors">
                        {t("ip.feedback")}
                      </Link>
                    </div>
                  </>
                )}
              </motion.div>
            ) : (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={FADE}>
                <div className="text-center py-14 space-y-2">
                  <div className="w-14 h-14 rounded-2xl bg-violet-500/8 border border-violet-500/20 flex items-center justify-center mx-auto mb-4">
                    <RiGlobalLine className="w-7 h-7 text-violet-500/60" />
                  </div>
                  <p className="text-sm font-medium text-muted-foreground">{t("ip.empty_title")}</p>
                  <p className="text-xs text-muted-foreground/60">{t("ip.empty_subtitle")}</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </ScrollArea>
    </>
  );
}
