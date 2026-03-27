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
  RiArrowLeftSLine, RiFlagLine, RiCheckLine, RiLoader4Line,
  RiServerLine, RiLockLine, RiGlobalLine,
  RiSparkling2Line, RiCloseCircleLine,
} from "@remixicon/react";

type QueryType = "domain" | "dns" | "ssl" | "ip" | "general";

const FADE = { duration: 0.18, ease: "easeOut" as const };

export default function FeedbackPage() {
  const router = useRouter();
  const settings = useSiteSettings();
  const { t } = useTranslation();

  const rawType = (router.query.type as string) || "general";
  const queryType: QueryType = ["domain", "dns", "ssl", "ip", "general"].includes(rawType)
    ? (rawType as QueryType)
    : "general";
  const initQuery = (router.query.q as string) || "";
  const source    = (router.query.source as string) || "";

  const ISSUE_OPTIONS: Record<QueryType, { key: string; label: string }[]> = {
    domain: [
      { key: "inaccurate",   label: t("feedback.inaccurate") },
      { key: "incomplete",   label: t("feedback.incomplete") },
      { key: "outdated",     label: t("feedback.outdated") },
      { key: "parse_error",  label: t("feedback.parse_error") },
      { key: "other",        label: t("feedback.other_issue") },
    ],
    dns: [
      { key: "resolve_failed",  label: t("feedback.resolve_failed") },
      { key: "wrong_result",    label: t("feedback.wrong_result") },
      { key: "missing_record",  label: t("feedback.missing_record") },
      { key: "inaccurate",      label: t("feedback.inaccurate") },
      { key: "other",           label: t("feedback.other_issue") },
    ],
    ssl: [
      { key: "cert_error",     label: t("feedback.cert_error") },
      { key: "chain_error",    label: t("feedback.chain_error") },
      { key: "expired_wrong",  label: t("feedback.expired_wrong") },
      { key: "wrong_result",   label: t("feedback.wrong_result") },
      { key: "other",          label: t("feedback.other_issue") },
    ],
    ip: [
      { key: "wrong_location", label: t("feedback.wrong_location") },
      { key: "wrong_isp",      label: t("feedback.wrong_isp") },
      { key: "wrong_asn",      label: t("feedback.wrong_asn") },
      { key: "inaccurate",     label: t("feedback.inaccurate") },
      { key: "other",          label: t("feedback.other_issue") },
    ],
    general: [
      { key: "feature_request", label: t("feedback.feature_request") },
      { key: "bug_report",      label: t("feedback.bug_report") },
      { key: "question",        label: t("feedback.question") },
      { key: "other",           label: t("feedback.other_general") },
    ],
  };

  const TYPE_META: Record<QueryType, { label: string; desc: string; icon: React.ElementType; color: string; placeholder: string }> = {
    domain: {
      label: t("feedback.page_title_domain"),
      desc: t("feedback.page_desc_domain"),
      icon: RiGlobalLine,
      color: "text-primary bg-primary/10",
      placeholder: t("feedback.placeholder_domain"),
    },
    dns: {
      label: t("feedback.page_title_dns"),
      desc: t("feedback.page_desc_dns"),
      icon: RiServerLine,
      color: "text-blue-600 dark:text-blue-400 bg-blue-500/10",
      placeholder: t("feedback.placeholder_dns"),
    },
    ssl: {
      label: t("feedback.page_title_ssl"),
      desc: t("feedback.page_desc_ssl"),
      icon: RiLockLine,
      color: "text-emerald-600 dark:text-emerald-400 bg-emerald-500/10",
      placeholder: t("feedback.placeholder_ssl"),
    },
    ip: {
      label: t("feedback.page_title_ip"),
      desc: t("feedback.page_desc_ip"),
      icon: RiGlobalLine,
      color: "text-violet-600 dark:text-violet-400 bg-violet-500/10",
      placeholder: t("feedback.placeholder_ip"),
    },
    general: {
      label: t("feedback.page_title_general"),
      desc: t("feedback.page_desc_general"),
      icon: RiSparkling2Line,
      color: "text-rose-600 dark:text-rose-400 bg-rose-500/10",
      placeholder: "",
    },
  };

  const meta = TYPE_META[queryType];
  const Icon = meta.icon;
  const options = ISSUE_OPTIONS[queryType];

  const [query, setQuery] = React.useState(initQuery);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [description, setDescription] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);
  const openedAt = React.useRef(Date.now());
  const [hp, setHp] = React.useState("");

  React.useEffect(() => {
    setQuery((router.query.q as string) || "");
    setSelected(new Set());
    setDescription("");
    setDone(false);
    openedAt.current = Date.now();
  }, [router.query.q, router.query.type]);

  function toggle(key: string) {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (queryType !== "general" && !query.trim()) {
      toast.error(t("feedback.err_no_query"));
      return;
    }
    if (selected.size === 0) {
      toast.error(t("feedback.err_no_type"));
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: query.trim() || "（通用反馈）",
          queryType,
          issueTypes: Array.from(selected),
          description: description.trim(),
          email: email.trim(),
          _hp: hp,
          _t: openedAt.current,
        }),
      });
      const data = await res.json();
      if (!res.ok) { toast.error(data?.error || t("feedback.err_failed")); return; }
      setDone(true);
    } catch {
      toast.error(t("feedback.err_network"));
    } finally {
      setSubmitting(false);
    }
  }

  const SOURCE_BACK: Record<string, string> = {
    sponsor: "/sponsor", links: "/links", about: "/about",
    dns: "/dns", ssl: "/ssl", ip: "/ip",
  };
  const TYPE_BACK: Record<QueryType, string> = {
    domain: "/", dns: "/dns", ssl: "/ssl", ip: "/ip", general: "/",
  };
  const backHref = source && SOURCE_BACK[source] ? SOURCE_BACK[source] : TYPE_BACK[queryType];

  const feedbackDisabled = settings.enable_feedback === "0" || settings.enable_feedback === "";

  return (
    <>
      <Head>
        <title key="title">{`${meta.label} — ${settings.site_logo_text || "X.RW"}`}</title>
      </Head>
      <ScrollArea className="w-full h-[calc(100vh-4rem)]">
        <main className="w-full max-w-xl mx-auto px-4 sm:px-6 py-6">
          <div className="flex items-center gap-3 mb-6">
            <Link href={backHref} className="p-1.5 rounded-lg hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground touch-manipulation">
              <RiArrowLeftSLine className="w-5 h-5" />
            </Link>
            <div className="flex items-center gap-2">
              <div className={cn("p-1.5 rounded-lg", meta.color)}>
                <Icon className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold leading-none">{meta.label}</h1>
                <p className="text-[11px] text-muted-foreground mt-0.5">{meta.desc}</p>
              </div>
            </div>
          </div>

          {feedbackDisabled && (
            <div className="flex items-start gap-3 rounded-2xl border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-4 mb-4 text-sm text-amber-800 dark:text-amber-300">
              <RiCloseCircleLine className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">{t("feedback.disabled_title")}</p>
                <p className="text-xs mt-0.5 opacity-80">{t("feedback.disabled_desc")}</p>
              </div>
            </div>
          )}

          <AnimatePresence mode="wait" initial={false}>
            {done ? (
              <motion.div
                key="done"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.25 }}
                className="text-center py-16 space-y-4"
              >
                <div className="w-16 h-16 rounded-full bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center mx-auto">
                  <RiCheckLine className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />
                </div>
                <div>
                  <p className="text-xl font-bold">{t("feedback.thanks_title")}</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    {t("feedback.thanks_body")}
                  </p>
                </div>
                <div className="flex justify-center gap-3 pt-2">
                  <Button variant="outline" onClick={() => { setDone(false); setSelected(new Set()); setDescription(""); setQuery(""); }} className="rounded-xl gap-2">
                    <RiFlagLine className="w-4 h-4" />{t("feedback.resubmit")}
                  </Button>
                  <Button onClick={() => router.push(backHref)} className="rounded-xl">
                    {t("feedback.back_btn")}
                  </Button>
                </div>
              </motion.div>
            ) : (
              <motion.form
                key="form"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={FADE}
                onSubmit={submit}
                className="space-y-5"
              >
                {queryType !== "general" && (
                  <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                    <label className="text-xs font-semibold text-muted-foreground">{t("feedback.query_target")}</label>
                    <Input
                      value={query}
                      onChange={e => setQuery(e.target.value)}
                      placeholder={meta.placeholder}
                      className="h-10 rounded-xl font-mono"
                      autoFocus={!initQuery}
                    />
                  </div>
                )}

                <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <label className="text-xs font-semibold text-muted-foreground">
                    {t("feedback.issue_type_label")} <span className="text-red-500">*</span>
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {options.map(opt => (
                      <button
                        key={opt.key}
                        type="button"
                        onClick={() => toggle(opt.key)}
                        className={cn(
                          "py-2.5 px-3 rounded-xl text-sm font-medium border transition-all touch-manipulation text-left",
                          selected.has(opt.key)
                            ? "bg-primary text-primary-foreground border-primary shadow-sm"
                            : "bg-muted/40 border-border text-foreground hover:border-primary/40 hover:bg-muted/60"
                        )}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <label className="text-xs font-semibold text-muted-foreground">{t("feedback.detail_label")}</label>
                  <textarea
                    value={description}
                    onChange={e => setDescription(e.target.value.slice(0, 500))}
                    placeholder={queryType === "general" ? t("feedback.detail_placeholder_general") : t("feedback.detail_placeholder_specific")}
                    rows={4}
                    className="w-full text-sm rounded-xl border border-border bg-muted/20 px-3 py-2.5 resize-none placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/50 transition-colors"
                  />
                  <p className="text-[10px] text-muted-foreground text-right">{description.length}/500</p>
                </div>

                <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                  <label className="text-xs font-semibold text-muted-foreground">{t("feedback.email_label")}</label>
                  <Input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="your@email.com"
                    className="h-10 rounded-xl"
                  />
                </div>

                <div style={{ display: "none" }} aria-hidden>
                  <input tabIndex={-1} value={hp} onChange={e => setHp(e.target.value)} autoComplete="off" />
                </div>

                <Button
                  type="submit"
                  disabled={submitting || selected.size === 0 || feedbackDisabled}
                  className="w-full h-11 rounded-xl gap-2 text-sm font-semibold"
                >
                  {submitting
                    ? <RiLoader4Line className="w-4 h-4 animate-spin" />
                    : <RiFlagLine className="w-4 h-4" />
                  }
                  {submitting ? t("feedback.submitting") : t("feedback.submit_btn")}
                </Button>

                <p className="text-[10px] text-muted-foreground/50 text-center leading-relaxed">
                  {t("feedback.privacy_note")}
                </p>
              </motion.form>
            )}
          </AnimatePresence>
        </main>
      </ScrollArea>
    </>
  );
}
