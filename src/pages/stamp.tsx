import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiArrowLeftLine,
  RiShieldCheckLine,
  RiCheckLine,
  RiVipCrownLine,
  RiInformationLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { HowItWorksGuide } from "@/components/stamp/HowItWorksGuide";
import { TAG_STYLES } from "@/components/stamp/TagStylePicker";
import { DnsVerificationPanel } from "@/components/stamp/DnsVerificationPanel";
import { StampResultCard } from "@/components/stamp/StampResultCard";
import { TagBadge } from "@/components/stamp/TagBadge";
import { StampLandingPage } from "@/components/stamp/StampLandingPage";
import { MemberBanner } from "@/components/stamp/MemberBanner";
import { StampFormCard } from "@/components/stamp/StampFormCard";

const SPECIAL_THEME_IDS = ["celebrate", "neon", "gradient", "split", "flash"] as const;

type Step = "form" | "verify" | "done";

interface StampSession {
  step: Step;
  form: { tagName: string; tagStyle: string; cardTheme: string; link: string; description: string; nickname: string; email: string };
  submitResult: { id: string; txtRecord: string; txtValue: string } | null;
}

function getSessionKey(domain: string) { return `stamp_session_${domain}`; }

function loadSession(domain: string): StampSession | null {
  if (typeof window === "undefined") return null;
  try { const raw = localStorage.getItem(getSessionKey(domain)); return raw ? JSON.parse(raw) : null; } catch { return null; }
}

function saveSession(domain: string, data: StampSession) {
  if (typeof window === "undefined") return;
  try { localStorage.setItem(getSessionKey(domain), JSON.stringify(data)); } catch {}
}

function clearSession(domain: string) {
  if (typeof window === "undefined") return;
  try { localStorage.removeItem(getSessionKey(domain)); } catch {}
}

function loadUserPrefs(): { nickname: string; email: string } | null {
  if (typeof window === "undefined") return null;
  try { const raw = localStorage.getItem("stamp_user_prefs"); return raw ? JSON.parse(raw) : null; } catch { return null; }
}

function saveUserPrefs(nickname: string, email: string) {
  if (typeof window === "undefined") return;
  try { localStorage.setItem("stamp_user_prefs", JSON.stringify({ nickname, email })); } catch {}
}

const STEP_LABELS: { key: Step }[] = [
  { key: "form" },
  { key: "verify" },
  { key: "done" },
];

const stepIndex = (step: Step) => STEP_LABELS.findIndex((s) => s.key === step);

const stepVariants = {
  enter: (dir: number) => ({ opacity: 0, x: dir > 0 ? 32 : -32, filter: "blur(3px)" }),
  center: { opacity: 1, x: 0, filter: "blur(0px)" },
  exit: (dir: number) => ({ opacity: 0, x: dir > 0 ? -32 : 32, filter: "blur(3px)" }),
};

const POLL_SCHEDULE = [30, 60, 120, 300, 600, 900, 1200] as const;

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

export default function StampPage() {
  const router = useRouter();
  const { data: session, status: authStatus } = useSession();
  const isMember = !!(session?.user as any)?.subscriptionAccess;
  const { t, locale } = useTranslation();
  const isZh = locale.startsWith("zh");
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  const domain = String(router.query.domain || "");

  React.useEffect(() => {
    if (authStatus === "unauthenticated" && domain) {
      const callbackUrl = `/stamp?domain=${encodeURIComponent(domain)}`;
      router.replace(`/login?callbackUrl=${encodeURIComponent(callbackUrl)}`);
    }
  }, [authStatus, domain, router]);

  const defaultForm = { tagName: "", tagStyle: "personal", cardTheme: "app", link: "", description: "", nickname: "", email: "" };

  const [hydrated, setHydrated] = React.useState(false);
  const [existingStamps, setExistingStamps] = React.useState<{ id: string; tagName: string; tagStyle: string; cardTheme: string; link: string; description: string; nickname: string }[]>([]);
  const [previewThemeKey, setPreviewThemeKey] = React.useState<string | null>(null);
  const [cardThemeManual, setCardThemeManual] = React.useState(false);
  const [existingExpanded, setExistingExpanded] = React.useState(false);
  const [step, setStep] = React.useState<Step>("form");
  const [direction, setDirection] = React.useState(1);
  const [loading, setLoading] = React.useState(false);
  const [form, setForm] = React.useState(defaultForm);
  const [submitResult, setSubmitResult] = React.useState<{ id: string; txtRecord: string; txtValue: string } | null>(null);
  const [formError, setFormError] = React.useState<string | null>(null);
  const [verifyState, setVerifyState] = React.useState<"idle" | "loading" | "fail" | "dnsError" | "nearMatch" | "giveUp">("idle");
  const [pollAttempt, setPollAttempt] = React.useState(0);
  const pollAttemptRef = React.useRef(0);
  const notifiedRef = React.useRef(false);
  const [resolvers, setResolvers] = React.useState<{ name: string; proto?: string; latencyMs: number; found: boolean; nearMatch?: boolean; records: string[]; error: string | null }[]>([]);
  const [anyNearMatch, setAnyNearMatch] = React.useState(false);
  const [anyRecordFound, setAnyRecordFound] = React.useState(false);
  const [expectedVal, setExpectedVal] = React.useState<string | null>(null);
  const [httpCheck, setHttpCheck] = React.useState<{ found: boolean; latencyMs: number; error: string | null; url: string; nearMatch?: boolean } | null>(null);
  const [verifyTab, setVerifyTab] = React.useState<"dns" | "http" | "vercel">("dns");
  const [quickTxtLoading, setQuickTxtLoading] = React.useState(false);
  const [quickTxtResult, setQuickTxtResult] = React.useState<{ found: boolean; flat: string[]; records: string[][]; latencyMs: number; tokenFound?: boolean; resolvers: { name: string; proto?: string; records: string[][]; flat?: string[]; latencyMs: number; error?: string | null }[] } | null>(null);
  const [countdown, setCountdown] = React.useState(0);
  const pollRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // Vercel verification state
  const [vercelTxtValue, setVercelTxtValue] = React.useState<string | null>(null);
  const [vercelTxtFullDomain, setVercelTxtFullDomain] = React.useState<string | null>(null);
  const [vercelApiError, setVercelApiError] = React.useState<string | null>(null);
  const [vercelInitLoading, setVercelInitLoading] = React.useState(false);
  const [vercelCheckLoading, setVercelCheckLoading] = React.useState(false);
  const [vercelCheckAttempt, setVercelCheckAttempt] = React.useState(0);
  const [vercelCountdown, setVercelCountdown] = React.useState(0);
  const vercelPollRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const vercelCountdownRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // Style/guide state
  const [previewStyleId, setPreviewStyleId] = React.useState<string | null>(null);
  const GUIDE_KEY = "stamp_guide_seen";
  const [showGuide, setShowGuide] = React.useState(false);

  React.useEffect(() => {
    if (!hydrated) return;
    if (!domain && !localStorage.getItem(GUIDE_KEY)) setShowGuide(true);
  }, [hydrated, domain]);

  function dismissGuide() {
    setShowGuide(false);
    localStorage.setItem(GUIDE_KEY, "1");
  }

  function goToStep(next: Step) {
    setDirection(stepIndex(next) > stepIndex(step) ? 1 : -1);
    setStep(next);
  }

  React.useEffect(() => {
    if (!domain || hydrated) return;
    const saved = loadSession(domain);
    const prefs = loadUserPrefs();
    if (saved) {
      const restoredStep = saved.step === "done" ? "form" : saved.step;
      setStep(restoredStep);
      const restoredForm = saved.form || defaultForm;
      if (!restoredForm.email && prefs?.email) restoredForm.email = prefs.email;
      if (!restoredForm.nickname && prefs?.nickname) restoredForm.nickname = prefs.nickname;
      setForm(restoredForm);
      setSubmitResult(saved.submitResult || null);
    } else if (prefs) {
      setForm(prev => ({ ...prev, nickname: prefs.nickname || prev.nickname, email: prefs.email || prev.email }));
    }
    setHydrated(true);
  }, [domain]);

  React.useEffect(() => {
    if (!domain || !hydrated) return;
    if (step === "done") { clearSession(domain); return; }
    saveSession(domain, { step, form, submitResult });
  }, [step, form, submitResult, domain, hydrated]);

  const sessionUserEmail = session?.user?.email ?? null;
  React.useEffect(() => {
    if (!hydrated || !sessionUserEmail) return;
    setForm(prev => ({ ...prev, email: prev.email || sessionUserEmail }));
  }, [hydrated, sessionUserEmail]);

  React.useEffect(() => {
    if (!domain) return;
    fetch(`/api/stamp/check?domain=${encodeURIComponent(domain)}`)
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data.stamps)) {
          setExistingStamps(data.stamps);
          const first = data.stamps[0];
          if (first?.cardTheme && !cardThemeManual) setForm(prev => ({ ...prev, cardTheme: first.cardTheme }));
        }
      })
      .catch(() => {});
  }, [domain]);

  function goBack() {
    clearSession(domain);
    stopPolling();
    if (window.history.length > 1) router.back();
    else router.push(domain ? `/${domain}` : "/");
  }

  function update(field: string, value: string) {
    if (field === "cardTheme") setCardThemeManual(true);
    setForm((prev) => {
      const next = { ...prev, [field]: value };
      if (field === "tagStyle") {
        const isSpecial = (SPECIAL_THEME_IDS as readonly string[]).includes(prev.cardTheme);
        if (!isSpecial) {
          const ts = TAG_STYLES.find(s => s.id === value);
          if (ts) next.cardTheme = ts.theme;
        }
      }
      return next;
    });
    if (formError) setFormError(null);
  }

  async function handleSubmit() {
    setFormError(null);
    if (!form.tagName.trim()) { setFormError(s("err_tag_name")); return; }
    if (!form.nickname.trim()) { setFormError(s("err_nickname")); return; }
    if (!form.email.trim()) { setFormError(s("err_email_empty")); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) { setFormError(s("err_email_invalid")); return; }
    let cleanLink = form.link.trim();
    if (cleanLink && !/^https?:\/\//i.test(cleanLink)) cleanLink = `https://${cleanLink}`;
    if (cleanLink && !/^https?:\/\/[^\s]+\.[^\s]+/i.test(cleanLink)) { setFormError(s("err_link_invalid")); return; }
    setLoading(true);
    try {
      const res = await fetch("/api/stamp/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, ...form, link: cleanLink }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      saveUserPrefs(form.nickname.trim(), form.email.trim());
      setSubmitResult({ id: data.id, txtRecord: data.txtRecord, txtValue: data.txtValue });
      goToStep("verify");
    } catch (err: any) {
      const msg = err?.message || "";
      const isSafeMsg = /[\u4e00-\u9fa5]/.test(msg);
      setFormError(isSafeMsg ? msg : s("err_submit_failed"));
    } finally {
      setLoading(false);
    }
  }

  function stopPolling() {
    if (pollRef.current) { clearTimeout(pollRef.current); pollRef.current = null; }
    if (countdownRef.current) { clearInterval(countdownRef.current); countdownRef.current = null; }
    setCountdown(0);
  }

  function startCountdown(sec: number, onDone: () => void) {
    stopPolling();
    setCountdown(sec);
    countdownRef.current = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) { clearInterval(countdownRef.current!); countdownRef.current = null; return 0; }
        return c - 1;
      });
    }, 1000);
    pollRef.current = setTimeout(onDone, sec * 1000);
  }

  async function handleQuickTxt() {
    if (!submitResult) return;
    setQuickTxtLoading(true);
    setQuickTxtResult(null);
    try {
      const res = await fetch(`/api/dns/records?name=${encodeURIComponent(submitResult.txtRecord)}&type=TXT`);
      const data = await res.json();
      const expectedValue = submitResult.txtValue;
      const tokenFound = (data.flat as string[] || []).some(
        (r: string) => r === expectedValue || r.includes(expectedValue)
      );
      setQuickTxtResult({ ...data, tokenFound });
      if (tokenFound) setTimeout(() => handleVerify(false), 300);
    } catch {
      setQuickTxtResult({ found: false, flat: [], records: [], latencyMs: 0, resolvers: [] });
    } finally {
      setQuickTxtLoading(false);
    }
  }

  const handleVerify = React.useCallback(async (silent = false) => {
    if (!submitResult) return;
    if (!silent) { pollAttemptRef.current = 0; setPollAttempt(0); }
    setVerifyState("loading");
    stopPolling();

    function scheduleNext() {
      const attempt = pollAttemptRef.current;
      if (attempt < POLL_SCHEDULE.length) {
        pollAttemptRef.current = attempt + 1;
        setPollAttempt(attempt + 1);
        startCountdown(POLL_SCHEDULE[attempt], () => handleVerify(true));
      } else {
        setVerifyState("giveUp");
        setCountdown(0);
        if (!notifiedRef.current && submitResult) {
          notifiedRef.current = true;
          fetch("/api/stamp/giveup-notify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: submitResult.id, domain, appUrl: typeof window !== "undefined" ? window.location.origin : "" }),
          }).catch(() => {});
        }
      }
    }

    try {
      const res = await fetch("/api/stamp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: submitResult.id, domain }),
      });
      const data = await res.json();
      if (data.resolvers) setResolvers(data.resolvers);
      if (data.httpCheck) setHttpCheck(data.httpCheck);
      if (data.anyNearMatch !== undefined) setAnyNearMatch(data.anyNearMatch);
      if (data.anyRecordFound !== undefined) setAnyRecordFound(data.anyRecordFound);
      if (data.expected) setExpectedVal(data.expected);
      if (data.verified) { goToStep("done"); setVerifyState("idle"); return; }
      else if (data.anyNearMatch) setVerifyState("nearMatch");
      else if (data.dnsError) setVerifyState("dnsError");
      else setVerifyState("fail");
      scheduleNext();
    } catch {
      setVerifyState("fail");
      scheduleNext();
    }
  }, [submitResult, domain]);

  React.useEffect(() => {
    if (step === "verify" && submitResult) {
      pollAttemptRef.current = 0;
      setPollAttempt(0);
      setVerifyState("idle");
      startCountdown(POLL_SCHEDULE[0], () => handleVerify(true));
    }
    return () => stopPolling();
  }, [step, submitResult?.id]);

  // Vercel verification helpers
  function stopVercelPolling() {
    if (vercelPollRef.current) { clearTimeout(vercelPollRef.current); vercelPollRef.current = null; }
    if (vercelCountdownRef.current) { clearInterval(vercelCountdownRef.current); vercelCountdownRef.current = null; }
    setVercelCountdown(0);
  }

  function startVercelCountdown(sec: number, onDone: () => void) {
    stopVercelPolling();
    setVercelCountdown(sec);
    vercelCountdownRef.current = setInterval(() => {
      setVercelCountdown(c => {
        if (c <= 1) { clearInterval(vercelCountdownRef.current!); vercelCountdownRef.current = null; return 0; }
        return c - 1;
      });
    }, 1000);
    vercelPollRef.current = setTimeout(onDone, sec * 1000);
  }

  const VERCEL_POLL_SCHEDULE = [30, 60, 120, 300, 600] as const;

  async function initVercelVerify() {
    if (!submitResult) return;
    setVercelInitLoading(true);
    setVercelApiError(null);
    setVercelTxtValue(null);
    setVercelTxtFullDomain(null);
    try {
      const res = await fetch("/api/vercel/add-domain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, stampId: submitResult.id }),
      });
      const data = await res.json();
      if (data.verified) { goToStep("done"); return; }
      if (data.apiError) { setVercelApiError(data.apiError); return; }
      setVercelTxtValue(data.txtValue ?? null);
      setVercelTxtFullDomain(data.txtFullDomain ?? `_vercel.${domain}`);
    } catch {
      setVercelApiError(s("network_error_retry"));
    } finally {
      setVercelInitLoading(false);
    }
  }

  const handleVercelCheck = React.useCallback(async (silent = false) => {
    if (!submitResult) return;
    setVercelCheckLoading(true);
    stopVercelPolling();
    try {
      const res = await fetch("/api/vercel/check-domain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, stampId: submitResult.id }),
      });
      const data = await res.json();
      if (data.verified) { goToStep("done"); return; }
      const attempt = vercelCheckAttempt;
      if (!silent) setVercelCheckAttempt(0);
      const nextAttempt = silent ? attempt + 1 : 1;
      setVercelCheckAttempt(nextAttempt);
      if (nextAttempt < VERCEL_POLL_SCHEDULE.length) {
        startVercelCountdown(
          VERCEL_POLL_SCHEDULE[nextAttempt - 1 < VERCEL_POLL_SCHEDULE.length ? nextAttempt - 1 : VERCEL_POLL_SCHEDULE.length - 1],
          () => handleVercelCheck(true)
        );
      }
    } catch {
      // silently fail
    } finally {
      setVercelCheckLoading(false);
    }
  }, [submitResult, domain, vercelCheckAttempt]);

  React.useEffect(() => {
    if (verifyTab === "vercel" && submitResult && !vercelTxtValue && !vercelInitLoading && !vercelApiError) {
      initVercelVerify();
    }
    if (verifyTab !== "vercel") stopVercelPolling();
  }, [verifyTab, submitResult?.id]);

  // No domain — show landing page
  if (!domain) return <StampLandingPage />;

  // Auth skeleton
  if (authStatus === "loading" || authStatus === "unauthenticated") {
    return (
      <div className="min-h-[calc(100vh-64px)] bg-background">
        <div className="max-w-lg mx-auto px-4 py-5 pb-10 space-y-4 animate-pulse">
          <div className="h-5 w-32 rounded-lg bg-muted/50" />
          <div className="h-28 rounded-2xl bg-muted/40" />
          <div className="h-48 rounded-2xl bg-muted/40" />
          <div className="h-12 rounded-xl bg-muted/35" />
        </div>
      </div>
    );
  }

  return (
    <>
      <Head>
        <title key="title">{`${s("title")} · ${domain}`}</title>
      </Head>
      <div className="min-h-[calc(100vh-64px)] bg-background">
        <div className="max-w-lg mx-auto px-4 py-5 pb-10">

          {/* Back nav */}
          <div className="flex items-center gap-2 mb-5">
            <button onClick={goBack}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors group">
              <RiArrowLeftLine className="w-4 h-4 transition-transform group-hover:-translate-x-0.5" />
              {s("back")}
            </button>
            <span className="text-muted-foreground/30">·</span>
            <span className="text-sm font-mono text-muted-foreground/80">{domain}</span>
          </div>

          {/* Session restore skeleton */}
          {!hydrated && (
            <div className="space-y-3 animate-pulse">
              <div className="h-28 rounded-2xl bg-muted/50" />
              <div className="h-8 rounded-lg bg-muted/30 w-2/3 mx-auto" />
              <div className="h-48 rounded-2xl bg-muted/40" />
              <div className="h-12 rounded-xl bg-muted/35" />
            </div>
          )}

          {hydrated && (
            <>
              {/* Header */}
              <div className="flex items-center justify-between mb-5">
                <div className="flex items-center gap-2">
                  <RiShieldCheckLine className="w-4 h-4 text-violet-500 shrink-0" />
                  <h1 className="text-sm font-bold text-foreground">{s("title")}</h1>
                  {step !== "done" && (
                    <span className="text-[10px] text-muted-foreground/60 font-medium">
                      · {s("step", { current: stepIndex(step) + 1 })}
                    </span>
                  )}
                </div>
                {step === "form" && (
                  <button type="button" onClick={() => setShowGuide(true)}
                    className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded-lg hover:bg-muted/60">
                    <RiInformationLine className="w-3.5 h-3.5" />
                    {s("how_it_works_section")}
                  </button>
                )}
              </div>

              {/* Step indicator */}
              {step !== "done" && (
                <div className="flex items-center mb-5 px-1">
                  {STEP_LABELS.filter(sl => sl.key !== "done").map((sl, i) => {
                    const cur = stepIndex(step);
                    const isActive = sl.key === step;
                    const isDone = i < cur;
                    return (
                      <React.Fragment key={sl.key}>
                        <div className="flex items-center gap-1.5">
                          <div className={cn(
                            "w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold transition-all",
                            isActive ? "bg-violet-500 text-white shadow-sm shadow-violet-500/30"
                              : isDone ? "bg-emerald-500 text-white"
                              : "bg-muted text-muted-foreground"
                          )}>
                            {isDone ? <RiCheckLine className="w-3 h-3" /> : i + 1}
                          </div>
                          <span className={cn(
                            "text-xs font-medium transition-colors",
                            isActive ? "text-foreground" : isDone ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"
                          )}>
                            {t(`stamp.step_${sl.key}`)}
                          </span>
                        </div>
                        {i < STEP_LABELS.filter(sl => sl.key !== "done").length - 1 && (
                          <div className={cn("flex-1 h-px mx-2 transition-colors", isDone ? "bg-emerald-400/60" : "bg-border")} />
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              )}

              {/* Animated step content */}
              <AnimatePresence mode="wait" custom={direction} initial={false}>
                <motion.div
                  key={step}
                  custom={direction}
                  variants={stepVariants}
                  initial="enter"
                  animate="center"
                  exit="exit"
                  transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
                >
                  {/* ── STEP 1: FORM ── */}
                  {step === "form" && (
                    <div className="space-y-4">

                      {/* Existing stamps notice */}
                      {existingStamps.length > 0 && (
                        <div className="rounded-2xl border border-amber-200/60 dark:border-amber-800/40 bg-amber-50/60 dark:bg-amber-950/20 p-4">
                          <button type="button" onClick={() => setExistingExpanded(!existingExpanded)}
                            className="flex items-center justify-between w-full">
                            <span className="text-xs font-semibold text-amber-700 dark:text-amber-300">
                              {s("existing_count", { count: existingStamps.length })}
                            </span>
                            <span className="text-[10px] text-amber-600/70">
                              {existingExpanded ? s("existing_collapse") : s("existing_expand")}
                            </span>
                          </button>
                          {existingExpanded && (
                            <div className="flex flex-wrap gap-2 mt-3">
                              {existingStamps.map((st) => (
                                <TagBadge key={st.id} tagName={st.tagName} tagStyle={st.tagStyle} />
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Member vs Free banner */}
                      <MemberBanner isMember={isMember} isZh={isZh} />

                      {/* Form card */}
                      <StampFormCard
                        form={form}
                        domain={domain}
                        isMember={isMember}
                        isZh={isZh}
                        loading={loading}
                        formError={formError}
                        previewStyleId={previewStyleId}
                        previewThemeKey={previewThemeKey}
                        onUpdate={update}
                        onSubmit={handleSubmit}
                        onPreviewStyleOpen={(id) => setPreviewStyleId(id)}
                        onPreviewStyleClose={() => setPreviewStyleId(null)}
                        onPreviewThemeOpen={(key) => setPreviewThemeKey(key)}
                        onPreviewThemeClose={() => setPreviewThemeKey(null)}
                        onSpecialDeselect={() => {
                          const ts = TAG_STYLES.find(ts => ts.id === form.tagStyle);
                          setCardThemeManual(false);
                          setForm(prev => ({ ...prev, cardTheme: ts?.theme || "app" }));
                        }}
                      />
                    </div>
                  )}

                  {/* ── STEP 2: VERIFY ── */}
                  {step === "verify" && submitResult && (
                    <DnsVerificationPanel
                      submitResult={submitResult}
                      domain={domain}
                      verifyState={verifyState}
                      verifyTab={verifyTab}
                      resolvers={resolvers}
                      anyNearMatch={anyNearMatch}
                      anyRecordFound={anyRecordFound}
                      expectedVal={expectedVal}
                      httpCheck={httpCheck}
                      pollAttempt={pollAttempt}
                      countdown={countdown}
                      quickTxtLoading={quickTxtLoading}
                      quickTxtResult={quickTxtResult}
                      vercel={{
                        txtValue: vercelTxtValue,
                        txtFullDomain: vercelTxtFullDomain,
                        apiError: vercelApiError,
                        initLoading: vercelInitLoading,
                        checkLoading: vercelCheckLoading,
                        checkAttempt: vercelCheckAttempt,
                        countdown: vercelCountdown,
                      }}
                      onVerify={handleVerify}
                      onQuickTxt={handleQuickTxt}
                      onTabChange={setVerifyTab}
                      onBackEdit={() => { stopPolling(); goToStep("form"); }}
                      onVercelInit={initVercelVerify}
                      onVercelCheck={handleVercelCheck}
                      onVercelCheckAttemptReset={() => setVercelCheckAttempt(0)}
                    />
                  )}

                  {/* ── STEP 3: DONE ── */}
                  {step === "done" && (
                    <StampResultCard
                      form={form}
                      submitResult={submitResult}
                      onGoBack={goBack}
                      renderTagBadge={(tagName, tagStyle, live) => (
                        <TagBadge tagName={tagName} tagStyle={tagStyle} live={live} />
                      )}
                    />
                  )}
                </motion.div>
              </AnimatePresence>

              {/* Guide modal */}
              <HowItWorksGuide show={showGuide} onDismiss={dismissGuide} />
            </>
          )}
        </div>
      </div>
    </>
  );
}
