import React from "react";
import Head from "next/head";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { motion, AnimatePresence } from "framer-motion";
import { RiLoader4Line, RiMailLine, RiArrowLeftLine, RiCheckLine, RiAlertLine, RiSendPlaneLine } from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";

export default function ForgotPasswordPage() {
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteName = settings.site_logo_text || "X.RW";
  const [email, setEmail] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [sent, setSent] = React.useState(false);
  const [resendCooldown, setResendCooldown] = React.useState(0);

  React.useEffect(() => {
    if (resendCooldown <= 0) return;
    const timer = setTimeout(() => setResendCooldown(c => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim()) { setError(t("auth.forgot_err_email")); return; }
    setLoading(true);
    try {
      const res = await fetch("/api/user/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || t("auth.forgot_err_failed")); return; }
      setSent(true);
      setResendCooldown(60);
    } catch {
      setError(t("auth.forgot_err_network"));
    } finally {
      setLoading(false);
    }
  }

  async function handleResend() {
    if (resendCooldown > 0) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/user/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || t("auth.forgot_err_failed")); return; }
      setResendCooldown(60);
    } catch {
      setError(t("auth.forgot_err_network"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Head><title key="title">{`${t("auth.forgot_page_title")} · ${siteName}`}</title></Head>
      <div className="min-h-screen flex items-center justify-center px-4 py-16 relative overflow-hidden">
        {/* Ambient glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] rounded-full bg-primary/4 dark:bg-primary/6 blur-[80px] pointer-events-none" />

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          className="w-full max-w-sm relative"
        >
          <div className="text-center mb-8">
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.08, duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
              className="relative inline-flex items-center justify-center mb-4"
            >
              <div className="absolute inset-0 rounded-2xl bg-primary/15 blur-xl" />
              <div className="relative inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-primary/20 via-primary/10 to-violet-600/10 border border-primary/20 shadow-lg shadow-primary/10">
                <AnimatePresence mode="wait">
                  {sent ? (
                    <motion.div key="check" initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 20 }}>
                      <RiCheckLine className="w-6 h-6 text-emerald-500" />
                    </motion.div>
                  ) : (
                    <motion.div key="mail" initial={{ scale: 0 }} animate={{ scale: 1 }}>
                      <RiMailLine className="w-6 h-6 text-primary" />
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
            <h1 className="text-2xl font-bold tracking-tight">{t("auth.forgot_title")}</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {sent ? t("auth.forgot_subtitle_sent") : t("auth.forgot_subtitle")}
            </p>
          </div>

          <AnimatePresence mode="wait">
            {sent ? (
              <motion.div
                key="success"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
                className="space-y-4"
              >
                <div className="glass-panel border border-emerald-400/40 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-2xl p-6 space-y-4">
                  <div className="h-0.5 w-full bg-gradient-to-r from-transparent via-emerald-400/40 to-transparent -mt-0.5" />
                  <div className="flex flex-col items-center text-center space-y-2.5">
                    <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-950/50 border border-emerald-200/60 dark:border-emerald-800/40 flex items-center justify-center">
                      <RiSendPlaneLine className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                    </div>
                    <div>
                      <p className="font-semibold text-sm">{t("auth.forgot_sent_title")}</p>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        {t("auth.forgot_sent_desc").replace("{{email}}", email)}
                      </p>
                    </div>
                    <p className="text-[11px] text-muted-foreground/70 bg-muted/40 rounded-lg px-3 py-1.5">{t("auth.forgot_sent_expire")}</p>
                  </div>

                  <AnimatePresence>
                    {error && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        exit={{ opacity: 0, height: 0 }}
                      >
                        <div className="flex items-start gap-2 text-xs text-red-500 bg-red-50/70 dark:bg-red-950/20 border border-red-200/50 dark:border-red-800/30 rounded-xl px-3 py-2.5">
                          <RiAlertLine className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                          <span>{error}</span>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Resend button */}
                  <button
                    type="button"
                    onClick={handleResend}
                    disabled={loading || resendCooldown > 0}
                    className="w-full text-xs text-muted-foreground hover:text-primary transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 py-1"
                  >
                    {loading ? (
                      <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />发送中…</>
                    ) : resendCooldown > 0 ? (
                      `${resendCooldown}秒后可重新发送`
                    ) : (
                      <><RiMailLine className="w-3.5 h-3.5" />重新发送邮件</>
                    )}
                  </button>
                </div>
              </motion.div>
            ) : (
              <motion.div
                key="form"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
              >
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div className="glass-panel border border-border/80 rounded-2xl overflow-hidden shadow-sm">
                    <div className="h-0.5 w-full bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
                    <div className="p-6 space-y-4">
                      <div className="space-y-1.5">
                        <Label htmlFor="email" className="text-xs font-semibold">{t("auth.forgot_email_label")}</Label>
                        <div className="relative">
                          <RiMailLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                          <Input
                            id="email"
                            type="email"
                            autoComplete="email"
                            placeholder="you@example.com"
                            value={email}
                            onChange={e => { setEmail(e.target.value); setError(null); }}
                            className="pl-9 h-10 rounded-xl"
                            disabled={loading}
                          />
                        </div>
                      </div>

                      <AnimatePresence>
                        {error && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="overflow-hidden"
                          >
                            <div className="flex items-start gap-2 text-xs text-red-500 bg-red-50/70 dark:bg-red-950/20 border border-red-200/50 dark:border-red-800/30 rounded-xl px-3 py-2.5">
                              <RiAlertLine className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                              <span>{error}</span>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>

                      <Button type="submit" disabled={loading}
                        className="w-full h-10 rounded-xl font-semibold text-sm gap-2">
                        {loading
                          ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{t("auth.forgot_submitting")}</>
                          : <><RiSendPlaneLine className="w-4 h-4" />{t("auth.forgot_submit")}</>
                        }
                      </Button>
                    </div>
                  </div>
                </form>
              </motion.div>
            )}
          </AnimatePresence>

          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="text-center text-xs text-muted-foreground mt-5"
          >
            <Link href="/login" className="inline-flex items-center gap-1 text-primary font-semibold hover:underline">
              <RiArrowLeftLine className="w-3 h-3" />{t("auth.forgot_back_login")}
            </Link>
          </motion.p>
        </motion.div>
      </div>
    </>
  );
}
