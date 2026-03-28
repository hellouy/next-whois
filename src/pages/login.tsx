import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { signIn, useSession } from "next-auth/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { motion, AnimatePresence } from "framer-motion";
import {
  RiLoader4Line, RiLockLine, RiMailLine,
  RiEyeLine, RiEyeOffLine, RiCheckLine, RiAlertLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";

export default function LoginPage() {
  const router = useRouter();
  const { status } = useSession();
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [showPwd, setShowPwd] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (status === "authenticated") router.replace("/dashboard");
  }, [status, router]);

  React.useEffect(() => {
    if (!router.isReady) return;
    if (router.query.msg === "require_login") {
      toast.info(t("auth.require_login_notice"));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim()) { setError(t("auth.login_err_email")); return; }
    if (!password) { setError(t("auth.login_err_password")); return; }
    setLoading(true);
    try {
      const res = await signIn("credentials", {
        redirect: false,
        email: email.trim().toLowerCase(),
        password,
      });
      if (res?.error) {
        setError(t("auth.login_err_invalid"));
      } else {
        toast.success(t("auth.login_success"));
        const callbackUrl = (router.query.callbackUrl as string) || "/dashboard";
        router.replace(callbackUrl);
      }
    } catch {
      setError(t("auth.login_err_network"));
    } finally {
      setLoading(false);
    }
  }

  const logoText = settings.site_logo_text || "X.RW";
  const subtitle = settings.site_subtitle || "RDAP+WHOIS";

  // Hide the login form while the session is loading (avoids a flash of the
  // form for already-authenticated users who are about to be redirected).
  if (status === "loading" || status === "authenticated") return null;

  return (
    <>
      <Head><title key="title">{`${t("auth.login_page_title")} · ${settings.site_title || "X.RW · RDAP+WHOIS"}`}</title></Head>
      <div className="min-h-screen flex items-center justify-center px-4 py-16 relative overflow-hidden">
        {/* Ambient glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[480px] h-[480px] rounded-full bg-primary/5 dark:bg-primary/8 blur-[80px] pointer-events-none" />

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
              <div className="absolute inset-0 rounded-2xl bg-primary/20 blur-xl" />
              <div className="relative inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-primary/25 via-primary/10 to-violet-600/10 border border-primary/25 shadow-lg shadow-primary/10">
                <RiLockLine className="w-7 h-7 text-primary" />
              </div>
            </motion.div>
            <h1 className="text-2xl font-bold tracking-tight">{t("auth.login_welcome")}</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {t("auth.login_subtitle").replace("{{name}}", logoText)}
            </p>
          </div>

          {settings.disable_login === "1" && (
            <div className="mb-4 rounded-xl border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 text-sm text-amber-800 dark:text-amber-300 text-center">
              {t("auth.login_disabled")}
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate>
            <div className="glass-panel border border-border/80 rounded-2xl overflow-hidden shadow-sm">
              {/* Accent top bar */}
              <div className="h-0.5 w-full bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
              <div className="p-6 space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email" className="text-xs font-semibold">{t("auth.login_email_label")}</Label>
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

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password" className="text-xs font-semibold">{t("auth.login_password_label")}</Label>
                  <Link href="/forgot-password" className="text-[11px] text-muted-foreground hover:text-primary transition-colors">
                    {t("auth.login_forgot")}
                  </Link>
                </div>
                <div className="relative">
                  <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                  <Input
                    id="password"
                    type={showPwd ? "text" : "password"}
                    autoComplete="current-password"
                    placeholder={t("auth.login_password_placeholder")}
                    value={password}
                    onChange={e => { setPassword(e.target.value); setError(null); }}
                    className="pl-9 pr-10 h-10 rounded-xl"
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPwd(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/60 hover:text-foreground transition-colors"
                    tabIndex={-1}
                    aria-label={showPwd ? "Hide password" : "Show password"}
                  >
                    {showPwd ? <RiEyeOffLine className="w-4 h-4" /> : <RiEyeLine className="w-4 h-4" />}
                  </button>
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

              <Button
                type="submit"
                disabled={loading}
                className="w-full h-10 rounded-xl bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-sm gap-2"
              >
                {loading
                  ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{t("auth.login_submitting")}</>
                  : <><RiCheckLine className="w-4 h-4" />{t("auth.login_submit")}</>
                }
              </Button>
              </div>
            </div>
          </form>

          <div className="mt-5 text-center space-y-2">
            <p className="text-xs text-muted-foreground">
              {t("auth.login_no_account")}{" "}
              <Link href="/register" className="text-primary font-semibold hover:underline">
                {t("auth.login_register_link")}
              </Link>
            </p>
            <p className="text-[10px] text-muted-foreground/50">{subtitle}</p>
          </div>
        </motion.div>
      </div>
    </>
  );
}
