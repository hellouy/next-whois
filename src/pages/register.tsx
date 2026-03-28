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
  RiLoader4Line, RiUserAddLine, RiMailLine,
  RiLockLine, RiEyeLine, RiEyeOffLine, RiUserLine,
  RiAlertLine, RiCheckLine, RiKeyLine,
  RiSendPlaneLine, RiShieldKeyholeLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { useSiteSettings } from "@/lib/site-settings";
import { useTranslation } from "@/lib/i18n";

interface StrengthResult { score: number; label: string; color: string; }

function getStrength(pwd: string, labels: string[]): StrengthResult {
  if (!pwd) return { score: 0, label: "", color: "bg-muted" };
  let s = 0;
  if (pwd.length >= 8) s++;
  if (pwd.length >= 12) s++;
  if (/[A-Z]/.test(pwd)) s++;
  if (/[0-9]/.test(pwd)) s++;
  if (/[^A-Za-z0-9]/.test(pwd)) s++;
  if (s <= 1) return { score: 1, label: labels[0], color: "bg-red-500" };
  if (s <= 2) return { score: 2, label: labels[1], color: "bg-amber-500" };
  if (s <= 3) return { score: 3, label: labels[2], color: "bg-yellow-500" };
  if (s <= 4) return { score: 4, label: labels[3], color: "bg-emerald-500" };
  return { score: 5, label: labels[4], color: "bg-emerald-600" };
}

export default function RegisterPage() {
  const router = useRouter();
  const { status } = useSession();
  const settings = useSiteSettings();
  const { t } = useTranslation();
  const [name, setName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [inviteCode, setInviteCode] = React.useState("");
  const [verifyCode, setVerifyCode] = React.useState("");
  const [codeSent, setCodeSent] = React.useState(false);
  const [codeCooldown, setCodeCooldown] = React.useState(0);
  const [sendingCode, setSendingCode] = React.useState(false);
  const [showPwd, setShowPwd] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [captchaToken, setCaptchaToken] = React.useState("");
  const captchaRef = React.useRef<HTMLDivElement>(null);
  const captchaWidgetId = React.useRef<unknown>(null);

  React.useEffect(() => {
    if (status === "authenticated") router.replace("/dashboard");
  }, [status, router]);

  React.useEffect(() => {
    if (codeCooldown <= 0) return;
    const timer = setInterval(() => setCodeCooldown(c => c - 1), 1000);
    return () => clearInterval(timer);
  }, [codeCooldown]);

  const captchaProvider = settings.captcha_provider;
  const captchaSiteKey = settings.captcha_site_key;

  React.useEffect(() => {
    if (!captchaProvider || !captchaSiteKey) return;
    const scriptId = `captcha-script-${captchaProvider}`;
    const w = window as unknown as Record<string, unknown>;

    if (captchaProvider === "mtcaptcha") {
      (w as any).mtcaptchaConfig = {
        sitekey: captchaSiteKey,
        callback: (detail: { verifyResult: string }) => setCaptchaToken(detail.verifyResult || ""),
        "expired-callback": () => setCaptchaToken(""),
        "error-callback": () => setCaptchaToken(""),
      };
      if (!document.getElementById(scriptId)) {
        const script = document.createElement("script");
        script.id = scriptId;
        script.src = "https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js";
        script.async = true;
        document.head.appendChild(script);
      } else if ((w as any).mtcaptcha) {
        setTimeout(() => {
          if (!captchaRef.current || captchaWidgetId.current !== null) return;
          (w as any).mtcaptcha.renderUI(captchaRef.current);
          captchaWidgetId.current = true;
        }, 200);
      }
      return;
    }

    if (!document.getElementById(scriptId)) {
      const scriptUrls: Record<string, string> = {
        turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
        hcaptcha: "https://js.hcaptcha.com/1/api.js?render=explicit",
      };
      const script = document.createElement("script");
      script.id = scriptId;
      script.src = scriptUrls[captchaProvider] || "";
      script.async = true;
      script.defer = true;
      script.onload = () => renderCaptcha();
      document.head.appendChild(script);
    } else {
      renderCaptcha();
    }
    function renderCaptcha() {
      setTimeout(() => {
        if (!captchaRef.current || captchaWidgetId.current !== null) return;
        if (captchaProvider === "turnstile" && w.turnstile) {
          captchaWidgetId.current = (w.turnstile as {
            render: (el: HTMLElement, opts: Record<string, unknown>) => unknown;
          }).render(captchaRef.current, {
            sitekey: captchaSiteKey,
            callback: (tk: string) => setCaptchaToken(tk),
            "expired-callback": () => setCaptchaToken(""),
            "error-callback": () => setCaptchaToken(""),
          });
        } else if (captchaProvider === "hcaptcha" && w.hcaptcha) {
          captchaWidgetId.current = (w.hcaptcha as {
            render: (el: HTMLElement, opts: Record<string, unknown>) => unknown;
          }).render(captchaRef.current, {
            sitekey: captchaSiteKey,
            callback: (tk: string) => setCaptchaToken(tk),
            "expired-callback": () => setCaptchaToken(""),
            "error-callback": () => setCaptchaToken(""),
          });
        }
      }, 200);
    }
  }, [captchaProvider, captchaSiteKey]);

  function resetCaptcha() {
    const w = window as unknown as Record<string, unknown>;
    if (captchaProvider === "mtcaptcha" && (w as any).mtcaptcha) {
      (w as any).mtcaptcha.resetUI();
      captchaWidgetId.current = null;
    } else if (captchaProvider === "turnstile" && w.turnstile && captchaWidgetId.current !== null) {
      (w.turnstile as { reset: (id: unknown) => void }).reset(captchaWidgetId.current);
    } else if (captchaProvider === "hcaptcha" && w.hcaptcha && captchaWidgetId.current !== null) {
      (w.hcaptcha as { reset: (id: unknown) => void }).reset(captchaWidgetId.current);
    }
    setCaptchaToken("");
  }

  async function handleSendCode() {
    if (!email.trim()) { setError(t("auth.register_err_email_required")); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) { setError(t("auth.register_err_email_invalid")); return; }
    if (captchaProvider && captchaSiteKey && !captchaToken) {
      setError(t("auth.register_err_captcha"));
      return;
    }
    setSendingCode(true);
    setError(null);
    try {
      const res = await fetch("/api/user/send-verify-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim().toLowerCase() }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || t("auth.register_err_send_failed")); return; }
      setCodeSent(true);
      setCodeCooldown(60);
      toast.success(t("auth.register_code_hint").replace("{{email}}", email.trim()));
    } catch {
      setError(t("auth.register_err_network"));
    } finally {
      setSendingCode(false);
    }
  }

  const strengthLabels = [
    t("auth.register_strength_weak"),
    t("auth.register_strength_fair"),
    t("auth.register_strength_medium"),
    t("auth.register_strength_strong"),
    t("auth.register_strength_very_strong"),
  ];
  const strength = getStrength(password, strengthLabels);
  const passwordsMatch = confirm && password === confirm;
  const passwordsMismatch = confirm && password !== confirm;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim()) { setError(t("auth.register_err_email_required")); return; }
    if (!password) { setError(t("auth.register_err_password_required")); return; }
    if (password.length < 8) { setError(t("auth.register_err_password_min")); return; }
    if (password !== confirm) { setError(t("auth.register_err_password_mismatch")); return; }
    if (captchaProvider && captchaSiteKey && !captchaToken) {
      setError(t("auth.register_err_captcha"));
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/user/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          password,
          name: name.trim() || undefined,
          inviteCode: inviteCode.trim() || undefined,
          verifyCode: verifyCode.trim() || undefined,
          captchaToken: captchaToken || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || t("auth.register_err_failed"));
        resetCaptcha();
        return;
      }
      toast.success(t("auth.register_success"));
      const loginRes = await signIn("credentials", {
        redirect: false,
        email: email.trim().toLowerCase(),
        password,
      });
      if (loginRes?.ok) {
        router.replace("/dashboard");
      } else {
        router.replace("/login");
      }
    } catch {
      setError(t("auth.register_err_network"));
      resetCaptcha();
    } finally {
      setLoading(false);
    }
  }

  // Hide the form while the session is loading or if already authenticated
  // (the useEffect above will redirect them to /dashboard).
  if (status === "loading" || status === "authenticated") return null;

  const logoText = settings.site_logo_text || "X.RW";
  const registrationOpen = settings.allow_registration !== "" ? settings.allow_registration === "1" : true;

  if (!registrationOpen) {
    return (
      <>
        <Head><title key="title">{`${t("auth.register_closed_page_title")} · ${settings.site_title || "X.RW · RDAP+WHOIS"}`}</title></Head>
        <div className="min-h-screen flex items-center justify-center px-4">
          <div className="text-center space-y-4 max-w-sm">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-amber-100 dark:bg-amber-950/40 border border-amber-200/50 dark:border-amber-700/30 mb-2">
              <RiAlertLine className="w-7 h-7 text-amber-500" />
            </div>
            <h1 className="text-xl font-bold">{t("auth.register_closed_title")}</h1>
            <p className="text-sm text-muted-foreground">{t("auth.register_closed_desc")}</p>
            <Link href="/login" className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline font-semibold">
              {t("auth.register_closed_back")}
            </Link>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Head><title key="title">{`${t("auth.register_page_title")} · ${settings.site_title || "X.RW · RDAP+WHOIS"}`}</title></Head>
      <div className="min-h-screen flex items-center justify-center px-4 py-16 relative overflow-hidden">
        {/* Ambient glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[480px] h-[480px] rounded-full bg-violet-500/5 dark:bg-violet-500/8 blur-[80px] pointer-events-none" />

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
              <div className="relative inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500/25 via-primary/10 to-primary/5 border border-primary/25 shadow-lg shadow-primary/10">
                <RiUserAddLine className="w-7 h-7 text-primary" />
              </div>
            </motion.div>
            <h1 className="text-2xl font-bold tracking-tight">{t("auth.register_title")}</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {t("auth.register_subtitle").replace("{{name}}", logoText)}
            </p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <div className="glass-panel border border-border/80 rounded-2xl overflow-hidden shadow-sm">
              {/* Accent top bar */}
              <div className="h-0.5 w-full bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
              <div className="p-6 space-y-4">
              {/* Name */}
              <div className="space-y-1.5">
                <Label htmlFor="name" className="text-xs font-semibold">
                  {t("auth.register_name_label")} <span className="text-muted-foreground font-normal">{t("auth.register_name_optional")}</span>
                </Label>
                <div className="relative">
                  <RiUserLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                  <Input
                    id="name"
                    type="text"
                    placeholder={t("auth.register_name_placeholder")}
                    value={name}
                    onChange={e => setName(e.target.value)}
                    className="pl-9 h-10 rounded-xl"
                    disabled={loading}
                    maxLength={50}
                  />
                </div>
              </div>

              {/* Email */}
              <div className="space-y-1.5">
                <Label htmlFor="email" className="text-xs font-semibold">{t("auth.register_email_label")}</Label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <RiMailLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                    <Input
                      id="email"
                      type="email"
                      autoComplete="email"
                      placeholder="you@example.com"
                      value={email}
                      onChange={e => { setEmail(e.target.value); setError(null); setCodeSent(false); }}
                      className="pl-9 h-10 rounded-xl"
                      disabled={loading || sendingCode}
                    />
                  </div>
                  <button
                    type="button"
                    onClick={handleSendCode}
                    disabled={sendingCode || codeCooldown > 0 || loading || !!(captchaProvider && captchaSiteKey && !captchaToken)}
                    className={cn(
                      "shrink-0 h-10 px-3 rounded-xl text-xs font-semibold border transition-all whitespace-nowrap",
                      (captchaProvider && captchaSiteKey && !captchaToken)
                        ? "border-border text-muted-foreground/50 cursor-not-allowed opacity-60"
                        : codeCooldown > 0
                        ? "border-border text-muted-foreground cursor-not-allowed"
                        : codeSent
                        ? "border-emerald-400/60 text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/20"
                        : "border-primary/40 text-primary hover:bg-primary/5"
                    )}
                  >
                    {sendingCode
                      ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                      : codeCooldown > 0
                      ? `${codeCooldown}s`
                      : codeSent
                      ? t("auth.register_code_sent")
                      : <><RiSendPlaneLine className="inline w-3 h-3 mr-1" />{t("auth.register_send_code")}</>
                    }
                  </button>
                </div>
              </div>

              {/* CAPTCHA widget — shown directly after email, must be completed before sending code */}
              {captchaProvider && captchaSiteKey && (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-1.5">
                    <RiShieldKeyholeLine className="w-3.5 h-3.5 text-muted-foreground/70" />
                    <span className="text-xs font-semibold">{t("auth.register_captcha_label")}</span>
                    {captchaToken && (
                      <span className="text-[10px] text-emerald-600 dark:text-emerald-400 flex items-center gap-0.5 ml-auto">
                        <RiCheckLine className="w-3 h-3" />{t("auth.register_captcha_verified")}
                      </span>
                    )}
                  </div>
                  <div
                    ref={captchaRef}
                    className={cn("w-full", captchaProvider === "mtcaptcha" && "mtcaptcha")}
                    {...(captchaProvider === "mtcaptcha" ? { "data-sitekey": captchaSiteKey } : {})}
                  />
                  {!captchaToken && (
                    <p className="text-[10px] text-muted-foreground px-0.5">{t("auth.register_captcha_hint")}</p>
                  )}
                </div>
              )}

              {/* Email verification code */}
              <AnimatePresence>
                {codeSent && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="space-y-1.5">
                      <Label htmlFor="verifyCode" className="text-xs font-semibold flex items-center gap-1.5">
                        <RiShieldKeyholeLine className="w-3.5 h-3.5 text-primary" />
                        {t("auth.register_verify_label")}
                      </Label>
                      <div className="relative">
                        <Input
                          id="verifyCode"
                          type="text"
                          inputMode="numeric"
                          placeholder={t("auth.register_verify_placeholder")}
                          value={verifyCode}
                          onChange={e => { setVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6)); setError(null); }}
                          className="h-10 rounded-xl font-mono text-sm text-center tracking-[0.35em] font-semibold"
                          disabled={loading}
                          autoComplete="one-time-code"
                          maxLength={6}
                        />
                      </div>
                      <p className="text-[10px] text-muted-foreground px-0.5">
                        {t("auth.register_code_hint").replace("{{email}}", email.trim())}
                      </p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Password */}
              <div className="space-y-1.5">
                <Label htmlFor="password" className="text-xs font-semibold">
                  {t("auth.register_password_label")} <span className="text-muted-foreground font-normal">({t("auth.reset_new_password_min")})</span>
                </Label>
                <div className="relative">
                  <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                  <Input
                    id="password"
                    type={showPwd ? "text" : "password"}
                    autoComplete="new-password"
                    placeholder={t("auth.register_password_placeholder")}
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

                {/* Password strength */}
                <AnimatePresence>
                  {password && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="overflow-hidden"
                    >
                      <div className="pt-1 space-y-1">
                        <div className="flex gap-1">
                          {[1, 2, 3, 4, 5].map(i => (
                            <div
                              key={i}
                              className={cn(
                                "h-1 flex-1 rounded-full transition-all duration-300",
                                i <= strength.score ? strength.color : "bg-muted"
                              )}
                            />
                          ))}
                        </div>
                        <p className="text-[11px] text-muted-foreground">
                          {t("auth.register_strength")}<span className={cn(
                            "font-semibold",
                            strength.score <= 1 ? "text-red-500" :
                            strength.score <= 2 ? "text-amber-500" :
                            strength.score <= 3 ? "text-yellow-600" :
                            "text-emerald-600"
                          )}>{strength.label}</span>
                        </p>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Confirm password */}
              <div className="space-y-1.5">
                <Label htmlFor="confirm" className="text-xs font-semibold">{t("auth.register_confirm_label")}</Label>
                <div className="relative">
                  <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                  <Input
                    id="confirm"
                    type={showPwd ? "text" : "password"}
                    autoComplete="new-password"
                    placeholder={t("auth.register_confirm_placeholder")}
                    value={confirm}
                    onChange={e => { setConfirm(e.target.value); setError(null); }}
                    className={cn(
                      "pl-9 pr-9 h-10 rounded-xl transition-colors",
                      passwordsMatch ? "border-emerald-400/60 focus-visible:ring-emerald-400/20" :
                      passwordsMismatch ? "border-red-400/60 focus-visible:ring-red-400/20" : ""
                    )}
                    disabled={loading}
                  />
                  <AnimatePresence>
                    {(passwordsMatch || passwordsMismatch) && (
                      <motion.div
                        initial={{ opacity: 0, scale: 0.8 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.8 }}
                        className="absolute right-3 top-1/2 -translate-y-1/2"
                      >
                        {passwordsMatch
                          ? <RiCheckLine className="w-4 h-4 text-emerald-500" />
                          : <RiAlertLine className="w-4 h-4 text-red-500" />
                        }
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>

              {/* Invite code */}
              <div className="space-y-1.5">
                <Label htmlFor="inviteCode" className="text-xs font-semibold">
                  {t("auth.register_invite_label")}
                </Label>
                <div className="relative">
                  <RiKeyLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                  <Input
                    id="inviteCode"
                    type="text"
                    placeholder="XXXXXX-XXXXXX-XXXXXX"
                    value={inviteCode}
                    onChange={e => { setInviteCode(e.target.value.toUpperCase()); setError(null); }}
                    className="pl-9 h-10 rounded-xl font-mono text-sm tracking-wider"
                    disabled={loading}
                    maxLength={24}
                    autoComplete="off"
                  />
                </div>
              </div>

              {/* Error */}
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
                  ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{t("auth.register_submitting")}</>
                  : <><RiUserAddLine className="w-4 h-4" />{t("auth.register_submit")}</>
                }
              </Button>

              <p className="text-[10px] text-muted-foreground/60 text-center leading-relaxed">
                {t("auth.register_terms")}
                <Link href="/docs#terms" className="underline hover:text-primary">
                  {t("auth.register_terms_link")}
                </Link>
              </p>
              </div>{/* end p-6 */}
            </div>{/* end glass-panel */}
          </form>

          <div className="mt-5 text-center space-y-2">
            <p className="text-xs text-muted-foreground">
              {t("auth.register_have_account")}{" "}
              <Link href="/login" className="text-primary font-semibold hover:underline">
                {t("auth.register_login_link")}
              </Link>
            </p>
          </div>
        </motion.div>
      </div>
    </>
  );
}
