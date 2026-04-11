import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  RiLoader4Line, RiLockLine, RiEyeLine, RiEyeOffLine,
  RiCheckLine, RiArrowLeftLine, RiErrorWarningLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";

export default function ResetPasswordPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const settings = useSiteSettings();
  const siteName = settings.site_logo_text || "WHOIS";
  const { token } = router.query;
  const [password, setPassword] = React.useState("");
  const [confirm, setConfirm] = React.useState("");
  const [showPwd, setShowPwd] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [done, setDone] = React.useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!password || password.length < 8) { setError(t("auth.reset_err_password_min")); return; }
    if (password !== confirm) { setError(t("auth.reset_err_password_mismatch")); return; }
    if (!token) { setError(t("auth.reset_err_invalid_token")); return; }
    setLoading(true);
    try {
      const res = await fetch("/api/user/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || t("auth.reset_err_failed")); return; }
      setDone(true);
      toast.success(t("auth.reset_success"));
      setTimeout(() => router.replace("/login"), 2500);
    } catch {
      setError(t("auth.reset_err_network"));
    } finally {
      setLoading(false);
    }
  }

  const isInvalidToken = !token && router.isReady;

  return (
    <>
      <Head><title key="title">{`${t("auth.reset_page_title")} · ${siteName}`}</title></Head>
      <div className="min-h-screen flex items-center justify-center px-4 py-16">
        <div className="w-full max-w-sm">
          <div className="text-center mb-8">
            <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4">
              <RiLockLine className="w-6 h-6 text-primary" />
            </div>
            <h1 className="text-2xl font-bold">
              {done ? t("auth.reset_title_done") : t("auth.reset_title")}
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              {done ? t("auth.reset_subtitle_done") : t("auth.reset_subtitle")}
            </p>
          </div>

          {isInvalidToken ? (
            <div className="glass-panel border border-red-300/40 bg-red-50/30 dark:bg-red-950/20 rounded-2xl p-6 text-center space-y-3">
              <RiErrorWarningLine className="w-8 h-8 text-red-500 mx-auto" />
              <p className="font-semibold text-sm">{t("auth.reset_invalid_title")}</p>
              <p className="text-xs text-muted-foreground">{t("auth.reset_invalid_desc")}</p>
              <Link href="/forgot-password">
                <Button size="sm" className="mt-2">{t("auth.reset_invalid_button")}</Button>
              </Link>
            </div>
          ) : done ? (
            <div className="glass-panel border border-emerald-400/40 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-2xl p-6 text-center space-y-4">
              <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center mx-auto">
                <RiCheckLine className="w-6 h-6 text-emerald-600" />
              </div>
              <p className="font-semibold text-sm">{t("auth.reset_done_title")}</p>
              <p className="text-xs text-muted-foreground">{t("auth.reset_done_desc")}</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="glass-panel border border-border rounded-2xl p-6 space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="password" className="text-xs font-semibold">
                    {t("auth.reset_new_password")} <span className="text-muted-foreground font-normal">{t("auth.reset_new_password_min")}</span>
                  </Label>
                  <div className="relative">
                    <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                    <Input
                      id="password"
                      type={showPwd ? "text" : "password"}
                      autoComplete="new-password"
                      placeholder={t("auth.reset_new_password_placeholder")}
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className="pl-9 pr-10 h-10 rounded-xl"
                      maxLength={128}
                    />
                    <button type="button" onClick={() => setShowPwd(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/60 hover:text-foreground transition-colors">
                      {showPwd ? <RiEyeOffLine className="w-4 h-4" /> : <RiEyeLine className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="confirm" className="text-xs font-semibold">{t("auth.reset_confirm_password")}</Label>
                  <div className="relative">
                    <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/60" />
                    <Input
                      id="confirm"
                      type={showPwd ? "text" : "password"}
                      autoComplete="new-password"
                      placeholder={t("auth.reset_confirm_placeholder")}
                      value={confirm}
                      onChange={e => setConfirm(e.target.value)}
                      className="pl-9 h-10 rounded-xl"
                      maxLength={128}
                    />
                  </div>
                </div>

                {error && (
                  <p className="text-xs text-red-500 bg-red-50/60 dark:bg-red-950/20 border border-red-200/50 rounded-lg px-3 py-2">
                    {error}
                  </p>
                )}

                <Button type="submit" disabled={loading || !token}
                  className="w-full h-10 rounded-xl font-semibold text-sm gap-2">
                  {loading
                    ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{t("auth.reset_submitting")}</>
                    : t("auth.reset_submit")
                  }
                </Button>
              </div>
            </form>
          )}

          <p className="text-center text-xs text-muted-foreground mt-5">
            <Link href="/login" className="inline-flex items-center gap-1 text-primary font-semibold hover:underline">
              <RiArrowLeftLine className="w-3 h-3" />{t("auth.reset_back_login")}
            </Link>
          </p>
        </div>
      </div>
    </>
  );
}
