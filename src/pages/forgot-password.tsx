import React from "react";
import Head from "next/head";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RiLoader4Line, RiMailLine, RiArrowLeftLine, RiCheckLine } from "@remixicon/react";
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
    } catch {
      setError(t("auth.forgot_err_network"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Head><title key="title">{`${t("auth.forgot_page_title")} · ${siteName}`}</title></Head>
      <div className="min-h-screen flex items-center justify-center px-4 py-16">
        <div className="w-full max-w-sm">
          <div className="text-center mb-8">
            <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto mb-4">
              <RiMailLine className="w-6 h-6 text-primary" />
            </div>
            <h1 className="text-2xl font-bold">{t("auth.forgot_title")}</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {sent ? t("auth.forgot_subtitle_sent") : t("auth.forgot_subtitle")}
            </p>
          </div>

          {sent ? (
            <div className="glass-panel border border-emerald-400/40 bg-emerald-50/30 dark:bg-emerald-950/20 rounded-2xl p-6 text-center space-y-4">
              <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center mx-auto">
                <RiCheckLine className="w-6 h-6 text-emerald-600" />
              </div>
              <div>
                <p className="font-semibold text-sm">{t("auth.forgot_sent_title")}</p>
                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                  {t("auth.forgot_sent_desc").replace("{{email}}", email)}
                </p>
              </div>
              <p className="text-xs text-muted-foreground">{t("auth.forgot_sent_expire")}</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="glass-panel border border-border rounded-2xl p-6 space-y-4">
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
                      onChange={e => setEmail(e.target.value)}
                      className="pl-9 h-10 rounded-xl"
                    />
                  </div>
                </div>

                {error && (
                  <p className="text-xs text-red-500 bg-red-50/60 dark:bg-red-950/20 border border-red-200/50 rounded-lg px-3 py-2">
                    {error}
                  </p>
                )}

                <Button type="submit" disabled={loading}
                  className="w-full h-10 rounded-xl font-semibold text-sm gap-2">
                  {loading
                    ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{t("auth.forgot_submitting")}</>
                    : t("auth.forgot_submit")
                  }
                </Button>
              </div>
            </form>
          )}

          <p className="text-center text-xs text-muted-foreground mt-5">
            <Link href="/login" className="inline-flex items-center gap-1 text-primary font-semibold hover:underline">
              <RiArrowLeftLine className="w-3 h-3" />{t("auth.forgot_back_login")}
            </Link>
          </p>
        </div>
      </div>
    </>
  );
}
