import React from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { RiCheckLine, RiAlertLine, RiLoader4Line, RiArrowLeftLine } from "@remixicon/react";
import en from "../../../locales/en.json";

type State = "loading" | "success" | "not_found" | "error";
type RemindKey = keyof (typeof en)["remind"];

export default function CancelPage() {
  const router = useRouter();
  const { t } = useTranslation();
  const r = (key: RemindKey, params?: Record<string, string | number>) =>
    t(`remind.${key}` as TranslationKey, params);

  const [state, setState] = React.useState<State>("loading");
  const [domain, setDomain] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [called, setCalled] = React.useState(false);

  React.useEffect(() => {
    if (!router.isReady || called) return;
    const token = String(router.query.token || "").trim();
    if (!token) {
      setState("error");
      return;
    }
    setCalled(true);
    fetch(`/api/remind/cancel?token=${encodeURIComponent(token)}`)
      .then(async (res) => {
        const data = await res.json();
        if (data.ok) {
          setDomain(data.domain || "");
          setEmail(data.email || "");
          setState("success");
        } else if (data.error === "not_found") {
          setState("not_found");
        } else {
          setState("error");
        }
      })
      .catch(() => setState("error"));
  }, [router.isReady, router.query.token, called]);

  return (
    <>
      <Head>
        <title key="title">{`${r("cancel_title")} — WHOIS`}</title>
      </Head>

      <div className="min-h-[calc(100vh-64px)] bg-background flex items-center justify-center px-4">
        <div className="w-full max-w-sm">

          {state === "loading" && (
            <div className="flex flex-col items-center gap-4 py-12">
              <div className="w-14 h-14 rounded-full bg-muted/40 flex items-center justify-center">
                <RiLoader4Line className="w-7 h-7 text-muted-foreground animate-spin" />
              </div>
              <p className="text-sm text-muted-foreground">{r("cancel_loading")}</p>
            </div>
          )}

          {state === "success" && (
            <div className="glass-panel border border-emerald-300/40 dark:border-emerald-700/30 rounded-2xl p-8 text-center space-y-4">
              <div className="relative w-16 h-16 mx-auto">
                <div className="absolute inset-0 rounded-full bg-emerald-500/15 animate-ping" />
                <div className="relative w-16 h-16 bg-emerald-500/10 border-2 border-emerald-400/40 rounded-full flex items-center justify-center">
                  <RiCheckLine className="w-8 h-8 text-emerald-500" />
                </div>
              </div>
              <div className="space-y-2">
                <h1 className="text-xl font-bold text-emerald-700 dark:text-emerald-300">
                  {r("cancel_success_title")}
                </h1>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {r("cancel_success_domain", { domain })}
                  <br />
                  <span className="text-xs opacity-70">{r("cancel_success_email", { email })}</span>
                </p>
              </div>
              <Button
                variant="outline"
                className="gap-2 rounded-xl"
                onClick={() => router.push(domain ? `/${domain}` : "/")}
              >
                <RiArrowLeftLine className="w-4 h-4" />
                {r("cancel_go_home")}
              </Button>
            </div>
          )}

          {state === "not_found" && (
            <div className="glass-panel border border-border rounded-2xl p-8 text-center space-y-4">
              <div className="w-16 h-16 mx-auto rounded-full bg-muted/40 border-2 border-border flex items-center justify-center">
                <RiAlertLine className="w-8 h-8 text-muted-foreground" />
              </div>
              <div className="space-y-2">
                <h1 className="text-xl font-bold text-foreground">
                  {r("cancel_not_found_title")}
                </h1>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {r("cancel_not_found_desc")}
                </p>
              </div>
              <Button
                variant="outline"
                className="gap-2 rounded-xl"
                onClick={() => router.push("/")}
              >
                <RiArrowLeftLine className="w-4 h-4" />
                {r("cancel_go_home")}
              </Button>
            </div>
          )}

          {state === "error" && (
            <div className="glass-panel border border-red-200/60 dark:border-red-800/40 rounded-2xl p-8 text-center space-y-4">
              <div className="w-16 h-16 mx-auto rounded-full bg-red-50/60 dark:bg-red-950/20 border-2 border-red-200/50 flex items-center justify-center">
                <RiAlertLine className="w-8 h-8 text-red-500" />
              </div>
              <div className="space-y-2">
                <h1 className="text-xl font-bold text-foreground">
                  {r("cancel_error_title")}
                </h1>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {r("cancel_error_desc")}
                </p>
              </div>
              <Button
                variant="outline"
                className="gap-2 rounded-xl"
                onClick={() => router.push("/")}
              >
                <RiArrowLeftLine className="w-4 h-4" />
                {r("cancel_go_home")}
              </Button>
            </div>
          )}

        </div>
      </div>
    </>
  );
}
