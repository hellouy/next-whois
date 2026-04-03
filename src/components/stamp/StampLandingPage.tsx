import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  RiArrowLeftLine,
  RiShieldCheckLine,
  RiCheckLine,
  RiExternalLinkLine,
  RiAlertLine,
  RiLoader4Line,
  RiTimeLine,
  RiArrowRightLine,
  RiDeleteBinLine,
  RiSearchLine,
  RiCheckboxCircleLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { TagBadge } from "./TagBadge";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

const RiAwardLine = (props: React.SVGProps<SVGSVGElement>) => (
  <svg viewBox="0 0 24 24" fill="currentColor" {...props}>
    <path d="M17 3H21V5H20L16.998 14.001L16.998 14C18.76 14 20 15.343 20 17C20 18.657 18.657 20 17 20H7C5.343 20 4 18.657 4 17C4 15.343 5.24 14 7.002 14L4 5H3V3H7L10 12H14L17 3ZM17 16H7C6.448 16 6 16.448 6 17C6 17.552 6.448 18 7 18H17C17.552 18 18 17.552 18 17C18 16.448 17.552 16 17 16ZM10.333 5H8.626L11 12H13L10.333 5Z" />
  </svg>
);

export function StampLandingPage() {
  const router = useRouter();
  const { t, locale } = useTranslation();
  const sl = (key: StampKey) => t(`stamp.${key}` as TranslationKey);
  const { data: session, status: authStatus } = useSession();
  const settings = useSiteSettings();
  const siteName = settings.site_logo_text || "X.RW";
  const [query, setQuery] = React.useState("");
  const [myStamps, setMyStamps] = React.useState<{
    id: string; domain: string; tag_name: string; tag_style: string;
    verified: boolean; created_at: string; verified_at: string | null;
    link: string | null; nickname: string;
  }[]>([]);
  const [stampsLoading, setStampsLoading] = React.useState(false);
  const [deletingId, setDeletingId] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (authStatus === "authenticated") {
      setStampsLoading(true);
      fetch("/api/user/stamps")
        .then(r => r.json())
        .then(d => { if (d.stamps) setMyStamps(d.stamps); })
        .catch(() => {})
        .finally(() => setStampsLoading(false));
    }
  }, [authStatus]);

  async function deleteStamp(id: string) {
    setDeletingId(id);
    try {
      await fetch(`/api/user/stamps?id=${id}`, { method: "DELETE" });
      setMyStamps(prev => prev.filter(s => s.id !== id));
      toast.success(sl("delete_success"));
    } catch {
      toast.error(sl("delete_fail"));
    } finally {
      setDeletingId(null);
    }
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;
    router.push(`/stamp?domain=${encodeURIComponent(q)}`);
  }

  const steps = [
    { icon: RiSearchLine, color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400", title: sl("landing_step1_title"), desc: sl("landing_step1_desc") },
    { icon: RiShieldCheckLine, color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400", title: sl("landing_step2_title"), desc: sl("landing_step2_desc") },
    { icon: RiCheckboxCircleLine, color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400", title: sl("landing_step3_title"), desc: sl("landing_step3_desc") },
    { icon: RiCheckboxCircleLine, color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400", title: sl("landing_step4_title"), desc: sl("landing_step4_desc") },
  ];

  const verifiedStamps = myStamps.filter(s => s.verified);
  const pendingStamps = myStamps.filter(s => !s.verified);

  return (
    <>
      <Head>
        <title key="title">{`${sl("page_title_main")} · ${siteName}`}</title>
        <meta name="description" content={sl("page_desc_main")} />
      </Head>
      <div className="max-w-lg mx-auto px-4 py-8 pb-10 space-y-6">
        <Link href="/dashboard" className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
          <RiArrowLeftLine className="w-3.5 h-3.5" />{sl("back_dashboard")}
        </Link>

        {/* Hero */}
        <div className="relative rounded-2xl overflow-hidden border border-violet-200/40 dark:border-violet-800/30">
          <div className="absolute inset-0 bg-gradient-to-br from-violet-500/8 via-transparent to-fuchsia-500/5 dark:from-violet-500/15 dark:to-fuchsia-500/8" />
          <div className="relative px-5 py-5 flex items-center gap-4">
            <div className="shrink-0 w-12 h-12 rounded-2xl bg-violet-500/10 border border-violet-300/30 dark:border-violet-700/40 flex items-center justify-center">
              <RiShieldCheckLine className="w-6 h-6 text-violet-500" />
            </div>
            <div>
              <h1 className="text-lg font-bold">{sl("page_title_main")}</h1>
              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{sl("page_desc_main")}</p>
            </div>
          </div>
        </div>

        {/* My claims */}
        {authStatus === "authenticated" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{sl("my_claims")}</p>
              {myStamps.length > 0 && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  {verifiedStamps.length > 0 && (
                    <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                      <RiCheckLine className="w-3 h-3" />{sl("verified_count").replace("{{n}}", String(verifiedStamps.length))}
                    </span>
                  )}
                  {pendingStamps.length > 0 && (
                    <span className="inline-flex items-center gap-1 text-amber-500">
                      <RiTimeLine className="w-3 h-3" />{sl("pending_count").replace("{{n}}", String(pendingStamps.length))}
                    </span>
                  )}
                </div>
              )}
            </div>
            {stampsLoading ? (
              <div className="flex justify-center py-6">
                <RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" />
              </div>
            ) : myStamps.length === 0 ? (
              <div className="glass-panel border border-dashed border-border rounded-2xl p-6 text-center space-y-2">
                <RiAwardLine className="w-7 h-7 text-muted-foreground/25 mx-auto" />
                <p className="text-sm text-muted-foreground">{sl("empty_claims")}</p>
                <p className="text-xs text-muted-foreground/60">{sl("empty_claims_hint")}</p>
              </div>
            ) : (
              <div className="space-y-2">
                {myStamps.map(stamp => (
                  <div key={stamp.id} className={cn(
                    "glass-panel border rounded-2xl p-4 flex items-center gap-3",
                    stamp.verified ? "border-border" : "border-amber-200/60 dark:border-amber-800/40 bg-amber-50/20 dark:bg-amber-950/10"
                  )}>
                    <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0",
                      stamp.verified ? "bg-emerald-100 dark:bg-emerald-950/40" : "bg-amber-100 dark:bg-amber-950/40")}>
                      {stamp.verified
                        ? <RiCheckLine className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                        : <RiTimeLine className="w-4 h-4 text-amber-500" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <p className="text-sm font-semibold font-mono truncate">{stamp.domain}</p>
                        <TagBadge tagName={stamp.tag_name} tagStyle={stamp.tag_style} live={stamp.verified} />
                      </div>
                      <p className="text-[11px] mt-0.5 text-muted-foreground">
                        {stamp.verified
                          ? sl("verified_at").replace("{{date}}", stamp.verified_at ? new Date(stamp.verified_at).toLocaleDateString(locale) : "")
                          : sl("pending_status")}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {stamp.verified ? (
                        <Link href={`/${stamp.domain}`} title={sl("view_whois")}
                          className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                          <RiExternalLinkLine className="w-3.5 h-3.5" />
                        </Link>
                      ) : (
                        <Link href={`/stamp?domain=${encodeURIComponent(stamp.domain)}`}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/40 transition-colors">
                          {sl("continue_verify")}
                        </Link>
                      )}
                      <button onClick={() => deleteStamp(stamp.id)} disabled={deletingId === stamp.id}
                        title={sl("delete")} className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors">
                        {deletingId === stamp.id ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiDeleteBinLine className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Login prompt */}
        {authStatus === "unauthenticated" && (
          <div className="glass-panel border border-violet-200/40 dark:border-violet-800/30 rounded-2xl p-5 text-center space-y-3">
            <RiShieldCheckLine className="w-7 h-7 text-violet-500/50 mx-auto" />
            <div>
              <p className="text-sm font-semibold">{sl("login_manage_title")}</p>
              <p className="text-xs text-muted-foreground mt-1">{sl("login_manage_desc")}</p>
            </div>
            <div className="flex gap-2 justify-center">
              <Link href="/login?callbackUrl=%2Fstamp">
                <Button size="sm" className="rounded-xl h-9 gap-1.5 text-xs bg-violet-600 hover:bg-violet-700">{sl("login_btn")}</Button>
              </Link>
              <Link href="/register?callbackUrl=%2Fstamp">
                <Button size="sm" variant="outline" className="rounded-xl h-9 gap-1.5 text-xs">{sl("register_btn")}</Button>
              </Link>
            </div>
          </div>
        )}

        {/* Visual mockup */}
        <div className="space-y-2">
          <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground px-1">{sl("find_entry")}</p>
          <div className="relative rounded-2xl border border-border bg-muted/10 p-4">
            <span className="absolute top-3 right-3 text-[9px] font-bold uppercase tracking-widest text-muted-foreground/50 bg-muted/60 px-2 py-0.5 rounded-full">{sl("preview_label")}</span>
            <div className="rounded-xl border border-border bg-background shadow-sm overflow-hidden">
              <div className="px-4 pt-3.5 pb-2 space-y-1.5">
                <p className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground/50">DOMAIN</p>
                <p className="text-sm font-bold font-mono tracking-tight">EXAMPLE.COM</p>
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />Active
                  </span>
                  <span className="text-[10px] text-muted-foreground">⏱ 2 years</span>
                </div>
              </div>
              <div className="px-4 pb-3.5 flex items-center gap-2">
                <div className="relative flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-semibold border bg-violet-100 dark:bg-violet-950/50 border-violet-400/70 text-violet-600 dark:text-violet-400 shadow-sm ring-2 ring-violet-400/20">
                  <RiShieldCheckLine className="w-3 h-3" />
                  {sl("page_title_main")}
                  <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-60" />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-violet-500" />
                  </span>
                </div>
                <div className="flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-medium border bg-muted/40 border-border/50 text-muted-foreground/50">
                  <RiTimeLine className="w-3 h-3" />
                  {t("remind.domain_subscription")}
                </div>
              </div>
            </div>
            <p className="text-[10px] text-muted-foreground text-center mt-2.5">{sl("desktop_hint")}</p>
          </div>
        </div>

        {/* Search */}
        <div className="border border-border rounded-2xl p-4 space-y-3 bg-muted/10">
          <div className="flex items-center gap-2">
            <RiSearchLine className="w-4 h-4 text-primary" />
            <p className="text-sm font-bold">{sl("search_title")}</p>
          </div>
          <form onSubmit={handleSearch} className="flex gap-2">
            <Input value={query} onChange={e => setQuery(e.target.value)}
              placeholder={sl("search_placeholder")} className="h-10 rounded-xl text-sm font-mono flex-1" autoComplete="off" />
            <Button type="submit" className="h-10 rounded-xl gap-1.5 px-4 shrink-0">
              {sl("claim_btn")}<RiArrowRightLine className="w-3.5 h-3.5" />
            </Button>
          </form>
          <p className="text-xs text-muted-foreground">{sl("search_redirect_hint")}</p>
        </div>

        {/* Steps */}
        <div className="space-y-3">
          <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground px-1">{sl("how_it_works_section")}</p>
          <div className="grid gap-2.5">
            {steps.map((step, i) => (
              <div key={i} className="flex items-start gap-3 p-3.5 rounded-xl border border-border bg-muted/10">
                <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0", step.color)}>
                  <step.icon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <span className="text-[9px] font-bold text-muted-foreground/40 uppercase tracking-widest">{sl("step_n").replace("{{n}}", String(i + 1))}</span>
                  </div>
                  <p className="text-xs font-semibold">{step.title}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Info note */}
        <div className="flex items-start gap-2 px-3 py-3 rounded-xl bg-amber-50/50 dark:bg-amber-950/20 border border-amber-200/40">
          <RiAlertLine className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
          <p className="text-[11px] text-muted-foreground">{sl("info_note")}</p>
        </div>
      </div>
    </>
  );
}
