import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import en from "../../locales/en.json";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiArrowLeftLine,
  RiShieldCheckLine,
  RiCheckLine,
  RiFileCopyLine,
  RiExternalLinkLine,
  RiAlertLine,
  RiLoader4Line,
  RiRefreshLine,
  RiTimeLine,
  RiWifiLine,
  RiServerLine,
  RiPencilLine,
  RiFlashlightLine,
  RiGlobalLine,
  RiArrowRightLine,
  RiArrowRightSLine,
  RiCloudLine,
  RiDeleteBinLine,
  RiFileTextLine,
  RiLinksLine,
  RiCheckboxCircleLine,
  RiSearchLine,
  RiIdCardLine,
  RiBuildingLine,
  RiAwardLine,
  RiShakeHandsLine,
  RiCodeSLine,
  RiVipCrownLine,
  RiCloseLine,
  RiInformationLine,
} from "@remixicon/react";
import { toast } from "sonner";
import { StampPreviewCard, STAMP_CARD_THEMES } from "@/components/stamp-preview-card";

const SPECIAL_THEME_IDS = ["celebrate", "neon", "gradient", "split", "flash"] as const;

const CARD_THEME_OPTIONS: {
  id: string; label: string; enLabel: string; hero: string; dot: string;
  shimmer: string; cardBg: string; cardBorder: string; cardText: string; btn: string;
}[] = [
  { id: "app",      label: "极简", enLabel: "Minimal",  hero: "bg-gradient-to-br from-zinc-600 to-zinc-900",                      dot: "bg-zinc-600",    shimmer: "text-shimmer",              cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-zinc-900 text-white"                              },
  { id: "official", label: "官方", enLabel: "Official", hero: "bg-gradient-to-br from-blue-600 to-indigo-800",                    dot: "bg-blue-700",    shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-blue-700 text-white"                               },
  { id: "aurora",   label: "极光", enLabel: "Aurora",   hero: "bg-gradient-to-br from-violet-500 via-fuchsia-500 to-purple-700",  dot: "bg-violet-600",  shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-violet-600 text-white"                             },
  { id: "emerald",  label: "翡翠", enLabel: "Emerald",  hero: "bg-gradient-to-br from-emerald-400 to-teal-700",                   dot: "bg-emerald-600", shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-emerald-600 text-white"                            },
  { id: "solar",    label: "暖阳", enLabel: "Solar",    hero: "bg-gradient-to-br from-amber-400 to-orange-600",                   dot: "bg-orange-500",  shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-orange-500 text-white"                             },
  { id: "dev",      label: "开发", enLabel: "Dev",      hero: "bg-gradient-to-br from-slate-600 to-[#0d1117]",                    dot: "bg-[#238636]",   shimmer: "text-[#58a6ff] font-black font-mono", cardBg: "bg-zinc-950",   cardBorder: "border-zinc-800",  cardText: "text-zinc-200",   btn: "bg-[#238636] text-white"                          },
  { id: "warning",  label: "警示", enLabel: "Warning",  hero: "bg-gradient-to-br from-yellow-400 to-amber-600",                   dot: "bg-amber-500",   shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-amber-500 text-white"                             },
  { id: "premium",  label: "尊享", enLabel: "Premium",  hero: "bg-gradient-to-br from-purple-600 via-fuchsia-500 to-rose-500",    dot: "bg-fuchsia-600", shimmer: "text-foreground font-black", cardBg: "bg-background", cardBorder: "border-border/50", cardText: "text-foreground", btn: "bg-gradient-to-r from-purple-600 to-fuchsia-500 text-white" },
];

const TAG_STYLES: { id: string; label: string; zhName: string; className: string; glow?: string; icon: React.ElementType; theme: string; accent: string }[] = [
  { id: "personal",  label: "Personal",  zhName: "个人",   icon: RiIdCardLine,      className: "bg-zinc-900 text-zinc-100 ring-1 ring-white/[0.07]",                                        glow: "shadow-zinc-800/50",   theme: "app",      accent: "from-zinc-500 via-zinc-700 to-zinc-900"                },
  { id: "official",  label: "Official",  zhName: "官方",   icon: RiBuildingLine,    className: "bg-gradient-to-r from-blue-600 to-blue-800 text-white",                                     glow: "shadow-blue-700/50",   theme: "official", accent: "from-blue-500 via-blue-700 to-indigo-900"              },
  { id: "brand",     label: "Brand",     zhName: "品牌",   icon: RiAwardLine,       className: "bg-gradient-to-r from-violet-600 to-violet-900 text-white",                                 glow: "shadow-violet-600/50", theme: "aurora",   accent: "from-violet-500 via-fuchsia-600 to-pink-600"           },
  { id: "verified",  label: "Verified",  zhName: "认证",   icon: RiShieldCheckLine, className: "bg-gradient-to-r from-emerald-500 to-teal-600 text-white",                                  glow: "shadow-emerald-500/50",theme: "emerald",  accent: "from-emerald-400 via-teal-500 to-teal-700"             },
  { id: "partner",   label: "Partner",   zhName: "合作",   icon: RiShakeHandsLine,  className: "bg-gradient-to-r from-orange-500 to-amber-400 text-white",                                  glow: "shadow-orange-500/50", theme: "solar",    accent: "from-amber-400 via-orange-500 to-orange-600"           },
  { id: "dev",       label: "Dev",       zhName: "开发",   icon: RiCodeSLine,       className: "bg-[#0d1117] text-[#58a6ff] ring-1 ring-[#30363d] font-mono",                               glow: "shadow-slate-900/60",  theme: "dev",      accent: "from-slate-600 via-slate-800 to-black"                 },
  { id: "warning",   label: "Warning",   zhName: "警示",   icon: RiAlertLine,       className: "bg-amber-400 text-amber-950 font-bold ring-1 ring-amber-300/50",                             glow: "shadow-amber-400/50",  theme: "warning",  accent: "from-yellow-300 via-amber-400 to-orange-400"           },
  { id: "premium",   label: "Premium",   zhName: "尊享",   icon: RiVipCrownLine,    className: "bg-gradient-to-r from-purple-600 via-fuchsia-500 to-rose-500 text-white",                   glow: "shadow-fuchsia-500/60",theme: "premium",  accent: "from-purple-500 via-fuchsia-500 to-rose-500"           },
];

function TagBadge({ tagName, tagStyle, live = false }: { tagName: string; tagStyle: string; live?: boolean }) {
  const style = TAG_STYLES.find((s) => s.id === tagStyle) || TAG_STYLES[0];
  const Icon = style.icon;
  return (
    <span className={cn(
      "relative inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold overflow-hidden select-none",
      style.className,
      live && style.glow && `shadow-md ${style.glow}`,
    )}>
      <span className="shrink-0 text-white/90">
        <Icon className="w-3 h-3" />
      </span>
      <span>{tagName || style.label}</span>
      {live && style.glow && (
        <motion.span
          className="absolute inset-0 pointer-events-none"
          style={{ background: "linear-gradient(105deg, transparent 20%, rgba(255,255,255,0.28) 50%, transparent 80%)" }}
          initial={{ x: "-120%" }}
          animate={{ x: "220%" }}
          transition={{ duration: 1.8, repeat: Infinity, ease: "easeInOut", repeatDelay: 2.2 }}
        />
      )}
    </span>
  );
}

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

const HOW_TO_STEPS = [
  { icon: RiPencilLine, color: "text-violet-500", bg: "bg-violet-500/10" },
  { icon: RiServerLine, color: "text-sky-500", bg: "bg-sky-500/10" },
  { icon: RiFlashlightLine, color: "text-emerald-500", bg: "bg-emerald-500/10" },
];

const stepVariants = {
  enter: (dir: number) => ({ opacity: 0, x: dir > 0 ? 32 : -32, filter: "blur(3px)" }),
  center: { opacity: 1, x: 0, filter: "blur(0px)" },
  exit: (dir: number) => ({ opacity: 0, x: dir > 0 ? -32 : 32, filter: "blur(3px)" }),
};

// Progressive backoff schedule (seconds between each auto-check):
// 30s → 1m → 2m → 5m → 10m → 15m → 20m  ≈ 53 min total, 7 auto-checks
const POLL_SCHEDULE = [30, 60, 120, 300, 600, 900, 1200] as const;
const AUTO_POLL_SEC = POLL_SCHEDULE[0];

type StampKey = keyof (typeof en)["stamp"];

const HOW_STEP_TITLE_KEYS: StampKey[] = ["how_step1_title", "how_step2_title", "how_step3_title"];
const HOW_STEP_DESC_KEYS: StampKey[] = ["how_step1_desc", "how_step2_desc", "how_step3_desc"];
// ── No-domain landing page ─────────────────────────────────────────────────────
function StampLandingPage() {
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
    {
      icon: RiSearchLine,
      color: "bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400",
      title: sl("landing_step1_title"),
      desc: sl("landing_step1_desc"),
    },
    {
      icon: RiShieldCheckLine,
      color: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
      title: sl("landing_step2_title"),
      desc: sl("landing_step2_desc"),
    },
    {
      icon: RiWifiLine,
      color: "bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400",
      title: sl("landing_step3_title"),
      desc: sl("landing_step3_desc"),
    },
    {
      icon: RiCheckboxCircleLine,
      color: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
      title: sl("landing_step4_title"),
      desc: sl("landing_step4_desc"),
    },
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
        {/* Back */}
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
              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                {sl("page_desc_main")}
              </p>
            </div>
          </div>
        </div>

        {/* My claims — authenticated users */}
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
                  <div
                    key={stamp.id}
                    className={cn(
                      "glass-panel border rounded-2xl p-4 flex items-center gap-3",
                      stamp.verified ? "border-border" : "border-amber-200/60 dark:border-amber-800/40 bg-amber-50/20 dark:bg-amber-950/10"
                    )}
                  >
                    <div className={cn(
                      "w-8 h-8 rounded-lg flex items-center justify-center shrink-0",
                      stamp.verified ? "bg-emerald-100 dark:bg-emerald-950/40" : "bg-amber-100 dark:bg-amber-950/40"
                    )}>
                      {stamp.verified
                        ? <RiCheckLine className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                        : <RiTimeLine className="w-4 h-4 text-amber-500" />
                      }
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <p className="text-sm font-semibold font-mono truncate">{stamp.domain}</p>
                        <TagBadge tagName={stamp.tag_name} tagStyle={stamp.tag_style} live={stamp.verified} />
                      </div>
                      <p className="text-[11px] mt-0.5 text-muted-foreground">
                        {stamp.verified
                          ? sl("verified_at").replace("{{date}}", stamp.verified_at ? new Date(stamp.verified_at).toLocaleDateString(locale) : "")
                          : sl("pending_status")
                        }
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {stamp.verified ? (
                        <Link
                          href={`/${stamp.domain}`}
                          className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                          title={sl("view_whois")}
                        >
                          <RiExternalLinkLine className="w-3.5 h-3.5" />
                        </Link>
                      ) : (
                        <Link
                          href={`/stamp?domain=${encodeURIComponent(stamp.domain)}`}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/40 transition-colors"
                        >
                          {sl("continue_verify")}
                        </Link>
                      )}
                      <button
                        onClick={() => deleteStamp(stamp.id)}
                        disabled={deletingId === stamp.id}
                        title={sl("delete")}
                        className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors"
                      >
                        {deletingId === stamp.id
                          ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                          : <RiDeleteBinLine className="w-3.5 h-3.5" />
                        }
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Login prompt for unauthenticated */}
        {authStatus === "unauthenticated" && (
          <div className="glass-panel border border-violet-200/40 dark:border-violet-800/30 rounded-2xl p-5 text-center space-y-3">
            <RiShieldCheckLine className="w-7 h-7 text-violet-500/50 mx-auto" />
            <div>
              <p className="text-sm font-semibold">{sl("login_manage_title")}</p>
              <p className="text-xs text-muted-foreground mt-1">{sl("login_manage_desc")}</p>
            </div>
            <div className="flex gap-2 justify-center">
              <Link href="/login?callbackUrl=%2Fstamp">
                <Button size="sm" className="rounded-xl h-9 gap-1.5 text-xs bg-violet-600 hover:bg-violet-700">
                  {sl("login_btn")}
                </Button>
              </Link>
              <Link href="/register?callbackUrl=%2Fstamp">
                <Button size="sm" variant="outline" className="rounded-xl h-9 gap-1.5 text-xs">
                  {sl("register_btn")}
                </Button>
              </Link>
            </div>
          </div>
        )}

        {/* Visual mockup — shows where to click */}
        <div className="space-y-2">
          <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground px-1">{sl("find_entry")}</p>
          <div className="relative rounded-2xl border border-border bg-muted/10 p-4">
            <span className="absolute top-3 right-3 text-[9px] font-bold uppercase tracking-widest text-muted-foreground/50 bg-muted/60 px-2 py-0.5 rounded-full">{sl("preview_label")}</span>
            {/* Mini domain card replica */}
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
                {/* Highlighted claim button */}
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

        {/* Search to enter flow */}
        <div className="border border-border rounded-2xl p-4 space-y-3 bg-muted/10">
          <div className="flex items-center gap-2">
            <RiSearchLine className="w-4 h-4 text-primary" />
            <p className="text-sm font-bold">{sl("search_title")}</p>
          </div>
          <form onSubmit={handleSearch} className="flex gap-2">
            <Input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder={sl("search_placeholder")}
              className="h-10 rounded-xl text-sm font-mono flex-1"
              autoComplete="off"
            />
            <Button type="submit" className="h-10 rounded-xl gap-1.5 px-4 shrink-0">
              {sl("claim_btn")}
              <RiArrowRightLine className="w-3.5 h-3.5" />
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
          <p className="text-[11px] text-muted-foreground">
            {sl("info_note")}
          </p>
        </div>
      </div>
    </>
  );
}

export default function StampPage() {
  const router = useRouter();
  const { data: session, status: authStatus } = useSession();
  const isMember = !!(session?.user as any)?.subscriptionAccess;
  const { t, locale } = useTranslation();
  const isZh = locale.startsWith("zh");
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  const domain = String(router.query.domain || "");

  // Redirect unauthenticated users to login only when a domain is specified.
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
  const [udpBlocked, setUdpBlocked] = React.useState(false);
  const [expectedVal, setExpectedVal] = React.useState<string | null>(null);
  const [httpCheck, setHttpCheck] = React.useState<{ found: boolean; latencyMs: number; error: string | null; url: string; nearMatch?: boolean } | null>(null);
  const [verifyTab, setVerifyTab] = React.useState<"dns" | "http" | "vercel">("dns");
  const [quickTxtLoading, setQuickTxtLoading] = React.useState(false);
  const [quickTxtResult, setQuickTxtResult] = React.useState<{ found: boolean; flat: string[]; records: string[][]; latencyMs: number; tokenFound?: boolean; resolvers: { name: string; proto?: string; records: string[][]; flat?: string[]; latencyMs: number; error?: string | null }[] } | null>(null);
  const [countdown, setCountdown] = React.useState(0);
  const pollRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Vercel verification state ──
  const [vercelTxtValue, setVercelTxtValue] = React.useState<string | null>(null);
  const [vercelTxtFullDomain, setVercelTxtFullDomain] = React.useState<string | null>(null);
  const [vercelApiError, setVercelApiError] = React.useState<string | null>(null);
  const [vercelInitLoading, setVercelInitLoading] = React.useState(false);
  const [vercelCheckLoading, setVercelCheckLoading] = React.useState(false);
  const [vercelCheckAttempt, setVercelCheckAttempt] = React.useState(0);
  const [vercelCountdown, setVercelCountdown] = React.useState(0);
  const vercelPollRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const vercelCountdownRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Style preview state ──
  const [previewStyleId, setPreviewStyleId] = React.useState<string | null>(null);

  // ── Guide tutorial state ──
  const GUIDE_KEY = "stamp_guide_seen";
  const [showGuide, setShowGuide] = React.useState(false);
  React.useEffect(() => {
    if (!hydrated) return;
    // When a domain is pre-filled via URL param the user arrived from a guide modal
    // and has already seen the walkthrough — skip the auto-popup to avoid double-guiding.
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
      // Fallback: fill email/nickname from global prefs if the saved form is missing them
      if (!restoredForm.email && prefs?.email) restoredForm.email = prefs.email;
      if (!restoredForm.nickname && prefs?.nickname) restoredForm.nickname = prefs.nickname;
      setForm(restoredForm);
      setSubmitResult(saved.submitResult || null);
    } else if (prefs) {
      // No domain session but we have saved user prefs — prefill contact info
      setForm(prev => ({
        ...prev,
        nickname: prefs.nickname || prev.nickname,
        email: prefs.email || prev.email,
      }));
    }
    setHydrated(true);
  }, [domain]);

  React.useEffect(() => {
    if (!domain || !hydrated) return;
    if (step === "done") { clearSession(domain); return; }
    saveSession(domain, { step, form, submitResult });
  }, [step, form, submitResult, domain, hydrated]);

  // Prefill email from NextAuth session if not already set
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
          // Sync cardTheme from DB — only if user hasn't manually picked a theme yet
          const first = data.stamps[0];
          if (first?.cardTheme && !cardThemeManual) {
            setForm(prev => ({ ...prev, cardTheme: first.cardTheme }));
          }
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
    if (!form.tagName.trim()) {
      setFormError(s("err_tag_name"));
      return;
    }
    if (!form.nickname.trim()) {
      setFormError(s("err_nickname"));
      return;
    }
    if (!form.email.trim()) {
      setFormError(s("err_email_empty"));
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) {
      setFormError(s("err_email_invalid"));
      return;
    }
    let cleanLink = form.link.trim();
    if (cleanLink && !/^https?:\/\//i.test(cleanLink)) {
      cleanLink = `https://${cleanLink}`;
    }
    if (cleanLink && !/^https?:\/\/[^\s]+\.[^\s]+/i.test(cleanLink)) {
      setFormError(s("err_link_invalid"));
      return;
    }
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
      // Check if our verification token is present in the results
      const expectedValue = submitResult.txtValue;
      const tokenFound = (data.flat as string[] || []).some(
        (r: string) => r === expectedValue || r.includes(expectedValue)
      );
      setQuickTxtResult({ ...data, tokenFound });
      // Auto-trigger full verification if token is detected
      if (tokenFound) {
        setTimeout(() => handleVerify(false), 300);
      }
    } catch {
      setQuickTxtResult({ found: false, flat: [], records: [], latencyMs: 0, resolvers: [] });
    } finally {
      setQuickTxtLoading(false);
    }
  }

  const handleVerify = React.useCallback(async (silent = false) => {
    if (!submitResult) return;
    // Manual trigger resets the backoff counter
    if (!silent) {
      pollAttemptRef.current = 0;
      setPollAttempt(0);
    }
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
        // Send one-time email notification (fire-and-forget, no retry)
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
      if (data.udpBlocked !== undefined) setUdpBlocked(data.udpBlocked);
      if (data.expected) setExpectedVal(data.expected);
      if (data.verified) {
        goToStep("done");
        setVerifyState("idle");
        return;
      } else if (data.anyNearMatch) {
        setVerifyState("nearMatch");
      } else if (data.dnsError) {
        setVerifyState("dnsError");
      } else {
        setVerifyState("fail");
      }
      scheduleNext();
    } catch {
      setVerifyState("fail");
      scheduleNext();
    }
  }, [submitResult, domain]);

  React.useEffect(() => {
    if (step === "verify" && submitResult) {
      // Don't verify immediately — give user time to set up the DNS record first.
      // Start a countdown and only verify after POLL_SCHEDULE[0] seconds.
      pollAttemptRef.current = 0;
      setPollAttempt(0);
      setVerifyState("idle");
      startCountdown(POLL_SCHEDULE[0], () => handleVerify(true));
    }
    return () => stopPolling();
  }, [step, submitResult?.id]);

  function copyText(text: string) {
    navigator.clipboard.writeText(text).then(() => toast.success(s("copied")));
  }

  // ── Vercel verification helpers ──────────────────────────────────────────

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
      // Schedule next auto-check
      const attempt = vercelCheckAttempt;
      if (!silent) { setVercelCheckAttempt(0); }
      const nextAttempt = silent ? attempt + 1 : 1;
      setVercelCheckAttempt(nextAttempt);
      if (nextAttempt < VERCEL_POLL_SCHEDULE.length) {
        startVercelCountdown(VERCEL_POLL_SCHEDULE[nextAttempt - 1 < VERCEL_POLL_SCHEDULE.length ? nextAttempt - 1 : VERCEL_POLL_SCHEDULE.length - 1], () => handleVercelCheck(true));
      }
    } catch {
      // silently fail, let user retry manually
    } finally {
      setVercelCheckLoading(false);
    }
  }, [submitResult, domain, vercelCheckAttempt]);

  // Auto-init when switching to Vercel tab
  React.useEffect(() => {
    if (verifyTab === "vercel" && submitResult && !vercelTxtValue && !vercelInitLoading && !vercelApiError) {
      initVercelVerify();
    }
    if (verifyTab !== "vercel") {
      stopVercelPolling();
    }
  }, [verifyTab, submitResult?.id]);

  // No domain specified — show a rich landing/guide page (handles own auth state)
  if (!domain) {
    return <StampLandingPage />;
  }

  // Show a skeleton while session is loading; unauthenticated users will be redirected by useEffect.
  if (authStatus === "loading" || authStatus === "unauthenticated") {
    return (
      <div className="min-h-[calc(100vh-64px)] bg-background">
        <div className="max-w-lg mx-auto px-4 py-5 pb-10 space-y-4 animate-pulse">
          <div className="h-5 w-32 rounded-lg bg-muted/50" />
          <div className="h-28 rounded-2xl bg-muted/40" />
          <div className="h-8 w-2/3 mx-auto rounded-lg bg-muted/30" />
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
            <button
              onClick={goBack}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors group"
            >
              <RiArrowLeftLine className="w-4 h-4 transition-transform group-hover:-translate-x-0.5" />
              {s("back")}
            </button>
            <span className="text-muted-foreground/30">·</span>
            <span className="text-sm font-mono text-muted-foreground/80">{domain}</span>
          </div>

          {/* Skeleton while restoring session */}
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
              {/* Compact header */}
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
                  <button
                    type="button"
                    onClick={() => setShowGuide(true)}
                    className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded-lg hover:bg-muted/60"
                  >
                    <RiInformationLine className="w-3.5 h-3.5" />
                    {s("how_it_works_section")}
                  </button>
                )}
              </div>

              {/* Step indicator */}
              {step !== "done" && (
                <div className="flex items-center mb-5 px-1">
                  {STEP_LABELS.filter(s => s.key !== "done").map((s, i) => {
                    const cur = stepIndex(step);
                    const isActive = s.key === step;
                    const isDone = i < cur;
                    return (
                      <React.Fragment key={s.key}>
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
                            {t(`stamp.step_${s.key}`)}
                          </span>
                        </div>
                        {i < STEP_LABELS.filter(s => s.key !== "done").length - 1 && (
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
                          <button
                            type="button"
                            onClick={() => setExistingExpanded(!existingExpanded)}
                            className="flex items-center justify-between w-full"
                          >
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

                      {/* Member vs Free benefits banner */}
                      <div className={cn(
                        "rounded-2xl border overflow-hidden text-[10px]",
                        isMember
                          ? "border-violet-200/60 dark:border-violet-800/40 bg-violet-50/60 dark:bg-violet-950/20"
                          : "border-amber-200/60 dark:border-amber-800/40 bg-amber-50/40 dark:bg-amber-950/10"
                      )}>
                        {/* header */}
                        <div className={cn(
                          "flex items-center justify-between px-4 py-2.5 border-b",
                          isMember
                            ? "border-violet-200/40 dark:border-violet-800/30 bg-violet-100/50 dark:bg-violet-900/20"
                            : "border-amber-200/40 dark:border-amber-800/30 bg-amber-100/30 dark:bg-amber-900/10"
                        )}>
                          <div className="flex items-center gap-1.5">
                            <RiVipCrownLine className={cn("w-3.5 h-3.5", isMember ? "text-violet-500" : "text-amber-500")} />
                            <span className={cn("font-bold tracking-wide text-[10.5px]", isMember ? "text-violet-700 dark:text-violet-300" : "text-amber-700 dark:text-amber-400")}>
                              {isMember ? (isZh ? "会员已激活" : "Member Active") : (isZh ? "普通用户 · 部分功能受限" : "Free User · Limited Features")}
                            </span>
                          </div>
                          {!isMember && (
                            <Link href="/payment/checkout"
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full font-semibold text-white bg-gradient-to-r from-violet-600 to-fuchsia-500 hover:opacity-90 transition-opacity text-[9.5px]">
                              <RiVipCrownLine className="w-2.5 h-2.5" />{isZh ? "立即升级" : "Upgrade"}
                            </Link>
                          )}
                        </div>
                        {/* comparison grid */}
                        <div className="grid grid-cols-2 divide-x divide-border/40 dark:divide-border/20">
                          {/* free */}
                          <div className="px-3.5 py-2.5 space-y-1.5">
                            <p className="font-bold text-muted-foreground/60 uppercase tracking-widest text-[8.5px] mb-1.5">{isZh ? "普通用户" : "Free"}</p>
                            {[
                              isZh ? "标签名最多 5 字" : "Tag name: max 5 chars",
                              isZh ? "仅「个人」标签样式" : "Only 'Personal' style",
                              isZh ? "8 种标准卡片配色" : "8 standard card themes",
                              isZh ? "无链接与介绍" : "No link or description",
                            ].map((item, i) => (
                              <div key={i} className="flex items-center gap-1.5 text-muted-foreground/60">
                                <span className="w-3 h-3 rounded-full bg-muted/60 flex items-center justify-center shrink-0 text-[7px]">✕</span>
                                {item}
                              </div>
                            ))}
                          </div>
                          {/* member */}
                          <div className="px-3.5 py-2.5 space-y-1.5">
                            <p className={cn("font-bold uppercase tracking-widest text-[8.5px] mb-1.5", isMember ? "text-violet-500" : "text-amber-500/70")}>{isZh ? "会员专属" : "Members"}</p>
                            {[
                              isZh ? "标签名最多 20 字" : "Tag name: up to 20 chars",
                              isZh ? "全部 8 种标签样式" : "All 8 badge styles",
                              isZh ? "5 种动态特殊排版" : "5 animated special layouts",
                              isZh ? "自定义链接与介绍" : "Custom link & description",
                            ].map((item, i) => (
                              <div key={i} className={cn("flex items-center gap-1.5", isMember ? "text-violet-700 dark:text-violet-300" : "text-muted-foreground/50")}>
                                <RiCheckLine className={cn("w-3 h-3 shrink-0", isMember ? "text-violet-500" : "text-amber-400/60")} />
                                {item}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Form card */}
                      <div className="space-y-4">
                        <div className="glass-panel border border-border rounded-2xl p-5 space-y-5">

                          {/* Domain field */}
                          <div>
                            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-2 block">{s("domain_label")}</Label>
                            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-muted/30 border border-border/60">
                              <RiGlobalLine className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                              <span className="text-sm font-mono text-foreground">{domain}</span>
                            </div>
                            <p className="text-[11px] text-muted-foreground mt-1.5">{s("domain_hint")}</p>
                          </div>

                          <div className="h-px bg-border/50" />

                          {/* Tag name */}
                          <div>
                            <div className="flex items-baseline justify-between mb-2">
                              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                                {s("tag_name_label")} <span className="text-red-500 normal-case tracking-normal font-normal">*</span>
                              </Label>
                              {!isMember && (
                                <span className="text-[10px] text-amber-600 dark:text-amber-400">
                                  {s("char_limit_hint")} · <Link href="/payment/checkout" className="underline underline-offset-2">{s("upgrade_now")}</Link>
                                </span>
                              )}
                            </div>
                            <Input
                              value={form.tagName}
                              onChange={(e) => update("tagName", e.target.value)}
                              placeholder={s("tag_name_placeholder")}
                              maxLength={isMember ? 20 : 5}
                            />
                            {!isMember && form.tagName.length >= 5 && (
                              <p className="text-[10px] text-amber-500 mt-1 flex items-center gap-1">
                                <RiVipCrownLine className="w-3 h-3" /> {s("member_title_hint")}
                              </p>
                            )}
                          </div>

                          {/* Unified style picker */}
                          <div>
                            <div className="flex items-center justify-between mb-2.5">
                              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">{s("tag_style_label")}</Label>
                              {!isMember
                                ? <span className="text-[10px] text-violet-600 dark:text-violet-400 flex items-center gap-1"><RiVipCrownLine className="w-3 h-3" />{s("member_only")}</span>
                                : <span className="text-[10px] text-muted-foreground/50">{s("click_preview")}</span>
                              }
                            </div>
                            <div className="grid grid-cols-4 gap-2">
                              {TAG_STYLES.map((ts) => {
                                const isSelected = form.tagStyle === ts.id;
                                const Icon = ts.icon;
                                const isFree = ts.id === "personal";
                                const locked = !isMember && !isFree;
                                return (
                                  <button
                                    key={ts.id}
                                    type="button"
                                    onClick={() => {
                                      if (locked) { toast.info(s("upgrade_to_unlock")); return; }
                                      update("tagStyle", ts.id);
                                      setPreviewStyleId(ts.id);
                                    }}
                                    className={cn(
                                      "relative flex flex-col overflow-hidden rounded-2xl border-2 transition-all duration-150 text-left",
                                      locked ? "opacity-45 cursor-not-allowed border-border/20"
                                        : isSelected ? "border-violet-400 dark:border-violet-500 shadow-md shadow-violet-500/10"
                                        : "border-border/40 hover:border-border/70 hover:shadow-sm"
                                    )}
                                  >
                                    {/* Gradient accent swatch */}
                                    <div className={cn("relative h-[68px] w-full flex flex-col items-center justify-center gap-1.5 overflow-hidden bg-gradient-to-br", ts.accent)}>
                                      <div className="absolute inset-0 opacity-[0.06]"
                                        style={{ backgroundImage: "radial-gradient(circle, white 1px, transparent 1px)", backgroundSize: "9px 9px" }} />
                                      <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/20" />
                                      {/* Icon */}
                                      <div className="relative w-7 h-7 rounded-xl bg-white/20 border border-white/25 flex items-center justify-center shadow-sm">
                                        {locked
                                          ? <RiVipCrownLine className="w-3.5 h-3.5 text-white/75 drop-shadow" />
                                          : <Icon className="w-3.5 h-3.5 text-white drop-shadow" />}
                                      </div>
                                      {/* Mini tag pill */}
                                      {!locked && (
                                        <span className={cn(
                                          "relative inline-flex items-center gap-0.5 px-1.5 py-[2px] rounded text-[6.5px] font-bold overflow-hidden max-w-[calc(100%-8px)] truncate",
                                          ts.className
                                        )}>
                                          <Icon className="w-1.5 h-1.5 shrink-0" />
                                          <span className="truncate">{isZh ? ts.zhName : ts.label}</span>
                                        </span>
                                      )}
                                      {/* Selected check */}
                                      {isSelected && !locked && (
                                        <div className="absolute top-1.5 right-1.5 w-3.5 h-3.5 rounded-full bg-white/95 flex items-center justify-center shadow-sm">
                                          <RiCheckLine className="w-2 h-2 text-violet-600" />
                                        </div>
                                      )}
                                      {/* Free chip */}
                                      {isFree && !isMember && (
                                        <div className="absolute top-1.5 left-1.5 text-[5.5px] font-bold px-1 py-[2px] rounded-full bg-emerald-500 text-white leading-tight shadow-sm whitespace-nowrap">
                                          FREE
                                        </div>
                                      )}
                                    </div>
                                    {/* Label */}
                                    <div className={cn("px-1.5 py-1.5 text-center",
                                      isSelected && !locked ? "bg-violet-50 dark:bg-violet-950/40" : "bg-background")}>
                                      <p className={cn("text-[10px] font-semibold leading-none tracking-tight",
                                        isSelected && !locked ? "text-violet-600 dark:text-violet-400" : "text-foreground/70")}>
                                        {isZh ? ts.zhName : ts.label}
                                      </p>
                                    </div>
                                  </button>
                                );
                              })}
                            </div>
                          </div>

                          {/* Card Layout — special themes (member-only) */}
                          <div>
                            <div className="flex items-center justify-between mb-2.5">
                              <div className="flex items-center gap-1.5">
                                <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">{isZh ? "卡片排版" : "Card Layout"}</Label>
                                {!isMember && (
                                  <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold text-violet-600 dark:text-violet-400">
                                    <RiVipCrownLine className="w-2.5 h-2.5" />{isZh ? "会员专属" : "Members Only"}
                                  </span>
                                )}
                              </div>
                              {/* current standard theme chip */}
                              {!(SPECIAL_THEME_IDS as readonly string[]).includes(form.cardTheme) && (
                                <span className="text-[9px] text-muted-foreground/60 font-mono">
                                  {isZh ? STAMP_CARD_THEMES[form.cardTheme]?.label : form.cardTheme}
                                </span>
                              )}
                            </div>
                            {/* 5 special theme swatches */}
                            <div className="grid grid-cols-5 gap-1.5">
                              {(SPECIAL_THEME_IDS as readonly string[]).map((themeId) => {
                                const th = STAMP_CARD_THEMES[themeId];
                                if (!th) return null;
                                const isSpecialSelected = form.cardTheme === themeId;
                                const locked = !isMember;
                                return (
                                  <button
                                    key={themeId}
                                    type="button"
                                    onClick={() => {
                                      if (locked) { toast.info(isZh ? "升级会员解锁特殊排版" : "Upgrade to unlock special layouts"); return; }
                                      if (isSpecialSelected) {
                                        // deselect → restore tagStyle default
                                        const ts = TAG_STYLES.find(s => s.id === form.tagStyle);
                                        setCardThemeManual(false);
                                        setForm(prev => ({ ...prev, cardTheme: ts?.theme || "app" }));
                                      } else {
                                        update("cardTheme", themeId);
                                        setPreviewThemeKey(themeId);
                                      }
                                    }}
                                    className={cn(
                                      "relative flex flex-col overflow-hidden rounded-xl border-2 transition-all duration-150",
                                      locked ? "opacity-50 cursor-not-allowed border-border/20"
                                        : isSpecialSelected ? "border-violet-400 dark:border-violet-500 shadow-md shadow-violet-500/15"
                                        : "border-border/40 hover:border-border/70"
                                    )}
                                  >
                                    {/* swatch */}
                                    <div className={cn("h-10 w-full flex items-center justify-center", th.hero)}>
                                      {locked
                                        ? <RiVipCrownLine className="w-3.5 h-3.5 text-white/70 drop-shadow" />
                                        : isSpecialSelected
                                          ? <RiCheckLine className="w-3.5 h-3.5 text-white drop-shadow" />
                                          : <span className="text-[11px]">{th.special || "✨"}</span>
                                      }
                                    </div>
                                    <div className={cn("px-0.5 py-1 text-center", isSpecialSelected ? "bg-violet-50 dark:bg-violet-950/40" : "bg-background")}>
                                      <p className={cn("text-[8.5px] font-semibold leading-none tracking-tight",
                                        isSpecialSelected ? "text-violet-600 dark:text-violet-400" : "text-foreground/70")}>
                                        {th.label}
                                      </p>
                                    </div>
                                  </button>
                                );
                              })}
                            </div>
                            {/* Current theme label when special is selected */}
                            {(SPECIAL_THEME_IDS as readonly string[]).includes(form.cardTheme) && (
                              <p className="text-[9.5px] text-muted-foreground/60 mt-1.5 flex items-center gap-1">
                                <RiCheckboxCircleLine className="w-3 h-3 text-violet-400" />
                                {isZh ? `已选特殊排版：${STAMP_CARD_THEMES[form.cardTheme]?.label}` : `Special layout selected: ${form.cardTheme}`}
                                <button type="button" className="text-muted-foreground/40 hover:text-muted-foreground underline ml-1"
                                  onClick={() => {
                                    const ts = TAG_STYLES.find(s => s.id === form.tagStyle);
                                    setCardThemeManual(false);
                                    setForm(prev => ({ ...prev, cardTheme: ts?.theme || "app" }));
                                  }}>
                                  {isZh ? "重置" : "Reset"}
                                </button>
                              </p>
                            )}
                          </div>

                          {/* Link (optional) — members only */}
                          {isMember ? (
                            <div>
                              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-2 block">
                                {s("link_label")} <span className="normal-case tracking-normal font-normal text-muted-foreground/60">{s("optional")}</span>
                              </Label>
                              <Input
                                value={form.link}
                                onChange={(e) => update("link", e.target.value)}
                                placeholder="https://x.rw"
                                type="text"
                                inputMode="url"
                              />
                            </div>
                          ) : (
                            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-muted/50 border border-dashed border-border">
                              <RiVipCrownLine className="w-4 h-4 text-violet-400 shrink-0" />
                              <div className="flex-1 min-w-0">
                                <p className="text-[11px] font-semibold text-muted-foreground">{s("link_member_only")}</p>
                                <p className="text-[10px] text-muted-foreground/60">{s("link_upgrade_hint")}</p>
                              </div>
                              <Link href="/payment/checkout" className="text-[10px] font-semibold text-violet-600 dark:text-violet-400 shrink-0 hover:underline">{s("upgrade_now")}</Link>
                            </div>
                          )}

                          {/* Description — members only */}
                          {isMember ? (
                            <div>
                              <div className="flex items-baseline justify-between mb-2">
                                <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
                                  {s("desc_label")} <span className="normal-case tracking-normal font-normal text-muted-foreground/60">{s("optional")}</span>
                                </Label>
                                <span className={cn("text-[10px] tabular-nums", form.description.length >= 270 ? "text-red-500 font-semibold" : "text-muted-foreground/50")}>{form.description.length}/300</span>
                              </div>
                              <textarea
                                value={form.description}
                                onChange={(e) => update("description", e.target.value)}
                                placeholder={s("desc_placeholder")}
                                maxLength={300}
                                rows={2}
                                className="w-full text-base sm:text-sm rounded-lg border border-border bg-background px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-violet-400/40 transition-shadow placeholder:text-muted-foreground/50"
                              />
                            </div>
                          ) : (
                            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-muted/50 border border-dashed border-border">
                              <RiVipCrownLine className="w-4 h-4 text-violet-400 shrink-0" />
                              <div className="flex-1 min-w-0">
                                <p className="text-[11px] font-semibold text-muted-foreground">{s("desc_member_only")}</p>
                                <p className="text-[10px] text-muted-foreground/60">{s("desc_upgrade_hint")}</p>
                              </div>
                              <Link href="/payment/checkout" className="text-[10px] font-semibold text-violet-600 dark:text-violet-400 shrink-0 hover:underline">{s("upgrade_now")}</Link>
                            </div>
                          )}

                          {/* Live real popup preview */}
                          {form.tagName && (() => {
                            const styleObj = TAG_STYLES.find(ts => ts.id === form.tagStyle) || TAG_STYLES[0];
                            const badgeLabel = s((`badge_${form.tagStyle}`) as StampKey) || s("badge_default");
                            return (
                              <div>
                                <div className="flex items-center gap-2 mb-2">
                                  <span className="text-[10px] font-bold uppercase tracking-widest text-violet-400/70">{s("live_preview")}</span>
                                  <div className="flex-1 h-px bg-violet-200/40 dark:bg-violet-800/30" />
                                </div>
                                <div className="rounded-[18px] overflow-hidden shadow-md">
                                  <StampPreviewCard
                                    themeKey={form.cardTheme || "app"}
                                    data={{
                                      tagName: form.tagName,
                                      domain: domain || undefined,
                                      description: form.description || undefined,
                                      link: form.link || undefined,
                                      tagLabel: badgeLabel,
                                      icon: styleObj.icon,
                                    }}
                                  />
                                </div>
                              </div>
                            );
                          })()}

                          <div className="h-px bg-border/50" />

                          {/* Contact */}
                          <div className="space-y-3">
                            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-widest block">{s("contact_label")}</Label>
                            <div>
                              <Label className="text-xs font-medium mb-1.5 block">
                                {s("name_label")} <span className="text-red-500">*</span>
                              </Label>
                              <Input
                                value={form.nickname}
                                onChange={(e) => update("nickname", e.target.value)}
                                placeholder={s("name_placeholder")}
                                maxLength={30}
                              />
                            </div>
                            <div>
                              <Label className="text-xs font-medium mb-1.5 block">
                                {s("email_label")} <span className="text-red-500">*</span>
                              </Label>
                              <Input
                                value={form.email}
                                onChange={(e) => update("email", e.target.value)}
                                placeholder="your@email.com"
                                type="text"
                              />
                              <p className="text-[11px] text-muted-foreground mt-1">{s("email_hint")}</p>
                            </div>
                          </div>
                        </div>

                        <AnimatePresence>
                          {formError && (
                            <motion.div
                              key="form-error"
                              initial={{ opacity: 0, y: -6, height: 0 }}
                              animate={{ opacity: 1, y: 0, height: "auto" }}
                              exit={{ opacity: 0, y: -4, height: 0 }}
                              transition={{ duration: 0.18 }}
                              className="overflow-hidden"
                            >
                              <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl bg-red-50/80 dark:bg-red-950/30 border border-red-200/60 dark:border-red-800/40 text-red-600 dark:text-red-400">
                                <RiAlertLine className="w-4 h-4 shrink-0" />
                                <span className="text-sm">{formError}</span>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                        <Button
                          type="button"
                          onClick={handleSubmit}
                          disabled={loading}
                          className="w-full gap-2 h-12 bg-violet-500 hover:bg-violet-600 active:bg-violet-700 text-white border-0 rounded-xl text-sm font-semibold shadow-md shadow-violet-500/25 transition-all hover:shadow-lg hover:shadow-violet-500/30 hover:-translate-y-px"
                        >
                          {loading
                            ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{s("btn_submitting")}</>
                            : <><RiFlashlightLine className="w-4 h-4" />{s("btn_submit")}</>
                          }
                        </Button>
                      </div>
                    </div>
                  )}

                  {/* ── STEP 2: VERIFY ── */}
                  {step === "verify" && submitResult && (
                    <div className="space-y-4">
                      <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">

                        {/* Method tab switcher */}
                        <div className="flex rounded-xl bg-muted/40 border border-border/50 p-1 gap-1">
                          <button
                            type="button"
                            onClick={() => setVerifyTab("dns")}
                            className={cn(
                              "flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-semibold transition-all",
                              verifyTab === "dns"
                                ? "bg-background shadow-sm text-foreground border border-border/60"
                                : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <RiServerLine className="w-3.5 h-3.5 shrink-0" />
                            <span className="hidden sm:inline">DNS TXT</span>
                            <span className="sm:hidden">DNS</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => setVerifyTab("http")}
                            className={cn(
                              "flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-semibold transition-all",
                              verifyTab === "http"
                                ? "bg-background shadow-sm text-foreground border border-border/60"
                                : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <RiFlashlightLine className="w-3.5 h-3.5 text-sky-500 shrink-0" />
                            <span className="hidden sm:inline">{s("file_verify")}</span>
                            <span className="sm:hidden">{s("file_verify_short")}</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => setVerifyTab("vercel")}
                            className={cn(
                              "flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-semibold transition-all",
                              verifyTab === "vercel"
                                ? "bg-background shadow-sm text-foreground border border-border/60"
                                : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <span className={cn(
                              "shrink-0 text-[11px] font-black leading-none",
                              verifyTab === "vercel" ? "text-foreground" : "text-muted-foreground"
                            )}>▲</span>
                            Vercel
                          </button>
                        </div>

                        {/* ── DNS tab ── */}
                        {verifyTab === "dns" && (
                          <>
                            <div>
                              <h2 className="text-sm font-bold flex items-center gap-2 mb-1">
                                <RiServerLine className="w-4 h-4 text-sky-500" />
                                {s("verify_dns_title")}
                              </h2>
                              <p className="text-xs text-muted-foreground">
                                {s("verify_dns_desc", { sec: AUTO_POLL_SEC })}
                              </p>
                            </div>

                            {/* DNS record table */}
                            {(() => {
                              // The host record shown to users = subdomain prefix only (without the domain).
                              // DNS panels (Cloudflare, DNSPod, etc.) auto-append the zone/domain.
                              const hostPrefix = submitResult.txtRecord.replace(new RegExp(`\\.${domain.replace(/\./g, "\\.")}$`), "");
                              return (
                            <div className="rounded-xl border border-border/60 overflow-hidden divide-y divide-border/60">
                              <div className="px-3 py-2 bg-amber-50/60 dark:bg-amber-950/20 border-b border-amber-200/40">
                                <p className="text-[10px] text-amber-700 dark:text-amber-400 leading-relaxed">
                                  {s("host_prefix_note")}
                                </p>
                              </div>
                              {[
                                { label: s("dns_field_type"), value: "TXT", mono: false, copyable: false, note: null },
                                { label: s("dns_field_host"), value: hostPrefix, mono: true, color: "text-violet-600 dark:text-violet-400", copyable: true, note: `${s("full_label")}: ${submitResult.txtRecord}` },
                                { label: s("dns_field_value"), value: submitResult.txtValue, mono: true, color: "text-emerald-600 dark:text-emerald-400", copyable: true, note: null },
                                { label: "TTL", value: s("dns_field_ttl_val"), mono: false, copyable: false, note: null },
                              ].map((row) => (
                                <div key={row.label} className="flex items-center justify-between gap-3 px-3 py-2.5 bg-muted/20">
                                  <div className="shrink-0 w-20">
                                    <p className="text-[10px] font-bold text-muted-foreground/70 uppercase tracking-wider">{row.label}</p>
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <p className={cn("text-xs break-all leading-relaxed", row.mono ? "font-mono" : "", row.color || "text-foreground")}>
                                      {row.value}
                                    </p>
                                    {row.note && (
                                      <p className="text-[10px] text-muted-foreground/50 mt-0.5 font-mono">{row.note}</p>
                                    )}
                                  </div>
                                  {row.copyable && (
                                    <button
                                      onClick={() => copyText(row.value)}
                                      className="shrink-0 p-1.5 rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                    >
                                      <RiFileCopyLine className="w-3.5 h-3.5" />
                                    </button>
                                  )}
                                </div>
                              ))}
                            </div>
                              ); })()}

                            {/* Quick TXT check */}
                            <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                              <div className="px-3 py-2 border-b border-border/40 flex items-center justify-between gap-2">
                                <div className="flex items-center gap-2">
                                  <RiFlashlightLine className="w-3.5 h-3.5 text-sky-500 shrink-0" />
                                  <p className="text-[11px] font-semibold text-foreground">
                                    {s("quick_txt_lookup")}
                                  </p>
                                </div>
                                <button
                                  type="button"
                                  onClick={handleQuickTxt}
                                  disabled={quickTxtLoading}
                                  className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-sky-500 hover:bg-sky-600 text-white text-[11px] font-semibold transition-colors disabled:opacity-60"
                                >
                                  {quickTxtLoading
                                    ? <><RiLoader4Line className="w-3 h-3 animate-spin" />{s("querying")}…</>
                                    : <><RiRefreshLine className="w-3 h-3" />{s("check_now")}</>
                                  }
                                </button>
                              </div>
                              <div className="px-3 py-2.5">
                                {!quickTxtResult && !quickTxtLoading && (
                                  <p className="text-[11px] text-muted-foreground/60 text-center py-1">
                                    {isZh
                                      ? "直接用 Google/Cloudflare DNS 查询 TXT 记录，无需等待页面轮询"
                                      : "Query TXT records directly via Google/Cloudflare DNS — instant result"}
                                  </p>
                                )}
                                {quickTxtLoading && (
                                  <div className="flex items-center gap-2 py-1">
                                    <RiLoader4Line className="w-3.5 h-3.5 animate-spin text-muted-foreground/60" />
                                    <p className="text-[11px] text-muted-foreground">{s("querying")}…</p>
                                  </div>
                                )}
                                {quickTxtResult && !quickTxtLoading && (
                                  <div className="space-y-2">
                                    {/* Token found — auto-verifying banner */}
                                    {quickTxtResult.tokenFound && (
                                      <div className="flex items-center gap-2 rounded-lg border border-emerald-400/60 bg-emerald-50/60 dark:bg-emerald-950/30 px-3 py-2">
                                        <RiCheckboxCircleLine className="w-4 h-4 text-emerald-500 shrink-0" />
                                        <p className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                                          {s("token_detected")}
                                        </p>
                                        <RiLoader4Line className="w-3.5 h-3.5 animate-spin text-emerald-500 shrink-0 ml-auto" />
                                      </div>
                                    )}
                                    {/* Per-resolver results */}
                                    <div className="grid grid-cols-2 gap-1.5">
                                      {quickTxtResult.resolvers.map((r) => {
                                        const recCount = (r.flat || r.records || []).length;
                                        const hasRecords = recCount > 0;
                                        return (
                                          <div key={r.name} className={cn(
                                            "rounded-lg border px-2.5 py-2 flex items-center gap-2",
                                            hasRecords ? "border-emerald-300/60 bg-emerald-50/50 dark:bg-emerald-950/25"
                                              : r.error === "timeout" ? "border-amber-200/50 bg-amber-50/30 dark:bg-amber-950/15"
                                              : "border-border/50 bg-muted/10"
                                          )}>
                                            <div className={cn("shrink-0 w-5 h-5 rounded-md flex items-center justify-center",
                                              hasRecords ? "bg-emerald-500/10" : r.error === "timeout" ? "bg-amber-500/10" : "bg-muted/30"
                                            )}>
                                              {hasRecords ? <RiCheckLine className="w-3 h-3 text-emerald-500" />
                                                : r.error === "timeout" ? <RiTimeLine className="w-3 h-3 text-amber-500" />
                                                : <RiCloudLine className="w-3 h-3 text-muted-foreground/30" />}
                                            </div>
                                            <div className="min-w-0 flex-1">
                                              <p className={cn("text-[10px] font-semibold truncate",
                                                hasRecords ? "text-emerald-700 dark:text-emerald-300"
                                                  : r.error === "timeout" ? "text-amber-600 dark:text-amber-400"
                                                  : "text-muted-foreground"
                                              )}>{r.name}</p>
                                              <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                                                {hasRecords ? `${r.latencyMs}ms · ${s("records_count", { count: recCount })}`
                                                  : r.error === "timeout" ? s("timeout_label")
                                                  : r.error === "no_record" ? s("no_record_label")
                                                  : r.error ? r.error
                                                  : s("not_found_label")}
                                              </p>
                                            </div>
                                          </div>
                                        );
                                      })}
                                    </div>
                                    {/* Found records (raw content display) */}
                                    {(quickTxtResult.flat || []).length > 0 && (
                                      <div className={cn(
                                        "rounded-lg border px-2.5 py-2 space-y-1",
                                        quickTxtResult.tokenFound
                                          ? "border-emerald-400/60 bg-emerald-50/40 dark:bg-emerald-950/25"
                                          : "border-emerald-300/50 bg-emerald-50/30 dark:bg-emerald-950/20"
                                      )}>
                                        <p className="text-[10px] font-bold text-emerald-700 dark:text-emerald-400 flex items-center gap-1">
                                          <RiCheckLine className="w-3 h-3" />
                                          {s("txt_records_found", { n: quickTxtResult.flat.length })}
                                        </p>
                                        {quickTxtResult.flat.slice(0, 5).map((record, i) => {
                                          const isToken = record === submitResult?.txtValue || record.includes(submitResult?.txtValue || "");
                                          return (
                                            <div key={i} className="flex items-start gap-1.5">
                                              <code className={cn(
                                                "text-[10px] font-mono break-all leading-relaxed flex-1 rounded px-1.5 py-0.5",
                                                isToken
                                                  ? "text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 ring-1 ring-emerald-400/40"
                                                  : "text-emerald-600 dark:text-emerald-400 bg-emerald-500/5"
                                              )}>
                                                {isToken && <RiCheckLine className="w-2.5 h-2.5 inline mr-1 mb-0.5" />}
                                                {record}
                                              </code>
                                              <button onClick={() => navigator.clipboard.writeText(record).then(() => toast.success(s("copied")))}
                                                className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground/50 hover:text-foreground mt-0.5">
                                                <RiFileCopyLine className="w-2.5 h-2.5" />
                                              </button>
                                            </div>
                                          );
                                        })}
                                      </div>
                                    )}
                                    {(quickTxtResult.flat || []).length === 0 && (
                                      <p className="text-[11px] text-muted-foreground/70 text-center py-0.5">
                                        {s("add_txt_first")}
                                      </p>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* DNS status grid — DoH only */}
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                                  <RiCloudLine className="w-3 h-3" />
                                  {s("parallel_check")}
                                </p>
                                <span className="flex items-center gap-0.5 text-[10px] text-muted-foreground/50">
                                  <RiCloudLine className="w-2.5 h-2.5" />DoH
                                </span>
                              </div>
                              {(() => {
                                const PLACEHOLDER_RESOLVERS = [
                                  { name: "Google DoH",     proto: "doh" },
                                  { name: "Cloudflare DoH", proto: "doh" },
                                  { name: "Quad9 DoH",      proto: "doh" },
                                  { name: "AdGuard DoH",    proto: "doh" },
                                ];
                                const isLoading = verifyState === "loading";
                                const displayList = isLoading && resolvers.length === 0
                                  ? PLACEHOLDER_RESOLVERS
                                  : resolvers;
                                return (
                                  <div className="grid grid-cols-2 gap-1.5">
                                    {displayList.map((item, i) => {
                                      const r = resolvers[i];
                                      return (
                                        <div
                                          key={item.name}
                                          className={cn(
                                            "rounded-lg border px-2.5 py-2 flex items-center gap-2 transition-all",
                                            r?.found
                                              ? "border-emerald-300/60 bg-emerald-50/50 dark:bg-emerald-950/25"
                                              : r?.nearMatch
                                              ? "border-orange-300/60 bg-orange-50/40 dark:bg-orange-950/20"
                                              : r?.error === "timeout"
                                              ? "border-amber-200/50 bg-amber-50/30 dark:bg-amber-950/15"
                                              : "border-border/50 bg-muted/15"
                                          )}
                                        >
                                          <div className={cn(
                                            "shrink-0 w-6 h-6 rounded-md flex items-center justify-center",
                                            r?.found ? "bg-emerald-500/10"
                                              : r?.nearMatch ? "bg-orange-500/10"
                                              : r?.error === "timeout" ? "bg-amber-500/10"
                                              : "bg-muted/40"
                                          )}>
                                            {isLoading
                                              ? <RiLoader4Line className="w-3 h-3 animate-spin text-muted-foreground/60" />
                                              : r?.found
                                              ? <RiCheckLine className="w-3 h-3 text-emerald-500" />
                                              : r?.nearMatch
                                              ? <RiAlertLine className="w-3 h-3 text-orange-500" />
                                              : r?.error === "timeout"
                                              ? <RiTimeLine className="w-3 h-3 text-amber-500" />
                                              : <RiCloudLine className="w-3 h-3 text-muted-foreground/30" />
                                            }
                                          </div>
                                          <div className="min-w-0 flex-1">
                                            <p className={cn(
                                              "text-[11px] font-semibold leading-none truncate",
                                              r?.found ? "text-emerald-700 dark:text-emerald-300"
                                                : r?.nearMatch ? "text-orange-600 dark:text-orange-400"
                                                : r?.error === "timeout" ? "text-amber-600 dark:text-amber-400"
                                                : "text-muted-foreground"
                                            )}>{item.name}</p>
                                            <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                                              {isLoading ? s("checking")
                                                : r?.found ? `${r.latencyMs}ms ✓`
                                                : r?.nearMatch ? s("token_mismatch")
                                                : r?.error === "timeout" ? s("timeout")
                                                : r?.error === "servfail" ? "SERVFAIL"
                                                : r?.error ? s("not_found_dns")
                                                : s("waiting")}
                                            </p>
                                          </div>
                                        </div>
                                      );
                                    })}
                                  </div>
                                );
                              })()}
                            </div>
                          </>
                        )}

                        {/* ── HTTP File tab ── */}
                        {verifyTab === "http" && (
                          <>
                            <div>
                              <h2 className="text-sm font-bold flex items-center gap-2 mb-1">
                                <RiFileTextLine className="w-4 h-4 text-sky-500" />
                                {s("file_verify")}
                              </h2>
                              <p className="text-xs text-muted-foreground leading-relaxed">
                                {s("file_verify_desc")}
                              </p>
                            </div>

                            {/* Step-by-step instructions */}
                            <div className="space-y-2.5">
                              {/* Step 1: Create file */}
                              <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                                <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                                  <span className="w-4 h-4 rounded-full bg-sky-500 text-white text-[9px] font-bold flex items-center justify-center shrink-0">1</span>
                                  <p className="text-[11px] font-semibold text-foreground">
                                    {s("file_verify_step1")}
                                  </p>
                                </div>
                                <div className="px-3 py-2.5 space-y-2">
                                  <div>
                                    <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                                      <RiLinksLine className="w-2.5 h-2.5" />
                                      {s("file_path_label")}
                                    </p>
                                    <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                                      <code className="text-[11px] font-mono text-violet-600 dark:text-violet-400 flex-1 break-all">
                                        {`/.well-known/next-whois-verify.txt`}
                                      </code>
                                      <button
                                        onClick={() => copyText(`/.well-known/next-whois-verify.txt`)}
                                        className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                      >
                                        <RiFileCopyLine className="w-3 h-3" />
                                      </button>
                                    </div>
                                  </div>
                                  <div>
                                    <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                                      <RiFileTextLine className="w-2.5 h-2.5" />
                                      {s("file_content_label")}
                                    </p>
                                    <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                                      <code className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex-1 break-all">
                                        {submitResult.txtValue}
                                      </code>
                                      <button
                                        onClick={() => copyText(submitResult.txtValue)}
                                        className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                      >
                                        <RiFileCopyLine className="w-3 h-3" />
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              </div>

                              {/* Step 2: Verify access URL */}
                              <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                                <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                                  <span className="w-4 h-4 rounded-full bg-sky-500 text-white text-[9px] font-bold flex items-center justify-center shrink-0">2</span>
                                  <p className="text-[11px] font-semibold text-foreground">
                                    {s("file_verify_step2")}
                                  </p>
                                </div>
                                <div className="px-3 py-2.5">
                                  <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                                    <RiLinksLine className="w-3 h-3 text-muted-foreground/50 shrink-0" />
                                    <code className="text-[11px] font-mono text-sky-600 dark:text-sky-400 flex-1 break-all">
                                      {`https://${domain}/.well-known/next-whois-verify.txt`}
                                    </code>
                                    <button
                                      onClick={() => copyText(`https://${domain}/.well-known/next-whois-verify.txt`)}
                                      className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                    >
                                      <RiFileCopyLine className="w-3 h-3" />
                                    </button>
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* HTTP check result */}
                            {httpCheck && (
                              <div className={cn(
                                "flex items-center gap-3 px-3 py-3 rounded-xl border transition-all",
                                httpCheck.found
                                  ? "border-emerald-300/60 bg-emerald-50/50 dark:bg-emerald-950/25"
                                  : httpCheck.error === "timeout"
                                  ? "border-amber-200/50 bg-amber-50/30 dark:bg-amber-950/15"
                                  : "border-border/50 bg-muted/20"
                              )}>
                                <div className={cn(
                                  "shrink-0 w-8 h-8 rounded-lg flex items-center justify-center",
                                  httpCheck.found ? "bg-emerald-500/10"
                                    : httpCheck.error === "timeout" ? "bg-amber-500/10"
                                    : "bg-muted/40"
                                )}>
                                  {verifyState === "loading"
                                    ? <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground/60" />
                                    : httpCheck.found
                                    ? <RiCheckLine className="w-4 h-4 text-emerald-500" />
                                    : httpCheck.error === "timeout"
                                    ? <RiTimeLine className="w-4 h-4 text-amber-500" />
                                    : <RiFileTextLine className="w-4 h-4 text-muted-foreground/40" />
                                  }
                                </div>
                                <div className="min-w-0 flex-1">
                                  <p className={cn(
                                    "text-xs font-semibold",
                                    httpCheck.found ? "text-emerald-700 dark:text-emerald-300"
                                      : httpCheck.error === "timeout" ? "text-amber-600 dark:text-amber-400"
                                      : "text-muted-foreground"
                                  )}>
                                    {httpCheck.found
                                      ? s("file_found")
                                      : httpCheck.error === "timeout"
                                      ? s("request_timeout")
                                      : httpCheck.error
                                      ? s("file_not_found_err").replace("{{error}}", httpCheck.error)
                                      : s("file_not_found")}
                                  </p>
                                  <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                                    {s("http_check")} · {httpCheck.latencyMs}ms
                                  </p>
                                </div>
                              </div>
                            )}
                            {!httpCheck && verifyState === "loading" && (
                              <div className="flex items-center gap-2 px-3 py-2.5 rounded-xl border border-border/50 bg-muted/20">
                                <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground/60 shrink-0" />
                                <p className="text-xs text-muted-foreground">{s("checking_file")}</p>
                              </div>
                            )}
                          </>
                        )}

                        {/* ── Vercel tab ── */}
                        {verifyTab === "vercel" && (
                          <>
                            <div>
                              <h2 className="text-sm font-bold flex items-center gap-2 mb-1">
                                <span className="text-sm font-black">▲</span>
                                {s("vercel_verify_title")}
                              </h2>
                              <p className="text-xs text-muted-foreground leading-relaxed">
                                {s("vercel_verify_desc")}
                              </p>
                            </div>

                            {/* Loading state while fetching TXT from Vercel */}
                            {vercelInitLoading && (
                              <div className="flex items-center gap-2 px-3 py-3 rounded-xl border border-border/50 bg-muted/20">
                                <RiLoader4Line className="w-4 h-4 animate-spin text-muted-foreground/60 shrink-0" />
                                <p className="text-xs text-muted-foreground">{s("fetching_record")}</p>
                              </div>
                            )}

                            {/* API error */}
                            {vercelApiError && !vercelInitLoading && (
                              <div className="rounded-xl border border-red-300/50 bg-red-50/40 dark:bg-red-950/20 p-3 space-y-2">
                                <p className="text-xs font-semibold text-red-700 dark:text-red-400 flex items-center gap-1.5">
                                  <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
                                  {s("cannot_get_vercel")}
                                </p>
                                <p className="text-[10px] text-red-600/70 dark:text-red-400/60 font-mono break-all">{vercelApiError}</p>
                                <button
                                  type="button"
                                  onClick={initVercelVerify}
                                  className="text-[11px] font-semibold text-red-700 dark:text-red-400 hover:underline flex items-center gap-1"
                                >
                                  <RiRefreshLine className="w-3 h-3" />
                                  {t("common.retry")}
                                </button>
                              </div>
                            )}

                            {/* TXT record instructions */}
                            {vercelTxtValue && !vercelInitLoading && (
                              <div className="space-y-2.5">
                                <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                                  <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                                    <span className="w-4 h-4 rounded-full bg-foreground text-background text-[9px] font-bold flex items-center justify-center shrink-0">1</span>
                                    <p className="text-[11px] font-semibold text-foreground">
                                      {s("add_txt_record")}
                                    </p>
                                  </div>
                                  <div className="px-3 py-2.5 space-y-2">
                                    <div>
                                      <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                                        <RiServerLine className="w-2.5 h-2.5" />
                                        {s("record_name")}
                                      </p>
                                      <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                                        <code className="text-[11px] font-mono text-violet-600 dark:text-violet-400 flex-1 break-all">
                                          {vercelTxtFullDomain ?? `_vercel.${domain}`}
                                        </code>
                                        <button
                                          onClick={() => copyText(vercelTxtFullDomain ?? `_vercel.${domain}`)}
                                          className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                        >
                                          <RiFileCopyLine className="w-3 h-3" />
                                        </button>
                                      </div>
                                    </div>
                                    <div>
                                      <p className="text-[10px] font-bold text-muted-foreground/70 uppercase mb-1 flex items-center gap-1">
                                        <RiFileTextLine className="w-2.5 h-2.5" />
                                        {s("record_value")}
                                      </p>
                                      <div className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-background border border-border/50">
                                        <code className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex-1 break-all">
                                          {vercelTxtValue}
                                        </code>
                                        <button
                                          onClick={() => copyText(vercelTxtValue!)}
                                          className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                        >
                                          <RiFileCopyLine className="w-3 h-3" />
                                        </button>
                                      </div>
                                    </div>
                                    <p className="text-[10px] text-muted-foreground/50 pt-0.5">
                                      {s("record_note_txt")}
                                    </p>
                                  </div>
                                </div>

                                <div className="rounded-xl border border-border/60 bg-muted/15 overflow-hidden">
                                  <div className="px-3 py-2 border-b border-border/40 flex items-center gap-2">
                                    <span className="w-4 h-4 rounded-full bg-foreground text-background text-[9px] font-bold flex items-center justify-center shrink-0">2</span>
                                    <p className="text-[11px] font-semibold text-foreground">
                                      {s("click_verify_after")}
                                    </p>
                                  </div>
                                  <div className="px-3 py-2.5">
                                    <button
                                      type="button"
                                      disabled={vercelCheckLoading}
                                      onClick={() => { setVercelCheckAttempt(0); handleVercelCheck(false); }}
                                      className={cn(
                                        "w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg text-xs font-semibold transition-all border",
                                        vercelCheckLoading
                                          ? "bg-muted/40 text-muted-foreground border-border/40 cursor-not-allowed"
                                          : "bg-foreground text-background border-transparent hover:opacity-90 active:scale-[0.98]"
                                      )}
                                    >
                                      {vercelCheckLoading
                                        ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin shrink-0" />
                                        : <RiCheckboxCircleLine className="w-3.5 h-3.5 shrink-0" />}
                                      {vercelCountdown > 0 && !vercelCheckLoading
                                        ? s("auto_checking", { n: vercelCountdown })
                                        : vercelCheckLoading
                                        ? `${s("checking_label")}…`
                                        : s("verify_now")}
                                    </button>
                                  </div>
                                </div>
                              </div>
                            )}
                          </>
                        )}

                        {/* Raw records found panel — shows actual found content when nearMatch */}
                        {anyNearMatch && resolvers.some(r => r.nearMatch && r.records.length > 0) && verifyTab === "dns" && (
                          <div className="rounded-xl border border-orange-300/50 bg-orange-50/50 dark:bg-orange-950/20 p-3 space-y-2">
                            <p className="text-[11px] font-semibold text-orange-700 dark:text-orange-400 flex items-center gap-1.5">
                              <RiAlertLine className="w-3.5 h-3.5 shrink-0" />
                              {s("token_mismatch")}
                            </p>
                            {resolvers.filter(r => r.nearMatch && r.records.length > 0).slice(0, 2).flatMap(r => r.records).slice(0, 3).map((record, i) => (
                              <div key={i} className="flex items-start gap-1.5">
                                <span className="text-[10px] font-bold text-orange-500/70 shrink-0 mt-0.5">{s("found_label")}</span>
                                <code className="text-[10px] font-mono text-orange-600 dark:text-orange-400 break-all leading-relaxed flex-1 bg-orange-500/5 rounded px-1.5 py-0.5">{record}</code>
                              </div>
                            ))}
                            {expectedVal && (
                              <div className="flex items-start gap-1.5">
                                <span className="text-[10px] font-bold text-emerald-600/70 shrink-0 mt-0.5">{s("expected_label")}</span>
                                <code className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 break-all leading-relaxed flex-1 bg-emerald-500/5 rounded px-1.5 py-0.5">{expectedVal}</code>
                              </div>
                            )}
                            <p className="text-[10px] text-muted-foreground leading-relaxed">
                              {s("token_mismatch_note")}
                            </p>
                          </div>
                        )}

                        {/* Status messages (shared) */}
                        <AnimatePresence mode="wait">
                          {verifyState === "nearMatch" && verifyTab === "dns" && (
                            <motion.div
                              key="nearMatch"
                              initial={{ opacity: 0, y: 6 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -4 }}
                              transition={{ duration: 0.18 }}
                              className="flex gap-2.5 p-3 rounded-xl bg-orange-50/60 dark:bg-orange-950/20 border border-orange-300/50"
                            >
                              <RiAlertLine className="w-4 h-4 text-orange-500 shrink-0 mt-0.5" />
                              <p className="text-[11px] text-muted-foreground leading-relaxed">
                                {s("check_content_note")}
                              </p>
                            </motion.div>
                          )}
                          {verifyState === "fail" && resolvers.length > 0 && verifyTab === "dns" && (
                            <motion.div
                              key="fail"
                              initial={{ opacity: 0, y: 6 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -4 }}
                              transition={{ duration: 0.18 }}
                              className="flex gap-2.5 p-3 rounded-xl bg-amber-50/60 dark:bg-amber-950/20 border border-amber-200/50"
                            >
                              <RiAlertLine className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                              <div className="space-y-1 flex-1">
                                <p className="text-[11px] text-muted-foreground leading-relaxed">
                                  {s("fail_msg")}
                                </p>
                              </div>
                            </motion.div>
                          )}
                          {verifyState === "dnsError" && verifyTab === "dns" && (
                            <motion.div
                              key="dnsError"
                              initial={{ opacity: 0, y: 6 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -4 }}
                              transition={{ duration: 0.18 }}
                              className="flex gap-2.5 p-3 rounded-xl bg-red-50/60 dark:bg-red-950/20 border border-red-200/50"
                            >
                              <RiAlertLine className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                              <p className="text-[11px] text-muted-foreground leading-relaxed">
                                {s("dns_error_msg")}
                              </p>
                            </motion.div>
                          )}
                          {verifyState === "giveUp" && (
                            <motion.div
                              key="giveUp"
                              initial={{ opacity: 0, y: 6 }}
                              animate={{ opacity: 1, y: 0 }}
                              exit={{ opacity: 0, y: -4 }}
                              transition={{ duration: 0.2 }}
                              className="rounded-xl border border-orange-200/60 bg-orange-50/50 dark:bg-orange-950/20 overflow-hidden"
                            >
                              <div className="flex gap-2.5 p-3">
                                <div className="shrink-0 w-7 h-7 rounded-lg bg-orange-500/10 flex items-center justify-center mt-0.5">
                                  <RiAlertLine className="w-3.5 h-3.5 text-orange-500" />
                                </div>
                                <div className="space-y-1 flex-1 min-w-0">
                                  <p className="text-xs font-semibold text-orange-700 dark:text-orange-400">
                                    {s("auto_checked_n", { n: POLL_SCHEDULE.length })}
                                  </p>
                                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                                    {s("tld_no_dns_note")}
                                  </p>
                                  <button
                                    type="button"
                                    onClick={() => setVerifyTab("http")}
                                    className="mt-1 flex items-center gap-1 text-[11px] font-semibold text-orange-600 dark:text-orange-400 hover:underline"
                                  >
                                    <RiFlashlightLine className="w-3.5 h-3.5" />
                                    {s("switch_file_verify")} →
                                  </button>
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>

                        {/* Verify button + progress + countdown */}
                        <div className="space-y-2">
                          <Button
                            onClick={() => handleVerify(false)}
                            disabled={verifyState === "loading"}
                            className="w-full gap-2 h-11 bg-violet-500 hover:bg-violet-600 active:bg-violet-700 text-white border-0 rounded-xl text-sm font-semibold shadow-sm shadow-violet-500/20 transition-all"
                          >
                            {verifyState === "loading"
                              ? <><RiLoader4Line className="w-4 h-4 animate-spin" />{s("checking")}</>
                              : <><RiRefreshLine className="w-4 h-4" />{s("btn_check")}</>
                            }
                          </Button>
                          {/* Attempt progress bar */}
                          {pollAttempt > 0 && verifyState !== "giveUp" && (
                            <div className="space-y-1">
                              <div className="flex justify-between items-center text-[10px] text-muted-foreground/60">
                                <span className="flex items-center gap-1">
                                  <RiTimeLine className="w-3 h-3" />
                                  {s("attempt_n", { current: pollAttempt, total: POLL_SCHEDULE.length })}
                                </span>
                                {countdown > 0 && verifyState !== "loading" && (
                                  <span>
                                    {countdown >= 60
                                      ? s("next_check_min", { n: Math.ceil(countdown / 60) })
                                      : s("next_check_sec", { n: countdown })}
                                  </span>
                                )}
                              </div>
                              <div className="w-full h-1 rounded-full bg-muted/40 overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-violet-400/60 transition-all duration-500"
                                  style={{ width: `${(pollAttempt / POLL_SCHEDULE.length) * 100}%` }}
                                />
                              </div>
                            </div>
                          )}
                          {pollAttempt === 0 && countdown > 0 && verifyState !== "loading" && (
                            <div className="rounded-lg bg-sky-50/60 dark:bg-sky-950/20 border border-sky-200/50 px-3 py-2 flex items-center gap-2">
                              <RiTimeLine className="w-3.5 h-3.5 text-sky-500 shrink-0" />
                              <p className="text-[11px] text-sky-700 dark:text-sky-300 flex-1">
                                {s("add_txt_first")}
                              </p>
                              <span className="shrink-0 text-[10px] font-mono text-sky-500 tabular-nums">
                                {countdown >= 60
                                  ? `${Math.ceil(countdown / 60)}m`
                                  : `${countdown}s`}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Tips card — only DNS tab */}
                      {verifyTab === "dns" && (
                        <div className="rounded-2xl border border-border/50 bg-muted/20 p-4 flex gap-3">
                          <div className="shrink-0 w-7 h-7 rounded-lg bg-amber-500/10 flex items-center justify-center mt-0.5">
                            <RiAlertLine className="w-3.5 h-3.5 text-amber-500" />
                          </div>
                          <div className="space-y-1">
                            <p className="text-xs font-semibold text-foreground">{s("dns_prop_title")}</p>
                            <p className="text-[11px] text-muted-foreground leading-relaxed">
                              {s("dns_prop_prefix")}<strong className="text-foreground">{s("dns_prop_highlight")}</strong>{s("dns_prop_suffix")}
                            </p>
                          </div>
                        </div>
                      )}

                      <button
                        onClick={() => { stopPolling(); goToStep("form"); }}
                        className="text-xs text-muted-foreground hover:text-foreground transition-colors w-full text-center py-1"
                      >
                        {s("back_edit")}
                      </button>
                    </div>
                  )}

                  {/* ── STEP 3: DONE ── */}
                  {step === "done" && (
                    <div className="space-y-4">
                      <div className="glass-panel border border-emerald-300/40 dark:border-emerald-700/30 rounded-2xl p-8 text-center">
                        <div className="relative w-16 h-16 mx-auto mb-5">
                          <div className="absolute inset-0 rounded-full bg-emerald-500/15 animate-ping" />
                          <div className="relative w-16 h-16 bg-emerald-500/10 border-2 border-emerald-400/40 rounded-full flex items-center justify-center">
                            <RiCheckLine className="w-8 h-8 text-emerald-500" />
                          </div>
                        </div>
                        <h2 className="text-xl font-bold text-emerald-700 dark:text-emerald-300 mb-2">{s("done_title")}</h2>
                        <p className="text-sm text-muted-foreground mb-4 leading-relaxed">
                          {s("done_claim_body", { domain })}
                        </p>
                        <div className="inline-flex items-center justify-center py-3 px-5 rounded-xl bg-gradient-to-br from-violet-50/60 to-fuchsia-50/40 dark:from-violet-950/30 dark:to-fuchsia-950/20 border border-violet-200/40 dark:border-violet-800/30 mb-6">
                          <TagBadge tagName={form.tagName} tagStyle={form.tagStyle} live />
                        </div>
                        <div className="space-y-2.5">
                          <Button
                            className="w-full gap-2 h-11 bg-violet-500 hover:bg-violet-600 text-white border-0 rounded-xl font-semibold"
                            onClick={goBack}
                          >
                            <RiExternalLinkLine className="w-4 h-4" />
                            {s("done_view")}
                          </Button>
                        </div>
                      </div>

                      {/* Delete verification record reminder */}
                      {submitResult && (
                        <div className="rounded-2xl border border-sky-200/60 dark:border-sky-800/40 bg-sky-50/60 dark:bg-sky-950/20 p-4">
                          <div className="flex gap-3">
                            <div className="shrink-0 w-8 h-8 rounded-lg bg-sky-500/10 flex items-center justify-center mt-0.5">
                              <RiDeleteBinLine className="w-4 h-4 text-sky-500" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <p className="text-xs font-semibold text-sky-700 dark:text-sky-300 mb-1">{s("done_delete_title")}</p>
                              <p className="text-[11px] text-muted-foreground leading-relaxed mb-2.5">
                                {s("done_delete_body")}
                              </p>
                              <div className="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-background/70 border border-sky-200/50 dark:border-sky-800/30">
                                <span className="text-[10px] font-bold text-muted-foreground/60 uppercase shrink-0">TXT</span>
                                <code className="text-[11px] font-mono text-sky-700 dark:text-sky-300 flex-1 break-all">
                                  {submitResult.txtRecord}
                                </code>
                                <button
                                  onClick={() => copyText(submitResult!.txtRecord)}
                                  className="shrink-0 p-1 rounded hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                                >
                                  <RiFileCopyLine className="w-3 h-3" />
                                </button>
                              </div>
                              <p className="text-[10px] text-muted-foreground/50 mt-1.5">
                                ℹ️ {s("done_keep_record")}
                              </p>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* What happens next */}
                      <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
                        <p className="text-xs font-bold text-muted-foreground uppercase tracking-widest">{s("done_next")}</p>
                        {[
                          { icon: RiGlobalLine, text: s("done_next_all_users") },
                          { icon: RiShieldCheckLine, text: s("done_next_prominent") },
                          { icon: RiCheckLine, text: s("done_next_resubmit") },
                        ].map((item, i) => {
                          const ItemIcon = item.icon;
                          return (
                          <div key={i} className="flex items-start gap-2.5">
                            <div className="shrink-0 w-5 h-5 rounded-md bg-violet-500/10 flex items-center justify-center mt-0.5">
                              <ItemIcon className="w-3 h-3 text-violet-500" />
                            </div>
                            <p className="text-[11px] text-muted-foreground leading-relaxed">{item.text}</p>
                          </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </motion.div>
              </AnimatePresence>

              {/* Style preview bottom sheet */}
              <AnimatePresence>
                {previewStyleId && (() => {
                  const ts = TAG_STYLES.find(t => t.id === previewStyleId) || TAG_STYLES[0];
                  const cardTheme = CARD_THEME_OPTIONS.find(t => t.id === ts.theme) || CARD_THEME_OPTIONS[0];
                  const Icon = ts.icon;
                  const badgeLabel = s((`badge_${previewStyleId}`) as StampKey) || s("badge_default");
                  const previewName = form.tagName.trim() || t("stamp.brand_name_placeholder" as TranslationKey);
                  const isSelected = form.tagStyle === previewStyleId;
                  return (
                    <>
                      <motion.div
                        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]"
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        onClick={() => setPreviewStyleId(null)}
                      />
                      <motion.div
                        className="fixed inset-0 z-50 flex items-center justify-center px-4"
                        initial={{ scale: 0.93, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.93, opacity: 0 }}
                        transition={{ type: "spring", damping: 24, stiffness: 300 }}
                        onClick={(e) => { if (e.target === e.currentTarget) setPreviewStyleId(null); }}
                      >
                        <div className="bg-background border border-border rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
                          {/* Sheet header */}
                          <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-border/50">
                            <div className="flex items-center gap-2">
                              <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold", ts.className)}>
                                <Icon className="w-3 h-3" />
                                {isZh ? ts.zhName : ts.label}
                              </span>
                              <span className="text-xs text-muted-foreground">{isZh ? cardTheme.label : cardTheme.enLabel}</span>
                            </div>
                            <button
                              type="button"
                              onClick={() => setPreviewStyleId(null)}
                              className="w-7 h-7 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
                            >
                              <RiCloseLine className="w-4 h-4" />
                            </button>
                          </div>
                          {/* Card preview — real popup */}
                          <div className="px-4 py-4">
                            <div className="rounded-[18px] overflow-hidden shadow-md">
                              <StampPreviewCard
                                themeKey={ts.theme || "app"}
                                data={{
                                  tagName: previewName,
                                  domain: domain || undefined,
                                  description: form.description || undefined,
                                  link: form.link || undefined,
                                  tagLabel: badgeLabel,
                                  icon: ts.icon,
                                }}
                              />
                            </div>
                          </div>
                          {/* Action */}
                          <div className="px-4 pb-4 flex gap-2">
                            {isSelected ? (
                              <button
                                type="button"
                                onClick={() => setPreviewStyleId(null)}
                                className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-1.5"
                              >
                                <RiCheckLine className="w-4 h-4" />
                                {s("selected")}
                              </button>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  onClick={() => setPreviewStyleId(null)}
                                  className="px-4 py-2.5 rounded-xl border border-border text-sm font-medium text-muted-foreground hover:bg-muted/50 transition-colors"
                                >
                                  {t("common.cancel")}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => { update("tagStyle", previewStyleId); setPreviewStyleId(null); }}
                                  className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity"
                                >
                                  {s("use_this_style")}
                                </button>
                              </>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    </>
                  );
                })()}
              </AnimatePresence>

              {/* Card Layout preview popup */}
              <AnimatePresence>
                {previewThemeKey && isMember && (() => {
                  const th = STAMP_CARD_THEMES[previewThemeKey];
                  if (!th) return null;
                  const styleObj = TAG_STYLES.find(ts => ts.id === form.tagStyle) || TAG_STYLES[0];
                  const badgeLabel = s((`badge_${form.tagStyle}`) as StampKey) || s("badge_default");
                  const previewName = form.tagName.trim() || t("stamp.brand_name_placeholder" as TranslationKey);
                  const isSelected = form.cardTheme === previewThemeKey;
                  return (
                    <>
                      <motion.div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]"
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                        onClick={() => setPreviewThemeKey(null)} />
                      <motion.div className="fixed inset-0 z-50 flex items-center justify-center px-4"
                        initial={{ scale: 0.93, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.93, opacity: 0 }}
                        transition={{ type: "spring", damping: 24, stiffness: 300 }}
                        onClick={(e) => { if (e.target === e.currentTarget) setPreviewThemeKey(null); }}
                      >
                        <div className="bg-background border border-border rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
                          <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-border/50">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-semibold">{isZh ? "特殊排版预览" : "Special Layout Preview"}</span>
                              <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[9px] font-bold"
                                style={{background:"rgba(124,58,237,0.08)",color:"#7C3AED",border:"1px solid rgba(124,58,237,0.2)"}}>
                                {th.label}
                              </span>
                            </div>
                            <button type="button" onClick={() => setPreviewThemeKey(null)}
                              className="w-7 h-7 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors">
                              <RiCloseLine className="w-4 h-4" />
                            </button>
                          </div>
                          <div className="px-4 py-4">
                            <div className="rounded-[18px] overflow-hidden shadow-md">
                              <StampPreviewCard
                                themeKey={previewThemeKey}
                                data={{
                                  tagName: previewName,
                                  domain: domain || undefined,
                                  description: form.description || undefined,
                                  link: form.link || undefined,
                                  tagLabel: badgeLabel,
                                  icon: styleObj.icon,
                                }}
                              />
                            </div>
                          </div>
                          <div className="px-4 pb-4 flex gap-2">
                            <button type="button" onClick={() => setPreviewThemeKey(null)}
                              className="px-4 py-2.5 rounded-xl border border-border text-sm font-medium text-muted-foreground hover:bg-muted/50 transition-colors">
                              {t("common.cancel")}
                            </button>
                            {isSelected ? (
                              <button type="button" onClick={() => setPreviewThemeKey(null)}
                                className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-1.5">
                                <RiCheckLine className="w-4 h-4" />
                                {s("selected")}
                              </button>
                            ) : (
                              <button type="button"
                                onClick={() => { update("cardTheme", previewThemeKey); setPreviewThemeKey(null); }}
                                className="flex-1 py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity">
                                {isZh ? "使用此排版" : "Use This Layout"}
                              </button>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    </>
                  );
                })()}
              </AnimatePresence>

              {/* Guide modal */}
              <AnimatePresence>
                {showGuide && (
                  <>
                    <motion.div
                      className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      onClick={dismissGuide}
                    />
                    <motion.div
                      className="fixed inset-0 z-50 flex items-center justify-center px-4"
                      initial={{ scale: 0.93, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      exit={{ scale: 0.93, opacity: 0 }}
                      transition={{ type: "spring", damping: 24, stiffness: 300 }}
                      onClick={(e) => { if (e.target === e.currentTarget) dismissGuide(); }}
                    >
                      <div className="bg-background border border-border rounded-2xl shadow-2xl overflow-hidden w-full max-w-sm">
                        {/* Header */}
                        <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border/60">
                          <div className="flex items-center gap-2">
                            <div className="w-7 h-7 rounded-lg bg-violet-500/10 flex items-center justify-center">
                              <RiShieldCheckLine className="w-4 h-4 text-violet-500" />
                            </div>
                            <p className="text-sm font-bold">{s("how_it_works")}</p>
                          </div>
                          <button
                            type="button"
                            onClick={dismissGuide}
                            className="w-7 h-7 rounded-lg flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
                          >
                            <RiCloseLine className="w-4 h-4" />
                          </button>
                        </div>
                        {/* Steps */}
                        <div className="px-5 py-4 space-y-3.5">
                          {HOW_TO_STEPS.map((hwStep, i) => {
                            const Icon = hwStep.icon;
                            return (
                              <div key={i} className="flex gap-3 items-start">
                                <div className={cn("shrink-0 w-7 h-7 rounded-lg flex items-center justify-center", hwStep.bg)}>
                                  <Icon className={cn("w-3.5 h-3.5", hwStep.color)} />
                                </div>
                                <div className="min-w-0 flex-1 pt-0.5">
                                  <p className="text-xs font-semibold text-foreground leading-none mb-1">{s(HOW_STEP_TITLE_KEYS[i])}</p>
                                  <p className="text-[11px] text-muted-foreground leading-relaxed">{s(HOW_STEP_DESC_KEYS[i])}</p>
                                </div>
                                {i < HOW_TO_STEPS.length - 1 && (
                                  <div className="shrink-0 flex items-center mt-1.5 text-muted-foreground/30">
                                    <RiArrowRightLine className="w-3.5 h-3.5" />
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                        {/* Dismiss button */}
                        <div className="px-5 pb-5">
                          <button
                            type="button"
                            onClick={dismissGuide}
                            className="w-full py-2.5 rounded-xl bg-primary text-primary-foreground text-sm font-semibold hover:opacity-90 transition-opacity"
                          >
                            {s("got_it")}
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  </>
                )}
              </AnimatePresence>
            </>
          )}
        </div>
      </div>
    </>
  );
}
