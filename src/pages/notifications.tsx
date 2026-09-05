import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession, signOut } from "next-auth/react";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import {
  RiNotification3Line,
  RiNotificationOffLine,
  RiLoader4Line,
  RiArrowLeftLine,
  RiCheckDoubleLine,
  RiLogoutBoxLine,
  RiTimeLine,
  RiAlertLine,
  RiErrorWarningLine,
  RiDeleteBinLine,
  RiAlarmWarningLine,
  RiCloseCircleLine,
  RiPauseCircleLine,
  RiLockLine,
  RiStarLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import { format } from "date-fns";

interface NotifItem {
  id: string;
  type: string;
  title: string;
  body: string | null;
  domain: string | null;
  read: boolean;
  created_at: string;
}

const NOTIF_TYPE_ICON: Record<string, React.ReactNode> = {
  threshold: <RiTimeLine className="w-4 h-4" />,
  grace: <RiAlertLine className="w-4 h-4" />,
  redemption: <RiErrorWarningLine className="w-4 h-4" />,
  pending_delete: <RiDeleteBinLine className="w-4 h-4" />,
  drop_soon: <RiAlarmWarningLine className="w-4 h-4" />,
  dropped: <RiCloseCircleLine className="w-4 h-4" />,
  hold: <RiPauseCircleLine className="w-4 h-4" />,
  reserved: <RiLockLine className="w-4 h-4" />,
  membership: <RiStarLine className="w-4 h-4" />,
};

const NOTIF_TYPE_COLOR: Record<string, string> = {
  threshold: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
  grace: "bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400",
  redemption: "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400",
  pending_delete: "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400",
  drop_soon: "bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400",
  dropped: "bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400",
  hold: "bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400",
  reserved: "bg-sky-100 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400",
  membership: "bg-violet-100 dark:bg-violet-950/40 text-violet-600 dark:text-violet-400",
};

export default function NotificationsPage() {
  const { data: session, status } = useSession();
  const { t, locale } = useTranslation();
  const router = useRouter();
  const [items, setItems] = React.useState<NotifItem[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);

  const email = (session?.user as any)?.email as string | undefined;

  const load = React.useCallback(async () => {
    try {
      const res = await fetch("/api/user/notifications?limit=100");
      if (!res.ok) throw new Error("bad status");
      const data = await res.json();
      setItems(Array.isArray(data.notifications) ? data.notifications : []);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (status === "authenticated") load();
  }, [status, load]);

  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (status === "unauthenticated") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-3">
          <RiNotificationOffLine className="w-8 h-8 mx-auto text-muted-foreground/60" />
          <p className="text-sm text-muted-foreground">{t("notifications.empty")}</p>
          <Link href="/login" className="text-sm font-medium text-primary hover:underline">
            {t("nav_login")}
          </Link>
        </div>
      </div>
    );
  }

  const markRead = async (id: string) => {
    setItems(prev => prev.map(it => (it.id === id ? { ...it, read: true } : it)));
    try {
      await fetch("/api/user/notifications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
    } catch {
      /* best-effort */
    }
  };

  const markAllRead = async () => {
    if (!items.some(it => !it.read)) return;
    setItems(prev => prev.map(it => ({ ...it, read: true })));
    try {
      await fetch("/api/user/notifications", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ markAll: true }),
      });
    } catch {
      /* best-effort */
    }
  };

  const fmtDate = (iso: string) => {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    const isChinese = locale === "zh" || locale === "zh-tw";
    return isChinese ? format(d, "yyyy年M月d日 HH:mm") : format(d, "MMM d, yyyy HH:mm");
  };

  const typeLabel = (type: string): string => {
    const keyMap: Record<string, string> = {
      threshold: "notifications.type_threshold",
      grace: "notifications.type_grace",
      redemption: "notifications.type_redemption",
      pending_delete: "notifications.type_pending_delete",
      drop_soon: "notifications.type_drop_soon",
      dropped: "notifications.type_dropped",
      hold: "notifications.type_hold",
      reserved: "notifications.type_reserved",
      membership: "notifications.type_membership",
    };
    const k = keyMap[type];
    return k ? (t as any)(k) : "";
  };

  const unreadCount = items.filter(it => !it.read).length;

  return (
    <>
      <Head>
        <title>{t("notifications.title")}</title>
      </Head>
      <div className="min-h-screen flex justify-center pt-8 pb-16 px-4">
        <div className="w-full max-w-xl">
          <div className="flex items-center justify-between mb-4">
            <button
              type="button"
              onClick={() => router.push("/dashboard")}
              className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors touch-manipulation py-2"
            >
              <RiArrowLeftLine className="w-4 h-4" />
              {t("notifications.back_to_dashboard")}
            </button>
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <span className="text-[10px] text-red-500 font-semibold">{unreadCount} {t("notifications.unread")}</span>
              )}
              <button
                type="button"
                onClick={markAllRead}
                disabled={unreadCount === 0}
                className={cn(
                  "inline-flex items-center gap-1 text-[11px] font-medium rounded-lg px-2.5 py-1.5 border transition-colors touch-manipulation",
                  unreadCount > 0
                    ? "border-primary/30 text-primary hover:bg-primary/10"
                    : "border-border text-muted-foreground/50 cursor-not-allowed",
                )}
              >
                <RiCheckDoubleLine className="w-3.5 h-3.5" />
                {t("notifications.mark_all_read")}
              </button>
            </div>
          </div>

          <div className="glass-panel border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border/50 flex items-center justify-between">
              <h1 className="text-sm font-bold flex items-center gap-2">
                <RiNotification3Line className="w-4 h-4 text-primary" />
                {t("notifications.title")}
              </h1>
            </div>

            {loading ? (
              <div className="px-4 py-12 text-center">
                <RiLoader4Line className="w-5 h-5 animate-spin mx-auto text-muted-foreground" />
              </div>
            ) : error ? (
              <div className="px-4 py-12 text-center space-y-2">
                <RiNotificationOffLine className="w-6 h-6 mx-auto text-muted-foreground/50" />
                <p className="text-xs text-muted-foreground">{t("notifications.load_failed")}</p>
                <button
                  type="button"
                  onClick={() => { setLoading(true); setError(false); load(); }}
                  className="text-[11px] font-medium text-primary hover:underline touch-manipulation"
                >
                  {t("common.retry")}
                </button>
              </div>
            ) : items.length === 0 ? (
              <div className="px-4 py-12 text-center space-y-2">
                <RiNotificationOffLine className="w-7 h-7 mx-auto text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">{t("notifications.all_clear")}</p>
              </div>
            ) : (
              <div className="divide-y divide-border/40">
                {items.map(it => (
                  <motion.button
                    key={it.id}
                    type="button"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    onClick={() => markRead(it.id)}
                    className={cn(
                      "w-full text-left flex items-start gap-3 px-4 py-3 hover:bg-muted active:bg-muted/70 transition-colors touch-manipulation",
                      !it.read && "bg-primary/[0.04]",
                    )}
                  >
                    <span className={cn(
                      "mt-0.5 w-8 h-8 rounded-lg flex items-center justify-center shrink-0",
                      NOTIF_TYPE_COLOR[it.type] ?? "bg-muted text-muted-foreground",
                    )}>
                      {NOTIF_TYPE_ICON[it.type] ?? <RiNotification3Line className="w-4 h-4" />}
                    </span>
                    <span className="flex-1 min-w-0">
                      <span className="flex items-center gap-2">
                        {typeLabel(it.type) && (
                          <span className="text-[9px] font-semibold uppercase tracking-wide text-muted-foreground/80 bg-muted/60 rounded px-1.5 py-0.5">
                            {typeLabel(it.type)}
                          </span>
                        )}
                        {it.domain && (
                          <span className="text-[10px] text-muted-foreground truncate">{it.domain}</span>
                        )}
                      </span>
                      <span className={cn("block text-sm mt-1", !it.read && "font-semibold")}>{it.title}</span>
                      {it.body && <span className="block text-xs text-muted-foreground mt-0.5">{it.body}</span>}
                      <span className="block text-[10px] text-muted-foreground/70 mt-1">{fmtDate(it.created_at)}</span>
                    </span>
                    {!it.read ? (
                      <span className="mt-1 w-2 h-2 rounded-full bg-red-500 shrink-0" />
                    ) : (
                      <RiCheckDoubleLine className="mt-1 w-3.5 h-3.5 text-muted-foreground/40 shrink-0" />
                    )}
                  </motion.button>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={() => signOut({ callbackUrl: "/" })}
              className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground hover:text-red-500 transition-colors touch-manipulation"
            >
              <RiLogoutBoxLine className="w-3.5 h-3.5" />
              {t("sign_out")}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
