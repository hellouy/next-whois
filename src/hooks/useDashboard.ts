import React from "react";
import { useRouter } from "next/router";
import { useSession, signOut } from "next-auth/react";
import { toast } from "sonner";
import { useTranslation } from "@/lib/i18n";
import { useSiteSettings } from "@/lib/site-settings";
import {
  fetchDashData, invalidateDashCache, getDashCache,
  type DashData, type SearchStats, type RecentSearch,
} from "@/lib/dashboard-cache";
import type { Subscription, Stamp, Order, BalanceTx, Plan, DashboardUser } from "@/components/dashboard/types";

export function useDashboard() {
  const router = useRouter();
  const { t, locale } = useTranslation();
  const { data: session, status, update: updateSession } = useSession();
  const siteSettings = useSiteSettings();
  const paymentEnabled = !!(
    siteSettings.payment_stripe_enabled ||
    siteSettings.payment_xunhupay_enabled ||
    siteSettings.payment_alipay_enabled ||
    siteSettings.payment_paypal_enabled
  );

  const VALID_TABS: ReadonlyArray<"subscriptions" | "stamps" | "account" | "membership"> = ["subscriptions", "stamps", "account", "membership"];
  const urlTab = router.query.tab as string | undefined;
  const urlTabValue = (VALID_TABS as ReadonlyArray<string>).includes(urlTab ?? "") ? (urlTab as "subscriptions" | "stamps" | "account" | "membership") : null;

  const [tab, setTab] = React.useState<"subscriptions" | "stamps" | "account" | "membership">(urlTabValue ?? "stamps");
  const [subFilter, setSubFilter] = React.useState<"all" | "expiring" | "urgent" | "expired">("all");
  const [subscriptions, setSubscriptions] = React.useState<Subscription[]>([]);
  const [stamps, setStamps] = React.useState<Stamp[]>([]);
  const [subscriptionAccessDB, setSubscriptionAccessDB] = React.useState<boolean | null>(null);
  const [subscriptionExpiresAt, setSubscriptionExpiresAt] = React.useState<string | null>(null);
  const [loadingData, setLoadingData] = React.useState(false);
  const [dashError, setDashError] = React.useState(false);
  const [editingStamp, setEditingStamp] = React.useState<Stamp | null>(null);
  const [editingSubscription, setEditingSubscription] = React.useState<Subscription | null>(null);
  const [savingDaysBefore, setSavingDaysBefore] = React.useState<string | null>(null);
  const [cancelling, setCancelling] = React.useState<string | null>(null);
  const [deletingStamp, setDeletingStamp] = React.useState<string | null>(null);
  const [showClaimGuide, setShowClaimGuide] = React.useState(false);
  const [showSubscribeGuide, setShowSubscribeGuide] = React.useState(false);
  const [balanceCents, setBalanceCents] = React.useState(0);
  const [membershipPlan, setMembershipPlan] = React.useState<string | null>(null);
  const [orders, setOrders] = React.useState<Order[]>([]);
  const [loadingOrders, setLoadingOrders] = React.useState(false);
  const [balanceTxs, setBalanceTxs] = React.useState<BalanceTx[]>([]);
  const [showBalanceTxs, setShowBalanceTxs] = React.useState(false);
  const [loadingBalanceTxs, setLoadingBalanceTxs] = React.useState(false);
  const [plans, setPlans] = React.useState<Plan[]>([]);
  const [loadingPlans, setLoadingPlans] = React.useState(false);
  const [redeemCode, setRedeemCode] = React.useState("");
  const [redeeming, setRedeeming] = React.useState(false);
  const [contactMsg, setContactMsg] = React.useState("");
  const [contactCategory, setContactCategory] = React.useState(() => t("contact.cat_payment"));
  const [contactSending, setContactSending] = React.useState(false);
  const [contactSent, setContactSent] = React.useState(false);
  const [subSearch, setSubSearch] = React.useState("");
  const [emailChangeCode, setEmailChangeCode] = React.useState("");
  const [sendingChangeCode, setSendingChangeCode] = React.useState(false);
  const [changeCodeCooldown, setChangeCodeCooldown] = React.useState(0);
  const [showDeleteConfirm, setShowDeleteConfirm] = React.useState(false);
  const [deleteConfirmEmail, setDeleteConfirmEmail] = React.useState("");
  const [deletingAccount, setDeletingAccount] = React.useState(false);
  const [inviteCodeInput, setInviteCodeInput] = React.useState("");
  const [applyingCode, setApplyingCode] = React.useState(false);
  const [editingName, setEditingName] = React.useState(false);
  const [nameValue, setNameValue] = React.useState("");
  const [savingName, setSavingName] = React.useState(false);
  const [editingEmail, setEditingEmail] = React.useState(false);
  const [emailValue, setEmailValue] = React.useState("");
  const [savingEmail, setSavingEmail] = React.useState(false);
  const [showPwdSection, setShowPwdSection] = React.useState(false);
  const [currentPwd, setCurrentPwd] = React.useState("");
  const [newPwd, setNewPwd] = React.useState("");
  const [confirmPwd, setConfirmPwd] = React.useState("");
  const [showCurrent, setShowCurrent] = React.useState(false);
  const [showNew, setShowNew] = React.useState(false);
  const [savingPwd, setSavingPwd] = React.useState(false);
  const [avatarColor, setAvatarColor] = React.useState("violet");
  const [editingAvatar, setEditingAvatar] = React.useState(false);
  const [savingAvatar, setSavingAvatar] = React.useState(false);
  const [searchStats, setSearchStats] = React.useState<SearchStats | null>(null);
  const [recentSearches, setRecentSearches] = React.useState<RecentSearch[]>([]);

  React.useEffect(() => {
    if (status === "unauthenticated") router.replace("/login?callbackUrl=/dashboard");
  }, [status, router]);

  React.useEffect(() => {
    if (status !== "authenticated") return;
    if (urlTabValue) return;
    if ((session?.user as DashboardUser)?.subscriptionAccess) setTab("subscriptions");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, session]);

  const applyDashData = React.useCallback((d: DashData) => {
    setSubscriptions(d.subscriptions);
    setStamps(d.stamps);
    setSubscriptionAccessDB(d.subscriptionAccess);
    setSubscriptionExpiresAt(d.subscriptionExpiresAt ?? null);
    setBalanceCents(d.balanceCents ?? 0);
    setMembershipPlan(d.membershipPlan ?? null);
    setSearchStats(d.searchStats ?? null);
    setRecentSearches(d.recentSearches ?? []);
    if (d.subscriptionAccess && !(session?.user as DashboardUser)?.subscriptionAccess) {
      updateSession({ refreshSubscription: true });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, updateSession]);

  React.useEffect(() => {
    if (status !== "authenticated") return;
    const cache = getDashCache();
    if (cache.fresh && cache.data) {
      applyDashData(cache.data);
      fetchDashData().then(applyDashData).catch(() => {});
      return;
    }
    setDashError(false);
    setLoadingData(true);
    fetchDashData()
      .then(applyDashData)
      .catch(() => setDashError(true))
      .finally(() => setLoadingData(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  React.useEffect(() => {
    if (tab === "membership" && status === "authenticated") {
      if (orders.length === 0) {
        setLoadingOrders(true);
        fetch("/api/user/orders")
          .then(r => r.json())
          .then(d => { if (d.orders) setOrders(d.orders); })
          .catch(() => {})
          .finally(() => setLoadingOrders(false));
      }
      if (plans.length === 0) {
        setLoadingPlans(true);
        fetch("/api/payment/plans")
          .then(r => r.json())
          .then(d => { if (Array.isArray(d.plans)) setPlans(d.plans); })
          .catch(() => {})
          .finally(() => setLoadingPlans(false));
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, status]);

  React.useEffect(() => {
    if (status === "authenticated") {
      fetch("/api/user/profile")
        .then(r => r.json())
        .then(data => { if (data.user?.avatar_color) setAvatarColor(data.user.avatar_color); })
        .catch(() => {});
    }
  }, [status]);

  function refreshData() {
    invalidateDashCache();
    fetchDashData().then(applyDashData).catch(() => {});
  }

  function retryLoad() {
    setDashError(false);
    setLoadingData(true);
    fetchDashData().then(applyDashData).catch(() => setDashError(true)).finally(() => setLoadingData(false));
  }

  async function cancelSubscription(id: string) {
    setCancelling(id);
    try {
      await fetch(`/api/user/subscriptions?id=${id}`, { method: "DELETE" });
      setSubscriptions(prev => prev.map(s => s.id === id ? { ...s, active: false } : s));
      invalidateDashCache();
      toast.success(t("dashboard.sub_cancelled"));
    } catch {
      toast.error(t("dashboard.op_failed"));
    } finally {
      setCancelling(null);
    }
  }

  async function saveDaysBefore(id: string, days: number) {
    setSavingDaysBefore(id);
    try {
      const res = await fetch(`/api/user/subscriptions?id=${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days_before: days }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      setSubscriptions(prev => prev.map(s => s.id === id ? { ...s, days_before: days } : s));
      invalidateDashCache();
      toast.success(t("dashboard.days_before_updated", { days }));
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.update_failed"));
    } finally {
      setSavingDaysBefore(null);
    }
  }

  async function deleteStamp(id: string) {
    setDeletingStamp(id);
    try {
      const res = await fetch(`/api/user/stamps?id=${id}`, { method: "DELETE" });
      if (!res.ok) throw new Error((await res.json()).error);
      setStamps(prev => prev.filter(s => s.id !== id));
      invalidateDashCache();
      toast.success(t("dashboard.stamp_deleted"));
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.delete_failed"));
    } finally {
      setDeletingStamp(null);
    }
  }

  function exportSubscriptionsCSV() {
    const activeSubs = subscriptions.filter(s => s.active);
    if (activeSubs.length === 0) { toast.info(t("dashboard.csv_empty")); return; }
    const rows = [
      [t("dashboard.csv_domain"), t("dashboard.csv_expiry"), t("dashboard.csv_phase"), t("dashboard.csv_days"), t("dashboard.csv_drop"), t("dashboard.csv_advance"), t("dashboard.csv_last_reminded"), t("dashboard.csv_created")],
      ...activeSubs.map(s => [
        s.domain,
        s.expiration_date ? new Date(s.expiration_date).toLocaleDateString() : t("dashboard.unknown"),
        s.phase ?? t("dashboard.unknown"),
        s.days_to_expiry !== null ? String(s.days_to_expiry) : "—",
        s.drop_date ? new Date(s.drop_date).toLocaleDateString() : "—",
        String(s.days_before ?? 30),
        s.last_reminded_at ? new Date(s.last_reminded_at).toLocaleDateString() : t("dashboard.never"),
        new Date(s.created_at).toLocaleDateString(),
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "domain-subscriptions.csv"; a.click();
    URL.revokeObjectURL(url);
    toast.success(t("dashboard.csv_exported", { count: activeSubs.length }));
  }

  async function saveName() {
    setSavingName(true);
    try {
      const res = await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: nameValue }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      await updateSession({ name: nameValue.trim() || null });
      toast.success(t("dashboard.name_updated"));
      setEditingName(false);
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.update_failed"));
    } finally {
      setSavingName(false);
    }
  }

  async function sendEmailChangeCode() {
    if (!emailValue.trim()) return;
    setSendingChangeCode(true);
    try {
      const res = await fetch("/api/user/send-email-change-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ newEmail: emailValue.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(t("dashboard.code_sent"));
      let countdown = 60;
      setChangeCodeCooldown(countdown);
      const timer = setInterval(() => {
        countdown--;
        setChangeCodeCooldown(countdown);
        if (countdown <= 0) clearInterval(timer);
      }, 1000);
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.send_failed"));
    } finally {
      setSendingChangeCode(false);
    }
  }

  async function saveEmail() {
    if (!emailValue.trim()) { toast.error(t("dashboard.enter_email")); return; }
    if (!emailChangeCode.trim()) { toast.error(t("dashboard.code_required")); return; }
    setSavingEmail(true);
    try {
      const res = await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailValue.trim(), emailChangeCode: emailChangeCode.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      await updateSession({ email: emailValue.trim().toLowerCase() });
      toast.success(t("dashboard.email_updated"));
      setEditingEmail(false);
      setEmailChangeCode("");
      setChangeCodeCooldown(0);
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.update_failed"));
    } finally {
      setSavingEmail(false);
    }
  }

  async function deleteAccount() {
    const userEmail = session?.user?.email;
    if (deleteConfirmEmail.toLowerCase().trim() !== userEmail?.toLowerCase()) {
      toast.error(t("dashboard.email_confirm_mismatch"));
      return;
    }
    setDeletingAccount(true);
    try {
      const res = await fetch("/api/user/delete-account", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmEmail: deleteConfirmEmail.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(t("dashboard.account_deleted"));
      await signOut({ callbackUrl: "/" });
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.delete_account_failed"));
    } finally {
      setDeletingAccount(false);
    }
  }

  async function changePassword() {
    if (!currentPwd) { toast.error(t("dashboard.enter_current_pwd")); return; }
    if (newPwd.length < 8) { toast.error(t("dashboard.pwd_min_length")); return; }
    if (newPwd !== confirmPwd) { toast.error(t("dashboard.pwd_mismatch")); return; }
    setSavingPwd(true);
    try {
      const res = await fetch("/api/user/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ currentPassword: currentPwd, newPassword: newPwd }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      toast.success(t("dashboard.pwd_updated"));
      setShowPwdSection(false);
      setCurrentPwd(""); setNewPwd(""); setConfirmPwd("");
    } catch (err) {
      toast.error((err instanceof Error ? err.message : String(err)) || t("dashboard.change_failed"));
    } finally {
      setSavingPwd(false);
    }
  }

  async function saveAvatarColor(color: string) {
    setSavingAvatar(true);
    try {
      await fetch("/api/user/profile", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ avatar_color: color }),
      });
      setAvatarColor(color);
      setEditingAvatar(false);
    } catch {
      toast.error(t("dashboard.avatar_save_failed"));
    } finally {
      setSavingAvatar(false);
    }
  }

  async function handleRedeemCode(e: React.FormEvent) {
    e.preventDefault();
    const code = redeemCode.trim().toUpperCase();
    if (!code) { toast.error(t("dashboard.enter_code")); return; }
    setRedeeming(true);
    try {
      const res = await fetch("/api/user/redeem-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (res.ok) {
        toast.success(data.message || t("dashboard.redeem_success"));
        setRedeemCode("");
        setSubscriptionAccessDB(data.subscriptionAccess ?? subscriptionAccessDB);
        setSubscriptionExpiresAt(data.subscriptionExpiresAt ?? subscriptionExpiresAt);
        setMembershipPlan(data.membershipPlan ?? membershipPlan);
        setBalanceCents(data.balanceCents ?? balanceCents);
        invalidateDashCache();
        if (data.subscriptionAccess) updateSession({ refreshSubscription: true });
      } else {
        toast.error(data.error || t("dashboard.redeem_failed"));
      }
    } catch {
      toast.error(t("remind.network_error"));
    } finally {
      setRedeeming(false);
    }
  }

  async function handleApplyInviteCode(e: React.FormEvent) {
    e.preventDefault();
    if (!inviteCodeInput.trim()) { toast.error(t("dashboard.enter_invite_code")); return; }
    setApplyingCode(true);
    try {
      const res = await fetch("/api/user/apply-invite-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inviteCode: inviteCodeInput.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        const errMsg = data.error || t("dashboard.invite_code_invalid");
        if (data.code === "ALREADY_HAS_ACCESS") {
          setSubscriptionAccessDB(true);
          await updateSession({ refreshSubscription: true });
          setInviteCodeInput("");
          setTab("subscriptions");
          toast.success(t("dashboard.already_has_access"));
          return;
        }
        toast.error(errMsg);
        return;
      }
      toast.success(t("dashboard.invite_code_success"));
      setSubscriptionAccessDB(true);
      invalidateDashCache();
      await updateSession({ refreshSubscription: true });
      setInviteCodeInput("");
      setTab("subscriptions");
    } catch {
      toast.error(t("dashboard.op_failed_retry"));
    } finally {
      setApplyingCode(false);
    }
  }

  return {
    session, status, locale, t, siteSettings, paymentEnabled,
    tab, setTab,
    subFilter, setSubFilter,
    subscriptions, setSubscriptions,
    stamps,
    subscriptionAccessDB,
    subscriptionExpiresAt,
    loadingData, dashError,
    editingStamp, setEditingStamp,
    editingSubscription, setEditingSubscription,
    savingDaysBefore,
    cancelling,
    deletingStamp,
    showClaimGuide, setShowClaimGuide,
    showSubscribeGuide, setShowSubscribeGuide,
    balanceCents, setBalanceCents,
    membershipPlan,
    orders, setOrders,
    loadingOrders, setLoadingOrders,
    balanceTxs, setBalanceTxs,
    showBalanceTxs, setShowBalanceTxs,
    loadingBalanceTxs, setLoadingBalanceTxs,
    plans,
    loadingPlans,
    redeemCode, setRedeemCode,
    redeeming,
    contactMsg, setContactMsg,
    contactCategory, setContactCategory,
    contactSending, setContactSending,
    contactSent, setContactSent,
    subSearch, setSubSearch,
    emailChangeCode, setEmailChangeCode,
    sendingChangeCode,
    changeCodeCooldown, setChangeCodeCooldown,
    showDeleteConfirm, setShowDeleteConfirm,
    deleteConfirmEmail, setDeleteConfirmEmail,
    deletingAccount,
    inviteCodeInput, setInviteCodeInput,
    applyingCode,
    editingName, setEditingName,
    nameValue, setNameValue,
    savingName,
    editingEmail, setEditingEmail,
    emailValue, setEmailValue,
    savingEmail,
    showPwdSection, setShowPwdSection,
    currentPwd, setCurrentPwd,
    newPwd, setNewPwd,
    confirmPwd, setConfirmPwd,
    showCurrent, setShowCurrent,
    showNew, setShowNew,
    savingPwd,
    avatarColor,
    editingAvatar, setEditingAvatar,
    savingAvatar,
    searchStats,
    recentSearches,
    refreshData, retryLoad,
    cancelSubscription, saveDaysBefore, deleteStamp, exportSubscriptionsCSV,
    saveName, sendEmailChangeCode, saveEmail, deleteAccount, changePassword, saveAvatarColor,
    handleRedeemCode, handleApplyInviteCode,
  };
}
