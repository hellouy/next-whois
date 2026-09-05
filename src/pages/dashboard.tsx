import React from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { signOut } from "next-auth/react";
import { cn } from "@/lib/utils";
import { AnimatePresence, motion } from "framer-motion";
import {
  RiLoader4Line, RiCalendarLine, RiShieldCheckLine,
  RiUserLine, RiLogoutBoxLine, RiFireLine,
  RiVipCrownLine, RiShieldUserLine, RiSearchLine, RiHistoryLine,
  RiExternalLinkLine,
} from "@remixicon/react";
import { useSiteSettings } from "@/lib/site-settings";
import { SubscriptionsTab } from "@/components/dashboard/SubscriptionsTab";
import { StampsTab } from "@/components/dashboard/StampsTab";
import { MembershipTab } from "@/components/dashboard/MembershipTab";
import { AccountTab } from "@/components/dashboard/AccountTab";
import type { DashboardUser } from "@/components/dashboard/types";
import { EditStampModal } from "@/components/dashboard/EditStampModal";
import { EditExpiryModal } from "@/components/dashboard/EditExpiryModal";
import { BulkImportModal } from "@/components/dashboard/BulkImportModal";
import { ClaimGuideModal, SubscribeGuideModal } from "@/components/dashboard/GuideModals";
import { invalidateDashCache } from "@/lib/dashboard-cache";
import { useDashboard } from "@/hooks/useDashboard";

export default function DashboardPage() {
  const router = useRouter();
  const siteSettings = useSiteSettings();
  const {
    session, status, locale, t, paymentEnabled,
    tab, setTab,
    subFilter, setSubFilter,
    subscriptions, setSubscriptions,
    stamps,
    subscriptionAccessDB,
    subscriptionExpiresAt,
    loadingData, dashError,
    editingStamp, setEditingStamp,
    editingSubscription, setEditingSubscription,
    cancelling,
    togglingPause,
    showBulkImport, setShowBulkImport,
    bulkImporting,
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
    cancelSubscription, togglePauseSubscription, bulkImport, deleteStamp, exportSubscriptionsCSV,
    saveName, sendEmailChangeCode, saveEmail, deleteAccount, changePassword, saveAvatarColor,
    handleRedeemCode, handleApplyInviteCode,
  } = useDashboard();

  if (status === "unauthenticated" || status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const user = session!.user! as DashboardUser;
  const isAdminUser = (session?.user as any)?.isAdmin === true;

  const activeSubs = subscriptions.filter(s => s.active);
  const expiringSoon = activeSubs.filter(s => {
    const d = s.days_to_expiry;
    return d !== null && d >= 0 && d <= 30;
  });
  const urgentSubs = activeSubs.filter(s => {
    const d = s.days_to_expiry;
    const dd = s.days_to_drop;
    return (d !== null && d >= 0 && d <= 7) || (dd !== null && dd >= 0 && dd <= 7);
  });
  const postExpirySubs = activeSubs.filter(s => s.phase && s.phase !== "active");
  const verifiedStamps = stamps.filter(s => s.verified);

  const TABS = [
    { key: "subscriptions" as const, label: t("dashboard.tab_subscriptions"), icon: <RiCalendarLine className="w-3.5 h-3.5" />, count: activeSubs.length || undefined },
    { key: "stamps" as const, label: t("dashboard.tab_stamps"), icon: <RiShieldCheckLine className="w-3.5 h-3.5" />, count: stamps.length || undefined },
    { key: "membership" as const, label: t("dashboard.tab_membership"), icon: <RiVipCrownLine className="w-3.5 h-3.5" /> },
    { key: "account" as const, label: t("dashboard.tab_account"), icon: <RiUserLine className="w-3.5 h-3.5" /> },
  ];

  const filteredSubscriptions = [...subscriptions]
    .filter(s => {
      if (subSearch.trim() && !s.domain.toLowerCase().includes(subSearch.trim().toLowerCase())) return false;
      if (subFilter === "all") return true;
      const d = s.days_to_expiry;
      const dd = s.days_to_drop;
      if (subFilter === "urgent") return s.active && ((d !== null && d >= 0 && d <= 7) || (dd !== null && dd >= 0 && dd <= 7));
      if (subFilter === "expiring") return s.active && d !== null && d >= 0 && d <= 30;
      if (subFilter === "expired") return !!(s.active && s.phase && s.phase !== "active");
      return true;
    })
    .sort((a, b) => {
      if (!a.active && b.active) return 1;
      if (a.active && !b.active) return -1;
      const da = a.days_to_expiry ?? 9999;
      const db = b.days_to_expiry ?? 9999;
      if (da !== db) return da - db;
      return a.domain.localeCompare(b.domain);
    });

  return (
    <>
      <Head><title key="title">{`${t("nav_dashboard")} · ${siteSettings.site_logo_text || "WHOIS"}`}</title></Head>

      {showClaimGuide && <ClaimGuideModal onClose={() => setShowClaimGuide(false)} />}
      {showSubscribeGuide && <SubscribeGuideModal onClose={() => setShowSubscribeGuide(false)} />}
      {showBulkImport && (
        <BulkImportModal onClose={() => setShowBulkImport(false)} onImport={bulkImport} />
      )}
      {editingStamp && (
        <EditStampModal stamp={editingStamp} onClose={() => setEditingStamp(null)} onSaved={refreshData} isMember={!!subscriptionAccessDB} />
      )}
      {editingSubscription && (
        <EditExpiryModal
          sub={editingSubscription}
          onClose={() => setEditingSubscription(null)}
          onSaved={(update) => {
            setSubscriptions(prev => prev.map(s =>
              s.id === editingSubscription.id ? { ...s, ...update } : s
            ));
            invalidateDashCache();
          }}
        />
      )}

      <div className="max-w-2xl mx-auto px-4 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              {t("nav_dashboard")}
              {isAdminUser && (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-gradient-to-r from-violet-500/20 to-indigo-500/20 text-violet-700 dark:text-violet-300 font-bold border border-violet-200/50 dark:border-violet-700/30 uppercase tracking-wider">
                  {t("founder")}
                </span>
              )}
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">{user.email}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => router.push("/")}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-primary hover:bg-primary/5 transition-colors px-3 py-1.5 rounded-lg font-medium active:opacity-70 touch-manipulation">
              <RiSearchLine className="w-3.5 h-3.5" />
              <span>{t("not_found.back_home")}</span>
            </button>
            {isAdminUser && (
              <Link href="/admin"
                className="flex items-center gap-1.5 text-xs text-violet-600 dark:text-violet-400 hover:bg-violet-50 dark:hover:bg-violet-950/30 transition-colors px-3 py-1.5 rounded-lg font-semibold active:scale-[0.96]">
                <RiShieldUserLine className="w-3.5 h-3.5" />
                {t("nav_admin")}
              </Link>
            )}
            <button onClick={() => signOut({ callbackUrl: "/" })}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors px-3 py-1.5 rounded-lg hover:bg-muted active:scale-[0.96]">
              <RiLogoutBoxLine className="w-3.5 h-3.5" />
              {t("sign_out")}
            </button>
          </div>
        </div>

        {/* Stats overview bar */}
        {!loadingData && (activeSubs.length > 0 || stamps.length > 0 || !!searchStats) && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <button
              type="button"
              onClick={() => { setTab("subscriptions"); setSubFilter("all"); }}
              className="glass-panel border border-border rounded-xl px-3 py-2.5 flex items-center gap-2.5 text-left hover:border-primary/40 hover:bg-primary/5 transition-colors"
            >
              <div className="w-7 h-7 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                <RiCalendarLine className="w-3.5 h-3.5 text-primary" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{activeSubs.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_active_subs")}</p>
              </div>
            </button>
            <button
              type="button"
              onClick={() => { setTab("subscriptions"); setSubFilter(urgentSubs.length > 0 ? "urgent" : "expiring"); }}
              className={cn(
                "glass-panel border rounded-xl px-3 py-2.5 flex items-center gap-2.5 text-left transition-colors",
                urgentSubs.length > 0 ? "border-red-300/60 bg-red-50/40 dark:bg-red-950/20 hover:bg-red-100/40 dark:hover:bg-red-950/30" :
                expiringSoon.length > 0 ? "border-amber-300/60 bg-amber-50/40 dark:bg-amber-950/20 hover:bg-amber-100/40 dark:hover:bg-amber-950/30" : "border-border hover:border-primary/40 hover:bg-primary/5"
              )}
            >
              <div className={cn("w-7 h-7 rounded-lg flex items-center justify-center shrink-0",
                urgentSubs.length > 0 ? "bg-red-100 dark:bg-red-950/40" :
                expiringSoon.length > 0 ? "bg-amber-100 dark:bg-amber-950/40" : "bg-muted"
              )}>
                <RiFireLine className={cn("w-3.5 h-3.5",
                  urgentSubs.length > 0 ? "text-red-500" :
                  expiringSoon.length > 0 ? "text-amber-500" : "text-muted-foreground"
                )} />
              </div>
              <div>
                <p className={cn("text-base font-bold leading-none",
                  urgentSubs.length > 0 ? "text-red-600 dark:text-red-400" :
                  expiringSoon.length > 0 ? "text-amber-600 dark:text-amber-400" : ""
                )}>{expiringSoon.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_expiring_30")}</p>
              </div>
            </button>
            <button
              type="button"
              onClick={() => setTab("stamps")}
              className="glass-panel border border-border rounded-xl px-3 py-2.5 flex items-center gap-2.5 text-left hover:border-emerald-400/40 hover:bg-emerald-50/20 dark:hover:bg-emerald-950/10 transition-colors"
            >
              <div className="w-7 h-7 rounded-lg bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center shrink-0">
                <RiShieldCheckLine className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{verifiedStamps.length}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_verified_brands")}</p>
              </div>
            </button>
            <button
              type="button"
              onClick={() => setTab("account")}
              className="glass-panel border border-border rounded-xl px-3 py-2.5 flex items-center gap-2.5 text-left hover:border-sky-400/40 hover:bg-sky-50/20 dark:hover:bg-sky-950/10 transition-colors"
            >
              <div className="w-7 h-7 rounded-lg bg-sky-100 dark:bg-sky-950/40 flex items-center justify-center shrink-0">
                <RiSearchLine className="w-3.5 h-3.5 text-sky-500" />
              </div>
              <div>
                <p className="text-base font-bold leading-none">{searchStats?.total ?? 0}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{t("dashboard.stat_history")}</p>
              </div>
            </button>
          </div>
        )}

        {/* Recent searches mini-list */}
        {!loadingData && recentSearches.length > 0 && (
          <div className="glass-panel border border-border rounded-xl p-3">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-[11px] font-bold flex items-center gap-1.5 text-muted-foreground">
                <RiHistoryLine className="w-3.5 h-3.5" />{t("recent_searches")}
              </h3>
              <Link href="/" className="text-[11px] text-primary hover:underline flex items-center gap-0.5">
                {t("search")}<RiExternalLinkLine className="w-3 h-3" />
              </Link>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {recentSearches.map((s, i) => (
                <Link
                  key={i}
                  href={`/${encodeURIComponent(s.query)}`}
                  className={cn(
                    "flex items-center gap-1 text-[11px] font-mono px-2 py-1 rounded-lg border transition-all hover:border-primary/40 hover:bg-primary/5 active:scale-[0.96]",
                    s.reg_status === "registered" ? "border-emerald-200/60 dark:border-emerald-700/30 bg-emerald-50/40 dark:bg-emerald-950/10" :
                    s.reg_status === "unregistered" ? "border-blue-200/60 dark:border-blue-700/30 bg-blue-50/40 dark:bg-blue-950/10" :
                    "border-border bg-muted/30"
                  )}
                >
                  <span className="font-semibold text-foreground">{s.query}</span>
                  {s.reg_status === "registered" && <span className="text-[9px] text-emerald-600 dark:text-emerald-400">{t("dashboard.reg_registered")}</span>}
                  {s.reg_status === "unregistered" && <span className="text-[9px] text-blue-500">{t("dashboard.reg_available")}</span>}
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Tab switcher */}
        <div className="flex rounded-xl bg-muted/40 border border-border/50 p-1 gap-1">
          {TABS.map(tabItem => (
            <button key={tabItem.key} type="button" onClick={() => setTab(tabItem.key)}
              className={cn(
                "relative flex-1 flex items-center justify-center gap-1.5 py-2 px-1 rounded-lg text-xs font-semibold transition-colors duration-150",
                tab === tabItem.key ? "text-foreground" : "text-muted-foreground hover:text-foreground"
              )}>
              {tab === tabItem.key && (
                <motion.div
                  layoutId="dashTabActive"
                  className="absolute inset-0 bg-background shadow-sm border border-border/60 rounded-lg"
                  transition={{ type: "spring", stiffness: 450, damping: 38 }}
                />
              )}
              <span className="relative z-10 flex items-center gap-1.5">
                {tabItem.icon}
                <span className="hidden sm:inline">{tabItem.label}</span>
                {tabItem.count !== undefined && (
                  <span className={cn(
                    "text-[10px] font-bold px-1 py-0 rounded-full min-w-[16px] text-center leading-4",
                    tab === tabItem.key ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
                  )}>{tabItem.count}</span>
                )}
              </span>
            </button>
          ))}
        </div>

        <AnimatePresence mode="wait">
          {tab === "subscriptions" && (
            <SubscriptionsTab
              subscriptionAccessDB={subscriptionAccessDB}
              freeLimit={subscriptionAccessDB ? null : 5}
              subscriptions={subscriptions}
              filteredSubscriptions={filteredSubscriptions}
              loadingData={loadingData}
              dashError={dashError}
              subSearch={subSearch}
              subFilter={subFilter}
              subscriptionExpiresAt={subscriptionExpiresAt}
              activeSubs={activeSubs}
              expiringSoon={expiringSoon}
              urgentSubs={urgentSubs}
              postExpirySubs={postExpirySubs}
              cancelling={cancelling}
              inviteCodeInput={inviteCodeInput}
              applyingCode={applyingCode}
              paymentEnabled={paymentEnabled}
              user={user}
              locale={locale}
              t={t}
              setSubSearch={setSubSearch}
              setSubFilter={setSubFilter}
              onShowSubscribeGuide={() => setShowSubscribeGuide(true)}
              onExportCSV={exportSubscriptionsCSV}
              onCancelSubscription={cancelSubscription}
              onEditSubscription={setEditingSubscription}
              onTogglePause={togglePauseSubscription}
              onShowBulkImport={() => setShowBulkImport(true)}
              togglingPause={togglingPause}
              bulkImporting={bulkImporting}
              onApplyInviteCode={handleApplyInviteCode}
              setInviteCodeInput={setInviteCodeInput}
              onRetryLoad={retryLoad}
            />
          )}

          {tab === "stamps" && (
            <StampsTab
              stamps={stamps}
              loadingData={loadingData}
              dashError={dashError}
              deletingStamp={deletingStamp}
              t={t}
              onShowClaimGuide={() => setShowClaimGuide(true)}
              onEditStamp={setEditingStamp}
              onDeleteStamp={deleteStamp}
              onRetryLoad={retryLoad}
            />
          )}

          {tab === "membership" && (
            <MembershipTab
              subscriptionAccessDB={subscriptionAccessDB}
              subscriptionExpiresAt={subscriptionExpiresAt}
              loadingData={loadingData}
              balanceCents={balanceCents}
              membershipPlan={membershipPlan}
              orders={orders}
              loadingOrders={loadingOrders}
              balanceTxs={balanceTxs}
              showBalanceTxs={showBalanceTxs}
              loadingBalanceTxs={loadingBalanceTxs}
              plans={plans}
              loadingPlans={loadingPlans}
              redeemCode={redeemCode}
              redeeming={redeeming}
              paymentEnabled={paymentEnabled}
              siteSettings={siteSettings}
              t={t}
              setShowBalanceTxs={setShowBalanceTxs}
              setLoadingBalanceTxs={setLoadingBalanceTxs}
              setBalanceTxs={setBalanceTxs}
              setBalanceCents={setBalanceCents}
              setOrders={setOrders}
              setLoadingOrders={setLoadingOrders}
              onRedeemCode={handleRedeemCode}
              setRedeemCode={setRedeemCode}
            />
          )}

          {tab === "account" && (
            <AccountTab
              user={user}
              isAdminUser={isAdminUser}
              avatarColor={avatarColor}
              editingAvatar={editingAvatar}
              savingAvatar={savingAvatar}
              editingName={editingName}
              nameValue={nameValue}
              savingName={savingName}
              editingEmail={editingEmail}
              emailValue={emailValue}
              savingEmail={savingEmail}
              showPwdSection={showPwdSection}
              currentPwd={currentPwd}
              newPwd={newPwd}
              confirmPwd={confirmPwd}
              showCurrent={showCurrent}
              showNew={showNew}
              savingPwd={savingPwd}
              emailChangeCode={emailChangeCode}
              sendingChangeCode={sendingChangeCode}
              changeCodeCooldown={changeCodeCooldown}
              showDeleteConfirm={showDeleteConfirm}
              deleteConfirmEmail={deleteConfirmEmail}
              deletingAccount={deletingAccount}
              contactMsg={contactMsg}
              contactCategory={contactCategory}
              contactSending={contactSending}
              contactSent={contactSent}
              subscriptions={subscriptions}
              stamps={stamps}
              searchStats={searchStats ?? null}
              t={t}
              setEditingAvatar={setEditingAvatar}
              onSaveAvatarColor={saveAvatarColor}
              setEditingName={setEditingName}
              setNameValue={setNameValue}
              onSaveName={saveName}
              setEditingEmail={setEditingEmail}
              setEmailValue={setEmailValue}
              setEmailChangeCode={setEmailChangeCode}
              onSaveEmail={saveEmail}
              onSendEmailChangeCode={sendEmailChangeCode}
              setChangeCodeCooldown={setChangeCodeCooldown}
              setShowPwdSection={setShowPwdSection}
              setCurrentPwd={setCurrentPwd}
              setNewPwd={setNewPwd}
              setConfirmPwd={setConfirmPwd}
              setShowCurrent={setShowCurrent}
              setShowNew={setShowNew}
              onChangePassword={changePassword}
              setContactMsg={setContactMsg}
              setContactCategory={setContactCategory}
              setContactSending={setContactSending}
              setContactSent={setContactSent}
              setShowDeleteConfirm={setShowDeleteConfirm}
              setDeleteConfirmEmail={setDeleteConfirmEmail}
              onDeleteAccount={deleteAccount}
            />
          )}
        </AnimatePresence>
      </div>
    </>
  );
}
