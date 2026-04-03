import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { signOut } from "next-auth/react";
import {
  RiLoader4Line, RiUserLine, RiLogoutBoxLine, RiAlertLine,
  RiPencilLine, RiCheckLine, RiCloseLine, RiMailLine,
  RiEyeLine, RiEyeOffLine, RiPaletteLine, RiLockLine,
  RiDeleteBinLine,
} from "@remixicon/react";
import type { Subscription, Stamp, DashboardUser, TFunction } from "./types";
import { AVATAR_COLORS } from "./types";

interface StrengthResult { score: number; label: string; color: string; }

function getPwdStrength(pwd: string, labels: string[]): StrengthResult {
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

export type AccountTabProps = {
  user: DashboardUser;
  isAdminUser: boolean;
  avatarColor: string;
  editingAvatar: boolean;
  savingAvatar: boolean;
  editingName: boolean;
  nameValue: string;
  savingName: boolean;
  editingEmail: boolean;
  emailValue: string;
  savingEmail: boolean;
  showPwdSection: boolean;
  currentPwd: string;
  newPwd: string;
  confirmPwd: string;
  showCurrent: boolean;
  showNew: boolean;
  savingPwd: boolean;
  emailChangeCode: string;
  sendingChangeCode: boolean;
  changeCodeCooldown: number;
  showDeleteConfirm: boolean;
  deleteConfirmEmail: string;
  deletingAccount: boolean;
  contactMsg: string;
  contactCategory: string;
  contactSending: boolean;
  contactSent: boolean;
  subscriptions: Subscription[];
  stamps: Stamp[];
  t: TFunction;
  setEditingAvatar: (v: boolean | ((prev: boolean) => boolean)) => void;
  onSaveAvatarColor: (color: string) => void;
  setEditingName: (v: boolean) => void;
  setNameValue: (v: string) => void;
  onSaveName: () => void;
  setEditingEmail: (v: boolean) => void;
  setEmailValue: (v: string) => void;
  setEmailChangeCode: (v: string) => void;
  onSaveEmail: () => void;
  onSendEmailChangeCode: () => void;
  setChangeCodeCooldown: (v: number) => void;
  setShowPwdSection: (v: boolean | ((prev: boolean) => boolean)) => void;
  setCurrentPwd: (v: string) => void;
  setNewPwd: (v: string) => void;
  setConfirmPwd: (v: string) => void;
  setShowCurrent: (v: boolean | ((prev: boolean) => boolean)) => void;
  setShowNew: (v: boolean | ((prev: boolean) => boolean)) => void;
  onChangePassword: () => void;
  setContactMsg: (v: string) => void;
  setContactCategory: (v: string) => void;
  setContactSending: (v: boolean) => void;
  setContactSent: (v: boolean) => void;
  setShowDeleteConfirm: (v: boolean) => void;
  setDeleteConfirmEmail: (v: string) => void;
  onDeleteAccount: () => void;
};

export function AccountTab({
  user, isAdminUser, avatarColor, editingAvatar, savingAvatar,
  editingName, nameValue, savingName,
  editingEmail, emailValue, savingEmail,
  showPwdSection, currentPwd, newPwd, confirmPwd, showCurrent, showNew, savingPwd,
  emailChangeCode, sendingChangeCode, changeCodeCooldown,
  showDeleteConfirm, deleteConfirmEmail, deletingAccount,
  contactMsg, contactCategory, contactSending, contactSent,
  subscriptions, stamps, t,
  setEditingAvatar, onSaveAvatarColor,
  setEditingName, setNameValue, onSaveName,
  setEditingEmail, setEmailValue, setEmailChangeCode, onSaveEmail, onSendEmailChangeCode, setChangeCodeCooldown,
  setShowPwdSection, setCurrentPwd, setNewPwd, setConfirmPwd, setShowCurrent, setShowNew, onChangePassword,
  setContactMsg, setContactCategory, setContactSending, setContactSent,
  setShowDeleteConfirm, setDeleteConfirmEmail, onDeleteAccount,
}: AccountTabProps) {
  const ac = AVATAR_COLORS.find(c => c.key === avatarColor) || AVATAR_COLORS[0];
  const initial = (user.name || user.email || "U").charAt(0).toUpperCase();

  return (
    <motion.div key="account" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }} className="space-y-4">

      {/* Avatar card */}
      <div className="glass-panel border border-border rounded-2xl p-5 flex items-center gap-4">
        <div className="relative shrink-0">
          <div className={cn("w-16 h-16 rounded-2xl flex items-center justify-center text-2xl font-bold shadow-sm", ac.bg, ac.text)}>
            {initial}
          </div>
          <button
            onClick={() => setEditingAvatar(v => !v)}
            className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-background border border-border shadow flex items-center justify-center hover:bg-muted transition-colors"
          >
            <RiPaletteLine className="w-3 h-3 text-muted-foreground" />
          </button>
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-bold text-base truncate">{user.name || t("dashboard.nickname_not_set")}</p>
          <p className="text-xs text-muted-foreground truncate">{user.email}</p>
          {isAdminUser && (
            <span className="inline-block mt-1 text-[10px] px-2 py-0.5 rounded-full bg-gradient-to-r from-violet-500/20 to-indigo-500/20 text-violet-700 dark:text-violet-300 font-bold border border-violet-200/50 dark:border-violet-700/30 uppercase tracking-wider">
              {t("founder")}
            </span>
          )}
        </div>
      </div>

      {/* Color picker */}
      {editingAvatar && (
        <div className="glass-panel border border-border rounded-2xl p-4 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("dashboard.select_avatar_color")}</p>
          <div className="flex gap-2 flex-wrap">
            {AVATAR_COLORS.map(c => (
              <button
                key={c.key}
                onClick={() => onSaveAvatarColor(c.key)}
                disabled={savingAvatar}
                className={cn(
                  "w-9 h-9 rounded-xl font-bold text-xs transition-all",
                  c.bg, c.text,
                  avatarColor === c.key ? "ring-2 ring-offset-2 ring-primary scale-110" : "opacity-70 hover:opacity-100 hover:scale-105"
                )}
              >
                {savingAvatar && avatarColor === c.key ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mx-auto" /> : c.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Profile fields */}
      <div className="glass-panel border border-border rounded-2xl divide-y divide-border/50">

        {/* Name */}
        <div className="px-4 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 shrink-0">
            <RiUserLine className="w-3.5 h-3.5 text-muted-foreground" />
            <p className="text-xs text-muted-foreground">{t("dashboard.nickname_field")}</p>
          </div>
          {editingName ? (
            <div className="flex items-center gap-2 flex-1 justify-end">
              <Input
                value={nameValue}
                onChange={e => setNameValue(e.target.value)}
                maxLength={50}
                className="h-7 rounded-lg text-xs w-36"
                autoFocus
                onKeyDown={e => { if (e.key === "Enter") onSaveName(); if (e.key === "Escape") setEditingName(false); }}
              />
              <button onClick={onSaveName} disabled={savingName} className="p-1.5 rounded-lg hover:bg-muted text-emerald-600 transition-colors">
                {savingName ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiCheckLine className="w-3.5 h-3.5" />}
              </button>
              <button onClick={() => setEditingName(false)} className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground transition-colors">
                <RiCloseLine className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <p className="text-xs font-semibold">{user.name || t("dashboard.not_set")}</p>
              <button onClick={() => { setNameValue(user.name || ""); setEditingName(true); }}
                className="p-1 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                <RiPencilLine className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        {/* Email */}
        <div className="px-4 py-3 space-y-2">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 shrink-0">
              <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />
              <p className="text-xs text-muted-foreground">{t("dashboard.email_field")}</p>
            </div>
            <div className="flex items-center gap-2">
              <p className="text-xs font-semibold truncate max-w-[160px]">{user.email}</p>
              {!editingEmail && (
                <button onClick={() => { setEmailValue(user.email || ""); setEditingEmail(true); }}
                  className="p-1 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                  <RiPencilLine className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
          {editingEmail && (
            <div className="space-y-2 pt-1">
              <Input
                type="email"
                value={emailValue}
                onChange={e => { setEmailValue(e.target.value); setEmailChangeCode(""); }}
                placeholder={t("dashboard.new_email_placeholder")}
                className="h-8 rounded-xl text-xs"
                autoFocus
              />
              <div className="flex gap-2 items-center">
                <Input
                  type="text"
                  value={emailChangeCode}
                  onChange={e => setEmailChangeCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder={t("dashboard.code_placeholder")}
                  className="h-8 rounded-xl text-xs flex-1 font-mono tracking-widest"
                  maxLength={6}
                />
                <Button
                  size="sm"
                  variant="outline"
                  disabled={sendingChangeCode || changeCodeCooldown > 0 || !emailValue.trim()}
                  onClick={onSendEmailChangeCode}
                  className="h-8 text-xs rounded-lg shrink-0 whitespace-nowrap"
                >
                  {sendingChangeCode ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : changeCodeCooldown > 0 ? `${changeCodeCooldown}s` : t("dashboard.send_code")}
                </Button>
              </div>
              <p className="text-[10px] text-amber-600 dark:text-amber-400">{t("dashboard.email_change_warn")}</p>
              <div className="flex gap-2">
                <Button size="sm" onClick={onSaveEmail} disabled={savingEmail || !emailChangeCode.trim()} className="h-7 text-xs rounded-lg gap-1 flex-1">
                  {savingEmail ? <RiLoader4Line className="w-3 h-3 animate-spin" /> : <RiCheckLine className="w-3 h-3" />}
                  {t("dashboard.confirm_change")}
                </Button>
                <Button size="sm" variant="outline" onClick={() => { setEditingEmail(false); setEmailChangeCode(""); setChangeCodeCooldown(0); }} className="h-7 text-xs rounded-lg">{t("dashboard.cancel")}</Button>
              </div>
            </div>
          )}
        </div>

        {/* Stats */}
        {[
          { label: t("dashboard.domain_sub_count"), value: t("dashboard.active_count", { n: subscriptions.filter(s => s.active).length }) },
          { label: t("dashboard.brand_claim_count"), value: t("dashboard.brand_count", { n: stamps.length, v: stamps.filter(s => s.verified).length }) },
        ].map(row => (
          <div key={row.label} className="flex items-center justify-between px-4 py-3">
            <p className="text-xs text-muted-foreground">{row.label}</p>
            <p className="text-xs font-semibold">{row.value}</p>
          </div>
        ))}
      </div>

      {/* Change password */}
      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
        <button
          onClick={() => { setShowPwdSection(v => !v); setCurrentPwd(""); setNewPwd(""); setConfirmPwd(""); }}
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/40 transition-colors"
        >
          <div className="flex items-center gap-2">
            <RiLockLine className="w-3.5 h-3.5 text-muted-foreground" />
            <p className="text-xs font-semibold">{t("dashboard.change_password")}</p>
          </div>
          <RiPencilLine className="w-3.5 h-3.5 text-muted-foreground" />
        </button>
        {showPwdSection && (
          <div className="border-t border-border px-4 py-4 space-y-3">
            {(() => {
              const strengthLabels = [
                t("auth.register_strength_weak"),
                t("auth.register_strength_fair"),
                t("auth.register_strength_medium"),
                t("auth.register_strength_strong"),
                t("auth.register_strength_very_strong"),
              ];
              const strength = getPwdStrength(newPwd, strengthLabels);
              const fields = [
                { label: t("dashboard.current_password"), value: currentPwd, onChange: setCurrentPwd, show: showCurrent, toggle: () => setShowCurrent(v => !v) },
                { label: t("dashboard.new_password_min"), value: newPwd, onChange: setNewPwd, show: showNew, toggle: () => setShowNew(v => !v) },
                { label: t("dashboard.confirm_new_password"), value: confirmPwd, onChange: setConfirmPwd, show: showNew, toggle: () => {} },
              ];
              return fields.map((f, i) => (
                <div key={i} className="space-y-1">
                  <Label className="text-[11px] text-muted-foreground">{f.label}</Label>
                  <div className="relative">
                    <RiLockLine className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
                    <Input
                      type={f.show ? "text" : "password"}
                      value={f.value}
                      onChange={e => f.onChange(e.target.value)}
                      className="pl-8 pr-8 h-9 rounded-xl text-xs"
                    />
                    {i < 2 && (
                      <button type="button" onClick={f.toggle}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground transition-colors">
                        {f.show ? <RiEyeOffLine className="w-3.5 h-3.5" /> : <RiEyeLine className="w-3.5 h-3.5" />}
                      </button>
                    )}
                  </div>
                  {i === 1 && (
                    <AnimatePresence>
                      {newPwd && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          className="overflow-hidden"
                        >
                          <div className="pt-1 space-y-1">
                            <div className="flex gap-1">
                              {[1, 2, 3, 4, 5].map(n => (
                                <div
                                  key={n}
                                  className={cn(
                                    "h-1 flex-1 rounded-full transition-all duration-300",
                                    n <= strength.score ? strength.color : "bg-muted"
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
                  )}
                </div>
              ));
            })()}
            <div className="flex gap-2 pt-1">
              <Button onClick={onChangePassword} disabled={savingPwd} className="flex-1 h-9 rounded-xl text-xs gap-1.5">
                {savingPwd ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.changing")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.confirm_modify")}</>}
              </Button>
              <Button variant="outline" onClick={() => setShowPwdSection(false)} className="h-9 rounded-xl text-xs">{t("dashboard.cancel")}</Button>
            </div>
          </div>
        )}
      </div>

      {/* Contact support */}
      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
        <div className="px-4 pt-3 pb-2 border-b border-border/60 flex items-center gap-2">
          <RiMailLine className="w-3.5 h-3.5 text-muted-foreground" />
          <p className="text-xs font-semibold">{t("contact.title")}</p>
        </div>
        {contactSent ? (
          <div className="px-4 py-5 flex flex-col items-center gap-2 text-center">
            <RiCheckLine className="w-8 h-8 text-emerald-500" />
            <p className="text-xs font-semibold">{t("contact.sent_title")}</p>
            <button onClick={() => { setContactSent(false); setContactMsg(""); }} className="text-[10px] text-muted-foreground hover:text-foreground mt-1">{t("contact.resend")}</button>
          </div>
        ) : (
          <div className="px-4 py-3 space-y-2.5">
            <div className="grid grid-cols-2 gap-1.5">
              {([
                [t("contact.cat_payment"), "cat_payment"],
                [t("contact.cat_membership"), "cat_membership"],
                [t("contact.cat_feature"), "cat_feature"],
                [t("contact.cat_other"), "cat_other"],
              ] as [string, string][]).map(([label]) => (
                <button key={label} type="button" onClick={() => setContactCategory(label)}
                  className={cn("h-8 rounded-xl text-[11px] font-medium border transition-all",
                    contactCategory === label ? "bg-foreground text-background border-foreground" : "bg-muted/30 text-muted-foreground border-border hover:border-muted-foreground/40"
                  )}>
                  {label}
                </button>
              ))}
            </div>
            <textarea value={contactMsg} onChange={e => setContactMsg(e.target.value)} placeholder={t("contact.placeholder")} rows={3} maxLength={500}
              className="w-full text-sm rounded-xl border border-border bg-background px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-primary/30 transition-shadow placeholder:text-muted-foreground/40" />
            <div className="flex items-center justify-between gap-2">
              <p className="text-[10px] text-muted-foreground/60">{t("contact.char_count", { count: contactMsg.length })}</p>
              <Button size="sm" className="h-8 rounded-xl text-xs gap-1.5 shrink-0" disabled={!contactMsg.trim() || contactSending}
                onClick={async () => {
                  if (!contactMsg.trim()) return;
                  setContactSending(true);
                  try {
                    const r = await fetch("/api/user/contact", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ category: contactCategory, message: contactMsg }) });
                    if (!r.ok) { return; }
                    setContactSent(true);
                  } catch { } finally { setContactSending(false); }
                }}>
                {contactSending ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiMailLine className="w-3.5 h-3.5" />}
                {t("contact.send")}
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Danger zone */}
      <button onClick={() => signOut({ callbackUrl: "/" })}
        className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl border border-red-200/50 bg-red-50/40 dark:bg-red-950/20 text-red-600 dark:text-red-400 text-sm font-semibold hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors">
        <RiLogoutBoxLine className="w-4 h-4" />
        {t("sign_out")}
      </button>

      {/* Delete account */}
      {!showDeleteConfirm ? (
        <button
          onClick={() => { setShowDeleteConfirm(true); setDeleteConfirmEmail(""); }}
          className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-xl text-xs text-muted-foreground/60 hover:text-red-500 transition-colors"
        >
          <RiDeleteBinLine className="w-3.5 h-3.5" />
          {t("dashboard.delete_account")}
        </button>
      ) : (
        <div className="glass-panel border border-red-200/50 dark:border-red-800/40 rounded-2xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <RiAlertLine className="w-4 h-4 text-red-500 shrink-0" />
            <p className="text-xs font-semibold text-red-600 dark:text-red-400">{t("dashboard.confirm_delete_title")}</p>
          </div>
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            {t("dashboard.confirm_delete_prefix")}<span className="font-semibold text-red-500">{t("dashboard.confirm_delete_irreversible")}</span>{t("dashboard.confirm_delete_suffix")}
          </p>
          <Input
            type="email"
            value={deleteConfirmEmail}
            onChange={e => setDeleteConfirmEmail(e.target.value)}
            placeholder={user?.email || t("dashboard.confirm_delete_email_placeholder")}
            className="h-9 rounded-xl text-xs"
            autoComplete="off"
          />
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1 h-8 text-xs rounded-lg border-red-200 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30"
              disabled={deletingAccount || deleteConfirmEmail.toLowerCase().trim() !== user?.email?.toLowerCase()}
              onClick={onDeleteAccount}
            >
              {deletingAccount ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin mr-1" /> : <RiDeleteBinLine className="w-3.5 h-3.5 mr-1" />}
              {t("dashboard.confirm_delete_btn")}
            </Button>
            <Button variant="outline" size="sm" className="h-8 text-xs rounded-lg" onClick={() => { setShowDeleteConfirm(false); setDeleteConfirmEmail(""); }}>
              {t("dashboard.cancel")}
            </Button>
          </div>
        </div>
      )}
    </motion.div>
  );
}
