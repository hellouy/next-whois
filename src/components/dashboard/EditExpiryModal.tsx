import React from "react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import {
  RiLoader4Line, RiCloseLine, RiCheckLine, RiCalendarLine,
  RiRefreshLine, RiShieldCheckLine, RiInformationLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import type { Subscription } from "@/components/dashboard/types";

type WhoisMeta = {
  expiry: string;
  registrar: string | null;
  creation_date: string | null;
  nameservers: string[];
};

export function EditExpiryModal({ sub, onClose, onSaved }: {
  sub: Subscription;
  onClose: () => void;
  onSaved: (update: { expiration_date: string; whois_synced_at?: string; registrar?: string | null; creation_date?: string | null; nameservers?: string[] }) => void;
}) {
  const [dateValue, setDateValue] = React.useState(
    sub.expiration_date ? sub.expiration_date.slice(0, 10) : ""
  );
  const [saving, setSaving] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [synced, setSynced] = React.useState<WhoisMeta | null>(null);
  const { t } = useTranslation();

  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  async function handleSyncWhois() {
    setSyncing(true);
    try {
      const res = await fetch(`/api/remind/whois?query=${encodeURIComponent(sub.domain)}`);
      const data = await res.json();
      const r = data?.result ?? data;
      const expiry = r?.expirationDate;
      if (!expiry || expiry === "Unknown" || expiry === "N/A") {
        toast.error(t("dashboard.no_expiry_whois"));
        return;
      }

      const d = new Date(expiry);
      if (isNaN(d.getTime())) { toast.error(t("dashboard.no_expiry_whois")); return; }
      const dateStr = d.toISOString().slice(0, 10);

      const clean = (v: unknown) => (v && v !== "Unknown" && v !== "N/A" ? String(v) : null);
      const registrar = clean(r.registrar);
      const creationRaw = clean(r.creationDate);
      const creation_date = (() => {
        if (!creationRaw) return null;
        const cd = new Date(creationRaw);
        return isNaN(cd.getTime()) ? null : cd.toISOString().slice(0, 10);
      })();
      const nameservers: string[] = Array.isArray(r.nameServers)
        ? r.nameServers.map((ns: unknown) => String(ns).toLowerCase().trim()).filter((ns: string) => ns && ns !== "unknown").slice(0, 6)
        : [];

      // Immediately persist all WHOIS data to the database
      const patchRes = await fetch(`/api/user/subscriptions?id=${sub.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ whois_sync: { expiry: dateStr, registrar, creation_date, nameservers } }),
      });
      if (!patchRes.ok) {
        const err = await patchRes.json();
        throw new Error(err.error || "保存失败");
      }
      const saved = await patchRes.json();

      setDateValue(dateStr);
      setSynced({ expiry: dateStr, registrar, creation_date, nameservers });
      toast.success(t("dashboard.sync_from_whois_ok"));

      // Immediately update parent state so dashboard reflects new WHOIS data
      onSaved({
        expiration_date: dateStr,
        whois_synced_at: saved.whois_synced_at ?? new Date().toISOString(),
        registrar,
        creation_date,
        nameservers,
      });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("dashboard.sync_failed"));
    } finally {
      setSyncing(false);
    }
  }

  async function handleSave() {
    if (!dateValue) { toast.error(t("dashboard.date_required")); return; }
    setSaving(true);
    try {
      const res = await fetch(`/api/user/subscriptions?id=${sub.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expiration_date: dateValue }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || t("dashboard.update_failed"));
      }
      toast.success(t("dashboard.expiry_updated"));
      onSaved({ expiration_date: new Date(dateValue).toISOString() });
      onClose();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("dashboard.update_failed"));
    } finally {
      setSaving(false);
    }
  }

  const fmt = (s: string) => new Date(s).toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center"
      style={{ padding: "calc(var(--ann-h, 0px) + 4.5rem) 1rem 1rem" }}
    >
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div
        className="relative w-full max-w-sm bg-background border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        style={{ maxHeight: "calc(100dvh - var(--ann-h, 0px) - 5.5rem)" }}
      >
        <div className="flex items-center justify-between px-6 pt-5 pb-4 shrink-0">
          <h2 className="text-base font-bold flex items-center gap-2">
            <RiCalendarLine className="w-4 h-4 text-primary" />{t("dashboard.edit_expiry_title")}
          </h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto overscroll-contain px-6 pb-2 space-y-4" style={{ minHeight: 0 }}>
          <p className="text-xs text-muted-foreground">{t("dashboard.domain_label")}<span className="font-mono text-foreground">{sub.domain}</span></p>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label className="text-xs font-semibold">{t("dashboard.expiry_date")}</Label>
              <button
                type="button"
                onClick={handleSyncWhois}
                disabled={syncing || saving}
                className="flex items-center gap-1 text-[11px] text-primary hover:underline disabled:opacity-50 disabled:no-underline transition-opacity"
              >
                {syncing
                  ? <RiLoader4Line className="w-3 h-3 animate-spin" />
                  : <RiRefreshLine className="w-3 h-3" />}
                {syncing ? t("dashboard.syncing_whois") : t("dashboard.sync_from_whois")}
              </button>
            </div>
            <Input type="date" value={dateValue} onChange={e => { setDateValue(e.target.value); setSynced(null); }} className="h-9 rounded-xl text-sm" />
          </div>

          {/* WHOIS metadata preview after successful sync */}
          {synced && (
            <div className="rounded-xl bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200/60 dark:border-emerald-700/30 px-3 py-2.5 space-y-1.5">
              <div className="flex items-center gap-1.5">
                <RiShieldCheckLine className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                <span className="text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">WHOIS 已同步并保存</span>
              </div>
              {synced.registrar && (
                <div className="flex items-center gap-1">
                  <RiInformationLine className="w-3 h-3 text-emerald-500 shrink-0" />
                  <span className="text-[10px] text-emerald-700 dark:text-emerald-400 truncate">注册商：{synced.registrar}</span>
                </div>
              )}
              {synced.creation_date && (
                <div className="flex items-center gap-1">
                  <RiCalendarLine className="w-3 h-3 text-emerald-500 shrink-0" />
                  <span className="text-[10px] text-emerald-700 dark:text-emerald-400">注册时间：{fmt(synced.creation_date)}</span>
                </div>
              )}
              {synced.nameservers.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {synced.nameservers.slice(0, 3).map((ns, i) => (
                    <span key={i} className="text-[9px] font-mono bg-emerald-100 dark:bg-emerald-900/30 rounded px-1.5 py-0.5 text-emerald-700 dark:text-emerald-400">{ns}</span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        <div className="flex gap-2 px-6 py-4 border-t border-border/50 shrink-0">
          <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
          <Button onClick={handleSave} disabled={saving || syncing} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
            {saving ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.save")}</>}
          </Button>
        </div>
      </div>
    </div>,
    document.body
  );
}
