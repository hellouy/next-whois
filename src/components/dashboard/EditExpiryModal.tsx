import React from "react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { RiLoader4Line, RiCloseLine, RiCheckLine, RiCalendarLine } from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";
import type { Subscription } from "@/components/dashboard/types";

export function EditExpiryModal({ sub, onClose, onSaved }: {
  sub: Subscription;
  onClose: () => void;
  onSaved: (newDate: string) => void;
}) {
  const [dateValue, setDateValue] = React.useState(
    sub.expiration_date ? sub.expiration_date.slice(0, 10) : ""
  );
  const [saving, setSaving] = React.useState(false);
  const { t } = useTranslation();

  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  async function handleSave() {
    if (!dateValue) { toast.error(t("dashboard.date_required")); return; }
    setSaving(true);
    try {
      const res = await fetch(`/api/user/subscriptions?id=${sub.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expiration_date: dateValue }),
      });
      if (!res.ok) throw new Error((await res.json()).error);
      toast.success(t("dashboard.expiry_updated"));
      onSaved(new Date(dateValue).toISOString());
      onClose();
    } catch (e: any) {
      toast.error(e.message || t("dashboard.update_failed"));
    } finally {
      setSaving(false);
    }
  }

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
            <Label className="text-xs font-semibold">{t("dashboard.expiry_date")}</Label>
            <Input type="date" value={dateValue} onChange={e => setDateValue(e.target.value)} className="h-9 rounded-xl text-sm" />
          </div>
        </div>
        <div className="flex gap-2 px-6 py-4 border-t border-border/50 shrink-0">
          <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
          <Button onClick={handleSave} disabled={saving} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
            {saving ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiCheckLine className="w-3.5 h-3.5" />{t("dashboard.save")}</>}
          </Button>
        </div>
      </div>
    </div>,
    document.body
  );
}
