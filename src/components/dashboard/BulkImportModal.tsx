import React from "react";
import { createPortal } from "react-dom";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  RiLoader4Line, RiCloseLine, RiUploadCloud2Line, RiInformationLine,
} from "@remixicon/react";
import { useTranslation } from "@/lib/i18n";

export function BulkImportModal({ onClose, onImport }: {
  onClose: () => void;
  onImport: (domains: string) => Promise<{ ok: boolean; skipped?: number; truncated?: boolean; limit?: number; current?: number }>;
}) {
  const [value, setValue] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const { t } = useTranslation();

  React.useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = prev; };
  }, []);

  async function handleImport() {
    if (!value.trim()) { toast.error(t("dashboard.bulk_empty")); return; }
    setSubmitting(true);
    try {
      const res = await onImport(value);
      if (res.ok) onClose();
    } finally {
      setSubmitting(false);
    }
  }

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center"
      style={{ padding: "calc(var(--ann-h, 0px) + 4.5rem) 1rem 1rem" }}
    >
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div
        className="relative w-full max-w-md bg-background border border-border rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        style={{ maxHeight: "calc(100dvh - var(--ann-h, 0px) - 5.5rem)" }}
      >
        <div className="flex items-center justify-between px-6 pt-5 pb-4 shrink-0">
          <h2 className="text-base font-bold flex items-center gap-2">
            <RiUploadCloud2Line className="w-4 h-4 text-primary" />{t("dashboard.bulk_import_title")}
          </h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-muted transition-colors">
            <RiCloseLine className="w-5 h-5 text-muted-foreground" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto overscroll-contain px-6 pb-2 space-y-4" style={{ minHeight: 0 }}>
          <div className="flex items-start gap-2 rounded-xl bg-sky-50 dark:bg-sky-950/20 border border-sky-200/50 dark:border-sky-700/30 px-3 py-2.5">
            <RiInformationLine className="w-3.5 h-3.5 text-sky-500 shrink-0 mt-0.5" />
            <p className="text-[11px] text-sky-700 dark:text-sky-300 leading-relaxed">{t("dashboard.bulk_import_hint")}</p>
          </div>
          <textarea
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder={t("dashboard.bulk_import_placeholder")}
            rows={8}
            className="w-full rounded-xl border border-border bg-muted/30 text-xs font-mono p-3 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition resize-y"
          />
        </div>
        <div className="flex gap-2 px-6 py-4 border-t border-border/50 shrink-0">
          <Button onClick={onClose} variant="outline" className="flex-1 h-9 rounded-xl text-sm">{t("dashboard.cancel")}</Button>
          <Button onClick={handleImport} disabled={submitting || !value.trim()} className="flex-1 h-9 rounded-xl text-sm gap-1.5">
            {submitting ? <><RiLoader4Line className="w-3.5 h-3.5 animate-spin" />{t("dashboard.saving")}</> : <><RiUploadCloud2Line className="w-3.5 h-3.5" />{t("dashboard.bulk_import_confirm")}</>}
          </Button>
        </div>
      </div>
    </div>,
    document.body
  );
}
