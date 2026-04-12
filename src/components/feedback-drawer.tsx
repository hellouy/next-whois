import * as React from "react";
import {
  Drawer,
  DrawerContent,
  DrawerTitle,
} from "@/components/ui/drawer";
import { RiCloseLine, RiFlagLine, RiCheckLine, RiLoader4Line } from "@remixicon/react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { useTranslation } from "@/lib/i18n";

const ISSUE_KEYS = ["inaccurate", "incomplete", "outdated", "parse_error", "other"] as const;

type IssueKey = (typeof ISSUE_KEYS)[number];

interface Props {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  query: string;
  queryType: string;
}

export function FeedbackDrawer({ open, onOpenChange, query, queryType }: Props) {
  const { t } = useTranslation();
  const [selected, setSelected] = React.useState<Set<IssueKey>>(new Set());
  const [description, setDescription] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [done, setDone] = React.useState(false);
  const openedAtRef = React.useRef<number>(0);
  // Honeypot — use state, no DOM element (avoids iOS Vaul pointer-event crash)
  const [hp, setHp] = React.useState("");

  React.useEffect(() => {
    if (open) openedAtRef.current = Date.now();
  }, [open]);

  function reset() {
    setSelected(new Set());
    setDescription("");
    setEmail("");
    setHp("");
    setDone(false);
  }

  function handleClose() {
    onOpenChange(false);
    reset();
  }

  function toggle(key: IssueKey) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  async function submit() {
    if (selected.size === 0) {
      toast.warning(t("feedback.select_required"));
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query, queryType,
          issueTypes: Array.from(selected),
          description: description.trim(),
          email: email.trim(),
          _hp: hp,
          _t: openedAtRef.current,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        toast.error(data?.error || t("feedback.submit_failed"));
        return;
      }
      setDone(true);
    } catch {
      toast.error(t("feedback.submit_failed"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Drawer
      open={open}
      onOpenChange={(v) => {
        if (!v) handleClose();
        else onOpenChange(true);
      }}
    >
      <DrawerContent className="max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 pt-4 pb-2 shrink-0">
          <div className="min-w-0 flex-1">
            <DrawerTitle className="text-sm font-semibold flex items-center gap-1.5 min-w-0">
              <RiFlagLine className="w-3.5 h-3.5 text-amber-500 shrink-0" />
              <span className="truncate">
                {t("feedback.title")} <span className="font-mono text-muted-foreground font-normal">{query}</span>
              </span>
            </DrawerTitle>
            <p className="text-[11px] text-muted-foreground mt-0.5">{t("feedback.subtitle")}</p>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="ml-2 shrink-0 p-1.5 rounded-lg hover:bg-muted/50 transition-colors"
            aria-label={t("close")}
          >
            <RiCloseLine className="w-4 h-4 text-muted-foreground" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="overflow-y-auto px-4 pb-8 flex-1">
          {done ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <div className="w-12 h-12 rounded-full bg-emerald-100 dark:bg-emerald-950/40 flex items-center justify-center">
                <RiCheckLine className="w-6 h-6 text-emerald-600" />
              </div>
              <p className="text-sm font-semibold">{t("feedback.thanks_title")}</p>
              <p className="text-xs text-muted-foreground text-center max-w-xs">
                {t("feedback.thanks_desc")}
              </p>
              <button
                type="button"
                onClick={handleClose}
                className="mt-2 px-4 py-1.5 rounded-lg bg-muted text-sm font-medium hover:bg-muted/70 transition-colors"
              >
                {t("close")}
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Honeypot — pure state, no DOM input to avoid iOS pointer-event crash */}
              <input
                type="text"
                name="website"
                value={hp}
                onChange={(e) => setHp(e.target.value)}
                autoComplete="off"
                tabIndex={-1}
                aria-hidden="true"
                style={{ display: "none" }}
              />

              <div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/40 rounded-xl px-3 py-2.5">
                <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-0.5 bg-background shrink-0">
                  {queryType}
                </span>
                <span className="font-mono font-medium text-foreground truncate">{query}</span>
              </div>

              {/* Issue type grid — 2 columns to prevent mobile overflow */}
              <div>
                <p className="text-xs font-semibold text-muted-foreground mb-2">{t("feedback.issue_type")}</p>
                <div className="grid grid-cols-2 gap-2">
                  {ISSUE_KEYS.map((key) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => toggle(key)}
                      className={cn(
                        "py-2.5 px-3 rounded-xl text-xs font-semibold border transition-all active:scale-95",
                        selected.has(key)
                          ? "bg-primary text-primary-foreground border-primary"
                          : "bg-muted/40 border-border text-foreground hover:border-primary/50"
                      )}
                    >
                      {t(`feedback.${key}` as any)}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value.slice(0, 500))}
                  placeholder={t("feedback.description_placeholder")}
                  rows={3}
                  className="w-full text-sm rounded-xl border border-border bg-muted/30 px-3 py-2.5 resize-none placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/50 transition-colors"
                />
                <p className="text-[10px] text-muted-foreground text-right mt-0.5">{description.length}/500</p>
              </div>

              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={t("feedback.email_placeholder")}
                className="w-full text-sm rounded-xl border border-border bg-muted/30 px-3 py-2.5 placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/50 transition-colors"
              />

              <button
                type="button"
                onClick={submit}
                disabled={submitting || selected.size === 0}
                className="w-full py-3 rounded-xl bg-primary text-primary-foreground text-sm font-semibold flex items-center justify-center gap-2 transition-opacity disabled:opacity-50 active:scale-[0.98]"
              >
                {submitting ? <RiLoader4Line className="w-4 h-4 animate-spin" /> : null}
                {t("feedback.submit")}
              </button>
            </div>
          )}
        </div>
      </DrawerContent>
    </Drawer>
  );
}

export default FeedbackDrawer;
