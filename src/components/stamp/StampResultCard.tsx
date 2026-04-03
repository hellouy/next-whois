import React from "react";
import {
  RiCheckLine,
  RiExternalLinkLine,
  RiDeleteBinLine,
  RiFileCopyLine,
  RiGlobalLine,
  RiShieldCheckLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useTranslation, TranslationKey } from "@/lib/i18n";
import { Button } from "@/components/ui/button";

type _ExtractStampKey<T extends string> = T extends `stamp.${infer K}` ? K : never;
type StampKey = _ExtractStampKey<TranslationKey>;

interface TagBadgeInlineProps {
  tagName: string;
  tagStyle: string;
  className?: string;
}

function TagBadgeInline({ tagName, tagStyle, className }: TagBadgeInlineProps) {
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-muted/60 text-foreground",
      className,
    )}>
      {tagName}
    </span>
  );
}

interface SubmitResult {
  id: string;
  txtRecord: string;
  txtValue: string;
}

interface StampResultCardProps {
  form: {
    tagName: string;
    tagStyle: string;
  };
  submitResult: SubmitResult | null;
  onGoBack: () => void;
  renderTagBadge: (tagName: string, tagStyle: string, live: boolean) => React.ReactNode;
}

export function StampResultCard({
  form,
  submitResult,
  onGoBack,
  renderTagBadge,
}: StampResultCardProps) {
  const { t } = useTranslation();
  const s = (key: StampKey, params?: Record<string, string | number>) =>
    t(`stamp.${key}` as TranslationKey, params);

  function copyText(text: string) {
    navigator.clipboard.writeText(text).then(() => toast.success(s("copied")));
  }

  return (
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
          {s("done_claim_body", {})}
        </p>
        <div className="inline-flex items-center justify-center py-3 px-5 rounded-xl bg-gradient-to-br from-violet-50/60 to-fuchsia-50/40 dark:from-violet-950/30 dark:to-fuchsia-950/20 border border-violet-200/40 dark:border-violet-800/30 mb-6">
          {renderTagBadge(form.tagName, form.tagStyle, true)}
        </div>
        <div className="space-y-2.5">
          <Button
            className="w-full gap-2 h-11 bg-violet-500 hover:bg-violet-600 text-white border-0 rounded-xl font-semibold"
            onClick={onGoBack}
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
                  onClick={() => copyText(submitResult.txtRecord)}
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
  );
}
