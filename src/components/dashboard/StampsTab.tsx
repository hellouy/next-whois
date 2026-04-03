import React from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  RiLoader4Line, RiShieldCheckLine, RiAlertLine,
  RiDeleteBinLine, RiPencilLine, RiExternalLinkLine,
  RiFlashlightLine, RiTimeLine, RiCheckLine,
} from "@remixicon/react";
import type { Stamp, TFunction } from "./types";
import { TAG_COLORS } from "./types";

function TagBadge({ style, name }: { style: string; name: string }) {
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold", TAG_COLORS[style] || TAG_COLORS.personal)}>
      {name}
    </span>
  );
}

export type StampsTabProps = {
  stamps: Stamp[];
  loadingData: boolean;
  dashError: boolean;
  deletingStamp: string | null;
  t: TFunction;
  onShowClaimGuide: () => void;
  onEditStamp: (stamp: Stamp) => void;
  onDeleteStamp: (id: string) => void;
  onRetryLoad: () => void;
};

export function StampsTab({
  stamps, loadingData, dashError, deletingStamp,
  t, onShowClaimGuide, onEditStamp, onDeleteStamp, onRetryLoad,
}: StampsTabProps) {
  return (
    <motion.div key="stamps" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }} className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-bold uppercase tracking-widest text-muted-foreground">{t("dashboard.stamps_section_title")}</p>
        <button
          onClick={onShowClaimGuide}
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          <RiShieldCheckLine className="w-3 h-3" />{t("dashboard.claim_new_domain")}
        </button>
      </div>
      {loadingData ? (
        <div className="flex justify-center py-8"><RiLoader4Line className="w-5 h-5 animate-spin text-muted-foreground" /></div>
      ) : dashError ? (
        <div className="flex flex-col items-center py-10 gap-3 text-center">
          <RiAlertLine className="w-7 h-7 text-destructive/60" />
          <p className="text-sm text-muted-foreground">{t("dashboard.load_failed")}</p>
          <Button size="sm" variant="outline" className="rounded-xl text-xs gap-1.5" onClick={onRetryLoad}>{t("dashboard.reload")}</Button>
        </div>
      ) : stamps.length === 0 ? (
        <div className="text-center py-12 space-y-4">
          <div className="w-14 h-14 rounded-2xl bg-violet-500/8 border border-dashed border-border flex items-center justify-center mx-auto">
            <RiShieldCheckLine className="w-7 h-7 text-muted-foreground/40" />
          </div>
          <div className="space-y-1.5">
            <p className="text-sm font-semibold">{t("dashboard.no_stamps")}</p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              {t("dashboard.no_stamps_desc")}
            </p>
          </div>
          <Button
            variant="default"
            size="sm"
            className="rounded-xl text-xs gap-1.5"
            onClick={onShowClaimGuide}
          >
            <RiShieldCheckLine className="w-3.5 h-3.5" />{t("dashboard.how_to_claim")}
          </Button>
        </div>
      ) : stamps.map(stamp => (
        <div key={stamp.id} className="glass-panel border border-border rounded-2xl p-4 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <p className="text-sm font-semibold">{stamp.domain}</p>
                <TagBadge style={stamp.tag_style} name={stamp.tag_name} />
                {stamp.verified
                  ? <span className="flex items-center gap-0.5 text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">
                      <RiCheckLine className="w-3 h-3" />{t("dashboard.verified")}
                    </span>
                  : <span className="flex items-center gap-0.5 text-[10px] text-amber-600 dark:text-amber-400 font-semibold">
                      <RiTimeLine className="w-3 h-3" />{t("dashboard.pending_verify")}
                    </span>
                }
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {t("dashboard.nickname_prefix")}{stamp.nickname}
                {stamp.link && <> · <a href={stamp.link} target="_blank" rel="noopener noreferrer" className="hover:underline">{stamp.link}</a></>}
              </p>
              {stamp.description && (
                <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{stamp.description}</p>
              )}
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              {!stamp.verified && (
                <Link href={`/stamp?domain=${stamp.domain}`}>
                  <button className="p-1.5 rounded-lg hover:bg-violet-50 dark:hover:bg-violet-950/30 text-muted-foreground hover:text-violet-500 transition-colors" title={t("dashboard.go_verify")}>
                    <RiFlashlightLine className="w-3.5 h-3.5" />
                  </button>
                </Link>
              )}
              <button onClick={() => onEditStamp(stamp)}
                className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                <RiPencilLine className="w-3.5 h-3.5" />
              </button>
              <Link href={`/${stamp.domain}`} className="p-1.5 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
                <RiExternalLinkLine className="w-3.5 h-3.5" />
              </Link>
              <button
                onClick={() => onDeleteStamp(stamp.id)}
                disabled={deletingStamp === stamp.id}
                title={t("dashboard.delete_stamp_title")}
                className="p-1.5 rounded-lg hover:bg-red-50 dark:hover:bg-red-950/30 text-muted-foreground hover:text-red-500 transition-colors">
                {deletingStamp === stamp.id
                  ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" />
                  : <RiDeleteBinLine className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
          {!stamp.verified && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-amber-50/50 dark:bg-amber-950/20 border border-amber-200/40">
              <RiAlertLine className="w-3.5 h-3.5 text-amber-500 shrink-0" />
              <p className="text-[11px] text-muted-foreground">{t("dashboard.stamp_unverified_hint")}</p>
            </div>
          )}
        </div>
      ))}
    </motion.div>
  );
}
