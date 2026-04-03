import React from "react";
import Link from "next/link";
import { RiVipCrownLine, RiCheckLine } from "@remixicon/react";
import { cn } from "@/lib/utils";

interface MemberBannerProps {
  isMember: boolean;
  isZh: boolean;
}

export function MemberBanner({ isMember, isZh }: MemberBannerProps) {
  const freeItems = isZh
    ? ["标签名最多 5 字", "仅「个人」标签样式", "8 种标准卡片配色", "无链接与介绍"]
    : ["Tag name: max 5 chars", "Only 'Personal' style", "8 standard card themes", "No link or description"];
  const memberItems = isZh
    ? ["标签名最多 20 字", "全部 8 种标签样式", "5 种动态特殊排版", "自定义链接与介绍"]
    : ["Tag name: up to 20 chars", "All 8 badge styles", "5 animated special layouts", "Custom link & description"];

  return (
    <div className={cn(
      "rounded-2xl border overflow-hidden text-[10px]",
      isMember ? "border-violet-200/60 dark:border-violet-800/40 bg-violet-50/60 dark:bg-violet-950/20"
        : "border-amber-200/60 dark:border-amber-800/40 bg-amber-50/40 dark:bg-amber-950/10"
    )}>
      <div className={cn(
        "flex items-center justify-between px-4 py-2.5 border-b",
        isMember ? "border-violet-200/40 dark:border-violet-800/30 bg-violet-100/50 dark:bg-violet-900/20"
          : "border-amber-200/40 dark:border-amber-800/30 bg-amber-100/30 dark:bg-amber-900/10"
      )}>
        <div className="flex items-center gap-1.5">
          <RiVipCrownLine className={cn("w-3.5 h-3.5", isMember ? "text-violet-500" : "text-amber-500")} />
          <span className={cn("font-bold tracking-wide text-[10.5px]", isMember ? "text-violet-700 dark:text-violet-300" : "text-amber-700 dark:text-amber-400")}>
            {isMember ? (isZh ? "会员已激活" : "Member Active") : (isZh ? "普通用户 · 部分功能受限" : "Free User · Limited Features")}
          </span>
        </div>
        {!isMember && (
          <Link href="/payment/checkout"
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full font-semibold text-white bg-gradient-to-r from-violet-600 to-fuchsia-500 hover:opacity-90 transition-opacity text-[9.5px]">
            <RiVipCrownLine className="w-2.5 h-2.5" />{isZh ? "立即升级" : "Upgrade"}
          </Link>
        )}
      </div>
      <div className="grid grid-cols-2 divide-x divide-border/40 dark:divide-border/20">
        <div className="px-3.5 py-2.5 space-y-1.5">
          <p className="font-bold text-muted-foreground/60 uppercase tracking-widest text-[8.5px] mb-1.5">{isZh ? "普通用户" : "Free"}</p>
          {freeItems.map((item, i) => (
            <div key={i} className="flex items-center gap-1.5 text-muted-foreground/60">
              <span className="w-3 h-3 rounded-full bg-muted/60 flex items-center justify-center shrink-0 text-[7px]">✕</span>
              {item}
            </div>
          ))}
        </div>
        <div className="px-3.5 py-2.5 space-y-1.5">
          <p className={cn("font-bold uppercase tracking-widest text-[8.5px] mb-1.5", isMember ? "text-violet-500" : "text-amber-500/70")}>{isZh ? "会员专属" : "Members"}</p>
          {memberItems.map((item, i) => (
            <div key={i} className={cn("flex items-center gap-1.5", isMember ? "text-violet-700 dark:text-violet-300" : "text-muted-foreground/50")}>
              <RiCheckLine className={cn("w-3 h-3 shrink-0", isMember ? "text-violet-500" : "text-amber-400/60")} />
              {item}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
