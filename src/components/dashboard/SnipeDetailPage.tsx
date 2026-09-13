import React from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  RiArrowLeftSLine, RiLoader4Line, RiWalletLine, RiArrowRightSLine,
  RiShieldCheckLine, RiTimeLine, RiCheckLine, RiCloseCircleLine,
  RiExternalLinkLine, RiVipCrownLine, RiArrowDownSLine, RiArrowUpSLine,
  RiScanLine, RiErrorWarningLine,
} from "@remixicon/react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { SNIPE_BALANCE_SYM, getSnipeStatusMeta } from "./snipe-status";

export type SnipeTargetDetail = {
  id: string;
  domain: string;
  tld: string;
  status: string;
  serviceCents: number | null;
  frozenCents: number;
  failReason: string | null;
  notes: string | null;
  dropEta: string | null;
  huntStart: string | null;
  huntEnd: string | null;
  registeredAt: string | null;
  createdAt: string;
  updatedAt: string;
  hasSubscription: boolean;
  linkedReminderId?: string | null;
};

export type SnipeDetailPageProps = {
  domain: string;
  target: SnipeTargetDetail | null;
  balanceCents: number;
  loading: boolean;
  notFound: boolean;
  onEnable: () => void;
  onDisable: () => void;
};

const FLOW_STEPS = [
  { key: "book", label: "预定", desc: "勾选抢注预定了这个域名" },
  { key: "freeze", label: "冻结", desc: "冻结服务费锁定抢占资格" },
  { key: "race", label: "竞速", desc: "到期自动发起注册抢占" },
  { key: "done", label: "成功 / 解冻", desc: "扣费注册或失败全额解冻" },
];

function stepStateFor(status: string, index: number): "done" | "current" | "todo" {
  const map: Record<string, number> = {
    watching: 0,
    blocked_balance: 0,
    armed: 1,
    sniping: 2,
    succeeded: 3,
    failed: 3,
    cancelled: 0,
    paused: 0,
  };
  const reached = map[status] ?? 0;
  if (index < reached) return "done";
  if (index === reached) {
    if (status === "failed" || status === "cancelled") return "todo";
    if (status === "succeeded") return "done";
    return "current";
  }
  return "todo";
}

export function SnipeFlowSteps({ status }: { status: string }) {
  const currentIndex = FLOW_STEPS.findIndex(step => stepStateFor(status, FLOW_STEPS.indexOf(step)) === "current");
  return (
    <div className="grid grid-cols-4 gap-1">
      {FLOW_STEPS.map((step, i) => {
        const state = stepStateFor(status, i);
        const isCurrent = state === "current";
        const isDone = state === "done";
        return (
          <div key={step.key} className={cn(
            "flex flex-col items-center text-center gap-1 rounded-xl py-2 px-1 transition-colors",
            isCurrent ? "bg-primary/10 ring-1 ring-primary/30" :
            isDone ? "bg-emerald-50 dark:bg-emerald-950/20" :
            "bg-muted/30"
          )}>
            <div className={cn(
              "w-6 h-6 rounded-full flex items-center justify-center shrink-0",
              isDone ? "bg-emerald-500 text-white" :
              isCurrent ? "bg-primary text-primary-foreground" :
              "bg-muted text-muted-foreground"
            )}>
              {isDone ? <RiCheckLine className="w-3 h-3" /> : <span className="text-[10px] font-bold">{i + 1}</span>}
            </div>
            <span className={cn(
              "text-[10px] font-semibold",
              isCurrent ? "text-primary" : isDone ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground"
            )}>{step.label}</span>
            <span className="text-[8px] leading-tight text-muted-foreground/70 hidden sm:block">{step.desc}</span>
          </div>
        );
      })}
    </div>
  );
}

export function SnipeDetailPage({
  domain, target, balanceCents, loading, notFound, onEnable, onDisable,
}: SnipeDetailPageProps) {
  const router = useRouter();
  const [showDisableConfirm, setShowDisableConfirm] = React.useState(false);
  const [showRules, setShowRules] = React.useState(false);
  const [activating, setActivating] = React.useState(false);

  const handleEnable = async () => {
    setActivating(true);
    try {
      await onEnable();
    } finally {
      setActivating(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-3">
        <div className="h-8 w-1/3 rounded-lg bg-muted/40 animate-pulse" />
        <div className="h-24 rounded-2xl bg-muted/30 animate-pulse" />
        <div className="h-32 rounded-2xl bg-muted/30 animate-pulse" />
      </div>
    );
  }

  if (notFound || !target) {
    return (
      <div className="glass-panel border border-border rounded-2xl p-8 text-center space-y-3 max-w-lg mx-auto">
        <RiCloseCircleLine className="w-10 h-10 text-muted-foreground/40 mx-auto" />
        <p className="text-sm font-bold">尚未预定抢注这个域名</p>
        <p className="text-xs text-muted-foreground">启用抢注后，域名到期释放的瞬间系统将自动为你发起注册抢占。</p>
        <div className="flex items-center justify-center gap-2 pt-1">
          <Button variant="outline" size="sm" onClick={() => router.push("/dashboard?tab=subscriptions")} className="h-9 rounded-xl text-xs">
            <RiArrowLeftSLine className="w-3.5 h-3.5" />返回抢注中心
          </Button>
          <Button size="sm" onClick={handleEnable} disabled={activating} className="h-9 rounded-xl text-xs gap-1.5">
            {activating ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiShieldCheckLine className="w-3.5 h-3.5" />}
            启用抢注
          </Button>
        </div>
      </div>
    );
  }

  const meta = getSnipeStatusMeta(target.status);
  const shortfall = Math.max(0, (target.serviceCents ?? 0) - target.frozenCents);
  const isBlocked = target.status === "blocked_balance";

  return (
    <div className="max-w-lg mx-auto space-y-3">
      {/* Back bar */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => router.push("/dashboard?tab=subscriptions")}
          className="flex items-center gap-0.5 text-[11px] text-muted-foreground hover:text-foreground px-2 py-1.5 rounded-lg hover:bg-muted transition-colors min-h-[32px]"
        >
          <RiArrowLeftSLine className="w-4 h-4" />返回抢注中心
        </button>
      </div>

      {/* Header card */}
      <div className="glass-panel border border-border rounded-2xl p-4 space-y-2">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-violet-100 dark:bg-violet-950/40 flex items-center justify-center shrink-0">
            <RiScanLine className="w-4.5 h-4.5 text-violet-600 dark:text-violet-400" />
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="text-base font-bold truncate">{target.domain}</h1>
            <p className="text-[10px] text-muted-foreground">预定于 {new Date(target.createdAt).toLocaleDateString()}</p>
          </div>
          <span className={cn("text-[10px] px-2 py-1 rounded-full flex items-center gap-1 font-semibold border", meta.cls)}>
            <span className={cn("w-1.5 h-1.5 rounded-full", meta.dot)} />
            {meta.label}
          </span>
        </div>

        {target.hasSubscription && (
          <Link href="/dashboard?tab=subscriptions" className="flex items-center gap-1.5 text-[11px] text-sky-600 dark:text-sky-400 hover:underline">
            <RiVipCrownLine className="w-3 h-3" />已关联到期提醒订阅，可前往管理
            <RiExternalLinkLine className="w-3 h-3" />
          </Link>
        )}
      </div>

      {/* Flow steps */}
      <div className="glass-panel border border-border rounded-2xl p-3">
        <p className="text-[11px] font-bold text-muted-foreground mb-2">抢注流程</p>
        <SnipeFlowSteps status={target.status} />
      </div>

      {/* Key numbers */}
      <div className="grid grid-cols-2 gap-2">
        <div className="glass-panel border border-border rounded-2xl p-3.5">
          <p className="text-[10px] text-muted-foreground flex items-center gap-1"><RiWalletLine className="w-3 h-3" />服务价（注册费用）</p>
          <p className="text-lg font-bold font-mono mt-1">{SNIPE_BALANCE_SYM}{(target.serviceCents ?? 0) / 100}</p>
        </div>
        <div className="glass-panel border border-border rounded-2xl p-3.5">
          <p className="text-[10px] text-muted-foreground flex items-center gap-1"><RiShieldCheckLine className="w-3 h-3" />已冻结金额</p>
          <p className="text-lg font-bold font-mono mt-1 text-emerald-600 dark:text-emerald-400">{SNIPE_BALANCE_SYM}{(target.frozenCents ?? 0) / 100}</p>
        </div>
        <div className="glass-panel border border-border rounded-2xl p-3.5">
          <p className="text-[10px] text-muted-foreground">当前余额</p>
          <p className={cn("text-lg font-bold font-mono mt-1", balanceCents < (target.serviceCents ?? 0) ? "text-amber-600 dark:text-amber-400" : "")}>
            {SNIPE_BALANCE_SYM}{(balanceCents ?? 0) / 100}
          </p>
        </div>
        <div className="glass-panel border border-border rounded-2xl p-3.5">
          <p className="text-[10px] text-muted-foreground flex items-center gap-1"><RiErrorWarningLine className="w-3 h-3" />待补缺口</p>
          <p className={cn("text-lg font-bold font-mono mt-1", shortfall > 0 ? "text-red-600 dark:text-red-400" : "text-emerald-600 dark:text-emerald-400")}>
            {shortfall > 0 ? `${SNIPE_BALANCE_SYM}${(shortfall / 100).toFixed(2)}` : "无"}
          </p>
        </div>
      </div>

      {/* Action bar */}
      <div className="flex gap-2">
        {isBlocked ? (
          <Link href="/payment/checkout" className="flex-1">
            <Button className="w-full h-10 rounded-xl text-xs bg-amber-500 hover:bg-amber-600 text-white gap-1.5">
              <RiWalletLine className="w-3.5 h-3.5" />去充值启动抢注
            </Button>
          </Link>
        ) : target.status === "armed" || target.status === "sniping" ? (
          <>
            <Button className="flex-1 h-10 rounded-xl text-xs" disabled>抢注进行中</Button>
            <Button variant="outline" className="h-10 rounded-xl text-xs" onClick={() => setShowDisableConfirm(true)}>
              停用
            </Button>
          </>
        ) : (
          <Button className="flex-1 h-10 rounded-xl text-xs gap-1.5" onClick={handleEnable} disabled={activating}>
            {activating ? <RiLoader4Line className="w-3.5 h-3.5 animate-spin" /> : <RiShieldCheckLine className="w-3.5 h-3.5" />}
            启用抢注
          </Button>
        )}
      </div>

      {/* Rules collapsible */}
      <div className="glass-panel border border-border rounded-2xl overflow-hidden">
        <button
          type="button"
          onClick={() => setShowRules(v => !v)}
          className="w-full flex items-center justify-between px-4 py-3 text-left"
        >
          <span className="text-[11px] font-bold text-muted-foreground">抢注说明与收费规则</span>
          {showRules ? <RiArrowUpSLine className="w-4 h-4 text-muted-foreground" /> : <RiArrowDownSLine className="w-4 h-4 text-muted-foreground" />}
        </button>
        {showRules && (
          <div className="px-4 pb-4 space-y-2.5 text-[11px] text-muted-foreground leading-relaxed">
            <div className="flex items-start gap-1.5">
              <RiShieldCheckLine className="w-3 h-3 mt-0.5 shrink-0 text-violet-500" />
              <p><span className="font-semibold text-foreground">收费：</span>服务费为注册预估价的若干倍（站点可配置，默认约 4 倍），用于覆盖代持与系统成本。实际以 Netim 注册价 × 汇率 × 倍率计算。</p>
            </div>
            <div className="flex items-start gap-1.5">
              <RiWalletLine className="w-3 h-3 mt-0.5 shrink-0 text-violet-500" />
              <p><span className="font-semibold text-foreground">冻结机制：</span>启用时先冻结余额中的服务费；到期抢注成功后扣费，失败则全额解冻退还。</p>
            </div>
            <div className="flex items-start gap-1.5">
              <RiTimeLine className="w-3 h-3 mt-0.5 shrink-0 text-violet-500" />
              <p><span className="font-semibold text-foreground">竞速窗口：</span>域名释放的瞬间系统自动发起注册。若余额不足会暂停等待充值，充值后自动恢复竞速。</p>
            </div>
            <div className="flex items-start gap-1.5">
              <RiVipCrownLine className="w-3 h-3 mt-0.5 shrink-0 text-violet-500" />
              <p><span className="font-semibold text-foreground">归属与交付：</span>抢注成功后域名将注册到站方名下并托管，交付细节请查看会员协议。</p>
            </div>
          </div>
        )}
      </div>

      {/* Disable confirm dialog */}
      <Dialog open={showDisableConfirm} onOpenChange={setShowDisableConfirm}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>停用抢注？</DialogTitle>
            <DialogDescription>
              停用后将取消预定并解冻 {SNIPE_BALANCE_SYM}{(target.frozenCents ?? 0) / 100} 冻结金额。该域名可能被他人抢占。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" size="sm" className="rounded-xl" onClick={() => setShowDisableConfirm(false)}>取消</Button>
            <Button
              variant="destructive"
              size="sm"
              className="rounded-xl"
              onClick={async () => {
                setShowDisableConfirm(false);
                await onDisable();
              }}
            >
              确认停用
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}