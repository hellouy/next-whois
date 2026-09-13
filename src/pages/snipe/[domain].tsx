import React, { useCallback, useEffect, useState } from "react";
import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { useSession } from "next-auth/react";
import { RiLoader4Line, RiShieldCheckLine } from "@remixicon/react";
import { toast } from "sonner";
import { SnipeDetailPage, type SnipeTargetDetail } from "@/components/dashboard/SnipeDetailPage";

export default function SnipeDetailRoute() {
  const router = useRouter();
  const { status } = useSession();
  const encodedDomain = (router.query.domain as string) ?? "";
  const domain = decodeURIComponent(encodedDomain);

  const [target, setTarget] = useState<SnipeTargetDetail | null>(null);
  const [balanceCents, setBalanceCents] = useState(0);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  const load = useCallback(async () => {
    if (!domain || status !== "authenticated") return;
    setLoading(true);
    setNotFound(false);
    try {
      const res = await fetch(`/api/user/snipe-targets/${encodeURIComponent(domain)}`);
      if (res.status === 404) {
        setNotFound(true);
        setTarget(null);
        return;
      }
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.json();
      setTarget(data.target);
      setBalanceCents(data.balanceCents ?? 0);
    } catch {
      toast.error("加载抢注详情失败");
    } finally {
      setLoading(false);
    }
  }, [domain, status]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleEnable = useCallback(async () => {
    if (!domain) return;
    const res = await fetch(`/api/user/snipe-targets/${encodeURIComponent(domain)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "enable" }),
    });
    const data = await res.json().catch(() => ({}));

    if (res.status === 409 && data.code === "SNIPE_TAKEN") {
      toast.error("该域名已被其他用户预定抢注");
      setTarget(t => t ? { ...t, status: "failed", failReason: "已被其他用户预定抢注" } : t);
      return;
    }
    if (!res.ok) {
      toast.error(data.error || "启用抢注失败，请稍后重试");
      return;
    }

    const snipe = data.snipe ?? {};
    if (snipe.status === "blocked_balance") {
      toast.warning(`余额不足，需充值 ¥${((snipe.neededCents ?? 0) / 100).toFixed(2)}`);
      setBalanceCents(snipe.balanceCents ?? 0);
    } else {
      toast.success("抢注已启用，冻结完成");
    }
    await load();
  }, [domain, load]);

  const handleDisable = useCallback(async () => {
    if (!domain) return;
    const res = await fetch(`/api/user/snipe-targets/${encodeURIComponent(domain)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "disable" }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      toast.error(data.error || "停用失败，请稍后重试");
      return;
    }
    const released = data.snipe?.releasedCents ?? 0;
    toast.success(released > 0 ? `已停用并解冻 ¥${(released / 100).toFixed(2)}` : "已停用抢注");
    await load();
  }, [domain, load]);

  if (status === "loading") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (status === "unauthenticated") {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-3">
          <RiShieldCheckLine className="w-8 h-8 mx-auto text-muted-foreground/60" />
          <p className="text-sm text-muted-foreground">请先登录后查看抢注重心</p>
          <Link href="/login" className="text-sm font-medium text-primary hover:underline">前往登录</Link>
        </div>
      </div>
    );
  }

  return (
    <>
      <Head><title>{`${domain} · 抢注详情`}</title></Head>
      <div className="max-w-2xl mx-auto px-4 py-8">
        <SnipeDetailPage
          domain={domain}
          target={target}
          balanceCents={balanceCents}
          loading={loading}
          notFound={notFound}
          onEnable={() => handleEnable()}
          onDisable={() => handleDisable()}
        />
      </div>
    </>
  );
}