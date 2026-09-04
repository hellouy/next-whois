import React from "react";
import { GetServerSideProps } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  RiLoader4Line,
  RiGlobalLine,
  RiRefreshLine,
  RiCheckLine,
  RiCloseLine,
  RiTimeLine,
  RiArrowRightLine,
  RiErrorWarningLine,
  RiFileListLine,
  RiAlertLine,
} from "@remixicon/react";
import { cn } from "@/lib/utils";
import { useRouter } from "next/router";

interface DomainAccessStats {
  total: number;
  active: number;
  tlds: { tld: string; count: number }[];
  recent: { domain: string; email: string; active: boolean; created_at: string }[];
  logs30d: number;
  noTldRules: number;
}

function StatCard({
  label,
  value,
  sub,
  color,
  icon: Icon,
}: {
  label: string;
  value: number | string;
  sub?: string;
  color?: string;
  icon?: React.ElementType;
}) {
  return (
    <div className="glass-panel border border-border rounded-2xl p-4 flex items-start gap-3">
      {Icon && (
        <div className={cn("w-9 h-9 rounded-xl flex items-center justify-center shrink-0", color || "bg-muted/60")}>
          <Icon className="w-4 h-4" />
        </div>
      )}
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-2xl font-bold tabular-nums">{value}</p>
        {sub && <p className="text-[11px] text-muted-foreground mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

function TldBar({ tld, count, max }: { tld: string; count: number; max: number }) {
  const pct = max > 0 ? Math.max(4, Math.round((count / max) * 100)) : 4;
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-mono text-muted-foreground w-20 shrink-0 truncate">.{tld}</span>
      <div className="flex-1 bg-muted/40 rounded-full h-2 overflow-hidden">
        <div
          className="h-full rounded-full bg-primary/70 transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs tabular-nums text-muted-foreground w-6 text-right shrink-0">{count}</span>
    </div>
  );
}

export default function AdminDomainAccessPage() {
  const router = useRouter();
  const [stats, setStats] = React.useState<DomainAccessStats | null>(null);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(() => {
    setLoading(true);
    fetch("/api/admin/domain-access-stats")
      .then(r => r.json())
      .then(d => {
        if (d.error) throw new Error(d.error);
        setStats(d);
      })
      .catch(err => toast.error(err instanceof Error ? err.message : "加载失败"))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => { load(); }, [load]);

  const max = stats?.tlds[0]?.count || 1;
  const inactive = stats ? stats.total - stats.active : 0;

  return (
    <AdminLayout title="域名接入">
      <div className="max-w-2xl space-y-6 pb-10">

        {/* Header */}
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2">
              <RiGlobalLine className="w-5 h-5 text-primary" />
              域名接入管理
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              查看各用户接入监控的域名分布、TLD 统计及接入状态概览
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={load}
            disabled={loading}
            className="shrink-0"
          >
            {loading
              ? <RiLoader4Line className="w-4 h-4 mr-1.5 animate-spin" />
              : <RiRefreshLine className="w-4 h-4 mr-1.5" />}
            刷新
          </Button>
        </div>

        {/* Stats */}
        {loading && !stats ? (
          <div className="flex items-center justify-center min-h-[120px]">
            <RiLoader4Line className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : stats ? (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <StatCard
                label="接入总量"
                value={stats.total}
                sub="所有域名监控"
                icon={RiGlobalLine}
                color="bg-blue-100 dark:bg-blue-950/40"
              />
              <StatCard
                label="活跃监控"
                value={stats.active}
                sub={`${stats.total > 0 ? Math.round((stats.active / stats.total) * 100) : 0}% 启用`}
                icon={RiCheckLine}
                color="bg-green-100 dark:bg-green-950/40"
              />
              <StatCard
                label="已停用"
                value={inactive}
                sub="用户主动停用"
                icon={RiCloseLine}
                color="bg-muted/60"
              />
              <StatCard
                label="近30天提醒"
                value={stats.logs30d}
                sub="已发送通知数"
                icon={RiTimeLine}
                color="bg-amber-100 dark:bg-amber-950/40"
              />
            </div>

            {/* Warning: domains without TLD rules */}
            {stats.noTldRules > 0 && (
              <div className="flex items-start gap-3 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/40 rounded-2xl px-4 py-3">
                <RiAlertLine className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-amber-700 dark:text-amber-400">
                    {stats.noTldRules} 个域名缺少 TLD 解析规则
                  </p>
                  <p className="text-xs text-amber-600 dark:text-amber-500 mt-0.5">
                    这些域名的到期时间可能无法自动同步。建议在后缀解析规则中添加对应 TLD 的规则。
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs h-7 shrink-0 border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-900/30"
                  onClick={() => router.push("/admin/tld-rules")}
                >
                  去补充规则
                </Button>
              </div>
            )}

            {/* TLD Distribution */}
            {stats.tlds.length > 0 && (
              <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold">TLD 分布</h3>
                    <p className="text-xs text-muted-foreground mt-0.5">接入域名按顶级域名的数量分布（Top 20）</p>
                  </div>
                  <Badge variant="secondary" className="text-xs">
                    {stats.tlds.length} 个 TLD
                  </Badge>
                </div>
                <div className="space-y-2.5">
                  {stats.tlds.map(({ tld, count }) => (
                    <TldBar key={tld} tld={tld} count={count} max={max} />
                  ))}
                </div>
              </div>
            )}

            {/* Recent domains */}
            {stats.recent.length > 0 && (
              <div className="glass-panel border border-border rounded-2xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold">最新接入</h3>
                    <p className="text-xs text-muted-foreground mt-0.5">最近 10 条域名监控记录</p>
                  </div>
                </div>
                <div className="divide-y divide-border/60">
                  {stats.recent.map((r, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 py-2.5 first:pt-0 last:pb-0">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-mono font-medium truncate">{r.domain}</p>
                        <p className="text-xs text-muted-foreground truncate">{r.email}</p>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={cn(
                          "text-[10px] font-semibold px-2 py-0.5 rounded-full",
                          r.active
                            ? "bg-green-100 dark:bg-green-950/40 text-green-700 dark:text-green-400"
                            : "bg-muted text-muted-foreground"
                        )}>
                          {r.active ? "活跃" : "停用"}
                        </span>
                        <span className="text-xs text-muted-foreground whitespace-nowrap">
                          {new Date(r.created_at).toLocaleDateString("zh-CN")}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Quick links */}
            <div className="glass-panel border border-border rounded-2xl p-5 space-y-3">
              <h3 className="text-sm font-semibold">快捷操作</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {[
                  { label: "管理所有监控域名", desc: "查看、搜索、删除到期提醒", href: "/admin/reminders", icon: RiFileListLine },
                  { label: "后缀解析规则", desc: "配置 TLD WHOIS 解析规则", href: "/admin/tld-rules", icon: RiGlobalLine },
                  { label: "域名生命周期", desc: "管理域名生命周期阶段节点", href: "/admin/domains", icon: RiTimeLine },
                  { label: "查询记录", desc: "查看用户 WHOIS 查询历史", href: "/admin/search-records", icon: RiFileListLine },
                ].map(({ label, desc, href, icon: Icon }) => (
                  <button
                    key={href}
                    onClick={() => router.push(href)}
                    className="flex items-center gap-3 text-left px-4 py-3 rounded-xl border border-border hover:bg-muted/40 transition-colors group"
                  >
                    <Icon className="w-4 h-4 text-muted-foreground shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">{label}</p>
                      <p className="text-xs text-muted-foreground truncate">{desc}</p>
                    </div>
                    <RiArrowRightLine className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                  </button>
                ))}
              </div>
            </div>
          </>
        ) : (
          <div className="flex items-center gap-2 text-muted-foreground py-8 justify-center">
            <RiErrorWarningLine className="w-5 h-5" />
            <span className="text-sm">加载统计数据失败，请刷新重试</span>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}

export const getServerSideProps: GetServerSideProps = async (ctx) => {
  const session = await getServerSession(ctx.req, ctx.res, authOptions);
  if (!(session?.user as any)?.isAdmin) {
    return { redirect: { destination: "/login", permanent: false } };
  }
  return { props: {} };
};
